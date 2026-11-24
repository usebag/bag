import {
  appendFileSync,
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { loadavg, tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { FsAuditSink } from '../src/adapters/fs-audit.ts'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { AUDIT_RULES, Audit, type AuditEntry } from '../src/audit.ts'
import { type AuditPrefix, type AuditScan, EdgeError } from '../src/ports.ts'

// The verified prefix (packages/edge/README.md, "The verified prefix"): an open hashes the bytes it verified at an
// earlier open and parses only the lines after them, and still refuses every tampering the full check refuses, with
// its words. On the production adapters: a SqliteStore on a file and FsAuditSink files.

const LOG = 'audit.jsonl'
const SIDE = 'cli-audit.jsonl'
const clock = { now: () => 1_795_476_000 }
const BIG = 200_000
const SMALL = 2_000

/** A line of about a real one's size (the investigator's grow-audit.ts). */
const entry = (i: number, tag = 'history'): AuditEntry => ({
  event: 'policy',
  decision: 'route',
  detail: {
    local: `synthetic ${tag} line ${i} for a probe of the start's cost, about the size of a real one`,
  },
})

/** `n` chained lines after `last` (null: from the genesis), built in memory. */
function chain(n: number, last: string | null = null, tag = 'history'): string[] {
  const out: string[] = []
  const a = new Audit({ name: LOG, last: () => last, append: (l) => out.push(l) }, clock)
  a.attribute(() => null)
  for (let i = 0; i < n; i++) a.record(entry(i, tag))
  return out
}

/** A sink that records each scan (what an open parses) and each whole read. */
class Counting extends FsAuditSink {
  readonly scans: { file: string | null; from: number; lines: number }[] = []
  reads = 0
  override scan(file: string | null, from: number): AuditScan | null {
    const s = super.scan(file, from)
    this.scans.push({ file, from, lines: s?.lines.length ?? -1 })
    return s
  }
  override read(): string[] {
    this.reads++
    return super.read()
  }
  /** The lines this open parsed, over every file. */
  get parsed(): number {
    return this.scans.reduce((n, s) => n + Math.max(0, s.lines), 0)
  }
}

/** A sink whose file `name` (null: its own) reads as changed, then is gone before the open reads it again. */
class Vanishing extends FsAuditSink {
  readonly #path: string
  readonly #which: string | null
  constructor(path: string, which: string | null) {
    super(path)
    this.#path = path
    this.#which = which
  }
  override scan(file: string | null, from: number): AuditScan | null {
    const s = super.scan(file, from)
    if (file !== this.#which || from === 0 || s === null) return s
    rmSync(file === null ? this.#path : join(this.#path, '..', file))
    return { ...s, head: 'another digest' }
  }
}

/** The anchor store an Edge gives its Audit, on `store`. */
const anchorOf = (store: SqliteStore) => ({
  get: () => store.auditAnchorGet(LOG),
  put: (anchor: { seq: number; hash: string }) => store.auditAnchorPut(LOG, anchor, clock.now()),
  others: () => store.auditAnchors().filter((a) => a.name !== LOG),
  prefix: (name: string) => store.auditPrefixGet(name),
  setPrefix: (name: string, prefix: AuditPrefix) => store.auditPrefixPut(name, prefix),
})

/** Opens the log of `dir` as an Edge does (its row, its set, its prefixes), then closes the store. */
function open(dir: string, record = 0): { sink: Counting; ms: number } {
  const store = new SqliteStore(join(dir, 'edge.sqlite'))
  try {
    const sink = new Counting(join(dir, LOG))
    const t = performance.now()
    const audit = new Audit(sink, clock, {
      get: () => store.auditAnchorGet(LOG),
      put: (anchor) => store.auditAnchorPut(LOG, anchor, clock.now()),
      others: () => store.auditAnchors().filter((a) => a.name !== LOG),
      prefix: (name) => store.auditPrefixGet(name),
      setPrefix: (name, prefix) => store.auditPrefixPut(name, prefix),
    })
    const ms = performance.now() - t
    for (let i = 0; i < record; i++) audit.record(entry(i, 'appended'))
    return { sink, ms }
  } finally {
    store.close()
  }
}

/** The refusal of an open: the EdgeError's code and message. */
function refusal(dir: string): [string, string] {
  try {
    open(dir)
  } catch (e) {
    if (e instanceof EdgeError) return [e.code, e.message.replace(`${e.code}: `, '')]
    throw e
  }
  throw new Error('the open did not refuse')
}

const sql = (dir: string, q: string): void => {
  const db = new DatabaseSync(join(dir, 'edge.sqlite'))
  try {
    db.exec(q)
  } finally {
    db.close()
  }
}
const prefixOf = (dir: string, name = LOG) => {
  const s = new SqliteStore(join(dir, 'edge.sqlite'), { lock: false })
  try {
    return s.auditPrefixGet(name)
  } finally {
    s.close()
  }
}

const dirs: string[] = []
const scratch = (): string => {
  const d = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-prefix-'))
  dirs.push(d)
  return d
}
afterAll(() => {
  if (process.env.AC_KEEP_TMP !== '1') for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

/** A state directory whose log holds `lines`, anchored at its last line with no prefix (as a 0.4.5 store leaves it). */
function home(lines: readonly string[]): string {
  const dir = scratch()
  writeFileSync(join(dir, LOG), `${lines.join('\n')}\n`, { mode: 0o600 })
  const last = JSON.parse(lines.at(-1) as string) as { seq: number; hash: string }
  const s = new SqliteStore(join(dir, 'edge.sqlite'))
  s.auditAnchorPut(LOG, { seq: last.seq, hash: last.hash }, clock.now())
  s.close()
  return dir
}
/** A copy of `from` (log and store), the prefix already written by a first open. */
function copy(from: string): string {
  const dir = scratch()
  for (const f of [LOG, 'edge.sqlite']) copyFileSync(join(from, f), join(dir, f))
  return dir
}

describe('a 200,000-line log', () => {
  let big: string[]
  let seeded: string
  let first: { sink: Counting; ms: number }
  let second: { sink: Counting; ms: number }

  beforeAll(() => {
    big = chain(BIG)
    seeded = home(big)
    first = open(seeded)
    second = open(seeded)
    // The figures for the report, with the machine's load.
    console.log(
      `audit-prefix: ${BIG} lines, ${statSync(join(seeded, LOG)).size} bytes: first open ${first.ms.toFixed(0)} ms (${first.sink.parsed} lines parsed), second ${second.ms.toFixed(0)} ms (${second.sink.parsed} parsed); load ${loadavg()[0]?.toFixed(1)}`,
    )
  }, 300_000)

  it('is checked whole at its first open, which keeps the prefix: the file to its last line', () => {
    expect(first.sink.parsed).toBe(BIG)
    const p = prefixOf(seeded)
    const last = JSON.parse(big.at(-1) as string) as { seq: number; hash: string }
    expect(p).toEqual({
      bytes: statSync(join(seeded, LOG)).size,
      digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      seq: BIG,
      hash: last.hash,
      rules: AUDIT_RULES,
    })
  })

  it('opens again parsing no line, never reading the file whole, in at most a quarter of the first and under 2 s', () => {
    expect(second.sink.parsed).toBe(0)
    expect(second.sink.reads).toBe(0)
    expect(second.sink.scans).toEqual([{ file: null, from: statSync(join(seeded, LOG)).size, lines: 0 }])
    expect(second.ms).toBeLessThanOrEqual(first.ms / 4)
    expect(second.ms).toBeLessThan(2000)
  })

  it('refuses line 100,000 edited by one byte, naming the line, as the full check does', () => {
    const dir = copy(seeded)
    const lines = big.slice()
    lines[99_999] = (lines[99_999] as string).replace('synthetic', 'synthetiC')
    writeFileSync(join(dir, LOG), `${lines.join('\n')}\n`)
    expect(refusal(dir)).toEqual([
      'diverged',
      `line 100000 of the audit log ${LOG} breaks its hash chain (the hash does not recompute); its anchor is at line ${BIG}`,
    ])
  }, 120_000)

  it('refuses lines 100,000 to 199,999 rewritten with recomputed hashes under the last line kept', () => {
    const dir = copy(seeded)
    const forged = chain(BIG / 2, big[99_998] as string, 'forged')
    const lines = [...big.slice(0, 99_999), ...forged, big.at(-1) as string]
    expect(lines).toHaveLength(BIG)
    writeFileSync(join(dir, LOG), `${lines.join('\n')}\n`)
    expect(refusal(dir)).toEqual([
      'diverged',
      `line ${BIG} of the audit log ${LOG} breaks its hash chain (prev is not the previous line's hash); its anchor is at line ${BIG}`,
    ])
  }, 120_000)
})

describe('a log with a prefix, against each tampering', () => {
  let seeded: string
  let lines: string[]
  beforeAll(() => {
    lines = chain(SMALL)
    seeded = home(lines)
    open(seeded)
  })
  const write = (dir: string, ls: readonly string[]) => writeFileSync(join(dir, LOG), `${ls.join('\n')}\n`)

  it('refuses the tail cut by three lines', () => {
    const dir = copy(seeded)
    write(dir, lines.slice(0, -3))
    expect(refusal(dir)).toEqual([
      'truncated',
      `the audit log ${LOG} has ${SMALL - 3} lines; its anchor is at line ${SMALL}`,
    ])
  })

  it('refuses a cut inside the lines after the prefix', () => {
    const dir = copy(seeded)
    open(dir, 10) // ten lines past the prefix, the anchor at the last
    const now = readFileSync(join(dir, LOG), 'utf8').split('\n').filter(Boolean)
    write(dir, now.slice(0, -3))
    expect(refusal(dir)).toEqual([
      'truncated',
      `the audit log ${LOG} has ${SMALL + 7} lines; its anchor is at line ${SMALL + 10}`,
    ])
  })

  it('refuses a rollback to a copy taken at three quarters', () => {
    const dir = copy(seeded)
    write(dir, lines.slice(0, (SMALL * 3) / 4))
    expect(refusal(dir)[0]).toBe('truncated')
  })

  it("refuses another identity's log of the same length swapped in", () => {
    const dir = copy(seeded)
    write(dir, chain(SMALL, null, 'other'))
    expect(refusal(dir)).toEqual([
      'diverged',
      `line ${SMALL} of the audit log ${LOG} does not have its anchor's hash`,
    ])
  })

  it('refuses a line after the prefix whose chain breaks', () => {
    const dir = copy(seeded)
    open(dir, 5)
    const now = readFileSync(join(dir, LOG), 'utf8').split('\n').filter(Boolean)
    now[SMALL + 1] = (now[SMALL + 1] as string).replace('appended', 'appendeD')
    write(dir, now)
    expect(refusal(dir)[1]).toMatch(
      new RegExp(`^line ${SMALL + 2} of the audit log ${LOG} breaks its hash chain`),
    )
  })

  it('refuses an interior edit when the prefix columns were nulled: the full check runs and names the line', () => {
    const dir = copy(seeded)
    sql(dir, 'UPDATE audit_anchor SET prefix_bytes = NULL, prefix_digest = NULL')
    const ls = lines.slice()
    ls[999] = (ls[999] as string).replace('synthetic', 'synthetiC')
    write(dir, ls)
    expect(refusal(dir)[1]).toMatch(/^line 1000 of the audit log audit\.jsonl breaks its hash chain/)
  })

  it('takes the documented reset (the row deleted) as before: adopted unchecked, no prefix, then checked whole', () => {
    const dir = copy(seeded)
    sql(dir, 'DELETE FROM audit_anchor')
    expect(open(dir).sink.parsed).toBe(SMALL)
    expect(prefixOf(dir)).toBeNull()
    const again = open(dir)
    expect(again.sink.scans).toEqual([{ file: null, from: 0, lines: SMALL }])
    expect(prefixOf(dir)?.seq).toBe(SMALL)
  })

  it('refuses a partial last line in its own log and keeps its prefix where it was', () => {
    const dir = copy(seeded)
    const before = prefixOf(dir)
    appendFileSync(join(dir, LOG), '{"seq":2001,"prev":"')
    expect(refusal(dir)[0]).toBe('diverged')
    expect(prefixOf(dir)).toEqual(before)
  })

  it('accepts lines past the anchor (a crash after an append) and moves the anchor and the prefix', () => {
    const dir = copy(seeded)
    appendFileSync(join(dir, LOG), `${chain(3, lines.at(-1) as string, 'crash').join('\n')}\n`)
    const o = open(dir)
    expect(o.sink.parsed).toBe(3)
    expect(prefixOf(dir)?.seq).toBe(SMALL + 3)
    expect(open(dir).sink.parsed).toBe(0)
  })

  it('checks a store from 0.4.5 (no prefix columns) whole once, then keeps the prefix', () => {
    const dir = scratch()
    writeFileSync(join(dir, LOG), `${lines.join('\n')}\n`)
    const last = JSON.parse(lines.at(-1) as string) as { seq: number; hash: string }
    const db = new DatabaseSync(join(dir, 'edge.sqlite'))
    db.exec(`CREATE TABLE audit_anchor (name TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL,
      updated_at INTEGER NOT NULL) STRICT`)
    db.prepare('INSERT INTO audit_anchor VALUES (?, ?, ?, ?)').run(LOG, last.seq, last.hash, 1)
    db.close()
    expect(open(dir).sink.scans).toEqual([{ file: null, from: 0, lines: SMALL }])
    expect(open(dir).sink.parsed).toBe(0)
  })

  it('refuses a 0.4.5 store whose log was edited before the update, at its first open, and keeps no prefix', () => {
    const dir = scratch()
    const ls = lines.slice()
    ls[999] = (ls[999] as string).replace('synthetic', 'synthetiC')
    writeFileSync(join(dir, LOG), `${ls.join('\n')}\n`)
    const last = JSON.parse(lines.at(-1) as string) as { seq: number; hash: string }
    const db = new DatabaseSync(join(dir, 'edge.sqlite'))
    db.exec(`CREATE TABLE audit_anchor (name TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL,
      updated_at INTEGER NOT NULL) STRICT`)
    db.prepare('INSERT INTO audit_anchor VALUES (?, ?, ?, ?)').run(LOG, last.seq, last.hash, 1)
    db.close()
    expect(refusal(dir)[1]).toMatch(/^line 1000 of the audit log audit\.jsonl breaks its hash chain/)
    expect(prefixOf(dir)).toBeNull()
    expect(refusal(dir)[1]).toMatch(/^line 1000 of the audit log audit\.jsonl breaks its hash chain/)
  })

  it('refuses a log that goes between the two reads of an open (its prefix no longer matching) as not there', () => {
    const dir = copy(seeded)
    const store = new SqliteStore(join(dir, 'edge.sqlite'))
    try {
      const sink = new Vanishing(join(dir, LOG), null)
      expect(() => new Audit(sink, clock, anchorOf(store))).toThrowError(
        new EdgeError('truncated', `the audit log ${LOG} has 0 lines; its anchor is at line ${SMALL}`),
      )
    } finally {
      store.close()
    }
  })

  it('checks whole once when the line rules changed', () => {
    const dir = copy(seeded)
    sql(dir, `UPDATE audit_anchor SET prefix_rules = ${AUDIT_RULES + 1}`)
    expect(open(dir).sink.scans).toEqual([{ file: null, from: 0, lines: SMALL }])
    expect(prefixOf(dir)?.rules).toBe(AUDIT_RULES)
    expect(open(dir).sink.parsed).toBe(0)
  })
})

describe('a sidecar of the set', () => {
  /** A state directory with the log and a sidecar, each anchored, after a first open. */
  function set(): { dir: string; side: string[] } {
    const dir = home(chain(50))
    const side = chain(20, null, 'sidecar')
    writeFileSync(join(dir, SIDE), `${side.join('\n')}\n`)
    const last = JSON.parse(side.at(-1) as string) as { seq: number; hash: string }
    const s = new SqliteStore(join(dir, 'edge.sqlite'))
    s.auditAnchorPut(SIDE, { seq: last.seq, hash: last.hash }, clock.now())
    s.close()
    open(dir)
    return { dir, side }
  }

  it('gets its own prefix, and is not parsed again', () => {
    const { dir } = set()
    expect(prefixOf(dir, SIDE)?.seq).toBe(20)
    expect(open(dir).sink.parsed).toBe(0)
  })

  it('refuses a sidecar that goes between the two reads of an open as not there', () => {
    const { dir } = set()
    const store = new SqliteStore(join(dir, 'edge.sqlite'))
    try {
      expect(() => new Audit(new Vanishing(join(dir, LOG), SIDE), clock, anchorOf(store))).toThrowError(
        new EdgeError('truncated', `the audit log ${SIDE} is anchored at line 20 and is not there`),
      )
    } finally {
      store.close()
    }
  })

  it('refuses a sidecar gone, or edited inside', () => {
    const a = set()
    rmSync(join(a.dir, SIDE))
    expect(refusal(a.dir)).toEqual([
      'truncated',
      `the audit log ${SIDE} is anchored at line 20 and is not there`,
    ])
    const b = set()
    const ls = b.side.slice()
    ls[4] = (ls[4] as string).replace('sidecar', 'sidecaR')
    writeFileSync(join(b.dir, SIDE), `${ls.join('\n')}\n`)
    expect(refusal(b.dir)[1]).toMatch(/^line 5 of the audit log cli-audit\.jsonl breaks its hash chain/)
  })

  it('ends its prefix at the last complete line while its writer is inside an append', () => {
    const { dir, side } = set()
    // The sidecar's writer (lock-free beside the service) has written a line and its anchor but not yet its newline.
    const next = chain(1, side.at(-1) as string, 'sidecar')[0] as string
    appendFileSync(join(dir, SIDE), next)
    const row = JSON.parse(next) as { seq: number; hash: string }
    const s = new SqliteStore(join(dir, 'edge.sqlite'), { lock: false })
    s.auditAnchorPut(SIDE, { seq: row.seq, hash: row.hash }, clock.now())
    s.close()
    open(dir)
    const p = prefixOf(dir, SIDE)
    expect(p?.seq).toBe(20)
    expect(p?.bytes).toBe(statSync(join(dir, SIDE)).size - Buffer.byteLength(next))
    // The newline lands; the next open verifies the line and moves the prefix past it.
    appendFileSync(join(dir, SIDE), '\n')
    expect(open(dir).sink.parsed).toBe(1)
    expect(prefixOf(dir, SIDE)?.seq).toBe(21)
  })
})
