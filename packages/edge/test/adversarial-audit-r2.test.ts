import { spawn } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { type AuditFields, auditHash, type Hop, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { FsAuditSink, readAuditLines } from '../src/adapters/fs-audit.ts'
import { readAuditAnchor, SqliteStore, storeLockPath } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import { EdgeError, type EdgeKeys } from '../src/ports.ts'
import { scratch } from './support/adversarial.ts'
import { FakeClock, P, PUBLIC_LOOKUP, seededRng, T0 } from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// A log cut short or rewritten, and the writer lock vs two sessions of one root, on the production adapters: a
// SqliteStore on a file (its audit_anchor row, sqlite-store.ts; its writer lock <dir>/audit.lock, fs-lock.ts) and an
// FsAuditSink (audit.jsonl), composed by the Edge, whose constructor checks the log against its anchor (audit.ts
// Audit#join, lines 185 to 207; checkAuditAnchor, lines 88 to 99). The edge must refuse to continue a log cut short
// (`truncated`) or rewritten with recomputed hashes (`diverged`), and a second writer of the same state directory gets
// `busy` (fs-lock.ts acquireLock, line 169; sqlite-store.ts line 101).

const HOME = 'http://home.test'
const LOG = 'audit.jsonl'
const ID = (i: number): string => i.toString(16).padStart(64, '0')
const STORE = resolve(import.meta.dirname, '../src/adapters/sqlite-store.ts')

interface Opened {
  readonly edge: Edge
  readonly store: SqliteStore
}

/** An edge on the state directory `dir` (state.db and audit.jsonl), its store closed again if the edge refuses. */
function openEdge(dir: string, o: { keys?: EdgeKeys; auth?: readonly Hop[]; mailbox?: string } = {}): Opened {
  const store = new SqliteStore(join(dir, 'state.db'))
  try {
    const edge = new Edge({
      keys: o.keys ?? P.carol.keys,
      ...(o.auth === undefined ? {} : { auth: o.auth }),
      ...(o.mailbox === undefined ? {} : { mailbox: o.mailbox }),
      store,
      relays: { client: new ScriptedRelay(), urls: [HOME] },
      policy: { roots: [], types: [] },
      clock: new FakeClock(),
      rng: seededRng('adversarial-audit-r2'),
      audit: new FsAuditSink(join(dir, LOG)),
      lookup: PUBLIC_LOOKUP,
    })
    return { edge, store }
  } catch (e) {
    store.close()
    throw e
  }
}

/** Twenty lines written by the edge itself, of the shapes the audit-tamper tests use; the store is closed after. */
function twentyLines(dir: string): string[] {
  const { edge, store } = openEdge(dir)
  for (let i = 1; i <= 20; i++) {
    edge.audit.record(
      i % 5 === 0
        ? { event: 'dedup', decision: 'reject', reason: 'duplicate', id: ID(i), detail: { cursor: i } }
        : { event: 'verify', decision: 'accept', id: ID(i), detail: { cursor: i } },
    )
  }
  store.close()
  return readAuditLines(join(dir, LOG))
}

/** The lines rewritten from line `from` (1-based): its reason edited, and every hash from there recomputed. */
function rewritten(lines: readonly string[], from: number, until = lines.length): string[] {
  const out = [...lines]
  let prev = from === 1 ? '0'.repeat(64) : (JSON.parse(lines[from - 2] as string) as { hash: string }).hash
  for (let n = from; n <= until; n++) {
    const v = JSON.parse(lines[n - 1] as string) as AuditFields
    const fields: AuditFields = {
      seq: v.seq,
      prev,
      ts: v.ts,
      event: v.event,
      decision: n === from ? 'reject' : v.decision,
      reason: n === from ? 'bad-sig' : v.reason,
      id: v.id,
      from: v.from,
      root: v.root,
      detail: v.detail,
    }
    const hash = auditHash(fields)
    out[n - 1] = JSON.stringify({ ...fields, hash })
    prev = hash
  }
  return out
}

/** What the edge's constructor throws on this state directory: [code, is an EdgeError, message], or 'opened'. */
function refusal(dir: string): [string, boolean, string] | 'opened' {
  try {
    openEdge(dir).store.close()
    return 'opened'
  } catch (e) {
    return [(e as { code: string }).code, e instanceof EdgeError, (e as Error).message]
  }
}

const writeLines = (dir: string, lines: readonly string[]): void =>
  writeFileSync(join(dir, LOG), `${lines.join('\n')}\n`, { mode: 0o600 })

describe('fixed: the edge refuses a log cut short or rewritten, and a second writer', () => {
  it('a 20-line log with its last 3 lines cut: truncated, and the edge refuses to continue it', () => {
    const dir = scratch('e3-cut')
    const log = twentyLines(dir)
    const anchor = readAuditAnchor(join(dir, 'state.db'), LOG)
    // V1: the untouched log verifies against its anchor, and the edge opens on it.
    expect(verifyAuditLog(log, anchor)).toEqual({
      ok: true,
      lines: 20,
      anchor: { state: 'ok', seq: 20, lines: 20 },
    })
    expect(refusal(dir)).toBe('opened')
    const cut = log.slice(0, 17)
    expect(cut).not.toEqual(log)
    // The chain alone cannot see the cut; the anchor does.
    expect(verifyAuditLog(cut)).toEqual({ ok: true, lines: 17 })
    writeLines(dir, cut)
    expect(verifyAuditLog(readAuditLines(join(dir, LOG)), anchor)).toEqual({
      ok: false,
      line: 18,
      problem: 'truncated: the log has 17 lines; its anchor is at line 20',
      anchor: { state: 'truncated', seq: 20, lines: 17 },
    })
    expect(refusal(dir)).toEqual([
      'truncated',
      true,
      `truncated: the audit log ${LOG} has 17 lines; its anchor is at line 20`,
    ])
    // The refusal wrote nothing and left the lock free: the file is the cut one, and a store opens.
    expect(readAuditLines(join(dir, LOG))).toEqual(cut)
    new SqliteStore(join(dir, 'state.db')).close()
    console.log(
      'MEASURE E3 (cut): 20 lines less 3 -> chain ok 17; with the anchor truncated at line 18; the edge refuses truncated',
    )
  })

  it('a 20-line log rewritten from line 10 with recomputed hashes: diverged, and the edge refuses to continue it', () => {
    const dir = scratch('e3-rewrite')
    const log = twentyLines(dir)
    const anchor = readAuditAnchor(join(dir, 'state.db'), LOG)
    expect(refusal(dir)).toBe('opened')
    const forged = rewritten(log, 10)
    expect(forged).not.toEqual(log)
    expect(forged).toHaveLength(20)
    // The forgery is a consistent chain: only the anchor sees it.
    expect(verifyAuditLog(forged)).toEqual({ ok: true, lines: 20 })
    writeLines(dir, forged)
    expect(verifyAuditLog(readAuditLines(join(dir, LOG)), anchor)).toEqual({
      ok: false,
      line: 20,
      problem: "diverged: line 20 does not have its anchor's hash",
      anchor: { state: 'diverged', seq: 20, lines: 20 },
    })
    expect(refusal(dir)).toEqual([
      'diverged',
      true,
      `diverged: line 20 of the audit log ${LOG} does not have its anchor's hash`,
    ])
    // The cut-and-refill variant: the last 3 lines replaced by 3 forged ones that chain on line 17.
    const refilled = rewritten(log, 18)
    writeLines(dir, refilled)
    expect(verifyAuditLog(refilled)).toEqual({ ok: true, lines: 20 })
    expect(refusal(dir)?.slice(0, 2)).toEqual(['diverged', true])
    console.log(
      'MEASURE E3 (rewrite): from line 10 recomputed -> chain ok 20; with the anchor diverged at line 20; the edge refuses diverged; lines 18 to 20 refilled -> diverged',
    )
  })

  it('post-hoc: lines 10 to 19 rewritten with line 20 kept verbatim (measured, not predicted)', () => {
    const dir = scratch('e3-keep-last')
    const log = twentyLines(dir)
    const anchor = readAuditAnchor(join(dir, 'state.db'), LOG)
    const forged = rewritten(log, 10, 19)
    expect(forged[19]).toBe(log[19])
    expect(forged).not.toEqual(log)
    writeLines(dir, forged)
    const verdict = verifyAuditLog(forged, anchor)
    const opened = refusal(dir)
    console.log(
      `MEASURE E3 (keep last): verifyAuditLog with the anchor -> ${JSON.stringify(verdict)}; the edge -> ${JSON.stringify(opened)}`,
    )
    // What was observed before the fix: the edge's constructor compared only the line at the anchor's seq with the
    // anchor (checkAuditAnchor) and did not recompute the chain, so it opened on a log whose lines 10 to 19 were
    // rewritten. Flipped to the fix: Audit recomputes the whole chain on join and refuses diverged.
    expect(verdict).toEqual({
      ok: false,
      line: 20,
      problem: "prev is not the previous line's hash",
      anchor: { state: 'ok', seq: 20, lines: 20 },
    })
    expect(opened).toEqual([
      'diverged',
      true,
      `diverged: line 20 of the audit log ${LOG} breaks its hash chain (prev is not the previous line's hash); its anchor is at line 20`,
    ])
  })

  it('a second writer opening the store while one holds the lock: busy, and the holder keeps its log', () => {
    const dir = scratch('e3-busy')
    const first = openEdge(dir)
    try {
      first.edge.audit.record({ event: 'verify', decision: 'accept', id: ID(1) })
      const lock = JSON.parse(readFileSync(storeLockPath(join(dir, 'state.db')), 'utf8')) as { pid: number }
      expect(lock.pid).toBe(process.pid)
      const second = refusal(dir)
      expect(second).toEqual([
        'busy',
        true,
        expect.stringMatching(
          new RegExp(`^busy: .*audit\\.lock is held by the process with pid ${process.pid}, started `),
        ),
      ])
      // The holder goes on: its next line chains, and the log verifies against the anchor.
      first.edge.audit.record({ event: 'verify', decision: 'accept', id: ID(2) })
    } finally {
      first.store.close()
    }
    const lines = readAuditLines(join(dir, LOG))
    expect(verifyAuditLog(lines, readAuditAnchor(join(dir, 'state.db'), LOG))).toMatchObject({
      ok: true,
      lines: 2,
    })
    // V1: once the holder closes, a new writer opens.
    expect(refusal(dir)).toBe('opened')
    console.log(
      "MEASURE E3 (lock): a second writer of the open store -> busy; the holder's log verifies, 2 lines",
    )
  })
})

describe('the writer lock (measure): against two sessions of one principal', () => {
  const chainTo = (p: typeof P.session): Hop[] => [signHop(P.jane.signing, p.address, [], T0 + 3600)]
  const sessionKeys = (p: typeof P.session): EdgeKeys => ({ signing: p.signing, sealing: P.jane.sealing })

  it("two sessions of jane on one state directory: the second gets busy, in this process and against a child's", async () => {
    const dir = scratch('e5')
    // V1: each session opens alone, under its chain, at jane's mailbox.
    for (const p of [P.session, P.other]) {
      const one = openEdge(dir, { keys: sessionKeys(p), auth: chainTo(p), mailbox: P.jane.address })
      expect([one.edge.address, one.edge.mailbox]).toEqual([p.address, P.jane.address])
      one.store.close()
    }
    const s1 = openEdge(dir, {
      keys: sessionKeys(P.session),
      auth: chainTo(P.session),
      mailbox: P.jane.address,
    })
    let inProcess: string
    let otherFile: string
    try {
      s1.edge.audit.record({ event: 'verify', decision: 'accept', id: ID(1) })
      try {
        openEdge(dir, { keys: sessionKeys(P.other), auth: chainTo(P.other), mailbox: P.jane.address })
        inProcess = 'opened'
      } catch (e) {
        inProcess = (e as { code: string }).code
      }
      // The lock is the directory's: a store under another file name there is a second writer too.
      try {
        new SqliteStore(join(dir, 'state-2.db')).close()
        otherFile = 'opened'
      } catch (e) {
        otherFile = (e as { code: string }).code
      }
    } finally {
      s1.store.close()
    }
    expect(inProcess).toBe('busy')
    expect(otherFile).toBe('busy')
    // Session 1's log is its own and verifies: nothing of session 2 reached it.
    const lines = readAuditLines(join(dir, LOG))
    expect(lines).toHaveLength(1)
    expect(lines[0]).toContain('"event":"verify"')
    expect(verifyAuditLog(lines, readAuditAnchor(join(dir, 'state.db'), LOG))).toMatchObject({ ok: true })

    // The live case: session 1 is another process (as two MCP servers of one home would be).
    const script = `import { SqliteStore } from ${JSON.stringify(STORE)}; new SqliteStore(process.argv[1]); process.stdout.write('held\\n'); setInterval(() => {}, 1000)`
    const child = spawn(
      process.execPath,
      ['--input-type=module', '--no-warnings', '-e', script, join(dir, 'state.db')],
      {
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    )
    let againstChild: string
    try {
      await new Promise<void>((done, fail) => {
        child.stdout?.on('data', (d: Buffer) => d.toString().includes('held') && done())
        child.once('exit', (c) => fail(new Error(`the child exited with ${c}`)))
      })
      try {
        openEdge(dir, { keys: sessionKeys(P.other), auth: chainTo(P.other), mailbox: P.jane.address })
        againstChild = 'opened'
      } catch (e) {
        againstChild = (e as { code: string }).code
      }
    } finally {
      child.kill('SIGKILL')
      await new Promise((r) => child.once('exit', r))
    }
    expect(againstChild).toBe('busy')
    console.log(
      `MEASURE E5: session 2 of jane on session 1's state directory -> ${inProcess} in process, ${againstChild} against a child; another store file in the directory -> ${otherFile}; session 1's log 1 line, verifies`,
    )
  }, 20_000)
})
