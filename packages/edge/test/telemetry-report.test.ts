import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { systemRng } from '../src/adapters/system-clock.ts'
import {
  PREVIEW_ID,
  readTelemetrySpool,
  setTelemetry,
  TELEMETRY_COUNTS_FILE,
  telemetryId,
  telemetryReport,
} from '../src/telemetry.ts'
import {
  addCell,
  addTree,
  bucket,
  buildTelemetryReport,
  type Cells,
  checkoutCommit,
  dayOf,
  durationIndex,
  machineFacts,
  type TelemetryFacts,
} from '../src/telemetry-report.ts'
import {
  BUILDS,
  MAX_AGE_DAYS,
  MAX_BYTES,
  MAX_CELLS,
  MAX_COUNT,
  MAX_KEYS,
  MEMBERS,
  SETS,
  type SetName,
  TELEMETRY_SCHEMA_COMMIT,
} from '../src/telemetry-schema.ts'
import { T0, tempDir } from './support/fixtures.ts'

// The client's report: the copy of the Worker's schema, the builder's buckets and caps (the red team's F-size),
// and the property that no report carries a string outside the schema's sets, whatever the spool holds. Where the
// checkout holds deploy/telemetry, every report built here also passes the Worker's own checkReport.

const tmp = tempDir('telemetry-report')
afterAll(() => tmp.cleanup())
let n = 0

/** T0's UTC date, and the time the Worker checks a report at (ms). */
const DAY = '2027-01-15'
const NOW = T0 * 1000
const ID = 'ab'.repeat(16)
const FACTS: TelemetryFacts = { id: ID, build: 'f'.repeat(40), os: 'darwin', arch: 'arm64', node: '24' }

/** The Worker's schema module, its builds and its MAX_BYTES. */
interface WorkerFiles {
  readonly schema: {
    readonly SETS: unknown
    readonly MEMBERS: unknown
    readonly MAX_CELLS: unknown
    readonly MAX_KEYS: unknown
    readonly MAX_COUNT: unknown
    readonly MAX_AGE_DAYS: unknown
    readonly checkReport: (report: unknown, now: number) => unknown
  }
  readonly builds: unknown
  readonly maxBytes: unknown
}

const WORKER = fileURLToPath(new URL('../../../deploy/telemetry/src/', import.meta.url))

/** The Worker's files where the checkout holds them; null in the public cut, which carries no deploy/telemetry. */
async function worker(): Promise<WorkerFiles | null> {
  if (!existsSync(join(WORKER, 'schema.ts'))) return null
  const schema = (await import(join(WORKER, 'schema.ts'))) as WorkerFiles['schema']
  const builds = ((await import(join(WORKER, 'builds.ts'))) as { BUILDS: unknown }).BUILDS
  const maxBytes = ((await import(join(WORKER, 'index.ts'))) as { MAX_BYTES: unknown }).MAX_BYTES
  return { schema, builds, maxBytes }
}

/** A report checked as the Worker checks one, where it can be: its bytes within MAX_BYTES, and checkReport's yes. */
async function sendable(report: Record<string, unknown>): Promise<void> {
  expect(Buffer.byteLength(JSON.stringify(report))).toBeLessThanOrEqual(MAX_BYTES)
  const w = await worker()
  if (w !== null) expect(w.schema.checkReport(report, NOW)).not.toBeNull()
}

/** The counted leaves of a family of a report, by path ("a b c", a duration's bucket last). */
function leaves(v: unknown, path: readonly string[] = []): [string, number][] {
  if (typeof v === 'number') return [[path.join(' '), v]]
  if (Array.isArray(v)) return v.flatMap((x, i) => leaves(x, [...path, String(i)]))
  if (typeof v !== 'object' || v === null) return []
  return Object.entries(v).flatMap(([k, x]) => leaves(x, [...path, k]))
}

describe('the schema: the edge copy of deploy/telemetry/src/schema.ts at TELEMETRY_SCHEMA_COMMIT', () => {
  it('equals the Worker files value for value wherever the checkout holds them (the cut holds none)', async () => {
    expect(TELEMETRY_SCHEMA_COMMIT).toMatch(/^[0-9a-f]{40}$/)
    const w = await worker()
    if (w === null) return
    expect(SETS).toEqual(w.schema.SETS)
    expect(MEMBERS).toEqual(w.schema.MEMBERS)
    expect(MAX_CELLS).toEqual(w.schema.MAX_CELLS)
    expect(MAX_KEYS).toEqual(w.schema.MAX_KEYS)
    expect([MAX_COUNT, MAX_AGE_DAYS]).toEqual([w.schema.MAX_COUNT, w.schema.MAX_AGE_DAYS])
    expect([MAX_BYTES, BUILDS]).toEqual([w.maxBytes, w.builds])
  })
})

describe('the builder: one schema-1 report for a UTC day', () => {
  it('buckets a count to the largest power of two not above it, at most 2^19', () => {
    const cases: [number, number][] = [
      [0, 0],
      [1, 1],
      [3, 2],
      [4, 4],
      [1000, 512],
      [MAX_COUNT, MAX_COUNT],
      [Number.MAX_SAFE_INTEGER, MAX_COUNT],
    ]
    for (const [count, b] of cases) expect(bucket(count), String(count)).toBe(b)
    const ms = [0, 99, 100, 999, 1000, 9999, 10_000, 59_999, 60_000, 3_600_000]
    expect(ms.map(durationIndex)).toEqual([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
    const days = [DAY, '2027-02-30', '2027-1-5', 'x'].map((d) => dayOf(d))
    expect(days).toEqual([20833, null, null, null])
  })

  it('lists the members in the schema order: the date, the id, the facts placed in their sets, no counts', async () => {
    const report = buildTelemetryReport(DAY, new Map(), FACTS)
    expect(Object.keys(report)).toEqual(Object.keys(MEMBERS))
    expect(report).toEqual({
      schema: 1,
      date: DAY,
      id: ID,
      build: 'other',
      os: 'darwin',
      arch: 'arm64',
      node: '24',
      host: 'other',
      relays: {},
      cli: {},
      mcp: {},
      sessions: {},
      bridge_starts: {},
      bridge_requests: {},
      audit: {},
      pairing: {},
      pairs: {},
      relay_errors: {},
      cli_durations: {},
      mcp_durations: {},
    })
    await sendable(report)
    const strange = { id: ID, build: null, os: 'aix', arch: 'ia32', node: '20' }
    const odd = buildTelemetryReport(DAY, new Map(), strange)
    expect([odd.build, odd.os, odd.arch, odd.node]).toEqual(['other', 'other', 'other', 'other'])
  })

  it('takes host as the kind with the most sessions in the day, other on a tie or with none', () => {
    const host = (cells: [string, number][]): unknown => buildTelemetryReport(DAY, new Map(cells), FACTS).host
    expect(host([['sessions codex', 3]])).toBe('codex')
    expect(host([['sessions claude-code', 1]])).toBe('claude-code')
    const most: [string, number][] = [
      ['sessions claude-code', 1],
      ['sessions codex', 3],
    ]
    expect(host(most)).toBe('codex')
    const tie: [string, number][] = [
      ['sessions codex', 2],
      ['sessions claude-code', 2],
      ['sessions other', 1],
    ]
    expect(host(tie)).toBe('other')
    expect(host([['cli send 0 ok', 1]])).toBe('other')
  })

  it('buckets every count and lists each map in its sets order: the same bytes whatever the order counted', () => {
    const counted: [string, number][] = [
      ['cli inbox 1 not-found', 1],
      ['cli send 0 ok', 5],
      ['relays relay2', 3],
      ['relays relay1', 1000],
      ['cli_durations send 4', 1],
      ['cli_durations send 0', 3],
    ]
    const a = JSON.stringify(buildTelemetryReport(DAY, new Map(counted), FACTS))
    const b = JSON.stringify(buildTelemetryReport(DAY, new Map([...counted].reverse()), FACTS))
    expect(a).toBe(b)
    const report = JSON.parse(a) as Record<string, unknown>
    expect(JSON.stringify(report.relays)).toBe('{"relay1":512,"relay2":2}')
    expect(JSON.stringify(report.cli)).toBe('{"send":{"0":{"ok":4}},"inbox":{"1":{"not-found":1}}}')
    expect(JSON.stringify(report.cli_durations)).toBe('{"send":[2,0,0,0,1]}')
  })
})

describe('the caps: each family within its cap, the rest summed into other, every report within 4,096 bytes', () => {
  it('keeps a count family largest cells, one fewer than MAX_CELLS, and sums the rest into other', async () => {
    const cells: Cells = new Map()
    const codes = SETS.code.slice(1, 41)
    for (const [i, code] of codes.entries()) addCell(cells, `cli send 1 ${code}`, 100 + i)
    addCell(cells, 'cli other other other', 7)
    const report = buildTelemetryReport(DAY, cells, FACTS)
    const cli = new Map(leaves(report.cli))
    expect(cli.size).toBe(MAX_CELLS.cli)
    for (const [i, code] of codes.entries()) {
      expect(cli.get(`send 1 ${code}`), code).toBe(i >= codes.length - 11 ? bucket(100 + i) : undefined)
    }
    expect(cli.get('other other other')).toBe(bucket(7 + 29 * 114))
    await sendable(report)
  })

  it('keeps a duration family keys of the most calls, one fewer than MAX_KEYS, others summed bucket by bucket', () => {
    const cells: Cells = new Map()
    const commands = SETS.command.slice(0, 20)
    for (const [i, command] of commands.entries()) {
      addCell(cells, `cli_durations ${command} 0`, i + 1)
      addCell(cells, `cli_durations ${command} 3`, 1)
    }
    const report = buildTelemetryReport(DAY, cells, FACTS)
    const rows = report.cli_durations as Record<string, number[]>
    expect(Object.keys(rows)).toEqual([...commands.slice(-7), 'other'])
    expect(rows[commands[19] as string]).toEqual([bucket(20), 0, 0, bucket(1), 0])
    expect(rows.other).toEqual([bucket(91), 0, 0, bucket(13), 0])
  })

  it('cuts a spool far over every cap to the caps, with the sums in other, within 4,096 bytes', async () => {
    const cells: Cells = new Map()
    let k = 1
    for (const [name, m] of Object.entries(MEMBERS)) {
      const sets: readonly SetName[] = m.kind === 'counts' ? m.keys : m.kind === 'hist' ? [m.key] : []
      const longest = sets.map((set) => [...SETS[set]].sort((x, y) => y.length - x.length))
      for (let i = 0; i < 30 && sets.length > 0; i++) {
        const path = longest.map((values, level) => values[level === 0 ? i % values.length : 0])
        const tail = m.kind === 'hist' ? [' 0', ' 1', ' 2', ' 3', ' 4'] : ['']
        for (const t of tail) addCell(cells, `${name} ${path.join(' ')}${t}`, 2 ** 30 - k++)
      }
    }
    const report = buildTelemetryReport(DAY, cells, FACTS)
    for (const [name, cap] of Object.entries(MAX_CELLS)) {
      expect(leaves(report[name]).length, name).toBeLessThanOrEqual(cap)
    }
    for (const [name, cap] of Object.entries(MAX_KEYS)) {
      expect(Object.keys(report[name] as object).length, name).toBe(cap)
    }
    const bytes = Buffer.byteLength(JSON.stringify(report))
    console.log(`MEASURE telemetry client report at every cap: ${bytes} bytes of ${MAX_BYTES}`)
    await sendable(report)
  })
})

/** A small seeded PRNG (mulberry32), so a failing case can be run again. */
function prng(seed: number): () => number {
  let a = seed
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** What a report must never carry: a test address, a path, a relay URL, a hostname, an identity, a raw code. */
const SEEDED = [
  `ed25519:${'c4'.repeat(32)}`,
  '/Users/alice/.bag/state/alice/audit.jsonl',
  'https://relay.example.com',
  'wss://relay1.bag.dev/v0/subscribe',
  'alice-macbook.local',
  'alice',
  'alice@acme.example',
  'ENOENT',
  'http-503',
  '127.0.0.1',
]

const ALLOWED = new Set<string>([...Object.values(SETS).flat(), ...Object.keys(MEMBERS), DAY, ID])

/** Every string a value holds: its keys and its string leaves. */
function strings(v: unknown): string[] {
  if (typeof v === 'string') return [v]
  if (Array.isArray(v)) return v.flatMap(strings)
  if (typeof v !== 'object' || v === null) return []
  return Object.entries(v).flatMap(([k, x]) => [k, ...strings(x)])
}

/** A random tree in the store's shape: keys from the sets or SEEDED, leaves mostly counts, some not. */
function randomTree(next: () => number): Record<string, unknown> {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(next() * list.length)] as T
  const key = (set: SetName): string => (next() < 0.6 ? pick(SETS[set]) : pick(SEEDED))
  const leaf = (): unknown => pick([1, 2, 7, 1000, 2 ** 40, -1, 1.5, 'x', null, { deep: 1 }])
  const branch = (sets: readonly SetName[]): unknown => {
    const [set, ...rest] = sets
    if (set === undefined) return leaf()
    const out: Record<string, unknown> = {}
    const count = 1 + Math.floor(next() * 6)
    for (let i = 0; i < count; i++) out[key(set)] = branch(rest)
    return out
  }
  const tree: Record<string, unknown> = {}
  for (const [name, m] of Object.entries(MEMBERS)) {
    if (m.kind === 'counts') tree[name] = branch(m.keys)
    if (m.kind !== 'hist') continue
    const rows: Record<string, unknown> = {}
    const count = Math.floor(next() * 12)
    for (let i = 0; i < count; i++) rows[key(m.key)] = SETS.duration.map(leaf)
    tree[next() < 0.9 ? name : pick(SEEDED)] = rows
  }
  tree[pick(SEEDED)] = { [pick(SEEDED)]: 1 }
  return tree
}

describe('the property: no report carries a string outside the schema sets, whatever the spool holds', () => {
  it('holds over 300 random spools seeded with addresses, paths, relay URLs, hostnames and identities', async () => {
    const next = prng(20261102)
    for (let round = 0; round < 300; round++) {
      const cells: Cells = new Map()
      addTree(cells, randomTree(next))
      const report = buildTelemetryReport(DAY, cells, FACTS)
      const text = JSON.stringify(report)
      for (const s of strings(report)) expect(ALLOWED.has(s), `round ${round}: ${s}`).toBe(true)
      for (const s of SEEDED) expect(text, `round ${round}`).not.toContain(s)
      if (round % 30 === 0) await sendable(report)
    }
  })

  it('holds for the machine spool as read, every line written by hand, and for the preview of a machine', async () => {
    const home = join(tmp.dir, `home-${n++}`)
    const dir = join(home, '.bag')
    setTelemetry(dir, 'on', systemRng)
    const next = prng(7)
    const rows = Array.from({ length: 40 }, () => ({ v: 1, day: DAY, counts: randomTree(next) }))
    writeFileSync(join(dir, TELEMETRY_COUNTS_FILE), `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`)
    const report = telemetryReport({ HOME: home }, DAY)
    expect(report.id).toBe(telemetryId(dir))
    const cells = readTelemetrySpool(dir).get(DAY) ?? new Map()
    expect(report).toEqual(buildTelemetryReport(DAY, cells, machineFacts(telemetryId(dir) as string)))
    const allowed = new Set([...ALLOWED, telemetryId(dir) as string])
    for (const s of strings(report)) expect(allowed.has(s), s).toBe(true)
    for (const s of [...SEEDED, home]) expect(JSON.stringify(report)).not.toContain(s)
    await sendable(report)
  })

  it('previews with the placeholder id and no counts where telemetry has never been on', () => {
    const report = telemetryReport({ HOME: join(tmp.dir, `home-${n++}`) }, DAY)
    expect(report.id).toBe(PREVIEW_ID)
    expect(telemetryReport({}, DAY)).toEqual(report)
    const families = Object.values(report).filter((v) => typeof v === 'object')
    expect(families).toEqual(Array.from({ length: 12 }, () => ({})))
  })
})

describe('the facts: the checkout commit, a cut only by the list, and the machine', () => {
  it('reads HEAD detached, a loose or packed ref, and nothing else', () => {
    const repo = (head: string, files: Record<string, string> = {}): string => {
      const root = join(tmp.dir, `repo-${n++}`)
      mkdirSync(join(root, '.git', 'refs', 'heads'), { recursive: true })
      writeFileSync(join(root, '.git', 'HEAD'), head)
      for (const [name, text] of Object.entries(files)) writeFileSync(join(root, '.git', name), text)
      return root
    }
    const [c, d] = ['c'.repeat(40), 'd'.repeat(40)]
    const packed = `# pack-refs with: peeled\n${d} refs/heads/main\n`
    expect(checkoutCommit(repo(`${c}\n`))).toBe(c)
    expect(checkoutCommit(repo('ref: refs/heads/main\n', { 'refs/heads/main': `${c}\n` }))).toBe(c)
    expect(checkoutCommit(repo('ref: refs/heads/main\n', { 'packed-refs': packed }))).toBe(d)
    expect(checkoutCommit(repo('ref: refs/heads/gone\n'))).toBeNull()
    expect(checkoutCommit(repo('not a commit'))).toBeNull()
    expect(checkoutCommit(join(tmp.dir, 'no-repo'))).toBeNull()
    const worktree = join(tmp.dir, `worktree-${n++}`)
    mkdirSync(worktree)
    writeFileSync(join(worktree, '.git'), 'gitdir: /elsewhere/.git/worktrees/x\n')
    expect(checkoutCommit(worktree)).toBeNull()
    const odd = join(tmp.dir, `odd-${n++}`)
    mkdirSync(join(odd, '.git', 'HEAD'), { recursive: true })
    expect(checkoutCommit(odd)).toBeNull()
  })

  it('names this machine: its commit, platform, arch and Node major, each placed when the report is built', () => {
    const facts = machineFacts(ID)
    expect(facts).toMatchObject({ id: ID, os: process.platform, arch: process.arch })
    expect(facts.node).toBe(process.versions.node.split('.')[0])
    expect(facts.build === null || /^[0-9a-f]{40}$/.test(facts.build)).toBe(true)
    const cut = facts.build !== null && BUILDS.includes(facts.build)
    expect(buildTelemetryReport(DAY, new Map(), facts).build).toBe(cut ? facts.build : 'other')
  })
})
