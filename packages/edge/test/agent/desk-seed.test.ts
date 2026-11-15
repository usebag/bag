import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  AcError,
  buildEnvelope,
  DEFAULT_WINDOW,
  newThread,
  parseEnvelope,
  type SealedContent,
  type Thread,
} from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SqliteStore } from '../../src/adapters/sqlite-store.ts'
import {
  type EnvelopeOpener,
  FrontDesk,
  type FrontDeskOptions,
  seedFromStore,
} from '../../src/agent/index.ts'
import type { InboxState } from '../../src/ports.ts'
import { P, T0, tempDir } from '../support/fixtures.ts'

// The front desk's ledger seeded from the principal's own store: the roots a plain server, the CLI or a 0.1 server
// accepted there, read only, merged into desk-handled at every desk start so a session's desk does not answer them
// again when its fresh store replays them (scenario 47e2).

const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))
const STALE = DEFAULT_WINDOW.ttl + DEFAULT_WINDOW.skew

/** A message from bob to jane on `thread` at `ts`: its bytes, id and content. */
function message(thread: Thread, ts = T0): { bytes: Uint8Array; id: string; content: SealedContent } {
  const content = { type: 'chat.v1', thread, body: 'hi' }
  const { bytes } = buildEnvelope({
    from: P.bob.signing,
    to: [{ address: P.jane.address, sealingKey: P.jane.sealing.publicKey }],
    ...content,
    ts,
    rng,
  })
  return { bytes, id: parseEnvelope(bytes).id, content }
}

const root = (ts = T0) => message(newThread(rng), ts)

/** Timers that never fire: these cases take the desk at once. */
const timers = { after: () => () => {} }

describe('seedFromStore and the desk merge', () => {
  let tmp: ReturnType<typeof tempDir>
  let cursor = 0
  const store = (): string => join(tmp.dir, 'edge.sqlite')
  const ledger = (): string => join(tmp.dir, 'desk-handled')

  /** Puts `m` into the store as a row in `state`, its content kept as the edge keeps it (none: content null). */
  const put = (
    s: SqliteStore,
    m: { bytes: Uint8Array; id: string; content: SealedContent },
    state: InboxState,
    content = true,
  ) => {
    const row = s.inboxAdd('http://r', 'm', ++cursor, m.bytes, T0)
    s.inboxPut(row, { state, id: m.id, content: content ? JSON.stringify(m.content) : null }, T0)
  }

  const desk = (more: Omit<FrontDeskOptions, 'lock'> = {}): FrontDesk =>
    new FrontDesk(tmp.dir, timers, {
      lock: { pid: 1, start: 1, alive: () => true, startOf: () => 1 },
      now: () => T0,
      seed: () => seedFromStore(store()),
      ...more,
    })

  const opener = (m: { id: string; content: SealedContent }): EnvelopeOpener => ({
    publicKey: P.jane.sealing.publicKey,
    open: (): never => {
      throw new Error('the agent opens whole envelopes')
    },
    openEnvelope: async () => m.content,
  })

  beforeEach(() => {
    tmp = tempDir('desk-seed')
  })

  afterEach(() => tmp.cleanup())

  it('takes the roots in an accepted state, with their ts, and leaves out the rest', () => {
    const s = new SqliteStore(store())
    const accepted = (['verified', 'routed', 'queued', 'acked', 'consumed'] as const).map((state) => {
      const m = root(T0 + cursor)
      put(s, m, state)
      return m
    })
    for (const state of ['received', 'rejected', 'quarantined'] as const) put(s, root(), state)
    const parent = root()
    put(s, message({ ...parent.content.thread, prev: [parent.id] }), 'acked') // a reply
    put(s, root(), 'acked', false) // no content: whether it is a root cannot be read
    s.close()
    const got = seedFromStore(store())
    expect(got.map((r) => r.id).sort()).toEqual(accepted.map((m) => m.id).sort())
    for (const m of accepted) expect(got.find((r) => r.id === m.id)?.ts).toBe(parseEnvelope(m.bytes).ts)
  })

  it('never writes the store: its bytes and mtime are the same, and only an empty WAL index pair may appear beside it', () => {
    const s = new SqliteStore(store())
    put(s, root(), 'acked')
    s.close()
    const files = readdirSync(tmp.dir).sort()
    const [bytes, mtime] = [readFileSync(store()), statSync(store()).mtimeMs]
    expect(seedFromStore(store())).toHaveLength(1)
    expect(readFileSync(store()).equals(bytes)).toBe(true)
    expect(statSync(store()).mtimeMs).toBe(mtime)
    // A read-only connection to a WAL store may leave SQLite's WAL index pair beside it (as the edge's own writer
    // does, and the next writer's close removes); the -wal holds no frame, so no row was written.
    const added = readdirSync(tmp.dir).filter((f) => !files.includes(f))
    expect(added.every((f) => f === 'edge.sqlite-wal' || f === 'edge.sqlite-shm')).toBe(true)
    if (added.includes('edge.sqlite-wal')) expect(statSync(join(tmp.dir, 'edge.sqlite-wal')).size).toBe(0)
    const mode = statSync(store()).mode & 0o777
    for (const f of added) expect(statSync(join(tmp.dir, f)).mode & 0o777).toBe(mode) // never wider than the store
  })

  it('reads the oldest inbox schema of the fixtures as it is, without migrating it', () => {
    // The inbox of a store made before tries and next_at (sqlite-store.test.ts, "a store made before them").
    const m = root()
    const db = new DatabaseSync(store())
    db.exec(`CREATE TABLE inbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, relay TEXT NOT NULL, mailbox TEXT NOT NULL,
      cursor INTEGER NOT NULL, bytes BLOB NOT NULL, id TEXT, state TEXT NOT NULL, reason TEXT, session TEXT,
      content TEXT, received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE (relay, mailbox, cursor)) STRICT`)
    db.prepare(
      "INSERT INTO inbox (relay, mailbox, cursor, bytes, id, state, content, received_at, updated_at) VALUES ('http://r', 'm', 4, ?, ?, 'acked', ?, 1, 1)",
    ).run(m.bytes, m.id, JSON.stringify(m.content))
    db.close()
    const bytes = readFileSync(store())
    expect(seedFromStore(store())).toEqual([{ id: m.id, ts: T0 }])
    expect(readFileSync(store()).equals(bytes)).toBe(true)
  })

  it("reads the inbox of the 0.1 cut's own schema (tag v0.1.2's inboxTable) as it is, without migrating it", () => {
    // packages/edge/src/adapters/sqlite-store.ts at v0.1.2, the inbox table word for word: a 0.1 server's store.
    const m = root()
    const db = new DatabaseSync(store())
    db.exec(`CREATE TABLE IF NOT EXISTS inbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, relay TEXT NOT NULL, mailbox TEXT NOT NULL,
  cursor INTEGER NOT NULL, bytes BLOB NOT NULL, id TEXT, state TEXT NOT NULL, reason TEXT, session TEXT, content TEXT,
  received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, next_at INTEGER) STRICT;`)
    db.prepare(
      "INSERT INTO inbox (relay, mailbox, cursor, bytes, id, state, content, received_at, updated_at) VALUES ('http://r', 'm', 1, ?, ?, 'acked', ?, 1, 1)",
    ).run(m.bytes, m.id, JSON.stringify(m.content))
    db.close()
    const bytes = readFileSync(store())
    expect(seedFromStore(store())).toEqual([{ id: m.id, ts: T0 }])
    expect(readFileSync(store()).equals(bytes)).toBe(true)
  })

  it('gives none for no store, a store with no inbox, an inbox lacking a column it reads, and a row that does not parse', () => {
    expect(seedFromStore(store())).toEqual([])
    const db = new DatabaseSync(store())
    db.exec('CREATE TABLE other (x INTEGER)')
    expect(seedFromStore(store())).toEqual([])
    db.exec(
      "CREATE TABLE inbox (seq INTEGER PRIMARY KEY, bytes BLOB, id TEXT, state TEXT); INSERT INTO inbox VALUES (1, x'00', 'aa', 'acked')",
    )
    expect(seedFromStore(store())).toEqual([])
    db.exec('DROP TABLE inbox')
    db.exec(
      "CREATE TABLE inbox (seq INTEGER PRIMARY KEY, bytes BLOB, id TEXT, state TEXT, content TEXT); INSERT INTO inbox VALUES (1, x'00', 'aa', 'acked', '{\"thread\":{\"prev\":[]}}'), (2, x'00', 'bb', 'acked', 'not json')",
    )
    db.close()
    expect(seedFromStore(store())).toEqual([])
  })

  it("refuses a seeded root desk-answered at the session's first desk, and still takes and appends a new one", async () => {
    const old = root()
    const s = new SqliteStore(store())
    put(s, old, 'acked')
    s.close()
    const d = desk()
    d.start()
    expect(d.desk).toBe(true)
    expect(readFileSync(ledger(), 'utf8')).toBe(`${old.id} ${T0}\n`)
    const e = await d
      .wrap(opener(old), () => false)
      .openEnvelope(old.bytes)
      .catch((x: unknown) => x)
    expect(e).toBeInstanceOf(AcError)
    expect((e as Error).message).toMatch(/desk-answered:/)
    const fresh = root()
    expect(await d.wrap(opener(fresh), () => false).openEnvelope(fresh.bytes)).toEqual(fresh.content)
    expect(readFileSync(ledger(), 'utf8')).toBe(`${old.id} ${T0}\n${fresh.id} ${T0}\n`)
  })

  it('merges at every desk start: a root accepted after the ledger existed is added, the lines there are kept', () => {
    const earlier = root()
    writeFileSync(ledger(), `${earlier.id} ${T0}\n`, { mode: 0o600 })
    const later = root()
    const s = new SqliteStore(store())
    put(s, later, 'consumed') // the CLI's reader took it while no desk ran
    s.close()
    const d = desk()
    d.start()
    expect(readFileSync(ledger(), 'utf8')).toBe(`${earlier.id} ${T0}\n${later.id} ${T0}\n`)
    expect(statSync(ledger()).mode & 0o777).toBe(0o600)
  })

  it('writes nothing when nothing is missing: an empty seed leaves no ledger, a seed the ledger holds leaves it as it was', () => {
    desk().start()
    expect(existsSync(ledger())).toBe(false)
    const m = root()
    const s = new SqliteStore(store())
    put(s, m, 'acked')
    s.close()
    writeFileSync(ledger(), `${m.id} ${T0}\n`, { mode: 0o600 })
    const ino = statSync(ledger()).ino
    desk().start()
    expect(statSync(ledger()).ino).toBe(ino) // not replaced
    expect(readFileSync(ledger(), 'utf8')).toBe(`${m.id} ${T0}\n`)
  })

  it('leaves out a seeded root past ts + ttl + skew, which the edge refuses as stale anyway', () => {
    const [stale, live] = [root(T0 - STALE - 1), root(T0 - STALE)]
    const s = new SqliteStore(store())
    put(s, stale, 'acked')
    put(s, live, 'acked')
    s.close()
    desk().start()
    expect(readFileSync(ledger(), 'utf8')).toBe(`${live.id} ${T0 - STALE}\n`)
  })

  it('starts the desk and tells the server when the ledger cannot be written, reporting the fault', () => {
    const s = new SqliteStore(store())
    put(s, root(), 'acked')
    s.close()
    mkdirSync(join(tmp.dir, 'desk-handled.tmp')) // replaceDurable's temporary file cannot be opened
    const faults: unknown[] = []
    let told = 0
    const d = desk({ onError: (e) => faults.push(e), onDesk: () => told++ })
    d.start()
    expect([d.desk, told, faults.length]).toEqual([true, 1, 1])
    expect(existsSync(ledger())).toBe(false)
  })

  it('starts the desk when the seed throws, reports the fault, and keeps the ledger as it was', () => {
    writeFileSync(ledger(), `aa ${T0}\n`, { mode: 0o600 })
    const faults: unknown[] = []
    const d = desk({
      seed: () => {
        throw new Error('a bad store')
      },
      onError: (e) => faults.push(e),
    })
    d.start()
    expect(d.desk).toBe(true)
    expect(faults).toEqual([new Error('a bad store')])
    expect(readFileSync(ledger(), 'utf8')).toBe(`aa ${T0}\n`)
  })
})
