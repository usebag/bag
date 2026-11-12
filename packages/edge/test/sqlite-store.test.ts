import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterAll, describe, expect, it } from 'vitest'
import { readAuditAnchor, SqliteStore, storeLockPath } from '../src/adapters/sqlite-store.ts'
import { sealedTarget, startTry, tryFailed } from '../src/outbox.ts'
import { T0, tempDir } from './support/fixtures.ts'

const tmp = tempDir('sqlite')
afterAll(() => tmp.cleanup())

const ID = 'aa'.repeat(32)
const BYTES = new Uint8Array([123, 34, 118, 34, 58, 49, 125])

describe('opening beside another process in the file', () => {
  it('waits for a lock it meets at the WAL pragma, and fails nothing: the busy timeout comes first', async () => {
    const path = join(tmp.dir, 'contended.sqlite')
    // Another process holds the database in a lock the pragma needs, here a file not yet in WAL mode, for 400 ms.
    const script = `
      const { DatabaseSync } = require('node:sqlite')
      const db = new DatabaseSync(${JSON.stringify(path)})
      db.exec('CREATE TABLE t (x INTEGER); BEGIN EXCLUSIVE')
      console.log('held')
      setTimeout(() => { db.exec('COMMIT'); db.close() }, 400)
    `
    const holder = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'ignore'] })
    await new Promise<void>((resolve) => holder.stdout.once('data', () => resolve()))
    const start = Date.now()
    const store = new SqliteStore(path, { lock: false })
    expect(Date.now() - start).toBeGreaterThan(100)
    store.close()
    await new Promise((resolve) => holder.once('exit', resolve))
  })
})

describe('SqliteStore on node:sqlite, with real files', () => {
  it('creates its file with mode 0600, in WAL mode, and keeps everything across a fresh instance', () => {
    const path = join(tmp.dir, 'edge.sqlite')
    const a = new SqliteStore(path)
    expect(statSync(path).mode & 0o777).toBe(0o600)
    a.outboxAdd({ id: ID, bytes: BYTES, thread: 'th', session: 's', createdAt: T0 }, [
      sealedTarget(ID, 'http://r2', T0),
      sealedTarget(ID, 'http://r1', T0),
    ])
    const row = a.inboxAdd('http://r1', 'mbox', 7, BYTES, T0)
    a.inboxPut(row, { state: 'rejected', reason: 'bad-sig', id: ID }, T0 + 1)
    a.seenAdd(ID, T0, T0 + 10)
    a.threadSet('th', 's', T0)
    a.pinPut({ subject: 'domain:a', key: 'k', record: BYTES, pinnedAt: T0, updatedAt: T0 })
    a.cachePut('domain:a', 'address', BYTES, T0 + 60)
    expect(existsSync(`${path}-wal`)).toBe(true)
    a.close()

    const db = new DatabaseSync(path)
    expect(db.prepare('PRAGMA journal_mode').get()).toEqual({ journal_mode: 'wal' })
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    // The org policy's five tables, the fs_known marker, the waiting sends and the returned marks beside the eight stores.
    expect(tables.all().map((t) => t.name)).toEqual([
      'audit_anchor',
      'contacts',
      'fs_known',
      'held_sends',
      'holds',
      'inbox',
      'outbox',
      'outbox_targets',
      'pins',
      'policy_counts',
      'receipts',
      'record_cache',
      'returned',
      'seen',
      'sends',
      'threads',
      'waiting',
    ])
    db.close()

    const b = new SqliteStore(path)
    expect(b.outboxGet(ID)).toEqual({ id: ID, bytes: BYTES, thread: 'th', session: 's', createdAt: T0 })
    expect(b.outboxTargets(ID).map((t) => t.relay)).toEqual(['http://r1', 'http://r2'])
    expect(b.inboxFind('http://r1', 'mbox', 7)).toMatchObject({
      state: 'rejected',
      reason: 'bad-sig',
      id: ID,
      bytes: BYTES,
    })
    expect(b.seenHas(ID, T0 + 10)).toBe(true)
    expect(b.threadGet('th')).toBe('s')
    expect(b.pinGet('domain:a')).toEqual({
      subject: 'domain:a',
      key: 'k',
      record: BYTES,
      pinnedAt: T0,
      updatedAt: T0,
    })
    expect(b.cacheGet('domain:a', 'address', T0 + 59)).toEqual(BYTES)
    b.close()
  })

  it('opens an existing file without changing it, and an in-memory store', () => {
    const path = join(tmp.dir, 'again.sqlite')
    new SqliteStore(path).close()
    const s = new SqliteStore(path)
    expect(s.outboxGet(ID)).toBeNull()
    s.close()
    const m = new SqliteStore(':memory:')
    expect(m.inboxList()).toEqual([])
    m.close()
  })

  it('lists the due targets with their bytes: sealed, publishing, and retry whose time has come', () => {
    const s = new SqliteStore(':memory:')
    const ids = ['01', '02', '03', '04'].map((b) => b.repeat(32))
    for (const id of ids)
      s.outboxAdd({ id, bytes: BYTES, thread: 't', session: null, createdAt: T0 }, [
        sealedTarget(id, 'http://r', T0),
      ])
    const [, b, c, d] = ids.map((id) => s.outboxTargets(id)[0]) as [
      never,
      ...ReturnType<SqliteStore['outboxTargets']>,
    ]
    s.outboxPut(startTry(b as NonNullable<typeof b>, T0 + 1))
    const lost = {
      reason: 'publish-failed',
      permanent: false,
      retryAfter: null,
      horizon: T0 + 604_800,
      jitter: 0,
    } as const
    s.outboxPut(tryFailed(startTry(c as NonNullable<typeof c>, T0), T0 + 2, lost))
    s.outboxPut({ ...(d as NonNullable<typeof d>), state: 'published', updatedAt: T0 + 3 })
    expect(s.outboxDue(T0 + 2).map((x) => x.target.id)).toEqual([ids[0], ids[1]])
    const due = s.outboxDue(T0 + 3)
    expect(due.map((x) => x.target.id)).toEqual([ids[0], ids[1], ids[2]])
    expect(due[2]).toEqual({
      target: {
        ...(c as object),
        state: 'retry',
        tries: 1,
        nextAt: T0 + 3,
        reason: 'publish-failed',
        updatedAt: T0 + 2,
      },
      bytes: BYTES,
    })
    s.close()
  })

  it('keeps inbox rows by relay, mailbox and cursor, and finds the last acked cursor', () => {
    const s = new SqliteStore(':memory:')
    expect(s.inboxLastAcked('http://r', 'm')).toBeNull()
    const one = s.inboxAdd('http://r', 'm', 1, BYTES, T0)
    s.inboxAdd('http://r', 'm', 2, BYTES, T0)
    s.inboxAdd('http://other', 'm', 9, BYTES, T0)
    const acked = s.inboxPut(
      s.inboxPut(one, { state: 'rejected', reason: 'duplicate' }, T0),
      { state: 'acked' },
      T0 + 1,
    )
    expect(acked).toMatchObject({ state: 'acked', reason: 'duplicate', updatedAt: T0 + 1 })
    expect(s.inboxLastAcked('http://r', 'm')).toBe(1)
    expect(s.inboxList().map((r) => r.cursor)).toEqual([1, 2, 9])
    expect(s.inboxList(['received']).map((r) => r.cursor)).toEqual([2, 9])
    expect(s.inboxFind('http://r', 'm', 3)).toBeNull()
    s.close()
  })

  it('keeps a seen id through its expiry second, replaces an entry, and prunes the expired', () => {
    const s = new SqliteStore(':memory:')
    s.seenAdd(ID, T0, T0 + 5)
    expect([s.seenHas(ID, T0 + 5), s.seenHas(ID, T0 + 6), s.seenHas('bb'.repeat(32), T0)]).toEqual([
      true,
      false,
      false,
    ])
    s.seenAdd(ID, T0 + 6, T0 + 20)
    expect(s.seenHas(ID, T0 + 20)).toBe(true)
    expect(s.seenPrune(T0 + 20)).toBe(0)
    expect(s.seenPrune(T0 + 21)).toBe(1)
    s.close()
  })

  it('replaces a thread binding, a pin and a cached record, and expires the cache at its time', () => {
    const s = new SqliteStore(':memory:')
    expect([s.threadGet('t'), s.pinGet('p'), s.cacheGet('c', 'key', T0)]).toEqual([null, null, null])
    s.threadSet('t', 'a', T0)
    s.threadSet('t', 'b', T0)
    expect(s.threadGet('t')).toBe('b')
    s.pinPut({ subject: 'p', key: 'k1', record: null, pinnedAt: T0, updatedAt: T0 })
    s.pinPut({ subject: 'p', key: 'k2', record: BYTES, pinnedAt: T0 + 1, updatedAt: T0 + 1 })
    expect(s.pinGet('p')).toEqual({
      subject: 'p',
      key: 'k2',
      record: BYTES,
      pinnedAt: T0 + 1,
      updatedAt: T0 + 1,
    })
    s.cachePut('c', 'key', BYTES, T0 + 1)
    s.cachePut('c', 'key', new Uint8Array([1]), T0 + 2)
    expect(s.cacheGet('c', 'key', T0 + 1)).toEqual(new Uint8Array([1]))
    expect(s.cacheGet('c', 'key', T0 + 2)).toBeNull()
    expect(s.cacheGet('c', 'address', T0)).toBeNull()
    s.close()
  })

  it('ratchets the fs-known marker on once set, idempotently, and keeps it across a fresh store (durable)', () => {
    const path = join(tmp.dir, 'fs-known.sqlite')
    const s = new SqliteStore(path)
    const subject = `address:${'ab'.repeat(32)}`
    expect(s.fsKnownGet(subject)).toBe(false)
    expect(s.fsKnownGet('address:other')).toBe(false)
    s.fsKnownSet(subject)
    expect(s.fsKnownGet(subject)).toBe(true)
    s.fsKnownSet(subject) // idempotent: a second set is a no-op, not a throw
    expect(s.fsKnownGet(subject)).toBe(true)
    expect(s.fsKnownGet('address:other')).toBe(false)
    s.close()
    // A fresh store over the same file still reads it: the marker is durable, not in-memory.
    const b = new SqliteStore(path)
    expect(b.fsKnownGet(subject)).toBe(true)
    expect(b.fsKnownGet('address:other')).toBe(false)
    b.close()
  })

  it('(f) gains the fs_known table for a store made before the marker, reading its old pins as fs-known false', () => {
    const dir = join(tmp.dir, 'old-fs-known')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    // An older store: a pins table with a row, and no fs_known table at all.
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE pins (subject TEXT PRIMARY KEY, key TEXT NOT NULL, record BLOB, pinned_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL) STRICT`)
    const subject = `address:${'cd'.repeat(32)}`
    db.prepare(
      'INSERT INTO pins (subject, key, record, pinned_at, updated_at) VALUES (?, ?, NULL, 1, 1)',
    ).run(subject, 'k')
    db.close()
    const s = new SqliteStore(path)
    // The pin row survives, and the gained fs_known table reads empty: an existing pin is fs-known false.
    expect(s.pinGet(subject)).toMatchObject({ subject, key: 'k' })
    expect(s.fsKnownGet(subject)).toBe(false)
    // The ratchet works on the migrated store, and persists on reopen.
    s.fsKnownSet(subject)
    expect(s.fsKnownGet(subject)).toBe(true)
    s.close()
    const b = new SqliteStore(path)
    expect(b.fsKnownGet(subject)).toBe(true)
    b.close()
  })

  it("records a thread binding's last use, and prunes the bindings last used before a time", () => {
    const s = new SqliteStore(':memory:')
    s.threadSet('old', 'a', T0)
    s.threadSet('used', 'a', T0)
    s.threadTouch('used', T0 + 50)
    // A touch binds nothing; a second threadSet is a use too.
    s.threadTouch('unbound', T0 + 50)
    s.threadSet('rebound', 'a', T0)
    s.threadSet('rebound', 'b', T0 + 40)
    expect(s.threadGet('unbound')).toBeNull()
    expect(s.threadsPrune(T0)).toBe(0)
    expect(s.threadsPrune(T0 + 40)).toBe(1)
    expect([s.threadGet('old'), s.threadGet('rebound'), s.threadGet('used')]).toEqual([null, 'b', 'a'])
    expect(s.threadsPrune(T0 + 41)).toBe(1)
    expect(s.threadsPrune(T0 + 50)).toBe(0)
    expect(s.threadsPrune(T0 + 51)).toBe(1)
    s.close()
  })

  it("round-trips a 'handle' cache entry, the port's CacheKind, beside a record kind of the same subject", () => {
    const s = new SqliteStore(':memory:')
    s.cachePut('handle:jane@acme.test', 'handle', BYTES, T0 + 60)
    s.cachePut('handle:jane@acme.test', 'address', new Uint8Array([2]), T0 + 60)
    expect(s.cacheGet('handle:jane@acme.test', 'handle', T0)).toEqual(BYTES)
    expect(s.cacheGet('handle:jane@acme.test', 'address', T0)).toEqual(new Uint8Array([2]))
    expect(s.cacheGet('handle:jane@acme.test', 'handle', T0 + 60)).toBeNull()
    s.close()
  })

  it('rolls a transaction back when it throws, and runs a nested one inside the open one', () => {
    const s = new SqliteStore(':memory:')
    expect(() =>
      s.transaction(() => {
        s.threadSet('t', 'a', T0)
        throw new Error('boom')
      }),
    ).toThrow('boom')
    expect(s.threadGet('t')).toBeNull()
    const out = s.transaction(() =>
      s.transaction(() => {
        s.threadSet('t', 'b', T0)
        return 7
      }),
    )
    expect([out, s.threadGet('t')]).toEqual([7, 'b'])
    s.close()
  })

  it('rejects an outbox entry whose targets would not persist, leaving nothing behind', () => {
    const s = new SqliteStore(':memory:')
    const t = sealedTarget(ID, 'http://r', T0)
    expect(() =>
      s.outboxAdd({ id: ID, bytes: BYTES, thread: 't', session: null, createdAt: T0 }, [t, t]),
    ).toThrow()
    expect(s.outboxGet(ID)).toBeNull()
    s.close()
  })
})

describe('SqliteStore: the inbox columns and retry state', () => {
  it('keeps the try count and next_at of an inbox row, and lists the due rows of a mailbox at a relay', () => {
    const s = new SqliteStore(':memory:')
    const a = s.inboxAdd('http://r', 'm', 1, BYTES, T0)
    const b = s.inboxAdd('http://r', 'm', 2, BYTES, T0)
    s.inboxAdd('http://other', 'm', 3, BYTES, T0)
    expect([a.tries, a.nextAt]).toEqual([0, null])
    s.inboxPut(a, { state: 'received', reason: 'resolve-failed', tries: 1, nextAt: T0 + 1 }, T0)
    s.inboxPut(b, { state: 'received', reason: 'future-ts', tries: 3, nextAt: T0 + 9 }, T0)
    expect(s.inboxDue('http://r', 'm', T0).map((r) => r.cursor)).toEqual([])
    expect(s.inboxDue('http://r', 'm', T0 + 1)).toEqual([
      expect.objectContaining({ cursor: 1, tries: 1, nextAt: T0 + 1, reason: 'resolve-failed' }),
    ])
    expect(s.inboxDue('http://r', 'm', T0 + 9).map((r) => r.cursor)).toEqual([1, 2])
    expect(s.inboxDue('http://r', 'other-mailbox', T0 + 9)).toEqual([])
    s.close()
  })

  it('adds the new inbox columns to a store made before them, keeping its rows', () => {
    const dir = join(tmp.dir, 'old')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE inbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, relay TEXT NOT NULL, mailbox TEXT NOT NULL,
      cursor INTEGER NOT NULL, bytes BLOB NOT NULL, id TEXT, state TEXT NOT NULL, reason TEXT, session TEXT,
      content TEXT, received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE (relay, mailbox, cursor)) STRICT`)
    db.prepare(
      "INSERT INTO inbox (relay, mailbox, cursor, bytes, state, received_at, updated_at) VALUES ('http://r', 'm', 4, ?, 'acked', 1, 1)",
    ).run(BYTES)
    db.close()
    const s = new SqliteStore(path)
    expect(s.inboxFind('http://r', 'm', 4)).toMatchObject({ state: 'acked', tries: 0, nextAt: null })
    s.close()
    // Opening it again finds the columns there.
    new SqliteStore(path).close()
  })

  it('holds two rows at one inbox position: inboxAt gives both, oldest first, inboxFind the newest', () => {
    const s = new SqliteStore(':memory:')
    const one = s.inboxAdd('http://r', 'm', 4, BYTES, 1)
    const two = s.inboxAdd('http://r', 'm', 4, new Uint8Array([1]), 2)
    expect(s.inboxAt('http://r', 'm', 4).map((r) => r.seq)).toEqual([one.seq, two.seq])
    expect(s.inboxFind('http://r', 'm', 4)?.seq).toBe(two.seq)
    expect(s.inboxAt('http://r', 'm', 5)).toEqual([])
    expect(s.inboxFind('http://r', 'm', 5)).toBeNull()
    s.close()
  })

  it('frees an inbox of its unique position at open, once, keeping every row, seq and hold', () => {
    const dir = join(tmp.dir, 'old-unique')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE inbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, relay TEXT NOT NULL, mailbox TEXT NOT NULL,
      cursor INTEGER NOT NULL, bytes BLOB NOT NULL, id TEXT, state TEXT NOT NULL, reason TEXT, session TEXT,
      content TEXT, received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0,
      next_at INTEGER, UNIQUE (relay, mailbox, cursor)) STRICT;
      CREATE TABLE holds (seq INTEGER PRIMARY KEY REFERENCES inbox (seq), rule TEXT NOT NULL, code TEXT NOT NULL,
      detail TEXT, waived TEXT NOT NULL DEFAULT '[]', held_at INTEGER NOT NULL) STRICT;
      INSERT INTO inbox (seq, relay, mailbox, cursor, bytes, id, state, reason, session, content, received_at,
      updated_at, tries, next_at) VALUES (7, 'http://r', 'm', 4, x'00', 'aa', 'quarantined', 'hold', 's', 'c', 1, 2, 3, 9);
      INSERT INTO holds (seq, rule, code, held_at) VALUES (7, 'roots.unknown', 'untrusted-root', 5);`)
    db.close()

    const s = new SqliteStore(path)
    expect(s.inboxAt('http://r', 'm', 4)).toEqual([
      {
        seq: 7,
        relay: 'http://r',
        mailbox: 'm',
        cursor: 4,
        bytes: new Uint8Array([0]),
        id: 'aa',
        state: 'quarantined',
        reason: 'hold',
        session: 's',
        content: 'c',
        receivedAt: 1,
        updatedAt: 2,
        tries: 3,
        nextAt: 9,
      },
    ])
    expect(s.holdGet(7)).toMatchObject({ rule: 'roots.unknown', code: 'untrusted-root' })
    // The same position takes a second row now, and its seq goes on from the kept one.
    expect(s.inboxAdd('http://r', 'm', 4, BYTES, 3).seq).toBe(8)
    // Foreign keys are back on in this very connection: a hold needs its row.
    const hold = { rule: 'roots.unknown', code: 'untrusted-root', detail: null } as const
    expect(() => s.holdPut(99, hold, 1)).toThrow(/FOREIGN KEY/)
    s.close()

    const again = new DatabaseSync(path)
    const unique = again.prepare('PRAGMA index_list(inbox)').all()
    expect(unique.filter((i) => i.origin === 'u')).toEqual([])
    expect(unique.map((i) => i.name)).toEqual(['inbox_position'])
    expect(again.prepare('PRAGMA foreign_key_check').all()).toEqual([])
    expect(again.prepare("SELECT name FROM sqlite_master WHERE name = 'inbox_rebuilt'").all()).toEqual([])
    again.close()

    // Opening it again changes nothing.
    const third = new SqliteStore(path)
    expect(third.inboxAt('http://r', 'm', 4)).toHaveLength(2)
    third.close()
  })

  it('adds used_at to a threads table made before the prune, and prunes its rows by their created_at', () => {
    const dir = join(tmp.dir, 'old-threads')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE threads (thread_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
      created_at INTEGER NOT NULL) STRICT`)
    db.prepare("INSERT INTO threads (thread_id, session_id, created_at) VALUES ('t', 's', 5)").run()
    db.close()
    const s = new SqliteStore(path)
    expect(s.threadGet('t')).toBe('s')
    expect(s.threadsPrune(5)).toBe(0)
    expect(s.threadsPrune(6)).toBe(1)
    s.close()
  })

  it('adds plan to an outbox table made before plans: its rows have none, and a new row keeps one', () => {
    const dir = join(tmp.dir, 'old-outbox')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE outbox (id TEXT PRIMARY KEY, bytes BLOB NOT NULL, thread TEXT NOT NULL, session TEXT,
      created_at INTEGER NOT NULL) STRICT`)
    db.prepare("INSERT INTO outbox (id, bytes, thread, created_at) VALUES ('old', x'00', 't', 5)").run()
    db.close()
    const s = new SqliteStore(path)
    expect(s.outboxPlan('old')).toBeNull()
    s.outboxAdd({ id: 'new', bytes: BYTES, thread: 't', session: null, createdAt: T0 }, [], { plan: '[]' })
    expect(s.outboxPlan('new')).toBe('[]')
    s.outboxPlanPut('old', '[1]')
    expect(s.outboxPlan('old')).toBe('[1]')
    expect(s.outboxPlan('none')).toBeNull()
    s.close()
  })

  it('keeps one anchor per audit log name, replaced by the next, and reads it from a read-only connection', () => {
    const dir = join(tmp.dir, 'anchor')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const s = new SqliteStore(path)
    expect(s.auditAnchorGet('audit.jsonl')).toBeNull()
    s.auditAnchorPut('audit.jsonl', { seq: 1, hash: 'a'.repeat(64) }, T0)
    s.auditAnchorPut('audit.jsonl', { seq: 2, hash: 'b'.repeat(64) }, T0 + 1)
    s.auditAnchorPut('other.jsonl', { seq: 9, hash: 'c'.repeat(64) }, T0)
    expect(s.auditAnchorGet('audit.jsonl')).toEqual({ seq: 2, hash: 'b'.repeat(64) })
    // A reader beside the live store, which holds the lock: audit verify runs while an edge does.
    expect(readAuditAnchor(path, 'audit.jsonl')).toEqual({ seq: 2, hash: 'b'.repeat(64) })
    expect(readAuditAnchor(path, 'missing.jsonl')).toBeNull()
    s.close()
    const bare = join(dir, 'bare.sqlite')
    new DatabaseSync(bare).close()
    expect(readAuditAnchor(bare, 'audit.jsonl')).toBeNull()
    expect(() => readAuditAnchor(join(dir, 'nothing.sqlite'), 'audit.jsonl')).toThrow()
  })

  it('holds the writer lock of its directory from its opening to its close: a second store refuses with busy', () => {
    const dir = join(tmp.dir, 'locked')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const first = new SqliteStore(path)
    const lock = storeLockPath(path)
    expect(lock).toBe(join(dir, 'audit.lock'))
    expect(JSON.parse(readFileSync(lock, 'utf8'))).toMatchObject({ pid: process.pid })
    expect(statSync(lock).mode & 0o777).toBe(0o600)
    expect(() => new SqliteStore(path)).toThrow(expect.objectContaining({ code: 'busy', name: 'EdgeError' }))
    expect(() => new SqliteStore(join(dir, 'other.sqlite'))).toThrow(
      /^busy: .*audit\.lock is held by the process/,
    )
    const unlocked = new SqliteStore(path, { lock: false })
    unlocked.close()
    first.close()
    expect(existsSync(lock)).toBe(false)
    const second = new SqliteStore(path)
    second.close()
    // A second close fails as before, and still leaves no lock behind.
    expect(() => second.close()).toThrow()
    expect(existsSync(lock)).toBe(false)
  })

  it('lets the lock go when the database cannot be opened', () => {
    const dir = join(tmp.dir, 'broken')
    mkdirSync(join(dir, 'edge.sqlite'), { recursive: true })
    expect(() => new SqliteStore(join(dir, 'edge.sqlite'))).toThrow()
    expect(existsSync(join(dir, 'audit.lock'))).toBe(false)
    new SqliteStore(join(dir, 'fine.sqlite')).close()
  })
})
