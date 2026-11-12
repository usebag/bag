import { closeSync, openSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { DatabaseSync, type SQLOutputValue, type StatementSync } from 'node:sqlite'
import type {
  AuditAnchor,
  CacheKind,
  DueTarget,
  EdgeStore,
  HeldSend,
  Hold,
  InboxPatch,
  InboxRow,
  InboxState,
  NamedAnchor,
  OutboxAddOptions,
  OutboxEntry,
  OutboxTarget,
  Pin,
  PolicyCount,
  Receipt,
  WaitingRow,
} from '../ports.ts'
import { acquireLock, type LockOptions } from './fs-lock.ts'

// The EdgeStore on node:sqlite (no native module): one file in WAL mode, STRICT tables for the eight stores, the
// outbox and the inbox holding each envelope's exact bytes. A store on a file holds the writer lock of its directory,
// `audit.lock`, from its opening to its close: every writer of an identity's state opens its store, so a
// second one refuses with `busy`. The org policy's five tables (holds, held sends, sends, contacts and
// counts) and the fs_known table are created when missing, so a store from before them opens and gains them.
// `waiting` holds the sends Sender.sendOrWait keeps: a row's `input` is the message in plaintext, since it cannot be
// sealed yet, in the same 0600 file as the inbox's unsealed content. A session's store keeps it in memory instead.
// The inbox has no unique position: a relay restored from an older copy issues used cursors again, so two envelopes can
// hold one (relay, mailbox, cursor), and the receiver tells them apart by id (spec/SPEC.md §9 item 2).

const inboxTable = (name: string): string =>
  `CREATE TABLE IF NOT EXISTS ${name} (seq INTEGER PRIMARY KEY AUTOINCREMENT, relay TEXT NOT NULL, mailbox TEXT NOT NULL,
  cursor INTEGER NOT NULL, bytes BLOB NOT NULL, id TEXT, state TEXT NOT NULL, reason TEXT, session TEXT, content TEXT,
  received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, next_at INTEGER) STRICT;`

const INBOX_COLUMNS =
  'seq, relay, mailbox, cursor, bytes, id, state, reason, session, content, received_at, updated_at, tries, next_at'

const SCHEMA = `
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, bytes BLOB NOT NULL, thread TEXT NOT NULL, session TEXT,
  created_at INTEGER NOT NULL, plan TEXT) STRICT;
CREATE TABLE IF NOT EXISTS outbox_targets (id TEXT NOT NULL REFERENCES outbox (id), relay TEXT NOT NULL,
  state TEXT NOT NULL, tries INTEGER NOT NULL, next_at INTEGER, reason TEXT, updated_at INTEGER NOT NULL,
  PRIMARY KEY (id, relay)) STRICT;
${inboxTable('inbox')}
CREATE TABLE IF NOT EXISTS receipts (id TEXT NOT NULL, reader TEXT NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY (id, reader)) STRICT;
CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS threads (thread_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, used_at INTEGER) STRICT;
CREATE TABLE IF NOT EXISTS pins (subject TEXT PRIMARY KEY, key TEXT NOT NULL, record BLOB, pinned_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS fs_known (subject TEXT PRIMARY KEY) STRICT;
CREATE TABLE IF NOT EXISTS record_cache (subject TEXT NOT NULL, kind TEXT NOT NULL, bytes BLOB NOT NULL,
  expires_at INTEGER NOT NULL, PRIMARY KEY (subject, kind)) STRICT;
CREATE TABLE IF NOT EXISTS audit_anchor (name TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL,
  updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS holds (seq INTEGER PRIMARY KEY REFERENCES inbox (seq), rule TEXT NOT NULL, code TEXT NOT NULL,
  detail TEXT, waived TEXT NOT NULL DEFAULT '[]', held_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS held_sends (id TEXT PRIMARY KEY, input TEXT NOT NULL, rule TEXT NOT NULL, detail TEXT,
  state TEXT NOT NULL, held_at INTEGER NOT NULL, decided_at INTEGER) STRICT;
CREATE TABLE IF NOT EXISTS sends (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS contacts (address TEXT PRIMARY KEY, first_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS policy_counts (rule TEXT NOT NULL, outcome TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (rule, outcome)) STRICT;
CREATE TABLE IF NOT EXISTS returned (seq INTEGER PRIMARY KEY REFERENCES inbox (seq), connection TEXT NOT NULL,
  at INTEGER NOT NULL) STRICT;
`

const waitingTable = (table: string): string =>
  `CREATE ${table} IF NOT EXISTS waiting (seq INTEGER PRIMARY KEY AUTOINCREMENT, input TEXT NOT NULL, view TEXT NOT NULL,
  next_at INTEGER NOT NULL) STRICT;`

/**
 * Columns added to a table that an older store already has (the inbox columns, the threads prune's used_at, null
 * on a row from before it, and the outbox's failover plan, null too): added in place when missing.
 */
const ADDED_COLUMNS: readonly (readonly [table: string, column: string, definition: string])[] = [
  ['inbox', 'tries', 'INTEGER NOT NULL DEFAULT 0'],
  ['inbox', 'next_at', 'INTEGER'],
  ['threads', 'used_at', 'INTEGER'],
  ['outbox', 'plan', 'TEXT'],
]

/** The writer lock of a store's directory: `<dir>/audit.lock`. */
export function storeLockPath(path: string): string {
  return join(dirname(path), 'audit.lock')
}

export interface SqliteStoreOptions {
  /** The writer lock's options, or false to open without it (default: take it, for a store on a file). */
  readonly lock?: LockOptions | false
  /**
   * Keeps the waiting sends in this connection's memory, gone at close: for a store no later process opens, as a session
   * server's, whose name dies with it, so that no row of plaintext stays on disk with nothing left to expire it.
   */
  readonly waitingInMemory?: boolean
}

/**
 * The anchor of the audit log `name` in the store at `path`, read without the writer lock from a read-only connection,
 * so that `audit verify` can run beside a live edge; null when the store has no anchor table or no row for the name.
 */
export function readAuditAnchor(path: string, name: string): AuditAnchor | null {
  const db = new DatabaseSync(path, { readOnly: true })
  try {
    const table = db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_anchor'")
      .get()
    if (table === undefined) return null
    const r = db.prepare('SELECT seq, hash FROM audit_anchor WHERE name = ?').get(name)
    return r === undefined ? null : { seq: r.seq as number, hash: r.hash as string }
  } finally {
    db.close()
  }
}

/** Every audit file the store at `path` anchors, read as readAuditAnchor reads one; none without an anchor table. */
export function readAuditAnchors(path: string): NamedAnchor[] {
  const db = new DatabaseSync(path, { readOnly: true })
  try {
    const table = db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_anchor'")
      .get()
    if (table === undefined) return []
    return db
      .prepare('SELECT name, seq, hash FROM audit_anchor ORDER BY name')
      .all() as unknown as NamedAnchor[]
  } finally {
    db.close()
  }
}

type Row = Record<string, SQLOutputValue>

/** A row as an object with camelCase members: the STRICT tables fix each column's type, so the cast only names it. */
function camel<T>(r: Row): T {
  return Object.fromEntries(
    Object.entries(r).map(([k, v]) => [k.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase()), v]),
  ) as T
}

/** The SQLite edge store. A new file is created with mode 0600: the inbox holds unsealed content. */
export class SqliteStore implements EdgeStore {
  readonly #db: DatabaseSync
  readonly #statements = new Map<string, StatementSync>()
  readonly #release: () => void

  /**
   * Opens the file at `path`, creating it when missing, or an in-memory store for ':memory:'. A store on a file first
   * takes the writer lock of its directory (EdgeError `busy` while another live process, or another open store of
   * this process, holds it) and keeps it until close.
   */
  constructor(path: string, options: SqliteStoreOptions = {}) {
    const memory = path === ':memory:'
    this.#release =
      memory || options.lock === false ? () => {} : acquireLock(storeLockPath(path), options.lock)
    try {
      if (!memory) closeSync(openSync(path, 'a', 0o600))
      this.#db = new DatabaseSync(path)
      // The timeout first: the WAL pragma takes a lock, and a second process in the file must wait for it, not fail.
      this.#db.exec('PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;')
      this.#db.exec(SCHEMA)
      this.#db.exec(
        options.waitingInMemory === true
          ? `PRAGMA temp_store = MEMORY; ${waitingTable('TEMP TABLE')}`
          : waitingTable('TABLE'),
      )
      this.#migrate()
    } catch (e) {
      this.#release()
      throw e
    }
  }

  /**
   * Adds the columns of ADDED_COLUMNS that an older store lacks, and frees an older inbox of its UNIQUE (relay, mailbox,
   * cursor). SQLite cannot drop a table constraint, so that table is rebuilt once, in one transaction, every row and seq
   * kept, with foreign keys off as ALTER TABLE's own procedure says: holds names inbox (seq), and DROP TABLE would
   * otherwise delete its parents.
   */
  #migrate(): void {
    for (const [table, column, definition] of ADDED_COLUMNS) {
      const columns = this.#db.prepare(`PRAGMA table_info(${table})`).all()
      if (!columns.some((c) => c.name === column)) {
        this.#db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
      }
    }
    if (
      this.#db
        .prepare('PRAGMA index_list(inbox)')
        .all()
        .some((i) => i.origin === 'u')
    ) {
      this.#db.exec('PRAGMA foreign_keys = OFF')
      try {
        this.transaction(() =>
          this.#db.exec(`${inboxTable('inbox_rebuilt')}
            INSERT INTO inbox_rebuilt (${INBOX_COLUMNS}) SELECT ${INBOX_COLUMNS} FROM inbox;
            DROP TABLE inbox;
            ALTER TABLE inbox_rebuilt RENAME TO inbox;`),
        )
      } finally {
        this.#db.exec('PRAGMA foreign_keys = ON')
      }
    }
    this.#db.exec('CREATE INDEX IF NOT EXISTS inbox_position ON inbox (relay, mailbox, cursor)')
  }

  #q(sql: string): StatementSync {
    let statement = this.#statements.get(sql)
    if (statement === undefined) {
      statement = this.#db.prepare(sql)
      this.#statements.set(sql, statement)
    }
    return statement
  }

  /** Runs `fn` in one transaction, or inside the open one; rolls back when it throws. */
  transaction<T>(fn: () => T): T {
    if (this.#db.isTransaction) return fn()
    this.#db.exec('BEGIN IMMEDIATE')
    try {
      const out = fn()
      this.#db.exec('COMMIT')
      return out
    } catch (e) {
      this.#db.exec('ROLLBACK')
      throw e
    }
  }

  outboxAdd(entry: OutboxEntry, targets: readonly OutboxTarget[], also: OutboxAddOptions = {}): void {
    this.transaction(() => {
      if (also.waiting !== undefined) this.waitingDelete(also.waiting)
      this.#q(
        'INSERT INTO outbox (id, bytes, thread, session, created_at, plan) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(entry.id, entry.bytes, entry.thread, entry.session, entry.createdAt, also.plan ?? null)
      for (const t of targets) {
        this.#q(
          'INSERT INTO outbox_targets (id, relay, state, tries, next_at, reason, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        ).run(t.id, t.relay, t.state, t.tries, t.nextAt, t.reason, t.updatedAt)
      }
    })
  }

  outboxGet(id: string): OutboxEntry | null {
    const r = this.#q('SELECT id, bytes, thread, session, created_at FROM outbox WHERE id = ?').get(id)
    return r === undefined ? null : camel<OutboxEntry>(r)
  }

  /** The bytes of the envelopes added in [from, to), in seconds: what telemetry's `pairs` reads (telemetry-pairs.ts). */
  outboxBetween(from: number, to: number): Uint8Array[] {
    const rows = this.#q('SELECT bytes FROM outbox WHERE created_at >= ? AND created_at < ?').all(from, to)
    return rows.map((r) => r.bytes as Uint8Array)
  }

  outboxPlan(id: string): string | null {
    const r = this.#q('SELECT plan FROM outbox WHERE id = ?').get(id)
    return (r?.plan ?? null) as string | null
  }

  outboxPlanPut(id: string, plan: string): void {
    this.#q('UPDATE outbox SET plan = ? WHERE id = ?').run(plan, id)
  }

  outboxTargets(id: string): OutboxTarget[] {
    return this.#q('SELECT * FROM outbox_targets WHERE id = ? ORDER BY relay')
      .all(id)
      .map((r) => camel<OutboxTarget>(r))
  }

  outboxDue(now: number): DueTarget[] {
    return this.#q(
      `SELECT t.*, o.bytes AS bytes FROM outbox_targets t JOIN outbox o ON o.id = t.id
       WHERE t.state IN ('sealed', 'publishing') OR (t.state = 'retry' AND t.next_at <= ?)
       ORDER BY t.updated_at, t.id, t.relay`,
    )
      .all(now)
      .map((r) => {
        const { bytes, ...target } = camel<OutboxTarget & { bytes: Uint8Array }>(r)
        return { target, bytes }
      })
  }

  outboxAddTarget(t: OutboxTarget): void {
    this.#q(
      'INSERT OR IGNORE INTO outbox_targets (id, relay, state, tries, next_at, reason, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ).run(t.id, t.relay, t.state, t.tries, t.nextAt, t.reason, t.updatedAt)
  }

  receiptAdd(id: string, reader: string, at: number): void {
    this.#q('INSERT OR IGNORE INTO receipts (id, reader, at) VALUES (?, ?, ?)').run(id, reader, at)
  }

  receiptsOf(id: string): Receipt[] {
    return this.#q('SELECT reader, at FROM receipts WHERE id = ? ORDER BY rowid')
      .all(id)
      .map((r) => camel<Receipt>(r))
  }

  waitingAdd(input: string, view: string, nextAt: number): number {
    const r = this.#q('INSERT INTO waiting (input, view, next_at) VALUES (?, ?, ?)').run(input, view, nextAt)
    return Number(r.lastInsertRowid)
  }

  waitingPut(seq: number, view: string, nextAt: number): void {
    this.#q('UPDATE waiting SET view = ?, next_at = ? WHERE seq = ?').run(view, nextAt, seq)
  }

  waitingDelete(seq: number): void {
    this.#q('DELETE FROM waiting WHERE seq = ?').run(seq)
  }

  waitingList(due = Number.MAX_SAFE_INTEGER): WaitingRow[] {
    return this.#q('SELECT * FROM waiting WHERE next_at <= ? ORDER BY seq')
      .all(due)
      .map((r) => camel<WaitingRow>(r))
  }

  outboxPut(t: OutboxTarget): void {
    this.#q(
      'UPDATE outbox_targets SET state = ?, tries = ?, next_at = ?, reason = ?, updated_at = ? WHERE id = ? AND relay = ?',
    ).run(t.state, t.tries, t.nextAt, t.reason, t.updatedAt, t.id, t.relay)
  }

  inboxAdd(relay: string, mailbox: string, cursor: number, bytes: Uint8Array, now: number): InboxRow {
    const r = this.#q(
      `INSERT INTO inbox (relay, mailbox, cursor, bytes, state, received_at, updated_at)
       VALUES (?, ?, ?, ?, 'received', ?, ?) RETURNING *`,
    ).get(relay, mailbox, cursor, bytes, now, now) as Row
    return camel<InboxRow>(r)
  }

  inboxFind(relay: string, mailbox: string, cursor: number): InboxRow | null {
    return this.inboxAt(relay, mailbox, cursor).at(-1) ?? null
  }

  inboxAt(relay: string, mailbox: string, cursor: number): InboxRow[] {
    return this.#q('SELECT * FROM inbox WHERE relay = ? AND mailbox = ? AND cursor = ? ORDER BY seq')
      .all(relay, mailbox, cursor)
      .map((r) => camel<InboxRow>(r))
  }

  inboxPut(row: InboxRow, patch: InboxPatch, now: number): InboxRow {
    const next: InboxRow = { ...row, ...patch, updatedAt: now }
    this.#q(
      `UPDATE inbox SET id = ?, state = ?, reason = ?, session = ?, content = ?, tries = ?, next_at = ?, updated_at = ?
       WHERE seq = ?`,
    ).run(next.id, next.state, next.reason, next.session, next.content, next.tries, next.nextAt, now, row.seq)
    return next
  }

  inboxList(states?: readonly InboxState[]): InboxRow[] {
    const rows = this.#q('SELECT * FROM inbox ORDER BY seq')
      .all()
      .map((r) => camel<InboxRow>(r))
    return states === undefined ? rows : rows.filter((r) => states.includes(r.state))
  }

  inboxDue(relay: string, mailbox: string, now: number): InboxRow[] {
    return this.#q(
      `SELECT * FROM inbox WHERE relay = ? AND mailbox = ? AND state = 'received' AND next_at IS NOT NULL
       AND next_at <= ? ORDER BY seq`,
    )
      .all(relay, mailbox, now)
      .map((r) => camel<InboxRow>(r))
  }

  inboxLastAcked(relay: string, mailbox: string): number | null {
    const r = this.#q(
      "SELECT max(cursor) AS cursor FROM inbox WHERE relay = ? AND mailbox = ? AND state IN ('acked', 'quarantined', 'consumed')",
    ).get(relay, mailbox) as Row
    return r.cursor as number | null
  }

  seenHas(id: string, now: number): boolean {
    return this.#q('SELECT 1 FROM seen WHERE id = ? AND expires_at >= ?').get(id, now) !== undefined
  }

  seenAdd(id: string, firstSeen: number, expiresAt: number): void {
    this.#q(
      `INSERT INTO seen (id, first_seen, expires_at) VALUES (?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET first_seen = excluded.first_seen, expires_at = excluded.expires_at`,
    ).run(id, firstSeen, expiresAt)
  }

  seenPrune(now: number): number {
    return Number(this.#q('DELETE FROM seen WHERE expires_at < ?').run(now).changes)
  }

  threadGet(threadId: string): string | null {
    const r = this.#q('SELECT session_id FROM threads WHERE thread_id = ?').get(threadId)
    return r === undefined ? null : (r.session_id as string)
  }

  threadSet(threadId: string, session: string, now: number): void {
    this.#q(
      `INSERT INTO threads (thread_id, session_id, created_at, used_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (thread_id) DO UPDATE SET session_id = excluded.session_id, used_at = excluded.used_at`,
    ).run(threadId, session, now, now)
  }

  threadTouch(threadId: string, now: number): void {
    this.#q('UPDATE threads SET used_at = ? WHERE thread_id = ?').run(now, threadId)
  }

  threadsPrune(before: number): number {
    return Number(this.#q('DELETE FROM threads WHERE coalesce(used_at, created_at) < ?').run(before).changes)
  }

  pinGet(subject: string): Pin | null {
    const r = this.#q('SELECT * FROM pins WHERE subject = ?').get(subject)
    return r === undefined ? null : camel<Pin>(r)
  }

  pinPut(pin: Pin): void {
    this.#q(
      `INSERT INTO pins (subject, key, record, pinned_at, updated_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (subject) DO UPDATE SET key = excluded.key, record = excluded.record,
       pinned_at = excluded.pinned_at, updated_at = excluded.updated_at`,
    ).run(pin.subject, pin.key, pin.record, pin.pinnedAt, pin.updatedAt)
  }

  fsKnownGet(subject: string): boolean {
    return this.#q('SELECT 1 FROM fs_known WHERE subject = ?').get(subject) !== undefined
  }

  fsKnownSet(subject: string): void {
    // A one-way ratchet: the row is inserted once and never updated or deleted, so the marker cannot be unset.
    this.#q('INSERT INTO fs_known (subject) VALUES (?) ON CONFLICT (subject) DO NOTHING').run(subject)
  }

  cacheGet(subject: string, kind: CacheKind, now: number): Uint8Array | null {
    const r = this.#q('SELECT bytes FROM record_cache WHERE subject = ? AND kind = ? AND expires_at > ?').get(
      subject,
      kind,
      now,
    )
    return r === undefined ? null : (r.bytes as Uint8Array)
  }

  cachePut(subject: string, kind: CacheKind, bytes: Uint8Array, expiresAt: number): void {
    this.#q(
      `INSERT INTO record_cache (subject, kind, bytes, expires_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (subject, kind) DO UPDATE SET bytes = excluded.bytes, expires_at = excluded.expires_at`,
    ).run(subject, kind, bytes, expiresAt)
  }

  cacheDrop(subject: string, kind: CacheKind): boolean {
    return (
      Number(this.#q('DELETE FROM record_cache WHERE subject = ? AND kind = ?').run(subject, kind).changes) >
      0
    )
  }

  auditAnchorGet(name: string): AuditAnchor | null {
    const r = this.#q('SELECT seq, hash FROM audit_anchor WHERE name = ?').get(name)
    return r === undefined ? null : { seq: r.seq as number, hash: r.hash as string }
  }

  auditAnchorPut(name: string, anchor: AuditAnchor, now: number): void {
    this.#q(
      `INSERT INTO audit_anchor (name, seq, hash, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (name) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, updated_at = excluded.updated_at`,
    ).run(name, anchor.seq, anchor.hash, now)
  }

  auditAnchors(): NamedAnchor[] {
    return this.#q('SELECT name, seq, hash FROM audit_anchor ORDER BY name').all() as unknown as NamedAnchor[]
  }

  returnedPut(seq: number, connection: string, now: number): void {
    this.#q('INSERT INTO returned (seq, connection, at) VALUES (?, ?, ?) ON CONFLICT (seq) DO NOTHING').run(
      seq,
      connection,
      now,
    )
  }

  returnedAll(): [number, string][] {
    const rows = this.#q('SELECT seq, connection FROM returned ORDER BY seq').all()
    return rows.map((r) => [r.seq as number, r.connection as string])
  }

  inboxGet(seq: number): InboxRow | null {
    const r = this.#q('SELECT * FROM inbox WHERE seq = ?').get(seq)
    return r === undefined ? null : camel<InboxRow>(r)
  }

  inboxContentSince(since: number): InboxRow[] {
    return this.#q('SELECT * FROM inbox WHERE content IS NOT NULL AND received_at >= ? ORDER BY seq')
      .all(since)
      .map((r) => camel<InboxRow>(r))
  }

  holdPut(seq: number, hold: Pick<Hold, 'rule' | 'code' | 'detail'>, now: number): void {
    this.#q(
      `INSERT INTO holds (seq, rule, code, detail, held_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (seq) DO UPDATE SET
       rule = excluded.rule, code = excluded.code, detail = excluded.detail, held_at = excluded.held_at`,
    ).run(seq, hold.rule, hold.code, hold.detail, now)
  }

  holdGet(seq: number): Hold | null {
    const r = this.#q('SELECT * FROM holds WHERE seq = ?').get(seq)
    return r === undefined ? null : { ...camel<Hold>(r), waived: JSON.parse(r.waived as string) as string[] }
  }

  holdWaive(seq: number, waived: readonly string[]): void {
    this.#q('UPDATE holds SET waived = ? WHERE seq = ?').run(JSON.stringify(waived), seq)
  }

  heldSendPut(h: HeldSend): void {
    this.#q(
      `INSERT INTO held_sends (id, input, rule, detail, state, held_at, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET state = excluded.state, decided_at = excluded.decided_at`,
    ).run(h.id, h.input, h.rule, h.detail, h.state, h.heldAt, h.decidedAt)
  }

  heldSendGet(id: string): HeldSend | null {
    const r = this.#q('SELECT * FROM held_sends WHERE id = ?').get(id)
    return r === undefined ? null : camel<HeldSend>(r)
  }

  heldSendList(state: HeldSend['state']): HeldSend[] {
    return this.#q('SELECT * FROM held_sends WHERE state = ? ORDER BY held_at, id')
      .all(state)
      .map((r) => camel<HeldSend>(r))
  }

  sendLog(id: string, to: readonly string[], at: number): void {
    this.transaction(() => {
      this.#q('INSERT OR IGNORE INTO sends (id, at) VALUES (?, ?)').run(id, at)
      for (const a of to)
        this.#q('INSERT OR IGNORE INTO contacts (address, first_at) VALUES (?, ?)').run(a, at)
    })
  }

  fanoutSince(since: number): { readonly sends: number; readonly contacts: number } {
    const sql =
      'SELECT (SELECT count(*) FROM sends WHERE at >= ?) AS sends, (SELECT count(*) FROM contacts WHERE first_at >= ?) AS contacts'
    return this.#q(sql).get(since, since) as { sends: number; contacts: number }
  }

  contactsNew(to: readonly string[]): string[] {
    return [...new Set(to)].filter(
      (a) => this.#q('SELECT 1 FROM contacts WHERE address = ?').get(a) === undefined,
    )
  }

  policyCount(rule: string, outcome: string): void {
    this.#q(
      `INSERT INTO policy_counts (rule, outcome, n) VALUES (?, ?, 1)
       ON CONFLICT (rule, outcome) DO UPDATE SET n = n + 1`,
    ).run(rule, outcome)
  }

  policyCounts(): PolicyCount[] {
    return this.#q('SELECT rule, outcome, n FROM policy_counts ORDER BY rule, outcome')
      .all()
      .map((r) => camel<PolicyCount>(r))
  }

  heldCounts(): { readonly quarantined: number; readonly pending: number } {
    const sql = `SELECT (SELECT count(*) FROM inbox WHERE state = 'quarantined') AS quarantined,
      (SELECT count(*) FROM held_sends WHERE state = 'pending-approval') AS pending`
    return this.#q(sql).get() as { quarantined: number; pending: number }
  }

  /** Closes the database and releases the writer lock, even when the close fails. */
  close(): void {
    try {
      this.#db.close()
    } finally {
      this.#release()
    }
  }
}
