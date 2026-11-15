import { existsSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { parseEnvelope } from '@usebag/core'

// The front desk's ledger, seeded from the principal's own store. A plain (non-session) server, the CLI and a 0.1 server
// take roots into <home>/state/<principal>/edge.sqlite and write no desk-handled, so a session's desk would take those
// roots again when its fresh store replays them. FrontDesk calls `seed` at every desk start, under desk.lock, and adds
// the unexpired ids its ledger lacks (front-desk.ts, #merge). Read only: one read-only connection and one SELECT, never
// SqliteStore, whose constructor runs the schema and its migration and so could write to an older store.
//
// "Accepted" is not "answered": a root a plain server's model saw and chose not to answer is seeded too, and no
// session answers it; it was seen. Not covered: a session's own store (s-<hex>), whose desk always writes the ledger,
// and a plain server or the CLI taking a root while a desk runs (two live answerers, outside the desk's reach).

/** The inbox states of a row the store's edge accepted: it reached a model, or the CLI's reader, or will. */
const ACCEPTED = ['verified', 'routed', 'queued', 'acked', 'consumed'] as const

/** The inbox columns the seed reads; a store lacking any of them (an older schema) gives an empty seed. */
const COLUMNS = ['id', 'state', 'content', 'bytes'] as const

/** One root the store accepted: its envelope id and its ts (the desk drops it once ts + ttl + skew is past). */
export interface SeedRoot {
  readonly id: string
  readonly ts: number
}

/**
 * The roots the store at `path` accepted: rows in an accepted state, with an id and a content whose thread has no
 * `prev` (a root, not a reply). A row without content is left out: whether it is a root sits inside the sealed content.
 * No store, no inbox table, or a column missing: none. The store is never written.
 */
export function seedFromStore(path: string): SeedRoot[] {
  if (!existsSync(path)) return []
  const db = new DatabaseSync(path, { readOnly: true })
  try {
    const columns = db.prepare('PRAGMA table_info(inbox)').all() as { name: string }[]
    const names = new Set(columns.map((c) => c.name))
    if (!COLUMNS.every((c) => names.has(c))) return []
    const rows = db
      .prepare(
        `SELECT id, content, bytes FROM inbox WHERE id IS NOT NULL AND content IS NOT NULL AND state IN (${ACCEPTED.map(() => '?').join(', ')})`,
      )
      .all(...ACCEPTED) as { id: string; content: string; bytes: Uint8Array }[]
    const roots: SeedRoot[] = []
    for (const r of rows) {
      let prev: unknown
      let ts: number
      try {
        prev = (JSON.parse(r.content) as { thread?: { prev?: unknown } }).thread?.prev
        ts = parseEnvelope(new Uint8Array(r.bytes)).ts
      } catch {
        continue // a row that does not read is no evidence of an answer
      }
      if (Array.isArray(prev) && prev.length === 0) roots.push({ id: r.id, ts })
    }
    return roots
  } finally {
    db.close()
  }
}
