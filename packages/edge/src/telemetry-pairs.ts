import { createHash } from 'node:crypto'
import { readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { isAddress, parseEnvelope } from '@usebag/core'
import type { Clock } from './ports.ts'
import { SPOOL_DAYS, TELEMETRY_PAIRS_FILE, telemetryDir, telemetryOn, telemetrySince } from './telemetry.ts'
import { addCell, type Cells, dateOf, dayOf } from './telemetry-report.ts'
import { SETS } from './telemetry-schema.ts'

// The `pairs` family (the W6 design note and the red team's ruling of 2026-11-03, in the operations records): for a
// day, the machine's peers, the address roots of each home's trust file, by their age at the day's end (under 7 days,
// or 7 days or more), and of each, those the home sent to in the 7 days before, never before the consent's date (Q8).
// The outbox is read, never written. A snapshot, not a count: a process that opens an identity writes its four counts
// per finished day to telemetry-pairs.json beside the spool, keyed by hashes of the home's path and of the identity's
// name, which never leave the machine. A report takes, per home, the largest of its identities' counts cell by cell,
// sums the homes, and floors each sum as every count. Without this file a report's `pairs` is empty.

const DAY = 86_400
const WEEK = 7 * DAY
const KEY = /^[0-9a-f]{16}$/

type Env = Readonly<Record<string, string | undefined>>
type Row = {
  readonly home: string
  readonly who: string
  readonly day: string
  readonly counts: readonly number[]
}

/** The part of an identity's store the snapshot reads: the bytes of the envelopes sent in [from, to), in seconds. */
export interface SentStore {
  outboxBetween(from: number, to: number): Uint8Array[]
}

const hashed = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 16)

const isRow = (r: Partial<Row> | null): r is Row =>
  KEY.test(String(r?.home)) &&
  KEY.test(String(r?.who)) &&
  dayOf(String(r?.day)) !== null &&
  Array.isArray(r?.counts) &&
  r.counts.length === SETS.pairs.length &&
  r.counts.every((n) => Number.isSafeInteger(n) && n >= 0)

function readRows(dir: string): Row[] {
  try {
    const rows: unknown = JSON.parse(readFileSync(join(dir, TELEMETRY_PAIRS_FILE), 'utf8')).rows
    return Array.isArray(rows) ? rows.filter(isRow) : []
  } catch {
    return []
  }
}

/** The address roots of `home`'s trust file with their added_at (the CLI owns the format); none when it does not read. */
function trustRoots(home: string): [string, number][] {
  try {
    const doc = JSON.parse(readFileSync(join(home, 'trust.json'), 'utf8')) as { roots?: object } | null
    return Object.entries(doc?.roots ?? {}).flatMap(([root, e]) => {
      const at = (e as { added_at?: unknown } | null)?.added_at
      return isAddress(root) && Number.isSafeInteger(at) ? [[root, at as number] as [string, number]] : []
    })
  } catch {
    return []
  }
}

/** The four counts of the day ending at `end`, in SETS.pairs' order. */
function countsOf(roots: readonly [string, number][], sent: ReadonlySet<string>, end: number): number[] {
  const counts = [0, 0, 0, 0]
  for (const [root, at] of roots) {
    if (at > end) continue
    const i = end - at < WEEK ? 0 : 2
    counts[i] = (counts[i] ?? 0) + 1
    if (sent.has(root)) counts[i + 1] = (counts[i + 1] ?? 0) + 1
  }
  return counts
}

/**
 * Writes the snapshot of identity `name` of `home` for each finished day of the spool's window that it lacks, from the
 * consent's date, while telemetry is on. Never throws: a count must not fail its caller.
 */
export function notePairs(env: Env, clock: Clock, home: string, name: string, store: SentStore): void {
  try {
    const dir = telemetryDir(env)
    const start = dir === null ? null : dayOf(telemetrySince(dir) ?? '')
    if (dir === null || start === null || !telemetryOn(env)) return
    const today = Math.floor(clock.now() / DAY)
    const [h, who] = [hashed(realpathSync(home)), hashed(name)]
    const rows = readRows(dir).filter((r) => r.day >= dateOf(today - SPOOL_DAYS))
    const roots = trustRoots(home)
    const before = rows.length
    for (let d = Math.max(start, today - SPOOL_DAYS); d < today; d++) {
      const day = dateOf(d)
      if (rows.some((r) => r.home === h && r.who === who && r.day === day)) continue
      const end = (d + 1) * DAY
      const sent = new Set(
        store.outboxBetween(Math.max(end - WEEK, start * DAY), end).flatMap((b) => parseEnvelope(b).to),
      )
      rows.push({ home: h, who, day, counts: countsOf(roots, sent, end) })
    }
    if (rows.length === before) return
    const path = join(dir, TELEMETRY_PAIRS_FILE)
    writeFileSync(`${path}.${process.pid}.tmp`, `${JSON.stringify({ v: 1, rows })}\n`, { mode: 0o600 })
    renameSync(`${path}.${process.pid}.tmp`, path)
  } catch {
    // The snapshot is left out; the next process that opens the identity writes it.
  }
}

const tracked = new Set<() => void>()

/** notePairs now, and before each try of this process's sender, until the untrack it returns (a server's identity). */
export function trackPairs(env: Env, clock: Clock, home: string, name: string, store: SentStore): () => void {
  const note = (): void => notePairs(env, clock, home, name, store)
  note()
  tracked.add(note)
  return () => {
    tracked.delete(note)
  }
}

/** Writes the snapshot of every identity this process tracks: the sender's first step. */
export function noteTrackedPairs(): void {
  for (const note of tracked) note()
}

/** The cells of `day` with `pairs` from the snapshots alone, never from the spool. */
export function withPairs(dir: string, day: string, cells: Cells): Cells {
  const out: Cells = new Map([...cells].filter(([k]) => !k.startsWith('pairs ')))
  const homes = new Map<string, number[]>()
  for (const r of readRows(dir)) {
    if (r.day === day)
      homes.set(
        r.home,
        r.counts.map((n, i) => Math.max(n, homes.get(r.home)?.[i] ?? 0)),
      )
  }
  for (const counts of homes.values()) {
    for (const [i, n] of counts.entries()) if (n > 0) addCell(out, `pairs ${SETS.pairs[i]}`, n)
  }
  return out
}
