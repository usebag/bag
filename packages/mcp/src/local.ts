import { lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fromHex, parseEnvelope } from '@usebag/core'
import { addressCopy, HomeCustody, KeyEpochStore } from '@usebag/edge'

// Delivery between identities of one home (spec/SPEC.md 9.2, decisions 98 and 104): the bag service's own files. The
// home word, <home>/run/local.json {"version": 2, "local_delivery": "on" | "off", "hidden": [label]}, is written by the
// CLI's `bag local-delivery` (on and show after a terminal y) and by a host dialog's hide or show; absent, it is
// LOCAL_DELIVERY_DEFAULT (on); a file that is not a 0600 regular file of this user or does not read is off. The local
// trust table, <home>/run/local-peers.json, 0600, written whole and renamed, holds the pairs the person said yes to
// in a dialog: never trust.json, never the name book, never an accept-from or a published record (M1), so no wire
// envelope between two identities of a home is ever accepted. The spool, <home>/state/<name>/local-spool/<envelope id>.env,
// holds what was sealed to an identity whose unit is not open (a Keychain identity before its first bind), delivered at
// its open (M6). The CLI repeats the word's reader and writer and the drop of one identity's entries
// (packages/cli/src/commands/local.ts): check-imports keeps it off this package.

/** The home word's file. */
export const localWordPath = (home: string): string => join(home, 'run', 'local.json')
/** The local trust table's file. */
export const localPeersPath = (home: string): string => join(home, 'run', 'local-peers.json')
/** One identity's spool directory, by its key name. */
export const spoolDir = (home: string, name: string): string => join(home, 'state', name, 'local-spool')

/** Local delivery in a home with no word file (decision 104): on. One constant, so a ruling flips it in one line. */
export const LOCAL_DELIVERY_DEFAULT = true

/** The home word as read: on or off, the hidden labels (v2), and why a file there was read as off (else null). */
export interface LocalWord {
  readonly on: boolean
  /** Whether run/local.json exists (false: the default holds). */
  readonly set: boolean
  readonly hidden: readonly string[]
  readonly why: string | null
}

/**
 * The home word, run/local.json: version 1 {local_delivery} or 2 {local_delivery, hidden: [label]}. No file is
 * LOCAL_DELIVERY_DEFAULT with none hidden. A file is read only when it is a regular file (never a symlink), this
 * user's, mode 0600 (C1); otherwise, or unreadable, it is off, with why.
 */
export function localWord(home: string): LocalWord {
  const file = localWordPath(home)
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(file)
  } catch {
    return { on: LOCAL_DELIVERY_DEFAULT, set: false, hidden: [], why: null }
  }
  const uid = process.getuid?.() ?? st.uid
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o777) !== 0o600)
    return { on: false, set: true, hidden: [], why: 'run/local.json is not a 0600 regular file of this user' }
  try {
    const v = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    if (v.version !== 1 && v.version !== 2) throw new Error('version')
    const hidden = v.version === 2 && Array.isArray(v.hidden) ? v.hidden : []
    const kept = hidden.filter((h) => typeof h === 'string')
    return { on: v.local_delivery === 'on', set: true, hidden: kept, why: null }
  } catch {
    return { on: false, set: true, hidden: [], why: 'run/local.json does not read' }
  }
}

/** Whether the home word is on (localWord). */
export function localDelivery(home: string): boolean {
  return localWord(home).on
}

/** Writes the home word, version 2, whole: 0600, renamed over (a dialog's hide or show; the CLI writes its own). */
export function writeLocalWord(home: string, on: boolean, hidden: readonly string[]): void {
  const file = localWordPath(home)
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.tmp`
  const body = { version: 2, local_delivery: on ? 'on' : 'off', hidden: [...new Set(hidden)].sort() }
  writeFileSync(tmp, `${JSON.stringify(body)}\n`, { mode: 0o600 })
  renameSync(tmp, file)
}

/** One own identity, by its label and its address. */
export interface Own {
  readonly label: string
  readonly address: string
}

/** One pair of the table: two identities of the home that trust each other locally. */
export interface LocalPair {
  readonly a: string
  readonly b: string
  readonly a_addr: string
  readonly b_addr: string
  readonly added_at: number
  /**
   * allowed: both ways. requested: a first touch from a waits for b's person (decision 104), with the held envelope
   * ids; declined: refused until `until`, with the re-asks of this cooling (the clock seconds of each). Absent or any
   * other value reads as none (stateOf).
   */
  readonly state?: 'allowed' | 'requested' | 'declined'
  readonly at?: number
  readonly until?: number
  readonly held?: readonly string[]
  readonly reasks?: readonly number[]
}

const isPair = (p: unknown): p is LocalPair => {
  const v = p as Record<string, unknown> | null
  return (
    typeof v === 'object' &&
    v !== null &&
    ['a', 'b', 'a_addr', 'b_addr'].every((k) => typeof v[k] === 'string') &&
    typeof v.added_at === 'number'
  )
}

/** A held envelope id as the table may name it: an envelope id, 64 lowercase hex (core's sha256hex), nothing else. */
export const HELD_ID = /^[0-9a-f]{64}$/

/**
 * The row with only envelope ids in `held` (r1): any other entry (a path such as ../../x, a non-string) is dropped, so
 * no file outside a spool's held/ is ever named by the table. The same row when it is clean.
 */
export function cleanHeld(p: LocalPair): LocalPair {
  const held = p.held as unknown
  if (held === undefined) return p
  const ok = Array.isArray(held)
    ? held.filter((id): id is string => typeof id === 'string' && HELD_ID.test(id))
    : []
  return Array.isArray(held) && ok.length === held.length ? p : { ...p, held: ok }
}

/** A pair's state as both directions read it. */
export type PairState = 'allowed' | 'requested' | 'declined' | 'none'

/**
 * The one reading of a row's state, for the sender (service.ts #pairState) and the receiver (localRootsOf), so the two
 * cannot disagree: allowed, requested or declined only as written; a missing or unknown state, no row, or a declined
 * row past its `until` (Unix seconds, against `now`) is none.
 */
export function stateOf(p: LocalPair | undefined, now = 0): PairState {
  if (p?.state === 'declined') return (p.until ?? 0) > now ? 'declined' : 'none'
  return p?.state === 'allowed' || p?.state === 'requested' ? p.state : 'none'
}

/** Why run/local-peers.json is refused (C1: not a 0600 regular file of this user), or null (absent, or fine). */
export function pairsRefused(home: string): string | null {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(localPeersPath(home))
  } catch {
    return null
  }
  return !st.isFile() || st.uid !== (process.getuid?.() ?? st.uid) || (st.mode & 0o777) !== 0o600
    ? 'run/local-peers.json is not a 0600 regular file of this user'
    : null
}

/** The table's pairs; a file that is absent or does not read holds none (no local trust, fail closed). */
export function localPairs(home: string): LocalPair[] {
  try {
    // As the word (C1): only a regular file of this user, mode 0600.
    if (pairsRefused(home) !== null) return []
    return pairsFromText(readFileSync(localPeersPath(home), 'utf8'))
  } catch {
    return []
  }
}

/**
 * The table's pairs from its text (version 1, rows of the pair shape; anything else holds none). The service parses
 * the very text it compares with its last write, one read, so no swap between two reads can feed it rows (t1).
 */
export function pairsFromText(text: string): LocalPair[] {
  try {
    const v = JSON.parse(text) as { version?: unknown; pairs?: unknown }
    return v.version === 1 && Array.isArray(v.pairs) ? v.pairs.filter(isPair) : []
  } catch {
    return []
  }
}

/** Writes the table whole, 0600, renamed over; the text written (the service keeps its hash, C1). */
export function writePairs(home: string, pairs: readonly LocalPair[]): string {
  const file = localPeersPath(home)
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.tmp`
  const text = `${JSON.stringify({ version: 1, pairs })}\n`
  writeFileSync(tmp, text, { mode: 0o600 })
  renameSync(tmp, file)
  return text
}

const names = (p: LocalPair, x: Own): boolean =>
  stateOf(p) === 'allowed' &&
  ((p.a === x.label && p.a_addr === x.address) || (p.b === x.label && p.b_addr === x.address))

/** The labels `x` is locally paired with: only its own pairs, never another identity's. */
export function localPeersOf(home: string, x: Own, rows: readonly LocalPair[] = localPairs(home)): string[] {
  return rows.filter((p) => names(p, x)).map((p) => (p.a === x.label ? p.b : p.a))
}

/**
 * The addresses a receiver of `x` trusts for a local row only (receiver.ts localRoots): none with the word off. The
 * bag service passes its reconciled rows (`rows`), never the raw disk, so a forged row is never trusted (item q1).
 */
export function localRootsOf(
  home: string,
  x: Own,
  rows: readonly LocalPair[] = localPairs(home),
  addressOf?: (label: string) => string | null,
): string[] {
  const { on, hidden } = localWord(home)
  // A hidden identity trusts none of the others locally, and none trusts it (symmetric, decision 103).
  if (!on || hidden.includes(x.label)) return []
  // The peer's address is its identity's in this home (`addressOf`, the service's), never the row's (s2).
  return rows
    .filter((p) => names(p, x) && !hidden.includes(p.a === x.label ? p.b : p.a))
    .flatMap((p) => {
      const peer = p.a === x.label ? p.b : p.a
      const address = addressOf === undefined ? (p.a === x.label ? p.b_addr : p.a_addr) : addressOf(peer)
      return address === null ? [] : [address]
    })
}

/**
 * Drops the local pair of addresses x and y (both sides' one entry), and from the spool of whichever of them is an
 * identity of this home every envelope the other sent: the console's pairings remove of an own address (console.ts).
 * True when anything was dropped.
 */
export function dropLocalPair(home: string, x: string, y: string): boolean {
  const pairs = localPairs(home)
  const ours = (p: LocalPair): boolean =>
    (p.a_addr === x && p.b_addr === y) || (p.a_addr === y && p.b_addr === x)
  const rest = pairs.filter((p) => !ours(p))
  if (rest.length !== pairs.length) writePairs(home, rest)
  let entries: { readonly name: string; readonly address: string }[] = []
  try {
    entries = new HomeCustody(home).list()
  } catch {}
  let spooledDropped = 0
  for (const e of entries.filter((e) => e.address === x || e.address === y)) {
    const other = e.address === x ? y : x
    for (const { file, bytes } of spooled(home, e.name)) {
      let from: string | null = null
      try {
        from = parseEnvelope(bytes).from
      } catch {}
      if (from !== other) continue
      rmSync(file, { force: true })
      spooledDropped++
    }
  }
  return rest.length !== pairs.length || spooledDropped > 0
}

/** Keeps sealed bytes for identity `name` until its unit opens, or (held) until its person allows the pair. */
export function spool(home: string, name: string, id: string, bytes: Uint8Array, held = false): void {
  const dir = held ? join(spoolDir(home, name), 'held') : spoolDir(home, name)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, `${id}.env`), bytes, { mode: 0o600 })
}

/** The spooled envelopes of `name`, by file, oldest name first; a failed one (.failed) is kept and not listed. */
export function spooled(home: string, name: string): { readonly file: string; readonly bytes: Uint8Array }[] {
  let files: string[] = []
  try {
    files = readdirSync(spoolDir(home, name)).filter((f) => /^[0-9a-f]{64}\.env$/.test(f))
  } catch {}
  return files.sort().map((f) => {
    const file = join(spoolDir(home, name), f)
    return { file, bytes: new Uint8Array(readFileSync(file)) }
  })
}

/** A spooled envelope delivered (or a duplicate): gone. One that failed to unseal is kept as <id>.env.failed. */
export function unspool(file: string, failed: boolean): void {
  if (failed) renameSync(file, `${file}.failed`)
  else rmSync(file, { force: true })
}

/**
 * The key identity `name` at `address` opens with, read only from the home's own files, never a relay: its newest held
 * epoch key (forward secrecy, <home>/key-records), else the sealing key of its address record copy
 * (<home>/records/<name>.address.json, verified and its own). Null when neither holds one.
 */
export function localSealingKey(home: string, name: string, address: string): Uint8Array | null {
  try {
    const epochs = new KeyEpochStore(join(home, 'key-records'))
    const newest = epochs.epochs(address)[0]
    if (newest !== undefined) return epochs.epoch(address, newest).key.publicKey
  } catch {}
  const copy = addressCopy(home, name, address)
  return copy === null || copy.sealing_key === null ? null : fromHex(copy.sealing_key, 32)
}
