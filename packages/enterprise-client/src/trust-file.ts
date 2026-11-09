import { randomUUID } from 'node:crypto'
import { readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { domainOfRoot, isAddress, isDomainHost } from '@usebag/core'

// The bag home's trust file as a bag enterprise session writes it: <home>/trust.json, version 1, 0600, written whole and
// renamed, as bag's own CLI and MCP server write it. A root is an address or `domain:<host>` (SPEC 7.4), never `*`. An
// entry the organisation granted carries provenance (the agent contract's trust roots): `source`, `org:<domain>`,
// `peer:<link id>` or `partner:<partnership id>` (a partner organisation's root), with `granted_by` and `granted_at`; at most 64 such. bag's readers ignore the three extra fields
// (they check only `added_at`), so a home this package wrote stays a trust file of version 1 to them. An entry with no
// source is a person's own act and wins: no organisation overwrites it and no sign-out removes it. @usebag/edge exports
// no reader or writer of this file (bag's CLI and MCP server each keep their own), so this package keeps its own.

export interface TrustEntry {
  readonly added_at: number
  readonly source?: string
  readonly granted_by?: string | null
  readonly granted_at?: number
}
export type TrustRoots = Record<string, TrustEntry>
export const MAX_SOURCED_ROOTS = 64

/** True for what a trust file may hold: an address, or a domain root with no port. */
export const isTrustRoot = (root: string): boolean => isAddress(root) || domainOfRoot(root) !== null

const source = (s: unknown): boolean =>
  typeof s === 'string' &&
  ((s.startsWith('org:') && isDomainHost(s.slice(4))) || /^(?:peer|partner):[A-Za-z0-9._-]{1,64}$/.test(s))

function entryOk(e: Partial<Record<keyof TrustEntry, unknown>> | null): boolean {
  const by = e?.granted_by
  if (e === null || typeof e !== 'object' || !Number.isSafeInteger(e.added_at)) return false
  if (e.source === undefined) return by === undefined && e.granted_at === undefined
  return (
    source(e.source) &&
    (by === null || (typeof by === 'string' && by.length <= 200)) &&
    Number.isSafeInteger(e.granted_at)
  )
}

const sourced = (roots: object): number => Object.values(roots).filter((e) => e?.source !== undefined).length

/** The roots of a home's trust file: {} when it is missing; `fail(detail)` is thrown when it is not one. */
export function readTrustFile(home: string, fail: (detail: string) => Error): TrustRoots {
  const path = join(home, 'trust.json')
  let doc: { version?: unknown; roots?: Record<string, TrustEntry | null> } | null
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return {}
    throw fail(`${path} cannot be read as JSON: ${(e as Error).message}`)
  }
  const roots = doc?.version === 1 && doc.roots?.constructor === Object ? doc.roots : null
  const ok = roots !== null && Object.entries(roots).every(([a, e]) => isTrustRoot(a) && entryOk(e))
  if (!ok || sourced(roots) > MAX_SOURCED_ROOTS) throw fail(`${path} is not a trust file of version 1`)
  return roots as TrustRoots
}

/** Writes a home's trust file whole: a new 0600 file renamed over the old one. */
export function writeTrustFile(home: string, roots: TrustRoots): void {
  const tmp = join(home, `.trust.json.${randomUUID()}.tmp`)
  writeFileSync(tmp, `${JSON.stringify({ version: 1, roots }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  renameSync(tmp, join(home, 'trust.json'))
}

/** A root the organisation grants (GET /agent/trust's AgentTrustRoot). */
export interface SourcedRoot {
  readonly root: string
  readonly source: string
  readonly granted_by: string | null
  readonly granted_at: number
}

/** What a sync changed, and the granted roots a person's own entry already holds. */
export interface TrustSync {
  readonly added: string[]
  readonly removed: string[]
  readonly person: string[]
}

/**
 * Makes the sourced entries that `owns` claims exactly `wanted`: adds, updates, removes; entries with no source stay.
 * Every wanted root must be a trust root (never `*`) with a source `owns` claims, and at most 64 sourced roots in all,
 * else `fail` and nothing is written. Sign-out and revocation pass [] (the set leaves as a set).
 */
export function syncSourcedTrust(
  home: string,
  owns: (source: string) => boolean,
  wanted: readonly SourcedRoot[],
  now: number,
  fail: (detail: string) => Error,
): TrustSync {
  const bad = wanted.find((w) => !isTrustRoot(w.root) || !owns(w.source) || !entryOk({ added_at: now, ...w }))
  if (bad !== undefined)
    throw fail(`the organisation granted ${JSON.stringify(bad.root)}, which a trust file never holds`)
  const roots: Record<string, TrustEntry> = { ...readTrustFile(home, fail) }
  const sync: TrustSync = { added: [], removed: [], person: [] }
  const want = new Map(wanted.map((w) => [w.root, w]))
  for (const [root, e] of Object.entries(roots)) {
    if (e.source !== undefined && owns(e.source) && !want.has(root)) {
      delete roots[root]
      sync.removed.push(root)
    }
  }
  for (const [root, { source, granted_by, granted_at }] of want) {
    const had = roots[root]
    if (had !== undefined && had.source === undefined) sync.person.push(root)
    else {
      if (had === undefined) sync.added.push(root)
      roots[root] = { added_at: had?.added_at ?? now, source, granted_by, granted_at }
    }
  }
  if (sourced(roots) > MAX_SOURCED_ROOTS)
    throw fail(`over ${MAX_SOURCED_ROOTS} roots granted by organisations`)
  writeTrustFile(home, roots)
  return sync
}

/**
 * Removes a root a pairing wrote (an entry with no source) from a home's trust file, as unpair does: a link the
 * console revoked or whose term ended (pairings.ts). An organisation's sourced entry stays; false when none was there.
 */
export function removePairedRoot(home: string, root: string, fail: (detail: string) => Error): boolean {
  const { [root]: gone, ...roots } = readTrustFile(home, fail)
  if (gone === undefined || gone.source !== undefined) return false
  writeTrustFile(home, roots)
  return true
}
