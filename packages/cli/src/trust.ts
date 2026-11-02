import { randomUUID } from 'node:crypto'
import { readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { domainOfRoot, isAddress } from '@usebag/core'
import { CliError } from './args.ts'

// The trust file: <home>/trust.json, the roots `peer` granted, which inbox trusts beside --trust-root and
// the MCP server re-reads (packages/mcp/src/trust.ts). 0600, written whole and renamed, as names.json is. A root is an
// address (trusted by key) or `domain:<host>` in spec/SPEC.md §7.4's grammar exactly, with no port (trusted by the
// domain's well-known record, pinned at first use, as --trust-root <host>); anything else is trust-invalid, on reading
// and on writing. A root is written only on an explicit act of the person naming it: the y
// of a peer pairing, or a typed --accept or --trust-domain; never from an incoming message, a resolved record or a default.

type Roots = Record<string, { readonly added_at: number }>

/** True for what a trust file may hold: an address, or a domain root with no port (SPEC.md §7.4). */
export const isTrustRoot = (root: string): boolean => isAddress(root) || domainOfRoot(root) !== null

/** The roots of a home's trust file: none when it is missing; trust-invalid when it is not one. */
export function readTrust(home: string): Roots {
  const path = join(home, 'trust.json')
  let doc: { version?: unknown; roots?: Record<string, { added_at?: unknown } | null> } | null
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return {}
    throw new CliError('trust-invalid', `${path} cannot be read as JSON: ${(e as Error).message}`)
  }
  const roots = doc?.version === 1 && doc.roots?.constructor === Object ? doc.roots : null
  const ok = ([a, e]: [string, { added_at?: unknown } | null]) =>
    isTrustRoot(a) && Number.isSafeInteger(e?.added_at)
  if (roots === null || !Object.entries(roots).every(ok)) {
    throw new CliError('trust-invalid', `${path} is not a trust file of version 1`)
  }
  return roots as Roots
}

/** Adds `root` (an address or `domain:<host>`) to a home's trust file (an entry it has stays) and writes it whole. */
export function addTrust(home: string, root: string, now: number): void {
  if (!isTrustRoot(root))
    throw new CliError('trust-invalid', `${JSON.stringify(root)} is not a root a trust file holds`)
  const roots = { [root]: { added_at: now }, ...readTrust(home) }
  const tmp = join(home, `.trust.json.${randomUUID()}.tmp`)
  writeFileSync(tmp, `${JSON.stringify({ version: 1, roots }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  renameSync(tmp, join(home, 'trust.json'))
}

/**
 * Removes `root` from a home's trust file and writes it whole, as addTrust writes it; false, with nothing
 * written, when the file lacks it. Only `unpair` calls it, after a person's y: a root leaves by that act.
 */
export function removeTrust(home: string, root: string): boolean {
  if (!isTrustRoot(root))
    throw new CliError('trust-invalid', `${JSON.stringify(root)} is not a root a trust file holds`)
  const { [root]: gone, ...roots } = readTrust(home)
  if (gone === undefined) return false
  const tmp = join(home, `.trust.json.${randomUUID()}.tmp`)
  writeFileSync(tmp, `${JSON.stringify({ version: 1, roots }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  renameSync(tmp, join(home, 'trust.json'))
  return true
}
