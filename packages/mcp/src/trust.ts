import { randomUUID } from 'node:crypto'
import { readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { domainOfRoot, isAddress } from '@usebag/core'
import type { TrustedRoot } from '@usebag/edge'
import { ConfigError } from './config.ts'

// The home's trust file: <home>/trust.json, which the CLI's `peer` writes after a pairing
// (packages/cli/src/trust.ts, the format's owner), and pair_invite and pair_accept after the person's confirmed code in a
// dialog the model cannot answer (pairing.ts), and the console's pairings add and remove (console.ts). The dependency rule keeps
// this package off @usebag/cli, so the reading and that writer are repeated here, to the same checks and bytes.
// open.ts reads it at start and again before the edge handles each frame, so a pairing needs no restart.

type Roots = Record<string, { readonly added_at: number }>

/** The roots of a home's trust file as written: {} without the file; trust-invalid when it is not one. */
function readRoots(home: string): Roots {
  const path = join(home, 'trust.json')
  let doc: { version?: unknown; roots?: Record<string, { added_at?: unknown } | null> } | null
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return {}
    throw new ConfigError('trust-invalid', `${path} cannot be read as JSON: ${(e as Error).message}`)
  }
  const roots = doc?.version === 1 && doc.roots?.constructor === Object ? doc.roots : null
  const ok = ([a, e]: [string, { added_at?: unknown } | null]) =>
    (isAddress(a) || domainOfRoot(a) !== null) && Number.isSafeInteger(e?.added_at)
  if (roots === null || !Object.entries(roots).every(ok)) {
    throw new ConfigError('trust-invalid', `${path} is not a trust file of version 1`)
  }
  return roots as Roots
}

/** The roots a home's trust file grants, as the edge's policy takes them: none without the file; trust-invalid else. */
export function trustFileRoots(home: string): TrustedRoot[] {
  // An address is trusted by key; `domain:<host>` (no port, SPEC.md §7.4) by the domain, as --trust-root <host>.
  return Object.keys(readRoots(home)).map((r) => {
    const domain = domainOfRoot(r)
    return domain === null ? { address: r } : { domain }
  })
}

/** Adds `root` to a home's trust file as the CLI's addTrust does (an entry it has stays): 0600, written whole, renamed. */
export function addTrust(home: string, root: string, now: number): void {
  if (!isAddress(root) && domainOfRoot(root) === null)
    throw new ConfigError('trust-invalid', `${JSON.stringify(root)} is not a root a trust file holds`)
  writeRoots(home, { [root]: { added_at: now }, ...readRoots(home) })
}

/** Takes `root` out of a home's trust file as the CLI's removeTrust does: false, nothing written, when it lacks it. */
export function removeTrust(home: string, root: string): boolean {
  const { [root]: gone, ...roots } = readRoots(home)
  if (gone === undefined) return false
  writeRoots(home, roots)
  return true
}

function writeRoots(home: string, roots: Roots): void {
  const tmp = join(home, `.trust.json.${randomUUID()}.tmp`)
  writeFileSync(tmp, `${JSON.stringify({ version: 1, roots }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  renameSync(tmp, join(home, 'trust.json'))
}
