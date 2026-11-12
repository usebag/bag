import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { CliError, relayUrl } from './args.ts'
import { addIdentity, type Identities, readIdentities, saveIdentities } from './identities.ts'

// The bag service serves the identities of <home>/identities.json only. So the
// commands that make or restore an identity in a home (keygen, init, restore) add that label's entry there, making the
// file when there is none, and identity relays adds a missing one: a fresh machine, or an identity no folder wired, is
// then one the service holds. The entry is the file's existing format, the home's defaults: its relays from the
// command's --relay, else install/<name>.env, else the file's first entry; keep_alive_records true, as host install's.

/** RELAYS and RENDEZVOUS of <home>/install/<name>.env, read as text, never sourced; null when absent. */
export function installEnv(
  home: string,
  name: string,
): { relays: string[]; rendezvous: string | null } | null {
  let text: string
  try {
    text = readFileSync(join(home, 'install', `${name}.env`), 'utf8')
  } catch {
    return null
  }
  const value = (k: string) => new RegExp(`^${k}="([^"]*)"$`, 'm').exec(text)?.[1]
  const relays = value('RELAYS')
  if (relays === undefined) return null
  return { relays: relays.split(/\s+/).filter(Boolean), rendezvous: value('RENDEZVOUS') ?? null }
}

/**
 * Adds `name` to <home>/identities.json when it is not there, and returns the line that says so; null when it is there
 * already, or when no relay is known (none given, no install env, no entry in the file): then nothing is written, and
 * identity relays adds it later.
 */
export function addToServiceHome(
  home: string,
  name: string,
  relays: readonly string[] = [],
  rendezvous?: string,
): string | null {
  const at = resolve(home)
  const file = join(at, 'identities.json')
  const doc: Identities = existsSync(file) ? readIdentities(file, true) : { version: 1, identities: [] }
  if (doc.identities.some((e) => e.label === name)) return null
  const env = installEnv(at, name)
  const use = relays.length > 0 ? [...relays] : (env?.relays ?? doc.identities[0]?.relays ?? [])
  if (use.length === 0) return null
  const meet = rendezvous ?? (relays.length > 0 ? undefined : (env?.rendezvous ?? undefined))
  const next = addIdentity(
    doc,
    {
      label: name,
      key: name,
      home: at,
      relays: use.map(relayUrl),
      ...(meet === undefined ? {} : { rendezvous: relayUrl(meet) }),
      keep_alive_records: true,
    },
    false,
    true,
  )
  if (next !== null) saveIdentities(file, next)
  return `added ${name} to ${file} for the bag service (relays ${use.join(' ')})`
}

/** The name suffixes the bag service's own files use under keys/ (an agent identity's session key: <label>.service.json). */
export const RESERVED = ['.service', '.session', '.signin'] as const

/** Refuses an identity name ending in a reserved suffix: the service's start-up sweep could take its key for its own. */
export function refuseReserved(name: string): void {
  const s = RESERVED.find((x) => name.endsWith(x))
  if (s !== undefined) {
    throw new CliError(
      'bad-name',
      `${JSON.stringify(name)} ends in ${s}, which is reserved for the bag service's own files: choose another name`,
    )
  }
}
