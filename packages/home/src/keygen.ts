import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { type CustodyTarget, generateEdgeKeys } from '@usebag/edge'
import { keepFirstRecordsLocal } from './first-records.ts'
import { homeCustody, loadKeys, localOnly } from './keys.ts'
import { readWord, visibleLine } from './local.ts'
import { byVersion } from './packaged.ts'
import { HomeError, type HomeIo } from './ports.ts'
import { addToServiceHome, RESERVED, refuseReserved } from './service-home.ts'

// A new identity in a home: a key file or a keychain item made from the random source, or an agent pointer to an
// identity the home holds. Both print the address only, never key material.

/** The refusal of a new identity on a home that holds identities already, unless a new one is asked for. */
export const HOLDS_IDENTITIES =
  'this home holds identities already: use one of them, or pass --new for a new one'

/**
 * The identities a home holds: the names of its key files (keys/), keychain pointers (keychain/) and agent pointers
 * (agent/), sorted. identities.json alone is not read, so a 0.3.0 home, which has none, counts by its files. The bag
 * service's own key files (RESERVED: <label>.service.json and the like) are no identity, as for local delivery's hide and
 * show and for status --home, so a home whose only file is a stale service key is a fresh home.
 */
export function heldIdentities(home: string): string[] {
  const names = new Set<string>()
  for (const d of ['keys', 'keychain', 'agent']) {
    let entries: string[]
    try {
      entries = readdirSync(join(home, d))
    } catch {
      continue
    }
    for (const f of entries) {
      if (!f.endsWith('.json') || f.startsWith('.')) continue
      const name = f.slice(0, -'.json'.length)
      if (!RESERVED.some((x) => name.endsWith(x))) names.add(name)
    }
  }
  return [...names].sort()
}

/**
 * Refuses (exists) a new identity on a home that holds others, unless `allowNew`: one home serves every identity of a
 * machine, so a second one is the person's choice. A fresh home, and a name the home holds, pass.
 */
export function refuseSecond(home: string, name: string, allowNew: boolean): void {
  const held = heldIdentities(home)
  if (!allowNew && held.length > 0 && !held.includes(name)) throw new HomeError('exists', HOLDS_IDENTITIES)
}

/**
 * The first bag service whose identities reader takes an entry with relays []. An older one, still running after an
 * update, refuses the whole identities file with such an entry and keeps serving its old list.
 */
export const LOCAL_ONLY_SERVICE = '0.4.3'

/** Whether pid answers kill 0; EPERM (a process of another user) reads as alive. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/**
 * Refuses (busy) an identity on this machine only while <home>/run/service.json, read once, names a live bag service
 * older than LOCAL_ONLY_SERVICE: no socket, no network. A missing or unreadable file, a pid that is not an integer or
 * is gone, a version that is no strict X.Y.Z, and 0.0.0 (an unbuilt service) pass.
 */
function refuseOlderService(home: string): void {
  let s: unknown
  try {
    s = JSON.parse(readFileSync(join(home, 'run', 'service.json'), 'utf8'))
  } catch {
    return
  }
  if (typeof s !== 'object' || s === null) return
  const { pid, version } = s as { pid?: unknown; version?: unknown }
  if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid <= 1 || !alive(pid)) return
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version) || version === '0.0.0') return
  if (byVersion(version, LOCAL_ONLY_SERVICE) < 0)
    throw new HomeError(
      'busy',
      `the running bag service (pid ${pid}) is bag ${version}, ` +
        'which refuses an identities file that holds an identity on this machine only: ' +
        'finish the update first (step P4 of the update page restarts it on the new version), then run this again',
    )
}

/** How a new key-holding identity is made. */
export interface CreateOptions {
  /** The custody it goes to. */
  readonly into: CustodyTarget
  /** Whether the custody was chosen for the person (then a keychain says so in a warning). */
  readonly defaulted: boolean
  /** Whether a home that holds other identities takes it. */
  readonly allowNew: boolean
  /** A warning given once the identity is made, before its service entry. */
  readonly note?: string
  /** What a failure of the custody's create becomes (a caller adds how to run it again); the error itself otherwise. */
  readonly refused?: (e: unknown) => unknown
  /** Its relays in the service entry (checked URLs); absent, the install env's or the file's first entry's. */
  readonly relays?: readonly string[]
  /**
   * On this machine only: the service entry has relays [] (never the inherited ones) and its first records are kept in
   * the home, published nowhere (keepFirstRecordsLocal); identity relays promotes it later. Not with `relays`.
   */
  readonly local?: boolean
}

/**
 * Makes the identity `name`: a new signing key and a separate sealing key from the random source, kept by the custody
 * `into` (never over an existing file); adds it to <home>/identities.json for the bag service (with `relays` when
 * given); says its address and returns it. Warns that a defaulted keychain holds it, the note, the service entry's line, and, with local delivery on
 * and the name not hidden, how to keep it apart from the home's other identities.
 */
export function createIdentity(io: HomeIo, home: string, name: string, o: CreateOptions): string {
  refuseReserved(name)
  if (o.local === true && (o.relays?.length ?? 0) > 0)
    throw new HomeError('usage', `${name} on this machine only takes no relays`)
  if (o.local === true) refuseOlderService(home)
  refuseSecond(home, name, o.allowNew)
  const keys = generateEdgeKeys(io.rng)
  try {
    homeCustody(io.security, home).create(name, keys, o.into)
  } catch (e) {
    throw o.refused === undefined ? e : o.refused(e)
  }
  // Signed with the keys in hand, so a keychain identity raises no dialog; kept before the service entry names it.
  const kept = o.local === true ? keepFirstRecordsLocal(io, home, name, keys) : []
  if (o.defaulted && o.into.custody === 'keychain')
    io.warn(`keygen: ${name} is kept in the macOS keychain (bag:${name})`)
  if (o.note !== undefined) io.warn(o.note)
  // The bag service serves <home>/identities.json: the new identity goes in it (service-home.ts).
  const added = addToServiceHome(home, name, o.relays, undefined, o.local === true)
  if (added !== null) io.warn(added)
  // An identity the bag service now serves is, with the word on, visible to the home's others: say how to hide it.
  const word = readWord(home)
  if (added !== null && word.on && !word.hidden.includes(name)) io.warn(visibleLine(name))
  io.say(keys.signing.address)
  for (const line of kept) io.say(line)
  return keys.signing.address
}

/**
 * Refuses (no-relays) an agent pointer to `principal` when its service entry has relays []: an agent identity is never
 * on this machine only (spec/SPEC.md 9.2 item 4), and the pointer shares the principal's address.
 */
function refuseLocalPrincipal(home: string, principal: string): void {
  if (localOnly(home, principal))
    throw new HomeError(
      'no-relays',
      `${principal} is on this machine only, and an agent identity never is: give it relays with bag identity relays ${principal} --relay <url> first`,
    )
}

/**
 * The agent pointer `name`: <home>/agent/<name>.json (public data) for the address and sealing key of the key file or
 * keychain identity `principal`, which a login then lets the agent hold for a window. Makes no key (a keychain
 * principal raises its one dialog); `recovery` is written into the pointer, a format field only. Refuses a name a key
 * custody holds (EEXIST). Adds it to <home>/identities.json for the bag service when a relay is known (the install
 * env's, or the file's first entry's), with the same warns as createIdentity. Says the address and returns it.
 */
export function createAgentPointer(
  io: HomeIo,
  home: string,
  name: string,
  principal: string,
  recovery?: string,
): string {
  refuseReserved(name)
  const custody = homeCustody(io.security, home)
  custody.holder(name)
  const held = ['keys', 'keychain'].map((d) => join(home, d, `${name}.json`)).find(existsSync)
  if (held !== undefined) throw new HomeError('EEXIST', `${name} is held already, by ${held}`)
  refuseLocalPrincipal(home, principal)
  const keys = loadKeys(io.security, home, principal)
  custody.agent.create(name, keys, recovery)
  // As createIdentity: the bag service serves <home>/identities.json, and an agent identity opens there as a session of
  // it (<name>.service); with no relay known nothing is written, and identity relays adds it later.
  const added = addToServiceHome(home, name)
  if (added !== null) io.warn(added)
  const word = readWord(home)
  if (added !== null && word.on && !word.hidden.includes(name)) io.warn(visibleLine(name))
  io.say(keys.signing.address)
  return keys.signing.address
}
