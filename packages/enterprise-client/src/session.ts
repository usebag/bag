import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { type Hop, hopPreimage, isAddress, isDomainHost, verifyPreimage } from '@usebag/core'
import { type EdgeKeys, FsKeyStore } from '@usebag/edge'
import { EnterpriseError } from './instance.ts'

// A home's bag enterprise sessions, one profile per organisation: <home>/orgs/<domain> is the profile's own home, whose
// enterprise/ (0700) holds the files below; <home>/enterprise/current.json names the most recently connected profile.
// A home of the older shape, its one session's files directly in <home>/enterprise, is moved into the profile of its
// domain on first touch (migrate). Each profile's enterprise/ holds session.json (0600: the token, the generation, the
// org hop and the local hop), pending.json (0600: the agent's keys' name and a device code waiting on a person), chain.json ([org root -> A,
// A -> session key], 0600 though a chain is public: bag's `send --auth` and the MCP server's --chain-cmd) and refresh.lock. The keys
// are key files of the home (FsKeyStore, 0600 in 0700): A is the identity <name>, the agent's address and mailbox;
// <name>.signin signs only bag-ent/refresh/1 and bag-ent/state/1; <name>.session signs sends under the local hop.

/**
 * Throws unless `path` is a directory (or a regular file) that no one but its owner may read, write or enter: the rule
 * of @usebag/edge's custody/files.ts `strict`, which the edge does not export. It guards only this package's own
 * files: the enterprise directory and its JSON.
 */
export function ownerOnly(prefix: string, path: string, directory: boolean): void {
  const st = lstatSync(path)
  if (directory ? !st.isDirectory() : !st.isFile())
    throw new Error(`${prefix}: ${path} is not a ${directory ? 'directory' : 'regular file'}`)
  if ((st.mode & 0o077) !== 0) {
    const mode = (st.mode & 0o777).toString(8).padStart(4, '0')
    throw new Error(`${prefix}: ${path} has mode ${mode}; it must be ${directory ? '0700' : '0600'}`)
  }
}

/**
 * Holds the bag home to its owner before the client writes in it: a home that exists and is this user's becomes 0700
 * (a `mkdir -p ~/.bag` makes it 0755 first), its enterprise directory 0700, and every file this client writes there
 * 0600 (session, pending, chain and records files, the refresh lock, trust.json). A home, directory or file of another
 * user is refused (home-invalid), nothing changed. A missing home is left to the first write, which makes it 0700. A
 * symbolic link among the files is not followed: the strict reads refuse it.
 */
export function secureHome(home: string, uid: number | undefined = process.getuid?.()): void {
  let st: ReturnType<typeof statSync>
  try {
    st = statSync(home)
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return
    throw e
  }
  const theirs = (s: { uid: number }) => uid !== undefined && s.uid !== uid
  if (!st.isDirectory()) throw new EnterpriseError('home-invalid', `${home} is not a directory`)
  if (theirs(st))
    throw new EnterpriseError('home-invalid', `${home} belongs to another user: use your own home`)
  const own = (path: string, directory: boolean): void => {
    let s: ReturnType<typeof lstatSync>
    try {
      s = lstatSync(path)
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT') return
      throw e
    }
    if (s.isSymbolicLink() || (directory ? !s.isDirectory() : !s.isFile())) return
    if (theirs(s)) throw new EnterpriseError('home-invalid', `${path} belongs to another user`)
    if ((s.mode & 0o077) !== 0) chmodSync(path, directory ? 0o700 : 0o600)
  }
  own(home, true)
  own(join(home, 'orgs'), true)
  const files = (at: string) => {
    own(enterpriseDir(at), true)
    for (const f of ['session.json', 'pending.json', 'chain.json', 'records.json', 'refresh.lock'])
      own(join(enterpriseDir(at), f), false)
  }
  files(home)
  migrate(home)
  for (const d of profiles(home)) {
    own(profileHome(home, d), true)
    files(profileHome(home, d))
  }
  own(currentPath(home), false)
  own(join(home, 'trust.json'), false)
}

/** A profile's own home: <home>/orgs/<domain>, a lowercase host (so never a path of its own). */
export function profileHome(home: string, domain: string): string {
  if (!isDomainHost(domain)) throw new EnterpriseError('usage', `${JSON.stringify(domain)} is not a domain`)
  return join(home, 'orgs', domain)
}
const currentPath = (home: string): string => join(home, 'enterprise', 'current.json')

/** The organisations this home holds a session or a waiting sign-in of, sorted. */
export function profiles(home: string): string[] {
  let names: string[]
  try {
    names = readdirSync(join(home, 'orgs'))
  } catch {
    return []
  }
  const held = (d: string) =>
    (['session', 'pending'] as const).some((f) => existsSync(fileOf(join(home, 'orgs', d), f)))
  return names.filter((d) => isDomainHost(d) && held(d)).sort()
}

/** Names `domain` the most recently connected profile. */
export function setCurrent(home: string, domain: string): void {
  mkdirSync(enterpriseDir(home), { recursive: true, mode: 0o700 })
  ownerOnly('enterprise', enterpriseDir(home), true)
  writeJson(currentPath(home), { v: 1, domain })
}

/**
 * The profile a command acts on: `org` when given (null when the home holds none of it); else the only one; else the
 * most recently connected (current.json), or the first by name when that names none held. Null for none.
 */
export function selectOrg(home: string, org?: string): string | null {
  migrate(home)
  const all = profiles(home)
  if (org !== undefined) return all.includes(org) ? org : null
  if (all.length <= 1) return all[0] ?? null
  let current: unknown = null
  try {
    current = JSON.parse(readFileSync(currentPath(home), 'utf8')).domain
  } catch {
    // none, or unreadable: the first by name
  }
  return all.find((d) => d === current) ?? (all[0] as string)
}

/** The older shape, one session in <home>/enterprise: its files move into the profile of its domain, once. */
export function migrate(home: string): void {
  const old = enterpriseDir(home)
  // A symbolic link or another kind of file is left where it is: the strict reads refuse it.
  const plain = (f: 'session' | 'pending') => {
    try {
      return lstatSync(fileOf(home, f)).isFile() ? readJson<Session | Pending>(home, f) : null
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT' || (e as { code?: unknown }).code === 'ENOTDIR')
        return null
      throw e
    }
  }
  const domain = (plain('session') ?? plain('pending'))?.domain
  if (domain === undefined) return
  if (typeof domain !== 'string' || !isDomainHost(domain))
    throw new EnterpriseError('session-invalid', `${old} holds a session of no domain`)
  const to = enterpriseDir(profileHome(home, domain))
  mkdirSync(to, { recursive: true, mode: 0o700 })
  for (const f of ['session.json', 'pending.json', 'chain.json', 'records.json']) {
    try {
      if (!existsSync(join(to, f))) renameSync(join(old, f), join(to, f))
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'ENOENT') throw e
    }
  }
  drop(join(old, 'session.json'), join(old, 'pending.json'))
  if (!existsSync(currentPath(home))) setCurrent(home, domain)
}

export interface Org {
  readonly domain: string
  readonly root: string
  readonly relays: readonly string[]
}

export interface Session {
  readonly v: 1
  readonly domain: string
  readonly instance: string
  readonly name: string
  /** The label the agent was given (--label, or the console's), when one was: bag connect and status print it. */
  readonly label?: string
  readonly agent_address: string
  readonly session_address: string
  readonly access_token: string
  readonly token_exp: number
  readonly generation: number
  readonly org: Org
  readonly hop: Hop | null
  readonly hop_got_at: number | null
  readonly local_hop: Hop | null
  readonly trust_etag: string
  readonly trust_applied: string | null
  /** The peer links this organisation granted at its last trust answer (its sync claims those, and its own). */
  readonly trust_peers?: readonly string[]
  /** The agent's accept list at the instance's last answer (accept-list.ts), and its etag; unset, [org.root]. */
  readonly accept_roots?: readonly string[]
  readonly accept_etag?: string
  readonly state: 'live' | 'frozen' | 'paused' | 'lapsed' | 'ended'
  readonly reason: string | null
  readonly refreshed_at: number
  readonly state_call_at: number | null
}

export interface Pending {
  readonly v: 1
  readonly domain: string
  readonly instance: string
  readonly name: string
  readonly label?: string
  readonly device_code: string
  readonly user_code: string | null
  readonly verification_uri: string | null
  readonly interval: number
  readonly expires_at: number
}

export const enterpriseDir = (home: string): string => join(home, 'enterprise')
/** A profile's chain and refresh lock, `at` its own home (profileHome). */
export const chainAt = (at: string): string => join(at, 'enterprise', 'chain.json')
export const lockAt = (at: string): string => join(at, 'enterprise', 'refresh.lock')
const fileOf = (home: string, f: 'session' | 'pending'): string => join(home, 'enterprise', `${f}.json`)
/** The chain file of the selected profile (selectOrg), or of the home's older shape when it holds none. */
export const chainPath = (home: string, org?: string): string => chainAt(atOf(home, org))
export const lockPath = (home: string, org?: string): string => lockAt(atOf(home, org))
const atOf = (home: string, org?: string): string => {
  const d = selectOrg(home, org)
  return d === null ? home : profileHome(home, d)
}

/** Writes JSON through a new file of `mode` and a rename, so a reader never sees half of it. */
export function writeJson(path: string, value: unknown, mode = 0o600): void {
  const tmp = `${path}.${randomUUID()}.tmp`
  writeFileSync(tmp, `${JSON.stringify(value)}\n`, { mode, flag: 'wx' })
  renameSync(tmp, path)
}

function readJson<T>(home: string, f: 'session' | 'pending'): T | null {
  const path = fileOf(home, f)
  let doc: { v?: unknown } | null = null
  try {
    ownerOnly('enterprise', path, false)
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return null
  }
  if (doc?.v !== 1)
    throw new EnterpriseError('session-invalid', `${path} is not a session file of version 1, 0600`)
  return doc as T
}

/** A profile's session and waiting sign-in, `at` its own home (profileHome). */
export const sessionAt = (at: string): Session | null => readJson<Session>(at, 'session')
export const pendingAt = (at: string): Pending | null => readJson<Pending>(at, 'pending')
/**
 * The session of `org`, or with none given of the selected profile (selectOrg), else of any profile that holds one;
 * null for none. readPending likewise for a waiting sign-in.
 */
export const readSession = (home: string, org?: string): Session | null => held(home, org, sessionAt)
export const readPending = (home: string, org?: string): Pending | null => held(home, org, pendingAt)
function held<T>(home: string, org: string | undefined, read: (at: string) => T | null): T | null {
  const first = selectOrg(home, org)
  if (org !== undefined) return first === null ? null : read(profileHome(home, first))
  for (const d of [first, ...profiles(home)]) {
    const v = d === null ? null : read(profileHome(home, d))
    if (v !== null) return v
  }
  return null
}
export function write(home: string, f: 'session' | 'pending', value: Session | Pending): void {
  mkdirSync(enterpriseDir(home), { recursive: true, mode: 0o700 })
  ownerOnly('enterprise', enterpriseDir(home), true)
  writeJson(fileOf(home, f), value)
}

/** Removes the files named, those that are there. */
export function drop(...paths: string[]): void {
  for (const path of paths) {
    try {
      unlinkSync(path)
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'ENOENT') throw e
    }
  }
}

export const dropPending = (home: string): void => drop(fileOf(home, 'pending'))
export const dropSession = (home: string): void =>
  drop(fileOf(home, 'session'), chainAt(home), fileOf(home, 'pending'))

/** The key files of an agent: A, the sign-in key and the session key. */
export const keyNames = (name: string) => [name, `${name}.signin`, `${name}.session`] as const
export const keyFile = (home: string, name: string): string => join(home, 'keys', `${name}.json`)
export const loadKey = (home: string, name: string): EdgeKeys => new FsKeyStore(join(home, 'keys')).load(name)

/** The org hop the instance handed back, kept only when it is a live hop from the org's root to A, root-signed. */
export function checkOrgHop(hop: unknown, org: Org, agent: string, now: number): Hop | null {
  const h = hop as Hop | null
  if (h === null) return null
  const ok = h?.iss === org.root && h.sub === agent && Array.isArray(h.caveats) && Number.isSafeInteger(h.exp)
  if (!ok || h.exp <= now || !verifyPreimage(h.iss, hopPreimage(h), h.sig))
    throw new EnterpriseError('bad-answer', `the org hop is not a live hop from ${org.root} to ${agent}`)
  return { iss: h.iss, sub: h.sub, caveats: [...h.caveats], exp: h.exp, sig: h.sig }
}

/** The organisation as the instance names it: the domain signed in to, its root address and its relays. */
export function checkOrg(org: unknown, domain: string): Org {
  const o = org as Org | null
  const ok = o?.domain === domain && isAddress(o.root) && Array.isArray(o.relays)
  if (!ok || !o.relays.every((r) => typeof r === 'string' && /^https?:\/\//.test(r)))
    throw new EnterpriseError('bad-answer', `the instance named no organisation for ${domain}`)
  return { domain, root: o.root, relays: [...o.relays] }
}
