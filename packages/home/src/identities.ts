import { randomUUID } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { type CaveatEvaluator, codingEvaluator, isAddress, MAX_RELAYS } from '@usebag/core'
import { checkName, KeyEpochStore, type TrustedRoot } from '@usebag/edge'
import { LABEL } from './index.ts'
import { homeCustody } from './keys.ts'
import { HomeError } from './ports.ts'

// The identities file: the identities one MCP server holds
// with `--identities <file>` and one wake hook watches, each in its own home. Host install adds to it and host remove
// takes from it; packages/mcp/src/identities.ts repeats the reader. The file holds no secret, but it is the one place
// that lists every identity of the machine together, so it is 0600, in a 0700 directory, written whole to a temporary
// file beside it and renamed.

/** A relay URL as a command takes it: http or https, else usage. Returned without a trailing slash. */
export function relayUrl(text: string): string {
  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw new HomeError('usage', `${JSON.stringify(text)} is not a URL`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new HomeError('usage', `${JSON.stringify(text)} is not an http or https URL`)
  }
  return text.replace(/\/+$/, '')
}

/** The caveat profiles an identity may honor: the coding profile's type= and repo= caveats (spec/SPEC.md 6.4). */
export const PROFILES: ReadonlyMap<string, CaveatEvaluator> = new Map([['coding', codingEvaluator]])

// A host name with an optional port, as the edge's well-known resolver takes it.
const DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/

/** A trust root: an address, trusted by key, or a domain, whose well-known record is pinned at first use; else usage. */
export function trustedRoot(text: string): TrustedRoot {
  if (isAddress(text)) return { address: text }
  if (DOMAIN.test(text)) return { domain: text }
  throw new HomeError('usage', `--trust-root ${JSON.stringify(text)} is neither an address nor a domain`)
}

/** The most identities in one file (measured on one relay in e2e scenario 54, 2026-10-30). */
export const MAX_IDENTITIES = 64

/** One identity: its label, its key name in its home (default the label), and its server's per-identity flags. */
export interface Identity {
  readonly label: string
  readonly key?: string
  readonly home: string
  readonly relays: readonly string[]
  readonly rendezvous?: string
  readonly trust_roots?: readonly string[]
  readonly honor?: readonly string[]
  readonly accept_types?: readonly string[]
  /** The peers this identity sends read receipts to, addresses only: a name could be filled by a pairing. */
  readonly receipts_to?: readonly string[]
  readonly keep_alive_records?: boolean
  readonly allow_delegate?: boolean
  readonly policy?: string
  readonly members?: string
}

export interface Identities {
  readonly version: 1
  readonly default?: string
  readonly identities: readonly Identity[]
}

const TOP = ['version', 'default', 'identities']
const LISTS = ['trust_roots', 'honor', 'accept_types', 'receipts_to']
const MEMBERS = ['label', 'key', 'home', 'relays', 'rendezvous', ...LISTS]
const FLAGS = ['keep_alive_records', 'allow_delegate']
const PATHS = ['policy', 'members']

/** An identity's key name in its home. */
export const keyOf = (e: Identity): string => e.key ?? e.label

const bad = (detail: string): HomeError => new HomeError('identities-invalid', detail)
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string')
const object = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Throws unless `f` accepts every value (a URL or root it refuses is identities-invalid). */
function each(values: readonly string[], f: (s: string) => unknown, what: string): void {
  try {
    for (const v of values) f(v)
  } catch (e) {
    throw bad(`${what}: ${(e as Error).message.replace(/^usage: /, '')}`)
  }
}

/** A home as one name per folder: its real path (a link, a case variant on a volume that folds case), else resolved. */
function folder(home: string, at: string, platform: string): string {
  try {
    return realpathSync.native(home)
  } catch (e) {
    // Only a home not made yet is compared as text: one that exists but cannot be read could alias another's.
    const code = (e as { code?: unknown }).code
    if (code !== 'ENOENT') throw bad(`${at}.home ${JSON.stringify(home)} cannot be resolved (${code})`)
    // macOS volumes fold case by default: two homes not made yet that differ only by case would become one folder.
    return platform === 'darwin' ? resolve(home).toLowerCase() : resolve(home)
  }
}

/** The refusal of relays [] for an identity that was published: its records are out, so it is not local-only. */
export const publishedRefusal = (label: string): string => `${label} was published: remove it, not its relays`

/**
 * Whether key `key` of `home` has an epoch its key-records/ marks published, read from its custody's public entry (no
 * key, no keychain dialog); false when the home does not hold it. Both identities.json readers refuse relays [] for one.
 */
export function hasPublished(home: string, key: string): boolean {
  let address: string
  try {
    address = homeCustody(undefined, home).entry(key).address
  } catch {
    return false
  }
  const store = new KeyEpochStore(join(home, 'key-records'))
  return store.epochs(address).some((n) => store.epoch(address, n).published)
}

/** One entry of the list, checked: identities-invalid, or home-shared for a home another entry holds. */
function entry(e: unknown, at: string, homes: Set<string> | null, platform: string): Identity {
  if (!object(e)) throw bad(`${at} is not an object`)
  const extra = Object.keys(e).find((k) => ![...MEMBERS, ...FLAGS, ...PATHS].includes(k))
  if (extra !== undefined) throw bad(`${at} has an unknown member ${JSON.stringify(extra)}`)
  if (typeof e.label !== 'string' || !LABEL.test(e.label)) throw bad(`${at}.label is not ${LABEL.source}`)
  // The key name by the home custodies' own rule (checkName), as the MCP server's reader checks it.
  if (e.key !== undefined && typeof e.key !== 'string') throw bad(`${at}.key is not a string`)
  each([(e.key as string | undefined) ?? e.label], (k) => checkName('key', k), at)
  if (typeof e.home !== 'string' || !isAbsolute(e.home)) throw bad(`${at}.home is not an absolute path`)
  const home = folder(e.home, at, platform)
  if (homes?.has(home))
    throw new HomeError('home-shared', `${at}.home ${e.home} is another identity's: one home per identity`)
  homes?.add(home)
  // No relays is an identity on this machine only: it publishes nothing until identity relays gives it some.
  const relays = e.relays
  if (!strings(relays) || relays.length > MAX_RELAYS)
    throw bad(`${at}.relays is not a list of 0 to ${MAX_RELAYS} URLs`)
  if (relays.length === 0 && hasPublished(home, keyOf(e as unknown as Identity)))
    throw bad(publishedRefusal(e.label))
  each(relays, relayUrl, `${at}.relays`)
  if (new Set(relays.map(relayUrl)).size !== relays.length) throw bad(`${at}.relays repeats a relay`)
  if (e.rendezvous !== undefined) each([e.rendezvous as string], relayUrl, `${at}.rendezvous`)
  for (const k of LISTS) {
    if (e[k] !== undefined && !strings(e[k])) throw bad(`${at}.${k} is not a list of strings`)
  }
  each((e.trust_roots as string[] | undefined) ?? [], trustedRoot, `${at}.trust_roots`)
  for (const h of (e.honor as string[] | undefined) ?? []) {
    if (!PROFILES.has(h))
      throw bad(`${at}.honor ${JSON.stringify(h)} is not a profile: ${[...PROFILES.keys()]}`)
  }
  if ((e.accept_types as string[] | undefined)?.includes(''))
    throw bad(`${at}.accept_types holds an empty type`)
  for (const t of (e.receipts_to as string[] | undefined) ?? []) {
    if (!isAddress(t)) throw bad(`${at}.receipts_to ${JSON.stringify(t)} is not an address`)
  }
  for (const k of FLAGS)
    if (e[k] !== undefined && typeof e[k] !== 'boolean') throw bad(`${at}.${k} is not true or false`)
  for (const k of PATHS) {
    if (e[k] !== undefined && (typeof e[k] !== 'string' || !isAbsolute(e[k]))) {
      throw bad(`${at}.${k} is not an absolute path`)
    }
  }
  return e as unknown as Identity
}

/**
 * `doc` as an identities file, checked whole; identities-invalid (or home-shared) names the first fault. `shared`: the
 * bag service's <home>/identities.json, where every identity has the service's home (no home-shared).
 */
export function checkIdentities(
  doc: unknown,
  platform: string = process.platform,
  shared = false,
): Identities {
  if (!object(doc)) throw bad('the file is not a JSON object')
  const extra = Object.keys(doc).find((k) => !TOP.includes(k))
  if (extra !== undefined) throw bad(`unknown member ${JSON.stringify(extra)}`)
  if (doc.version !== 1) throw bad('version is not 1')
  const list = doc.identities
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_IDENTITIES) {
    throw bad(`identities is not a list of 1 to ${MAX_IDENTITIES}`)
  }
  const homes = shared ? null : new Set<string>()
  const labels = list.map((e, i) => entry(e, `identities[${i}]`, homes, platform).label)
  if (new Set(labels).size !== labels.length) throw bad('a label repeats')
  if (doc.default !== undefined && !labels.includes(doc.default as string))
    throw bad(`default ${JSON.stringify(doc.default)} names no label`)
  return doc as unknown as Identities
}

/**
 * The file, read and checked through one descriptor, opened without blocking (a FIFO cannot hold the reader):
 * identities-invalid when it is a symbolic link or not a regular file, the group or others may read or write it, or it is
 * not one.
 * `allowEmpty`: after every one of those checks, exactly {version: 1, identities: []} is an empty home's file and is
 * returned as it is, in place of failing the 1-to-64 rule (an identity is added to it as to no file).
 */
export function readIdentities(file: string, shared = false, allowEmpty = false): Identities {
  // O_NOFOLLOW, as the home's other files: a link at the path is refused (ELOOP), never read through, so the list the
  // bag service serves is the file at the path itself and nothing a link points it at.
  let fd: number
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ELOOP')
      throw bad(
        `${file} is a symbolic link: it is read only as a regular file, never through a link; replace the link with ` +
          'a 0600 copy of the file it points to',
      )
    throw e
  }
  let text: string
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw bad(`${file} is not a regular file`)
    if ((st.mode & 0o077) !== 0) throw bad(`${file} is open to the group or others: chmod 600 it`)
    text = readFileSync(fd, 'utf8')
  } finally {
    closeSync(fd)
  }
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    throw bad(`${file} is not JSON`)
  }
  if (allowEmpty && isEmptyList(doc)) return { version: 1, identities: [] }
  return checkIdentities(doc, process.platform, shared)
}

/** Exactly {version: 1, identities: []}, with no other member. */
const isEmptyList = (doc: unknown): boolean =>
  object(doc) &&
  Object.keys(doc).length === 2 &&
  doc.version === 1 &&
  Array.isArray(doc.identities) &&
  doc.identities.length === 0

/** Writes the file: its directory made 0700 when missing, a 0600 temporary file beside it, renamed over it. */
export function saveIdentities(file: string, doc: Identities): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  const tmp = join(dirname(file), `.${basename(file)}.${randomUUID()}.tmp`)
  writeFileSync(tmp, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  try {
    renameSync(tmp, file)
  } catch (e) {
    unlinkSync(tmp)
    throw e
  }
}

/** The members host install writes. Any other in an entry is the person's: it is not compared, and it stays. */
const INSTALLED = [
  'label',
  'key',
  'home',
  'relays',
  'rendezvous',
  'trust_roots',
  'keep_alive_records',
] as const

/**
 * `doc` with `e` appended (at the front with `first`), checked whole; null when an entry with the same installed members
 * is there. exists when the label, or the home and key, is there with other settings.
 */
export function addIdentity(doc: Identities, e: Identity, first = false, shared = false): Identities | null {
  const there = doc.identities.find(
    (x) => x.label === e.label || (x.home === e.home && keyOf(x) === keyOf(e)),
  )
  if (there !== undefined && INSTALLED.every((k) => isDeepStrictEqual(there[k], e[k]))) return null
  if (there !== undefined) {
    throw new HomeError(
      'exists',
      `identity ${there.label} is in the file with other settings: edit or remove it first`,
    )
  }
  return checkIdentities(
    { ...doc, identities: first ? [e, ...doc.identities] : [...doc.identities, e] },
    process.platform,
    shared,
  )
}

/** `doc` without the identity `label`, and without `default` when it named it; unknown-identity, last-identity. */
export function removeIdentity(doc: Identities, label: string): Identities {
  const labels = doc.identities.map((x) => x.label)
  if (!labels.includes(label)) {
    throw new HomeError(
      'unknown-identity',
      `no identity ${label} in the file; its labels: ${labels.join(', ')}`,
    )
  }
  if (labels.length === 1) {
    throw new HomeError(
      'last-identity',
      `${label} is the last identity: keep one, or remove the server entry by hand`,
    )
  }
  const { default: dflt, ...rest } = doc
  const identities = doc.identities.filter((x) => x.label !== label)
  return dflt === label ? { ...rest, identities } : { ...doc, identities }
}
