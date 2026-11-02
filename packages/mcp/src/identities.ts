import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'
import { MAX_RELAYS } from '@usebag/core'
import { checkName } from '@usebag/edge'
import {
  type Config,
  ConfigError,
  PROFILES,
  receiptPeer,
  relayUrl,
  type ServerConfig,
  type ServerWide,
  trustedRoot,
} from './config.ts'

// The --identities file: one 0600 JSON file that lists the
// server's identities, each with its own home, key, relays and trust. It is read once, at start, and checked whole
// before anything opens: every refusal is a ConfigError, so a bad file exits 2 as a bad flag does. The CLI writes the
// format (packages/cli/src/identities.ts); check-imports keeps this package off the CLI, so the reading is repeated
// here. Homes are only resolved (their real paths, to find a shared one), never opened: open.ts does that, per
// identity. config.ts imports this file, so its bindings are used only inside functions, never at the top level.

/** The most identities one file lists (set on 2026-10-30, measured on one relay in e2e scenario 54). */
export const MAX_IDENTITIES = 64
/** A label, the name tools take as `as`: local only, never sent. */
export const LABEL = /^[a-z0-9][a-z0-9_-]{0,31}$/

const TOP = ['version', 'default', 'identities']
const MEMBERS = [
  ...['label', 'key', 'home', 'relays', 'rendezvous', 'trust_roots', 'honor', 'accept_types'],
  ...['keep_alive_records', 'allow_delegate', 'policy', 'members', 'receipts_to'],
]

type Entry = Readonly<Record<string, unknown>>
type Bad = (detail: string) => ConfigError

const usage = (detail: string): ConfigError => new ConfigError('usage', `--identities: ${detail}`)
const show = (v: unknown): string => (v === undefined ? 'absent' : JSON.stringify(v))
const isObject = (v: unknown): v is Entry => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * Reads and checks the file at `file`: its identities, each with the server-wide values, and the default label.
 * `platform` decides how homes not made yet compare (realHome); tests pass it.
 */
export function readIdentities(
  file: string,
  wide: ServerWide,
  platform: NodeJS.Platform = process.platform,
): Pick<ServerConfig, 'identities' | 'defaultLabel'> {
  if (!isAbsolute(file)) throw usage(`${JSON.stringify(file)} is not an absolute path`)
  const doc = fileOf(file)
  if (!isObject(doc)) throw usage(`${file} is not a JSON object`)
  for (const k of Object.keys(doc)) if (!TOP.includes(k)) throw usage(`unknown member ${JSON.stringify(k)}`)
  if (doc.version !== 1) throw usage(`version is ${show(doc.version)}; this server reads version 1`)
  const entries = doc.identities
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_IDENTITIES)
    throw usage(`identities is a list of 1 to ${MAX_IDENTITIES} identities`)
  const identities = entries.map((e, i) => identityOf(e, i, wide))
  distinct(identities, platform)
  const defaultLabel = doc.default === undefined ? (identities[0] as Config).label : doc.default
  if (!identities.some((c) => c.label === defaultLabel))
    throw usage(`default ${show(doc.default)} names no identity`)
  return { identities, defaultLabel: defaultLabel as string }
}

/**
 * The file's parsed JSON (undefined when it is not JSON), through one fd: a regular file only (a FIFO or /dev/stdin
 * would eat the server's stdin; O_NONBLOCK keeps the open from waiting on a FIFO's writer), of mode 0600.
 */
function fileOf(file: string): unknown {
  let fd = -1
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK)
  } catch (e) {
    throw usage(`${file} cannot be read (${(e as NodeJS.ErrnoException).code})`)
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw usage(`${file} is not a regular file`)
    if ((st.mode & 0o077) !== 0) {
      const octal = (st.mode & 0o777).toString(8).padStart(4, '0')
      throw usage(`${file} has mode ${octal}; it must be 0600 (it lists every identity together)`)
    }
    const text = readFileSync(fd, 'utf8')
    try {
      return JSON.parse(text)
    } catch {
      return undefined
    }
  } finally {
    closeSync(fd)
  }
}

/**
 * A home's real path (symlinks followed, its on-disk case); resolved if not made yet, and then lower-cased on darwin,
 * whose file systems fold case by default, so homes made later that differ only by case still compare equal.
 */
function realHome(home: string, platform: NodeJS.Platform): string {
  try {
    return realpathSync.native(home)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code !== 'ENOENT') throw usage(`home ${JSON.stringify(home)} cannot be resolved (${code})`)
    return platform === 'darwin' ? resolve(home).toLowerCase() : resolve(home)
  }
}

/** Throws unless every label and every home (by its real path) is one identity's own (§2.2). */
function distinct(all: readonly Config[], platform: NodeJS.Platform): void {
  const homes = all.map((c) => realHome(c.home, platform))
  all.forEach((c, i) => {
    const label = all.findIndex((d) => d.label === c.label)
    if (label < i)
      throw usage(`identities[${i}] repeats the label ${JSON.stringify(c.label)} of identities[${label}]`)
    const home = homes.indexOf(homes[i] as string)
    if (home < i) {
      const other = JSON.stringify((all[home] as Config).label)
      throw new ConfigError(
        'home-shared',
        `--identities: identities[${i}] ${JSON.stringify(c.label)} has the home of identities[${home}] ${other}; ` +
          'each identity has its own',
      )
    }
  })
}

/** Entry `i` as a Config, with the server-wide values and no session, chain or mailbox. */
function identityOf(e: unknown, i: number, wide: ServerWide): Config {
  if (!isObject(e)) throw usage(`identities[${i}] is not an object`)
  const label = e.label
  if (typeof label !== 'string' || !LABEL.test(label))
    throw usage(`identities[${i}]: label is ${show(label)}; it must match ${LABEL.source}`)
  const at = `--identities: identities[${i}] ${JSON.stringify(label)}`
  const bad: Bad = (detail) => new ConfigError('usage', `${at}: ${detail}`)
  for (const k of Object.keys(e)) if (!MEMBERS.includes(k)) throw bad(`unknown member ${JSON.stringify(k)}`)
  const as = str(e, 'key', bad) ?? label
  try {
    checkName('key', as)
  } catch (err) {
    throw bad((err as Error).message)
  }
  const home = str(e, 'home', bad, true)
  if (home === undefined) throw bad('home is required')
  const relays = (list(e, 'relays', bad) ?? []).map((r) => relayUrl(r, `${at}: relays`))
  const distinctRelays = new Set(relays).size
  if (relays.length === 0 || relays.length > MAX_RELAYS || distinctRelays < relays.length) {
    throw bad(
      `relays is 1 to ${MAX_RELAYS} distinct relay URLs, not ${relays.length} (${distinctRelays} distinct)`,
    )
  }
  const given = str(e, 'rendezvous', bad)
  const trustRootTexts = list(e, 'trust_roots', bad) ?? []
  const honor = [...new Set(list(e, 'honor', bad) ?? [])]
  for (const p of honor) {
    if (!(PROFILES as readonly string[]).includes(p))
      throw bad(`honor ${JSON.stringify(p)} is not a profile; the profiles are ${PROFILES.join(', ')}`)
  }
  const types = list(e, 'accept_types', bad) ?? []
  if (types.includes('')) throw bad('accept_types holds an empty type')
  return {
    label,
    as,
    home,
    relays,
    rendezvous: given === undefined ? (relays[0] as string) : relayUrl(given, `${at}: rendezvous`),
    trustRootTexts,
    trustRoots: trustRootTexts.map((t) => trustedRoot(t, `${at}: trust_roots`)),
    honor,
    acceptTypes: types.length > 0 ? [...new Set(types)] : ['*'],
    auth: null,
    chainCmd: null,
    mailbox: null,
    session: null,
    allowDelegate: flag(e, 'allow_delegate', bad),
    allowSessionDelegation: false,
    keepAliveRecords: flag(e, 'keep_alive_records', bad),
    receiptsTo: (list(e, 'receipts_to', bad) ?? []).map((t) => receiptPeer(t, `${at}: receipts_to`)),
    policy: str(e, 'policy', bad, true) ?? null,
    members: str(e, 'members', bad, true) ?? null,
    ...wide,
  }
}

/** Member `m`: a string (an absolute path when `path`), or undefined when absent. */
function str(e: Entry, m: string, bad: Bad, path = false): string | undefined {
  const v = e[m]
  if (v === undefined) return undefined
  if (typeof v !== 'string') throw bad(`${m} is not a string`)
  if (path && !isAbsolute(v)) throw bad(`${m} ${JSON.stringify(v)} is not an absolute path`)
  return v
}

/** Member `m`: a list of strings, or undefined when absent. */
function list(e: Entry, m: string, bad: Bad): string[] | undefined {
  const v = e[m]
  if (v === undefined || (Array.isArray(v) && v.every((s) => typeof s === 'string'))) return v
  throw bad(`${m} is not a list of strings`)
}

/** Member `m`: true or false; false when absent. */
function flag(e: Entry, m: string, bad: Bad): boolean {
  const v = e[m]
  if (v === undefined || typeof v === 'boolean') return v === true
  throw bad(`${m} is not true or false`)
}
