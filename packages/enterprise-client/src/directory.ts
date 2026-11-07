import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isAddress } from '@usebag/core'
import { isLoopbackOrigin } from './connect-code.ts'
import { EnterpriseError, type Fetch } from './instance.ts'
import { enterpriseDir, profileHome, readSession, type Session, writeJson } from './session.ts'

// The organisation's directory: every agent of the organisation by its label (the console's agents list), so that an
// agent is addressable by its label from connect onwards, with no name book entry and no record step. GET
// <instance>/api/v1/agent/directory with the session's bearer: 200 { agents: [{ label, address, connectedAt }], etag },
// 304 to a matching If-None-Match, 401 or 403 when the session is not live. The instance is the session's own origin,
// pinned (https, or http on a loopback host); no DNS, no redirect, a 3 s timeout, the bearer in its header only. The
// answer is kept in the profile's <home>/orgs/<domain>/enterprise/directory.json (0600, written whole; a symbolic link
// or another user's file is refused), so one organisation's list never answers for another's, and served from there
// while under 60 s old, or, with its age in a line on stderr, when the call fails. `org` picks the profile (--org).

export const DIRECTORY_PATH = '/api/v1/agent/directory'
/** A label as the directory resolves it: the grammar of the name book's names, compared in lowercase. */
export const LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/
const [TTL_MS, TIMEOUT_MS] = [60_000, 3_000]
const WORD = /^[a-z][a-z0-9_-]{0,63}$/

export interface DirectoryAgent {
  readonly label: string
  readonly address: string
  readonly connectedAt: string
}

export interface Directory {
  readonly agents: readonly DirectoryAgent[]
  readonly fetchedAt: number // when the instance last gave or confirmed the list, in ms since the epoch
  readonly source: 'instance' | 'cache' | 'stale' // fetched now; a copy under 60 s old; an older copy, the call failed
}

export interface DirectoryOptions {
  readonly refresh?: boolean // asks the instance even when the copy is under 60 s old
  readonly fetch?: Fetch
  readonly now?: () => number
  readonly warn?: (line: string) => void
  readonly org?: string // the profile (--org); unset, the selected one (selectOrg)
}

interface Copy extends Omit<Directory, 'source'> {
  readonly v: 1
  readonly session: string
  readonly etag: string | null
}

/** The kept copy of `domain`'s directory: in its profile, never shared between organisations. */
export const directoryPath = (home: string, domain: string): string =>
  join(enterpriseDir(profileHome(home, domain)), 'directory.json')
const plain = (s: string): string => s.replace(/[^\x20-\x7e]/g, ' ').slice(0, 200)
const sessionKey = (s: Session): string => `${s.domain} ${s.instance} ${s.agent_address}`

/** The well-formed entries of a list (a label of 1 to 100 printable characters, an address); the rest left out. */
function entries(list: unknown): DirectoryAgent[] {
  const ok = (x: unknown): x is DirectoryAgent => {
    const e = x as Partial<Record<keyof DirectoryAgent, unknown>> | null
    const label = typeof e?.label === 'string' && /^[\x20-\x7e]{1,100}$/.test(e.label)
    return label && isAddress(e?.address) && typeof e?.connectedAt === 'string'
  }
  const kept = Array.isArray(list) ? list.filter(ok).slice(0, 10_000) : []
  return kept.map((e) => ({ label: e.label, address: e.address, connectedAt: plain(e.connectedAt) }))
}

/** The session's instance as a pinned origin: https, or http on a loopback host; anything else is refused. */
function pinned(s: Session): string {
  const url = URL.canParse(s.instance) ? new URL(s.instance) : null
  const local = url?.protocol === 'http:' && isLoopbackOrigin(s.instance)
  if (url?.origin === s.instance && (url.protocol === 'https:' || local)) return url.origin
  throw new EnterpriseError('session-invalid', `the session's instance ${plain(s.instance)} is not an origin`)
}

/** The JSON of `text`, or null when it is not JSON. */
function json<T>(text: string): Partial<T> | null {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** The kept copy of this session, or null (none, not JSON, another session's); refused unless this user's, 0600. */
function readCopy(home: string, s: Session, uid = process.getuid?.()): Copy | null {
  const path = directoryPath(home, s.domain)
  const refused = () =>
    new EnterpriseError('home-invalid', `${path} must be a regular file of this user, 0600`)
  let [fd, text]: [number, string | null] = [-1, null]
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return null
    throw refused()
  }
  try {
    const st = fstatSync(fd)
    const mine = st.isFile() && (uid === undefined || st.uid === uid) && (st.mode & 0o077) === 0
    text = mine ? readFileSync(fd, 'utf8') : null
  } finally {
    closeSync(fd)
  }
  if (text === null) throw refused()
  const doc = json<Copy>(text)
  if (doc?.v !== 1 || doc.session !== sessionKey(s) || !Number.isSafeInteger(doc.fetchedAt)) return null
  const etag = typeof doc.etag === 'string' ? doc.etag : null
  return { ...(doc as Copy), etag, agents: entries(doc.agents) }
}

type Answer = { agents: DirectoryAgent[] | null; etag: string | null } | { fail: string }

/** One GET of the directory. A refusal (401, 403) is thrown; any other failure is returned, so a copy may serve. */
async function ask(f: Fetch, origin: string, s: Session, etag: string | null): Promise<Answer> {
  const headers = new Headers({ accept: 'application/json', authorization: `Bearer ${s.access_token}` })
  if (etag !== null) headers.set('if-none-match', etag)
  let res: Response
  let text = ''
  try {
    const signal = AbortSignal.timeout(TIMEOUT_MS)
    res = await f(`${origin}${DIRECTORY_PATH}`, { method: 'GET', headers, redirect: 'error', signal })
    if (res.status !== 304) text = await res.text()
  } catch (e) {
    return { fail: plain((e as Error).message) }
  }
  if (res.status === 304) return { agents: null, etag }
  const doc = text.length <= 1 << 20 ? json<{ agents: unknown; etag: unknown; error: unknown }>(text) : null
  if (res.status === 401 || res.status === 403) {
    const code = typeof doc?.error === 'string' && WORD.test(doc.error) ? doc.error : 'session-not-live'
    throw new EnterpriseError(code, `${origin} refused the directory (${res.status}): run bag status`)
  }
  if (!res.ok || !Array.isArray(doc?.agents))
    return { fail: res.ok ? 'not a directory' : `http-${res.status}` }
  return { agents: entries(doc.agents), etag: typeof doc.etag === 'string' ? doc.etag.slice(0, 200) : null }
}

/**
 * The organisation's directory for the home's session: the kept copy while under 60 s old (unless `refresh`), else
 * the instance's answer, kept; when the call fails, the copy of any age, with a warning line naming its age. Throws
 * no-session with no session, the refusal when the session is not live, unreachable with no answer and no copy.
 */
export async function directory(home: string, o: DirectoryOptions = {}): Promise<Directory> {
  const s = readSession(home, o.org)
  if (s === null) throw new EnterpriseError('no-session', `no session in ${home}: run bag connect`)
  const origin = pinned(s)
  const now = (o.now ?? Date.now)()
  const copy = readCopy(home, s)
  const age = copy === null ? 0 : now - copy.fetchedAt
  const view = ({ agents, fetchedAt }: Copy, source: Directory['source']) => ({ agents, fetchedAt, source })
  if (copy !== null && o.refresh !== true && age >= 0 && age < TTL_MS) return view(copy, 'cache')
  const a = await ask(o.fetch ?? fetch, origin, s, copy?.etag ?? null)
  if ('fail' in a) {
    if (copy === null) throw new EnterpriseError('unreachable', `${origin} did not answer: ${a.fail}`)
    const line = `bag: ${origin} did not answer the directory (${a.fail}); using the copy from ${Math.round(age / 1000)} s ago`
    ;(o.warn ?? ((l: string) => process.stderr.write(`${l}\n`)))(line)
    return view(copy, 'stale')
  }
  const agents = a.agents ?? copy?.agents
  if (agents === undefined) throw new EnterpriseError('bad-answer', `${origin} answered 304 to no copy`)
  const kept: Copy = { v: 1, session: sessionKey(s), etag: a.etag, fetchedAt: now, agents }
  writeJson(directoryPath(home, s.domain), kept)
  return view(kept, 'instance')
}

/**
 * The address of the organisation's agent labelled `label` (any case), or undefined when none is. A miss in a copy
 * under 60 s old asks the instance once more, since an agent connected since then is addressable at once. Two agents
 * under one label is an error naming both addresses. The label must fit LABEL once in lowercase.
 */
export async function resolveLabel(home: string, label: string, o: DirectoryOptions = {}) {
  const want = label.toLowerCase()
  if (!LABEL.test(want)) throw new EnterpriseError('usage', `${JSON.stringify(plain(label))} is not a label`)
  const is = (a: DirectoryAgent) => a.label.toLowerCase() === want
  const find = (d: Directory) => [...new Set(d.agents.filter(is).map((a) => a.address))]
  const d = await directory(home, o)
  let found = find(d)
  if (found.length === 0 && d.source === 'cache') found = find(await directory(home, { ...o, refresh: true }))
  const all = `${found.length} agents: ${found.join(' and ')}`
  if (found.length > 1) throw new EnterpriseError('ambiguous-label', `${want} names ${all}`)
  return found[0] as string | undefined
}
