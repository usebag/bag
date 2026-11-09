import { isAcceptRoot, MAX_ROOTS, WILDCARD_ROOT } from '@usebag/core'
import type { Fetch } from './instance.ts'
import type { Session } from './session.ts'

// The agent's accept list (the console's "Takes mail from"): GET <instance>/api/v1/agent/accept-list with the session's
// bearer: 200 { accept: [root...], etag } (an ETag header too), 304 to a matching If-None-Match, 404 from an instance
// older than the list. A root is an address (a partner's pinned org key) or domain:<host>, the org's own root first.
// The list is the roots of the accept-from record the agent signs (records.ts), so a partner's mail is taken at the
// relay; inbox's trust in a partner comes from GET /agent/trust (source partner:<id>), never from this list. An answer
// with "*", more than MAX_ROOTS or an entry that is not a root is refused whole, with a line: the list kept stays. A call
// that fails, or a refusal, keeps the list too (the next tick asks again); a 404 is [org.root].

export const ACCEPT_LIST_PATH = '/api/v1/agent/accept-list'
const TIMEOUT_MS = 3_000

/** The roots of the agent's accept-from record: the list kept from the instance, else the org's own root. */
export const acceptRoots = (s: Session): string[] => [...(s.accept_roots ?? [s.org.root])]

/** The roots of an answer, the org's root first and once; a string naming why when it is not a list to sign. */
function rootsOf(s: Session, accept: unknown): string[] | string {
  if (!Array.isArray(accept)) return 'accept is not a list'
  if (accept.includes(WILDCARD_ROOT)) return 'it names "*"'
  if (!accept.every((r) => typeof r === 'string' && isAcceptRoot(r))) return 'an entry is not a root'
  const roots = [...new Set([s.org.root, ...(accept as string[])])]
  return roots.length > MAX_ROOTS ? `${roots.length} roots; the cap is ${MAX_ROOTS}` : roots
}

/**
 * The session with the accept list the instance answers now: unchanged on a 304, a failed call or a refused answer
 * (with a line to `warn`); [org.root] on a 404. Only a live session asks.
 */
export async function syncAcceptList(
  s: Session,
  f: Fetch | undefined,
  warn: (line: string) => void,
): Promise<Session> {
  if (s.state !== 'live' || f === undefined) return s
  const headers = new Headers({ accept: 'application/json', authorization: `Bearer ${s.access_token}` })
  if (s.accept_etag !== undefined) headers.set('if-none-match', s.accept_etag)
  let res: Response
  let doc: { accept?: unknown; etag?: unknown } | null = null
  try {
    const signal = AbortSignal.timeout(TIMEOUT_MS)
    res = await f(`${s.instance}${ACCEPT_LIST_PATH}`, { method: 'GET', headers, redirect: 'error', signal })
    if (res.status === 200) doc = JSON.parse(await res.text())
  } catch {
    return s
  }
  if (res.status === 404) {
    const { accept_roots: _, accept_etag: __, ...rest } = s
    return rest
  }
  if (res.status !== 200) return s
  const roots = rootsOf(s, doc?.accept)
  if (typeof roots === 'string') {
    warn(`bag: the accept list of ${s.domain} was refused (${roots}); the accept-from record keeps its roots`)
    return s
  }
  const etag = typeof doc?.etag === 'string' ? doc.etag.slice(0, 200) : res.headers.get('etag')
  return { ...s, accept_roots: roots, ...(etag === null ? {} : { accept_etag: etag }) }
}
