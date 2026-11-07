// The agent's calls to a bag enterprise instance (the agent contract, "Agent sign-in"): JSON over fetch under
// <origin>/api/v1/auth, each within a timeout. A refusal answers RFC 6749 5.2's shape, extended: { error, error_description, detail?, server_time? }; it becomes an EnterpriseError with `error` as
// its code and `detail` as its reason. The token rides in the Authorization header only, never in a URL or a line.

export type Fetch = (url: string, init: RequestInit) => Promise<Response>

export const AGENT_PATHS = {
  code: '/agent/code',
  redeem: '/agent/redeem',
  token: '/agent/token',
  refresh: '/agent/refresh',
  state: '/agent/state',
  signOut: '/agent/sign-out',
  trust: '/agent/trust',
} as const

const ENDED = ['agent_revoked', 'agent_lapsed', 'signed-out']
const WAITING = ['authorization_pending', 'agent_frozen', 'stale_generation', 'org_suspended', 'no-hop']

/**
 * A refusal, with the exit status the commands give it (the contract's AGENT_EXIT): 1 refused or failed, 2 usage, 3
 * the session has ended, 4 waiting on a person of the organisation. Its detail never holds a token or a key.
 */
export class EnterpriseError extends Error {
  readonly code: string
  readonly reason: string | null
  readonly exit: number
  constructor(code: string, detail: string, reason: string | null = null) {
    super(`${code}: ${detail}`)
    ;[this.code, this.reason] = [code, reason]
    this.exit = ENDED.includes(code) ? 3 : WAITING.includes(code) ? 4 : code === 'usage' ? 2 : 1
  }
}

const WORD = /^[a-z][a-z0-9_-]{0,63}$/
const plain = (s: unknown): string =>
  typeof s === 'string' ? s.replace(/[^\x20-\x7e]/g, ' ').slice(0, 300) : ''

/** One call to the instance at `origin`: a POST of `body`, or a GET when it is null; the answer's JSON, null for 204. */
export async function call<T>(
  f: Fetch | undefined,
  origin: string,
  path: string,
  body: object | null,
  bearer?: string,
) {
  if (f === undefined) throw new EnterpriseError('unreachable', 'this io has no fetch')
  const headers: Record<string, string> = { accept: 'application/json', 'content-type': 'application/json' }
  if (bearer !== undefined) headers.authorization = `Bearer ${bearer}`
  let res: Response
  try {
    const init = { method: body === null ? 'GET' : 'POST', headers, redirect: 'error' as const }
    const signal = AbortSignal.timeout(10_000)
    res = await f(`${origin}/api/v1/auth${path}`, {
      ...init,
      signal,
      ...(body === null ? {} : { body: JSON.stringify(body) }),
    })
  } catch (e) {
    throw new EnterpriseError(
      'unreachable',
      `${origin} did not answer ${path}: ${plain((e as Error).message)}`,
    )
  }
  if (res.status === 204) return null as T
  let doc: Record<string, unknown> | null = null
  try {
    doc = JSON.parse(await res.text()) as Record<string, unknown>
  } catch {
    // not JSON: a refusal below
  }
  if (res.ok && typeof doc === 'object' && doc !== null) return doc as T
  const code = typeof doc?.error === 'string' && WORD.test(doc.error) ? doc.error : `http-${res.status}`
  const reason = typeof doc?.detail === 'string' && WORD.test(doc.detail) ? doc.detail : null
  const time = Number.isSafeInteger(doc?.server_time) ? `server time ${doc?.server_time}` : ''
  const said = [plain(doc?.error_description), reason ?? '', time].filter((s) => s !== '').join('; ')
  throw new EnterpriseError(code, `${path}: ${said || res.status}`, reason)
}
