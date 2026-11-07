import { EnterpriseError } from './instance.ts'

// The connect code a person copies once from the console for `bag connect` (minted by the instance): one string
// carrying where to redeem it beside its secret,
//
//   bagcode_<payload>.<secret>
//
// payload is base64url (no padding) of the UTF-8 JSON {"v":1,"instance":"<origin>","domain":"<domain>"}, exactly those
// keys in that order; secret is 32 random bytes in base64url (43 characters); the whole string is at most 900
// characters. The WHOLE string is the code: it is posted as `code` to <instance>/api/v1/auth/agent/redeem, and the
// binding's nonce is sha256hex("bag-ent/bind-nonce/1\n" + the whole string). The server stores the whole string's
// hash, so an instance or domain changed after mint is a code no row holds.
//
// parseConnectCode is the one source of the origin. It MIRRORS the instance's own parser exactly (its rules, its order,
// its one-spelling check); the client carries no server code. test/connect-code.test.ts holds it to the instance's
// verdicts, pinned as fixtures.

export const CONNECT_CODE = { prefix: 'bagcode_', separator: '.', version: 1, maxLength: 900 } as const

/** What a connect code carries. */
export interface ConnectCode {
  /** The instance's API origin: https, or http on a loopback host (the local instance). */
  readonly origin: string
  /** The organisation's proved domain, which the binding names. */
  readonly domain: string
  /** The whole string, which the instance redeems. */
  readonly code: string
}

const SECRET = /^[A-Za-z0-9_-]{43}$/
const LOOPBACK_HOST = /^(?:127(?:\.[0-9]{1,3}){3}|\[::1\]|localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.localhost)$/
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** True for an origin on this machine: the local instance, outside the private-address guard. */
export function isLoopbackOrigin(origin: string): boolean {
  return LOOPBACK_HOST.test(new URL(origin).hostname)
}

/** Why `origin` may not be a code's instance (the instance's own rule for a local instance), or null. */
function instanceProblem(origin: string): string | null {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return 'not an origin'
  }
  if (url.origin !== origin || !/^[a-z0-9.:[\]-]+$/.test(url.host)) return 'not an exact origin'
  if (url.protocol === 'https:') return null
  if (url.protocol === 'http:' && LOOPBACK_HOST.test(url.hostname)) return null
  return 'the instance is https, or http on a loopback host'
}

/** The string the console mints, for a payload and a 43-character secret. */
export function connectCodeOf(payload: { instance: string; domain: string }, secret: string): string {
  const json = JSON.stringify({ v: CONNECT_CODE.version, instance: payload.instance, domain: payload.domain })
  return `${CONNECT_CODE.prefix}${Buffer.from(json, 'utf8').toString('base64url')}${CONNECT_CODE.separator}${secret}`
}

const bad = (detail: string): EnterpriseError =>
  new EnterpriseError('usage', `this is not a connect code from the console: ${detail}`)

/** The parts of a pasted connect code (surrounding white space ignored); usage (exit 2) for anything else. */
export function parseConnectCode(text: string): ConnectCode {
  const code = text.trim()
  if (code.length > CONNECT_CODE.maxLength) throw bad('it is too long')
  if (!code.startsWith(CONNECT_CODE.prefix)) throw bad(`it does not start with ${CONNECT_CODE.prefix}`)
  const parts = code.slice(CONNECT_CODE.prefix.length).split(CONNECT_CODE.separator)
  if (parts.length !== 2) throw bad('it names no instance (copy the whole code)')
  const [encoded, secret] = parts as [string, string]
  if (!SECRET.test(secret) || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw bad('it is cut short or changed')
  let value: unknown
  try {
    value = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
  } catch {
    throw bad('it does not decode')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw bad('it does not decode')
  const v = value as Record<string, unknown>
  if (Object.keys(v).sort().join(',') !== 'domain,instance,v' || v.v !== CONNECT_CODE.version)
    throw bad('it is not of version 1')
  if (typeof v.domain !== 'string' || !HOST.test(v.domain)) throw bad('it names no domain')
  if (typeof v.instance !== 'string') throw bad('it names no instance')
  const problem = instanceProblem(v.instance)
  if (problem !== null) throw bad(`its instance: ${problem}`)
  if (connectCodeOf({ instance: v.instance, domain: v.domain }, secret) !== code)
    throw bad('it is not in its one spelling')
  return { origin: v.instance, domain: v.domain, code }
}
