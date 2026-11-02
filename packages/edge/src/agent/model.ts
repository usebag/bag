import {
  AcError,
  type AcErrorCode,
  type CanonicalValue,
  canonical,
  checkChainShape,
  type Hop,
  isAcError,
  isAddress,
  isCanonicalInteger,
  isHex,
  MAX_ENVELOPE_BYTES,
  parseJson,
  type SignerLike,
  sha256hex,
  signPreimage,
  utf8,
} from '@usebag/core'

// The agent's request, its codes and its caps: data and pure checks, no socket
// and no key. The framing is an implementation default: one JSON object per request.

/** Position 0 of the request preimage, so a session's signature for the agent is never another object. */
export const AGENT_TAG = 'ac/agent/1'

// The agent's caps are implementation defaults to confirm in the build (no basis). The caveat, hop
// and envelope caps are the core's: MAX_CAVEATS, MAX_CAVEAT_BYTES, MAX_HOPS, MAX_ENVELOPE_BYTES.
/** A window lasts at most 8 hours, and no hop's `exp` is past `now` + 8 hours. */
export const WINDOW_MAX = 28_800
/** At least one caveat on a grant and on a derived hop. */
export const MIN_CAVEATS = 1
/** Openings and signatures per session per minute (no basis). */
export const OPENS_PER_MINUTE = 600
export const SIGNS_PER_MINUTE = 60
/** Registered thread ids per session in a window (no basis). */
export const THREADS_PER_SESSION = 4_096
/** Requests on one connection, `seq` 0 to SEQ_MAX - 1, before it must be made again (no basis). */
export const SEQ_MAX = 1_000_000
/** The connection nonce: 32 random bytes, sent as 64 hex. */
export const NONCE_BYTES = 32
/** A device hop's `exp` is at most `now` + 30 days (no basis). */
export const DEVICE_MAX = 2_592_000
/** The groups whose generations one window holds, two each (no basis). */
export const GROUPS_MAX = 32

/** The agent's own codes, proposed for Appendix A: raised on the socket only, never on the wire. */
export const AGENT_CODES = ['agent-locked', 'not-in-grant'] as const
export type AgentLocalCode = (typeof AGENT_CODES)[number]
/** Every code the agent answers: the reused closed set of Appendix A and its own two. */
export type AgentCode = AcErrorCode | AgentLocalCode

/** A refusal with one of the agent's codes. The message adds a detail; it never holds key material. */
export class AgentError extends Error {
  readonly code: AgentCode

  constructor(code: AgentCode, detail: string) {
    super(`${code}: ${detail}`)
    this.name = 'AgentError'
    this.code = code
  }
}

/** The code of a refusal (an AgentError or an AcError); anything else is a fault, not a verdict, and is rethrown. */
export function codeOf(error: unknown): AgentCode {
  if (error instanceof AgentError || isAcError(error)) return error.code
  throw error
}

/** The session ops: a closed set, so anything else is `bad-shape` and never a request to sign. */
export type AgentOp = 'sign' | 'open' | 'register'

interface RequestHead {
  readonly seq: number
  readonly session: string
  readonly sig: string
  /** sha256hex(canonical(args)). */
  readonly argsHash: string
  /** The chain when the request carries one, shape-checked (§6.2 rules 1 to 4) and still to be judged. */
  readonly chain: readonly Hop[] | null
}

/** `sign`, args `[sub, caveats, exp]`. */
export interface SignRequest extends RequestHead {
  readonly op: 'sign'
  readonly sub: string
  readonly caveats: readonly string[]
  readonly exp: number
}

/** `open`, args `[mailbox, id]`, the envelope's exact JSON text beside them. */
export interface OpenRequest extends RequestHead {
  readonly op: 'open'
  readonly mailbox: string
  readonly id: string
  readonly envelope: string
}

/** `register`, args `[thread]`. */
export interface RegisterRequest extends RequestHead {
  readonly op: 'register'
  readonly thread: string
}

export type AgentRequest = SignRequest | OpenRequest | RegisterRequest

type Signed = Pick<AgentRequest, 'seq' | 'session' | 'op' | 'argsHash'>

const HEAD: readonly string[] = ['seq', 'session', 'op', 'args', 'sig']

function bad(detail: string): never {
  throw new AcError('bad-shape', detail)
}

const isOp = (v: unknown): v is AgentOp => v === 'sign' || v === 'open' || v === 'register'

/**
 * Parses one request: exactly `seq`, `session`, `op`, `args` and `sig`, an optional `chain`, and for `open` the
 * `envelope` text. `bad-shape` for anything else (an unknown op included), a `sub` that is not an address too;
 * a malformed chain gets the chain's own shape codes, an envelope over the cap `envelope-too-large`. Every string is
 * then bounded but the caveats, which `deriveHop` bounds before any use. It verifies nothing: that is the Agent's.
 */
export function parseRequest(input: Uint8Array | string): AgentRequest {
  const v = parseJson(input, 'bad-shape')
  if (typeof v !== 'object' || v === null || Array.isArray(v)) bad('a request is a JSON object')
  const o = v as Record<string, unknown>
  const { op, seq, session, sig, args: a, envelope } = o
  if (!isOp(op)) bad('op is sign, open or register')
  const allowed = op === 'open' ? [...HEAD, 'chain', 'envelope'] : [...HEAD, 'chain']
  const keys = Object.keys(o)
  if (!HEAD.every((k) => keys.includes(k)) || !keys.every((k) => allowed.includes(k))) {
    bad('a request has exactly seq, session, op, args and sig, and may carry chain')
  }
  if (!isCanonicalInteger(seq) || !isAddress(session) || !isHex(sig, 64) || !Array.isArray(a)) {
    bad('seq is an integer, session an address, sig 64 bytes of hex and args a list')
  }
  const head = { seq, session, sig, chain: Object.hasOwn(o, 'chain') ? checkChainShape(o.chain) : null }
  if (op === 'sign') {
    const ok = a.length === 3 && isAddress(a[0]) && Array.isArray(a[1]) && isCanonicalInteger(a[2])
    if (!ok || !a[1].every((c: unknown) => typeof c === 'string')) bad('sign args are [sub, caveats, exp]')
    return { ...head, op, argsHash: argsHash(a), sub: a[0], caveats: [...a[1]], exp: a[2] }
  }
  if (op === 'open') {
    if (a.length !== 2 || !isAddress(a[0]) || !isHex(a[1], 32)) bad('open args are [mailbox, id]')
    if (typeof envelope !== 'string') bad('open carries the envelope as JSON text')
    if (utf8(envelope).length > MAX_ENVELOPE_BYTES) throw new AcError('envelope-too-large', 'over the cap')
    return { ...head, op, argsHash: argsHash(a), mailbox: a[0], id: a[1], envelope }
  }
  if (a.length !== 1 || !isHex(a[0], 32)) bad('register args are [thread], a 32-byte thread id')
  return { ...head, op, argsHash: argsHash(a), thread: a[0] }
}

/** sha256hex(utf8(canonical(args))). */
export function argsHash(args: CanonicalValue): string {
  return sha256hex(canonical(args))
}

/** The request preimage: ["ac/agent/1", nonce, seq, session, op, argsHash]. */
export function requestPreimage(nonce: string, r: Signed): CanonicalValue {
  return [AGENT_TAG, nonce, r.seq, r.session, r.op, r.argsHash]
}

/**
 * The session's side of the request: a request's JSON text, signed by the session key with the connection's nonce. `args` is
 * `[sub, caveats, exp]`, `[mailbox, id]` or `[thread]`; `extras` the chain (first request) and an open's envelope.
 */
export function buildRequest(
  session: SignerLike,
  nonce: string,
  seq: number,
  op: AgentOp,
  args: readonly CanonicalValue[],
  extras: { readonly chain?: readonly Hop[]; readonly envelope?: string } = {},
): string {
  const signed = { seq, session: session.address, op, argsHash: argsHash(args) }
  const sig = signPreimage(session, requestPreimage(nonce, signed))
  return JSON.stringify({ seq, session: session.address, op, args, sig, ...extras })
}
