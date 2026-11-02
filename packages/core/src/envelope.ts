import { decodeAddress, isAddress, SUITE_1 } from './address.ts'
import { type CanonicalValue, canonical, isCanonicalInteger } from './canonical.ts'
import { checkChainShape, type Hop, hopTuple } from './chain.ts'
import { AcError } from './errors.ts'
import { sha256hex } from './hash.ts'
import { fromHex, isHex, toHex, utf8 } from './hex.ts'
import { hasExactKeys, hexField, isPlainObject, parseJson, utf8Length } from './json.ts'
import { type Rng, type SignerLike, verifySig } from './keys.ts'
import {
  checkRecipients,
  checkSealed,
  ENVELOPE_VERSION,
  type Recipient,
  type Sealed,
  sealedHash,
  sealTo,
} from './seal.ts'
import type { Thread } from './thread.ts'

export { ENVELOPE_VERSION } from './seal.ts'

/** The crypto suite of v0. */
export const SUITE = SUITE_1.id
/** The envelope cap: 64 KiB of serialized envelope. */
export const MAX_ENVELOPE_BYTES = 65_536
/** The relay TTL, 7 days, and the clock skew allowance. */
export const DEFAULT_TTL = 604_800
export const DEFAULT_SKEW = 300

/** An envelope (spec/SPEC.md §5): the outer fields, relay-visible and covered by sig, and the sealed part. */
export interface Envelope {
  readonly v: 1
  readonly id: string
  readonly to: readonly string[]
  readonly from: string
  readonly auth: readonly Hop[]
  readonly suite: 1
  readonly ts: number
  readonly sealed: Sealed
  readonly sig: string
}

/** An envelope before its id and sig exist. */
export type UnsignedEnvelope = Omit<Envelope, 'id' | 'sig'>

/** The window `ts` must fall in: now - (ttl + skew) <= ts <= now + skew. */
export interface TimeWindow {
  readonly ttl: number
  readonly skew: number
}

export const DEFAULT_WINDOW: TimeWindow = { ttl: DEFAULT_TTL, skew: DEFAULT_SKEW }

const ENVELOPE_KEYS = ['v', 'id', 'to', 'from', 'auth', 'suite', 'ts', 'sealed', 'sig'] as const

/** The envelope id preimage (spec/SPEC.md §2): [v, to, from, auth as [[iss, sub, caveats, exp, sig]...], suite, ts, sealedHash]. */
export function envelopeIdPreimage(e: UnsignedEnvelope): CanonicalValue {
  return [e.v, e.to, e.from, e.auth.map(hopTuple), e.suite, e.ts, sealedHash(e.sealed)]
}

/** The envelope id: sha256hex(utf8(canonical(id preimage))). */
export function envelopeId(e: UnsignedEnvelope): string {
  return sha256hex(canonical(envelopeIdPreimage(e)))
}

/** What buildEnvelope takes. `auth` defaults to the empty chain (self-rooted). */
export interface EnvelopeInput {
  readonly from: SignerLike
  readonly to: readonly Recipient[]
  readonly auth?: readonly Hop[]
  readonly type: string
  readonly thread: Thread
  readonly body: unknown
  readonly ts: number
  readonly rng: Rng
}

/** An envelope and the exact bytes an outbox keeps and retransmits. */
export interface BuiltEnvelope {
  readonly envelope: Envelope
  readonly bytes: Uint8Array
}

function isObject(value: unknown): boolean {
  return typeof value === 'object' && value !== null
}

/**
 * Seals, signs and serializes an envelope. It checks what parseEnvelope would reject (the recipients, the chain's
 * shape and caps, the size), not the chain's meaning: verifyChain is the receiver's check, so tests and the e2e
 * scenarios can build an envelope whose chain must fail. An input, signer or recipient that is null or not an object,
 * and a `to` that is not a list, are bad-shape, each checked where it is first read, so a bad ts or chain keeps its
 * own code. A signer whose signature is not 64 bytes of hex is bad-hex.
 */
export function buildEnvelope(input: EnvelopeInput): BuiltEnvelope {
  if (!isObject(input)) throw new AcError('bad-shape', 'an envelope input is an object')
  if (!isCanonicalInteger(input.ts)) throw new AcError('bad-shape', 'ts is an integer number of Unix seconds')
  const auth = checkChainShape(input.auth ?? [])
  if (!isObject(input.from)) throw new AcError('bad-shape', 'the signer is an object')
  const from = input.from.address
  if (!Array.isArray(input.to) || !input.to.every(isObject)) throw new AcError('bad-shape', 'to: recipients')
  const sealed = sealTo(
    input.to,
    from,
    { type: input.type, thread: input.thread, body: input.body },
    input.rng,
  )
  const to = input.to.map((r) => r.address)
  const unsigned: UnsignedEnvelope = {
    v: ENVELOPE_VERSION,
    to,
    from,
    auth,
    suite: SUITE,
    ts: input.ts,
    sealed,
  }
  return assembleEnvelope(unsigned, toHex(input.from.sign(fromHex(envelopeId(unsigned), 32))))
}

/**
 * The built envelope of its unsigned form and a signature over its id, without a key: buildEnvelope's last step
 * (bad-hex for a bad sig, envelope-too-large over the cap). The signer signs envelopeIdPreimage(unsigned); the sig is
 * checkSig's to verify. It checks only the signature and the size cap, not the unsigned form (buildEnvelope does
 * those checks before calling it; parseEnvelope and checkSig verify later), so a hand-made malformed unsigned form
 * can throw something other than an AcError.
 */
export function assembleEnvelope(unsigned: UnsignedEnvelope, sig: string): BuiltEnvelope {
  const { v, to, from, auth, suite, ts, sealed } = unsigned
  const id = envelopeId(unsigned)
  const envelope: Envelope = { v, id, to, from, auth, suite, ts, sealed, sig: hexField(sig, 64, 'sig') }
  const bytes = serializeEnvelope(envelope)
  if (bytes.length > MAX_ENVELOPE_BYTES) {
    throw new AcError('envelope-too-large', `${bytes.length} bytes; the cap is ${MAX_ENVELOPE_BYTES}`)
  }
  return { envelope, bytes }
}

/**
 * An envelope split into its unsigned form, its id and the signed one. `signed` is the input itself and `id` is its
 * `id`, not recomputed, so the id is the digest the sender signed for a valid envelope only (checkId verifies it).
 */
export function splitEnvelope(e: Envelope): {
  readonly unsigned: UnsignedEnvelope
  readonly id: string
  readonly signed: Envelope
} {
  const { v, to, from, auth, suite, ts, sealed } = e
  return { unsigned: { v, to, from, auth, suite, ts, sealed }, id: e.id, signed: e }
}

/** The envelope as UTF-8 JSON, members in the order of spec/SPEC.md §5, no white space. */
export function serializeEnvelope(e: Envelope): Uint8Array {
  return utf8(
    JSON.stringify({
      v: e.v,
      id: e.id,
      to: e.to,
      from: e.from,
      auth: e.auth.map((h) => ({ iss: h.iss, sub: h.sub, caveats: h.caveats, exp: h.exp, sig: h.sig })),
      suite: e.suite,
      ts: e.ts,
      sealed: {
        wraps: e.sealed.wraps.map((w) => ({ to: w.to, enc: w.enc, ct: w.ct })),
        nonce: e.sealed.nonce,
        ct: e.sealed.ct,
      },
      sig: e.sig,
    }),
  )
}

/**
 * Parses envelope bytes (spec/SPEC.md §5): envelope-too-large over 65,536 bytes, bad-json for anything that is not
 * UTF-8 JSON, then checkEnvelope's checks. It verifies nothing cryptographic: that is verifyOuter and verifyChain.
 */
export function parseEnvelope(input: Uint8Array | string): Envelope {
  const size = typeof input === 'string' ? utf8Length(input) : input.length
  if (size > MAX_ENVELOPE_BYTES) {
    throw new AcError('envelope-too-large', `${size} bytes; the cap is ${MAX_ENVELOPE_BYTES}`)
  }
  return checkEnvelope(parseJson(input))
}

function addressField(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new AcError('bad-shape', `${name} is an address string`)
  if (!isAddress(value)) throw new AcError('bad-address', `${name} is not an address`)
  return value
}

/**
 * Checks a parsed envelope, in the order of spec/SPEC.md §5: an object; v (bad-shape, bad-version); suite
 * (bad-shape, bad-suite); exactly the nine members (bad-shape); id; to; from; auth (chain rules 1 to 4); ts; sealed;
 * sig. Returns a copy with the members in wire order.
 */
export function checkEnvelope(value: unknown): Envelope {
  if (!isPlainObject(value)) throw new AcError('bad-shape', 'an envelope is a JSON object')
  if (typeof value.v !== 'number') throw new AcError('bad-shape', 'v is the integer 1')
  if (value.v !== ENVELOPE_VERSION) throw new AcError('bad-version', `v is ${value.v}; this reader knows 1`)
  if (typeof value.suite !== 'number') throw new AcError('bad-shape', 'suite is the integer 1')
  if (value.suite !== SUITE) throw new AcError('bad-suite', `suite is ${value.suite}; this reader knows 1`)
  if (!hasExactKeys(value, ENVELOPE_KEYS)) {
    throw new AcError('bad-shape', 'an envelope has exactly v, id, to, from, auth, suite, ts, sealed and sig')
  }
  const id = hexField(value.id, 32, 'id')
  const to = checkRecipients(value.to)
  const from = addressField(value.from, 'from')
  const auth = checkChainShape(value.auth)
  if (!isCanonicalInteger(value.ts)) throw new AcError('bad-shape', 'ts is an integer from 0 to 2^53 - 1')
  const sealed = checkSealed(value.sealed, to)
  const sig = hexField(value.sig, 64, 'sig')
  return { v: ENVELOPE_VERSION, id, to, from, auth, suite: SUITE, ts: value.ts, sealed, sig }
}

/** bad-id unless the id recomputes from the other fields. */
export function checkId(e: Envelope): void {
  if (envelopeId(e) !== e.id) throw new AcError('bad-id', 'the id does not match the envelope')
}

/** bad-sig unless sig is from's Ed25519 signature over the 32 bytes of the id. */
export function checkSig(e: Envelope): void {
  const ok =
    isHex(e.id, 32) && isHex(e.sig, 64) && verifySig(decodeAddress(e.from), fromHex(e.id), fromHex(e.sig))
  if (!ok) throw new AcError('bad-sig', "sig is not from's signature over the id")
}

/** stale-ts when ts < now - (ttl + skew); future-ts when ts > now + skew. */
export function checkTs(ts: number, now: number, window: TimeWindow = DEFAULT_WINDOW): void {
  if (ts < now - (window.ttl + window.skew)) throw new AcError('stale-ts', 'ts is older than the window')
  if (ts > now + window.skew) throw new AcError('future-ts', 'ts is ahead of the clock by more than the skew')
}

/**
 * The outer checks, in order (spec/SPEC.md §5): 1 to 16 unique recipients, the id recomputes, the sig verifies, and
 * now - (ttl + skew) <= ts <= now + skew. The relay's policy order runs the chain between the sig and the ts window;
 * it composes checkId, checkSig, verifyChain and checkTs itself.
 */
export function verifyOuter(e: Envelope, now: number, window: TimeWindow = DEFAULT_WINDOW): void {
  checkRecipients(e.to)
  checkId(e)
  checkSig(e)
  checkTs(e.ts, now, window)
}
