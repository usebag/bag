import { isAddress } from './address.ts'
import { type CanonicalValue, isCanonicalInteger } from './canonical.ts'
import { AcError } from './errors.ts'
import { isHex } from './hex.ts'
import { hasExactKeys, isPlainObject, utf8Length } from './json.ts'
import { type SignerLike, signPreimage, verifyPreimage } from './keys.ts'

/** The domain tag of a hop preimage. */
export const HOP_TAG = 'ac/hop/1'
/** Caps. */
export const MAX_HOPS = 8
export const MAX_CAVEATS = 32
export const MAX_CAVEAT_BYTES = 256

/**
 * One hop of an authority chain: `iss` grants to `sub`, under the caveats this hop adds,
 * until `exp` (Unix seconds); `sig` is iss's signature over the hop preimage.
 */
export interface Hop {
  readonly iss: string
  readonly sub: string
  readonly caveats: readonly string[]
  readonly exp: number
  readonly sig: string
}

/** What a valid chain establishes: its root, the principal it names, and the effective caveats in chain order. */
export interface ChainResult {
  readonly root: string
  readonly principal: string
  readonly caveats: readonly string[]
}

const HOP_KEYS = ['iss', 'sub', 'caveats', 'exp', 'sig'] as const

/** The hop preimage (spec/SPEC.md §2): ["ac/hop/1", iss, sub, caveats, exp]. */
export function hopPreimage(h: Omit<Hop, 'sig'>): CanonicalValue {
  return [HOP_TAG, h.iss, h.sub, h.caveats, h.exp]
}

/** A hop's position in the envelope id preimage: [iss, sub, caveats, exp, sig]. */
export function hopTuple(h: Hop): CanonicalValue {
  return [h.iss, h.sub, h.caveats, h.exp, h.sig]
}

/** A signed hop from `issuer` to `sub`. Throws the shape codes of rules 2 to 4 for a hop that could not pass them. */
export function signHop(issuer: SignerLike, sub: string, caveats: readonly string[], exp: number): Hop {
  const unsigned = { iss: issuer.address, sub, caveats: [...caveats], exp }
  checkChainShape([{ ...unsigned, sig: '0'.repeat(128) }])
  return { ...unsigned, sig: signPreimage(issuer, hopPreimage(unsigned)) }
}

/** The signed hop of its unsigned form and a signature, without a key: signHop's last step (the shape codes apply). */
export function assembleHop(unsigned: Omit<Hop, 'sig'>, sig: string): Hop {
  return checkChainShape([{ ...unsigned, sig }])[0] as Hop
}

function isWellFormedHop(h: unknown): h is Hop {
  return (
    isPlainObject(h) &&
    hasExactKeys(h, HOP_KEYS) &&
    isAddress(h.iss) &&
    isAddress(h.sub) &&
    Array.isArray(h.caveats) &&
    h.caveats.every((c: unknown) => typeof c === 'string' && c.length > 0 && c.isWellFormed()) &&
    isCanonicalInteger(h.exp) &&
    isHex(h.sig, 64)
  )
}

/**
 * Rules 1 to 4 of the chain (spec/SPEC.md §6), each over every hop before the next rule: at most 8 hops
 * (too-many-hops); each hop well-formed (bad-hop); at most 32 caveats per hop (too-many-caveats); each caveat at most
 * 256 UTF-8 bytes (caveat-too-long). bad-shape when auth is not a list. Returns copies of the hops.
 */
export function checkChainShape(auth: unknown): readonly Hop[] {
  if (!Array.isArray(auth)) throw new AcError('bad-shape', 'auth is a list of hops')
  if (auth.length > MAX_HOPS)
    throw new AcError('too-many-hops', `${auth.length} hops; the cap is ${MAX_HOPS}`)
  const hops: Hop[] = []
  for (const [i, h] of auth.entries()) {
    if (!isWellFormedHop(h)) throw new AcError('bad-hop', `hop ${i} is not well-formed`)
    hops.push({ iss: h.iss, sub: h.sub, caveats: [...h.caveats], exp: h.exp, sig: h.sig })
  }
  for (const [i, h] of hops.entries()) {
    if (h.caveats.length > MAX_CAVEATS) {
      throw new AcError(
        'too-many-caveats',
        `hop ${i} has ${h.caveats.length} caveats; the cap is ${MAX_CAVEATS}`,
      )
    }
  }
  for (const [i, h] of hops.entries()) {
    if (h.caveats.some((c) => utf8Length(c) > MAX_CAVEAT_BYTES)) {
      throw new AcError('caveat-too-long', `hop ${i} has a caveat over ${MAX_CAVEAT_BYTES} bytes`)
    }
  }
  return hops
}

/**
 * Verifies an authority chain for the key `from` at time `ts` (spec/SPEC.md §6). Rules in order, each over every hop
 * before the next: 1 to 4 (checkChainShape); 5, hop[i].sub == hop[i+1].iss (chain-broken); 6, the last sub is `from`
 * (chain-not-to-sender); 7, hop[i+1].exp <= hop[i].exp (exp-not-monotone); 8, ts <= exp for every hop
 * (hop-expired); 9, every hop's sig verifies under its iss (bad-hop-sig). An empty chain is self-rooted: root =
 * from. Caveats are only collected here; evaluating them is the edge's work, never the relay's.
 */
export function verifyChain(auth: readonly Hop[], from: string, ts: number): ChainResult {
  if (!isAddress(from)) throw new AcError('bad-address', 'from is not an address')
  if (!isCanonicalInteger(ts)) throw new AcError('bad-shape', 'ts is an integer from 0 to 2^53 - 1')
  const hops = checkChainShape(auth)
  const pairs = hops.slice(1).map((next, i) => [hops[i] as Hop, next] as const)
  for (const [i, [a, b]] of pairs.entries()) {
    if (a.sub !== b.iss) throw new AcError('chain-broken', `hop ${i}'s sub is not hop ${i + 1}'s iss`)
  }
  const last = hops.at(-1)
  if (last !== undefined && last.sub !== from) {
    throw new AcError('chain-not-to-sender', "the last hop's sub is not the sender")
  }
  for (const [i, [a, b]] of pairs.entries()) {
    if (b.exp > a.exp) throw new AcError('exp-not-monotone', `hop ${i + 1} expires after hop ${i}`)
  }
  for (const [i, h] of hops.entries()) {
    if (ts > h.exp) throw new AcError('hop-expired', `hop ${i} expired before ts`)
  }
  for (const [i, h] of hops.entries()) {
    if (!verifyPreimage(h.iss, hopPreimage(h), h.sig))
      throw new AcError('bad-hop-sig', `hop ${i}'s sig does not verify`)
  }
  return {
    root: hops[0]?.iss ?? from,
    principal: last?.iss ?? from,
    caveats: hops.flatMap((h) => h.caveats),
  }
}
