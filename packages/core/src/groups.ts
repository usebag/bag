import { isAddress } from './address.ts'
import { type CanonicalValue, canonical, isCanonicalInteger } from './canonical.ts'
import type { CaveatContext, CaveatEvaluator, CaveatVerdict } from './caveats.ts'
import { type ChainResult, checkChainShape, type Hop, signHop, verifyChain } from './chain.ts'
import { DEFAULT_SKEW } from './envelope.ts'
import { AcError } from './errors.ts'
import { bytesEqual, fromHex, isHex, toHex, utf8 } from './hex.ts'
import { hpkeSeal } from './hpke.ts'
import { hasExactKeys, isPlainObject } from './json.ts'
import { type Rng, SealingKey, type SignerLike, signPreimage, verifyPreimage } from './keys.ts'
import { type AddressRecord, signRecord } from './records.ts'
import type { RecipientKey } from './seal.ts'

// Groups: a group is an identity whose members share its sealing key, one generation at a time. Its record is its
// address record; membership is a hop from the group key that carries `group=<group>`; a generation reaches a
// holder as a `group-key.v1` body: the group key's statement over the generation's public key, and the private
// key wrapped to the holder's own sealing key, so no plaintext key is ever written.

/** The sealed type of the message that hands a generation to a holder. */
export const GROUP_KEY_TYPE = 'group-key.v1'
/** The domain tag of a generation's statement, and the HPKE info of its wrap. */
export const GROUP_KEY_TAG = 'ac/gkey/1'
/** The membership caveat's prefix: `group=<the group's address>`. */
export const GROUP_CAVEAT_PREFIX = 'group='
/** A membership hop's default life. 2026-10-26: 7 days as documented, after the relay cut. */
export const MEMBERSHIP_SECONDS = 604_800
/** The group record's default ttl, an hour. */
export const GROUP_RECORD_TTL = 3_600

/** What the group key signs: that `sealing_key`, the generation's public key, is held by `member`. */
export interface GroupKeyStatement {
  readonly group: string
  readonly generation: number
  readonly sealing_key: string
  readonly member: string
  readonly iat: number
}

/** A `group-key.v1` body: the statement, its signature, the wrap of the private key and the holder's hop. */
export interface GroupKeyBody extends GroupKeyStatement {
  readonly sig: string
  readonly enc: string
  readonly ct: string
  /** The holder's membership hop; null only in the group's own copy, where `member` is the group. */
  readonly hop: Hop | null
}

/** A verified generation: its body, and its private key, opened in memory and never written. */
export interface OpenedGroupKey {
  readonly body: GroupKeyBody
  readonly key: SealingKey
}

/** What a membership chain establishes: the chain's result, the member (its first hop's sub) and its earliest exp. */
export interface Membership extends ChainResult {
  readonly member: string
  readonly exp: number
}

const BODY_KEYS = ['group', 'generation', 'sealing_key', 'member', 'iat', 'sig', 'enc', 'ct', 'hop'] as const

/** The membership caveat of a group. */
export function groupCaveat(group: string): string {
  return `${GROUP_CAVEAT_PREFIX}${group}`
}

/**
 * The groups profile: `group=<address>` holds only when `to` is exactly `[<address>]`, the group alone, fails
 * for any other `to`, and is unknown when malformed; so a member never carries the group's authority to anyone else,
 * not even beside the group (2026-10-26).
 */
export function evaluateGroupCaveat(caveat: string, ctx: CaveatContext): CaveatVerdict {
  const group = caveat.startsWith(GROUP_CAVEAT_PREFIX) ? caveat.slice(GROUP_CAVEAT_PREFIX.length) : ''
  if (!isAddress(group)) return 'unknown'
  return ctx.to.length === 1 && ctx.to[0] === group ? 'hold' : 'fail'
}

/** The groups profile's evaluator. */
export const groupEvaluator: CaveatEvaluator = { name: 'groups', evaluate: evaluateGroupCaveat }

/** A membership hop: the group key grants `member` its mailbox and its posts until `exp`. */
export function signMembership(group: SignerLike, member: string, exp: number): Hop {
  return signHop(group, member, [groupCaveat(group.address)], exp)
}

/**
 * Verifies a membership chain for `subject` at `at`: the chain's own rules (verifyChain's codes), then untrusted-root
 * unless the group is its root, and caveat-failed unless its first hop carries the group's caveat.
 */
export function checkMembership(
  auth: readonly Hop[],
  group: string,
  subject: string,
  at: number,
): Membership {
  const chain = verifyChain(auth, subject, at)
  const first = auth[0]
  if (first === undefined || chain.root !== group) {
    throw new AcError('untrusted-root', 'a membership chain starts with a hop from the group')
  }
  if (!first.caveats.includes(groupCaveat(group))) {
    throw new AcError('caveat-failed', 'the first hop does not carry the group caveat')
  }
  return { ...chain, member: first.sub, exp: Math.min(...auth.map((h) => h.exp)) }
}

/** The statement's preimage: ["ac/gkey/1", group, generation, sealing_key, member, iat]. */
export function groupKeyPreimage(s: GroupKeyStatement): CanonicalValue {
  return [GROUP_KEY_TAG, s.group, s.generation, s.sealing_key, s.member, s.iat]
}

function isHop(value: unknown): boolean {
  try {
    checkChainShape([value])
    return true
  } catch {
    return false
  }
}

/**
 * Checks a `group-key.v1` body's form, not its signature or wrap: bad-content unless it has exactly the
 * nine members, each of its type, with `hop` null only when the member is the group. Returns a copy in wire order.
 */
export function checkGroupKeyBody(value: unknown): GroupKeyBody {
  const ok =
    isPlainObject(value) &&
    hasExactKeys(value, BODY_KEYS) &&
    isAddress(value.group) &&
    isCanonicalInteger(value.generation) &&
    value.generation >= 1 &&
    isHex(value.sealing_key, 32) &&
    isAddress(value.member) &&
    isCanonicalInteger(value.iat) &&
    isHex(value.sig, 64) &&
    isHex(value.enc, 32) &&
    isHex(value.ct, 48) &&
    (value.hop === null ? value.member === value.group : isHop(value.hop))
  if (!ok) throw new AcError('bad-content', 'a group-key body has exactly its nine members, each of its form')
  const v = value as unknown as GroupKeyBody
  const hop = v.hop === null ? null : (checkChainShape([v.hop])[0] as Hop)
  const { group, generation, sealing_key, member, iat, sig, enc, ct } = v
  return { group, generation, sealing_key, member, iat, sig, enc, ct, hop }
}

/** What sealGroupKey takes: the group key, the generation and its key, the holder, the hop, the time and an rng. */
export interface GroupKeyInput {
  readonly group: SignerLike
  readonly generation: number
  readonly key: SealingKey
  /** The holder's address and its own X25519 sealing key, which the generation's private key is wrapped to. */
  readonly holder: { readonly address: string; readonly sealingKey: Uint8Array }
  readonly hop: Hop | null
  readonly iat: number
  /** Supplies the wrap's 32-byte ephemeral key. */
  readonly rng: Rng
}

/**
 * A `group-key.v1` body: the group key's statement over the generation's public key for the holder, and the
 * generation's private key sealed to the holder's sealing key (HPKE, info `ac/gkey/1`, AAD the statement's canonical
 * text). bad-content for a body that could not pass checkGroupKeyBody, bad-key for a malformed key.
 */
export function sealGroupKey(i: GroupKeyInput): GroupKeyBody {
  const statement: GroupKeyStatement = {
    group: i.group.address,
    generation: i.generation,
    sealing_key: toHex(i.key.publicKey),
    member: i.holder.address,
    iat: i.iat,
  }
  const preimage = groupKeyPreimage(statement)
  const sig = signPreimage(i.group, preimage)
  const aad = utf8(canonical(preimage))
  const { enc, ct } = hpkeSeal(i.holder.sealingKey, utf8(GROUP_KEY_TAG), aad, i.key.exportSeed(), i.rng(32))
  return checkGroupKeyBody({ ...statement, sig, enc: toHex(enc), ct: toHex(ct), hop: i.hop })
}

/**
 * Verifies a `group-key.v1` body for its holder at `now` (in order) and opens its key: bad-content (the form),
 * not-recipient (another holder), bad-record-sig (not the group's signature), future-iat, the hop's chain codes,
 * untrusted-root and caveat-failed (a hop that is not a membership of the group, judged at iat), open-failed (the
 * wrap), bad-key (a key that is not `sealing_key`'s).
 */
export function openGroupKey(
  value: unknown,
  holder: RecipientKey,
  now: number,
  skew: number = DEFAULT_SKEW,
): OpenedGroupKey {
  const body = checkGroupKeyBody(value)
  if (body.member !== holder.address) throw new AcError('not-recipient', 'the statement names another holder')
  const preimage = groupKeyPreimage(body)
  if (!verifyPreimage(body.group, preimage, body.sig)) {
    throw new AcError('bad-record-sig', "sig is not the group key's signature over the statement")
  }
  if (body.iat > now + skew)
    throw new AcError('future-iat', 'iat is ahead of the clock by more than the skew')
  if (body.hop !== null) checkMembership([body.hop], body.group, body.member, body.iat)
  const aad = utf8(canonical(preimage))
  const seed = holder.key.open(fromHex(body.enc), utf8(GROUP_KEY_TAG), aad, fromHex(body.ct))
  const key = new SealingKey(seed)
  if (!bytesEqual(key.publicKey, fromHex(body.sealing_key))) {
    throw new AcError('bad-key', 'the wrapped key is not the key of sealing_key')
  }
  return { body, key }
}

/** What the group's address record says: its generation's public key, relays, revoked members, ttl and iat. */
export interface GroupRecordInput {
  readonly group: SignerLike
  readonly sealingKey: Uint8Array
  readonly relays: readonly string[]
  readonly revoked?: readonly string[]
  readonly ttl?: number
  readonly iat: number
  readonly rotationKey?: string | null
}

/** The group record: the group key's address record, naming the current generation's public key. */
export function signGroupRecord(i: GroupRecordInput): AddressRecord {
  return signRecord(i.group, {
    kind: 'address',
    key: i.group.address,
    sealing_key: toHex(i.sealingKey),
    relays: i.relays,
    rotation_key: i.rotationKey ?? null,
    revoked: i.revoked ?? [],
    ttl: i.ttl ?? GROUP_RECORD_TTL,
    iat: i.iat,
    rotated_from: null,
  })
}
