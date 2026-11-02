import { isAddress } from './address.ts'
import { type CanonicalValue, isCanonicalInteger } from './canonical.ts'
import { DEFAULT_SKEW } from './envelope.ts'
import { AcError, type AcErrorCode } from './errors.ts'
import { isHex, utf8 } from './hex.ts'
import { hasExactKeys, isPlainObject, type JsonObject, parseJson } from './json.ts'
import { type SignerLike, signPreimage, verifyPreimage } from './keys.ts'
import { isIpLiteralHost } from './net.ts'

/** Domain tags of the record preimages. */
export const ADDRESS_RECORD_TAG = 'ac/addr/1'
export const ACCEPT_FROM_TAG = 'ac/accept/1'
export const KEY_RECORD_TAG = 'ac/key/1'
/** Caps, and the address record's TTL ceiling, 24 hours. */
export const MAX_RELAYS = 64
export const MAX_REVOKED = 1024
export const MAX_ADDRESS_TTL = 86_400
/** The most entries an accept-from record's roots may hold (changed 2026-10-25). */
export const MAX_ROOTS = 1024
/**
 * The longest a key record may live, `exp - iat`, in seconds: the 24-hour ceiling, which binds key records as it
 * binds address records (changed 2026-10-25).
 */
export const MAX_KEY_LIFETIME = 86_400
/** The wildcard root of an accept-from record. */
export const WILDCARD_ROOT = '*'
/** The prefix of a domain root of an accept-from record: `domain:` and a host name. */
export const DOMAIN_ROOT_PREFIX = 'domain:'
/** The longest host name of a domain root, in characters (a DNS name in text form, RFC 1035 §2.3.4). */
export const MAX_DOMAIN_LENGTH = 253
/** The record kinds, as publish's `kind` and fetch's second shape name them (spec/SPEC.md §7, §8). */
export const RECORD_KINDS = ['address', 'accept-from', 'key'] as const

/**
 * An address record (spec/SPEC.md §7): the key's sealing key, its relays, its rotation key, the principal keys it
 * revokes, a TTL of at most 24 hours from iat, and, after a rotation, the previous key and that key's countersignature.
 */
export interface AddressRecord {
  readonly kind: 'address'
  readonly key: string
  readonly sealing_key: string | null
  readonly relays: readonly string[]
  readonly rotation_key: string | null
  readonly revoked: readonly string[]
  readonly ttl: number
  readonly iat: number
  readonly rotated_from: string | null
  readonly rotation_sig: string | null
  readonly sig: string
}

/** An accept-from record: the roots a mailbox accepts, its size limit and its retention. */
export interface AcceptFromRecord {
  readonly kind: 'accept-from'
  readonly owner: string
  readonly roots: readonly string[]
  readonly max_bytes: number
  readonly ttl: number
  readonly iat: number
  readonly sig: string
}

/** A key record: a key's sealing key, valid from iat to exp, at most a day after iat. */
export interface KeyRecord {
  readonly kind: 'key'
  readonly key: string
  readonly sealing_key: string
  readonly iat: number
  readonly exp: number
  readonly sig: string
}

export type AcRecord = AddressRecord | AcceptFromRecord | KeyRecord
export type RecordKind = AcRecord['kind']
export type UnsignedAddressRecord = Omit<AddressRecord, 'sig' | 'rotation_sig'>
export type UnsignedAcceptFromRecord = Omit<AcceptFromRecord, 'sig'>
export type UnsignedKeyRecord = Omit<KeyRecord, 'sig'>
export type UnsignedRecord = UnsignedAddressRecord | UnsignedAcceptFromRecord | UnsignedKeyRecord

const ADDRESS_KEYS = [
  'kind',
  'key',
  'sealing_key',
  'relays',
  'rotation_key',
  'revoked',
  'ttl',
  'iat',
  'rotated_from',
  'rotation_sig',
  'sig',
] as const
const ACCEPT_KEYS = ['kind', 'owner', 'roots', 'max_bytes', 'ttl', 'iat', 'sig'] as const
const KEY_KEYS = ['kind', 'key', 'sealing_key', 'iat', 'exp', 'sig'] as const
// http or https, a non-empty authority, and no space or control character (U+0000 to U+001F, U+007F to U+009F).
const RELAY_URL = /^https?:\/\/[^\p{Cc} /?#]+[^\p{Cc} ]*$/u
const PLACEHOLDER_SIG = '0'.repeat(128)

/** The record preimages (spec/SPEC.md §2). */
export function recordPreimage(r: UnsignedRecord): CanonicalValue {
  switch (r.kind) {
    case 'address':
      return [
        ADDRESS_RECORD_TAG,
        r.key,
        r.sealing_key,
        r.relays,
        r.rotation_key,
        r.revoked,
        r.ttl,
        r.iat,
        r.rotated_from,
      ]
    case 'accept-from':
      return [ACCEPT_FROM_TAG, r.owner, r.roots, r.max_bytes, r.ttl, r.iat]
    case 'key':
      return [KEY_RECORD_TAG, r.key, r.sealing_key, r.iat, r.exp]
  }
}

/** The key that signs a record: `owner` for accept-from, `key` for the other two. */
export function recordSigner(r: UnsignedRecord): string {
  return r.kind === 'accept-from' ? r.owner : r.key
}

function bad(code: AcErrorCode, detail: string): AcError {
  return new AcError(code, detail)
}

function isNullOr(value: unknown, test: (v: unknown) => boolean): boolean {
  return value === null || test(value)
}

function isUniqueList(value: unknown[]): boolean {
  return new Set(value).size === value.length
}

// A DNS label: 1 to 63 lowercase letters, digits and hyphens, with no hyphen at either end (RFC 1123 §2.1).
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * True when the value is the host of a domain root: a lowercase DNS name of at most 253
 * characters and two or more labels, each a DNS label, with no trailing dot, that is not an IP literal
 * (`isIpLiteralHost`: its last label is not a number). No port, scheme, path or user part can ride along.
 */
export function isDomainHost(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > MAX_DOMAIN_LENGTH) return false
  const labels = value.split('.')
  return labels.length >= 2 && labels.every((l) => DNS_LABEL.test(l)) && !isIpLiteralHost(value)
}

/** The host of a `domain:<host>` root, or null when the value is not one. */
export function domainOfRoot(value: unknown): string | null {
  if (typeof value !== 'string' || !value.startsWith(DOMAIN_ROOT_PREFIX)) return null
  const host = value.slice(DOMAIN_ROOT_PREFIX.length)
  return isDomainHost(host) ? host : null
}

/** True when the value is one entry of an accept-from record's roots: an address, `"*"` or `domain:<host>`. */
export function isAcceptRoot(value: unknown): value is string {
  return value === WILDCARD_ROOT || isAddress(value) || domainOfRoot(value) !== null
}

/** The value when it is an accept-from root (`isAcceptRoot`), else bad-record naming it: for one root at a time. */
export function checkAcceptRoot(value: unknown): string {
  if (!isAcceptRoot(value)) {
    const shown = typeof value === 'string' ? JSON.stringify(value) : `a ${typeof value}`
    throw bad('bad-record', `${shown} is not an address, "*" or domain:<host>`)
  }
  return value
}

function checkAddressRecord(v: JsonObject): AddressRecord {
  if (!hasExactKeys(v, ADDRESS_KEYS))
    throw bad('bad-record', 'an address record has exactly its eleven members')
  if (!isAddress(v.key)) throw bad('bad-record', 'key is an address')
  if (!isNullOr(v.sealing_key, (x) => isHex(x, 32)))
    throw bad('bad-record', 'sealing_key is 32 bytes of hex or null')
  if (!Array.isArray(v.relays)) throw bad('bad-record', 'relays is a list')
  if (v.relays.length > MAX_RELAYS)
    throw bad('too-many-relays', `${v.relays.length} relays; the cap is ${MAX_RELAYS}`)
  if (
    !v.relays.every((u: unknown) => typeof u === 'string' && RELAY_URL.test(u)) ||
    !isUniqueList(v.relays)
  ) {
    throw bad('bad-record', 'each relay is a distinct http or https URL')
  }
  if (!isNullOr(v.rotation_key, isAddress)) throw bad('bad-record', 'rotation_key is an address or null')
  if (!Array.isArray(v.revoked)) throw bad('bad-record', 'revoked is a list')
  if (v.revoked.length > MAX_REVOKED) {
    throw bad('too-many-revoked', `${v.revoked.length} revoked keys; the cap is ${MAX_REVOKED}`)
  }
  if (!v.revoked.every(isAddress) || !isUniqueList(v.revoked))
    throw bad('bad-record', 'revoked lists distinct addresses')
  if (!isCanonicalInteger(v.ttl) || v.ttl < 1 || v.ttl > MAX_ADDRESS_TTL) {
    throw bad('bad-record', `ttl is from 1 to ${MAX_ADDRESS_TTL} seconds`)
  }
  if (!isCanonicalInteger(v.iat)) throw bad('bad-record', 'iat is an integer from 0 to 2^53 - 1')
  if (!isNullOr(v.rotated_from, isAddress)) throw bad('bad-record', 'rotated_from is an address or null')
  if (!isNullOr(v.rotation_sig, (x) => isHex(x, 64)))
    throw bad('bad-record', 'rotation_sig is 64 bytes of hex or null')
  if (v.rotation_sig !== null && v.rotated_from === null)
    throw bad('bad-record', 'a rotation_sig needs rotated_from')
  if (!isHex(v.sig, 64)) throw bad('bad-record', 'sig is 64 bytes of hex')
  return {
    kind: 'address',
    key: v.key,
    sealing_key: v.sealing_key as string | null,
    relays: [...(v.relays as string[])],
    rotation_key: v.rotation_key as string | null,
    revoked: [...(v.revoked as string[])],
    ttl: v.ttl,
    iat: v.iat,
    rotated_from: v.rotated_from as string | null,
    rotation_sig: v.rotation_sig as string | null,
    sig: v.sig,
  }
}

function checkAcceptFrom(v: JsonObject): AcceptFromRecord {
  if (!hasExactKeys(v, ACCEPT_KEYS))
    throw bad('bad-record', 'an accept-from record has exactly its seven members')
  if (!isAddress(v.owner)) throw bad('bad-record', 'owner is an address')
  const roots = v.roots
  if (!Array.isArray(roots) || roots.length === 0) throw bad('bad-record', 'roots is a non-empty list')
  if (roots.length > MAX_ROOTS) throw bad('bad-record', `${roots.length} roots; the cap is ${MAX_ROOTS}`)
  if (!roots.every(isAcceptRoot) || !isUniqueList(roots)) {
    throw bad('bad-record', 'roots lists distinct addresses and domain:<host> entries, or is ["*"]')
  }
  if (roots.includes(WILDCARD_ROOT) && roots.length > 1) throw bad('bad-record', '"*" stands alone in roots')
  if (!isCanonicalInteger(v.max_bytes) || v.max_bytes < 1)
    throw bad('bad-record', 'max_bytes is a positive integer')
  if (!isCanonicalInteger(v.ttl) || v.ttl < 1) throw bad('bad-record', 'ttl is a positive integer')
  if (!isCanonicalInteger(v.iat)) throw bad('bad-record', 'iat is an integer from 0 to 2^53 - 1')
  if (!isHex(v.sig, 64)) throw bad('bad-record', 'sig is 64 bytes of hex')
  return {
    kind: 'accept-from',
    owner: v.owner,
    roots: [...(roots as string[])],
    max_bytes: v.max_bytes,
    ttl: v.ttl,
    iat: v.iat,
    sig: v.sig,
  }
}

function checkKeyRecord(v: JsonObject): KeyRecord {
  if (!hasExactKeys(v, KEY_KEYS)) throw bad('bad-record', 'a key record has exactly its six members')
  if (!isAddress(v.key)) throw bad('bad-record', 'key is an address')
  if (!isHex(v.sealing_key, 32)) throw bad('bad-record', 'sealing_key is 32 bytes of hex')
  if (!isCanonicalInteger(v.iat)) throw bad('bad-record', 'iat is an integer from 0 to 2^53 - 1')
  if (!isCanonicalInteger(v.exp) || v.exp < v.iat || v.exp - v.iat > MAX_KEY_LIFETIME) {
    throw bad('bad-record', `exp is an integer from iat to iat + ${MAX_KEY_LIFETIME}`)
  }
  if (!isHex(v.sig, 64)) throw bad('bad-record', 'sig is 64 bytes of hex')
  return { kind: 'key', key: v.key, sealing_key: v.sealing_key, iat: v.iat, exp: v.exp, sig: v.sig }
}

/**
 * Checks a record's form and caps (spec/SPEC.md §7), not its signature or time: bad-record, too-many-relays,
 * too-many-revoked. Returns a copy with the members in wire order.
 */
export function checkRecord(value: unknown): AcRecord {
  if (!isPlainObject(value)) throw bad('bad-record', 'a record is a JSON object')
  switch (value.kind) {
    case 'address':
      return checkAddressRecord(value)
    case 'accept-from':
      return checkAcceptFrom(value)
    case 'key':
      return checkKeyRecord(value)
    default:
      throw bad('bad-record', 'kind is "address", "accept-from" or "key"')
  }
}

/** Parses record bytes: bad-json for anything that is not UTF-8 JSON, then checkRecord. */
export function parseRecord(input: Uint8Array | string): AcRecord {
  return checkRecord(parseJson(input))
}

/** The record as UTF-8 JSON, members in wire order, no white space. */
export function serializeRecord(r: AcRecord): Uint8Array {
  return utf8(JSON.stringify(checkRecord(r)))
}

/** Signs a record with its own key (bad-key for another key). An address record comes back with rotation_sig null. */
export function signRecord(key: SignerLike, r: UnsignedAddressRecord): AddressRecord
export function signRecord(key: SignerLike, r: UnsignedAcceptFromRecord): AcceptFromRecord
export function signRecord(key: SignerLike, r: UnsignedKeyRecord): KeyRecord
export function signRecord(key: SignerLike, r: UnsignedRecord): AcRecord
export function signRecord(key: SignerLike, r: UnsignedRecord): AcRecord {
  if (recordSigner(r) !== key.address) throw new AcError('bad-key', 'a record is signed by its own key')
  const draft = assembleRecord(r, PLACEHOLDER_SIG)
  return { ...draft, sig: signPreimage(key, recordPreimage(draft)) }
}

/**
 * The signed record of its unsigned form and a signature, without a key: signRecord's last step (checkRecord's codes
 * apply; the signature is verifyRecord's to check). An address record comes back with rotation_sig null.
 */
export function assembleRecord(r: UnsignedAddressRecord, sig: string): AddressRecord
export function assembleRecord(r: UnsignedAcceptFromRecord, sig: string): AcceptFromRecord
export function assembleRecord(r: UnsignedKeyRecord, sig: string): KeyRecord
export function assembleRecord(r: UnsignedRecord, sig: string): AcRecord
export function assembleRecord(r: UnsignedRecord, sig: string): AcRecord {
  return checkRecord(r.kind === 'address' ? { ...r, rotation_sig: null, sig } : { ...r, sig })
}

function rotationOf(next: AddressRecord): AddressRecord {
  const r = checkRecord(next)
  if (r.kind !== 'address' || r.rotated_from === null) {
    throw new AcError('bad-record', 'a rotation is an address record that names rotated_from')
  }
  return r
}

/**
 * Countersigns a rotation: `key`, the previous key or its rotation key, signs the new record's
 * preimage, which names the previous key in rotated_from.
 */
export function countersignRotation(key: SignerLike, next: AddressRecord): AddressRecord {
  const r = rotationOf(next)
  return { ...r, rotation_sig: signPreimage(key, recordPreimage(r)) }
}

/**
 * The rotation `next` with a countersignature, without a key: countersignRotation's last step. A signature that is
 * not 64 bytes of hex (a non-string too) is bad-record, as checkRecord reports a malformed rotation_sig; so is a
 * `next` that is null or not a rotation.
 */
export function assembleRotation(next: AddressRecord, rotationSig: string): AddressRecord {
  const rotation = rotationOf(next)
  if (!isHex(rotationSig, 64)) throw bad('bad-record', 'rotation_sig is 64 bytes of hex')
  return { ...rotation, rotation_sig: rotationSig }
}

/**
 * Verifies a record at time `now` (spec/SPEC.md §7), in order: its form and caps (checkRecord), its signature by its
 * key or owner (bad-record-sig), iat <= now + skew (future-iat), and its expiry (record-expired): an address record
 * after iat + ttl, a key record after exp. An accept-from record does not expire; a newer iat replaces it.
 */
export function verifyRecord(value: AcRecord, now: number, skew: number = DEFAULT_SKEW): AcRecord {
  const r = checkRecord(value)
  if (!verifyPreimage(recordSigner(r), recordPreimage(r), r.sig)) {
    throw new AcError('bad-record-sig', 'sig is not the signature of the record key')
  }
  if (r.iat > now + skew) throw new AcError('future-iat', 'iat is ahead of the clock by more than the skew')
  if ((r.kind === 'address' && now > r.iat + r.ttl) || (r.kind === 'key' && now > r.exp)) {
    throw new AcError('record-expired', 'the record is past its ttl or exp')
  }
  return r
}

/**
 * Verifies that `next` rotates `prev`: next.rotated_from is prev.key, and next.rotation_sig
 * verifies over next's preimage under prev.key or prev.rotation_key. bad-rotation otherwise, which includes a bare
 * rotation without a rotation_sig. Run verifyRecord on both records first; this checks the link only. A reader that
 * holds no record of next.rotated_from checks verifyRotationClaim instead.
 */
export function verifyRotation(prev: AddressRecord, next: AddressRecord): void {
  const p = checkRecord(prev)
  const n = checkRecord(next)
  if (p.kind !== 'address' || n.kind !== 'address')
    throw new AcError('bad-record', 'a rotation links address records')
  if (n.rotated_from !== p.key)
    throw new AcError('bad-rotation', "rotated_from is not the previous record's key")
  if (n.rotation_sig === null) throw new AcError('bad-rotation', 'a bare rotation: no rotation_sig')
  const preimage = recordPreimage(n)
  const signers = p.rotation_key === null ? [p.key] : [p.key, p.rotation_key]
  if (!signers.some((s) => verifyPreimage(s, preimage, n.rotation_sig as string))) {
    throw new AcError(
      'bad-rotation',
      'rotation_sig verifies under neither the previous key nor its rotation key',
    )
  }
}

/**
 * Verifies the rotation a record claims, for a reader that holds no record of its `rotated_from` (spec/SPEC.md §7.3;
 * changed 2026-10-25): when rotated_from is set, rotation_sig must verify over the record's
 * preimage under rotated_from, so a bare rotation and a countersignature by any other key are bad-rotation. A record
 * that names no rotated_from claims nothing and passes. A rotation countersigned by the previous record's rotation key
 * verifies only through verifyRotation, by a reader that holds that previous record, the one place the rotation key is
 * written. Run verifyRecord first; this checks the claim only.
 */
export function verifyRotationClaim(next: AddressRecord): void {
  const n = checkRecord(next)
  if (n.kind !== 'address') throw new AcError('bad-record', 'a rotation claim is an address record')
  if (n.rotated_from === null) return
  if (n.rotation_sig === null) throw new AcError('bad-rotation', 'a bare rotation: no rotation_sig')
  if (!verifyPreimage(n.rotated_from, recordPreimage(n), n.rotation_sig)) {
    throw new AcError('bad-rotation', 'rotation_sig does not verify under rotated_from')
  }
}
