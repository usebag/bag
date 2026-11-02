import { isAddress } from './address.ts'
import { type CanonicalValue, isCanonicalInteger } from './canonical.ts'
import { DEFAULT_SKEW } from './envelope.ts'
import { AcError } from './errors.ts'
import { isHex, utf8 } from './hex.ts'
import { hasExactKeys, isPlainObject, parseJson } from './json.ts'
import { type SignerLike, signPreimage, verifyPreimage } from './keys.ts'
import { isDomainHost, MAX_ADDRESS_TTL } from './records.ts'

// Handles (spec/SPEC.md §12.3 and §12.4, L2; 2026-10-26):
// `jane@acme.example` names an address under an org's domain, bound by a handle record that the org's key signs and the
// org serves at its one origin, <origin>/.well-known/bag/handles/<local>.json (§12.1). A handle finds an
// address and admits no one. Relays do not store handle records. Pure: the edge fetches.

/** The domain tag of a handle record's preimage. */
export const HANDLE_TAG = 'ac/handle/1'
/** Where an org serves its handle records, under its one origin (§12.1); then `<local>.json`. */
export const HANDLES_PATH = '/.well-known/bag/handles/'
/** The longest local part of a handle, in characters. */
export const MAX_HANDLE_LOCAL = 64
/**
 * The special-use top-level names a handle's domain may not end in: they name no org on the public DNS (.local mDNS,
 * RFC 6762; .localhost and .invalid, RFC 6761; .onion, RFC 7686; .alt, RFC 9476; .arpa, RFC 3172; .internal, ICANN's
 * private-use name). Added 2026-10-26.
 */
export const SPECIAL_USE_TLDS = ['alt', 'arpa', 'internal', 'invalid', 'local', 'localhost', 'onion'] as const

/** A handle, read: its local part and its domain. */
export interface Handle {
  readonly local: string
  readonly domain: string
}

/** A handle record: `org`'s word that `handle` names `address`, valid from iat to iat + ttl (a day at most). */
export interface HandleRecord {
  readonly kind: 'handle'
  readonly org: string
  readonly handle: string
  readonly address: string
  readonly iat: number
  readonly ttl: number
  readonly sig: string
}

export type UnsignedHandleRecord = Omit<HandleRecord, 'sig'>

/** What a reader expects of a handle record: the domain's current key, the handle asked for, the org's revoked list. */
export interface HandleExpectation {
  readonly org: string
  readonly handle: string
  readonly revoked?: readonly string[]
}

// 1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit, so that no handle maps to a dot file.
const LOCAL = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/
const HANDLE_KEYS = ['kind', 'org', 'handle', 'address', 'iat', 'ttl', 'sig'] as const
const PLACEHOLDER_SIG = '0'.repeat(128)

/** True when a domain's last label is one of SPECIAL_USE_TLDS: no handle names it, and no TXT is asked for it (§12.2). */
export function isSpecialUseDomain(domain: string): boolean {
  return (SPECIAL_USE_TLDS as readonly string[]).includes(domain.slice(domain.lastIndexOf('.') + 1))
}

/** The handle's parts, or null when the value is not a handle. */
function handleParts(value: unknown): Handle | null {
  if (typeof value !== 'string') return null
  const at = value.indexOf('@')
  if (at === -1 || at !== value.lastIndexOf('@')) return null
  const local = value.slice(0, at)
  const domain = value.slice(at + 1)
  return LOCAL.test(local) && isDomainHost(domain) && !isSpecialUseDomain(domain) ? { local, domain } : null
}

/** True when the value is a handle, `<local>@<domain>`, its domain under no special-use name (spec/SPEC.md §12.3 item 1). */
export function isHandle(value: unknown): value is string {
  return handleParts(value) !== null
}

/** Reads a handle; bad-address for anything else, an address included (where a handle or an address may stand). */
export function parseHandle(value: unknown): Handle {
  const h = handleParts(value)
  if (h === null) {
    throw new AcError(
      'bad-address',
      'a handle is <local>@<domain>, the local part 1 to 64 of a-z, 0-9, ., - and _',
    )
  }
  return h
}

/** The path of a handle's record under its org's origin: /.well-known/bag/handles/<local>.json. */
export function handlePath(handle: string): string {
  return `${HANDLES_PATH}${parseHandle(handle).local}.json`
}

/** The preimage a handle record's signature covers: ["ac/handle/1", org, handle, address, iat, ttl]. */
export function handleRecordPreimage(r: UnsignedHandleRecord): CanonicalValue {
  return [HANDLE_TAG, r.org, r.handle, r.address, r.iat, r.ttl]
}

/** Checks a handle record's form (spec/SPEC.md §12.4 item 1), not its signature or time: bad-record. */
export function checkHandleRecord(value: unknown): HandleRecord {
  const bad = (detail: string): AcError => new AcError('bad-record', detail)
  if (!isPlainObject(value)) throw bad('a record is a JSON object')
  if (value.kind !== 'handle') throw bad('kind is "handle"')
  if (!hasExactKeys(value, HANDLE_KEYS)) throw bad('a handle record has exactly its seven members')
  if (!isAddress(value.org)) throw bad('org is an address')
  if (!isHandle(value.handle)) throw bad('handle is a handle')
  if (!isAddress(value.address)) throw bad('address is an address')
  if (!isCanonicalInteger(value.iat)) throw bad('iat is an integer from 0 to 2^53 - 1')
  if (!isCanonicalInteger(value.ttl) || value.ttl < 1 || value.ttl > MAX_ADDRESS_TTL) {
    throw bad(`ttl is from 1 to ${MAX_ADDRESS_TTL} seconds`)
  }
  if (!isHex(value.sig, 64)) throw bad('sig is 64 bytes of hex')
  return {
    kind: 'handle',
    org: value.org,
    handle: value.handle,
    address: value.address,
    iat: value.iat,
    ttl: value.ttl,
    sig: value.sig,
  }
}

/** Parses handle record bytes: bad-json for anything that is not UTF-8 JSON, then checkHandleRecord. */
export function parseHandleRecord(input: Uint8Array | string): HandleRecord {
  return checkHandleRecord(parseJson(input))
}

/** The handle record as UTF-8 JSON, members in wire order, no white space. */
export function serializeHandleRecord(r: HandleRecord): Uint8Array {
  return utf8(JSON.stringify(checkHandleRecord(r)))
}

/** Signs a handle record with the org's key (bad-key for any other key). */
export function signHandleRecord(key: SignerLike, r: UnsignedHandleRecord): HandleRecord {
  if (r.org !== key.address) throw new AcError('bad-key', 'a handle record is signed by its org key')
  const draft = checkHandleRecord({ ...r, sig: PLACEHOLDER_SIG })
  return { ...draft, sig: signPreimage(key, handleRecordPreimage(draft)) }
}

/**
 * Verifies a handle record for a reader that resolves `expected.handle` of a domain whose current key is
 * `expected.org` (spec/SPEC.md §12.4 item 3), in order: its form (bad-record), its signature under its own org
 * (bad-record-sig), iat <= now + skew (future-iat), now <= iat + ttl (record-expired), its org and its handle against
 * the expected ones (resolve-failed), and its address against the org's revoked list (revoked).
 */
export function verifyHandleRecord(
  value: unknown,
  expected: HandleExpectation,
  now: number,
  skew: number = DEFAULT_SKEW,
): HandleRecord {
  const r = checkHandleRecord(value)
  if (!verifyPreimage(r.org, handleRecordPreimage(r), r.sig)) {
    throw new AcError('bad-record-sig', 'sig is not the signature of the org key')
  }
  if (r.iat > now + skew) throw new AcError('future-iat', 'iat is ahead of the clock by more than the skew')
  if (now > r.iat + r.ttl) throw new AcError('record-expired', 'the handle record is past its ttl')
  if (r.org !== expected.org)
    throw new AcError('resolve-failed', "the handle record is not signed by the domain's key")
  if (r.handle !== expected.handle)
    throw new AcError('resolve-failed', 'the handle record names another handle')
  if ((expected.revoked ?? []).includes(r.address)) {
    throw new AcError('revoked', "the handle's address is revoked by its org")
  }
  return r
}
