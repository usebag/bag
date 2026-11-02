import { isAddress } from './address.ts'
import { type CanonicalValue, isCanonicalInteger, MAX_CANONICAL_INTEGER } from './canonical.ts'
import { MAX_CAVEAT_BYTES, MAX_HOPS } from './chain.ts'
import { DEFAULT_SKEW, MAX_ENVELOPE_BYTES } from './envelope.ts'
import { AcError, type AcErrorCode, isAcErrorCode } from './errors.ts'
import { isHex, utf8 } from './hex.ts'
import { hasExactKeys, isPlainObject, type JsonObject, parseJson, utf8Length } from './json.ts'
import { type SignerLike, signPreimage, verifyPreimage } from './keys.ts'
import { domainOfRoot } from './records.ts'

// The org policy, in two records that an org's root signs. The
// served record, kind `policy`, holds only what a sender needs to comply: the scopes, what an external chain must
// carry, and the reserved `inspection`, null. The members record, kind `policy-members`, holds what the org's own edges
// enforce and nobody else may read: the roots allowed or denied, the rate per root, where sends may not go, and the
// moderation module with its terms; it is loaded from a file and never served. Neither expires: a newer iat replaces
// an older one, as an accept-from record's does. Where the served record lives is still open (one origin).
// Neither is a record kind of records.ts until the spec merges: this module is used directly.

/** The domain tags of the two preimages. */
export const POLICY_RECORD_TAG = 'ac/policy/1'
export const MEMBERS_RECORD_TAG = 'ac/policy-members/1'
/**
 * The closed-set code for a refusal by a policy rule that no other code names (Appendix A of the draft). It is the
 * edge's own: an inbox row's reason and an audit line's, never a relay's answer or anything a sender is told.
 */
export const POLICY_REFUSED = 'policy-refused'
/** This module's code list, until its one registration line in errors.ts. */
export const POLICY_ERROR_CODES = [POLICY_REFUSED] as const
export type PolicyCode = AcErrorCode | typeof POLICY_REFUSED

/** Caps: entries of a roots or deny list, scopes, patterns of a list, moderation params and their bytes. */
export const MAX_POLICY_ENTRIES = 1024
export const MAX_SCOPES = 32
export const MAX_PATTERNS = 32
export const MAX_PARAMS = 64
export const MAX_PARAM_BYTES = 256
export const MAX_RATE_WINDOW = 86_400

export const ROOTS_MODES = ['allow', 'deny'] as const
/** What an unknown root meets: held or refused, never admitted (an org policy only narrows). */
export const UNKNOWN_ACTIONS = ['quarantine', 'refuse'] as const
export const MODERATION_ACTIONS = ['quarantine', 'drop', 'allow'] as const

export interface PolicyRoots {
  readonly mode: (typeof ROOTS_MODES)[number]
  readonly list: readonly string[]
  readonly unknown: (typeof UNKNOWN_ACTIONS)[number]
}
export interface PolicyScope {
  readonly match: string
  readonly accept_types: readonly string[]
  readonly max_bytes: number
}
export interface PolicyExternal {
  readonly required_caveats: readonly string[]
  readonly max_hop_lifetime: number | null
  readonly max_hops: number | null
}
export interface PolicyRates {
  readonly per_root: number
  readonly window: number
}
export interface PolicyOutbound {
  readonly deny: readonly string[]
}
export interface PolicyModeration {
  readonly module: string
  readonly action: (typeof MODERATION_ACTIONS)[number]
  readonly params: readonly string[]
}

/** The served policy record: what a sender needs to comply. `inspection` is reserved and null. */
export interface PolicyRecord {
  readonly kind: 'policy'
  readonly key: string
  readonly scopes: readonly PolicyScope[]
  readonly external: PolicyExternal | null
  readonly inspection: null
  readonly iat: number
  readonly sig: string
}

/** The members record: what the org's own edges enforce, never served. A null section sets no rule. */
export interface MembersRecord {
  readonly kind: 'policy-members'
  readonly key: string
  readonly roots: PolicyRoots | null
  readonly rates: PolicyRates | null
  readonly outbound: PolicyOutbound | null
  readonly moderation: PolicyModeration | null
  readonly iat: number
  readonly sig: string
}
export type UnsignedPolicyRecord = Omit<PolicyRecord, 'sig'>
export type UnsignedMembersRecord = Omit<MembersRecord, 'sig'>

const POLICY_KEYS = ['kind', 'key', 'scopes', 'external', 'inspection', 'iat', 'sig'] as const
const MEMBERS_KEYS = ['kind', 'key', 'roots', 'rates', 'outbound', 'moderation', 'iat', 'sig'] as const
const MODULE_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/
const PLACEHOLDER_SIG = '0'.repeat(128)

/** True when the value is the code of a policy refusal: one of the closed set, or policy-refused. */
export function isPolicyCode(value: unknown): value is PolicyCode {
  return value === POLICY_REFUSED || isAcErrorCode(value)
}

/** True for an entry of a roots or deny list: an address or `domain:<host>` (no wildcard). */
export function isPolicyEntry(value: unknown): value is string {
  return isAddress(value) || domainOfRoot(value) !== null
}

function isCaveatText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && utf8Length(value) <= MAX_CAVEAT_BYTES
}

/** True for a caveat pattern: `*` (when allowed), an exact caveat, or `<name>=*` for any caveat named so. */
export function isCaveatPattern(value: unknown, star: boolean): value is string {
  return (star && value === '*') || (value !== '*' && isCaveatText(value) && value !== '=*')
}

/** True when one of `caveats` matches the pattern: `*` always, `<name>=*` by its prefix, any other exactly. */
export function matchesCaveat(pattern: string, caveats: readonly string[]): boolean {
  if (pattern === '*') return true
  if (pattern.endsWith('=*')) return caveats.some((c) => c.startsWith(pattern.slice(0, -1)))
  return caveats.includes(pattern)
}

/** True for a type pattern: `*`, `<prefix>.*` or an exact type, with no other `*`. */
export function isTypePattern(value: unknown): value is string {
  if (value === '*') return true
  if (!isCaveatText(value)) return false
  const name = value.endsWith('.*') ? value.slice(0, -2) : value
  return name.length > 0 && !name.includes('*')
}

/** True when `type` matches a type pattern: `*` any, `<prefix>.*` by its prefix and dot, any other exactly. */
export function typeMatches(pattern: string, type: string): boolean {
  if (pattern === '*') return true
  return pattern.endsWith('.*') ? type.startsWith(pattern.slice(0, -1)) : type === pattern
}

function bad(detail: string): AcError {
  return new AcError('bad-record', `policy: ${detail}`)
}

function list(value: unknown, max: number, test: (v: unknown) => boolean, what: string, min = 0): string[] {
  if (!Array.isArray(value) || value.length < min || value.length > max || !value.every(test)) {
    throw bad(`${what} is a list of ${min} to ${max} entries of its form`)
  }
  if (new Set(value).size !== value.length) throw bad(`${what} lists each entry once`)
  return [...(value as string[])]
}

function object(value: unknown, keys: readonly string[], what: string): JsonObject {
  if (!isPlainObject(value) || !hasExactKeys(value, keys)) throw bad(`${what} is {${keys.join(', ')}}`)
  return value
}

function orNull<T>(value: unknown, check: (v: unknown) => T): T | null {
  return value === null ? null : check(value)
}

function int(value: unknown, min: number, max: number, what: string): number {
  if (!isCanonicalInteger(value) || value < min || value > max) {
    throw bad(`${what} is an integer from ${min} to ${max}`)
  }
  return value
}

function oneOf<T extends string>(value: unknown, values: readonly T[], what: string): T {
  if (!values.includes(value as T)) throw bad(`${what} is one of ${values.join(', ')}`)
  return value as T
}

/** The members both records share: the kind, the org root that signs, iat and sig. */
function common(value: unknown, keys: readonly string[], kind: string): JsonObject {
  const v = object(value, keys, `a ${kind} record`)
  if (v.kind !== kind) throw bad(`kind is "${kind}"`)
  if (!isAddress(v.key)) throw bad('key is an address')
  int(v.iat, 0, MAX_CANONICAL_INTEGER, 'iat')
  if (!isHex(v.sig, 64)) throw bad('sig is 64 bytes of hex')
  return v
}

function checkScope(value: unknown, i: number): PolicyScope {
  const v = object(value, ['match', 'accept_types', 'max_bytes'], `scopes[${i}]`)
  if (!isCaveatPattern(v.match, true)) throw bad(`scopes[${i}].match is "*" or a caveat pattern`)
  return {
    match: v.match,
    accept_types: list(v.accept_types, MAX_PATTERNS, isTypePattern, `scopes[${i}].accept_types`, 1),
    max_bytes: int(v.max_bytes, 1, MAX_ENVELOPE_BYTES, `scopes[${i}].max_bytes`),
  }
}

function checkExternal(value: unknown): PolicyExternal {
  const v = object(value, ['required_caveats', 'max_hop_lifetime', 'max_hops'], 'external')
  const pattern = (c: unknown): boolean => isCaveatPattern(c, false)
  return {
    required_caveats: list(v.required_caveats, MAX_PATTERNS, pattern, 'external.required_caveats'),
    max_hop_lifetime: orNull(v.max_hop_lifetime, (x) =>
      int(x, 1, MAX_CANONICAL_INTEGER, 'external.max_hop_lifetime'),
    ),
    max_hops: orNull(v.max_hops, (x) => int(x, 0, MAX_HOPS, 'external.max_hops')),
  }
}

/**
 * Checks a served policy record's form and caps, not its signature or time: bad-record, naming the member. A deny
 * list, a rate, an outbound rule or a moderation section is no member of it, so a served record cannot carry one.
 */
export function checkPolicyRecord(value: unknown): PolicyRecord {
  const v = common(value, POLICY_KEYS, 'policy')
  if (!Array.isArray(v.scopes) || v.scopes.length > MAX_SCOPES)
    throw bad(`scopes is a list of at most ${MAX_SCOPES}`)
  if (v.inspection !== null) throw bad('inspection is reserved and null until the spec rules')
  return {
    kind: 'policy',
    key: v.key as string,
    scopes: v.scopes.map(checkScope),
    external: orNull(v.external, checkExternal),
    inspection: null,
    iat: v.iat as number,
    sig: v.sig as string,
  }
}

function checkRoots(value: unknown): PolicyRoots {
  const v = object(value, ['mode', 'list', 'unknown'], 'roots')
  return {
    mode: oneOf(v.mode, ROOTS_MODES, 'roots.mode'),
    list: list(v.list, MAX_POLICY_ENTRIES, isPolicyEntry, 'roots.list'),
    unknown: oneOf(v.unknown, UNKNOWN_ACTIONS, 'roots.unknown'),
  }
}

function checkRates(value: unknown): PolicyRates {
  const v = object(value, ['per_root', 'window'], 'rates')
  return {
    per_root: int(v.per_root, 1, MAX_CANONICAL_INTEGER, 'rates.per_root'),
    window: int(v.window, 1, MAX_RATE_WINDOW, 'rates.window'),
  }
}

function checkOutbound(value: unknown): PolicyOutbound {
  const v = object(value, ['deny'], 'outbound')
  return { deny: list(v.deny, MAX_POLICY_ENTRIES, isPolicyEntry, 'outbound.deny') }
}

function checkModeration(value: unknown): PolicyModeration {
  const v = object(value, ['module', 'action', 'params'], 'moderation')
  if (typeof v.module !== 'string' || !MODULE_NAME.test(v.module)) {
    throw bad('moderation.module is 1 to 64 of a-z, 0-9 and -, starting with a letter or digit')
  }
  const param = (p: unknown): boolean =>
    typeof p === 'string' && p.length > 0 && utf8Length(p) <= MAX_PARAM_BYTES
  return {
    module: v.module,
    action: oneOf(v.action, MODERATION_ACTIONS, 'moderation.action'),
    params: list(v.params, MAX_PARAMS, param, 'moderation.params'),
  }
}

/** Checks a members record's form and caps, not its signature or time: bad-record, naming the member. */
export function checkMembersRecord(value: unknown): MembersRecord {
  const v = common(value, MEMBERS_KEYS, 'policy-members')
  return {
    kind: 'policy-members',
    key: v.key as string,
    roots: orNull(v.roots, checkRoots),
    rates: orNull(v.rates, checkRates),
    outbound: orNull(v.outbound, checkOutbound),
    moderation: orNull(v.moderation, checkModeration),
    iat: v.iat as number,
    sig: v.sig as string,
  }
}

/**
 * The preimages, each section a fixed-position list or null: ["ac/policy/1", key, scopes, external, inspection, iat]
 * and ["ac/policy-members/1", key, roots, rates, outbound, moderation, iat].
 */
export function policyPreimage(r: UnsignedPolicyRecord | UnsignedMembersRecord): CanonicalValue {
  if (r.kind === 'policy') {
    const e = r.external
    const scopes = r.scopes.map((s) => [s.match, s.accept_types, s.max_bytes])
    const external = e === null ? null : [e.required_caveats, e.max_hop_lifetime, e.max_hops]
    return [POLICY_RECORD_TAG, r.key, scopes, external, r.inspection, r.iat]
  }
  const m = r.moderation
  return [
    MEMBERS_RECORD_TAG,
    r.key,
    r.roots === null ? null : [r.roots.mode, r.roots.list, r.roots.unknown],
    r.rates === null ? null : [r.rates.per_root, r.rates.window],
    r.outbound === null ? null : [r.outbound.deny],
    m === null ? null : [m.module, m.action, m.params],
    r.iat,
  ]
}

const check = (r: PolicyRecord | MembersRecord): PolicyRecord | MembersRecord =>
  r.kind === 'policy' ? checkPolicyRecord(r) : checkMembersRecord(r)

/** Signs a served or members record with the org root it names (bad-key for another key). */
export function signPolicyRecord(key: SignerLike, r: UnsignedPolicyRecord): PolicyRecord
export function signPolicyRecord(key: SignerLike, r: UnsignedMembersRecord): MembersRecord
export function signPolicyRecord(key: SignerLike, r: UnsignedPolicyRecord | UnsignedMembersRecord) {
  if (r.key !== key.address) throw new AcError('bad-key', 'a policy record is signed by its own key')
  const draft = check({ ...r, sig: PLACEHOLDER_SIG })
  return { ...draft, sig: signPreimage(key, policyPreimage(draft)) }
}

function verified<R extends PolicyRecord | MembersRecord>(r: R, now: number, skew: number): R {
  if (!verifyPreimage(r.key, policyPreimage(r), r.sig)) {
    throw new AcError('bad-record-sig', 'sig is not the signature of the policy key')
  }
  if (r.iat > now + skew) throw new AcError('future-iat', 'iat is ahead of the clock by more than the skew')
  return r
}

/**
 * Verifies a served record at `now`, in order: its form and caps, its signature by its key (bad-record-sig), and
 * iat <= now + skew (future-iat). It does not expire: a newer iat replaces it, as an accept-from record.
 */
export function verifyPolicyRecord(value: unknown, now: number, skew: number = DEFAULT_SKEW): PolicyRecord {
  return verified(checkPolicyRecord(value), now, skew)
}

/** Verifies a members record at `now`, as verifyPolicyRecord does a served one. */
export function verifyMembersRecord(value: unknown, now: number, skew: number = DEFAULT_SKEW): MembersRecord {
  return verified(checkMembersRecord(value), now, skew)
}

/** Parses served record bytes: bad-json for anything that is not UTF-8 JSON, then checkPolicyRecord. */
export function parsePolicyRecord(input: Uint8Array | string): PolicyRecord {
  return checkPolicyRecord(parseJson(input))
}

/** Parses members record bytes: bad-json, then checkMembersRecord. */
export function parseMembersRecord(input: Uint8Array | string): MembersRecord {
  return checkMembersRecord(parseJson(input))
}

/** A served or members record as UTF-8 JSON, members in wire order, no white space. */
export function serializePolicyRecord(r: PolicyRecord | MembersRecord): Uint8Array {
  return utf8(JSON.stringify(check(r)))
}
