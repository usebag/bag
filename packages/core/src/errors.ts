/**
 * The closed set of error codes (spec/SPEC.md, Appendix A). The core raises the first group. The relay and the edge use the
 * other two in their responses and audit lines, so one vocabulary serves every part of the system, in any language.
 */
export const CORE_ERROR_CODES = [
  // encodings and parsing
  'bad-canonical',
  'bad-hex',
  'bad-address',
  'bad-key',
  'bad-json',
  'bad-shape',
  'bad-version',
  'bad-suite',
  'envelope-too-large',
  'too-many-recipients',
  // the outer checks
  'bad-id',
  'bad-sig',
  'stale-ts',
  'future-ts',
  // the authority chain, in rule order
  'too-many-hops',
  'bad-hop',
  'too-many-caveats',
  'caveat-too-long',
  'chain-broken',
  'chain-not-to-sender',
  'exp-not-monotone',
  'hop-expired',
  'bad-hop-sig',
  // caveats
  'unknown-caveat',
  'caveat-failed',
  // the sealed part
  'not-recipient',
  'open-failed',
  'bad-content',
  'bad-thread',
  'too-many-prev',
  // records
  'bad-record',
  'too-many-relays',
  'too-many-revoked',
  'bad-record-sig',
  'future-iat',
  'record-expired',
  'bad-rotation',
] as const

/** Codes the relay answers with (spec/SPEC.md §8). The core never raises them. */
export const RELAY_ERROR_CODES = [
  'body-too-large',
  'not-hosted',
  'root-not-accepted',
  'too-large-for-mailbox',
  'rate-limited',
  'bad-auth',
  'not-authorized',
  'not-found',
  'stale-record',
  // a relay's own failure: 500, a failed try (added 2026-10-25)
  'internal',
  // a publish refused for a full store: 503, a try to repeat (added 2026-10-29)
  'store-full',
  // a pair/claim for a nameplate the relay does not hold or that has expired: 404 (added 2026-10-30, §8.10)
  'no-nameplate',
] as const

/**
 * Reasons the edge writes into its audit lines (spec/SPEC.md §9). The core never raises them. The relay also answers two
 * of them, `resolve-failed` (503, with Retry-After: 60) and `revoked` (403), for a root it admits by domain (SPEC.md
 * §8.8 and Appendix A), and they stay in this group so that the closed set's order holds.
 */
export const EDGE_ERROR_CODES = [
  'untrusted-root',
  'type-not-accepted',
  'revoked',
  'pin-mismatch',
  'duplicate',
  'resolve-failed',
  'publish-failed',
  // a try that got no answer from the relay (added 2026-10-25)
  'unreachable',
  // pairing by a short code (§8.10, 2026-10-30): a bad MAC under the code, a consumed invitation, typed digits differ
  'bad-code',
  'leaked',
  'digits-mismatch',
] as const

export const AC_ERROR_CODES = [...CORE_ERROR_CODES, ...RELAY_ERROR_CODES, ...EDGE_ERROR_CODES] as const

export type CoreErrorCode = (typeof CORE_ERROR_CODES)[number]
export type RelayErrorCode = (typeof RELAY_ERROR_CODES)[number]
export type EdgeErrorCode = (typeof EDGE_ERROR_CODES)[number]
export type AcErrorCode = CoreErrorCode | RelayErrorCode | EdgeErrorCode

const KNOWN: ReadonlySet<string> = new Set(AC_ERROR_CODES)

/** An error with a code from the closed set. The message adds a detail; it never holds key material. */
export class AcError extends Error {
  readonly code: AcErrorCode

  constructor(code: AcErrorCode, detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`)
    this.name = 'AcError'
    this.code = code
  }
}

/** True when the value is an AcError, with the given code when one is given. */
export function isAcError(value: unknown, code?: AcErrorCode): value is AcError {
  return value instanceof AcError && (code === undefined || value.code === code)
}

/** True when the value is one of the codes, for reading a code from a relay response or an audit line. */
export function isAcErrorCode(value: unknown): value is AcErrorCode {
  return typeof value === 'string' && KNOWN.has(value)
}
