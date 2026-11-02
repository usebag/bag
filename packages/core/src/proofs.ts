import { type CanonicalValue, canonical } from './canonical.ts'
import { sha256hex } from './hash.ts'
import { type SignerLike, signPreimage, verifyPreimage } from './keys.ts'

// The relay API's signed proofs and the audit line (spec/SPEC.md §2, §8, §9): their preimages live here so the edge, the
// relay's conformance tests and any other implementation compute them one way.

/** Domain tags of the subscribe response and the fetch proof. */
export const SUBSCRIBE_TAG = 'ac/sub/1'
export const FETCH_TAG = 'ac/fetch/1'
/** The `prev` of an audit log's first line: 64 zeros. */
export const AUDIT_GENESIS = '0'.repeat(64)

/** The fetch proof preimage ["ac/fetch/1", signer, id, ts, audience]; audience is the exact relays entry. */
export function fetchAuthPreimage(signer: string, id: string, ts: number, audience: string): CanonicalValue {
  return [FETCH_TAG, signer, id, ts, audience]
}

/** The AC-Sig value: `key`'s fetch proof for envelope `id` at `ts`, for relay `audience`. */
export function signFetchAuth(key: SignerLike, id: string, ts: number, audience: string): string {
  return signPreimage(key, fetchAuthPreimage(key.address, id, ts, audience))
}

/** True when `sig` is `signer`'s fetch proof for `id` at `ts`, for relay `audience` byte for byte. */
export function verifyFetchAuth(signer: string, id: string, ts: number, audience: string, sig: string) {
  return verifyPreimage(signer, fetchAuthPreimage(signer, id, ts, audience), sig)
}

/** The subscribe response preimage: ["ac/sub/1", nonce, signer, mailbox, cursor or null]. */
export function subscribePreimage(
  nonce: string,
  signer: string,
  mailbox: string,
  cursor: number | null,
): CanonicalValue {
  return [SUBSCRIBE_TAG, nonce, signer, mailbox, cursor]
}

/** The subscribe response's sig: `key` answers the relay's challenge `nonce` for `mailbox`, resuming at `cursor`. */
export function signSubscribe(
  key: SignerLike,
  nonce: string,
  mailbox: string,
  cursor: number | null,
): string {
  return signPreimage(key, subscribePreimage(nonce, key.address, mailbox, cursor))
}

/** True when `sig` is `signer`'s subscribe response to `nonce` for `mailbox` at `cursor`. */
export function verifySubscribe(
  signer: string,
  nonce: string,
  mailbox: string,
  cursor: number | null,
  sig: string,
): boolean {
  return verifyPreimage(signer, subscribePreimage(nonce, signer, mailbox, cursor), sig)
}

/** The hashed fields of one audit line. `detail` is the line's detail as JSON text, or null. */
export interface AuditFields {
  readonly seq: number
  readonly prev: string
  readonly ts: number
  readonly event: string
  readonly decision: string
  readonly reason: string
  readonly id: string | null
  readonly from: string | null
  readonly root: string | null
  readonly detail: string | null
}

/** The audit line preimage: [seq, prev, ts, event, decision, reason, id, from, root, detail]. */
export function auditPreimage(f: AuditFields): CanonicalValue {
  return [f.seq, f.prev, f.ts, f.event, f.decision, f.reason, f.id, f.from, f.root, f.detail]
}

/** An audit line's hash: sha256hex(canonical(audit preimage)). The next line's prev. */
export function auditHash(f: AuditFields): string {
  return sha256hex(canonical(auditPreimage(f)))
}
