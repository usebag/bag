import {
  type AcRecord,
  parseRecord,
  type RecordKind,
  recordSigner,
  serializeRecord,
  verifyRecord,
} from '@usebag/core'
import { type RelayClient, RelayError } from './ports.ts'

// Offer-to-all (spec/SPEC.md Appendix B 110): a record goes to every relay an identity lists, and a relay that does not
// take it now is a laggard the keep-alive carries, not a failed operation. A caller that needs one relay to hold it
// asks for that with heldSomewhere. The one exception is a record that carries a revoked list: a relay honours only the
// list it has stored (§8.7), so the keys it revokes are still honoured at a laggard, and that is reported as incomplete,
// a security gap and not a benign not-yet.

/** A relay that did not take a record. */
export interface Lagging {
  readonly relay: string
  readonly kind: RecordKind
  /** The relay's code, `unreachable` for no answer, or `http-<n>` for a status with no code. */
  readonly code: string
  /** The record carries a revoked list, so the revocation is incomplete until this relay takes it. */
  readonly revokes: boolean
}

/** What one offer did, in `relays` order. */
export interface Offered {
  /** The relays that hold the record now. */
  readonly held: readonly string[]
  readonly lagging: readonly Lagging[]
  /** The first relay's failure as it was thrown; null when none failed. */
  readonly first: unknown
}

export interface OfferOptions {
  /** A relay that answers stale-record holds this record or a newer one: for bytes re-offered, or a peer's record. */
  readonly staleHolds?: boolean
}

/** What a report of an incomplete revocation says of the relay it names. */
export const INCOMPLETE_REVOCATION =
  'that relay still honours the keys this record revokes until it takes it, and the keep-alive offers it again'

/** A failure's code, as a relay gave it; `error` for one with none, a connection cut mid-answer. */
function lagCode(e: unknown): string {
  if (e instanceof RelayError) return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
  const code = (e as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : 'error'
}

/** True for a record that carries a revoked list. */
const revokes = (record: AcRecord): boolean => record.kind === 'address' && record.revoked.length > 0

/** Offers `record` to every relay in turn, through `publish`; a relay's failure never stops the next one. */
export async function offerRecord(
  record: AcRecord,
  relays: readonly string[],
  publish: (url: string) => Promise<unknown>,
  options: OfferOptions = {},
): Promise<Offered> {
  const held: string[] = []
  const lagging: Lagging[] = []
  let first: unknown = null
  for (const url of relays) {
    try {
      await publish(url)
      held.push(url)
    } catch (e) {
      const code = lagCode(e)
      if (options.staleHolds === true && code === 'stale-record') {
        held.push(url)
        continue
      }
      first ??= e
      lagging.push({ relay: url, kind: record.kind, code, revokes: revokes(record) })
    }
  }
  return { held, lagging, first }
}

/** True when `url` reads back `record`: its kind, signer and iat, checked by the core. A failed read is false. */
async function holds(client: RelayClient, url: string, record: AcRecord): Promise<boolean> {
  const own = recordSigner(record)
  try {
    const bytes = await client.fetchRecord(url, own, record.kind)
    if (bytes === null) return false
    const parsed = parseRecord(bytes)
    // At its own iat a record is neither early nor expired, so this checks its form and its signature.
    const r = verifyRecord(parsed, parsed.iat)
    return r.kind === record.kind && recordSigner(r) === own && r.iat === record.iat
  } catch {
    return false
  }
}

/**
 * Offers `record`, bytes signed before, to the relays that do not read back as holding it. A relay that holds it would
 * answer stale-record, and that still spends the client address's publishes at the relay, where a read spends none; one
 * address keeping many identities alive meets that limit (e2e scenario 54). `held` names every relay that holds it.
 */
export async function offerBehind(
  client: RelayClient,
  record: AcRecord,
  relays: readonly string[],
): Promise<Offered> {
  const behind: string[] = []
  for (const url of relays) if (!(await holds(client, url, record))) behind.push(url)
  const bytes = serializeRecord(record)
  const offered = await offerRecord(record, behind, (url) => client.publish(url, bytes), { staleHolds: true })
  return { ...offered, held: relays.filter((url) => !offered.lagging.some((l) => l.relay === url)) }
}

/** `offered`, or its first failure thrown when no relay took the record. */
export function heldSomewhere(offered: Offered): Offered {
  if (offered.held.length === 0 && offered.first !== null) throw offered.first
  return offered
}
