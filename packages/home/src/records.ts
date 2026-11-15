import {
  type AcceptFromRecord,
  AcError,
  type AcRecord,
  parseRecord,
  recordSigner,
  verifyRecord,
} from '@usebag/core'
import type { RelayClient } from '@usebag/edge'

// An identity's own records as the relays hold them, each checked by the core before it is used.

/**
 * The newest accept-from record of `own` at the relays, each checked by the core (ownRecord); null when none
 * holds one. For a reader with no address record to keep (onboard, after a lapse swept it).
 */
export async function newestAccept(
  client: RelayClient,
  relays: readonly string[],
  own: string,
): Promise<AcceptFromRecord | null> {
  let accept: AcceptFromRecord | null = null
  for (const url of relays) {
    const f = (await ownRecord(client, url, own, 'accept-from')) as AcceptFromRecord | null
    if (f !== null && f.iat > (accept?.iat ?? -1)) accept = f
  }
  return accept
}

/** The record of `kind` that `own` signed, at one relay, checked by the core; null when the relay holds none. */
export async function ownRecord(
  client: RelayClient,
  url: string,
  own: string,
  kind: 'address' | 'accept-from',
): Promise<AcRecord | null> {
  const bytes = await client.fetchRecord(url, own, kind)
  if (bytes === null) return null
  const parsed = parseRecord(bytes)
  // At its own iat a record is neither early nor expired, so this checks its form and its signature.
  const r = verifyRecord(parsed, parsed.iat)
  if (r.kind !== kind || recordSigner(r) !== own) {
    throw new AcError(
      'bad-record',
      `${url} answered the ${r.kind} record of ${recordSigner(r)} for the ${kind} record of ${own}`,
    )
  }
  return r
}
