import { type AcceptFromRecord, parseEnvelope, parseRecord, recordSigner } from '@usebag/core'
import {
  type FetchProof,
  type PairOpen,
  type PairReach,
  type PublishResult,
  RelayError,
  type Subscription,
} from '@usebag/edge'
import type { CliRelay } from '../../src/io.ts'
import { MemoryRelay } from './relay.ts'

// Several memory relays by URL, for the pairing tests: each URL its own MemoryRelay, and the two refusals
// the pairing leans on, as spec/SPEC.md §8.2 states them: a record not newer than the one held is 409 stale-record,
// and an envelope to a mailbox whose accept-from does not admit its root is 403 root-not-accepted (none: 404
// not-hosted; over max_bytes: 403 too-large-for-mailbox). Every record publish is logged as "<url> <kind> <signer>".
// The pair rendezvous is offered once a test sets `pair`; until then pair/open answers no nameplate.

export class Network implements CliRelay {
  readonly relays = new Map<string, MemoryRelay>()
  readonly log: string[] = []

  client(): CliRelay {
    return this
  }

  at(url: string): MemoryRelay {
    let relay = this.relays.get(url)
    if (relay === undefined) {
      relay = new MemoryRelay()
      this.relays.set(url, relay)
    }
    return relay
  }

  /** The bytes of a record a relay holds, as text, or null. */
  record(url: string, signer: string, kind: string): string | null {
    const bytes = this.at(url).records.get(`${signer} ${kind}`)
    return bytes === undefined ? null : new TextDecoder().decode(bytes)
  }

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    const relay = this.at(url)
    if ((JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }).kind !== undefined) {
      const r = parseRecord(bytes)
      const held = this.record(url, recordSigner(r), r.kind)
      if (held !== null && parseRecord(held).iat >= r.iat) {
        throw new RelayError('stale-record', 409, null, `${url} holds a record not older`)
      }
      this.log.push(`${url} ${r.kind} ${recordSigner(r)}`)
      return relay.publish(url, bytes)
    }
    const env = parseEnvelope(bytes)
    const root = env.auth[0]?.iss ?? env.from
    for (const to of env.to) {
      const accept = this.record(url, to, 'accept-from')
      if (accept === null) throw new RelayError('not-hosted', 404, null, `${url} hosts no ${to}`)
      const { roots, max_bytes } = parseRecord(accept) as AcceptFromRecord
      if (!roots.includes('*') && !roots.includes(root)) {
        throw new RelayError('root-not-accepted', 403, null, `${url}: ${to} does not accept ${root}`)
      }
      if (bytes.length > max_bytes) throw new RelayError('too-large-for-mailbox', 403, null, url)
    }
    return relay.publish(url, bytes)
  }

  fetch(url: string, id: string, proof: FetchProof): Promise<Uint8Array> {
    return this.at(url).fetch(url, id, proof)
  }

  fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    return this.at(url).fetchRecord(url, address, kind)
  }

  subscribe(
    url: string,
    mailbox: string,
    signer: unknown,
    hops: unknown,
    cursor: number | null,
  ): Subscription {
    return this.at(url).subscribe(url, mailbox, signer, hops, cursor)
  }

  /** Whether the relays offer pair/open, and the reach each open nameplate holds, by "<url> <nameplate>". */
  pair = false
  readonly plates = new Map<string, PairReach>()

  async pairOpen(url: string, open: PairOpen): Promise<string | null> {
    if (!this.pair) return null
    const n = String(472 + this.plates.size)
    this.plates.set(`${url} ${n}`, {
      inviter: open.inviter,
      invitation: open.invitation,
      relays: open.relays,
      exp: 0,
    })
    return n
  }

  async pairClaim(url: string, nameplate: string): Promise<PairReach | null> {
    return this.plates.get(`${url} ${nameplate}`) ?? null
  }

  async health(): Promise<boolean> {
    return true
  }
}
