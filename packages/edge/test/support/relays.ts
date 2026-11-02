import { parseEnvelope, parseRecord, recordSigner, verifyFetchAuth } from '@usebag/core'
import {
  type FetchProof,
  type Frame,
  type PublishResult,
  type RecordSource,
  type RelayClient,
  RelayError,
  type Subscription,
} from '../../src/ports.ts'

// Two fake RelayClients. ScriptedRelay answers publishes from a script and records every call. MemoryRelay is a
// tiny relay in memory: records, mailboxes with cursors, live subscriptions, fetch by id for a party.

/** What a scripted publish does: answer, or throw. */
export type Outcome = PublishResult | Error

export class ScriptedRelay implements RelayClient {
  readonly published: { readonly url: string; readonly bytes: Uint8Array }[] = []
  readonly script: Outcome[] = []
  /** Answers when the script is empty. */
  fallback: Outcome | null = null

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.published.push({ url, bytes })
    const outcome = this.script.shift() ?? this.fallback ?? { id: 'x', duplicate: false, delivered: 1 }
    if (outcome instanceof Error) throw outcome
    return outcome
  }

  async fetch(): Promise<Uint8Array> {
    throw new RelayError('not-found', 404, null, 'scripted')
  }

  async fetchRecord(): Promise<Uint8Array | null> {
    return null
  }

  subscribe(): Subscription {
    throw new Error('ScriptedRelay does not subscribe')
  }
}

interface Row {
  readonly cursor: number
  readonly bytes: Uint8Array
}

class MemorySubscription implements Subscription, AsyncIterator<Frame> {
  readonly #relay: MemoryRelay
  readonly url: string
  readonly mailbox: string
  readonly signer: string
  readonly start: number | null
  #delivered: number
  #closed = false
  #wake: (() => void) | null = null

  constructor(relay: MemoryRelay, url: string, mailbox: string, signer: string, cursor: number | null) {
    this.#relay = relay
    this.url = url
    this.mailbox = mailbox
    this.signer = signer
    this.start = cursor
    this.#delivered = cursor ?? relay.acks.get(`${url} ${mailbox} ${signer}`) ?? 0
  }

  [Symbol.asyncIterator](): AsyncIterator<Frame> {
    return this
  }

  async next(): Promise<IteratorResult<Frame>> {
    for (;;) {
      if (this.#closed) return { value: undefined, done: true }
      const row = this.#relay.box(this.url, this.mailbox).find((r) => r.cursor > this.#delivered)
      if (row !== undefined) {
        this.#delivered = row.cursor
        return { value: { cursor: row.cursor, envelopeBytes: row.bytes }, done: false }
      }
      await new Promise<void>((resolve) => {
        this.#wake = resolve
      })
    }
  }

  wake(): void {
    const wake = this.#wake
    this.#wake = null
    wake?.()
  }

  ack(cursor: number): void {
    this.#relay.acks.set(`${this.url} ${this.mailbox} ${this.signer}`, cursor)
  }

  close(): void {
    this.#closed = true
    this.#relay.subs.delete(this)
    this.wake()
  }
}

export class MemoryRelay implements RelayClient {
  readonly ids = new Map<string, Uint8Array>()
  readonly boxes = new Map<string, Row[]>()
  readonly records = new Map<string, Uint8Array>()
  readonly acks = new Map<string, number>()
  readonly subs = new Set<MemorySubscription>()
  /** When set, publishes to this relay URL fail with it. */
  failing: Map<string, RelayError> = new Map()
  /** Record publishes to this relay URL fail with it (a 429 rate-limited, say); envelopes still go through. */
  readonly failingRecords = new Map<string, Error>()
  /** Record fetches from this relay URL fail with it. */
  readonly failingFetches = new Map<string, Error>()
  /** Every record fetch, as `<url> <address> <kind>`. */
  readonly recordFetches: string[] = []
  /** Every record publish, as `<url> <signer> <kind>`, in order. */
  readonly recordPublishes: string[] = []

  box(url: string, mailbox: string): Row[] {
    const key = `${url} ${mailbox}`
    let rows = this.boxes.get(key)
    if (rows === undefined) {
      rows = []
      this.boxes.set(key, rows)
    }
    return rows
  }

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    const failure = this.failing.get(url)
    if (failure !== undefined) throw failure
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }
    if (typeof v.kind === 'string') {
      const r = parseRecord(bytes)
      this.recordPublishes.push(`${url} ${recordSigner(r)} ${r.kind}`)
      const refused = this.failingRecords.get(url)
      if (refused !== undefined) throw refused
      // As the relay does (spec/SPEC.md §8.2): a record whose iat is not newer than the one it holds is 409.
      const held = this.records.get(`${url} ${recordSigner(r)} ${r.kind}`)
      if (held !== undefined && parseRecord(held).iat >= r.iat)
        throw new RelayError('stale-record', 409, null, `${url} holds a record as new`)
      this.records.set(`${url} ${recordSigner(r)} ${r.kind}`, bytes)
      const validUntil = r.kind === 'address' ? r.iat + r.ttl : r.kind === 'key' ? r.exp : null
      const record = { kind: r.kind, signer: recordSigner(r), iat: r.iat, valid_until: validUntil }
      return { id: '', duplicate: false, delivered: 0, record }
    }
    const env = parseEnvelope(bytes)
    const duplicate = this.ids.has(`${url} ${env.id}`)
    if (!duplicate) {
      this.ids.set(`${url} ${env.id}`, bytes)
      for (const to of env.to) {
        const rows = this.box(url, to)
        rows.push({ cursor: rows.length + 1, bytes })
      }
      for (const s of this.subs) s.wake()
    }
    return { id: env.id, duplicate, delivered: duplicate ? 0 : env.to.length }
  }

  async fetch(url: string, id: string, proof: FetchProof): Promise<Uint8Array> {
    const bytes = this.ids.get(`${url} ${id}`)
    if (bytes === undefined) throw new RelayError('not-found', 404, null, id)
    // The relay at `url` takes a proof whose audience is `url` byte for byte, as a relay checks its own base URL.
    if (!verifyFetchAuth(proof.signer, id, proof.ts, url, proof.sig))
      throw new RelayError('bad-auth', 401, null, id)
    const env = parseEnvelope(bytes)
    const party = (a: string): boolean => a === env.from || env.to.includes(a)
    if (!party(proof.signer) && !party(proof.auth[0]?.iss ?? ''))
      throw new RelayError('not-authorized', 403, null, id)
    return bytes
  }

  async fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    this.recordFetches.push(`${url} ${address} ${kind}`)
    const failure = this.failingFetches.get(url)
    if (failure !== undefined) throw failure
    return this.records.get(`${url} ${address} ${kind}`) ?? null
  }

  /** A RecordSource over this relay's records (no well-known records). */
  recordSource(): RecordSource {
    return {
      wellKnown: async (domain) => {
        throw new Error(`no well-known record for ${domain}`)
      },
      relayRecord: (url, address, kind) => this.fetchRecord(url, address, kind),
    }
  }

  subscribe(
    url: string,
    mailbox: string,
    signer: { readonly address: string },
    _hops: unknown,
    cursor: number | null,
  ): MemorySubscription {
    const s = new MemorySubscription(this, url, mailbox, signer.address, cursor)
    this.subs.add(s)
    return s
  }
}
