import { parseEnvelope, parseRecord, recordSigner, verifyFetchAuth } from '@usebag/core'
import {
  type FetchProof,
  type Frame,
  type PublishResult,
  RelayError,
  type Subscription,
  type WsSubscriberOptions,
} from '@usebag/edge'
import type { CliRelay } from '../../src/io.ts'

// A relay in memory for the CLI's unit tests: records by signer and kind, one mailbox per recipient with cursors from
// 1, live subscriptions with acks, fetch for a party, and a health answer. The e2e suite runs the real one.

interface Row {
  readonly cursor: number
  readonly bytes: Uint8Array
}

class MemorySubscription implements Subscription, AsyncIterator<Frame> {
  readonly #relay: MemoryRelay
  readonly #mailbox: string
  #after: number
  #closed = false
  #wake: (() => void) | null = null

  constructor(relay: MemoryRelay, mailbox: string, cursor: number | null) {
    this.#relay = relay
    this.#mailbox = mailbox
    this.#after = relay.replay ? 0 : (cursor ?? relay.acks.get(mailbox) ?? 0)
  }

  [Symbol.asyncIterator](): AsyncIterator<Frame> {
    return this
  }

  async next(): Promise<IteratorResult<Frame>> {
    for (;;) {
      if (this.#relay.failSubscribe !== null) throw this.#relay.failSubscribe
      if (this.#closed) return { value: undefined, done: true }
      const row = this.#relay.box(this.#mailbox).find((r) => r.cursor > this.#after)
      if (row !== undefined) {
        this.#after = row.cursor
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
    this.#relay.acks.set(this.#mailbox, Math.max(cursor, this.#relay.acks.get(this.#mailbox) ?? 0))
  }

  close(): void {
    this.#closed = true
    this.#relay.subs.delete(this)
    this.wake()
  }
}

export class MemoryRelay implements CliRelay {
  readonly records = new Map<string, Uint8Array>()
  /** Records of one relay URL, by `<signer> <kind>`: fetchRecord answers from them, not `records`, for that URL. */
  readonly recordsAt = new Map<string, Map<string, Uint8Array>>()
  readonly envelopes = new Map<string, Uint8Array>()
  readonly boxes = new Map<string, Row[]>()
  readonly acks = new Map<string, number>()
  readonly subs = new Set<MemorySubscription>()
  readonly published: string[] = []
  readonly options: WsSubscriberOptions[] = []
  /** When set, every envelope publish throws it. */
  failPublish: RelayError | null = null
  /** A relay URL whose record publishes throw the error given (record keep's tests). */
  readonly failRecordPublish = new Map<string, unknown>()
  /** A relay URL whose record fetches throw the error given. */
  readonly failRecordFetch = new Map<string, unknown>()
  /** When set, every subscription throws it on its next read. */
  failSubscribe: RelayError | null = null
  healthy: boolean | RelayError = true
  /** When true, a subscription starts from the first row whatever cursor it asks for (a relay that sends again). */
  replay = false

  /** The relay client the CLI's io hands out; `options` are what the command asked for. */
  client(options: WsSubscriberOptions): CliRelay {
    this.options.push(options)
    return this
  }

  box(mailbox: string): Row[] {
    let rows = this.boxes.get(mailbox)
    if (rows === undefined) {
      rows = []
      this.boxes.set(mailbox, rows)
    }
    return rows
  }

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.published.push(url)
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }
    if (v.kind !== undefined) {
      if (this.failRecordPublish.has(url)) throw this.failRecordPublish.get(url)
      const r = parseRecord(bytes)
      this.records.set(`${recordSigner(r)} ${r.kind}`, bytes)
      this.recordsAt.get(url)?.set(`${recordSigner(r)} ${r.kind}`, bytes)
      return { id: '', duplicate: false, delivered: 0 }
    }
    if (this.failPublish !== null) throw this.failPublish
    const env = parseEnvelope(bytes)
    const duplicate = this.envelopes.has(env.id)
    if (!duplicate) {
      this.envelopes.set(env.id, bytes)
      for (const to of env.to) {
        const rows = this.box(to)
        rows.push({ cursor: rows.length + 1, bytes })
      }
      for (const s of this.subs) s.wake()
    }
    return { id: env.id, duplicate, delivered: duplicate ? 0 : env.to.length }
  }

  async fetch(url: string, id: string, proof: FetchProof): Promise<Uint8Array> {
    const bytes = this.envelopes.get(id)
    if (bytes === undefined) throw new RelayError('not-found', 404, null, id)
    // The proof's audience is the relay URL addressed, byte for byte (spec/SPEC.md §8.3).
    if (!verifyFetchAuth(proof.signer, id, proof.ts, url, proof.sig))
      throw new RelayError('bad-auth', 401, null, id)
    return bytes
  }

  async fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    if (this.failRecordFetch.has(url)) throw this.failRecordFetch.get(url)
    return (this.recordsAt.get(url) ?? this.records).get(`${address} ${kind}`) ?? null
  }

  subscribe(
    _url: string,
    mailbox: string,
    _signer: unknown,
    _hops: unknown,
    cursor: number | null,
  ): MemorySubscription {
    const s = new MemorySubscription(this, mailbox, cursor)
    this.subs.add(s)
    return s
  }

  async health(): Promise<boolean> {
    if (this.healthy instanceof RelayError) throw this.healthy
    return this.healthy
  }
}
