import { parseEnvelope, parseRecord, recordSigner } from '@usebag/core'
import { type Frame, type PublishResult, type RelayClient, RelayError, type Subscription } from '@usebag/edge'

// A relay in memory for the enterprise client's tests, one store per relay URL: records by signer and kind, a mailbox
// per recipient with cursors from 1 and one ack each, live subscriptions. `down` fails every call to a URL with its
// status (0: no answer); `hold` keeps every frame back, as a relay that takes an envelope and never delivers it.
export class FakeRelay implements RelayClient {
  readonly records = new Map<string, Uint8Array>()
  readonly boxes = new Map<string, Uint8Array[]>()
  readonly acks = new Map<string, number>()
  /** `<url> <kind>` per record taken, `<url> envelope` per envelope. */
  readonly published: string[] = []
  readonly down = new Map<string, number>()
  hold = false
  #wakes: (() => void)[] = []

  #up(url: string): void {
    const status = this.down.get(url)
    if (status !== undefined) throw new RelayError(null, status, null, `${url} is down`)
  }

  box(url: string, mailbox: string): Uint8Array[] {
    const key = `${url} ${mailbox}`
    const rows = this.boxes.get(key) ?? []
    this.boxes.set(key, rows)
    return rows
  }

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.#up(url)
    const doc = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }
    if (doc.kind !== undefined) {
      const r = parseRecord(bytes)
      this.records.set(`${url} ${recordSigner(r)} ${r.kind}`, bytes)
      this.published.push(`${url} ${r.kind}`)
      return { id: '', duplicate: false, delivered: 0 }
    }
    const env = parseEnvelope(bytes)
    for (const to of env.to) this.box(url, to).push(bytes)
    this.published.push(`${url} envelope`)
    for (const wake of this.#wakes.splice(0)) wake()
    return { id: env.id, duplicate: false, delivered: env.to.length }
  }

  async fetch(): Promise<Uint8Array> {
    throw new Error('the enterprise client fetches no envelope by id')
  }

  async fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    this.#up(url)
    return this.records.get(`${url} ${address} ${kind}`) ?? null
  }

  subscribe(url: string, mailbox: string, _s: unknown, _h: unknown, cursor: number | null): Subscription {
    this.#up(url)
    const relay = this
    const key = `${url} ${mailbox}`
    const state = { after: cursor ?? this.acks.get(key) ?? 0, closed: false, wake: () => {} }
    return {
      ack: (c: number) => relay.acks.set(key, Math.max(c, relay.acks.get(key) ?? 0)),
      close: () => {
        state.closed = true
        state.wake()
      },
      async *[Symbol.asyncIterator](): AsyncGenerator<Frame> {
        for (;;) {
          if (state.closed) return
          const rows = relay.box(url, mailbox)
          const next = relay.hold ? undefined : rows[state.after]
          if (next !== undefined) {
            state.after += 1
            yield { cursor: state.after, envelopeBytes: next }
          } else
            await new Promise<void>((wake) => {
              state.wake = wake
              relay.#wakes.push(wake)
            })
        }
      },
    }
  }
}
