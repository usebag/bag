import { AcError, parseEnvelope, replyThread, type SealedContent } from '@usebag/core'
import { jitterOf } from './outbox.ts'
import type { Clock, EdgeStore, InboxRow, Rng } from './ports.ts'
import type { SendInput } from './sender.ts'

// Read receipts (spec/SPEC.md §10): an optional profile above the core, so a
// sealed envelope of its own type that neither the relay nor the core knows of. The reader decides: a receipt goes out
// only for a message that asks for one, from a peer the reader named, and a reader who has not named the peer emits
// nothing, exactly as one who never read it or has no receipts at all, so the absence of a receipt says nothing. A sender
// may ask and can never compel. A receipt carries the acknowledged id and nothing else. Its authenticity is its own
// envelope's signature: an inner signature would only mint a proof of reading that a sender could show anyone. It carries
// no time, but its envelope's `ts` says when it was sent, so it waits a jitter first, which widens the window and no more.
// It is terminal: it stops in the sender's receiver (Receiver's `receipts`), so it never reaches a session, never asks
// for a receipt and never answers one. The `ac.` prefix of body members is reserved; an unknown one is ignored.

/** The sealed type of a receipt. */
export const RECEIPT_TYPE = 'ac.receipt'
/** The body member that asks for a receipt: sealed, and in the body because the sealed content has no other (§5.2). */
export const RECEIPT_HINT = 'ac.receipt'
/** The body member of a receipt that holds the acknowledged envelope id. */
export const RECEIPT_ACK = 'ac.ack'
/** A receipt's wait before it goes out, in s: uniform up to this, the spread of an identity's network start. */
export const RECEIPT_SPREAD_S = 20

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** `body` with the request in it: a JSON object, the one body that can carry a member. */
export function askingReceipt(body: unknown): Record<string, unknown> {
  if (!isObject(body)) throw new AcError('bad-content', 'a receipt request needs a JSON object body')
  return { ...body, [RECEIPT_HINT]: true }
}

export interface ReceiptsOptions {
  readonly store: EdgeStore
  readonly clock: Clock
  readonly rng: Rng
  /** The peers this reader answers, addresses, read at each message: none by default. */
  readonly to: () => readonly string[]
  /** The jitter's spread, in s. */
  readonly spreadS: number
  /** Sends the receipt; a recipient that does not resolve yet waits, as any send does. */
  readonly send: (input: SendInput) => Promise<unknown>
  /** The recipients of an envelope sealed with no outbox entry (a local send), else undefined. */
  readonly sealed?: (id: string) => readonly string[] | undefined
  readonly onError: (error: unknown) => void
}

export class Receipts {
  readonly #o: ReceiptsOptions
  readonly #jittering = new Set<ReturnType<typeof setTimeout>>()

  constructor(options: ReceiptsOptions) {
    this.#o = options
  }

  /**
   * The reader's side, for an accepted row: a receipt when the message asks for one and its peer is named, after the
   * jitter. It lives in memory until it goes: a process that ends first sends none, which says nothing. Never throws.
   */
  answer(row: InboxRow, send = this.#o.send): void {
    const { onError, rng, spreadS, to } = this.#o
    try {
      const { type, thread, body } = JSON.parse(row.content as string) as SealedContent
      if (type === RECEIPT_TYPE || !isObject(body) || body[RECEIPT_HINT] !== true) return
      const env = parseEnvelope(row.bytes)
      const peer = env.auth.at(-1)?.iss ?? env.from
      if (!to().includes(peer)) return
      const input = {
        to: [peer],
        type: RECEIPT_TYPE,
        body: { [RECEIPT_ACK]: env.id },
        thread: replyThread(thread, [env.id]),
        relays: [row.relay],
      }
      const timer = setTimeout(
        () => {
          this.#jittering.delete(timer)
          send(input).catch(onError)
        },
        Math.floor(jitterOf(rng.bytes(4)) * spreadS * 1000),
      )
      timer.unref()
      this.#jittering.add(timer)
    } catch (e) {
      onError(e)
    }
  }

  /** Drops the receipts still in their jitter. */
  stop(): void {
    for (const timer of this.#jittering) clearTimeout(timer)
    this.#jittering.clear()
  }

  /**
   * The sender's side, for a receipt the receiver opened from `principal` (its envelope verified, so its sender is
   * authentic): kept when its body holds only an acknowledged id, and `ac.` members it ignores, for an envelope of this
   * edge's outbox that named `principal`. False refuses it. A person learns of it from Edge.receipts; it is a fact about
   * a send, not a message.
   */
  take(principal: string, body: unknown): boolean {
    const { clock, store } = this.#o
    if (!isObject(body) || Object.keys(body).some((k) => !k.startsWith('ac.'))) return false
    const id = body[RECEIPT_ACK]
    if (typeof id !== 'string') return false
    const sent = store.outboxGet(id)
    const named = sent === null ? this.#o.sealed?.(id) : parseEnvelope(sent.bytes).to
    if (named === undefined || !named.includes(principal)) return false
    store.receiptAdd(id, principal, clock.now())
    return true
  }
}
