import type { AcErrorCode } from '@usebag/core'
import { type Clock, MAX_REFUSALS, REFUSALS, RelayError } from '@usebag/edge'
import type { Logger } from './log.ts'

// The server's subscriptions, one per --relay (the MCP half; the edge keeps the other), kept
// from what the edge already tells the server, read-only: what the relay client says of each connection (its
// SubscriptionLink, through the observed client), each frame that arrives, each error a subscription's frames end in
// (onSubscriptionError) and the edge's onError. A subscription is `connecting` until the relay first admits it (its
// `ok`), and `subscribed` only while it is admitted. It is `retrying` after a connection lost or never admitted, a close
// with no frame, on which the client connects again by itself, and after an error the edge subscribes again on (a
// RelayError with a code, below its three refusals in a row); and `ended` once the edge's run for that relay rejects.
// `refusals` counts the permanent refusals (the edge's REFUSALS) since the last frame arrived, as the edge counts them
// toward its MAX_REFUSALS. A lost connection is none: a relay over its cap answers no frame at all, so no error reaches
// the edge, edge_errors stays as it was and the mailbox is not dead, and last_code and last_at are its one report.
//
// The end is read by identity: Receiver.run rejects with the error its subscription last threw (receiver.ts, `throw
// failure`, and a fault from the frames rethrown), Edge.start passes it to onError unchanged, and each subscription
// throws its own error object, as ws-relay.ts's WsSubscription makes a fresh RelayError for each. The Subscription
// port (ports.ts) does not promise that last part; a client that shared one error object between relays would end
// them together here (test/support/relay.ts's `refuse` makes a fresh one per throw, as the real client does). A local
// fault that ends a run without an error from the relay (a retry's fault, a store error) is not seen here;
// edge_errors has it.
//
// When every one has ended the mailbox is dead: `dead` aborts, so a wait in progress returns, and wait and inbox say
// `mailbox: "refused: <code>"` (the edge's three refusals), `"ended: <code>"` (an error it
// does not retry) or `"stopped: <code>"` (a session's edge that did not start again after a renewal: halt). The record
// lives in this process: a restarted server starts at `connecting` and does not read the audit log back. A restarted
// edge subscribes afresh, and reset() starts the records again.

export type SubscriptionState = 'connecting' | 'subscribed' | 'retrying' | 'ended'

/** What wait and inbox add once every subscription has ended. */
export type Refused = {
  readonly mailbox: string
  readonly relay: string
  readonly at: string
  readonly hint: string
}

/** What status lists for each relay. */
export type SubscriptionView = {
  readonly relay: string
  readonly state: SubscriptionState
  readonly refusals: number
  readonly last_code: string | null
  readonly last_at: string | null
}

interface Entry {
  state: SubscriptionState
  refusals: number
  code: string | null
  at: number | null
  error: unknown
}

/** No error yet: nothing the edge throws is this symbol. */
const NONE = Symbol('none')

/** The hint of each way a mailbox ends, by the word its `mailbox` field starts with. */
export const HINTS = {
  refused:
    "the relay refused this mailbox's subscription three times in a row, so nothing new arrives here: status lists the subscriptions; a session's is made again once its chain is renewed, a principal's only when its server is restarted",
  ended:
    'the subscription failed in a way the edge does not retry, so nothing new arrives here: status lists the subscriptions; it is made again only when the server is restarted',
  stopped:
    "the edge did not start again after this session's chain was renewed, so nothing new arrives here: the server's log has the resubscribe error; the next renewal tries again, or restart the server",
} as const

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()

export class Subscriptions {
  readonly #relays: readonly string[]
  readonly #clock: Clock
  readonly #log: Logger
  readonly #entries = new Map<string, Entry>()
  #dead = new AbortController()
  #refused: Refused | null = null

  constructor(relays: readonly string[], clock: Clock, log: Logger) {
    this.#relays = relays
    this.#clock = clock
    this.#log = log
    this.reset()
  }

  /** Aborts once every subscription has ended; a new signal after reset(). */
  get dead(): AbortSignal {
    return this.#dead.signal
  }

  /** Every relay connecting afresh, as a started edge subscribes; a state that changes is logged. */
  reset(): void {
    for (const relay of this.#relays) {
      const was = this.#entries.get(relay)?.state ?? 'connecting'
      this.#entries.set(relay, { state: 'connecting', refusals: 0, code: null, at: null, error: NONE })
      if (was !== 'connecting')
        this.#log.log('info', 'subscription', { relay, state: 'connecting', refusals: 0 })
    }
    this.#refused = null
    if (this.#dead.signal.aborted) this.#dead = new AbortController()
  }

  /** The relay admitted a connection, a reconnect's too. */
  admitted(relay: string): void {
    const e = this.#entries.get(relay)
    if (e === undefined || e.state === 'subscribed' || e.state === 'ended') return
    e.state = 'subscribed'
    this.#log.log('info', 'subscription', { relay, state: e.state, refusals: e.refusals })
  }

  /** A connection closed with no frame, admitted or not: the client connects again; the refusals in a row stay. */
  lost(relay: string, code: string): void {
    const e = this.#entries.get(relay)
    if (e === undefined || e.state === 'ended') return
    Object.assign(e, { code, at: this.#clock.now() })
    if (e.state === 'retrying') return
    e.state = 'retrying'
    this.#log.log('warn', 'subscription', { relay, state: e.state, code, refusals: e.refusals })
  }

  /** A frame of `relay` arrived: the refusals in a row start again, as the edge's do. */
  arrived(relay: string): void {
    const e = this.#entries.get(relay)
    if (e !== undefined) e.refusals = 0
  }

  /**
   * A subscription's frames ended in `error` (its code as the tools name it). The edge retries a RelayError with a
   * code until its refusals in a row reach MAX_REFUSALS: `retrying`; else its run ends, and onError says so (ended).
   */
  failed(relay: string, error: unknown, code: string): void {
    const e = this.#entries.get(relay)
    if (e === undefined) return
    e.refusals = REFUSALS.has(code as AcErrorCode) ? e.refusals + 1 : 0
    Object.assign(e, { code, at: this.#clock.now(), error })
    if (!(error instanceof RelayError) || error.code === null || e.refusals >= MAX_REFUSALS) return
    e.state = 'retrying'
    this.#log.log('warn', 'subscription', { relay, state: e.state, code, refusals: e.refusals })
  }

  /** The edge's onError: the run of the relay whose subscription last threw `error` has ended. */
  ended(error: unknown): void {
    for (const [relay, e] of this.#entries) {
      if (e.error === error) this.#end(relay, e, REFUSALS.has(e.code as AcErrorCode) ? 'refused' : 'ended')
    }
  }

  /** A restarted edge did not start (server.ts): no subscription runs, so each one has ended with `code`. */
  halt(code: string): void {
    for (const [relay, e] of this.#entries) {
      if (e.state !== 'ended') this.#end(relay, Object.assign(e, { code, at: this.#clock.now() }), 'stopped')
    }
  }

  #end(relay: string, e: Entry, how: keyof typeof HINTS): void {
    if (e.state === 'ended') return
    e.state = 'ended'
    this.#log.log('warn', 'subscription', { relay, state: e.state, code: e.code, refusals: e.refusals })
    if (this.list().some((s) => s.state !== 'ended')) return
    this.#refused = { mailbox: `${how}: ${e.code}`, relay, at: iso(e.at as number), hint: HINTS[how] }
    this.#dead.abort()
  }

  /** Each relay's subscription, in --relay order. */
  list(): SubscriptionView[] {
    return [...this.#entries].map(([relay, e]) => {
      const at = e.at === null ? null : iso(e.at)
      return { relay, state: e.state, refusals: e.refusals, last_code: e.code, last_at: at }
    })
  }

  /** `<how>: <code>` with the relay that ended last and when, once every subscription has ended; else null. */
  refused(): Refused | null {
    return this.#refused
  }
}
