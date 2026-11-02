import {
  type Hop,
  isAcErrorCode,
  isCanonicalInteger,
  isHex,
  parseJson,
  type SigningKey,
  signSubscribe,
  utf8,
} from '@usebag/core'
import {
  type Frame,
  type RelayClient,
  RelayError,
  type Subscription,
  type SubscriptionLink,
} from '../ports.ts'
import { countRelayCall, countRelayError } from '../telemetry.ts'
import type { Leave, RelayTurns } from './relay-turns.ts'

// subscribe (spec/SPEC.md §8.5) on the global WebSocket: the relay's challenge, the auth frame signed over the
// ac/sub/1 preimage, ok or error, env frames in cursor order, cumulative acks, and a reconnect with cursor null, so the
// relay resumes from the ack it stores: a cursor remembered here is in a restored relay's old numbering, and rows at or
// below it would never be framed (spec/SPEC.md §9 item 10). The socket comes from a factory, so tests drive the frames.
// An env frame is {t, cursor, received_at, envelope}: the envelope a JSON string whose UTF-8 bytes are the
// exact bytes the relay stored, which the receiver verifies as they are, and received_at the second the relay stored
// them, which the receiver judges live delivery at. A frame whose envelope is not a string, raw JSON as older relays sent it
// or anything else, is a frame no stage takes (bad-shape): the edge never re-serializes an envelope to read it.

/** The part of a WebSocket the subscription uses. */
export interface SocketLike {
  addEventListener(type: 'message', listener: (event: { readonly data: unknown }) => void): void
  addEventListener(type: 'close', listener: () => void): void
  send(data: string): void
  close(): void
}

export type SocketFactory = (url: string) => SocketLike

/** The real socket: Node's global WebSocket client. */
export const webSocketFactory: SocketFactory = (url) => new WebSocket(url)

export interface WsSubscriberOptions {
  readonly socketFactory?: SocketFactory
  /** Failed connections in a row before the subscription fails (default: never). */
  readonly maxReconnects?: number
  /** The wait before reconnect attempt n, from 0 (default 250 ms × 2^n, at most 30 s). */
  readonly reconnectDelayMs?: (attempt: number) => number
  /** The turns of the process at its relays: each upgrade takes one, as an HTTP call does (default: none, no wait). */
  readonly turns?: RelayTurns
}

/** How long an upgrade with no frame keeps its turn, an HTTP call's default timeout: a stuck relay holds no turn for good. */
const UPGRADE_TURN_MS = 10_000

/** The turns upgrades leave free: calls wait on none of them, however many are stuck or queued. */
const UPGRADE_SPARE = 1

type Stage = 'challenge' | 'auth' | 'open'

/** The subscribe URL of a relay URL: http becomes ws, https becomes wss. */
export function subscribeUrl(relay: string): string {
  return `${relay.replace(/\/+$/, '').replace(/^http/, 'ws')}/v0/subscribe`
}

class WsSubscription implements Subscription, AsyncIterator<Frame> {
  readonly #url: string
  readonly #mailbox: string
  readonly #signer: SigningKey
  readonly #hops: readonly Hop[]
  readonly #o: WsSubscriberOptions
  readonly #onLink: ((link: SubscriptionLink) => void) | undefined
  readonly #frames: Frame[] = []
  /** What the next auth frame carries: the caller's cursor once, then null. */
  #cursor: number | null
  #socket: SocketLike | null = null
  #open = false
  #failures = 0
  #closed = false
  #error: unknown = null
  #wake: (() => void) | null = null
  #timer: ReturnType<typeof setTimeout> | null = null

  constructor(
    url: string,
    mailbox: string,
    signer: SigningKey,
    hops: readonly Hop[],
    cursor: number | null,
    options: WsSubscriberOptions,
    onLink?: (link: SubscriptionLink) => void,
  ) {
    this.#url = url
    this.#mailbox = mailbox
    this.#signer = signer
    this.#hops = hops
    this.#o = options
    this.#onLink = onLink
    this.#cursor = cursor
    this.#connect()
  }

  [Symbol.asyncIterator](): AsyncIterator<Frame> {
    return this
  }

  async next(): Promise<IteratorResult<Frame>> {
    for (;;) {
      const frame = this.#frames.shift()
      if (frame !== undefined) return { value: frame, done: false }
      if (this.#error !== null) throw this.#error
      if (this.#closed) return { value: undefined, done: true }
      await new Promise<void>((resolve) => {
        this.#wake = resolve
      })
    }
  }

  async return(): Promise<IteratorResult<Frame>> {
    this.close()
    return { value: undefined, done: true }
  }

  /** Acknowledges every frame up to `cursor`, at the relay, which a reconnect resumes from. */
  ack(cursor: number): void {
    if (this.#open) this.#socket?.send(JSON.stringify({ t: 'ack', cursor }))
  }

  close(): void {
    this.#closed = true
    if (this.#timer !== null) clearTimeout(this.#timer)
    this.#timer = null
    const socket = this.#socket
    this.#socket = null
    this.#open = false
    socket?.close()
    this.#notify()
  }

  #notify(): void {
    const wake = this.#wake
    this.#wake = null
    wake?.()
  }

  #fail(error: unknown): void {
    this.#error ??= error
    this.close()
  }

  #report(link: SubscriptionLink): void {
    // The machine's telemetry, while it is on, counts a refusal or a lost connection by the relay's name and its code.
    if (!link.admitted) countRelayError(this.#url, link.error)
    try {
      this.#onLink?.(link)
    } catch {
      // The reader's fault: it stays out of the socket's path.
    }
  }

  #connect(): void {
    const turns = this.#o.turns
    if (turns === undefined) this.#dial(() => {})
    else turns.take(this.#url, (leave) => this.#dial(leave), UPGRADE_SPARE)
  }

  /** Opens the socket, on a turn that ends with the relay's first frame, which shows the upgrade done, or its close. */
  #dial(leave: Leave): void {
    if (this.#closed) {
      leave()
      return
    }
    countRelayCall(this.#url)
    let socket: SocketLike
    try {
      socket = (this.#o.socketFactory ?? webSocketFactory)(subscribeUrl(this.#url))
    } catch (e) {
      leave()
      this.#fail(new RelayError(null, 0, null, `${this.#url}: ${String(e)}`))
      return
    }
    const timer = setTimeout(leave, UPGRADE_TURN_MS)
    timer.unref()
    const upgraded = (): void => {
      clearTimeout(timer)
      leave()
    }
    this.#socket = socket
    let stage: Stage = 'challenge'
    socket.addEventListener('message', (event) => {
      upgraded()
      if (this.#socket !== socket) return
      try {
        stage = this.#onFrame(socket, stage, event.data)
      } catch (e) {
        if (e instanceof RelayError) this.#report({ admitted: false, error: e })
        this.#fail(e)
      }
    })
    socket.addEventListener('close', () => {
      upgraded()
      if (this.#socket === socket) this.#lost()
    })
  }

  #onFrame(socket: SocketLike, stage: Stage, data: unknown): Stage {
    const f = typeof data === 'string' ? jsonObject(data) : {}
    if (f.t === 'error') {
      throw new RelayError(
        isAcErrorCode(f.error) ? f.error : null,
        0,
        null,
        'the relay refused the subscription',
      )
    }
    if (stage === 'challenge' && f.t === 'challenge' && isHex(f.nonce, 32)) {
      const cursor = this.#cursor
      this.#cursor = null
      const sig = signSubscribe(this.#signer, f.nonce, this.#mailbox, cursor)
      const auth = {
        t: 'auth',
        mailbox: this.#mailbox,
        signer: this.#signer.address,
        auth: this.#hops,
        cursor,
        sig,
      }
      socket.send(JSON.stringify(auth))
      return 'auth'
    }
    if (stage === 'auth' && f.t === 'ok' && isCanonicalInteger(f.cursor)) {
      this.#open = true
      this.#failures = 0
      this.#report({ admitted: true })
      return 'open'
    }
    const stamped = f.received_at === undefined || isCanonicalInteger(f.received_at)
    const env = stage === 'open' && f.t === 'env' && typeof f.envelope === 'string' && stamped
    if (!env || !isCanonicalInteger(f.cursor)) {
      throw new RelayError('bad-shape', 0, null, `a frame the ${stage} stage does not take`)
    }
    // The relay's stamp as the frame's receivedAt; a frame without one leaves it out, and the receiver's own first sight
    // stands in (spec/SPEC.md §9 item 3).
    const stamp = isCanonicalInteger(f.received_at) ? { receivedAt: f.received_at } : {}
    this.#frames.push({ cursor: f.cursor, envelopeBytes: utf8(f.envelope as string), ...stamp })
    this.#notify()
    return 'open'
  }

  #lost(): void {
    const how = this.#open
      ? 'the connection closed'
      : 'the relay refused the subscription or could not be reached'
    const error = new RelayError(null, 0, null, `${this.#url}: ${how}`)
    this.#socket = null
    this.#open = false
    this.#failures++
    this.#report({ admitted: false, error })
    if (this.#failures > (this.#o.maxReconnects ?? Number.POSITIVE_INFINITY)) {
      this.#fail(error)
      return
    }
    const delay = (this.#o.reconnectDelayMs ?? defaultDelay)(this.#failures - 1)
    this.#timer = setTimeout(() => {
      this.#timer = null
      this.#connect()
    }, delay)
  }
}

function defaultDelay(attempt: number): number {
  return Math.min(250 * 2 ** attempt, 30_000)
}

/**
 * The JSON object of a text (or of UTF-8 bytes), or {} for anything else. A number is read only when written as a
 * plain decimal integer (spec/SPEC.md §2.5); any other is NaN, so a frame whose `cursor` is `1.0` or `1e0` is a frame
 * no stage takes (bad-shape).
 */
export function jsonObject(input: string | Uint8Array): Record<string, unknown> {
  try {
    const v: unknown = parseJson(input)
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** The subscribe half of a RelayClient. */
export function createWsSubscriber(options: WsSubscriberOptions = {}): Pick<RelayClient, 'subscribe'> {
  return {
    subscribe: (url, mailbox, signer, hops, cursor, onLink) =>
      new WsSubscription(url, mailbox, signer, hops, cursor, options, onLink),
  }
}
