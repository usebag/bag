import {
  type AcErrorCode,
  type Hop,
  isAcError,
  parseEnvelope,
  parseRecord,
  recordSigner,
  verifyChain,
  verifyFetchAuth,
} from '@usebag/core'
import {
  createWsSubscriber,
  type FetchProof,
  type Frame,
  type PairOpen,
  type PairReach,
  type PublishResult,
  type RelayClient,
  RelayError,
  type SocketFactory,
  type Subscription,
  type SubscriptionLink,
} from '@usebag/edge'

// A relay in memory, the fake RelayClient of the MCP tests: records by relay, signer and kind; one mailbox per relay
// and recipient, with cursors from 1; live subscriptions that wake on publish and keep acks; fetch for a party;
// failures to inject; the hops each subscription and fetch presented; and, when asked, the chain checks a relay makes
// at publish (spec/SPEC.md §8.2, at the envelope's ts). The e2e suite runs the real relay.

interface Row {
  readonly cursor: number
  readonly bytes: Uint8Array
}

class MemorySubscription implements Subscription, AsyncIterator<Frame> {
  readonly #relay: MemoryRelay
  readonly url: string
  readonly mailbox: string
  #after: number
  #closed = false
  #wake: (() => void) | null = null
  #link: ((link: SubscriptionLink) => void) | undefined

  constructor(
    relay: MemoryRelay,
    url: string,
    mailbox: string,
    cursor: number | null,
    link: ((link: SubscriptionLink) => void) | undefined,
  ) {
    this.#relay = relay
    this.url = url
    this.mailbox = mailbox
    this.#link = link
    this.#after = cursor ?? relay.acks.get(`${url} ${mailbox}`) ?? 0
  }

  [Symbol.asyncIterator](): AsyncIterator<Frame> {
    return this
  }

  async next(): Promise<IteratorResult<Frame>> {
    for (;;) {
      const failure = this.#relay.failSubscribe
      if (failure !== null) throw failure
      const code = this.#relay.refusals.get(`${this.url} ${this.mailbox}`)?.shift()
      if (code !== undefined) throw new RelayError(code, 0, null, 'refused')
      const once = this.#relay.failOnce.get(this.mailbox)
      if (once !== undefined) {
        this.#relay.failOnce.delete(this.mailbox)
        throw once
      }
      if (this.#closed) return { value: undefined, done: true }
      // Admitted past those checks: a real relay's refusal is an error frame before its ok.
      this.#link?.({ admitted: true })
      this.#link = undefined
      const row = this.#relay.box(this.url, this.mailbox).find((r) => r.cursor > this.#after)
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
    const key = `${this.url} ${this.mailbox}`
    this.#relay.acks.set(key, Math.max(cursor, this.#relay.acks.get(key) ?? 0))
  }

  close(): void {
    this.#closed = true
    this.#relay.subs.delete(this)
    this.wake()
  }
}

export class MemoryRelay implements RelayClient {
  readonly envelopes = new Map<string, Uint8Array>()
  readonly boxes = new Map<string, Row[]>()
  readonly records = new Map<string, Uint8Array>()
  readonly acks = new Map<string, number>()
  readonly subs = new Set<MemorySubscription>()
  readonly published: string[] = []
  /** Publishes of envelopes to these relay URLs throw the error. */
  readonly failPublish = new Map<string, RelayError>()
  /** Publishes of records to these relay URLs throw the error. */
  readonly failRecordPublish = new Map<string, RelayError>()
  /** The hops each subscribe and fetch presented, in call order. */
  readonly presented: { readonly call: 'subscribe' | 'fetch'; readonly hops: readonly Hop[] }[] = []
  /** When true, an envelope publish verifies its chain at its ts and throws the code with status 422. */
  checkChains = false
  /** The pair rendezvous (edge pair-code.ts): absent until offerRendezvous, so every other test keeps the string. */
  pairOpen?: (url: string, open: PairOpen) => Promise<string | null>
  pairClaim?: (url: string, nameplate: string) => Promise<PairReach | null>
  /** The opens by `<url> <nameplate>`, each until its end (the relay's pair/open and pair/claim, in memory). */
  readonly rendezvous = new Map<string, PairReach>()
  /**
   * When true, an envelope publish is refused 403 root-not-accepted, as the relay's step 7 refuses it, when no
   * recipient's accept-from record at the relay admits its root (the first hop's iss, else from). A recipient with no
   * accept-from record here is not checked.
   */
  checkRoots = false
  /** When set, every record lookup throws it (a relay that cannot be reached). */
  failRecords: RelayError | null = null
  /** When set, every subscription throws it on its next read. */
  failSubscribe: RelayError | null = null
  /** The first subscription to a mailbox that reads next throws the error, once (an error frame). */
  readonly failOnce = new Map<string, RelayError>()
  /** The codes the next reads of a mailbox's subscriptions at a relay throw, in order, each a new error (refuse). */
  readonly refusals = new Map<string, AcErrorCode[]>()

  /**
   * Makes the next reads at `url` for `mailbox` throw these codes, one each, each a fresh RelayError as the real
   * client's subscriptions throw (subscriptions.ts reads an end by the error's identity); wakes the subscriptions.
   */
  refuse(url: string, mailbox: string, ...codes: AcErrorCode[]): void {
    this.refusals.set(`${url} ${mailbox}`, codes)
    this.wakeAll()
  }

  /** Offers pair/open and pair/claim: nameplates from 472 up, each open until its ttl on `now`'s clock. */
  offerRendezvous(now: () => number): void {
    this.pairOpen = async (url, open) => {
      const nameplate = String(472 + this.rendezvous.size)
      const { inviter, invitation, relays, ttl } = open
      this.rendezvous.set(`${url} ${nameplate}`, { inviter, invitation, relays, exp: now() + ttl })
      return nameplate
    }
    this.pairClaim = async (url, nameplate) => {
      const reach = this.rendezvous.get(`${url} ${nameplate}`)
      return reach === undefined || now() > reach.exp ? null : reach
    }
  }

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
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }
    if (v.kind !== undefined) {
      const refused = this.failRecordPublish.get(url)
      if (refused !== undefined) throw refused
      const r = parseRecord(bytes)
      this.records.set(`${url} ${recordSigner(r)} ${r.kind}`, bytes)
      return { id: '', duplicate: false, delivered: 0 }
    }
    const failure = this.failPublish.get(url)
    if (failure !== undefined) throw failure
    const env = parseEnvelope(bytes)
    if (this.checkChains) {
      try {
        verifyChain(env.auth, env.from, env.ts)
      } catch (e) {
        if (isAcError(e)) throw new RelayError(e.code, 422, null, e.message)
        throw e
      }
    }
    if (this.checkRoots) {
      const root = env.auth[0]?.iss ?? env.from
      const roots = env.to.map((to) => {
        const r = this.records.get(`${url} ${to} accept-from`)
        return r === undefined ? null : (parseRecord(r) as { roots: readonly string[] }).roots
      })
      if (roots.every((rs) => rs !== null && !rs.includes('*') && !rs.includes(root)))
        throw new RelayError('root-not-accepted', 403, null, 'the root is not accepted')
    }
    this.published.push(url)
    const duplicate = this.envelopes.has(`${url} ${env.id}`)
    if (!duplicate) {
      this.envelopes.set(`${url} ${env.id}`, bytes)
      for (const to of env.to) {
        const rows = this.box(url, to)
        rows.push({ cursor: rows.length + 1, bytes })
      }
      for (const s of this.subs) s.wake()
    }
    return { id: env.id, duplicate, delivered: duplicate ? 0 : env.to.length }
  }

  async fetch(url: string, id: string, proof: FetchProof): Promise<Uint8Array> {
    this.presented.push({ call: 'fetch', hops: proof.auth })
    const bytes = this.envelopes.get(`${url} ${id}`)
    if (bytes === undefined) throw new RelayError('not-found', 404, null, id)
    // The relay at `url` accepts a proof for its own base only, byte for byte (spec/SPEC.md §8.3).
    if (!verifyFetchAuth(proof.signer, id, proof.ts, url, proof.sig))
      throw new RelayError('bad-auth', 401, null, id)
    return bytes
  }

  async fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    if (this.failRecords !== null) throw this.failRecords
    return this.records.get(`${url} ${address} ${kind}`) ?? null
  }

  subscribe(
    url: string,
    mailbox: string,
    _signer: unknown,
    hops: readonly Hop[],
    cursor: number | null,
    onLink?: (link: SubscriptionLink) => void,
  ): Subscription {
    this.presented.push({ call: 'subscribe', hops })
    const s = new MemorySubscription(this, url, mailbox, cursor, onLink)
    this.subs.add(s)
    return s
  }

  /** Wakes every live subscription (after a test changes failSubscribe). */
  wakeAll(): void {
    for (const s of this.subs) s.wake()
  }
}

/** What a connection gets from a gated relay: a close with no frame, the relay's answers, silence, or this refusal. */
type Gate = 'close' | 'admit' | 'hold' | AcErrorCode

export interface GatedRelay {
  /** `relay` for all but subscribe, which is the real client's. */
  readonly client: MemoryRelay
  /** What each new connection gets. */
  gate: Gate
  /** The connections tried, and those the relay admitted. */
  dials(): number
  admitted(): number
  /** Closes the connections open now, as a relay that goes away does. */
  drop(): void
}

/**
 * A relay as the real client meets it. A relay over its connection cap answers 503 at the upgrade
 * (crates/ac-relay/src/http.rs), which a socket shows as a close with no frame and no code, so the subscription here is
 * the real client's (ws-relay.ts): what it makes of that close is the point, and MemorySubscription has no connection.
 */
export function gatedRelay(relay: MemoryRelay, gate: Gate): GatedRelay {
  const open = new Set<() => void>()
  let [dials, admitted] = [0, 0]
  const socketFactory: SocketFactory = () => {
    dials++
    const on = new Map<string, (event: { readonly data: unknown }) => void>()
    const frame = (f: object): void => on.get('message')?.({ data: JSON.stringify(f) })
    const lost = (): void => {
      open.delete(lost)
      on.get('close')?.({ data: null })
    }
    // After the client has its listeners, as a socket's events always are.
    queueMicrotask(() => {
      if (g.gate === 'hold') return
      if (g.gate === 'admit') {
        open.add(lost)
        frame({ t: 'challenge', nonce: '00'.repeat(32) })
        return
      }
      if (g.gate !== 'close') frame({ t: 'error', error: g.gate })
      lost()
    })
    return {
      addEventListener: (
        type: 'message' | 'close',
        listener: (event: { readonly data: unknown }) => void,
      ) => {
        on.set(type, listener)
      },
      send: (data) => {
        if ((JSON.parse(data) as { t?: unknown }).t !== 'auth') return
        // Later, as a relay's answer always is: the client is still inside its challenge frame.
        queueMicrotask(() => {
          admitted++
          frame({ t: 'ok', cursor: 0 })
        })
      },
      close: () => {
        open.delete(lost)
      },
    }
  }
  const subscriber = createWsSubscriber({ socketFactory, reconnectDelayMs: () => 1 })
  const g: GatedRelay = {
    client: Object.assign(Object.create(relay) as MemoryRelay, subscriber),
    gate,
    dials: () => dials,
    admitted: () => admitted,
    drop: () => {
      for (const lost of [...open]) lost()
    },
  }
  return g
}
