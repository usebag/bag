import {
  type AcRecord,
  buildEnvelope,
  type ChainResult,
  checkChainShape,
  DEFAULT_WINDOW,
  generateSealingKey,
  generateSigningKey,
  groupCaveat,
  type Hop,
  newThread,
  parseEnvelope,
  replyThread,
  serializeRecord,
  signFetchAuth,
  type Thread,
  type TimeWindow,
  verifyChain,
} from '@usebag/core'
import { createRecordSource } from './adapters/well-known.ts'
import { Audit } from './audit.ts'
import { Gate, type GateOptions, type Held, SendHeld } from './moderation/gate.ts'
import { guardCheck, type Lookup, RelayGuard } from './net.ts'
import { Policy, type PolicyOptions } from './policy.ts'
import {
  type AuditSink,
  type Clock,
  EdgeError,
  type EdgeKeys,
  type EdgeStore,
  type FetchedBytes,
  type HeldSend,
  type InboundMessage,
  type InboxRow,
  type InboxState,
  type OutboxTarget,
  type Receipt,
  type RecordAnswer,
  type RecordSource,
  type RelayClient,
  type Rng,
  type SessionHandler,
  type SessionKeys,
  type SpawnHook,
} from './ports.ts'
import { askingReceipt, RECEIPT_SPREAD_S, Receipts } from './receipts.ts'
import { LOCAL_RELAY, Receiver } from './receiver.ts'
import { Resolver, recorded } from './resolver.ts'
import { Router } from './router.ts'
import { coreRng, Sender, type SendInput, type SendResult, type WaitingSend } from './sender.ts'

/** What composes an edge: its keys and chain, its ports, its relays and its policy. */
export interface EdgeOptions {
  readonly keys: SessionKeys
  /** The chain from the root to the signing key; [] (the default) when the signing key is its own root. */
  readonly auth?: readonly Hop[]
  /** The address the edge receives at; by default the signing key's. */
  readonly mailbox?: string
  readonly store: EdgeStore
  /** The relay client, and the edge's own relays: subscribed to, and asked for records. */
  readonly relays: { readonly client: RelayClient; readonly urls: readonly string[] }
  /** Where records come from; by default the well-known URLs over https and the relays. */
  readonly records?: RecordSource
  readonly policy: PolicyOptions
  /** v0 has none: a root message no session takes is queued. */
  readonly spawn?: SpawnHook
  readonly clock: Clock
  readonly rng: Rng
  readonly audit: AuditSink
  /** The relay TTL and clock skew of the ts window and the dedup window; spec defaults. */
  readonly window?: TimeWindow
  /**
   * How often a started edge publishes due outbox targets, and a running receiver retries the inbox rows that wait,
   * in milliseconds (default 1,000).
   */
  readonly flushEveryMs?: number
  /**
   * Called with the error of a subscription or a flush that failed in a started edge, and with the error a `doorbell`
   * or `accepted` callback threw (the row stays acked; the other callback is still called).
   */
  readonly onError?: (error: unknown) => void
  /**
   * The receiver's doorbell: called once per accepted row, when the store marks it acked. Synchronous: a
   * returned promise is ignored, and a slow call blocks the frame loop, the retrier tick and start.
   */
  readonly doorbell?: () => void
  /**
   * The receiver's `accepted`: called once per accepted row, right after the doorbell (receiver.ts, ack). Synchronous,
   * like the doorbell.
   */
  readonly accepted?: (row: InboxRow) => void
  /**
   * Calls relay URLs on loopback, link-local, private, unique-local, multicast and unspecified addresses that are not
   * among `relays.urls` (which are always allowed). For tests, and for a network of several relays on such addresses;
   * off by default.
   */
  readonly allowPrivateRelays?: boolean
  /** How the private-address guard resolves a relay's host name (default getaddrinfo). */
  readonly lookup?: Lookup
  /** The wait before a resubscription, attempt n from 0, in milliseconds (default 250 × 2^n, at most 30,000). */
  readonly resubscribeDelayMs?: (attempt: number) => number
  /**
   * Gives an outbox target whose last try got no answer from its relay (no HTTP status: the connection was refused or
   * timed out, or the client threw) the reason `unreachable`, in place of `publish-failed`
   * (spec/SPEC.md Appendix A names it). On by default; false keeps
   * `publish-failed`. The audit line names the cause in its detail either way.
   */
  readonly unreachableReason?: boolean
  /**
   * Leaves the mailbox's address record, as the edge's own relays serve it, at a relay an envelope goes to that holds
   * no current one, so that a reply resolves; never the accept-from record. Default true.
   */
  readonly leaveRecords?: boolean
  /**
   * The peers this reader answers a receipt request from, addresses, read at each message (receipts.ts): the person's
   * choice, never a sender's or a message's. Absent, none: a reader with receipts off emits nothing.
   */
  readonly receiptsTo?: () => readonly string[]
  /** A receipt's jitter before it goes out, in s (default RECEIPT_SPREAD_S). */
  readonly receiptSpreadS?: number
  /** The hooks and bounds of the org's outbound gate, which every send goes through when `policy.members` is set. */
  readonly gate?: Pick<GateOptions, 'breakers' | 'maxHeld' | 'domainOf' | 'recipientPolicy'>
  /** Roots the receiver trusts for a LOCAL_RELAY row only, read at each such row (receiver.ts). */
  readonly localRoots?: () => readonly string[]
  /** Sends a LOCAL_RELAY row's receipt on this machine (the bag service); absent, a local row is answered by none. */
  readonly localSend?: (input: SendInput) => Promise<unknown>
}

/** A known peer's relays: those its accepted messages came by. */
export interface PeerRelays {
  readonly address: string
  readonly relays: readonly string[]
}

/** A reply's input: the thread and the recipient (the principal) come from the message. */
export type ReplyInput = Omit<SendInput, 'to' | 'thread'>

/** What a renewed chain establishes (the core's ChainResult), and its earliest exp. */
export interface RenewedChain extends ChainResult {
  readonly exp: number
}

/** The earliest exp of a chain that has hops. */
function earliestExp(auth: readonly Hop[]): number {
  return Math.min(...auth.map((h) => h.exp))
}

/** New keys for an edge, from the rng: a signing key and a separate sealing key. */
export function generateEdgeKeys(rng: Rng): EdgeKeys {
  return { signing: generateSigningKey(coreRng(rng)), sealing: generateSealingKey(coreRng(rng)) }
}

/** The part of `auth` that runs from `mailbox` to `signer`: what subscribe and fetch present. [] for one key. */
export function hopsFrom(auth: readonly Hop[], mailbox: string, signer: string): readonly Hop[] {
  const i = auth.findIndex((h) => h.iss === mailbox)
  return mailbox === signer || i < 0 ? [] : auth.slice(i)
}

/** The edge (spec/SPEC.md §9): a sender, a receiver, a resolver, a policy, a router and an audit log, composed. */
export class Edge {
  readonly audit: Audit
  /** The private-address guard of every relay call but those to the edge's own relays. */
  readonly guard: RelayGuard
  readonly resolver: Resolver
  readonly policy: Policy
  readonly router: Router
  readonly sender: Sender
  readonly receiver: Receiver
  readonly #o: EdgeOptions
  readonly #receipts: Receipts
  /** The recipients of each envelope sealed here (local sends), for their receipts: kept in memory only. */
  readonly #sealedTo = new Map<string, readonly string[]>()
  /** The org's outbound gate: send, sendOrWait and reply go through it when policy.members is set. */
  readonly #gate: Gate
  /**
   * The chain the edge signs under, and its part from the mailbox key: read at each send, subscribe and fetch, and
   * swapped by renewChain.
   */
  readonly #chain: { auth: readonly Hop[]; hops: readonly Hop[] }
  /**
   * How long a thread's binding outlives its last use, in seconds: 2 x TTL + skew. A peer may read our message as late
   * as its TTL and reply then, and the reply may wait out its own TTL at the relay while this edge is down.
   */
  readonly #threadHorizon: number
  #run: {
    readonly abort: AbortController
    readonly loops: Promise<void>[]
    readonly timer: NodeJS.Timeout
  } | null = null

  constructor(options: EdgeOptions) {
    this.#o = options
    const { clock, rng, store } = options
    const auth = options.auth ?? []
    const relay = options.relays.client
    const window = options.window ?? DEFAULT_WINDOW
    this.#threadHorizon = 2 * window.ttl + window.skew
    // The anchor of the log is the store's row under the sink's name: checked here, put after every line.
    const log = options.audit.name ?? 'audit'
    this.audit = new Audit(options.audit, clock, {
      get: () => store.auditAnchorGet(log),
      put: (anchor) => store.auditAnchorPut(log, anchor, clock.now()),
      others: () => store.auditAnchors().filter((a) => a.name !== log),
    })
    this.guard = new RelayGuard({
      own: options.relays.urls,
      ...(options.allowPrivateRelays === undefined ? {} : { allowPrivate: options.allowPrivateRelays }),
      ...(options.lookup === undefined ? {} : { lookup: options.lookup }),
    })
    const guard = this.guard
    const source = options.records ?? createRecordSource(relay)
    this.resolver = new Resolver({
      store,
      source,
      clock,
      audit: this.audit,
      relays: options.relays.urls,
      guard,
    })
    this.policy = new Policy(options.policy, this.resolver)
    this.router = new Router(store, clock, options.spawn)
    const chain = { auth, hops: hopsFrom(auth, this.mailbox, this.address) }
    this.#chain = chain
    const common = {
      keys: options.keys,
      store,
      relay,
      router: this.router,
      audit: this.audit,
      clock,
      rng,
      guard,
    }
    this.sender = new Sender({
      ...common,
      // Getters, so that a chain renewChain swaps in is what every later send and subscription presents.
      get auth() {
        return chain.auth
      },
      resolver: this.resolver,
      ttl: window.ttl,
      unreachableReason: options.unreachableReason !== false,
      mailbox: this.mailbox,
      relays: options.relays.urls,
      records: source,
      leaveRecords: options.leaveRecords !== false,
    })
    this.#receipts = new Receipts({
      store,
      clock,
      rng,
      spreadS: options.receiptSpreadS ?? RECEIPT_SPREAD_S,
      // A group's mailbox answers no one: a receipt there would tell one member about another.
      to: () => (this.#atGroup ? [] : (options.receiptsTo?.() ?? [])),
      send: (i) => this.sendOrWait(i),
      sealed: (id) => this.#sealedTo.get(id),
      onError: (e) => options.onError?.(e),
    })
    this.receiver = new Receiver({
      ...common,
      mailbox: this.mailbox,
      receipts: this.#receipts,
      get hops() {
        return chain.hops
      },
      policy: this.policy,
      window,
      ...(options.flushEveryMs === undefined ? {} : { retryEveryMs: options.flushEveryMs }),
      ...(options.resubscribeDelayMs === undefined ? {} : { resubscribeDelayMs: options.resubscribeDelayMs }),
      ...(options.doorbell === undefined ? {} : { doorbell: options.doorbell }),
      ...(options.localRoots === undefined ? {} : { localRoots: options.localRoots }),
      accepted: (row) => {
        // A local row's receipt goes back on this machine only, never on the wire (decision 103).
        const local = row.relay === LOCAL_RELAY
        if (!local || options.localSend) this.#receipts.answer(row, local ? options.localSend : undefined)
        options.accepted?.(row)
      },
      ...(options.onError === undefined ? {} : { onError: options.onError }),
    })
    const { members } = options.policy
    this.#gate = new Gate({
      ...options.gate,
      edge: { send: (i) => this.sender.send(i), audit: this.audit, resolver: this.resolver },
      store,
      clock,
      rng,
      ...(members === undefined ? {} : { members }),
    })
  }

  /** The signing key's address: the `from` of what this edge sends. */
  get address(): string {
    return this.#o.keys.signing.address
  }

  /** The address this edge receives at. */
  get mailbox(): string {
    return this.#o.mailbox ?? this.address
  }

  /** The chain this edge signs under, root first: [] when the signing key is its own root. */
  get auth(): readonly Hop[] {
    return this.#chain.auth
  }

  /**
   * Swaps the chain this edge signs under for a renewed one, for every later send,
   * subscription and fetch. The new chain is verified by the core at the edge's clock, to this edge's signing key (the
   * core's codes: chain-not-to-sender, hop-expired, bad-hop-sig, the shape and cap codes), and must continue the current
   * one: the same root and the same principal (the first hop's iss, the last hop's iss), a hop from the mailbox key
   * when the mailbox is not the signing key, else EdgeError chain-mismatch (also for an edge that signs as its own
   * root); and a later earliest exp, else EdgeError chain-not-later. A refusal changes nothing. The swap writes one
   * audit line (rotate, accept), whose detail names the chain's subject, principal, hop count, effective caveats and
   * the earliest exp before and after: public data, never key material. A subscription that is open keeps the hops it
   * was opened with until it ends; the next one, a resubscription after an error frame included, presents these.
   */
  renewChain(auth: readonly Hop[]): RenewedChain {
    const current = this.#chain.auth
    const first = current[0]
    if (first === undefined) {
      throw new EdgeError('chain-mismatch', 'this edge signs as its own root, so it has no chain to renew')
    }
    const hops = checkChainShape(auth)
    const next = verifyChain(hops, this.address, this.#o.clock.now())
    const principal = (current.at(-1) as Hop).iss
    if (next.root !== first.iss || next.principal !== principal) {
      throw new EdgeError(
        'chain-mismatch',
        `the chain runs from ${next.root} through ${next.principal}, not from ${first.iss} through ${principal}`,
      )
    }
    const fromMailbox = hopsFrom(hops, this.mailbox, this.address)
    if (this.mailbox !== this.address && fromMailbox.length === 0) {
      throw new EdgeError('chain-mismatch', `the chain has no hop from the mailbox key ${this.mailbox}`)
    }
    const before = earliestExp(current)
    const exp = earliestExp(hops)
    if (exp <= before) {
      throw new EdgeError(
        'chain-not-later',
        `its earliest exp, ${exp}, is not after the current chain's, ${before}`,
      )
    }
    this.#chain.auth = hops
    this.#chain.hops = fromMailbox
    this.audit.record({
      event: 'rotate',
      decision: 'accept',
      from: this.address,
      root: next.root,
      detail: {
        subject: `chain:${this.address}`,
        principal,
        hops: hops.length,
        caveats: next.caveats,
        exp_before: before,
        exp_after: exp,
      },
    })
    return { ...next, exp }
  }

  /**
   * Sends one envelope to every recipient (Sender.send), through the org's gate when policy.members is set: a denied
   * recipient is a PolicyRefusal and a send a breaker holds a SendHeld, both before anything is sealed.
   */
  async send(input: SendInput): Promise<SendResult> {
    const r = await this.#gated(input, (i) => this.sender.send(i))
    if ('held' in r) throw new SendHeld(r)
    return r
  }

  /**
   * Sends, or keeps waiting in the store a send whose recipient does not resolve; flush tries it again (sendOrWait). Through
   * the org's gate as send is, a held send is returned: `{held: true, id, rule, ...}`.
   */
  sendOrWait(input: SendInput): Promise<SendResult | WaitingSend | Held> {
    return this.#gated(input, (i) => this.sender.sendOrWait(i))
  }

  /** The sends the org's gate holds pending a person, oldest first. */
  held(): HeldSend[] {
    return this.#gate.held()
  }

  /** A person's release of a held send: the deny list checked again, then sealed and sent with a fresh ts. */
  release(id: string): Promise<SendResult> {
    return this.#gate.release(id)
  }

  /** A person's drop of a held send: nothing is sealed or sent. */
  drop(id: string): HeldSend {
    return this.#gate.drop(id)
  }

  async #gated<R extends SendResult | WaitingSend>(input: SendInput, via: (i: SendInput) => Promise<R>) {
    if (this.#o.policy.members === undefined) return via(input)
    const r = await this.#gate.send(input, via)
    return r.held === null ? r.sent : { ...r.held, held: true as const }
  }

  /** The sends waiting because a recipient did not resolve (sendOrWait), oldest first. */
  waiting(): readonly WaitingSend[] {
    return this.sender.waiting()
  }

  /** For each principal of an accepted message, the relays its messages came by; read from the inbox, it calls no relay. */
  peers(): readonly PeerRelays[] {
    const peers = new Map<string, Set<string>>()
    for (const row of this.#o.store.inboxList(['routed', 'queued', 'acked'])) {
      if (row.content === null || row.relay === LOCAL_RELAY) continue
      // An accepted row's principal: the chain's last hop's iss, else `from`, as verifyChain names it.
      const env = parseEnvelope(row.bytes)
      const address = env.auth.at(-1)?.iss ?? env.from
      peers.set(address, (peers.get(address) ?? new Set<string>()).add(recorded(row.relay)))
    }
    return [...peers].map(([address, relays]) => ({ address, relays: [...relays] }))
  }

  /** True at a group's mailbox, read under a membership chain. */
  get #atGroup(): boolean {
    return this.#chain.hops[0]?.caveats.includes(groupCaveat(this.mailbox)) === true
  }

  /** The read receipts of envelope `id` of this edge's outbox, in the order they arrived; none says nothing (receipts.ts). */
  receipts(id: string): readonly Receipt[] {
    return this.#o.store.receiptsOf(id)
  }

  /** Replies in the message's thread to the principal, looking its record up first at the relay it came by; as send. */
  reply(message: InboundMessage, input: ReplyInput): Promise<SendResult> {
    // At a group's mailbox, read under a membership chain, a reply goes to the group.
    return this.send({
      ...input,
      to: [this.#atGroup ? this.mailbox : message.principal],
      thread: replyThread(message.thread, [message.id]),
      relays: [message.relay, ...(input.relays ?? [])],
    })
  }

  /**
   * Builds one envelope to `recipients` as a send does (signed, sealed to each sealing key, the session's thread bound)
   * and returns its bytes: no resolver, no outbox, no relay. The bag service delivers it between identities of one
   * home (spec/SPEC.md 9.2).
   */
  seal(
    input: Omit<SendInput, 'to'>,
    recipients: readonly { readonly address: string; readonly sealingKey: Uint8Array }[],
  ): { readonly id: string; readonly thread: Thread; readonly bytes: Uint8Array } {
    const { clock, keys, rng } = this.#o
    const thread = input.thread ?? newThread(coreRng(rng))
    const { envelope, bytes } = buildEnvelope({
      from: keys.signing,
      to: [...recipients],
      auth: this.#chain.auth,
      type: input.type,
      thread,
      body: input.receipt === true ? askingReceipt(input.body) : input.body,
      ts: clock.now(),
      rng: coreRng(rng),
    })
    this.#sealedTo.set(envelope.id, envelope.to)
    if (input.session !== undefined) this.router.bind(thread.id, input.session)
    return { id: envelope.id, thread, bytes }
  }

  /** Publishes a failed envelope's exact bytes again. */
  resend(id: string): Promise<OutboxTarget[]> {
    return this.sender.resend(id)
  }

  /** Publishes every outbox target that is due now. */
  flush(): Promise<OutboxTarget[]> {
    return this.sender.flush()
  }

  /** The outbox state of an envelope at each of its relays. */
  status(id: string): OutboxTarget[] {
    return this.#o.store.outboxTargets(id)
  }

  /** Routes a thread to a session's handler, persisted (Router.register). */
  register(threadId: string, handler: SessionHandler): void {
    this.router.register(threadId, handler)
  }

  /** Makes a session's handler live for the threads bound to it. */
  attach(handler: SessionHandler): void {
    this.router.attach(handler)
  }

  /** The handler of root messages on threads no session holds. */
  setDefault(handler: SessionHandler | null): void {
    this.router.setDefault(handler)
  }

  /**
   * Handles one frame from a relay (Receiver.receive); a started edge does this for every frame. `receivedAt` is the
   * relay's stamp (a frame's, or a fetched envelope's `receivedAt`); without one the edge's first sight stands in.
   * It does not ack: the row stays routed or queued, and the doorbell and `accepted` have not fired. A caller outside a
   * started edge must call `edge.receiver.ack(row)`, else the next `recover()` acks the row and fires them late.
   */
  receive(relay: string, cursor: number, bytes: Uint8Array, receivedAt?: number): Promise<InboxRow> {
    return this.receiver.receive(relay, cursor, bytes, receivedAt ?? null)
  }

  /** The inbox rows in arrival order, of the given states when given. */
  inbox(states?: readonly InboxState[]): InboxRow[] {
    return this.#o.store.inboxList(states)
  }

  /**
   * Publishes a signed record (address, accept-from or key) to relays, by default the edge's own; resolve-failed for
   * a relay the guard refuses. Each relay's answer, in `urls` order: what it stored (kind, signer, iat, valid_until;
   * spec/SPEC.md §8.2), or null from a relay that answers `{"ok": true}` alone, as an older relay does.
   */
  publishRecord(
    record: AcRecord,
    urls: readonly string[] = this.#o.relays.urls,
  ): Promise<(RecordAnswer | null)[]> {
    const bytes = serializeRecord(record)
    return Promise.all(
      urls.map(async (url) => {
        const checked = guardCheck(this.guard, url)
        if (checked !== undefined) await checked
        return (await this.#o.relays.client.publish(url, bytes)).record ?? null
      }),
    )
  }

  /**
   * Fetches an envelope by id, proving the signing key, with the chain from the mailbox when they differ, as its bytes
   * with the relay's `receivedAt` when it sent one; resolve-failed for a relay the guard refuses. The proof's audience
   * is `url` byte for byte (spec/SPEC.md §8.3): pass the relays entry as listed, since nothing here adds or strips a
   * character, and a relay refuses bad-auth a proof whose audience is not its own base URL.
   */
  async fetch(url: string, id: string): Promise<FetchedBytes> {
    const checked = guardCheck(this.guard, url)
    if (checked !== undefined) await checked
    const ts = this.#o.clock.now()
    const sig = signFetchAuth(this.#o.keys.signing, id, ts, url)
    return this.#o.relays.client.fetch(url, id, { signer: this.address, ts, sig, auth: this.#chain.hops })
  }

  /** Finishes interrupted rows, subscribes at every relay of the edge, and publishes due targets on a timer. */
  async start(): Promise<void> {
    if (this.#run !== null) return
    const abort = new AbortController()
    const onError = (e: unknown): void => this.#o.onError?.(e)
    const run = {
      abort,
      loops: [] as Promise<void>[],
      timer: setInterval(() => this.#tick(onError), this.#o.flushEveryMs ?? 1000),
    }
    run.timer.unref()
    this.#run = run
    try {
      await this.receiver.recover()
    } catch (e) {
      await this.stop()
      throw e
    }
    if (abort.signal.aborted) return
    run.loops.push(...this.#o.relays.urls.map((url) => this.receiver.run(url, abort.signal).catch(onError)))
    this.#tick(onError)
  }

  /** Stops the subscriptions and the timer, and waits for the subscriptions to end. */
  async stop(): Promise<void> {
    this.#receipts.stop()
    const run = this.#run
    if (run === null) return
    this.#run = null
    clearInterval(run.timer)
    run.abort.abort()
    await Promise.all(run.loops)
  }

  #tick(onError: (e: unknown) => void): void {
    try {
      const now = this.#o.clock.now()
      this.#o.store.seenPrune(now)
      this.#o.store.threadsPrune(now - this.#threadHorizon)
    } catch (e) {
      onError(e)
    }
    this.sender.flush().catch(onError)
  }
}
