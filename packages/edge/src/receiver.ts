import {
  AcError,
  type AcErrorCode,
  bytesEqual,
  type ChainResult,
  type Envelope,
  type Hop,
  isAcError,
  openSealed,
  type PolicyCode,
  parseEnvelope,
  type SealedContent,
  type TimeWindow,
  verifyChain,
  verifyOuter,
} from '@usebag/core'
import { AgentError } from './agent/model.ts'
import { type Audit, type AuditEvent, type AuditValue, reasonOf } from './audit.ts'
import { advanceInbox, isWaiting, TRANSIENT_CODES } from './inbox.ts'
import { guardCheck, type RelayGuard } from './net.ts'
import { jitterOf, retryWait } from './outbox.ts'
import type { Decision, Policy, Ruling } from './policy.ts'
import {
  type Clock,
  type EdgeStore,
  type Frame,
  type Hold,
  type InboundMessage,
  type InboxRow,
  isEnvelopeOpener,
  type RelayClient,
  RelayError,
  type Rng,
  type SessionKeys,
  type Subscription,
} from './ports.ts'
import { RECEIPT_TYPE, type Receipts } from './receipts.ts'
import type { Router } from './router.ts'

// The receiver (spec/SPEC.md §9.2, §9.3): each frame becomes an inbox row before anything is checked, then runs
// verify (parse, outer checks, a recipient) -> policy (chain, the receipt bound, trusted root, revocation) -> dedup
// -> unseal -> caveats and type -> route, auditing every step, and is acked only once its row is past routing. From
// the dedup check to the verdict nothing awaits, so the seen set is read and written in one turn. A transient
// rejection (inbox.ts) waits and is retried until ts + TTL, and at once at each recover(), the start of a read; a
// subscription the relay ends with an error frame is made again. Live delivery is judged at the relay's clock as well as at ts: the row's received_at is
// the relay's stamp on the frame, or the receiver's own first sight when the frame has none, and a chain is refused
// hop-expired once that second is past its earliest exp + skew, at first sight and on every retry alike. An org's
// policy refuses or holds a row; a held row's content stays null until a release re-checks it, or a drop.

export interface ReceiverOptions {
  readonly keys: SessionKeys
  readonly mailbox: string
  /** The chain from the mailbox key to the signing key: [] when they are one key. */
  readonly hops: readonly Hop[]
  readonly store: EdgeStore
  readonly relay: RelayClient
  readonly policy: Policy
  readonly router: Router
  readonly audit: Audit
  readonly clock: Clock
  readonly window: TimeWindow
  /** The rng of the retry jitter. */
  readonly rng: Rng
  /** The private-address guard: a run at a URL it refuses fails with resolve-failed. */
  readonly guard?: RelayGuard
  /** How often a running receiver retries the rows that wait, in milliseconds (default 1,000). */
  readonly retryEveryMs?: number
  /** The wait before resubscription attempt n, from 0, in milliseconds (default resubscribeDelay). */
  readonly resubscribeDelayMs?: (attempt: number) => number
  /**
   * The doorbell: called once per accepted row, when the store marks it acked (ack); never for a refusal,
   * a hold or a row that waits. Synchronous: a returned promise is ignored, and a slow call blocks the caller of ack.
   * A throw is reported to onError and loses this row's ring.
   */
  readonly doorbell?: () => void
  /**
   * Called once per accepted row, right after the doorbell, when the store marks it acked (from routed or queued), on
   * every path that acks: a frame, the retrier (any cursor), release, recover(). Gets the row as accepted (state
   * routed or queued). Never for a rejected, held or waiting row. Synchronous, like the doorbell; a throw is reported
   * to onError, loses this row's call, and leaves the row acked.
   */
  readonly accepted?: (row: InboxRow) => void
  /** Called with the error a doorbell or an accepted callback threw in ack (the Edge passes its own onError). */
  readonly onError?: (error: unknown) => void
  /** Takes a read receipt, before the type check: the sender's accept list is for messages, and a receipt is none. */
  readonly receipts?: Pick<Receipts, 'take'>
}

/**
 * The error-frame codes that refuse a subscription's handshake whatever the timing: a proof that does not verify, a
 * signer who may not read the mailbox, and every chain code (spec/SPEC.md §8.5).
 */
export const REFUSALS: ReadonlySet<AcErrorCode> = new Set<AcErrorCode>([
  'bad-auth',
  'not-authorized',
  'too-many-hops',
  'bad-hop',
  'too-many-caveats',
  'caveat-too-long',
  'chain-broken',
  'chain-not-to-sender',
  'exp-not-monotone',
  'hop-expired',
  'bad-hop-sig',
  // The relay refuses a revoked hop at subscribe and ends a live subscription with it (close 4001).
  'revoked',
])

/** Refusals in a row that end a subscription for good. */
export const MAX_REFUSALS = 3

/** The wait before resubscription attempt n, from 0: 250 ms × 2^n, at most 30 s. */
export function resubscribeDelay(attempt: number): number {
  return Math.min(250 * 2 ** attempt, 30_000)
}

/** Resolves after `ms`, or at once when the signal aborts. */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const done = (): void => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', done)
      resolve()
    }
    const timer = setTimeout(done, ms)
    signal?.addEventListener('abort', done, { once: true })
  })
}

const where = (row: InboxRow): Record<string, AuditValue> => ({ relay: row.relay, cursor: row.cursor })

/** A hold that the full quarantine turns into a refusal, rule quarantine.full, naming the rule that would have held. */
function verdictFull(d: Ruling, cap: number): Ruling {
  return {
    action: 'refuse',
    code: 'policy-refused',
    rule: 'quarantine.full',
    detail: { held_rule: d.rule, cap },
  }
}

/** An open the agent refused that a retry can undo: it is down or locked, or it rate-limited; not-in-grant is final. */
function openRetry(e: unknown): boolean {
  if (e instanceof AgentError) return e.code === 'agent-locked'
  return !isAcError(e) || e.code === 'rate-limited'
}

/** True for one envelope's bytes: the very bytes, or the same id. Bytes that do not parse claim no id to match. */
function sameEnvelope(a: Uint8Array, b: Uint8Array): boolean {
  if (bytesEqual(a, b)) return true
  try {
    return parseEnvelope(a).id === parseEnvelope(b).id
  } catch {
    return false
  }
}

/** The relay's received_at a frame carries, Unix seconds, or null when it carries none or not as a plain second. */
function stampOf(frame: Frame): number | null {
  const stamp = frame.receivedAt
  return stamp !== undefined && Number.isSafeInteger(stamp) && stamp >= 0 ? stamp : null
}

/**
 * The receipt bound (spec/SPEC.md §9 item 3): the last second a chain's mail may be received, its earliest exp
 * over every hop plus the skew, or null for an empty chain, which has no exp.
 */
export function receiptBound(hops: readonly Hop[], skew: number): number | null {
  return hops.length === 0 ? null : Math.min(...hops.map((h) => h.exp)) + skew
}

/** The retries of one subscription: a timer, the highest cursor it delivered, and the fault of a retry. */
interface Retrier {
  seen(cursor: number): void
  /** Stops the timer, waits for a retry in flight, and returns its fault (null when there was none). */
  halt(): Promise<{ readonly error: unknown } | null>
}

export class Receiver {
  readonly #o: ReceiverOptions
  /** The seq of each row being checked or routed now: a redelivered frame or a retry never handles it twice. */
  readonly #busy = new Set<number>()

  constructor(options: ReceiverOptions) {
    this.#o = options
  }

  /**
   * Handles one frame and returns its row: rejected, routed or queued (acked when it was acked before), or received
   * when it waits for a retry (a transient rejection not yet due) or is being handled by another call. `receivedAt` is
   * the relay's stamp on the frame; a new row keeps it as its received_at, or this edge's clock when there is none
   * (spec/SPEC.md §9 item 3), and a frame handed in again keeps its row's.
   */
  receive(
    relay: string,
    cursor: number,
    bytes: Uint8Array,
    receivedAt: number | null = null,
  ): Promise<InboxRow> {
    return this.#receive(relay, cursor, bytes, receivedAt, false)
  }

  /** receive, and with `now` a row that waits is checked at once, whatever its next_at (recover()). */
  async #receive(
    relay: string,
    cursor: number,
    bytes: Uint8Array,
    receivedAt: number | null,
    now: boolean,
  ): Promise<InboxRow> {
    const { clock, mailbox, store } = this.#o
    // A position is not an identity: a relay restored from an older copy issues used cursors again (spec/SPEC.md §9
    // item 2), so a row here is this frame only when it holds the same envelope; any other is a new row, never dropped.
    let row =
      store.inboxAt(relay, mailbox, cursor).find((r) => sameEnvelope(r.bytes, bytes)) ??
      store.inboxAdd(relay, mailbox, cursor, bytes, receivedAt ?? clock.now())
    const due = now || !isWaiting(row) || (row.nextAt as number) <= clock.now()
    if (!due || this.#busy.has(row.seq)) return row
    this.#busy.add(row.seq)
    try {
      if (row.state === 'received') row = await this.#check(row)
      if (row.state === 'verified') row = await this.#route(row)
    } finally {
      this.#busy.delete(row.seq)
    }
    return row
  }

  /**
   * Finishes this mailbox's rows a crash left received, verified, or routed or queued but not acked, and checks every
   * waiting row at once, whatever its next_at; acks every row that reached an outcome (so an accepted one rings the
   * doorbell and reaches `accepted`, once) and returns those rows as they were before the ack (a row that still waits
   * is not among them, its next try after the backoff of its tries). A waiting row is checked here, not left to its
   * next_at, because a receiver that starts may hold what its last check lacked: a root trusted since (inbox
   * --trust-root, a trust file the person fixed). The relay was acked when the row first arrived and does not send its
   * frame again, so without this check the next read would print nothing until the backoff passed while it ran.
   */
  async recover(): Promise<InboxRow[]> {
    const rows: InboxRow[] = []
    const unfinished = this.#o.store.inboxList(['received', 'verified', 'routed', 'queued'])
    // This receiver's mailbox only: a group's rows in the same store are its member receiver's (CLI inbox --group).
    for (const r of unfinished.filter((u) => u.mailbox === this.#o.mailbox)) {
      const row = await this.#receive(r.relay, r.cursor, r.bytes, null, true)
      if (row.state === 'received' || row.state === 'verified') continue
      rows.push(row)
      this.ack(row)
    }
    return rows
  }

  /**
   * Marks a handled row acked, once its ack is sent, by the row's state in the store, not the caller's copy: a row
   * that waits, is still being handled, is quarantined (acked at the relay, held at the edge) or is acked already
   * stays as it is. A row acked from routed or queued then rings the doorbell and reaches `accepted`: the store moves a
   * row to acked once, and this read and write are synchronous, so each accepted row does so exactly once. The row is
   * acked before the calls, and neither call throws out of ack: each is tried on its own and a throw goes to onError.
   * Throws for a seq the store does not hold.
   */
  ack(row: InboxRow): InboxRow {
    const { accepted, clock, doorbell, onError, store } = this.#o
    const stored = store.inboxGet(row.seq)
    if (stored === null) throw new Error(`inbox: row ${row.seq} is not in the store`)
    if (stored.state !== 'rejected' && stored.state !== 'routed' && stored.state !== 'queued') return stored
    const next = advanceInbox(store, stored, { state: 'acked' }, clock.now())
    if (stored.state === 'rejected') return next
    try {
      doorbell?.()
    } catch (e) {
      onError?.(e)
    }
    try {
      accepted?.(stored)
    } catch (e) {
      onError?.(e)
    }
    return next
  }

  /** The quarantined rows with their holds, in arrival order. */
  quarantined(): { readonly row: InboxRow; readonly hold: Hold }[] {
    return this.#o.store.inboxList(['quarantined']).map((row) => this.#held(row.seq))
  }

  /**
   * Releases a quarantined row: its hold's rule joins the rules its releases waived, and the row is checked again from
   * its exact bytes, routed and acked; another rule may hold it again. Throws for a row that is not quarantined.
   */
  async release(seq: number): Promise<InboxRow> {
    const { clock, store } = this.#o
    const { row, hold } = this.#held(seq)
    const waived = [...hold.waived, hold.rule]
    const back = store.transaction(() => {
      store.holdWaive(seq, waived)
      return advanceInbox(store, row, { state: 'received', reason: null }, clock.now())
    })
    this.#decision(row, hold, 'released', { waived })
    return this.ack(await this.receive(back.relay, back.cursor, back.bytes))
  }

  /** Drops a quarantined row: rejected with policy-refused, then acked, and nothing routed. */
  drop(seq: number): InboxRow {
    const { row, hold } = this.#held(seq)
    const next = advanceInbox(
      this.#o.store,
      row,
      { state: 'rejected', reason: 'policy-refused' },
      this.#o.clock.now(),
    )
    this.#decision(row, hold, 'dropped', {})
    return this.ack(next)
  }

  /** A release or drop: counted by the held rule, and one release line. */
  #decision(
    row: InboxRow,
    hold: Hold,
    outcome: 'released' | 'dropped',
    more: Record<string, AuditValue>,
  ): void {
    this.#o.store.policyCount(hold.rule, outcome)
    const reason = outcome === 'released' ? 'ok' : 'policy-refused'
    const decision = outcome === 'released' ? 'accept' : 'reject'
    const detail = { ...where(row), rule: hold.rule, ...more }
    this.#o.audit.record({ event: 'release', decision, reason, id: row.id, detail })
  }

  #held(seq: number): { readonly row: InboxRow; readonly hold: Hold } {
    const row = this.#o.store.inboxGet(seq)
    const hold = this.#o.store.holdGet(seq)
    if (row?.state !== 'quarantined' || hold === null) throw new Error(`inbox: row ${seq} is not quarantined`)
    return { row, hold }
  }

  /**
   * Subscribes to the mailbox at a relay, from the ack the relay stores, until the signal aborts or the subscription
   * ends without an error (closed by its caller). While subscribed it retries the rows of that relay that wait. When the
   * relay ends the subscription with an error frame, run subscribes again after resubscribeDelay(n), auditing `subscribe
   * retry <code>` (the detail names the relay and the
   * mailbox); three permanent refusals in a row (REFUSALS) end it
   * for good: an audit line `subscribe reject <code>` with `subscription-ended` in its detail, and run rejects with
   * the refusal. A local fault, a failure of the client's own reconnect policy (a RelayError without a code) and a
   * URL the guard refuses reject at once.
   */
  async run(url: string, signal?: AbortSignal): Promise<void> {
    const delay = this.#o.resubscribeDelayMs ?? resubscribeDelay
    let failures = 0
    let refusals = 0
    const delivered = (): void => {
      failures = 0
      refusals = 0
    }
    // A function, not a narrowed property: the signal can abort during any await below.
    const stopped = (): boolean => signal?.aborted === true
    for (;;) {
      if (stopped()) return
      const checked = guardCheck(this.#o.guard, url)
      if (checked !== undefined) await checked
      const failure = await this.#subscribe(url, signal, delivered)
      if (failure === null || stopped()) return
      const code = failure.code as AcErrorCode
      refusals = REFUSALS.has(code) ? refusals + 1 : 0
      if (refusals >= MAX_REFUSALS) {
        this.#o.audit.record({
          event: 'subscribe',
          decision: 'reject',
          reason: code,
          detail: { relay: url, mailbox: this.#o.mailbox, refusals, end: 'subscription-ended' },
        })
        throw failure
      }
      const wait = delay(failures)
      failures++
      this.#o.audit.record({
        event: 'subscribe',
        decision: 'retry',
        reason: code,
        detail: { relay: url, mailbox: this.#o.mailbox, attempt: failures, wait_ms: wait },
      })
      await sleep(wait, signal)
    }
  }

  /**
   * One subscription: each frame handled, then acked, and the waiting rows retried on a timer. Resolves null when the
   * subscription ends without an error, or the relay's error (a RelayError with a code: an error frame, or a frame its
   * stage does not take) to subscribe again on; rejects with anything else.
   */
  async #subscribe(
    url: string,
    signal: AbortSignal | undefined,
    delivered: () => void,
  ): Promise<RelayError | null> {
    const { hops, keys, mailbox, relay } = this.#o
    // Cursor null, never one this edge remembers: after a restore the relay issues rows at or below a remembered cursor,
    // and it frames only rows after the cursor a client resumes from, so those would never come (spec/SPEC.md §9 item 10).
    const sub = relay.subscribe(url, mailbox, keys.signing, hops, null)
    const stop = (): void => sub.close()
    signal?.addEventListener('abort', stop, { once: true })
    const retrier = this.#retrier(url, sub)
    let outcome: RelayError | null = null
    let fault: { readonly error: unknown } | null = null
    try {
      outcome = await this.#frames(url, sub, retrier, delivered)
    } catch (e) {
      fault = { error: e }
    }
    signal?.removeEventListener('abort', stop)
    sub.close()
    const retryFault = await retrier.halt()
    fault ??= retryFault
    if (fault !== null) throw fault.error
    return outcome
  }

  async #frames(
    url: string,
    sub: Subscription,
    retrier: Retrier,
    delivered: () => void,
  ): Promise<RelayError | null> {
    const frames = sub[Symbol.asyncIterator]()
    for (;;) {
      let next: IteratorResult<Frame>
      try {
        next = await frames.next()
      } catch (e) {
        if (e instanceof RelayError && e.code !== null) return e
        throw e
      }
      if (next.done === true) return null
      const frame = next.value
      delivered()
      retrier.seen(frame.cursor)
      const row = await this.receive(url, frame.cursor, frame.envelopeBytes, stampOf(frame))
      sub.ack(frame.cursor)
      this.ack(row)
    }
  }

  #retrier(url: string, sub: Subscription): Retrier {
    let highest = 0
    let pending: Promise<void> | null = null
    let fault: { readonly error: unknown } | null = null
    const tick = (): void => {
      if (pending !== null) return
      pending = this.#retryDue(url, sub, highest)
        .catch((e: unknown) => {
          fault ??= { error: e }
          sub.close()
        })
        .finally(() => {
          pending = null
        })
    }
    const timer = setInterval(tick, this.#o.retryEveryMs ?? 1000)
    timer.unref()
    return {
      seen: (cursor) => {
        highest = Math.max(highest, cursor)
      },
      halt: async () => {
        clearInterval(timer)
        await pending
        return fault
      },
    }
  }

  /**
   * Retries the rows of `url` that wait and are due. A row that reaches an outcome is acked: to the relay as well, when
   * its cursor is at most `highest`, the highest this subscription delivered (the relay refuses an ack past the last
   * cursor it sent; the relay acked it when it first arrived), and in the store in any case, where an accepted row
   * reaches `accepted` (ack) whatever its cursor.
   */
  async #retryDue(url: string, sub: Subscription, highest: number): Promise<void> {
    const { clock, mailbox, store } = this.#o
    for (const due of store.inboxDue(url, mailbox, clock.now())) {
      const row = await this.receive(due.relay, due.cursor, due.bytes)
      if (row.state === 'received') continue
      if (row.cursor <= highest) sub.ack(row.cursor)
      this.ack(row)
    }
  }

  async #check(row: InboxRow): Promise<InboxRow> {
    const { audit, clock, keys, mailbox, policy, store, window } = this.#o
    const now = clock.now()
    const waived = policy.orgKey === null ? [] : (store.holdGet(row.seq)?.waived ?? [])
    const pinned = (host: string): string | null => store.pinGet(`domain:${host}`)?.key ?? null
    let parsed: Envelope | null = null
    try {
      parsed = parseEnvelope(row.bytes)
      verifyOuter(parsed, now, window)
      if (!parsed.to.includes(mailbox)) throw new AcError('not-recipient', 'the mailbox is not in to')
    } catch (e) {
      const code = reasonOf(e, 'bad-shape')
      if (parsed !== null && TRANSIENT_CODES.has(code)) return this.#defer(row, 'verify', code, parsed, null)
      return this.#reject(row, 'verify', code, parsed, null)
    }
    const env: Envelope = parsed
    const line = { id: env.id, from: env.from }
    const receivedAt = { received_at: row.receivedAt }
    audit.record({ ...line, event: 'verify', decision: 'accept', detail: { ...where(row), ...receivedAt } })
    let chain: ChainResult | null = null
    let decision: Decision
    try {
      chain = verifyChain(env.auth, env.from, env.ts)
      const until = receiptBound(env.auth, window.skew)
      if (until !== null && row.receivedAt > until) {
        return this.#reject(row, 'policy', 'hop-expired', env, chain.root, undefined, {
          ...receivedAt,
          until,
        })
      }
      decision = await policy.decide(chain, env.auth, { ts: env.ts, now, waived, pinned })
    } catch (e) {
      // A verdict rejects; a local fault (the store, say) propagates, and the row stays received for recover().
      if (!isAcError(e)) throw e
      const root = chain?.root ?? null
      if (TRANSIENT_CODES.has(e.code)) return this.#defer(row, 'policy', e.code, env, root)
      return this.#reject(row, 'policy', e.code, env, root)
    }
    const root = chain.root
    if (decision.action !== 'pass') return this.#decided(row, 'policy', decision, env, root)
    const released = waived.length === 0 ? {} : { waived }
    audit.record({
      ...line,
      root,
      event: 'policy',
      decision: 'accept',
      detail: { principal: chain.principal, ...released },
    })
    if (store.seenHas(env.id, clock.now())) return this.#reject(row, 'dedup', 'duplicate', env, root)
    audit.record({ ...line, root, event: 'dedup', decision: 'accept' })
    // The seen entry outlives every ts the stale check still accepts: max(first sight, ts) + ttl + skew.
    const seenUntil = Math.max(now, env.ts) + window.ttl + window.skew
    let content: SealedContent
    try {
      // An EnvelopeOpener (the agent's) opens the whole envelope, awaited; any other opens its wrap in this turn.
      content = isEnvelopeOpener(keys.sealing)
        ? await keys.sealing.openEnvelope(row.bytes)
        : openSealed(env, { address: mailbox, key: keys.sealing })
    } catch (e) {
      if (isEnvelopeOpener(keys.sealing) && openRetry(e)) {
        return this.#defer(row, 'unseal', 'open-failed', env, root)
      }
      return this.#reject(row, 'unseal', reasonOf(e, 'open-failed'), env, root, seenUntil)
    }
    audit.record({ ...line, root, event: 'unseal', decision: 'accept' })
    const verdict = policy.caveats(chain.caveats, {
      from: env.from,
      to: env.to,
      ts: env.ts,
      root,
      sealed: content,
    })
    if (!verdict.ok) {
      return this.#reject(row, 'policy', verdict.code, env, root, seenUntil, { caveat: verdict.caveat })
    }
    if (content.type === RECEIPT_TYPE) {
      return this.#receipt(row, env, chain.principal, content.body, root, seenUntil)
    }
    if (!policy.acceptsType(content.type)) {
      return this.#reject(row, 'policy', 'type-not-accepted', env, root, seenUntil, { type: content.type })
    }
    const scoped = policy.scope(chain.caveats, content.type, row.bytes.length)
    if (scoped !== null) return this.#decided(row, 'policy', scoped, env, root, seenUntil)
    const input = { type: content.type, body: content.body, from: env.from, root, caveats: chain.caveats }
    const m = await policy.moderate(input, waived)
    if (m?.ruling) {
      return this.#decided(
        row,
        'moderate',
        m.ruling,
        env,
        root,
        m.ruling.action === 'refuse' ? seenUntil : undefined,
      )
    }
    if (m !== null) {
      if (m.flag) store.policyCount(m.rule, 'allowed')
      const flagged = { ...m.detail, rule: m.rule, flag: m.flag }
      audit.record({ ...line, root, event: 'moderate', decision: 'accept', detail: flagged })
    }
    // The moderation module and the agent's open awaited: a copy of this id through another relay may be accepted.
    if (store.seenHas(env.id, clock.now())) return this.#reject(row, 'dedup', 'duplicate', env, root)
    const next = store.transaction(() => {
      store.seenAdd(env.id, now, seenUntil)
      return advanceInbox(
        store,
        row,
        { state: 'verified', id: env.id, content: JSON.stringify(content), reason: null, nextAt: null },
        now,
      )
    })
    audit.record({ ...line, root, event: 'policy', decision: 'accept', detail: { type: content.type } })
    return next
  }

  async #route(row: InboxRow): Promise<InboxRow> {
    const { audit, clock, router, store } = this.#o
    const env = parseEnvelope(row.bytes)
    const chain = verifyChain(env.auth, env.from, env.ts)
    const content = JSON.parse(row.content as string) as SealedContent
    const message: InboundMessage = {
      id: env.id,
      from: env.from,
      principal: chain.principal,
      root: chain.root,
      to: env.to,
      ts: env.ts,
      type: content.type,
      thread: content.thread,
      body: content.body,
      caveats: chain.caveats,
      relay: row.relay,
    }
    const outcome = await router.route(message)
    const next = advanceInbox(store, row, { state: outcome.state, session: outcome.session }, clock.now())
    audit.record({
      event: 'route',
      decision: outcome.state === 'routed' ? 'route' : 'queue',
      id: env.id,
      from: env.from,
      root: chain.root,
      detail: { ...where(row), session: outcome.session, error: outcome.error },
    })
    return next
  }

  /** A read receipt stops here, kept or refused: whatever its accept list, it reaches no session (receipts.ts). */
  #receipt(
    row: InboxRow,
    env: Envelope,
    principal: string,
    body: unknown,
    root: string,
    seenUntil: number,
  ): InboxRow {
    const { audit, clock, receipts, store } = this.#o
    const detail = { type: RECEIPT_TYPE }
    if (receipts?.take(principal, body) !== true) {
      return this.#reject(row, 'policy', 'type-not-accepted', env, root, seenUntil, detail)
    }
    const now = clock.now()
    const next = store.transaction(() => {
      store.seenAdd(env.id, now, seenUntil)
      return advanceInbox(store, row, { state: 'consumed', id: env.id, reason: null, nextAt: null }, now)
    })
    audit.record({ id: env.id, from: env.from, root, event: 'policy', decision: 'accept', detail })
    return next
  }

  /**
   * A transient rejection (TRANSIENT_CODES): the row stays received, with one more try and a next_at after the
   * outbox's backoff, never past ts + TTL; at or past that horizon the rejection is final. Audited `retry`.
   */
  #defer(
    row: InboxRow,
    event: AuditEvent,
    reason: AcErrorCode,
    env: Envelope,
    root: string | null,
  ): InboxRow {
    const { audit, clock, rng, store, window } = this.#o
    const now = clock.now()
    const horizon = env.ts + window.ttl
    const tries = row.tries + 1
    if (now >= horizon) return this.#reject(row, event, reason, env, root, undefined, { tries }, tries)
    const jitter = jitterOf(rng.bytes(4))
    const nextAt = Math.min(now + retryWait(tries - 1, jitter), horizon)
    const next = advanceInbox(store, row, { state: 'received', reason, id: env.id, tries, nextAt }, now)
    audit.record({
      event,
      decision: 'retry',
      reason,
      id: env.id,
      from: env.from,
      root,
      detail: { ...where(row), tries, next_at: nextAt },
    })
    return next
  }

  /**
   * An org rule's refusal or hold, counted by its rule: a refusal rejects as #reject does; a hold
   * quarantines the row, its content null and its id not marked seen, so that a release passes the dedup check.
   */
  #decided(
    row: InboxRow,
    event: AuditEvent,
    d: Ruling,
    env: Envelope,
    root: string,
    seenUntil?: number,
  ): InboxRow {
    const { audit, clock, policy, store } = this.#o
    // The quarantine is bounded: a hold past its cap is a refusal, so a flood cannot grow the store without end.
    const cap = policy.maxQuarantined
    if (d.action === 'hold' && store.heldCounts().quarantined >= cap) {
      return this.#decided(row, event, verdictFull(d, cap), env, root, seenUntil)
    }
    store.policyCount(d.rule, d.action === 'hold' ? 'quarantined' : 'refused')
    const detail = { ...where(row), ...d.detail, rule: d.rule }
    if (d.action === 'refuse') return this.#reject(row, event, d.code, env, root, seenUntil, detail)
    const now = clock.now()
    const next = store.transaction(() => {
      store.holdPut(row.seq, { rule: d.rule, code: d.code, detail: JSON.stringify(d.detail) }, now)
      return advanceInbox(store, row, { state: 'quarantined', id: env.id, reason: d.code, nextAt: null }, now)
    })
    const held = { ...detail, held: 'quarantined' }
    audit.record({ event, decision: 'queue', reason: d.code, id: env.id, from: env.from, root, detail: held })
    return next
  }

  /** Rejects a row with a code; after the dedup check, the id is marked seen in the same transaction. */
  #reject(
    row: InboxRow,
    event: AuditEvent,
    reason: PolicyCode,
    env: Envelope | null,
    root: string | null,
    seenUntil?: number,
    detail?: Record<string, AuditValue>,
    tries: number = row.tries,
  ): InboxRow {
    const { audit, clock, store } = this.#o
    const now = clock.now()
    const id = env?.id ?? null
    const next = store.transaction(() => {
      if (id !== null && seenUntil !== undefined) store.seenAdd(id, now, seenUntil)
      return advanceInbox(store, row, { state: 'rejected', reason, id, tries, nextAt: null }, now)
    })
    audit.record({
      event,
      decision: 'reject',
      reason,
      id,
      from: env?.from ?? null,
      root,
      detail: { ...where(row), ...detail },
    })
    return next
  }
}
