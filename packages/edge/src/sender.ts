import {
  AcError,
  type AcErrorCode,
  buildEnvelope,
  type Rng as CoreRng,
  DEFAULT_SKEW,
  type Hop,
  isAcError,
  newThread,
  parseEnvelope,
  parseRecord,
  type Thread,
  verifyRecord,
} from '@usebag/core'
import { type Audit, reasonOf } from './audit.ts'
import { guardRefusal, type Refusal, type RelayGuard, relayKey } from './net.ts'
import {
  jitterOf,
  resendTarget,
  retryWait,
  sealedTarget,
  startTry,
  tryFailed,
  tryPublished,
  tryRetired,
  UNREACHABLE,
} from './outbox.ts'
import {
  type Clock,
  type EdgeStore,
  type OutboxTarget,
  type PublishResult,
  type RecordSource,
  type RelayClient,
  RelayError,
  type Rng,
  type SessionKeys,
  type WaitingRow,
} from './ports.ts'
import { askingReceipt } from './receipts.ts'
import { ResolveFailed, type Resolver, recorded } from './resolver.ts'
import type { Router } from './router.ts'

// The sender (spec/SPEC.md §9.1, §9.7): resolve every recipient, build one envelope with the core, persist its exact
// bytes, then publish those bytes to the first K = 3 of each recipient's listed relays (§4.3, 'relays N'), each target
// through the outbox state machine, which retries until the relay TTL has passed since the envelope's ts. A target
// refused for good, or unreachable for RETIRE_TRIES tries, is retired when each recipient that counted it has a later
// listed relay, which is counted in its place: at most K live targets per recipient. A relay URL the guard refuses (a
// private address that is not one of the edge's own relays) fails its target at once, before any request. A try
// that got no answer from its relay is `unreachable` in its target's reason and its audit line's unless the edge turns
// that off, and the line names that cause in its detail either way. An audit line records a relay URL that
// carries a user name or password as its scheme and host only; the outbox row keeps the URL, which is the
// target's key.
//
// Leaving records: before an envelope's first try at a relay, the sender makes sure that relay holds a
// current address record of the edge's mailbox, so that a reply resolves there. It republishes, as they are, the
// bytes the edge's own relays serve (it signs nothing), and only the address record: an accept-from record is its
// owner's to publish at its own relays. No outcome of that publish fails the envelope. Waiting
// sendOrWait keeps a send whose recipient does not resolve in the store, plaintext, since it cannot be sealed
// yet, and flush tries it again, after a restart too, to the same `until` (last mile, ruling 1 (b)). Its row leaves in the
// transaction that adds its envelope to the outbox, so a crash leaves it in one of the two: it goes out once, under one id.
// A recipient may be a handle (spec/SPEC.md §12.4): Resolver.recipient binds it to its address, checked
// against its org's revoked list, and reads that address's records at the org record's relays first.

/** A message to send. Without `thread` it opens a new thread; `session` binds the thread to the sending session. */
export interface SendInput {
  /** Each an address, or a handle (spec/SPEC.md §12.4), which the resolver binds to its address at every send. */
  readonly to: readonly string[]
  readonly type: string
  readonly body: unknown
  readonly thread?: Thread
  readonly session?: string
  /** Relays to look the recipients' records up at, before the edge's own. */
  readonly relays?: readonly string[]
  /** Asks the recipients for a read receipt (receipts.ts), which each may ignore: `body` must be a JSON object. */
  readonly receipt?: boolean
}

export interface SendResult {
  readonly id: string
  readonly thread: Thread
  readonly targets: readonly OutboxTarget[]
}

export interface SenderOptions {
  readonly keys: SessionKeys
  readonly auth: readonly Hop[]
  readonly store: EdgeStore
  readonly relay: RelayClient
  readonly resolver: Resolver
  readonly router: Router
  readonly audit: Audit
  readonly clock: Clock
  readonly rng: Rng
  /** The relay TTL, in seconds: a target is retried until the envelope's ts + ttl. */
  readonly ttl: number
  /** The private-address guard; without one, every relay URL is called. */
  readonly guard?: RelayGuard
  /**
   * Gives a try that got no answer from its relay the reason `unreachable`, in place of `publish-failed` (Appendix A): on by default; false keeps `publish-failed`, as the Edge's option of the same name.
   */
  readonly unreachableReason?: boolean
  /** The address replies come to (a session edge's principal); by default the signing key's. */
  readonly mailbox?: string
  /** The edge's own relays, where the mailbox's own records are read to be left at other relays. */
  readonly relays?: readonly string[]
  /** Where records are read; without it, or without `relays`, no record is left. */
  readonly records?: RecordSource
  /** Leaves the mailbox's address record (never its accept-from) at a relay that holds none: default on. */
  readonly leaveRecords?: boolean
}

/**
 * A send kept waiting because a recipient did not resolve (sendOrWait): tried again at `nextAt` by flush, with the
 * outbox's backoff, until `until` (its creation + the relay TTL), then dropped. The store keeps it, so it outlives a
 * restart but never `until`; `held` names only the store's quarantine.
 */
export interface WaitingSend {
  readonly waiting: true
  readonly key: string
  /** The thread the message opens or answers: wait on it for the answer. */
  readonly thread: Thread
  readonly to: readonly string[]
  /** The relays the last resolution asked, recorded (a user name or password left out). */
  readonly tried: readonly string[]
  /** The last resolve-failed's detail. */
  readonly reason: string
  /** A relay asked gave no answer: it refused the connection or could not be reached, so the record may well be there. */
  readonly unanswered: boolean
  readonly tries: number
  readonly nextAt: number
  readonly until: number
}

/** A current address record of the mailbox, as a relay serves it: its bytes, iat and last valid second. */
interface Found {
  readonly bytes: Uint8Array
  readonly iat: number
  readonly validUntil: number
}

/** How long a relay is not asked again when the edge's own relays hold no record to leave there. */
const NOTHING_TO_LEAVE_SECONDS = 60

/** The core's rng shape, a function, over the edge's Rng port. */
export function coreRng(rng: Rng): CoreRng {
  return (length) => rng.bytes(length)
}

/** How many sends may wait at once; past it, sendOrWait throws resolve-failed as send does. As the gate's maxHeld. */
export const MAX_WAITING = 256

/** A row's WaitingSend: its key is its seq's, so it holds across restarts. */
function viewOf(row: WaitingRow): WaitingSend {
  const view = JSON.parse(row.view) as WaitingSend
  return { ...view, unanswered: view.unanswered === true, key: `waiting-${row.seq}` }
}

/** How many of a recipient's listed relays an envelope is published to at once (spec/SPEC.md §4.3). */
export const K = 3
/** Tries with no answer after which a target is given up for the next listed relay (§4.3: a few tries, never the TTL). */
export const RETIRE_TRIES = 3

/** One recipient's share of an envelope (§4.3): its listed relays, those it counts now, and the next one to promote. */
type Share = { readonly list: readonly string[]; readonly counted: Set<string>; next: number }

/** The shares as the outbox row keeps them. */
function planOf(shares: readonly Share[]): string {
  return JSON.stringify(shares.map((s) => ({ ...s, counted: [...s.counted] })))
}

/** True for a refusal that the same bytes will meet again: a 4xx other than 408 and 429. */
function isPermanent(status: number): boolean {
  return status >= 400 && status < 500 && status !== 408 && status !== 429
}

export class Sender {
  readonly #o: SenderOptions
  readonly #root: string
  readonly #inflight = new Set<string>()
  /** Each envelope's shares while a target of it is live, this Edge's own (never pooled per process). The outbox row
   * keeps them, so a later process can promote; a row from before plans has none, and its targets retry to the horizon. */
  readonly #plans = new Map<string, Share[]>()
  /** Relays that need no record left before `until`: they hold one, the own relays hold none, or a try failed. */
  readonly #left = new Map<string, { until: number; tries: number }>()
  /** Record leaving in progress, by relay: a burst of sends to one relay leaves the record once. */
  readonly #leaving = new Map<string, Promise<void>>()
  /** The mailbox's own address record, read once and kept until its valid_until (or 60 s when there is none). */
  #own: { until: number; readonly value: Promise<Found | null> } | null = null
  readonly #mailbox: string
  /** Waiting rows a flush is trying now. */
  readonly #trying = new Set<number>()

  constructor(options: SenderOptions) {
    this.#o = options
    this.#root = options.auth[0]?.iss ?? options.keys.signing.address
    this.#mailbox = options.mailbox ?? options.keys.signing.address
  }

  /** Resolves, builds, persists and publishes; resolve-failed when a recipient has no sealing key or no relay. */
  send(input: SendInput): Promise<SendResult> {
    return this.#send(input)
  }

  /** send, for the waiting row `waiting` when it comes from one: the row leaves as the envelope enters the outbox. */
  async #send(input: SendInput, waiting?: number): Promise<SendResult> {
    const { clock, keys, store } = this.#o
    // First, so that a body that cannot ask is refused at once, never kept waiting for a recipient.
    const body = input.receipt === true ? askingReceipt(input.body) : input.body
    const recipients = []
    for (const address of input.to) {
      recipients.push(await this.#o.resolver.recipient(address, input.relays))
    }
    const shares = recipients.map((r) => {
      const list = [...new Set(r.relays)]
      return { list, counted: new Set(list.slice(0, K)), next: Math.min(K, list.length) }
    })
    const relays = [...new Set(shares.flatMap((s) => [...s.counted]))]
    if (relays.length === 0) throw new AcError('resolve-failed', 'no relay to publish to')
    const thread = input.thread ?? newThread(coreRng(this.#o.rng))
    const now = clock.now()
    const { envelope, bytes } = buildEnvelope({
      from: keys.signing,
      to: recipients.map((r) => ({ address: r.address, sealingKey: r.sealingKey })),
      auth: this.#o.auth,
      type: input.type,
      thread,
      body,
      ts: now,
      rng: coreRng(this.#o.rng),
    })
    const entry = {
      id: envelope.id,
      bytes,
      thread: thread.id,
      session: input.session ?? null,
      createdAt: now,
    }
    // Bound first: a crash just after the outbox write must not lose the thread's session. A later retry binds it again.
    if (input.session !== undefined) this.#o.router.bind(thread.id, input.session)
    store.outboxAdd(
      entry,
      relays.map((url) => sealedTarget(envelope.id, url, now)),
      { waiting, plan: planOf(shares) },
    )
    this.#plans.set(envelope.id, shares)
    await Promise.all(store.outboxTargets(envelope.id).map((t) => this.#try(t, bytes)))
    // A retired target was replaced by the relay promoted for it, which the result names instead.
    return {
      id: envelope.id,
      thread,
      targets: store.outboxTargets(envelope.id).filter((t) => t.state !== 'retired'),
    }
  }

  /**
   * Sends as `send` does, but a send whose recipient does not resolve (resolve-failed) is kept waiting in the store and
   * returned as a WaitingSend, with its thread (generated here when absent, so the caller can wait on it); flush tries it again.
   * Any other failure throws as from `send`, and so does resolve-failed while MAX_WAITING sends wait already.
   */
  async sendOrWait(input: SendInput): Promise<SendResult | WaitingSend> {
    const full = { ...input, thread: input.thread ?? newThread(coreRng(this.#o.rng)) }
    const { clock, store } = this.#o
    const createdAt = clock.now()
    try {
      return await this.send(full)
    } catch (e) {
      if (!isAcError(e, 'resolve-failed') || store.waitingList().length >= MAX_WAITING) throw e
      const view: WaitingSend = {
        waiting: true,
        key: '',
        thread: full.thread,
        to: [...full.to],
        tried: [],
        reason: '',
        unanswered: false,
        tries: 0,
        nextAt: createdAt,
        until: createdAt + this.#o.ttl,
      }
      const row = { input: JSON.stringify(full), view: JSON.stringify(view), nextAt: createdAt }
      const seq = store.waitingAdd(row.input, row.view, row.nextAt)
      return this.#again({ ...row, seq }, e, 'queue')
    }
  }

  /** The sends waiting because a recipient did not resolve, oldest first. */
  waiting(): readonly WaitingSend[] {
    return this.#o.store.waitingList().map(viewOf)
  }

  /**
   * Publishes every due target: sealed, retry whose time has come, and publishing left by a crash; and tries each waiting
   * send whose time has come once, returning the targets of those that went out.
   */
  async flush(): Promise<OutboxTarget[]> {
    const now = this.#o.clock.now()
    const due = this.#o.store.outboxDue(now).filter((d) => !this.#inflight.has(key(d.target)))
    const waiting = this.#o.store.waitingList(now).filter((r) => !this.#trying.has(r.seq))
    const [targets, sent] = await Promise.all([
      Promise.all(due.map((d) => this.#try(d.target, d.bytes))),
      Promise.all(waiting.map((r) => this.#retry(r))),
    ])
    return [...targets, ...sent.flat()]
  }

  /**
   * One try of a waiting send: sent, it leaves the list; resolve-failed again, it waits or, at `until`, is dropped. One
   * found past `until`, after a restart say, is dropped with no try: a restart never lengthens the retry horizon.
   */
  async #retry(r: WaitingRow): Promise<readonly OutboxTarget[]> {
    this.#trying.add(r.seq)
    try {
      if (this.#o.clock.now() > viewOf(r).until) throw new AcError('resolve-failed', 'past its until')
      return (await this.#send(JSON.parse(r.input) as SendInput, r.seq)).targets
    } catch (e) {
      this.#again(r, e, 'retry')
      return []
    } finally {
      this.#trying.delete(r.seq)
    }
  }

  /**
   * Counts a failed resolution of a waiting send, audited: it waits retryWait(tries - 1) (never past `until`), or is
   * dropped at `until`, or at once on any failure other than resolve-failed (a pin-mismatch, say), with that code.
   */
  #again(r: WaitingRow, e: unknown, decision: 'queue' | 'retry'): WaitingSend {
    const { store } = this.#o
    const now = this.#o.clock.now()
    const v = viewOf(r)
    const tries = v.tries + 1
    const code = reasonOf(e, 'publish-failed')
    const gone = code !== 'resolve-failed' || now >= v.until
    const view = {
      ...v,
      tries,
      nextAt: Math.min(now + retryWait(tries - 1, jitterOf(this.#o.rng.bytes(4))), v.until),
      tried: e instanceof ResolveFailed ? e.tried.map((t) => t.relay) : [],
      reason: e instanceof Error ? e.message.replace(/^resolve-failed: /, '') : String(e),
      unanswered: e instanceof ResolveFailed && e.tried.some((t) => t.outcome === UNREACHABLE),
    }
    if (gone) store.waitingDelete(r.seq)
    else store.waitingPut(r.seq, JSON.stringify(view), view.nextAt)
    this.#o.audit.record({
      event: 'publish',
      decision: gone ? 'reject' : decision,
      reason: code,
      from: this.#o.keys.signing.address,
      root: this.#root,
      detail: {
        waiting: v.key,
        thread: v.thread.id,
        to: v.to,
        tried: view.tried,
        tries,
        next_at: gone ? null : view.nextAt,
        until: v.until,
      },
    })
    return view
  }

  /**
   * Seals a failed envelope's failed targets again and publishes the same bytes. A try of a resent target that fails
   * after the horizon (ts + TTL) fails it again at once, since the relay would refuse the envelope as stale soon after.
   * A retired target (§4.3) is not resent: a later listed relay took its place, so the K live bound holds here too.
   */
  async resend(id: string): Promise<OutboxTarget[]> {
    const { clock, store } = this.#o
    const entry = store.outboxGet(id)
    if (entry === null) throw new Error(`outbox: no envelope ${id}`)
    const failed = store.outboxTargets(id).filter((t) => t.state === 'failed')
    return Promise.all(
      failed.map((t) => {
        const sealed = resendTarget(t, clock.now())
        store.outboxPut(sealed)
        return this.#try(sealed, entry.bytes)
      }),
    )
  }

  async #try(target: OutboxTarget, bytes: Uint8Array): Promise<OutboxTarget> {
    const { audit, clock, relay, store } = this.#o
    const k = key(target)
    this.#inflight.add(k)
    let t = startTry(target, clock.now())
    store.outboxPut(t)
    // Only the guard and the relay call are inside the try: a fault in the bookkeeping after it is not a failed publish.
    let outcome: PublishResult | RelayError | Refusal
    try {
      const refusal = guardRefusal(this.#o.guard, t.relay)
      const refused = refusal instanceof Promise ? await refusal : refusal
      // The mailbox's records go first, to a relay the guard allows; no outcome of theirs fails the envelope.
      const leaving = refused === null ? this.#leave(t.relay) : undefined
      if (leaving !== undefined) await leaving
      outcome = refused ?? (await relay.publish(t.relay, bytes))
    } catch (e) {
      outcome = e instanceof RelayError ? e : new RelayError(null, 0, null, String(e))
    } finally {
      this.#inflight.delete(k)
    }
    const line = { id: t.id, from: this.#o.keys.signing.address, root: this.#root }
    if ('range' in outcome) {
      const refused = {
        reason: 'resolve-failed',
        permanent: true,
        retryAfter: null,
        horizon: 0,
        jitter: 0,
      } as const
      t = tryFailed(t, clock.now(), refused)
      audit.record({
        ...line,
        event: 'publish',
        decision: 'reject',
        reason: 'resolve-failed',
        detail: { relay: recorded(t.relay), tries: t.tries, refused: outcome.range },
      })
    } else if (outcome instanceof RelayError) {
      const code: AcErrorCode = outcome.code ?? 'publish-failed'
      // No code and no HTTP status: the relay never answered (refused, timed out), or the client threw.
      const unreachable = outcome.code === null && outcome.status === 0
      const permanent = isPermanent(outcome.status)
      const reason = unreachable && this.#o.unreachableReason !== false ? UNREACHABLE : code
      const horizon = parseEnvelope(bytes).ts + this.#o.ttl
      const givenUp = permanent || (unreachable && t.tries + 1 >= RETIRE_TRIES)
      t =
        givenUp && clock.now() < horizon && this.#spare(t.id, t.relay)
          ? tryRetired(t, clock.now(), reason)
          : tryFailed(t, clock.now(), {
              reason,
              permanent,
              retryAfter: outcome.retryAfter,
              horizon,
              jitter: jitterOf(this.#o.rng.bytes(4)),
            })
      audit.record({
        ...line,
        event: outcome.status === 429 ? 'rate-limit' : 'publish',
        decision: t.state === 'retry' ? 'retry' : 'reject',
        // The line's reason is the target's: `unreachable` for a try with no answer while the option is on (Appendix A;
        // §9 item 8), its code otherwise; the give-up at the horizon stays publish-failed.
        reason: t.state !== 'failed' || permanent ? reason : 'publish-failed',
        detail: {
          relay: recorded(t.relay),
          tries: t.tries,
          status: outcome.status,
          next_at: t.nextAt,
          ...(t.state === 'retired' ? { retired: true } : {}),
          ...(unreachable ? { cause: UNREACHABLE } : {}),
        },
      })
    } else {
      t = tryPublished(t, clock.now())
      audit.record({
        ...line,
        event: 'publish',
        decision: 'accept',
        detail: {
          relay: recorded(t.relay),
          tries: t.tries,
          duplicate: outcome.duplicate,
          delivered: outcome.delivered,
        },
      })
    }
    // One transaction: a crash between the two would leave a retired target and no relay promoted in its place.
    const promoted = store.transaction(() => {
      store.outboxPut(t)
      return t.state === 'retired' ? this.#promote(t.id, t.relay) : []
    })
    await Promise.all(promoted.map((p) => this.#try(p, bytes)))
    const live: readonly string[] = ['sealed', 'publishing', 'retry']
    if (this.#plans.has(t.id) && !store.outboxTargets(t.id).some((x) => live.includes(x.state)))
      this.#plans.delete(t.id)
    return t
  }

  /** Whether each recipient that counts `relay` for envelope `id` has a later listed relay it does not count yet. */
  #spare(id: string, relay: string): boolean {
    const spare = (s: Share): boolean =>
      !s.counted.has(relay) || s.list.slice(s.next).some((u) => !s.counted.has(u))
    return this.#plan(id)?.every(spare) === true
  }

  /** The shares of envelope `id`: this Edge's, or those its outbox row keeps, as a restart finds them. */
  #plan(id: string): Share[] | undefined {
    const live = this.#plans.get(id)
    if (live !== undefined) return live
    const kept = this.#o.store.outboxPlan(id)
    if (kept === null) return undefined
    const shares = (JSON.parse(kept) as (Omit<Share, 'counted'> & { counted: string[] })[]).map((s) => ({
      ...s,
      counted: new Set(s.counted),
    }))
    this.#plans.set(id, shares)
    return shares
  }

  /**
   * Retires `relay` from each share of envelope `id` that counts it and counts the share's next listed relay that is not
   * given up: one already a live target counts without a new publish; a new one is added sealed and returned, to try.
   */
  #promote(id: string, relay: string): OutboxTarget[] {
    const { clock, store } = this.#o
    const held = new Map(store.outboxTargets(id).map((x) => [x.relay, x.state]))
    const fresh: OutboxTarget[] = []
    const shares = this.#plan(id) ?? []
    // Out of memory until the write commits: a rollback must leave the row's plan the one that is read next.
    this.#plans.delete(id)
    for (const s of shares) {
      if (!s.counted.delete(relay)) continue
      while (s.next < s.list.length) {
        const url = s.list[s.next++] as string
        const state = held.get(url)
        if (s.counted.has(url) || state === 'failed' || state === 'retired') continue
        s.counted.add(url)
        if (state === undefined) {
          const promoted = sealedTarget(id, url, clock.now())
          store.outboxAddTarget(promoted)
          held.set(url, 'sealed')
          fresh.push(promoted)
        }
        break
      }
    }
    store.outboxPlanPut(id, planOf(shares))
    this.#plans.set(id, shares)
    return fresh
  }

  /**
   * Makes sure `url` holds a current address record of the mailbox, memoized per relay until the record's
   * valid_until; a no-op when leaving is off, or while the relay's memo is current.
   */
  #leave(url: string): Promise<void> | undefined {
    const { leaveRecords, records, relays } = this.#o
    if (leaveRecords === false || records === undefined || relays === undefined) return undefined
    const k = relayKey(url)
    const memo = this.#left.get(k)
    if (memo !== undefined && this.#o.clock.now() < memo.until) return undefined
    const running =
      this.#leaving.get(k) ??
      this.#leaveAt(url, k, records, memo?.tries ?? 0).finally(() => this.#leaving.delete(k))
    this.#leaving.set(k, running)
    return running
  }

  async #leaveAt(url: string, k: string, records: RecordSource, tries: number): Promise<void> {
    // 1. The relay holds a current address record of the mailbox: nothing to leave until it expires.
    const there = await this.#read(records, url)
    // 2. Else the newest one the edge's own relays serve; none, and there is nothing to leave for 60 s.
    const own = there ?? (await this.#ownRecord(records))
    let wait = 0
    if (there === null && own !== null) {
      // 3. Its bytes as they are: stored, or 409 stale-record (it holds a newer one), the relay holds it; else wait.
      let status = 200
      let reason: AcErrorCode | 'ok' = 'ok'
      try {
        await this.#o.relay.publish(url, own.bytes)
      } catch (e) {
        const err = e instanceof RelayError ? e : new RelayError(null, 0, null, String(e))
        status = err.status
        reason =
          err.code ?? (status === 0 && this.#o.unreachableReason !== false ? UNREACHABLE : 'publish-failed')
        if (status !== 409)
          wait = Math.max(retryWait(tries, jitterOf(this.#o.rng.bytes(4))), err.retryAfter ?? 0)
      }
      this.#o.audit.record({
        event: 'publish',
        decision: reason === 'ok' ? 'accept' : 'reject',
        reason,
        from: this.#o.keys.signing.address,
        root: this.#root,
        detail: { record: 'address', relay: recorded(url), signer: this.#mailbox, iat: own.iat, status },
      })
    }
    const now = this.#o.clock.now()
    const holds = { until: own?.validUntil ?? now + NOTHING_TO_LEAVE_SECONDS, tries: 0 }
    this.#left.set(k, wait > 0 ? { until: now + wait, tries: tries + 1 } : holds)
  }

  /** The mailbox's address record at `url` when it verifies and is current; null for none or any failure. */
  async #read(records: RecordSource, url: string): Promise<Found | null> {
    try {
      const bytes = await records.relayRecord(url, this.#mailbox, 'address')
      if (bytes === null) return null
      const r = verifyRecord(parseRecord(bytes), this.#o.clock.now(), DEFAULT_SKEW)
      return r.kind === 'address' && r.key === this.#mailbox
        ? { bytes, iat: r.iat, validUntil: r.iat + r.ttl }
        : null
    } catch {
      return null
    }
  }

  /**
   * The newest address record of the mailbox that the edge's own relays serve, one GET per own relay, kept until its
   * valid_until (60 s when there is none); each own relay that serves a current one is memoized as holding it.
   */
  #ownRecord(records: RecordSource): Promise<Found | null> {
    const memo = this.#own
    if (memo !== null && this.#o.clock.now() < memo.until) return memo.value
    const own = this.#o.relays as readonly string[]
    const entry = {
      until: Number.POSITIVE_INFINITY,
      value: Promise.all(own.map((url) => this.#read(records, url))).then((found) => {
        let newest: Found | null = null
        for (const [i, f] of found.entries()) {
          if (f === null) continue
          this.#left.set(relayKey(own[i] as string), { until: f.validUntil, tries: 0 })
          if (newest === null || f.iat > newest.iat) newest = f
        }
        entry.until = newest?.validUntil ?? this.#o.clock.now() + NOTHING_TO_LEAVE_SECONDS
        return newest
      }),
    }
    this.#own = entry
    return entry.value
  }
}

function key(t: OutboxTarget): string {
  return `${t.id} ${t.relay}`
}
