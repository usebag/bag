import {
  isHandle,
  type MembersRecord,
  type PolicyCode,
  type PolicyRecord,
  parseEnvelope,
  parseHandle,
  type SealedContent,
  typeMatches,
} from '@usebag/core'
import type { AuditValue } from '../audit.ts'
import type { Edge } from '../edge.ts'
import type { Clock, EdgeStore, HeldSend, Rng } from '../ports.ts'
import type { SendInput, SendResult, WaitingSend } from '../sender.ts'
import { normalize, stringsOf } from './modules.ts'

// The outbound gate, decided before a send is resolved, sealed or persisted: the members record's
// deny list (a domain by its current or pinned key), a recipient org's served `*` scopes through a hook, and two
// breakers that hold a worm-shaped send pending approval, a person releasing it (sealed then, with a fresh ts) or
// dropping it: an echo of a recent message to someone who neither sent nor received it, and a fan-out to many new
// recipients. The held sends are capped. Every refusal, hold, release and drop is one audit line. A handle in `to` is
// resolved to its address before anything is judged (its domain first, before any lookup), so the deny list, the
// breakers and a held send see addresses. The Edge composes one Gate when its policy holds a members record
// and sends through it: a Gate composed over such an Edge judges each send twice.

/** The breakers' bounds (default 12), each settable. */
export const DEFAULT_BREAKERS = {
  echoSeconds: 600,
  echoMinChars: 32,
  fanoutSends: 20,
  fanoutRecipients: 10,
  fanoutSeconds: 300,
} as const
export type Breakers = { readonly [K in keyof typeof DEFAULT_BREAKERS]: number }
/** Sends the fan-out breaker passes, still logged: a group admin's key distribution ("exempt"). */
export const FANOUT_EXEMPT = new WeakSet<SendInput>()
type Trip = { readonly rule: string; readonly detail: Record<string, AuditValue> } | null

export interface GateOptions {
  /** Sends through the edge: Edge.send, its audit and its resolver (for a deny list's domains). */
  readonly edge: Pick<Edge, 'send' | 'audit' | 'resolver'>
  readonly store: EdgeStore
  readonly clock: Clock
  readonly rng: Rng
  /** The org's members record (its outbound deny list); without one, only the breakers apply. */
  readonly members?: MembersRecord
  /** The most sends pending approval at once (default 256): a hold past it is refused, rule held.full. */
  readonly maxHeld?: number
  /** The breakers' bounds, or false for none. */
  readonly breakers?: Breakers | false
  /** A recipient's domain when the caller knows it (a handle), for the deny list. */
  readonly domainOf?: (address: string) => string | null
  /** A recipient org's served policy record, verified, when the caller can read it (the resolver). */
  readonly recipientPolicy?: (address: string) => Promise<PolicyRecord | null>
}

/** A send the policy refused, before anything was sealed: the code and the rule. */
export class PolicyRefusal extends Error {
  readonly code: PolicyCode
  readonly rule: string

  constructor(code: PolicyCode, rule: string, detail: string) {
    super(`${code}: ${rule}: ${detail}`)
    this.name = 'PolicyRefusal'
    this.code = code
    this.rule = rule
  }
}

/** A send the gate holds pending a person, as the Edge answers it: nothing was sealed or sent. */
export type Held = HeldSend & { readonly held: true }

/** Edge.send's and Edge.reply's refusal of a send the Edge's gate holds (Edge.sendOrWait returns it): `held` names it. */
export class SendHeld extends Error {
  readonly held: Held

  constructor(held: Held) {
    super(`held ${held.id} ${held.rule}: nothing was sealed or sent; a person releases or drops it`)
    this.name = 'SendHeld'
    this.held = held
  }
}

/** What a send through the gate came to: sent (or, through Sender.sendOrWait, waiting), or held pending approval. */
export type GateResult<R = SendResult> =
  | { readonly sent: R; readonly held: null }
  | { readonly sent: null; readonly held: HeldSend }

/** How a passed send goes out: the edge's send by default; the Edge's own gate passes its Sender's. */
type Via<R> = (input: SendInput) => Promise<R>

/** The policy's counts by rule and outcome, the rows quarantined now and the sends pending approval. */
export function policyStatus(store: EdgeStore) {
  return { ...store.heldCounts(), counts: store.policyCounts() }
}

export class Gate {
  readonly #o: GateOptions
  readonly #b: Breakers | null

  constructor(options: GateOptions) {
    this.#o = options
    this.#b = options.breakers === false ? null : (options.breakers ?? DEFAULT_BREAKERS)
  }

  /**
   * Sends through `via`, unless the policy refuses (PolicyRefusal, nothing sealed) or a breaker holds it pending
   * approval; a WaitingSend that `via` returns is not counted as a send.
   */
  async send<R extends SendResult | WaitingSend = SendResult>(
    given: SendInput,
    via?: Via<R>,
  ): Promise<GateResult<R>> {
    const input = await this.#outbound(given)
    const now = this.#o.clock.now()
    const hold =
      this.#b === null ? null : (this.#echo(input, now, this.#b) ?? this.#fanout(input, now, this.#b))
    if (hold === null) return { sent: await this.#pass(input, via), held: null }
    const cap = this.#o.maxHeld ?? 256
    if (this.#o.store.heldCounts().pending >= cap)
      this.#refuse('policy-refused', 'held.full', input.to.join(' '))
    const id = Buffer.from(this.#o.rng.bytes(16)).toString('hex')
    const held: HeldSend = {
      id,
      input: JSON.stringify(input),
      rule: hold.rule,
      detail: JSON.stringify(hold.detail),
      state: 'pending-approval',
      heldAt: now,
      decidedAt: null,
    }
    this.#o.store.heldSendPut(held)
    this.#record('policy', 'queue', 'policy-refused', hold.rule, { ...hold.detail, held: id }, 'held')
    return { sent: null, held }
  }

  /** The sends pending approval, oldest first. */
  held(): HeldSend[] {
    return this.#o.store.heldSendList('pending-approval')
  }

  /** Releases a held send: the deny list is checked again, then it is sealed and sent with a fresh ts. */
  async release(id: string): Promise<SendResult> {
    const held = this.#pending(id)
    const input = JSON.parse(held.input) as SendInput
    await this.#outbound(input)
    this.#decide(held, 'released')
    this.#record('release', 'accept', 'ok', held.rule, { held: id }, 'released')
    return this.#pass<SendResult>(input)
  }

  /** Drops a held send: nothing is sealed or sent. */
  drop(id: string): HeldSend {
    const dropped = this.#decide(this.#pending(id), 'dropped')
    this.#record('release', 'reject', 'policy-refused', dropped.rule, { held: id }, 'dropped')
    return dropped
  }

  #pending(id: string): HeldSend {
    const held = this.#o.store.heldSendGet(id)
    if (held?.state !== 'pending-approval') throw new Error(`gate: send ${id} is not pending approval`)
    return held
  }

  #decide(held: HeldSend, state: 'released' | 'dropped'): HeldSend {
    const next = { ...held, state, decidedAt: this.#o.clock.now() }
    this.#o.store.heldSendPut(next)
    return next
  }

  async #pass<R extends SendResult | WaitingSend>(input: SendInput, via?: Via<R>): Promise<R> {
    const sent = via === undefined ? ((await this.#o.edge.send(input)) as R) : await via(input)
    if ('waiting' in sent) return sent
    this.#o.store.sendLog(sent.id, input.to, this.#o.clock.now())
    return sent
  }

  #record(
    event: 'policy' | 'release',
    decision: 'queue' | 'accept' | 'reject',
    reason: PolicyCode | 'ok',
    rule: string,
    detail: Record<string, AuditValue>,
    outcome: string,
  ): void {
    this.#o.store.policyCount(rule, outcome)
    this.#o.edge.audit.record({ event, decision, reason, detail: { ...detail, rule } })
  }

  /**
   * The deny list, then the recipient org's `*` scopes, for every recipient: a refusal throws before anything is sealed,
   * its line naming the handle beside the address. A handle's domain is judged before any lookup, then the address its
   * binding names; the input comes back with addresses, the bindings' relays first among its hints.
   */
  async #outbound(input: SendInput): Promise<SendInput> {
    const deny = this.#o.members?.outbound?.deny ?? []
    const [all, relays]: [string[], string[]] = [[], []]
    for (const given of input.to) {
      const named: { handle?: string } = isHandle(given) ? { handle: given } : {}
      const at = named.handle === undefined ? -1 : deny.indexOf(`domain:${parseHandle(given).domain}`)
      if (at >= 0) this.#refuse('policy-refused', `outbound.deny[${at}]`, given, named)
      const b = named.handle === undefined ? null : await this.#o.edge.resolver.handle(given)
      const to = b?.address ?? given
      all.push(to)
      relays.push(...(b?.relays ?? []))
      for (const [i, entry] of deny.entries()) {
        if (await this.#denies(entry, to)) this.#refuse('policy-refused', `outbound.deny[${i}]`, to, named)
      }
      const theirs = (await this.#o.recipientPolicy?.(to)) ?? null
      for (const [i, s] of (theirs?.scopes ?? []).entries()) {
        if (s.match === '*' && !s.accept_types.some((p) => typeMatches(p, input.type))) {
          this.#refuse('type-not-accepted', `recipient.scopes[${i}].accept_types`, to, named)
        }
      }
    }
    const resolved = { ...input, to: all, relays: [...relays, ...(input.relays ?? [])] }
    return input.to.some((t) => isHandle(t)) ? resolved : input
  }

  #refuse(code: PolicyCode, rule: string, to: string, named: { handle?: string } = {}): never {
    this.#record('policy', 'reject', code, rule, { to, ...named }, 'refused')
    throw new PolicyRefusal(code, rule, `the send to ${to} is refused before it is sealed`)
  }

  async #denies(entry: string, to: string): Promise<boolean> {
    if (entry === to) return true
    if (!entry.startsWith('domain:')) return false
    const host = entry.slice('domain:'.length)
    if (this.#o.domainOf?.(to) === host || this.#o.store.pinGet(`domain:${host}`)?.key === to) return true
    try {
      return (await this.#o.edge.resolver.domain(host)).key === to
    } catch {
      return false
    }
  }

  /**
   * A send that repeats a recent message's text to someone who did not have it: not its sender, its principal or any
   * of its recipients, so a reply-all passes.
   */
  #echo(input: SendInput, now: number, b: Breakers): Trip {
    const sent = stringsOf(input.body).map(normalize)
    for (const row of this.#o.store.inboxContentSince(now - b.echoSeconds)) {
      const env = parseEnvelope(row.bytes)
      const principal = env.auth.at(-1)?.iss ?? env.from
      const others = input.to.filter((a) => a !== env.from && a !== principal && !env.to.includes(a))
      const body = (JSON.parse(row.content as string) as SealedContent).body
      const quoted = stringsOf(body)
        .map(normalize)
        .filter((t) => t.length >= b.echoMinChars)
      if (others.length > 0 && quoted.some((q) => sent.some((s) => s.includes(q)))) {
        return { rule: 'breaker.echo', detail: { echoes: env.id, to: others } }
      }
    }
    return null
  }

  /** More than fanoutSends sends, with more than fanoutRecipients first contacts, in the last fanoutSeconds. */
  #fanout(input: SendInput, now: number, b: Breakers): Trip {
    if (FANOUT_EXEMPT.has(input)) return null
    const seen = this.#o.store.fanoutSince(now - b.fanoutSeconds)
    const sends = seen.sends + 1
    const fresh = seen.contacts + this.#o.store.contactsNew(input.to).length
    if (sends <= b.fanoutSends || fresh <= b.fanoutRecipients) return null
    return { rule: 'breaker.fanout', detail: { sends, new_recipients: fresh, seconds: b.fanoutSeconds } }
  }
}
