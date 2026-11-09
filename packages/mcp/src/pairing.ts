import { join } from 'node:path'
import {
  type AddressRecord,
  isAddress,
  type KeyRecord,
  parseRecord,
  signRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import {
  acceptPeer,
  continueFrom,
  digitsMatch,
  type EdgeKeys,
  HomeCustody,
  INVITE_PREFIX,
  inviteOf,
  invitePeer,
  KeyEpochStore,
  keepAddressCopy,
  type Lagging,
  MAX_DIGIT_TRIES,
  MAX_INVITE_TTL,
  type PeerRequest,
  RelayError,
  RelayGuard,
} from '@usebag/edge'
import type { PairingPorts } from '@usebag/enterprise-client'
import { incompleteLine } from './keepalive.ts'
import { NAME, Names } from './names.ts'
import { type ProgressExtra, startProgress } from './progress.ts'
import { codeOf, refuseLinks, type ToolContext, ToolError } from './tools.ts'
import { addTrust } from './trust.ts'

// Pairing inside the MCP host (relaxing, on 2026-10-29, the earlier "CLI only" rule): pair_invite and pair_accept drive the edge's unchanged invitePeer
// and acceptPeer, and every approval is a form dialog (MCP elicitation) that the host shows to the person and the model
// neither sees nor answers. pair_invite's first result carries the word code
// (`472-tulip-orbit-cedar`, its nameplate claimed at the relay and its words making S), or the invite string from a
// relay without the rendezvous, which the model shows the person verbatim to copy (Claude Code cuts a long
// dialog line); no other result, progress notification, log
// or audit line holds it. The acceptor's person pastes it into a dialog (read raw by the edge's inviteOf), sees the six
// check digits there, reads them to the peer and confirms, which sends the request; the inviter's dialog never shows
// them: its person types what the peer read out, and a root is written only after a match
// (there is no two-sided compare). The digits and key material
// appear only in the acceptor's dialog. Every dialog is at most 3 lines of at most 60 characters. One pairing at a time per server, in memory, under an opaque token; a wait spans calls as wait's does,
// with no dialog open while it waits. A host that cannot show a form refuses no-elicitation, with no terminal command.
// The request's 403 root-not-accepted (a closed I) reads as an invite used, cancelled or expired, and the acceptor's
// results say it is not paired until paired: true (a send in that gap read as a failed pairing).
// The root written is the peer's address only: domain trust (`domain:<host>`) stays the CLI's --trust-domain, typed by
// the person, because a tool argument is the model's (and so an injected message's) and the compared check digits do not bind it.

/** The edge's pairing refusals (packages/edge/src/pairing.ts), whose codes a tool error keeps. */
export const PAIRING_CODES =
  'bad-invite bad-code invite-expired bad-request bad-mac not-for leaked declined no-answer'.split(' ')

/** What pair_accept says while it is not paired: a send to the inviter before its admit is refused. */
export const NOT_PAIRED = 'not paired yet: send nothing to this peer until pair_accept answers paired: true'

/**
 * What pair_invite's first result adds: the description already asked for the code in a code block, yet in two real
 * runs one agent wrote it inside a sentence and said it had sent it, and another printed nothing and said it had given
 * it. A person sees no tool result, and a model acts on a result it has just read. A model that goes straight on to the
 * resume writes no reply at all: Claude Code showed a line it made itself, tagged "summary", which may drop the code
 * (LN-8), so the code ends a turn and the resume waits for the person's word. It holds no code, by the must-not.
 */
export const SHOW_CODE =
  'your user does not see this result, and what you write between tool calls may never reach them, so they have no code until you end your turn with it. Make no other tool call now. End your turn with a message that says when it expires, then the code or invite string alone in a fenced code block, exactly as it is here, then asks them to pass it to the peer and to tell you when the peer has it. Say the peer will read six digits to them, which they type in a dialog here; they read nothing out themselves. Only then call pair_invite with resume alone: the dialog opens during that call. That block is all they pass to the peer, and they pass it, not you: never say you sent it or gave it.'

/**
 * What pair_invite adds while it waits: in a real run a model stopped after two calls, and with no call open its dialog
 * cannot appear, so the peer's request waits on a person who was told nothing is happening.
 */
export const STILL_WAITING =
  'not paired yet: the dialog for the check digits can open only during a pair_invite call, so call it again now with resume alone, until paired: true or an error'

/**
 * What a finished pairing adds for a relay this identity lists that did not take one of its records: the pairing
 * stands once the rendezvous and one listed relay hold them (spec/SPEC.md Appendix B 110), and the rest is carried.
 */
export const LAGGING =
  "paired, but the relays in lagging did not take this identity's records: they serve older ones until the keep-alive (--keep-alive-records or the CLI's record keep) offers them again. Name them to your user."

/**
 * The same when the record carries a revoked list. A relay honours only the list it stored, so no pairing makes this
 * good and no result may read as if it had: `paired` is true of the peer, not of the revocation.
 */
export const INCOMPLETE =
  'this is a security gap, not a delay: the pairing finished, but a record with a revoked list did not reach the relays in incomplete, so the revocation is incomplete and those relays still honour the revoked keys. Tell your user now, and say which relays.'

/** An address as a dialog shows it: ed25519:, its first 8 and its last 4 hex characters. */
export function shortAddress(address: string): string {
  return `${address.slice(0, 16)}…${address.slice(-4)}`
}

/**
 * The request's one publish (edge pairing.ts, acceptPeer) refused root-not-accepted: an inviter on a client from before
 * rule that closes I's accept-from, so the invitation was used, cancelled or expired;
 * any other error as it is.
 */
function usedInvite(e: unknown): unknown {
  if (!(e instanceof RelayError && e.code === 'root-not-accepted')) return e
  return new ToolError('invite-expired', 'invite used, cancelled or expired: ask your peer for a new one')
}

/** How often the edge's pairing loops poll the relay, in ms: the CLI's idleMs. */
export const PAIR_POLL_MS = 1000

/** A tool call's handler extra, as a pair tool uses it: progress, the request id a dialog relates to, and the abort. */
export type PairExtra = ProgressExtra & { readonly requestId: string | number; readonly signal: AbortSignal }

type Json = Record<string, unknown>
type Opt<T> = T | undefined

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()

type Field =
  | { readonly type: 'string'; readonly title: string }
  | { readonly type: 'boolean'; readonly title: string }

/** The peer's address in a dialog, the address-bound path (spec/SPEC.md §8.10): held out of band, never read from a code. */
const ADDRESS: Record<string, Field> = {
  address: { type: 'string', title: "Your peer's address, if you know it" },
}

/** A dialog's address field: undefined left empty, for first contact; anything but an address stops here. */
function addressIn(form: Json): string | undefined {
  const text = String(form.address ?? '').trim()
  if (text === '') return undefined
  if (!isAddress(text)) throw new ToolError('usage', 'that is not an address: nothing was sent')
  return text
}

/** One pairing: its token, what it writes, the edge's outcome once settled, and the inviter's request held. */
class Live {
  readonly tool: string
  readonly token: string
  readonly name: string
  readonly write: (peer: string) => void
  exp = 0
  from: string | null = null
  end: { readonly value: Json } | { readonly error: unknown } | null = null
  /** The inviter's request waiting for its dialog, and the answer to the edge's ask (once). */
  ask: PeerRequest | null = null
  answer: (yes: boolean) => void = () => {}
  /** What the tool answers in place of the edge's declined: name-exists, invite-expired. */
  refusal: unknown = null
  /** Ended here and audited: every later ask is no, and the edge's end is only logged. */
  over = false
  /** The relays that did not take a record of this identity's, one entry for each relay and kind. */
  readonly lagging: Lagging[] = []
  #waiters: (() => void)[] = []

  constructor(tool: string, token: string, name: string, write: (peer: string) => void) {
    this.tool = tool
    this.token = token
    this.name = name
    this.write = write
  }

  changed(): Promise<void> {
    return new Promise((resolve) => this.#waiters.push(resolve))
  }

  poke(): void {
    for (const w of this.#waiters.splice(0)) w()
  }
}

/**
 * The pair tools' bodies over one identity's context: one pairing at a time across `all`, the server's Pairings (one
 * per identity of an --identities server), which the constructor joins.
 */
export class Pairings {
  readonly #ctx: ToolContext
  readonly #all: Pairings[]
  #live: Live | null = null

  constructor(ctx: ToolContext, all: Pairings[] = []) {
    this.#ctx = ctx
    this.#all = all
    all.push(this)
  }

  /** pair_invite: open an invitation and hand it over in a dialog, or (resume) wait for its request and admit it. */
  async invite(
    a: {
      name?: Opt<string>
      for?: Opt<string>
      ttl?: Opt<number>
      resume?: Opt<string>
    },
    extra: PairExtra,
  ): Promise<Json> {
    const { resume, ...rest } = a
    if (resume !== undefined) return this.#resume('pair_invite', resume, rest, extra)
    const live = this.#start('pair_invite', a.name, a.for)
    const only = a.for ?? (await this.#first(live, this.#boundPeer(live, extra), true))
    const { keys, relay, key } = await this.#first(live, this.#keys(live))
    const opened = Promise.withResolvers<{ text: string; exp: number }>()
    const run = invitePeer(this.#ports(live), {
      relay,
      keys,
      ...key,
      ttl: a.ttl ?? MAX_INVITE_TTL,
      rendezvous: this.#ctx.config.rendezvous,
      ...(only === undefined ? {} : { only }),
      opened: (text, exp) => {
        live.exp = exp
        this.#audit('queue', 'invite-open', null, { name: live.name })
        opened.resolve({ text, exp })
      },
      refused: (from, code) => this.#audit('reject', 'request', from, { code }),
      leaked: (from) => this.#audit('reject', 'request', from, { code: 'leaked' }),
      ask: (q) => this.#held(live, q),
      write: (q) => live.write(q.from),
    })
    this.#settle(live, 'refuse', run, (q) => this.#paired(live, q.from))
    const { text, exp } = await this.#first(
      live,
      Promise.race([opened.promise, run.then(() => opened.promise)]),
    )
    // The one result that carries the invite string: the model shows it, the person hands it over.
    // The word code, or the invite string from a relay without the rendezvous (edge pairing.ts, INVITE_PREFIX).
    const given = text.startsWith(INVITE_PREFIX) ? { invite: text } : { code: text }
    return { invite_open: true, ...given, expires_at: iso(exp), resume: live.token, note: SHOW_CODE }
  }

  /** pair_accept: take the pasted invite string, show this side's code and send the request; or (resume) wait. */
  async accept(
    a: { name?: Opt<string>; for?: Opt<string>; resume?: Opt<string> },
    extra: PairExtra,
  ): Promise<Json> {
    const { resume, ...rest } = a
    if (resume !== undefined) return this.#resume('pair_accept', resume, rest, extra)
    const live = this.#start('pair_accept', a.name, a.for)
    const v = await this.#first(
      live,
      (async () => {
        const form = await this.#form(
          live,
          extra,
          `${this.#line('Paste the code or invite string your peer sent.', (l) => `As ${l}: paste your peer's code.`)}\nSpaces, hyphens and line breaks are fine.\nThey will be named ${live.name} here.`,
          { invite: { type: 'string', title: 'the code or invite string' }, ...ADDRESS },
          ['invite'],
        )
        const only = a.for ?? addressIn(form)
        // The raw paste: the edge normalises a code (case, spaces, hyphens; claimed at --rendezvous, or at the host of
        // a code typed as code@host) and drops an invite string's whitespace. A claim consumes no invitation, so a
        // not-for below leaves it open.
        const invite = await inviteOf(
          this.#ports(live),
          this.#ctx.config.rendezvous,
          String(form.invite ?? ''),
        )
        // An invite string is read here, before any network call; a word code names its inviter only once claimed at
        // the relay. A sibling's own invite never gets here: one pairing runs per server, so it meets busy first.
        refuseLinks(this.#ctx, { to: invite.inviter })
        if (only !== undefined && invite.inviter !== only)
          throw new ToolError(
            'not-for',
            `that invitation is from ${invite.inviter}, not ${only}: nothing was sent`,
          )
        Names.read(this.#ctx.config.home).check(live.name, invite.inviter)
        return invite
      })(),
      true,
    )
    live.from = v.inviter
    const { keys, relay, key } = await this.#first(live, this.#keys(live))
    const sent = Promise.withResolvers<number>()
    const run = acceptPeer(this.#ports(live), keys, relay, v, {
      ...key,
      // The check digits alone on line 1, the one place they are shown. The read-out is the security step, by another
      // channel than the code's, for a code edited in transit is caught only if the digits do not go the same way
      // (spec/SPEC.md §8.10, both dialogs say so), and this confirm only sends the request: the inviter's dialog opens after it, and types what was read out.
      ask: async (code) => {
        const digits = this.#line(`Check digits: ${code}`, (l) => `As ${l}, check digits: ${code}`)
        const message = `${digits}\nSecurity check: read them out, not where the code was sent.\nNot shown again. Confirm to send to ${shortAddress(v.inviter)}.`
        const property = { type: 'boolean', title: 'I read them to my peer' } as const
        const yes = await this.#ask(live, extra, message, 'confirm', property)
        if (yes !== true) {
          throw new ToolError('declined', 'the check digits were not confirmed: no request was sent')
        }
      },
      sent: (exp) => {
        live.exp = exp
        sent.resolve(exp)
      },
      write: () => live.write(v.inviter),
    }).catch((e: unknown) => {
      throw usedInvite(e)
    })
    this.#settle(live, 'decline', run, () => this.#paired(live, v.inviter))
    const exp = await this.#first(live, Promise.race([sent.promise, run.then(() => sent.promise)]))
    return { requested: true, expires_at: iso(exp), resume: live.token, note: NOT_PAIRED }
  }

  /** True while a pairing of this server has not ended: one runs at a time across its identities. */
  busy(): boolean {
    return this.#all.some((p) => p.#live !== null && p.#live.end === null)
  }

  /**
   * The console's ceremony (decision 38c, console.ts): pair_invite's invitePeer on this identity's keys and relay, with
   * the console's person in the inviter's seat (runPairing checks the digits typed there). It holds the server's one
   * pairing until the edge ends; it writes nothing, for runPairing writes after it (as the CLI's `bag pairings`).
   */
  readonly consoleInvite: PairingPorts['invite'] = async (o) => {
    if (this.busy()) throw new ToolError('busy', 'a pairing is running')
    const live = new Live('console', toHex(this.#ctx.rng.bytes(16)), 'console', () => {})
    this.#live = live
    try {
      const { keys, relay, key } = await this.#keys(live)
      // The organisation's relay, where the agent's records are (records.ts), over this server's --relay, which a host
      // install may have named otherwise: the invitation meets there, as the CLI's bag pairings opens it.
      const at = o.relay ?? relay
      const got = await invitePeer(this.#ports(live, o.relay === undefined ? [] : [o.relay]), {
        relay: at,
        keys,
        ...key,
        ttl: o.ttl,
        rendezvous: o.relay ?? this.#ctx.config.rendezvous,
        ...(o.only === undefined ? {} : { only: o.only }),
        opened: (text, exp) => {
          live.exp = exp
          this.#audit('queue', 'invite-open', null, { name: live.name })
          o.opened(text, exp)
        },
        refused: (from, code) => this.#audit('reject', 'request', from, { code }),
        leaked: (from) => this.#audit('reject', 'request', from, { code: 'leaked' }),
        ask: (q) => {
          live.from = q.from
          return o.ask(q)
        },
        write: () => {},
      })
      this.#audit('accept', 'admit', got.from, { name: live.name })
      return got.from
    } finally {
      this.#drop(live)
    }
  }

  /** True while a pairing here with one of `to` has not ended: a send to it is refused until the admit. */
  pendingWith(to: readonly string[]): boolean {
    const live = this.#live
    return live !== null && live.end === null && live.from !== null && to.includes(live.from)
  }

  /**
   * The inviter's question before a code exists (spec/SPEC.md §8.10): an address the person holds binds the invitation,
   * so the edge refuses any other request before a dialog; empty leaves it open, for first contact. Its first line says
   * an invite is being made: a person who saw only the address question read it as the wrong dialog.
   */
  async #boundPeer(live: Live, extra: PairExtra): Promise<string | undefined> {
    const head = this.#line(
      'Invite a peer: next you get a pairing code to send them.',
      (l) => `As ${l}: make a code for a peer.`,
    )
    const message = `${head}\nTheir address, if known: only it can answer. Else empty.\nThey will be named ${live.name} here.`
    return addressIn(await this.#form(live, extra, message, ADDRESS))
  }

  /** The checks before any dialog or network (no-elicitation, name, for, busy, a held name), then the live pairing. */
  #start(tool: string, name: Opt<string>, only?: Opt<string>): Live {
    const ctx = this.#ctx
    // No terminal command is suggested: pairing is the person's act in dialogs, in a host that shows them.
    if (!ctx.canElicit())
      throw new ToolError(
        'no-elicitation',
        'this host cannot show your user a dialog, so it cannot pair: pair in an interactive Claude Code session',
      )
    if (name === undefined || !NAME.test(name))
      throw new ToolError('usage', `name is the peer's petname (${NAME.source})`)
    if (only !== undefined && !isAddress(only)) throw new ToolError('usage', 'for takes an address')
    if (this.busy()) throw new ToolError('busy', 'a pairing is running: resume it, or wait for it to end')
    const { home } = ctx.config
    // Before a code goes out or a person is asked, for the peer's address may come only with its request, after the
    // whole ceremony: a held name goes on only under for, its own address. #held and the paste check a name taken since.
    Names.read(home).check(name, only)
    const write = (peer: string): void => {
      // The book as it is now: a pairing runs for minutes, and a save writes back what it read and checks against it.
      Names.read(home).save(name, peer, ctx.clock.now())
      addTrust(home, peer, ctx.clock.now())
    }
    const live = new Live(tool, toHex(ctx.rng.bytes(16)), name, write)
    this.#live = live
    return live
  }

  /**
   * The server's own keys, as open.ts and the CLI load them (file or keychain custody), its first relay, and its
   * current key record under forward secrecy. It differs from the CLI's currentKey (packages/cli/src/epochs.ts) in three ways, by
   * the seam: a due epoch is published through the server's own keep-alive rotation (opened.epochs), not the CLI's
   * rotateEpoch; with no epoch held and a record that names no sealing key it publishes the first epoch, for that record
   * tells a peer to read a key record, and a peer finding none refuses bad-request (spec/SPEC.md §9 item 4); with no epoch
   * held and any other record, or none, it passes no key record and pairs on the record's sealing key (the edge's pre-forward-secrecy
   * path), where the CLI would publish a first epoch: the keep-alive's first cycle does that; and a newest epoch that has
   * ended and cannot be rotated now is refused usage naming the CLI's record keep, since the peer would refuse an expired
   * key record.
   */
  async #keys(live: Live): Promise<{ keys: EdgeKeys; relay: string; key: { key?: KeyRecord } }> {
    const { config, clock, opened, log } = this.#ctx
    const keys = new HomeCustody(config.home).keys(config.as)
    const relay = config.relays[0] as string
    const at = keys.signing.address
    const store = new KeyEpochStore(join(config.home, 'key-records'))
    const none = store.epochs(at).length === 0
    if (opened.epochs !== null && clock.now() >= opened.epochs.dueAt()) {
      try {
        // A relay that holds none (a sweep) or an older record (a replay): the home's copy, so its revoked list goes on.
        const bytes = await this.#ownRecord(at)
        const r = bytes === null ? null : parseRecord(bytes)
        if (r === null || (r.kind === 'address' && r.key === at)) {
          const found = r === null ? null : (verifyRecord(r, r.iat) as AddressRecord)
          const held = continueFrom(found, config.home, config.as, at)
          const stays = held === null || (none && held.sealing_key !== null)
          const next = stays ? null : await opened.epochs.rotate(held)
          if (next !== null) {
            keepAddressCopy(config.home, config.as, next.address)
            for (const lag of next.lagging) this.#lagged(live, lag)
          }
        }
      } catch (e) {
        log.log('warn', 'pair-epoch', { tool: live.tool, code: codeOf(e) })
      }
    }
    const newest = store.epochs(at)[0]
    if (newest === undefined) return { keys, relay, key: {} }
    const e = store.epoch(at, newest)
    if (clock.now() >= e.exp)
      throw new ToolError(
        'usage',
        `the newest key record of ${at} has ended: run the CLI's record keep, then pair again`,
      )
    const sealing_key = toHex(e.key.publicKey)
    const key = signRecord(keys.signing, { kind: 'key', key: at, sealing_key, iat: e.iat, exp: e.exp })
    return { keys, relay, key: { key } }
  }

  /** The identity's address record at the first of its relays that answers: the first may be down (Appendix B 110). */
  async #ownRecord(at: string): Promise<Uint8Array | null> {
    const { config, opened } = this.#ctx
    let silent: unknown = null
    for (const url of config.relays) {
      try {
        return await opened.client.fetchRecord(url, at, 'address')
      } catch (e) {
        silent ??= e
      }
    }
    throw silent
  }

  /**
   * The edge's pairing ports, with SPEC rule 11's private-address guard: its own relays are --relay and --rendezvous,
   * so a pasted code@host or an inviter's relay on a loopback or private address is refused resolve-failed before any
   * request, unless --allow-private-relays. The home's copy of the address record stands in for one that a relay swept,
   * so a pairing does not publish an empty first record over it. A relay that did not take a record goes on `live`.
   */
  #ports(live: Live, more: readonly string[] = []) {
    const { opened, clock, rng, pollMs, config } = this.#ctx
    const { home, as } = config
    const own = [...config.relays, config.rendezvous, ...more]
    const guard = new RelayGuard({ own, allowPrivate: config.allowPrivateRelays })
    return {
      client: opened.client,
      clock,
      rng,
      pollMs,
      guard,
      continueFrom: (found: AddressRecord | null) => continueFrom(found, home, as, opened.signer.address),
      keepAddress: (r: AddressRecord) => keepAddressCopy(home, as, r),
      lagging: (lag: Lagging) => this.#lagged(live, lag),
    }
  }

  /** One relay that did not take a record of this identity's: logged, and kept for the result. */
  #lagged(live: Live, lag: Lagging): void {
    this.#ctx.log.log('warn', 'pair-lagging', { tool: live.tool, ...lag })
    if (!live.lagging.some((l) => l.relay === lag.relay && l.kind === lag.kind)) live.lagging.push(lag)
  }

  /** What a finished pairing answers, with the relays that did not take a record when there are any. */
  #paired(live: Live, peer: string): Json {
    const done = { paired: true, peer, name: live.name }
    const { lagging } = live
    if (lagging.length === 0) return done
    const address = this.#ctx.opened.signer.address
    const incomplete = lagging.filter((l) => l.revokes).map((l) => incompleteLine(address, l))
    if (incomplete.length === 0) return { ...done, lagging, note: LAGGING }
    return { ...done, lagging, incomplete, note: INCOMPLETE }
  }

  /** A first call's step: its value, or its refusal with the pairing dropped (audited when `audit`, else by #settle). */
  async #first<T>(live: Live, step: Promise<T>, audit = false): Promise<T> {
    try {
      return await step
    } catch (e) {
      if (audit) this.#end(live, live.from, e)
      this.#drop(live)
      throw e
    }
  }

  /** The inviter's request: audited, then held for the next resume call's dialog, with a timer to the invite's end. */
  #held(live: Live, q: PeerRequest): Promise<boolean> {
    this.#audit('queue', 'request', q.from, {})
    live.from = q.from
    if (live.over) return Promise.resolve(false)
    try {
      refuseLinks(this.#ctx, { to: q.from })
      Names.read(this.#ctx.config.home).check(live.name, q.from)
    } catch (e) {
      live.refusal = e
      return Promise.resolve(false)
    }
    const { promise, resolve } = Promise.withResolvers<boolean>()
    const late = (): void => {
      live.refusal ??= new ToolError(
        'invite-expired',
        'no one answered the request before the invitation ended',
      )
      live.answer(false)
    }
    const cancel = this.#ctx.timers.after(Math.max(0, live.exp - this.#ctx.clock.now()) * 1000, late)
    live.answer = (yes) => {
      live.answer = () => {}
      live.ask = null
      cancel()
      resolve(yes)
    }
    live.ask = q
    live.poke()
    return promise
  }

  /** Records the edge's outcome on the pairing: a refusal audited once (or only logged after #end), then wakes it. */
  #settle<T>(live: Live, step: string, run: Promise<T>, done: (value: T) => Json): void {
    run
      .then(
        (value) => {
          live.end = { value: done(value) }
          this.#audit('accept', step === 'refuse' ? 'admit' : 'accept', live.from, { name: live.name })
        },
        (e: unknown) => {
          const error = live.refusal ?? e
          live.end = { error }
          if (live.over) this.#ctx.log.log('info', 'pair-ended', { tool: live.tool, code: codeOf(e) })
          else this.#audit('reject', step, live.from, { code: codeOf(error) })
        },
      )
      .catch((e: unknown) => this.#ctx.log.log('warn', 'pair-ended', { tool: live.tool, code: codeOf(e) }))
      .finally(() => live.poke())
  }

  /** Ends a pairing here: the held ask is no, nothing is written, the refusal is audited once and the state dropped. */
  #end(live: Live, from: string | null, e: unknown): void {
    live.over = true
    live.answer(false)
    this.#drop(live)
    this.#audit('reject', live.tool === 'pair_invite' ? 'refuse' : 'decline', from, { code: codeOf(e) })
  }

  #drop(live: Live): void {
    if (this.#live === live) this.#live = null
  }

  /**
   * A resume call: it opens the inviter's compare dialog when a request is held, else blocks at most the window for
   * the pairing to end (progress as wait's), and answers pending while it has not. A dialog answered starts the window
   * again, for the admit that follows takes a moment and this call must not answer pending for a pairing that just
   * finished: in a real run a model read that as "the peer has not responded".
   */
  async #resume(tool: string, token: string, rest: Json, extra: PairExtra): Promise<Json> {
    if (Object.values(rest).some((v) => v !== undefined))
      throw new ToolError('usage', 'resume continues a pairing: pass resume alone')
    const live = this.#live
    if (live === null || live.token !== token || live.tool !== tool)
      throw new ToolError('usage', `resume names no live pairing of ${tool}: start a new one`)
    const { config, timers, log, clock } = this.#ctx
    const window = config.maxToolSeconds
    let due = false
    const stop = (): void => {
      due = true
      live.poke()
    }
    let cancel = timers.after(window * 1000, stop)
    const progress = startProgress({ tool, extra, every: config.progressSeconds, window, timers, log })
    extra.signal.addEventListener('abort', stop, { once: true })
    try {
      for (;;) {
        if (live.end !== null) {
          this.#drop(live)
          if ('error' in live.end) throw live.end.error
          return live.end.value
        }
        const q = live.ask
        if (q !== null) {
          live.ask = null
          await this.#compare(live, q, extra)
          cancel()
          due = extra.signal.aborted
          cancel = timers.after(window * 1000, stop)
          continue
        }
        if (due) {
          const remaining_s = Math.max(0, live.exp - clock.now())
          const note = tool === 'pair_accept' ? NOT_PAIRED : STILL_WAITING
          return { pending: true, resume: token, remaining_s, note }
        }
        await live.changed()
      }
    } finally {
      cancel()
      progress()
      extra.signal.removeEventListener('abort', stop)
    }
  }

  /**
   * The inviter's compare dialog: its person types the digits the peer reads out. No dialog here shows them or says
   * what they should be; the tries are this person's own, not the relay's guess bound, and a typed mismatch ends only
   * in digits-mismatch, which the acceptor does not hear (no oracle: it gets no-answer at the invitation's end).
   */
  async #compare(live: Live, q: PeerRequest, extra: PairExtra): Promise<void> {
    const head = this.#line(
      'Type the six digits your peer reads to you.',
      (l) => `As ${l}: type the six digits.`,
    )
    const peer = `${shortAddress(q.from)} named ${live.name}`
    let hint = 'Your peer reads them out, not where the code was sent.'
    try {
      for (let left = MAX_DIGIT_TRIES - 1; ; left--) {
        const message = `${head}\n${hint}\n${peer}`
        const typed = await this.#dialog(live, extra, message, 'digits', 'The six check digits')
        if (digitsMatch(typed, q.code)) break
        if (live.refusal !== null) return // The invitation ended under the dialog: its timer has answered no.
        if (left === 0) {
          throw new ToolError('digits-mismatch', 'the typed digits did not match: nothing was written')
        }
        hint = `No match. Tries left: ${left}. Ask your peer to repeat them.`
      }
    } catch (e) {
      this.#end(live, q.from, e)
      throw e
    }
    live.answer(true)
  }

  /**
   * A dialog's first line: `one`, or in an --identities server `many` of the label, so the person always knows which
   * identity pairs; at most 60 characters for a label of 32.
   */
  #line(one: string, many: (label: string) => string): string {
    return this.#ctx.identities === undefined ? one : many(this.#ctx.config.label)
  }

  /**
   * One dialog with one string field: its text on accept; declined, or cancelled for a cancel, an error or an abort
   * (the host ended the call: the pairing fails closed). A failed dialog logs its code and name only, never its text.
   */
  async #dialog(
    live: Live,
    extra: PairExtra,
    message: string,
    field: string,
    title: string,
  ): Promise<string> {
    return String((await this.#ask(live, extra, message, field, { type: 'string', title })) ?? '')
  }

  /** One dialog with one required field of `property`'s type: the field's value on accept, else as #dialog says. */
  async #ask(
    live: Live,
    extra: PairExtra,
    message: string,
    field: string,
    property: Field,
  ): Promise<unknown> {
    return (await this.#form(live, extra, message, { [field]: property }, [field]))[field]
  }

  /** One dialog of `properties`, those in `required` required: what the person gave on accept, else as #dialog says. */
  async #form(
    live: Live,
    extra: PairExtra,
    message: string,
    properties: Record<string, Field>,
    required: string[] = [],
  ): Promise<Json> {
    const requestedSchema = { type: 'object' as const, properties, required }
    const cancel = { action: 'cancel' as const }
    const r = await this.#ctx.elicit({ message, requestedSchema }, extra).catch((e: unknown) => {
      const name = e instanceof Error ? e.name : typeof e
      this.#ctx.log.log('warn', 'pair-dialog', { tool: live.tool, code: codeOf(e), name })
      return cancel
    })
    if (r.action === 'accept') return r.content ?? {}
    if (r.action === 'decline') throw new ToolError('declined', 'the person declined: nothing was written')
    throw new ToolError('cancelled', 'the dialog was closed before an answer: nothing was written')
  }

  /** One `pair` audit line: the step, the peer's address, a code or the name; never S, a code's digits or a key. */
  #audit(decision: 'accept' | 'reject' | 'queue', step: string, from: string | null, more: Json): void {
    const detail = { step, ...more } as Record<string, string>
    this.#ctx.opened.edge.audit.record({ event: 'pair', decision, reason: 'ok', from, detail })
  }
}
