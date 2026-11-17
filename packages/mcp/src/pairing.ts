import { join } from 'node:path'
import {
  type AcceptFromRecord,
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
  heldAccept,
  INVITE_PREFIX,
  inviteOf,
  invitePeer,
  KeyEpochStore,
  keepAcceptCopy,
  keepAddressCopy,
  type Lagging,
  MAX_DIGIT_TRIES,
  MAX_INVITE_TTL,
  type PeerRequest,
  RelayError,
  RelayGuard,
} from '@usebag/edge'
import type { PairingPorts } from '@usebag/enterprise-client'
import { askPerson, type ConsentPeer, type ConsentWords, countStart, MAX_PASTE, textOf } from './ask.ts'
import type { ServiceConnection } from './binding.ts'
import { incompleteLine } from './keepalive.ts'
import { NAME, Names } from './names.ts'
import { type ProgressExtra, startProgress } from './progress.ts'
import {
  codeOf,
  detailOf,
  LOCAL_DECLINED,
  LOCAL_HIDDEN,
  LOCAL_PENDING,
  noRelays,
  REQUESTED_NOTE,
  refuseLinks,
  SHOW_HOW,
  type ToolContext,
  ToolError,
} from './tools.ts'
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
// with no dialog open while it waits. A host that cannot show a form, or that answers the first dialog sooner than a
// person can (FAST_ANSWER_MS), refuses no-elicitation naming the host's setting, never a terminal command.
// The request's 403 root-not-accepted (a closed I) reads as an invite used, cancelled or expired, and the acceptor's
// results say it is not paired until paired: true (a send in that gap read as a failed pairing).
// The root written is the peer's address only: domain trust (`domain:<host>`) stays the CLI's --trust-domain, typed by
// the person, because a tool argument is the model's (and so an injected message's) and the compared check digits do not bind it.

/** The edge's pairing refusals (packages/edge/src/pairing.ts), whose codes a tool error keeps. */
export const PAIRING_CODES =
  'bad-invite bad-code invite-expired bad-request bad-mac not-for leaked declined no-answer'.split(' ')

/** What a local pair's result says. */
/** What pair_accept says while it is not paired: a send to the inviter before its admit is refused. */
export const NOT_PAIRED = 'not paired yet: send nothing to this peer until pair_accept answers paired: true'

/**
 * What an omp pair_invite's first result says, in place of the code: omp shows the code in its bag widget, so the
 * result never carries it (the omp pty proof, 2026-11-12: with the code in the result the model printed it anyway).
 */
export const BRIDGE_SHOW =
  "the code is shown in your host's bag widget, for your user to hand to the peer out of band; this result does not carry it, so there is nothing for you to print or pass on. Once your user says the peer has it, call this tool again with resume alone to wait. When the peer requests, your host asks your user to type the six digits the peer reads them; only your user answers."

/**
 * What an omp pair_accept answers once the pasted code is taken: one question per call, so the
 * check digits' Yes/No opens during the next call.
 */
export const LINK_DIGITS =
  'the code was taken, and nothing is sent yet: during your next call of this tool (resume alone) a Yes/No dialog in your host shows your user the six check digits to read to the peer, and only their Yes sends the request (you cannot answer it, and must not try). Tell them, then call this tool again with resume alone, until paired: true or a refusal.'

/** What an omp pair tool answers when its question was not answered in time: no answer is not a No (L1). */
export const LINK_AGAIN =
  'your user did not answer the dialog in your host in time; that is not a No, and the pairing stays open. Tell them it opens again, then call this tool again with resume alone when they are ready (until the invitation ends).'

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

/** `name` cut to `max` characters with '...' at its end, so an omp question line never passes 60 (a petname runs 64). */
export function fitName(name: string, max: number): string {
  return name.length <= max ? name : `${name.slice(0, max - 3)}...`
}

/**
 * An omp question's peer lines: the address on a line of its own, never after the name, so a long petname cannot push
 * it off the line where it identifies the peer; then the name, cut to fit 60 characters.
 */
export function peerLines(address: string, name: string): string {
  return `${shortAddress(address)}\nnamed ${fitName(name, 54)}`
}

/** omp's bag widget while the invite opens: one line, the name cut so the line never passes 60 columns. */
export function makingLine(name: string): string {
  return `bag: making a pairing code for ${fitName(name, 29)}`
}

/**
 * omp's bag widget with the invite: the code on a line of its own, never after the name, so a long petname cannot
 * push the code off the line the person reads it from; the name cut so the first line never passes 60.
 */
export function inviteLines(name: string, code: string): string[] {
  return [
    `bag: your invite code for ${fitName(name, 33)}:`,
    `  ${code}`,
    ...(code.length > 58 ? ['it wraps on screen: copy it all, as one line'] : []),
    'give it to your peer yourself, never through an agent',
  ]
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

/**
 * A pasted invite or code through the one text check (ask.ts textOf): line breaks folded (`fold`) on the elicitation
 * path, and on the link before the answer reaches here (the ask's own fold). A text that fails it never reaches
 * inviteOf: bad-code, nothing sent.
 */
function pastedOf(raw: unknown, fold: boolean): string {
  const text = textOf(raw, MAX_PASTE, fold)
  if (text === null)
    throw new ToolError(
      'bad-code',
      `not a code or invite string: one line of printable characters, at most ${MAX_PASTE}; nothing was sent`,
    )
  return text
}

/** The dialog's words to hide an identity, and to show it again (spec/SPEC.md 9.2 item 1). */
export const HIDE_WORDS = (name: string): string =>
  `Keep ${name} apart from your other identities on this machine?`
export const SHOW_WORDS = (name: string): string => `Let ${name} reach your other identities on this machine?`
/** One show dialog per identity per this many seconds (a hide needs no bound): when each home's label last asked. */
export const SHOW_EVERY_S = 600
const SHOW_ASKED = new Map<string, number>()
const HIDDEN_NOTE =
  "hidden: the home's other identities no longer see this identity or reach it on this machine"
const SHOWN_NOTE =
  "shown: the home's other identities see this identity and may reach it on this machine again"

/** A local dialog with no answer (a decline faster than a person, a timeout, a cancel): cancelled, never declined. */
const UNANSWERED = 'the dialog was not answered: nothing was changed'

/** The no-elicitation detail for an omp window with no registered consent link (an older extension, or a subagent). */
export const OLD_EXTENSION =
  "This omp session's bag extension has no link to the bag service for this dialog (older, or not in omp's main " +
  'interactive session), so nothing was written. Your user runs bag host install omp --user again and restarts omp, then ' +
  'asks again. Do not call a pair tool again until they say so.'

/** The window a service pairing runs in, as busy and a refused cancel name it: host kind and cwd, never the handle. */
const windowOf = (c: ServiceConnection): string => `the ${c.host} window at ${c.cwd}`

/** What pair_invite and pair_accept answer while a pairing of this server runs: one runs at a time. */
export const BUSY =
  'a pairing is running: resume it, wait for it to end, or cancel it with pair_cancel if your person asks'

/**
 * What busy answers in the window that started the running pairing, beside a fresh resume token: a model that lost
 * its token (a dropped result, a compacted context) goes on with the pairing instead of cancelling it.
 */
export const BUSY_HERE = (tool: string): string =>
  `a pairing is running in this window: call ${tool} with resume alone (the resume here) to go on with it, or wait for it to end; cancel it with pair_cancel only if your person asks`

/**
 * What busy answers in the window whose own pairing has ended but is still winding down (its edge withdrawing, at
 * most CANCEL_WAIT_S): nothing to resume or cancel, so it names neither.
 */
export const CLOSING = 'the last pairing is still closing; try again in a few seconds'

/** Why a pairing ended here before its edge did: pair_cancel, its window's close, or the client's abort of its first call. */
type StopWhy = 'cancel' | 'close' | 'client-abort'

/** What a pairing ended by #stop answers, by why. */
const STOPPED: Record<StopWhy, string> = {
  cancel: 'your user cancelled this pairing (pair_cancel): nothing was written',
  close: 'the window that started this pairing closed: nothing was written',
  'client-abort': 'the host cancelled the call that started this pairing: nothing was written',
}

/** How long pair_cancel waits for the edge to end the pairing it aborted (a withdrawal or a rollback), in seconds. */
export const CANCEL_WAIT_S = 30

/** How often the edge's pairing loops poll the relay, in ms: the CLI's idleMs. */
export const PAIR_POLL_MS = 1000

/**
 * A first dialog declined, cancelled or failed sooner than this (ms, on the monotonic `mono`) was never seen by a
 * person: no-elicitation, not declined. codex exec declines a form in 0.5 to 0.6 ms, content and _meta null (measured
 * 2026-11-12); a person must see the form, read it and press a key.
 */
export const FAST_ANSWER_MS = 250

/** The first Codex release with the form renderer the pair dialogs need (PR #13621), as major.minor.patch. */
export const CODEX_FLOOR = [0, 113, 0] as const

/** The numeric major.minor.patch core of a version, any prerelease tag ignored; null when unparsable or 0.0.0. */
export function versionCore(version: string): number[] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(version)
  const core = m === null ? null : m.slice(1, 4).map(Number)
  return core === null || core.every((n) => n === 0) ? null : core
}

/** Why a pair tool answers no-elicitation: no form capability, a first dialog answered at once, a Codex too old. */
type NoDialog = 'none' | 'fast' | 'version'

/**
 * The no-elicitation detail: what to change in this host, by its own setting, never a terminal command, a flag or a
 * path: the person changes it in the host itself, with no bag command. `codex --version` is the person's
 * own host's version check, not a way to pair.
 */
export function noDialog(kind: string, why: NoDialog, version = ''): string {
  const again =
    ' Tell your user which of these to change. Do not call a pair tool again until they say it is changed.' +
    (why === 'fast' ? ' If a pairing dialog did appear and was closed, call the tool again.' : '')
  if (kind === 'codex') {
    const head = {
      none: 'Codex did not offer the pairing dialog, so nothing was written.',
      fast: 'Codex did not show the pairing dialog to your user (it answered at once), so nothing was written.',
      version: `This Codex is ${version}; bag's pairing dialogs need 0.113.0 or later, so nothing was written.`,
    }[why]
    return `${head} A pair tool needs the interactive codex TUI, not codex exec; Codex 0.113.0 or later (your user can check with codex --version); and an approval policy that lets MCP servers ask: on-request, the default, is enough (or a granular policy with mcp_elicitations allowed): your user changes it with /permissions in the TUI or approval_policy in their Codex config.${again}`
  }
  if (kind === 'omp')
    return `omp shows bag's pairing dialogs only in an interactive session that runs bag's omp extension with bag's service. This omp is connected another way, so nothing was written: bag's per-folder server cannot pair, and neither can an omp without bag's extension. Your user pairs in an interactive omp session that runs bag's extension with bag's service.${again}`
  const head =
    why === 'fast'
      ? 'This host answered the pairing dialog at once, without showing it to your user, so nothing was written.'
      : 'This host cannot show your user the pairing dialog, so nothing was written.'
  return `${head} Pairing needs a host that shows dialogs: this host's interactive form, with its setting that lets MCP servers ask your user, or Claude Code, or the interactive codex TUI.${again}`
}

/** A tool call's handler extra, as a pair tool uses it: progress, the request id a dialog relates to, and the abort. */
export type PairExtra = ProgressExtra & {
  readonly requestId: string | number
  readonly signal: AbortSignal
  /** When the tool call started (ctx.mono, ms): an omp question never stands past the call's deadline (ask.ts). */
  readonly startedAt?: number
}

/** `extra` with its call's start, stamped at the tool body's entry when the caller has not. */
function started(ctx: ToolContext, extra: PairExtra): PairExtra {
  return extra.startedAt === undefined
    ? { ...extra, startedAt: (ctx.mono ?? (() => performance.now()))() }
    : extra
}

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
  /** The resume token: single-use (a resume or a busy answer replaces it), and dead once the pairing is dropped. */
  token: string
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
  /** True when the host cannot elicit (omp): its questions go over the extension's registered link (ask.ts). */
  linked = false
  /** omp: the invite code's widget (a show), withdrawn when the pairing ends in any way. */
  show: AbortController | null = null
  /** omp's acceptor: the paste is still to be asked (no answer yet), and the inviter it must be (pair_accept for). */
  paste = false
  only: string | undefined = undefined
  /** omp's acceptor: the check digits held for the next call's Yes/No (one question per call). */
  digits: string | null = null
  /** omp's inviter: the digits typed wrong so far, across calls (a no answer is not a try). */
  tries = 0
  /** Aborted by pair_cancel, on the person's word: the edge ends the pairing cancelled (edge pairing.ts). */
  readonly stop = new AbortController()
  /** True once the edge's run is under way (#settle): before it, a first call's own step ends on the aborted signal. */
  running = false
  /** The relays that did not take a record of this identity's, one entry for each relay and kind. */
  readonly lagging: Lagging[] = []
  /**
   * The service connection that started it (its dialogs, bridge, cancel and resume are that one's); null in stdio. Its
   * close or unbind ends the pairing through the binding table (binding.ts servicePairings, endFor).
   */
  conn: ServiceConnection | null = null
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
  /** Told after each start, end or drop of this identity's pairing: the service rewrites service.json's count. */
  #watcher: () => void = () => {}

  constructor(ctx: ToolContext, all: Pairings[] = []) {
    this.#ctx = ctx
    this.#all = all
    all.push(this)
  }

  /** Sets who hears each start, end or drop of this identity's pairing (binding.ts servicePairings). */
  watch(fn: () => void): void {
    this.#watcher = fn
  }

  /** Tells the watcher that busy(true) may have changed; its failure never fails the pairing. */
  #moved(): void {
    try {
      this.#watcher()
    } catch {}
  }

  /** pair_invite: open an invitation and hand it over in a dialog, or (resume) wait for its request and admit it. */
  invite(
    a: {
      name?: Opt<string>
      for?: Opt<string>
      ttl?: Opt<number>
      resume?: Opt<string>
    },
    extra: PairExtra,
    conn?: ServiceConnection,
  ): Promise<Json> {
    return this.#watched(a.resume, extra, () => this.#invite(a, extra, conn))
  }

  /** pair_invite's body. */
  async #invite(
    a: {
      name?: Opt<string>
      for?: Opt<string>
      ttl?: Opt<number>
      resume?: Opt<string>
    },
    extra: PairExtra,
    conn?: ServiceConnection,
  ): Promise<Json> {
    const { resume, ...rest } = a
    extra = started(this.#ctx, extra)
    if (resume !== undefined) return this.#resume('pair_invite', resume, rest, extra, conn)
    // for naming this identity's own address in the bag service: hide it from the home's others, or show it again.
    if (a.for !== undefined && this.#ctx.local !== undefined && a.for === this.#ctx.opened.identity.address)
      return this.#visibility(extra, conn)
    // for naming an identity of this home, with the home word on: the local pair, one dialog and nothing else.
    const local = a.for === undefined ? null : (this.#ctx.local?.own(this.#ctx.config.label, a.for) ?? null)
    const shut =
      local === null ? undefined : [this.#ctx.config.label, local].find((l) => this.#ctx.local?.hidden(l))
    if (shut !== undefined)
      throw new ToolError(
        LOCAL_HIDDEN,
        `hidden: ${shut} is kept apart from this home's other identities; ${SHOW_HOW}`,
      )
    if (local !== null) return this.#localPair(local, extra, conn)
    const live = this.#start('pair_invite', a.name, a.for, conn)
    if (live.linked) return this.#linkInvite(live, a.for, a.ttl)
    const only = a.for ?? (await this.#first(live, this.#boundPeer(live, extra), true))
    const { keys, relay, key } = await this.#first(live, this.#keys(live))
    const opened = Promise.withResolvers<{ text: string; exp: number }>()
    const run = invitePeer(this.#ports(live), {
      relay,
      relays: this.#ctx.config.relays,
      keys,
      ...key,
      ttl: a.ttl ?? MAX_INVITE_TTL,
      rendezvous: this.#ctx.config.rendezvous ?? noRelays(this.#ctx.config),
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
      signal: live.stop.signal,
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

  /**
   * pair_invite with `for` an own identity (spec/SPEC.md 9.2 item 1): allowed answers already allowed; requested,
   * local-pair-pending; none asks now (a request in its window, nothing held). Declined, in cooling, first asks this
   * window's own person, within 3 per cooling and one per 10 minutes, then the request.
   */
  async #localPair(peer: string, extra: PairExtra, conn: Opt<ServiceConnection>): Promise<Json> {
    const ctx = this.#ctx
    const self = ctx.config.label
    const local = ctx.local as NonNullable<ToolContext['local']>
    const { state, row } = local.pairState(self, peer)
    if (state === 'allowed') return { local: true, peer, pair: 'allowed', note: 'already allowed' }
    if (state === 'requested')
      throw new ToolError(LOCAL_PENDING, `already asked: waiting for ${peer} to allow it`)
    if (state === 'declined') {
      const wait = local.reask(self, peer, null)
      if (wait !== null) throw new ToolError(LOCAL_DECLINED, `${peer} declined: ask again in ${wait} s`)
      // The time of the No (the declined row's at), never the time of this re-ask.
      const at = new Date((row?.at ?? ctx.clock.now()) * 1000).toISOString().slice(11, 16)
      const message = `Ask ${peer} again to allow messages from ${self}? You declined at ${at}.`
      const yes = await this.#localConfirm(
        extra,
        conn,
        this.#peer(peer, ''),
        { title: `Yes: ask ${peer}`, message },
        'local-reask',
      )
      if (yes === null) throw new ToolError('cancelled', UNANSWERED)
      local.reask(self, peer, yes)
      if (!yes) throw new ToolError('declined', 'not asked again: nothing was changed')
    } else local.request(self, peer)
    return { local: true, peer, pairing: 'requested', note: REQUESTED_NOTE(peer) }
  }

  /** The dialog of a local pair request in this window (askPending): a yes or no, or a throw when none is shown. */
  confirmLocal(
    extra: PairExtra,
    conn: Opt<ServiceConnection>,
    peer: ConsentPeer,
    words: ConsentWords,
  ): Promise<boolean | null> {
    return this.#localConfirm(started(this.#ctx, extra), conn, peer, words)
  }

  /**
   * Hide or show this identity to the home's other identities (spec/SPEC.md 9.2 item 1): pair_invite with `for` its own
   * address asks the person in one dialog (HIDE_WORDS, SHOW_WORDS); only their Yes writes run/local.json, never a
   * tool argument.
   */
  async #visibility(extra: PairExtra, conn: Opt<ServiceConnection>): Promise<Json> {
    const ctx = this.#ctx
    const self = ctx.config.label
    const local = ctx.local as NonNullable<ToolContext['local']>
    const hidden = local.hidden(self)
    const key = `${ctx.config.home} ${self}`
    const wait = (SHOW_ASKED.get(key) ?? -SHOW_EVERY_S) + SHOW_EVERY_S - ctx.clock.now()
    if (hidden && wait > 0)
      throw new ToolError('busy', `a show dialog for ${self} was asked lately: ask again in ${wait} s`)
    if (hidden) SHOW_ASKED.set(key, ctx.clock.now())
    const words = hidden
      ? { title: `Yes: let ${self} reach them again`, message: SHOW_WORDS(self) }
      : { title: `Yes: keep ${self} apart`, message: HIDE_WORDS(self) }
    const me = this.#peer(self, ctx.opened.identity.address)
    // Only the person's explicit No is declined; no answer (a fast decline, a timeout, a cancel) is cancelled (q2).
    const yes = await this.#localConfirm(extra, conn, me, words, hidden ? 'local-show' : 'local-hide')
    if (yes === null) throw new ToolError('cancelled', UNANSWERED)
    if (!yes) throw new ToolError('declined', 'not confirmed: nothing was changed')
    local.setHidden(self, !hidden)
    this.#audit('accept', hidden ? 'local-shown' : 'local-hidden', null, { name: self })
    return { local: true, hidden: !hidden, note: hidden ? SHOWN_NOTE : HIDDEN_NOTE }
  }

  /**
   * One yes or no for a local act, in the asking window (ask.ts askPerson): its elicitation, or with none (omp) the
   * question over its extension's registered consent link, else no-elicitation. True for Yes, false for the person's
   * own No, null for no answer (a closed dialog, a timeout, an aborted confirm, a decline faster than a person): only a
   * No declines (L1).
   */
  async #localConfirm(
    extra: PairExtra,
    conn: Opt<ServiceConnection>,
    _peer: ConsentPeer,
    words: ConsentWords,
    act = 'local-pair',
  ): Promise<boolean | null> {
    // The local pair request (askPending) is paced by the service and asked at every call until answered: unlimited.
    const limit = act !== 'local-pair'
    const q = { act, kind: 'confirm' as const, title: words.title, message: words.message, limit }
    const a = await askPerson(this.#ctx, extra, q, conn)
    if (a === null) throw new ToolError('no-elicitation', OLD_EXTENSION)
    return a.said === 'yes' ? true : a.said === 'no' ? false : null
  }

  /** pair_accept: take the pasted invite string, show this side's code and send the request; or (resume) wait. */
  accept(
    a: { name?: Opt<string>; for?: Opt<string>; resume?: Opt<string> },
    extra: PairExtra,
    conn?: ServiceConnection,
  ): Promise<Json> {
    return this.#watched(a.resume, extra, () => this.#accept(a, extra, conn))
  }

  /**
   * A first call's run. When the client cancels the call (omp's own timeout among them), its result never reaches the
   * model, and that result is the pairing's only handle: so the pairing this call started ends at the abort itself, as
   * pair_cancel ends it, and nothing is written; the window's next call starts afresh. A resume is not watched: its
   * caller already holds a token, and busy in its window hands out a fresh one.
   */
  async #watched(resume: Opt<string>, extra: PairExtra, run: () => Promise<Json>): Promise<Json> {
    if (resume !== undefined) return run()
    const before = this.#live
    // The rule this rests on: #invite and #accept must reach #start before their first await, or this call cannot
    // tell which pairing it started. Then the pairing this call started, if any, is this.#live once run() returns
    // its promise. Only that one is ended: a call that started none (busy, the local pair, the visibility dialog)
    // must never end a pairing another window started meanwhile.
    const running = run()
    const mine = this.#live !== before ? this.#live : null
    const gone = (): void => {
      const live = this.#live
      if (live === null || live !== mine || live.over || live.end !== null) return
      void this.#stop(live, 'client-abort').catch((e: unknown) =>
        this.#ctx.log.log('warn', 'pair-ended', { tool: live.tool, code: codeOf(e) }),
      )
    }
    extra.signal.addEventListener('abort', gone, { once: true })
    try {
      return await running
    } finally {
      // From here to the SDK's own check of the signal there are only promise steps, no I/O, so an abort that can
      // still drop this result is already visible now.
      if (extra.signal.aborted) gone()
      extra.signal.removeEventListener('abort', gone)
    }
  }

  /** pair_accept's body. */
  async #accept(
    a: { name?: Opt<string>; for?: Opt<string>; resume?: Opt<string> },
    extra: PairExtra,
    conn?: ServiceConnection,
  ): Promise<Json> {
    const { resume, ...rest } = a
    extra = started(this.#ctx, extra)
    if (resume !== undefined) return this.#resume('pair_accept', resume, rest, extra, conn)
    const live = this.#start('pair_accept', a.name, a.for, conn)
    if (live.linked) {
      live.only = a.for
      return this.#paste(live, extra, true)
    }
    const v = await this.#first(
      live,
      (async () => {
        const form = await this.#form(
          live,
          extra,
          `${this.#line('Paste the code or invite string your peer sent.', (l) => `As ${l}: paste your peer's code.`)}\nSpaces, hyphens and line breaks are fine.\nThey will be named ${fitName(live.name, 35)} here.`,
          { invite: { type: 'string', title: 'the code or invite string' }, ...ADDRESS },
          ['invite'],
          true,
        )
        const only = a.for ?? addressIn(form)
        // One check of every pasted text (ask.ts textOf): printable, line breaks folded as the
        // dialog promises, at most MAX_PASTE. Then the raw paste: the edge normalises a code (case, spaces, hyphens; claimed at --rendezvous, or at the host of
        // a code typed as code@host) and drops an invite string's whitespace. A claim consumes no invitation, so a
        // not-for below leaves it open.
        const invite = await inviteOf(
          this.#ports(live),
          this.#ctx.config.rendezvous ?? noRelays(this.#ctx.config),
          pastedOf(form.invite, true),
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
      relays: this.#ctx.config.relays,
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
      signal: live.stop.signal,
    }).catch((e: unknown) => {
      throw usedInvite(e)
    })
    this.#settle(live, 'decline', run, () => this.#paired(live, v.inviter))
    const exp = await this.#first(live, Promise.race([sent.promise, run.then(() => sent.promise)]))
    return { requested: true, expires_at: iso(exp), resume: live.token, note: NOT_PAIRED }
  }

  /**
   * pair_cancel, on the person's word: ends the pairing running on this server (across its identities, as busy counts
   * them), an invite this side opened or an accept it waits on. `resume`, when given, must name it, else usage. The
   * edge ends it cancelled: an invitation still waiting for a request is withdrawn at the rendezvous (I's address record, the one-time invitation identity's and never the
   * inviter's own, re-signed with no sealing key: its code then meets
   * invite-expired), a held request is answered no, a wait for the peer's admit stops and the roots go back; an open
   * question and the code's widget on omp are withdrawn. Nothing is written. It waits for the edge to end (at most CANCEL_WAIT_S), and answers
   * {cancelled: true, was}; with nothing running, {cancelled: false}: the person's word holds already, and a refusal
   * would read as a failure to cancel. A pairing that finished first answers {cancelled: false} and its end. It asks
   * no one: the tool text tells the model to call it only when its person asks, and busy in the starting window
   * offers a resume instead.
   */
  async cancel(a: { resume?: Opt<string> }, conn?: ServiceConnection): Promise<Json> {
    // On a service connection only this identity's pairing counts, and only the window that started it cancels it.
    const owner = conn === undefined ? this.#all.find((p) => p.#live !== null && p.#live.end === null) : this
    const live = owner === undefined ? null : owner.#live
    // A pairing already being ended here (over: a client's abort or a close, its edge still winding down) is not
    // ended twice: the person's word holds already, and a second audit line would read as a second end.
    if (owner === undefined || live === null || live.end !== null || live.over) return { cancelled: false }
    if (live.conn !== null && live.conn !== conn)
      throw new ToolError('not-authorized', `this pairing runs in ${windowOf(live.conn)}: cancel it there`)
    if (a.resume !== undefined && a.resume !== live.token)
      throw new ToolError(
        'usage',
        'resume names no running pairing: pass the resume of the running one, or none',
      )
    return owner.#stop(live, 'cancel')
  }

  /**
   * Ends the running pairing of `conn`, and only that connection's, as pair_cancel does: the service calls it for a
   * connection's close or an unbind (never without a connection: one window's close never ends another's pairing).
   * Its codes and digits die with it.
   */
  endFor(conn: ServiceConnection): void {
    const live = this.#live
    if (live === null || live.end !== null || live.over || live.conn !== conn) return
    void this.#stop(live, 'close').catch((e: unknown) =>
      this.#ctx.log.log('warn', 'pair-ended', { tool: live.tool, code: codeOf(e) }),
    )
  }

  /**
   * pair_cancel's work on `live`, also a window's close and a client's abort of the first call (`why`): refused,
   * aborted, its open question and widget withdrawn, waited on at most CANCEL_WAIT_S, audited with the why and the
   * window. The abort carries the why, so the service's log can tell a cancel from a close or the client's abort.
   */
  async #stop(live: Live, why: StopWhy): Promise<Json> {
    const was = live.tool === 'pair_accept' ? 'accept' : 'invite'
    live.refusal = new ToolError('cancelled', STOPPED[why])
    live.over = true
    live.stop.abort({ why })
    live.answer(false)
    this.#unshow(live)
    const { timers } = this.#ctx
    let due = false
    const stop = timers.after(CANCEL_WAIT_S * 1000, () => {
      due = true
      live.poke()
    })
    try {
      while (live.running && live.end === null && !due) await live.changed()
    } finally {
      stop()
    }
    const end = live.end as { readonly value?: Json } | null
    if (end?.value !== undefined) {
      this.#drop(live)
      return { cancelled: false, ...end.value }
    }
    const window = live.conn === null ? {} : { window: `${live.conn.host} ${live.conn.cwd}` }
    this.#audit('reject', live.tool === 'pair_accept' ? 'decline' : 'refuse', live.from, {
      code: 'cancelled',
      reason: why,
      ...window,
    })
    this.#drop(live)
    return { cancelled: true, was }
  }

  /** The window running this identity's pairing, while one runs that a window started; else null. */
  runningIn(): ServiceConnection | null {
    const live = this.#live
    return live === null || live.end !== null || live.over ? null : live.conn
  }

  /**
   * The service's drain: ends the pairing running here as the service, past pair_cancel's window check (only the
   * window that started a pairing cancels it), as that window's close would: refused, withdrawn, audited as a close,
   * waited on as pair_cancel waits.
   */
  async drainStop(): Promise<void> {
    const live = this.#live
    if (live === null || live.end !== null || live.over) return
    await this.#stop(live, 'close')
  }

  /**
   * True while a pairing of this server has not ended: one runs at a time across its identities. In the service
   * (`service`) busy is per identity: two identities pair at once from two windows.
   */
  busy(service = false): boolean {
    if (service) return this.#live !== null && this.#live.end === null
    return this.#all.some((p) => p.#live !== null && p.#live.end === null)
  }

  /**
   * The console's ceremony (console.ts): pair_invite's invitePeer on this identity's keys and relay, with
   * the console's person in the inviter's seat (runPairing checks the digits typed there). It holds the server's one
   * pairing until the edge ends; it writes nothing, for runPairing writes after it (as the CLI's `bag pairings`).
   */
  readonly consoleInvite: PairingPorts['invite'] = async (o) => {
    if (this.busy()) throw new ToolError('busy', 'a pairing is running')
    const live = new Live('console', toHex(this.#ctx.rng.bytes(16)), 'console', () => {})
    this.#live = live
    this.#moved()
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
        rendezvous: o.relay ?? this.#ctx.config.rendezvous ?? at,
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
        signal: live.stop.signal,
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
    return addressIn(await this.#form(live, extra, message, ADDRESS, [], true))
  }

  /** A new resume token: 128 random bits, kept only in memory. */
  #token(): string {
    return toHex(this.#ctx.rng.bytes(16))
  }

  /** Replaces `live`'s token with a fresh one, so the one it had is dead: a token serves one call. */
  #fresh(live: Live): string {
    live.token = this.#token()
    return live.token
  }

  /** The checks before any dialog or network (no-elicitation, name, for, busy, a held name), then the live pairing. */
  #start(tool: string, name: Opt<string>, only: Opt<string>, conn: Opt<ServiceConnection>): Live {
    const ctx = this.#ctx
    // A Codex below CODEX_FLOOR shows only a dialog's message. A compatibility gate, never a trust boundary: the
    // version is the client's own word, so this grants nothing, and a spoofed one still meets the person's dialogs.
    // A service connection's hello names its host kind and no version, so the gate does not apply there.
    const client =
      conn === undefined
        ? (ctx.client?.() ?? { kind: 'other', version: '' })
        : { kind: conn.host, version: '' }
    const core = versionCore(client.version)
    const old = core?.map((n, i) => n - (CODEX_FLOOR[i] as number)).find((d) => d !== 0) ?? 0
    if (client.kind === 'codex' && old < 0)
      throw new ToolError('no-elicitation', noDialog('codex', 'version', (core as number[]).join('.')))
    // This host cannot show a dialog (omp has no elicitation at all). An omp window of the bag service asks over its
    // extension's registered link (ask.ts; with none, its first question is no-elicitation, OLD_EXTENSION). With no
    // service (the per-folder form) or another host, there is no link: name the host's setting, never a silent
    // decline and never a terminal command (noDialog). Never a file.
    const linked = conn === undefined ? !ctx.canElicit() : !conn.capabilities.elicitation
    if (linked && (conn === undefined || conn.host !== 'omp' || ctx.local === undefined))
      throw new ToolError('no-elicitation', noDialog(client.kind, 'none'))
    if (name === undefined || !NAME.test(name))
      throw new ToolError('usage', `name is the peer's petname (${NAME.source})`)
    if (only !== undefined && !isAddress(only)) throw new ToolError('usage', 'for takes an address')
    if (this.busy(conn !== undefined)) {
      const live = this.#live
      const own = live !== null && (conn === undefined ? live.conn === null : live.conn === conn)
      // This window's own pairing has ended and its edge is winding down (at most CANCEL_WAIT_S): try again soon.
      if (own && live.over && live.end === null) throw new ToolError('busy', CLOSING)
      // The starting window alone gets a token, a fresh one (the one it had is dead from here): on the service the
      // window whose connection started it, in stdio the identity whose own pairing runs. Any other window has no use
      // for one, and a token in its model's context could only be carried on.
      const here =
        live !== null &&
        live.end === null &&
        !live.over &&
        (live.tool === 'pair_invite' || live.tool === 'pair_accept') &&
        (conn === undefined ? live.conn === null : live.conn === conn)
      if (here) throw new ToolError('busy', BUSY_HERE(live.tool), { resume: this.#fresh(live) })
      const at = live?.conn
      throw new ToolError(
        'busy',
        at === null || at === undefined ? BUSY : `${BUSY} (it runs in ${windowOf(at)})`,
      )
    }
    const { home } = ctx.config
    // Before a code goes out or a person is asked, for the peer's address may come only with its request, after the
    // whole ceremony: a held name goes on only under for, its own address. #held and the paste check a name taken since.
    Names.read(home).check(name, only)
    // Each start opens something at the relay or asks the person, and a client that cancels every first call ends
    // each one: bound them per window, and past the bound start nothing.
    countStart(ctx, conn)
    const write = (peer: string): void => {
      // The book as it is now: a pairing runs for minutes, and a save writes back what it read and checks against it.
      Names.read(home).save(name, peer, ctx.clock.now())
      addTrust(home, peer, ctx.clock.now())
    }
    const live = new Live(tool, this.#token(), name, write)
    live.linked = linked
    if (conn !== undefined) live.conn = conn
    this.#live = live
    this.#moved()
    return live
  }

  /**
   * omp's acceptor: the person pastes the peer's code into omp's input over the link
   * (so the code is never a tool argument); the code is checked (ask.ts textOf, then the edge's inviteOf), and the edge
   * runs until it has the six check digits, which it holds for the next call's Yes/No: one question per call. No answer leaves the paste
   * to ask again at the next resume, until MAX_INVITE_TTL; only the person's No declines. `first`: pair_accept's own
   * call, whose refusals end the pairing (a resume's rate-limited does not).
   */
  async #paste(live: Live, extra: PairExtra, first: boolean): Promise<Json> {
    const ctx = this.#ctx
    try {
      const title = this.#line("bag: paste your peer's pairing code", (l) => `bag: as ${l}, paste the code`)
      const q = {
        act: 'pair-accept-code',
        kind: 'text' as const,
        title,
        message: `The code or invite string your peer sent.\nThey will be named ${fitName(live.name, 35)} here.`,
        placeholder: 'invite or code',
        max: MAX_PASTE,
        // A long invite string copied from omp's wrapped widget carries a break at every wrap: fold them (Ask.fold).
        fold: true,
      }
      const a = await askPerson(ctx, this.#within(live, extra), q, live.conn ?? undefined)
      if (live.over) throw live.refusal ?? new ToolError('cancelled', 'the pairing ended')
      if (a === null) throw new ToolError('no-elicitation', OLD_EXTENSION)
      if (a.said === 'no') throw new ToolError('declined', 'the person declined: nothing was written')
      if (a.said === 'none') {
        if (!live.paste) {
          live.paste = true
          ctx.timers.after(MAX_INVITE_TTL * 1000, () => {
            if (this.#live !== live || live.end !== null || !live.paste) return
            const expired = new ToolError(
              'invite-expired',
              'no code was pasted in time: start pair_accept again',
            )
            live.over = true
            // A resume's paste question still open is withdrawn now and answers this, as the audit line says.
            live.refusal = expired
            live.end = { error: expired }
            this.#moved()
            this.#audit('reject', 'decline', null, { code: 'invite-expired' })
            live.stop.abort({ why: 'ended' })
            live.poke()
          })
        }
        return { requested: false, asked: true, resume: live.token, note: LINK_AGAIN }
      }
      live.paste = false
      const v = await inviteOf(
        this.#ports(live),
        ctx.config.rendezvous ?? noRelays(ctx.config),
        pastedOf(a.text, false),
      )
      refuseLinks(ctx, { to: v.inviter })
      if (live.only !== undefined && v.inviter !== live.only)
        throw new ToolError(
          'not-for',
          `that invitation is from ${v.inviter}, not ${live.only}: nothing was sent`,
        )
      Names.read(ctx.config.home).check(live.name, v.inviter)
      live.from = v.inviter
      const { keys, relay, key } = await this.#keys(live)
      const run = acceptPeer(this.#ports(live), keys, relay, v, {
        ...key,
        relays: ctx.config.relays,
        ask: (code) => this.#holdDigits(live, code),
        sent: (exp) => {
          live.exp = exp
        },
        write: () => live.write(v.inviter),
        signal: live.stop.signal,
      }).catch((e: unknown) => {
        throw usedInvite(e)
      })
      this.#settle(live, 'decline', run, () => this.#paired(live, v.inviter))
    } catch (e) {
      if (live.over || (!first && e instanceof ToolError && e.code === 'rate-limited')) throw e
      this.#end(live, live.from, e)
      throw e
    }
    while (live.digits === null && live.end === null) await live.changed()
    if (live.end !== null) {
      this.#drop(live)
      if ('error' in live.end) throw live.end.error
      return live.end.value
    }
    return { requested: false, asked: true, resume: live.token, note: LINK_DIGITS }
  }

  /** The edge's ask on omp: the check digits held for the next call's Yes/No, until the invitation's longest life. */
  #holdDigits(live: Live, code: string): Promise<void> {
    // Ended under the edge's read (a cancel, or the client's abort of the first call): nothing is held or asked.
    if (live.over) return Promise.reject(live.refusal ?? new ToolError('cancelled', 'the pairing ended'))
    const { promise, resolve, reject } = Promise.withResolvers<void>()
    const late = (): void => {
      live.refusal ??= new ToolError(
        'invite-expired',
        'the check digits were not confirmed before the invitation ended',
      )
      live.answer(false)
    }
    const cancel = this.#ctx.timers.after(MAX_INVITE_TTL * 1000, late)
    live.answer = (yes) => {
      live.answer = () => {}
      live.digits = null
      cancel()
      if (yes) resolve()
      else
        reject(
          live.refusal ??
            new ToolError('declined', 'the check digits were not confirmed: no request was sent'),
        )
    }
    live.digits = code
    live.poke()
    return promise
  }

  /** omp's acceptor at a resume: the check digits' Yes/No over the link. Yes sends the request; none asks again later. */
  async #linkDigits(live: Live, extra: PairExtra): Promise<'done' | 'unanswered'> {
    const code = live.digits as string
    const digits = this.#line(`Check digits: ${code}`, (l) => `As ${l}, check digits: ${code}`)
    const to = shortAddress(live.from ?? '')
    const q = {
      act: 'pair-accept',
      kind: 'confirm' as const,
      title: 'bag: read these check digits to your peer',
      message: `${digits}\nSecurity check: read them out, not where the code was sent.\nYes sends the request to ${to}.`,
    }
    const a = await askPerson(this.#ctx, this.#within(live, extra), q, live.conn ?? undefined)
    if (live.over) throw live.refusal ?? new ToolError('cancelled', 'the pairing ended')
    if (a === null) {
      const e = new ToolError('no-elicitation', OLD_EXTENSION)
      live.refusal ??= e
      live.answer(false)
      throw e
    }
    if (a.said === 'none') return 'unanswered'
    live.answer(a.said === 'yes')
    return 'done'
  }

  /**
   * omp's inviter: the edge opens the invitation and omp shows the code in its bag widget (a show over the link)
   * until the pairing ends in any way; the peer's request is held for a resume's typed digits (#held, #compare). The
   * first result carries no code. A link that cannot show is no-elicitation before any invitation opens.
   */
  async #linkInvite(live: Live, only: Opt<string>, ttl: Opt<number>): Promise<Json> {
    if (!this.#show(live, [makingLine(live.name)], 60_000)) {
      this.#drop(live)
      throw new ToolError('no-elicitation', OLD_EXTENSION)
    }
    const { keys, relay, key } = await this.#first(live, this.#keys(live))
    const opened = Promise.withResolvers<{ text: string; exp: number }>()
    const run = invitePeer(this.#ports(live), {
      relay,
      relays: this.#ctx.config.relays,
      keys,
      ...key,
      ttl: ttl ?? MAX_INVITE_TTL,
      rendezvous: this.#ctx.config.rendezvous ?? noRelays(this.#ctx.config),
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
      signal: live.stop.signal,
    })
    this.#settle(live, 'refuse', run, (q) => this.#paired(live, q.from))
    const { text, exp } = await this.#first(
      live,
      Promise.race([opened.promise, run.then(() => opened.promise)]),
    )
    // Ended while the invitation opened (the client's abort, a cancel): the code is never shown, and the edge
    // withdraws the invitation.
    if (live.over) throw live.refusal ?? new ToolError('cancelled', 'the pairing ended')
    const ms = Math.max(0, exp - this.#ctx.clock.now()) * 1000
    this.#show(live, inviteLines(live.name, text), ms)
    return { invite_open: true, expires_at: iso(exp), resume: live.token, note: BRIDGE_SHOW }
  }

  /** The call's extra with its signal also aborted by the pairing's own end (pair_cancel, a close): asks withdraw. */
  #within(live: Live, extra: PairExtra): PairExtra {
    return { ...extra, signal: AbortSignal.any([extra.signal, live.stop.signal]) }
  }

  /** Shows `lines` in omp's bag widget over the link, replacing any show of this pairing; false when it cannot. */
  #show(live: Live, lines: readonly string[], ms: number): boolean {
    const local = this.#ctx.local
    if (live.conn === null || local === undefined || live.over) return false
    this.#unshow(live)
    const ctl = new AbortController()
    const q = {
      act: 'pair-show',
      kind: 'show' as const,
      title: 'bag: pairing',
      message: lines[0] ?? '',
      lines,
      ms,
    }
    const shown = local.consent(live.conn, q, AbortSignal.any([ctl.signal, live.stop.signal]))
    if (shown === null) return false
    live.show = ctl
    void shown.then(() => {
      if (live.show === ctl) live.show = null
    })
    return true
  }

  /** Clears the pairing's widget at once (service/consent-withdraw): at its end, its cancel, its expiry. */
  #unshow(live: Live): void {
    live.show?.abort({ why: 'ended' })
    live.show = null
  }

  /** A consent request's peer block: its petname, address and root (the address; a domain root stays the CLI's). */
  #peer(name: string, address: string): ConsentPeer {
    return { name, address, root: address }
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
    // Before any key read or client call: every wire pairing (the console's too) passes here.
    const relay = config.relays[0] ?? noRelays(config)
    const keys = new HomeCustody(config.home).keys(config.as)
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
    const own = [...config.relays, ...[config.rendezvous ?? []].flat(), ...more]
    const guard = new RelayGuard({ own, allowPrivate: config.allowPrivateRelays })
    return {
      client: opened.client,
      clock,
      rng,
      pollMs,
      guard,
      continueFrom: (found: AddressRecord | null) => continueFrom(found, home, as, opened.signer.address),
      keepAddress: (r: AddressRecord) => keepAddressCopy(home, as, r),
      continueFromAccept: (found: AcceptFromRecord | null) =>
        heldAccept(found, home, as, opened.signer.address),
      keepAccept: (r: AcceptFromRecord) => keepAcceptCopy(home, as, r),
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
      // A pairing already ended here (#stop) was audited there: one line per end.
      if (audit && !live.over) this.#end(live, live.from, e)
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
    live.running = true
    run
      .then(
        (value) => {
          live.end = { value: done(value) }
          this.#moved()
          this.#audit('accept', step === 'refuse' ? 'admit' : 'accept', live.from, { name: live.name })
        },
        (e: unknown) => {
          const error = live.refusal ?? e
          live.end = { error }
          this.#moved()
          if (live.over) this.#ctx.log.log('info', 'pair-ended', { tool: live.tool, code: codeOf(e) })
          else this.#audit('reject', step, live.from, { code: codeOf(error) })
        },
      )
      .catch((e: unknown) => this.#ctx.log.log('warn', 'pair-ended', { tool: live.tool, code: codeOf(e) }))
      .finally(() => {
        this.#unshow(live)
        live.poke()
      })
  }

  /** Ends a pairing here: the held ask is no, nothing is written, the refusal is audited once and the state dropped. */
  #end(live: Live, from: string | null, e: unknown): void {
    live.over = true
    live.answer(false)
    this.#drop(live)
    this.#audit('reject', live.tool === 'pair_invite' ? 'refuse' : 'decline', from, { code: codeOf(e) })
  }

  #drop(live: Live): void {
    this.#unshow(live)
    if (this.#live === live) {
      this.#live = null
      this.#moved()
    }
  }

  /**
   * A resume call: it opens the inviter's compare dialog when a request is held, else blocks at most the window for
   * the pairing to end (progress as wait's), and answers pending while it has not. A dialog answered starts the window
   * again, for the admit that follows takes a moment and this call must not answer pending for a pairing that just
   * finished: in a real run a model read that as "the peer has not responded".
   */
  async #resume(
    tool: string,
    token: string,
    rest: Json,
    extra: PairExtra,
    conn: Opt<ServiceConnection>,
  ): Promise<Json> {
    if (Object.values(rest).some((v) => v !== undefined))
      throw new ToolError('usage', 'resume continues a pairing: pass resume alone')
    const live = this.#live
    // Another window's pairing is no live pairing of this one: its dialogs never open here.
    const other = live !== null && live.conn !== (conn ?? null)
    // A pairing ended here and still winding down (over, no end recorded yet: a cancel, a close, a client's abort) is
    // no live pairing: its token is dead at once. One with its end recorded (the paste's expiry) reports it below, once.
    const closing = live?.over === true && live.end === null
    if (live === null || other || closing || live.token !== token || live.tool !== tool)
      throw new ToolError('usage', `resume names no live pairing of ${tool}: start a new one`)
    // The token is spent by this call: every answer that leaves the pairing running carries the next one.
    this.#fresh(live)
    try {
      return await this.#resumed(tool, live, extra)
    } catch (e) {
      // A refusal that leaves the pairing running (rate-limited) carries the next token too, or the window has none.
      const running = this.#live === live && live.end === null && !live.over
      if (running && e instanceof ToolError && e.more.resume === undefined)
        throw new ToolError(e.code, detailOf(e, e.code), { ...e.more, resume: live.token })
      throw e
    }
  }

  /** A resume call's wait and questions, on the pairing its token named (#resume). */
  async #resumed(tool: string, live: Live, extra: PairExtra): Promise<Json> {
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
        const remaining_s = (): number => Math.max(0, live.exp - clock.now())
        if (q !== null) {
          live.ask = null
          if ((await this.#compare(live, q, extra)) === 'unanswered')
            return { pending: true, resume: live.token, remaining_s: remaining_s(), note: LINK_AGAIN }
          cancel()
          due = extra.signal.aborted
          cancel = timers.after(window * 1000, stop)
          continue
        }
        // omp (one question per call): the paste not yet answered, or the acceptor's check digits held.
        if (live.linked && live.paste) return await this.#paste(live, extra, false)
        if (live.linked && live.digits !== null) {
          if ((await this.#linkDigits(live, extra)) === 'unanswered')
            return { pending: true, resume: live.token, remaining_s: remaining_s(), note: LINK_AGAIN }
          cancel()
          due = extra.signal.aborted
          cancel = timers.after(window * 1000, stop)
          continue
        }
        if (due) {
          const note = tool === 'pair_accept' ? NOT_PAIRED : STILL_WAITING
          return { pending: true, resume: live.token, remaining_s: remaining_s(), note }
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
  async #compare(live: Live, q: PeerRequest, extra: PairExtra): Promise<'done' | 'unanswered'> {
    if (live.linked) return this.#linkCompare(live, q, extra)
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
        if (live.refusal !== null) return 'done' // The invitation ended under the dialog: its timer has answered no.
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
    return 'done'
  }

  /**
   * omp's inviter compare, over the link: its person types the six digits the peer reads out, in omp's input. A typed
   * mismatch counts one of MAX_DIGIT_TRIES across calls; no answer counts none and holds the request for the next
   * resume ('unanswered'). As #compare, no question shows the digits or says what they should be.
   */
  async #linkCompare(live: Live, q: PeerRequest, extra: PairExtra): Promise<'done' | 'unanswered'> {
    const peer = peerLines(q.from, live.name)
    try {
      for (;;) {
        const hint =
          live.tries === 0
            ? 'Your peer reads them out, not where the code was sent.'
            : `No match. Tries left: ${MAX_DIGIT_TRIES - live.tries}. Ask your peer to repeat them.`
        const six = (t: string): string | null => {
          const d = t.replace(/[\s-]/g, '')
          return /^\d{6}$/.test(d) ? d : null
        }
        const ask = {
          act: 'pair-digits',
          kind: 'text' as const,
          title: this.#line(
            'bag: type the six digits your peer reads to you',
            (l) => `bag: as ${l}, type the six digits`,
          ),
          message: `${hint}\n${peer}`,
          placeholder: '123 456',
          max: 16,
          check: six,
        }
        const a = await askPerson(this.#ctx, this.#within(live, extra), ask, live.conn ?? undefined)
        if (a === null) throw new ToolError('no-elicitation', OLD_EXTENSION)
        if (live.refusal !== null) return 'done' // The invitation ended under the question: its timer answered no.
        if (a.said === 'none') {
          live.ask = q
          return 'unanswered'
        }
        if (a.said === 'no') throw new ToolError('declined', 'the person declined: nothing was written')
        if (digitsMatch(a.text ?? '', q.code)) break
        live.tries++
        if (live.tries >= MAX_DIGIT_TRIES)
          throw new ToolError('digits-mismatch', 'the typed digits did not match: nothing was written')
      }
    } catch (e) {
      if (e instanceof ToolError && e.code === 'rate-limited') {
        live.ask = q
        throw e
      }
      this.#end(live, q.from, e)
      throw e
    }
    live.answer(true)
    return 'done'
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

  /**
   * One dialog of `properties`, those in `required` required: what the person gave on accept, else as #dialog says.
   * The `first` dialog of a pairing not accepted within FAST_ANSWER_MS (monotonic) is no-elicitation: no person saw it.
   * Later dialogs keep declined and cancelled at any speed, for a person who saw the first is in the loop.
   */
  async #form(
    live: Live,
    extra: PairExtra,
    message: string,
    properties: Record<string, Field>,
    required: string[] = [],
    first = false,
  ): Promise<Json> {
    const requestedSchema = { type: 'object' as const, properties, required }
    const [mono, failed] = [this.#ctx.mono ?? (() => performance.now()), [] as unknown[]]
    const t0 = mono()
    // A service pairing's dialogs go only to the connection that started it, never to another window that uses the
    // identity (docs/bag-service.md, "Pairing in a window").
    const dialog = { message, requestedSchema }
    const asked =
      live.conn === null
        ? this.#ctx.elicit(dialog, extra)
        : live.conn.elicit(dialog, { signal: extra.signal })
    const r = await asked.catch((e: unknown) => {
      failed.push(e)
      return { action: 'cancel' as const }
    })
    const took = mono() - t0
    const ms = Math.round(took)
    for (const e of failed) {
      const name = e instanceof Error ? e.name : typeof e
      this.#ctx.log.log('warn', 'pair-dialog', { tool: live.tool, code: codeOf(e), name, ms })
    }
    if (r.action === 'accept') return r.content ?? {}
    if (first && took < FAST_ANSWER_MS) {
      this.#ctx.log.log('info', 'pair-dialog', { tool: live.tool, code: 'no-elicitation', ms })
      const kind = live.conn?.host ?? this.#ctx.client?.().kind ?? 'other'
      throw new ToolError('no-elicitation', noDialog(kind, 'fast'))
    }
    if (r.action === 'decline') throw new ToolError('declined', 'the person declined: nothing was written')
    throw new ToolError('cancelled', 'the dialog was closed before an answer: nothing was written')
  }

  /** One `pair` audit line: the step, the peer's address, a code or the name; never S, a code's digits or a key. */
  #audit(decision: 'accept' | 'reject' | 'queue', step: string, from: string | null, more: Json): void {
    const detail = { step, ...more } as Record<string, string>
    this.#ctx.opened.edge.audit.record({ event: 'pair', decision, reason: 'ok', from, detail })
  }
}
