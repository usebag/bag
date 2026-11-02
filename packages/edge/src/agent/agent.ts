import {
  AcError,
  type CaveatEvaluator,
  checkId,
  checkSig,
  type Envelope,
  GROUP_KEY_TYPE,
  type GroupKeyBody,
  type Hop,
  hpkeOpen,
  isCanonicalInteger,
  type OpenerLike,
  openGroupKey,
  openSealed,
  parseEnvelope,
  type SealedContent,
  type SignerLike,
  signHop,
  toHex,
  verifyChain,
  verifyPreimage,
} from '@usebag/core'
import { GENERATIONS_TRIED } from '../groups/member.ts'
import type { Clock, Rng } from '../ports.ts'
import { type AgentAudit, type AgentAuditEntry as Line, openEntry, signEntry } from './audit.ts'
import {
  type AgentCode,
  AgentError,
  type AgentRequest,
  codeOf,
  GROUPS_MAX,
  NONCE_BYTES,
  OPENS_PER_MINUTE,
  type OpenRequest,
  parseRequest,
  requestPreimage,
  SEQ_MAX,
  SIGNS_PER_MINUTE,
  type SignRequest,
  THREADS_PER_SESSION,
  WINDOW_MAX,
} from './model.ts'
import {
  checkDeviceGrant,
  checkGrant,
  type DeviceGrantRequest,
  decideRead,
  deriveHop,
  type GrantRequest,
  grantLimit,
  grantLines,
  hopDigest,
  rootRule,
  type UnsignedHop,
} from './rules.ts'

// The agent's protocol core: the window state and the connection
// ledgers in memory, and one entry per request. The socket, the peer uid, the terminal and the custody are the
// server's (README.md); this class reads only the clock, the rng and the keys it is handed.

/** The held keys for one window: the principal's, or on a device D's own, whose sealing key opens nothing. */
export interface PrincipalKeys {
  readonly signing: SignerLike
  readonly sealing: OpenerLike
}

export interface AgentOptions {
  /** The address of the principal this agent serves; each login hands it that identity's keys. */
  readonly principal: string
  readonly clock: Clock
  readonly rng: Rng
  readonly audit: AgentAudit
  /** The evaluators of the read rule's limb (b); a caveat none of them knows fails closed. */
  readonly evaluators: readonly CaveatEvaluator[]
  /** On a device, the hop P -> D: the held key is D, the agent signs only, no window outlives it. */
  readonly device?: Hop | null
}

/** A session connection: the nonce the server sends the session when the socket opens. */
export type Connection = { readonly nonce: string }
export type AgentRefusal = { readonly ok: false; readonly code: AgentCode }

/** The answer to a session request. On a renewal the server prints one line. */
export type AgentReply =
  | AgentRefusal
  | { readonly ok: true; readonly op: 'sign'; readonly hop: Hop; readonly renewal: boolean }
  | { readonly ok: true; readonly op: 'open'; readonly content: SealedContent }
  | { readonly ok: true; readonly op: 'register' }

/** A first grant checked and waiting for the terminal's answer, with the lines to print first. */
export interface PendingGrant {
  readonly ok: true
  readonly hop: UnsignedHop
  readonly lines: readonly string[]
}

/** The answer to `ac grant`: the signed first grant, a refusal, or the CLI's `declined`. */
export type GrantReply =
  | AgentRefusal
  | { readonly ok: false; readonly code: 'declined' }
  | { readonly ok: true; readonly hop: Hop }

/** `device-grant`'s answer. The hop never enters a grant-set or a dated map, or P's logout revokes D. */
export type DeviceReply = Exclude<GrantReply, { ok: true }> | { readonly ok: true; readonly device: Hop }

/** What `group-key` takes: a received envelope's exact JSON text, or a stored body replayed at login. */
export type GroupKeyIn = { readonly envelope: string } | { readonly body: unknown }

/** `group-key` releases only {group, generation, body}: the body held there (the offered one if dropped). */
export type GroupKeyReply =
  | AgentRefusal
  | { readonly ok: true; readonly group: string; readonly generation: number; readonly body: GroupKeyBody }

/** A chain's authority: `grant`, `hops` and `own` from the held key's hop; `group` a held group's root. */
interface Authority {
  readonly session: string
  readonly hops: number
  readonly caveats: readonly string[]
  readonly own: readonly string[]
  readonly exp: number
  readonly grant: string
  readonly group: string | null
}

type Pending = { readonly w: Window; readonly hop: UnsignedHop; readonly device: boolean }
type Generation = { generation: number; seed: Uint8Array; key: OpenerLike; body: GroupKeyBody }
type Kept = { readonly kept: 'new' | 'renewed' | 'held' | 'dropped'; readonly body: GroupKeyBody }

/** The connection ledger. */
type Ledger = { high: number; auth: Authority | null }

/** The window state: the keys and every fact logout drops. A `first` grant is one a renewal may continue. */
interface Window {
  readonly keys: PrincipalKeys
  readonly end: number
  readonly grants: Map<string, { readonly sub: string; readonly exp: number; readonly first: boolean }>
  readonly threads: Map<string, Set<string>>
  readonly counts: Map<string, { readonly minute: number; readonly n: number }>
  readonly groups: Map<string, Generation[]>
}

const refuse = (code: AgentCode): AgentRefusal => ({ ok: false, code })
const locked = () => new AgentError('agent-locked', 'no login window is open: run ac login')

export class Agent {
  readonly principal: string
  /** The key held and signed under: the principal, or D on a device. */
  readonly held: string
  readonly device: Hop | null
  readonly #o: AgentOptions
  #window: Window | null = null
  readonly #ledgers = new WeakMap<Connection, Ledger>()
  readonly #pending = new WeakMap<PendingGrant, Pending>()

  constructor(options: AgentOptions) {
    this.principal = options.principal
    this.device = options.device ?? null
    this.held = this.device?.sub ?? options.principal
    if (this.device !== null && this.device.iss !== this.principal) throw new Error("not P's device hop")
    this.#o = options
  }

  /** The open window; one past its end is closed first. */
  #open(): Window | null {
    if (this.#window !== null && this.#o.clock.now() >= this.#window.end) this.#drop()
    return this.#window
  }

  /** Drops the window, zeroing every held generation's seed. */
  #drop(): void {
    for (const held of this.#window?.groups.values() ?? []) for (const g of held) g.seed.fill(0)
    this.#window = null
  }

  /** The end of the open window in Unix seconds, or null. */
  windowEnd(): number | null {
    return this.#open()?.end ?? null
  }

  /**
   * `ac login`: opens a window of `seconds`, at most WINDOW_MAX, with the held keys; returns its end. Throws when
   * a window is open, the keys are not the held key's, or `seconds` is not a positive integer; on a device, the hop's
   * codes when it is not live, and the window ends by its `exp`.
   */
  login(keys: PrincipalKeys, seconds: number = WINDOW_MAX): number {
    if (this.#open() !== null) throw new Error('a login window is open')
    const whose = this.device === null ? 'principal' : 'device'
    if (keys.signing.address !== this.held) throw new Error(`the keys are not the ${whose}'s`)
    if (!isCanonicalInteger(seconds) || seconds === 0) throw new Error('a window is whole seconds')
    const now = this.#o.clock.now()
    if (this.device !== null) verifyChain([this.device], this.held, now)
    const end = Math.min(now + Math.min(seconds, WINDOW_MAX), this.device?.exp ?? Number.POSITIVE_INFINITY)
    this.#window = { keys, end, grants: new Map(), threads: new Map(), counts: new Map(), groups: new Map() }
    return end
  }

  /**
   * `ac logout`: drops the keys, the grant-set, the threads and the generations. Returns the sorted subjects of
   * the grants still live, for logout's re-signed address record to revoke. Zeroing the keys is the custody's.
   */
  logout(): readonly string[] {
    const w = this.#open()
    this.#drop()
    const now = this.#o.clock.now()
    const live = [...(w?.grants.values() ?? [])].filter((g) => g.exp >= now).map((g) => g.sub)
    return [...new Set(live)].sort()
  }

  /** A new session connection and its ledger, with a nonce of 32 random bytes. */
  connect(): Connection {
    const conn = { nonce: toHex(this.#o.rng.bytes(NONCE_BYTES)) }
    this.#ledgers.set(conn, { high: -1, auth: null })
    return conn
  }

  /** Drops a connection's ledger when its socket ends; a request on it after is `bad-shape`. */
  disconnect(conn: Connection): void {
    this.#ledgers.delete(conn)
  }

  /**
   * One session request. In order: parse; the window (`agent-locked`); `seq` (`rate-limited` from SEQ_MAX, else
   * `bad-shape` unless one above the last); the signature with this connection's nonce (`bad-sig`); the chain;
   * the per-minute caps (`rate-limited`); the op. A refusal is a reply; a `sign` or `open` refused after its signature
   * verified is audited, and nothing before that, so no line names a requester it has not proven. A fault (a key or a
   * sink that throws other than a code) propagates.
   */
  handle(conn: Connection, input: Uint8Array | string): AgentReply {
    const ledger = this.#ledgers.get(conn)
    if (ledger === undefined) return refuse('bad-shape')
    let req: AgentRequest
    let w: Window
    try {
      req = parseRequest(input)
      w = this.#verify(ledger, conn.nonce, req)
    } catch (e) {
      return refuse(codeOf(e))
    }
    try {
      return this.#serve(ledger, w, req)
    } catch (e) {
      const code = codeOf(e)
      if (req.op === 'sign') {
        const asked = { iss: this.held, sub: req.sub, caveats: req.caveats, exp: req.exp }
        this.#o.audit.record(this.#line(code, asked, req.session))
      } else if (req.op === 'open') {
        this.#o.audit.record(openEntry(code, req, this.principal, null))
      }
      return refuse(code)
    }
  }

  /** The window, the `seq` and the request's signature; on success the `seq` is spent. */
  #verify(ledger: Ledger, nonce: string, req: AgentRequest): Window {
    const w = this.#open()
    if (w === null) throw locked()
    if (req.seq >= SEQ_MAX) throw new AcError('rate-limited', 'the connection is spent: open another')
    if (req.seq !== ledger.high + 1) throw new AcError('bad-shape', `seq is not ${ledger.high + 1}`)
    if (!verifyPreimage(req.session, requestPreimage(nonce, req), req.sig)) {
      throw new AcError('bad-sig', "sig is not the session's signature over the request")
    }
    ledger.high = req.seq
    return w
  }

  #serve(ledger: Ledger, w: Window, req: AgentRequest): AgentReply {
    const auth = this.#authority(ledger, w, req)
    if (req.op === 'register') {
      // Read rule limb (a): the thread joins the session's set in the window, which a reconnect keeps.
      const threads = w.threads.get(req.session) ?? new Set<string>()
      if (!threads.has(req.thread) && threads.size >= THREADS_PER_SESSION) {
        throw new AcError('rate-limited', `a session registers at most ${THREADS_PER_SESSION} threads`)
      }
      w.threads.set(req.session, threads.add(req.thread))
      return { ok: true, op: 'register' }
    }
    this.#count(w, req)
    return req.op === 'sign' ? this.#sign(w, auth, req) : this.#read(w, auth, req)
  }

  /**
   * A chain sent with a request is judged at the agent's clock (its root by rootRule) and replaces the connection's
   * authority. At every request the session is the chain's last sub (`not-authorized`), the chain is live
   * (`hop-expired`) and its held-key hop is in this window's grant-set (`not-in-grant`), so a logout ends every use.
   */
  #authority(ledger: Ledger, w: Window, req: AgentRequest): Authority {
    if (req.chain !== null) {
      ledger.auth = null
      const result = verifyChain(req.chain, req.session, this.#o.clock.now())
      const { at, group } = rootRule(req.chain, this.principal, this.device, (g) => w.groups.has(g))
      const own = req.chain.slice(at)
      const first = own[0]
      if (first === undefined) throw new AcError('not-authorized', 'no hop of the chain is from the held key')
      const exp = Math.min(...req.chain.map((h) => h.exp))
      const [caveats, prefix, grant] = [result.caveats, own.flatMap((h) => h.caveats), hopDigest(first)]
      ledger.auth = { session: req.session, hops: own.length, caveats, own: prefix, exp, grant, group }
    }
    const auth = ledger.auth
    if (auth === null) throw new AcError('bad-shape', 'the first request on a connection carries the chain')
    if (auth.session !== req.session) throw new AcError('not-authorized', 'session is not the last sub')
    if (this.#o.clock.now() > auth.exp) throw new AcError('hop-expired', 'a hop of the chain has expired')
    if (!w.grants.has(auth.grant)) throw new AgentError('not-in-grant', 'not a grant of this window')
    return auth
  }

  /** The sign and open caps, per session per clock minute. */
  #count(w: Window, req: SignRequest | OpenRequest): void {
    const cap = req.op === 'sign' ? SIGNS_PER_MINUTE : OPENS_PER_MINUTE
    const key = `${req.op} ${req.session}`
    const minute = Math.floor(this.#o.clock.now() / 60)
    const last = w.counts.get(key)
    const n = last !== undefined && last.minute === minute ? last.n + 1 : 1
    if (n > cap) throw new AcError('rate-limited', `${req.op} is capped at ${cap} a minute per session`)
    w.counts.set(key, { minute, n })
  }

  /**
   * `sign`: the one derived hop. A renewal (`sub` is the session itself, its chain one first grant) is
   * bounded by the window's end, any other hop by the chain's earliest `exp`, and both by `now` + 8 hours.
   */
  #sign(w: Window, auth: Authority, req: SignRequest): AgentReply {
    if (auth.group !== null) throw new AcError('not-authorized', 'a sign is rooted at P')
    const now = this.#o.clock.now()
    const renewal = req.sub === auth.session && auth.hops === 1 && w.grants.get(auth.grant)?.first === true
    const limit = Math.min(renewal ? w.end : auth.exp, grantLimit(now, w.end))
    const hop = this.#signHop(w, deriveHop(this.held, auth.own, req, limit), renewal, req.session)
    return { ok: true, op: 'sign', hop, renewal }
  }

  /** Signs a hop's preimage under the held key, enters its digest in the grant-set and audits it. */
  #signHop(w: Window, unsigned: UnsignedHop, first: boolean, from: string | null): Hop {
    const hop = signHop(w.keys.signing, unsigned.sub, unsigned.caveats, unsigned.exp)
    // The same preimage signed again (another session's hop equal to a first grant) never takes `first` away.
    const digest = hopDigest(unsigned)
    w.grants.set(digest, { sub: hop.sub, exp: hop.exp, first: first || w.grants.get(digest)?.first === true })
    this.#o.audit.record(this.#line('ok', unsigned, from))
    return hop
  }

  /** A `sign`-shaped line whose root is the principal, whichever key signs. */
  #line(r: Line['reason'], hop: UnsignedHop, from: string | null, event: Line['event'] = 'sign'): Line {
    return { ...signEntry(r, hop, from), event, root: this.principal }
  }

  /**
   * `open`: the mailbox of the chain's root, P or a held group (`not-authorized` else, and on a
   * device); the envelope parsed, its id and sig checked (§5.5 steps 1 to 3; the ts window is the edge's); the wrap opened
   * here; then the read rule, whose every refusal leaves as `not-in-grant` and is audited with its precise reason.
   */
  #read(w: Window, auth: Authority, req: OpenRequest): AgentReply {
    if (this.device !== null || req.mailbox !== (auth.group ?? this.principal)) {
      throw new AcError('not-authorized', 'not this mailbox')
    }
    const env = parseEnvelope(req.envelope)
    if (env.id !== req.id) throw new AcError('bad-shape', 'the envelope is not the one the request names')
    checkId(env)
    checkSig(env)
    const { content, generation } =
      auth.group === null
        ? { content: openSealed(env, { address: this.principal, key: w.keys.sealing }), generation: null }
        : // Unreachable fallback dropped: auth.group is set only when rootRule's held(g), `w.groups.has(g)` (line 290), said
          // the group is held, in this same synchronous call on the same window `w`.
          this.#openGroup(env, w.groups.get(auth.group) as Generation[])
    const ctx = { from: env.from, to: env.to, ts: env.ts, root: env.auth[0]?.iss ?? env.from }
    const threads = w.threads.get(req.session) ?? new Set<string>()
    const d = decideRead(content, threads, auth.caveats, this.#o.evaluators, ctx)
    const line = openEntry(d.release ? 'ok' : d.reason, req, this.principal, d.rule)
    this.#o.audit.record(generation === null ? line : { ...line, detail: { ...line.detail, generation } })
    return d.release ? { ok: true, op: 'open', content } : refuse('not-in-grant')
  }

  /** The group's wrap, opened by the current generation, then the previous; else the first failure. */
  #openGroup(env: Envelope, held: readonly Generation[]): { content: SealedContent; generation: number } {
    const failures: unknown[] = []
    for (const g of held) {
      try {
        return { content: openSealed(env, { address: g.body.group, key: g.key }), generation: g.generation }
      } catch (e) {
        failures.push(e)
      }
    }
    // Unreachable fallback dropped: a held list is never empty. Its one writer, #keep's `w.groups.set(body.group, keep)`
    // (line 512), sets a slice of a list that holds `fresh`, and GENERATIONS_TRIED is at least 1.
    throw failures[0]
  }

  /**
   * `ac grant`, step one, which the server admits by uid alone: `agent-locked`, `bad-shape` for no caveat, the
   * hop shape codes, `exp-not-monotone` past the window or `now` + 8 hours. Returns what to print on the agent's own
   * terminal before reading the answer.
   */
  prepareGrant(req: GrantRequest): PendingGrant | AgentRefusal {
    try {
      const w = this.#open()
      if (w === null) throw locked()
      const hop = checkGrant(this.held, req, grantLimit(this.#o.clock.now(), w.end))
      const pending: PendingGrant = { ok: true, hop, lines: grantLines(hop) }
      this.#pending.set(pending, { w, hop: { ...hop, caveats: [...hop.caveats] }, device: false })
      return pending
    } catch (e) {
      return refuse(codeOf(e))
    }
  }

  /**
   * `ac grant`, step two: `answer` is the line typed on the agent's terminal. Exactly `y` signs the grant as it
   * was printed; anything else is `declined`. A pending grant answers once (`bad-shape` after) and only in its own
   * window (`agent-locked` after a logout or the window's end).
   */
  confirmGrant(pending: PendingGrant, answer: string): GrantReply {
    const held = this.#pending.get(pending)
    this.#pending.delete(pending)
    if (held === undefined || held.device) return refuse('bad-shape')
    if (this.#open() !== held.w) return refuse('agent-locked')
    if (answer.trim() !== 'y') {
      this.#o.audit.record({ ...this.#line('declined', held.hop, null, 'declined'), id: null })
      return { ok: false, code: 'declined' }
    }
    return { ok: true, hop: this.#signHop(held.w, held.hop, true, null) }
  }

  /** `device-grant`, uid-only: checkDeviceGrant's codes, `agent-locked`, `not-authorized` on D. */
  prepareDeviceGrant(req: DeviceGrantRequest): PendingGrant | AgentRefusal {
    try {
      const hop = checkDeviceGrant(this.principal, req, this.#o.clock.now())
      const w = this.#open()
      if (w === null) throw locked()
      if (this.device !== null) throw new AcError('not-authorized', 'a device pairs no other device')
      const pending: PendingGrant = { ok: true, hop, lines: grantLines(hop, 'device grant') }
      this.#pending.set(pending, { w, hop: { ...hop, caveats: [...hop.caveats] }, device: true })
      return pending
    } catch (e) {
      const code = codeOf(e)
      const hop = { iss: this.principal, sub: req.device, caveats: req.caveats, exp: req.exp }
      // A well-formed ask's refusal is one `device reject` line; a malformed one names nothing.
      if (!/^bad-(shape|address)$/.test(code)) this.#o.audit.record(this.#line(code, hop, null, 'device'))
      return refuse(code)
    }
  }

  /** Step two: exactly `y` signs the device hop under P's key, else `declined`; never in the grant-set. */
  confirmDeviceGrant(pending: PendingGrant, answer: string): DeviceReply {
    const held = this.#pending.get(pending)
    this.#pending.delete(pending)
    if (held === undefined || !held.device) return refuse('bad-shape')
    if (this.#open() !== held.w) return refuse('agent-locked')
    if (answer.trim() !== 'y') {
      this.#o.audit.record(this.#line('declined', held.hop, null, 'device'))
      return { ok: false, code: 'declined' }
    }
    const device = signHop(held.w.keys.signing, held.hop.sub, held.hop.caveats, held.hop.exp)
    this.#o.audit.record(this.#line('ok', held.hop, null, 'device'))
    return { ok: true, device }
  }

  /**
   * `group-key`, uid-only: `agent-locked`, `not-authorized` on D, an envelope's id, sig and wrap, the group-key
   * envelope checks (openGroupKey), the keep rule; one `rotate` line, never the key. THE NAMED EXCEPTION:
   * the envelope is opened as P OUTSIDE the session read rule, uid-only, gated to group-key.v1 before its body is
   * used (`type-not-accepted`), releasing only {group, generation, body}. No bypass for any other type.
   */
  takeGroupKey(input: GroupKeyIn): GroupKeyReply {
    let env: Envelope | null = null
    try {
      const w = this.#open()
      if (w === null) throw locked()
      if (this.device !== null) throw new AcError('not-authorized', "a device holds no key of P's")
      const me = { address: this.principal, key: w.keys.sealing }
      let value = 'body' in input ? input.body : undefined
      if ('envelope' in input) {
        const parsed = parseEnvelope(input.envelope)
        checkId(parsed)
        checkSig(parsed)
        env = parsed
        const content = openSealed(parsed, me)
        if (content.type !== GROUP_KEY_TYPE) throw new AcError('type-not-accepted', `not ${GROUP_KEY_TYPE}`)
        value = content.body
      }
      const opened = openGroupKey(value, me, this.#o.clock.now())
      const { group, generation, sealing_key, hop } = opened.body
      if (hop === null) throw new AcError('not-authorized', "the group's own copy is the admin's")
      const { kept, body } = this.#keep(w, opened)
      // Unreachable fallback dropped: #keep returns `opened.body`, whose null hop line 481 refused, or a held body, which
      // passed the same check when it was kept.
      this.#rotate('ok', env, { group, generation, sealing_key, hop_exp: (body.hop as Hop).exp, kept })
      return { ok: true, group, generation, body }
    } catch (e) {
      const code = codeOf(e)
      this.#rotate(code, env, {})
      return refuse(code)
    }
  }

  /**
   * The keep rule: GROUPS_MAX groups; another key at a held generation `bad-key`; the later hop `exp` and the newest
   * two kept; returns what is held there. A key is a window seed over hpkeOpen, zeroed when dropped. Core debt: the
   * SealingKey openGroupKey returns keeps its own copy, and its intermediate seed is not zeroed (core at its ceiling).
   */
  #keep(w: Window, { body, key }: ReturnType<typeof openGroupKey>): Kept {
    const held = w.groups.get(body.group) ?? []
    if (held.length === 0 && w.groups.size >= GROUPS_MAX) throw new AcError('rate-limited', 'too many groups')
    const same = held.find((g) => g.generation === body.generation)
    if (same && same.body.sealing_key !== body.sealing_key) throw new AcError('bad-key', 'the first is kept')
    // Unreachable fallbacks dropped (two): neither hop is null. #keep's only caller, takeGroupKey, refuses a null hop at
    // line 481 before calling it, and every held body was kept by this method after that same check.
    if (same && (same.body.hop as Hop).exp >= (body.hop as Hop).exp) return { kept: 'held', body: same.body }
    const seed = key.exportSeed()
    const fresh = { generation: body.generation, seed, key: { open: hpkeOpen.bind(null, seed) }, body }
    const all = [...held.filter((g) => g !== same), fresh].sort((a, b) => b.generation - a.generation)
    const keep = all.slice(0, GENERATIONS_TRIED)
    for (const g of [...held, fresh]) if (!keep.includes(g)) g.seed.fill(0)
    w.groups.set(body.group, keep)
    return { kept: !keep.includes(fresh) ? 'dropped' : same ? 'renewed' : 'new', body }
  }

  #rotate(reason: AgentCode | 'ok', env: Envelope | null, detail: Line['detail']): void {
    const [id, from] = [env?.id ?? null, env?.from ?? null]
    const decision = reason === 'ok' ? 'accept' : 'reject'
    this.#o.audit.record({ event: 'rotate', decision, reason, id, from, root: this.principal, detail })
  }
}
