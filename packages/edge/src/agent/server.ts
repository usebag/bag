import { once } from 'node:events'
import { chmodSync, lstatSync, mkdirSync, unlinkSync } from 'node:fs'
import { createConnection, createServer, type Socket } from 'node:net'
import { join } from 'node:path'
import {
  AcError,
  type AcRecord,
  type AddressRecord,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Hop,
  isCanonicalInteger,
  MAX_REVOKED,
  RECORD_KINDS,
  type RecordKind,
  signRecord,
} from '@usebag/core'
import { strict } from '../custody/files.ts'
import type { Clock } from '../ports.ts'
import type {
  Agent,
  AgentRefusal,
  Connection,
  DeviceReply,
  GrantReply,
  GroupKeyReply,
  PendingGrant,
  PrincipalKeys,
} from './agent.ts'
import { AgentError, codeOf } from './model.ts'
import { hopDigest } from './rules.ts'

// The agent's socket: newline-framed JSON, the nonce first, session requests to
// Agent.handle, and `grant`, `resign`, `device-grant` and `group-key`, uid-only frames.

/** A subject a device's logout leaves live: `until` is its hop's exp + TTL + skew. */
export type Unrevoked = { readonly sub: string; readonly until: number }

export type LogoutReply =
  | { readonly ok: true; readonly record: AddressRecord | null; readonly unrevoked?: readonly Unrevoked[] }
  | { readonly ok: false; readonly code: string; readonly detail?: string; unrevoked?: readonly string[] }

/** The agent's own terminal: `print` writes a line, `ask` reads the line typed back. */
export interface Terminal {
  print(line: string): void
  ask(): Promise<string>
}

/** What a logout did: the re-signed address record to publish, or null; `error` when something was not revoked. */
export interface LogoutOutcome {
  readonly record: AddressRecord | null
  readonly error: RevokeError | null
  /** On a device, which signs no record of P's: each subject still able to carry mail, for P to revoke D. */
  readonly unrevoked?: readonly Unrevoked[]
}

/** A logout that left subjects out of `revoked`: `unrevoked` names them, `record` is the one it did sign, if any. */
export class RevokeError extends Error {
  readonly record: AddressRecord | null
  readonly unrevoked: readonly string[]

  constructor(detail: string, record: AddressRecord | null, unrevoked: readonly string[]) {
    super(`revoke: ${detail}; not revoked: ${unrevoked.join(' ')}`)
    this.name = 'RevokeError'
    this.record = record
    this.unrevoked = unrevoked
  }
}

export interface AgentServerOptions {
  readonly agent: Agent
  readonly clock: Clock
  readonly home: string
  readonly terminal: Terminal
  /** The principal's last record of each kind, as its dialog approved it; logout re-signs the address record. */
  readonly records: Map<RecordKind, AcRecord>
  /** Receives the outcome of a logout the server ran itself: at the window's end, or at a signal. */
  readonly ended: (outcome: LogoutOutcome) => void
  /** The uid served (default: this process's); `zero` zeroes the principal's keys when the window ends. */
  readonly uid?: number
  readonly zero?: () => void
  /** The hop exps seen, by subject, that date `revoked` entries at logout (default: empty); the caller may persist it. */
  readonly expiry?: Map<string, number>
  /** The timer of the window's end (default: setTimeout, unref'd) and the signal source (default: process). */
  readonly timers?: Timers
  readonly signals?: Signals
}

export interface Timers {
  set(fn: () => void, ms: number): unknown
  clear(handle: unknown): void
}

export interface Signals {
  on(signal: NodeJS.Signals, fn: () => void): unknown
  off(signal: NodeJS.Signals, fn: () => void): unknown
}

/** What one connection lets a grant do: ask whether the requester is still there, and tell it the prompt's code. */
interface Peer {
  readonly gone: () => boolean
  readonly tell: (line: unknown, done?: () => void) => void
}

const LINE_MAX = 1_048_576
const QUEUED_MAX = 64
const SIGNALS: readonly NodeJS.Signals[] = ['SIGINT', 'SIGHUP', 'SIGTERM']
const refuse = (error: unknown): AgentRefusal => ({ ok: false, code: codeOf(error) })
/** `[subject, caveats, exp]`, the args of `grant` and `device-grant`, or null. */
const triple = (args: unknown): [string, string[], number] | null => {
  const [sub, caveats, exp] = Array.isArray(args) ? args : []
  return typeof sub === 'string' && Array.isArray(caveats) && isCanonicalInteger(exp)
    ? [sub, caveats, exp]
    : null
}
const TIMERS: Timers = {
  set: (fn, ms) => setTimeout(fn, ms).unref(),
  clear: (h) => clearTimeout(h as NodeJS.Timeout),
}
/** True when something accepts connections at `path`. */
const listening = (path: string): Promise<boolean> => {
  const probe = createConnection(path)
  return once(probe, 'connect').then(
    () => probe.destroy().destroyed,
    () => false,
  )
}
const SIGNAL_SOURCE: Signals = { on: (s, fn) => process.on(s, fn), off: (s, fn) => process.off(s, fn) }

export class AgentServer {
  readonly path: string
  /** The listening socket; an accept error on it must not end the agent. */
  readonly listener = createServer((socket) => this.#serve(socket)).on('error', () => {})
  readonly #o: AgentServerOptions
  readonly #timers: Timers
  readonly #signals: Signals
  readonly #sockets = new Set<Socket>()
  /** When each subject's latest grant ends, from the hops that passed here: what tells a revoked entry has expired. */
  readonly #expiry: Map<string, number>
  #tty: Promise<unknown> = Promise.resolve()
  #signing: PrincipalKeys['signing'] | null = null
  #timer: unknown

  constructor(options: AgentServerOptions) {
    this.#expiry = options.expiry ?? new Map()
    this.#o = options
    this.#timers = options.timers ?? TIMERS
    this.#signals = options.signals ?? SIGNAL_SOURCE
    this.path = join(options.home, 'agent.sock')
  }

  /** Makes the socket, mode 0600 in the 0700 directory; a stale socket of a dead agent is replaced, a live one is not. */
  async listen(): Promise<void> {
    mkdirSync(this.#o.home, { recursive: true, mode: 0o700 })
    strict('agent', this.#o.home, true)
    if (await listening(this.path)) throw new Error('agent: another agent listens here')
    if (lstatSync(this.path, { throwIfNoEntry: false })?.isSocket()) unlinkSync(this.path)
    this.listener.listen(this.path)
    await once(this.listener, 'listening')
    chmodSync(this.path, 0o600)
    for (const s of SIGNALS) this.#signals.on(s, this.#stop)
  }

  /** Opens the window and arms the timer of its end, which logs out and zeroes the keys as `ac logout` does. */
  login(keys: PrincipalKeys, seconds?: number): number {
    const end = this.#o.agent.login(keys, seconds)
    this.#signing = keys.signing
    this.#timer = this.#timers.set(this.#expire, (end - this.#o.clock.now()) * 1000)
    return end
  }

  /** `ac logout`: the record to publish (null: nothing to revoke); a RevokeError when subjects are left out. */
  logout(): AddressRecord | null {
    const { record, error } = this.#end(true)
    if (error !== null) throw error
    return record
  }

  async close(): Promise<void> {
    for (const s of SIGNALS) this.#signals.off(s, this.#stop)
    this.#timers.clear(this.#timer)
    for (const s of this.#sockets) s.destroy()
    await new Promise<void>((resolve) => this.listener.close(() => resolve()))
  }

  readonly #expire = (): void => this.#o.ended(this.#end(false))
  readonly #stop = (): void => {
    this.#expire()
    void this.close()
  }

  /**
   * Ends the window and re-signs the address record with the subjects whose hops can still carry mail in `revoked`
   * (spec/SPEC.md section 7.2, B2): an entry stays until its hop's `exp` + TTL + skew, the last second such mail passes
   * the stale-ts check. The window's live grants are added and, at an explicit logout (`expired`), the subjects the
   * server saw whose bound is still ahead; an entry whose hop's exp the server saw is dropped once past it, and one it
   * cannot date is kept. Past the core's cap nothing is signed, so no live revocation leaves the published list, and the
   * error names every subject, as any failure does. On a device nothing is signed: the subjects are
   * returned as `unrevoked`, each with its instant. The keys are zeroed whatever happens.
   */
  #end(expired: boolean): LogoutOutcome {
    this.#timers.clear(this.#timer)
    const now = this.#o.clock.now()
    const hold = DEFAULT_TTL + DEFAULT_SKEW
    const signing = this.#signing
    this.#signing = null
    // Only a window can sign: a logout with none open adds no expired subject (and has nothing to re-sign).
    const device = this.#o.agent.device
    const open = (expired && signing !== null) || device !== null
    const recent = open ? [...this.#expiry].filter(([, exp]) => exp + hold >= now).map(([s]) => s) : []
    const subjects = [...new Set([...this.#o.agent.logout(), ...recent])]
    const last = this.#o.records.get('address')
    try {
      if (device !== null) {
        for (const [s, exp] of this.#expiry) if (exp + hold < now) this.#expiry.delete(s)
        // A live subject this server cannot date is bounded by the device hop, which every chain on D carries.
        const until = (sub: string) => (this.#expiry.get(sub) ?? device.exp) + hold
        return {
          record: null,
          error: null,
          unrevoked: subjects.sort().map((sub) => ({ sub, until: until(sub) })),
        }
      }
      if (subjects.length === 0) return { record: null, error: null }
      if (signing === null || last?.kind !== 'address')
        throw new Error('no window opened here, or no address record')
      if (last.rotated_from !== null)
        throw new AcError('bad-record', 'a rotation record is not re-signed here')
      // Dropped only when this server saw the hop's exp and it is past; any other entry, a manual one too, stays.
      const kept = last.revoked.filter(
        (s) => !subjects.includes(s) && (this.#expiry.get(s) ?? now) + hold >= now,
      )
      const all = [...kept, ...subjects]
      if (all.length > MAX_REVOKED) {
        return { record: null, error: new RevokeError('too many revoked for one record', null, all) }
      }
      for (const [s, exp] of this.#expiry) if (exp + hold < now) this.#expiry.delete(s)
      const { sig: _sig, rotation_sig: _rotation, ...rest } = last
      const iat = Math.max(now, last.iat + 1)
      const record = signRecord(signing, { ...rest, iat, revoked: all })
      this.#o.records.set('address', record)
      return { record, error: null }
    } catch (e) {
      return { record: null, error: new RevokeError((e as Error).message, null, subjects) }
    } finally {
      this.#o.zero?.()
    }
  }

  /** Node has no peer credentials: the uid floor is the owner and mode of the socket and its directory (a gap). */
  #trusted(): boolean {
    const uid = this.#o.uid ?? (process.getuid as () => number)()
    try {
      return [this.#o.home, this.path].every((p) => {
        const st = lstatSync(p)
        return st.uid === uid && (st.mode & 0o077) === 0
      })
    } catch {
      return false
    }
  }

  #serve(socket: Socket): void {
    if (!this.#trusted()) return void socket.end(`${JSON.stringify({ ok: false, code: 'not-authorized' })}\n`)
    const conn = this.#o.agent.connect()
    let gone = false
    this.#sockets.add(socket)
    socket.setEncoding('utf8')
    const tell = (reply: unknown, done?: () => void) => socket.write(`${JSON.stringify(reply)}\n`, done)
    tell({ nonce: conn.nonce })
    socket.on('error', () => {})
    socket.on('close', () => {
      gone = true
      this.#sockets.delete(socket)
      this.#o.agent.disconnect(conn)
    })
    const peer = { gone: () => gone, tell }
    let buffer = ''
    let queued = 0
    let queue: Promise<unknown> = Promise.resolve()
    socket.on('data', (chunk: Buffer | string) => {
      buffer += chunk
      if (Buffer.byteLength(buffer) > LINE_MAX) return void socket.destroy()
      for (let i = buffer.indexOf('\n'); i >= 0; i = buffer.indexOf('\n')) {
        const line = buffer.slice(0, i)
        buffer = buffer.slice(i + 1)
        if (++queued > QUEUED_MAX) return void socket.destroy()
        queue = queue
          .then(() => this.#line(conn, line, peer))
          .then(
            (reply) => {
              queued--
              tell(reply)
            },
            () => void socket.destroy(),
          )
      }
    })
  }

  async #line(conn: Connection, line: string, peer: Peer): Promise<unknown> {
    let frame: unknown
    try {
      frame = JSON.parse(line)
    } catch {
      return refuse(new AcError('bad-shape', 'a request is JSON'))
    }
    const f = (frame ?? {}) as Record<string, unknown>
    const { op, args } = f
    if (op === 'grant') return this.#grant(args, peer)
    if (op === 'resign') return this.#resign(args)
    // The two uid-only ops; a session frame naming one goes to Agent.handle, and is `bad-shape` (13.6).
    if (op === 'device-grant' && f.session === undefined) return this.#deviceGrant(args, peer)
    if (op === 'group-key' && f.session === undefined) return this.#groupKey(args)
    if (op === 'logout') {
      const { record, error: e, unrevoked } = this.#end(true)
      const failed = e && { ok: false, code: 'bad-record', detail: e.message, unrevoked: e.unrevoked }
      peer.tell(failed ?? { ok: true, record, unrevoked }, () => void this.close())
      return new Promise(() => {})
    }
    const reply = this.#o.agent.handle(conn, line)
    if (reply.ok && reply.op === 'sign') {
      this.#note(reply.hop)
      if (reply.renewal)
        this.#o.terminal.print(`renewed the grant of ${reply.hop.sub} until ${reply.hop.exp}`)
    }
    return reply
  }

  /** `resign <kind>`: the held record of that kind, every member equal, `iat` moved; once per half ttl. */
  #resign(args: unknown): { readonly ok: true; readonly record: AcRecord } | AgentRefusal {
    const kind = Array.isArray(args) ? args[0] : undefined
    try {
      if (this.#o.agent.device !== null)
        throw new AcError('not-authorized', "a device re-signs no record of P's")
      if (!RECORD_KINDS.some((k) => k === kind)) throw new AcError('bad-shape', 'resign args are [kind]')
      const signing = this.#o.agent.windowEnd() === null ? null : this.#signing
      if (signing === null) throw new AgentError('agent-locked', 'no login window is open: run ac login')
      const last = this.#o.records.get(kind)
      if (last === undefined) throw new AcError('bad-record', `no ${kind} record is held`)
      if (last.kind === 'address' && last.rotated_from !== null)
        throw new AcError('bad-record', 'a rotation record is not re-signed here')
      const now = this.#o.clock.now()
      if (now < last.iat + (last.kind === 'key' ? last.exp - last.iat : last.ttl) / 2)
        throw new AcError('rate-limited', 'a record is re-signed at most once per half ttl')
      const record = signRecord(signing, { ...last, iat: Math.max(now, last.iat + 1) })
      this.#o.records.set(record.kind, record)
      return { ok: true, record }
    } catch (e) {
      return refuse(e)
    }
  }

  #note(hop: Hop): void {
    this.#expiry.set(hop.sub, Math.max(this.#expiry.get(hop.sub) ?? 0, hop.exp))
  }

  /**
   * `grant`: prints what would be signed and signs only after a `y` typed here, one grant at a time. A prompt
   * carries a short code that the requester receives too; a requester that has left is not asked, nor signed for.
   */
  async #grant(args: unknown, peer: Peer): Promise<GrantReply> {
    const asked = triple(args)
    if (asked === null) return refuse(new AcError('bad-shape', 'grant args are [session, caveats, exp]'))
    const [session, caveats, exp] = asked
    const pending = this.#o.agent.prepareGrant({ session, caveats, exp })
    if (!pending.ok) return pending
    return this.#ask(pending, peer, (typed) => {
      const reply = this.#o.agent.confirmGrant(pending, typed)
      if (reply.ok) this.#note(reply.hop)
      return reply
    })
  }

  /**
   * `device-grant`: the hop P -> D through the same prompt as `grant`. Its hop is NEVER noted: in
   * the dated map, P's next logout would revoke D. It leaves as `device`, never as a grant's `hop`.
   */
  async #deviceGrant(args: unknown, peer: Peer): Promise<DeviceReply> {
    const asked = triple(args)
    if (asked === null)
      return refuse(new AcError('bad-shape', 'device-grant args are [device, caveats, exp]'))
    const [device, caveats, exp] = asked
    const pending = this.#o.agent.prepareDeviceGrant({ device, caveats, exp })
    if (!pending.ok) return pending
    return this.#ask(pending, peer, (typed) => this.#o.agent.confirmDeviceGrant(pending, typed))
  }

  /** The terminal's queue: one prompt at a time, its code told to the requester first; `confirm` gets the typed line. */
  #ask<R>(pending: PendingGrant, peer: Peer, confirm: (typed: string) => R): Promise<R | AgentRefusal> {
    const left = refuse(new AcError('bad-shape', 'the requester has left'))
    const run = this.#tty.then(async (): Promise<R | AgentRefusal> => {
      if (peer.gone()) return left
      const code = hopDigest(pending.hop).slice(0, 8)
      peer.tell({ pending: code })
      for (const line of [`request ${code}`, ...pending.lines]) this.#o.terminal.print(line)
      const typed = await this.#o.terminal.ask()
      if (peer.gone() && typed.trim() === 'y') return left
      const reply = confirm(typed)
      return peer.gone() ? left : reply
    })
    this.#tty = run.catch(() => {})
    return run
  }

  /**
   * `group-key`: args [envelope text], or [{body}], a body stored at an earlier login, replayed. THE NAMED
   * EXCEPTION to the read rule is takeGroupKey's: uid-only, type-gated to group-key.v1, releasing only
   * {group, generation, body}.
   */
  #groupKey(args: unknown): GroupKeyReply {
    const [x] = Array.isArray(args) && args.length === 1 ? args : []
    if (typeof x === 'string') return this.#o.agent.takeGroupKey({ envelope: x })
    if (typeof x === 'object' && x !== null && 'body' in x)
      return this.#o.agent.takeGroupKey({ body: x.body })
    return refuse(new AcError('bad-shape', 'group-key args are [envelope] or [{body}]'))
  }
}
