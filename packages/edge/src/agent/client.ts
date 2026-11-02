import { createConnection, type Socket } from 'node:net'
import { createInterface } from 'node:readline'
import {
  AcError,
  type AcRecord,
  type CanonicalValue,
  HOP_TAG,
  type Hop,
  isAcErrorCode,
  parseEnvelope,
  type RecordKind,
  type SealedContent,
  type SignerLike,
  verifyPreimage,
} from '@usebag/core'
import type { Opener, Signer } from '../ports.ts'
import type { AgentRefusal, AgentReply, DeviceReply, GrantReply, GroupKeyIn, GroupKeyReply } from './agent.ts'
import { type AgentCode, AgentError, type AgentOp, buildRequest } from './model.ts'
import type { LogoutReply } from './server.ts'

// The client of the agent socket, one request in flight at a time. A plain client (no
// session) is uid-only: `grant`, `logout`, `resign`, `device-grant` and `group-key`.

export type AgentSession = { readonly key: SignerLike; readonly chain: readonly Hop[] }

/** A core code stays an AcError, with its code; the agent's two (`agent-locked`, `not-in-grant`) are AgentErrors. */
const refused = (r: object): Error => {
  if (!('code' in r)) return new Error('agent: a reply of no known shape')
  return isAcErrorCode(r.code)
    ? new AcError(r.code, 'refused')
    : new AgentError(r.code as AgentCode, 'refused')
}

export class AgentClient {
  readonly #socket: Socket
  readonly #lines: AsyncIterator<string>
  readonly #nonce: Promise<string>
  readonly #session: AgentSession | null
  /** The chain the next request carries: the session's, until a request that carried it is answered. */
  #chain: readonly Hop[] | null
  #queue: Promise<unknown> = Promise.resolve()
  #seq = 0

  constructor(path: string, session: AgentSession | null = null) {
    this.#session = session
    this.#chain = session?.chain ?? null
    this.#socket = createConnection(path).on('error', () => {})
    this.#lines = createInterface({ input: this.#socket })[Symbol.asyncIterator]()
    this.#nonce = this.#lines.next().then((r) => {
      const first = JSON.parse(String(r.value))
      if (typeof first.nonce !== 'string') throw refused(first)
      return first.nonce
    })
    this.#nonce.catch(() => {})
  }

  /** Presents `chain` with the next request, for an authority to replace (a derived hop's chain). */
  use(chain: readonly Hop[]): void {
    this.#chain = chain
  }

  /** One frame and its reply; lines `{"pending": code}` before it (a grant's prompt) go to `onCode`. */
  #call<T>(frame: string, onCode?: (code: string) => void): Promise<T> {
    const run = this.#queue.then(async () => {
      this.#socket.write(`${frame}\n`)
      for (;;) {
        const r = await this.#lines.next()
        if (r.done) throw new Error('agent: the socket closed')
        const reply = JSON.parse(r.value)
        if (reply.pending === undefined) return reply as T
        onCode?.(reply.pending)
      }
    })
    this.#queue = run.catch(() => {})
    return run
  }

  async #send(op: AgentOp, args: readonly CanonicalValue[], envelope?: string): Promise<AgentReply> {
    const s = this.#session
    if (s === null) throw new Error('agent: a session request needs a session')
    const nonce = await this.#nonce
    const chain = this.#chain
    const extras = { ...(chain !== null && { chain }), ...(envelope !== undefined && { envelope }) }
    const frame = buildRequest(s.key, nonce, this.#seq, op, args, extras)
    this.#seq++
    const reply = await this.#call<AgentReply>(frame)
    if (chain !== null && reply.ok) this.#chain = null
    return reply
  }

  async sign(sub: string, caveats: readonly string[], exp: number): Promise<Hop> {
    const r = await this.#send('sign', [sub, caveats, exp])
    if (r.ok && r.op === 'sign') return r.hop
    throw refused(r)
  }

  async open(mailbox: string, id: string, envelope: string): Promise<SealedContent> {
    const r = await this.#send('open', [mailbox, id], envelope)
    if (r.ok && r.op === 'open') return r.content
    throw refused(r)
  }

  async register(thread: string): Promise<void> {
    const r = await this.#send('register', [thread])
    if (!r.ok) throw refused(r)
  }

  /** `ac grant`: `onCode` gets the code the agent's prompt shows, to match it with the one the user sees. */
  grant(
    session: string,
    caveats: readonly string[],
    exp: number,
    onCode?: (code: string) => void,
  ): Promise<GrantReply> {
    return this.#call<GrantReply>(JSON.stringify({ op: 'grant', args: [session, caveats, exp] }), onCode)
  }

  /** `ac device grant`, as `grant`: the hop P -> D, signed on a `y` at the agent's terminal. */
  deviceGrant(
    device: string,
    caveats: readonly string[],
    exp: number,
    onCode?: (code: string) => void,
  ): Promise<DeviceReply> {
    return this.#call<DeviceReply>(
      JSON.stringify({ op: 'device-grant', args: [device, caveats, exp] }),
      onCode,
    )
  }

  /** `group-key`: a received envelope's text, or a body a past reply gave, replayed at `ac login`. */
  groupKey(input: GroupKeyIn): Promise<GroupKeyReply> {
    const arg = 'envelope' in input ? input.envelope : { body: input.body }
    return this.#call<GroupKeyReply>(JSON.stringify({ op: 'group-key', args: [arg] }))
  }

  /** `ac logout`, uid-only: the record to publish or a RevokeError's subjects; the agent then closes. */
  logout(): Promise<LogoutReply> {
    return this.#call<LogoutReply>('{"op":"logout"}')
  }

  close(): void {
    this.#socket.end()
  }

  /** `resign <kind>`, uid-only: the agent's re-signed record of that kind, for the caller to publish. */
  async resign(kind: RecordKind): Promise<AcRecord> {
    const frame = JSON.stringify({ op: 'resign', args: [kind] })
    const r = await this.#call<{ ok: true; record: AcRecord } | AgentRefusal>(frame)
    if (r.ok) return r.record
    throw refused(r)
  }
}

/**
 * The held key's signer through the agent: a hop preimage and nothing else (it signs no digest). On a device its
 * address is D, the iss of every hop the agent signs there, so D's sessions sign through it.
 */
export class AgentSigner implements Signer {
  readonly address: string
  readonly #client: () => AgentClient

  constructor(address: string, client: () => AgentClient) {
    this.address = address
    this.#client = client
  }

  sign(): never {
    throw new AcError('not-authorized', 'the agent signs a hop preimage, never a digest')
  }

  async signPreimage(preimage: CanonicalValue): Promise<string> {
    const [tag, iss, sub, caveats, exp, ...more] = (Array.isArray(preimage) ? preimage : []) as unknown[]
    const hop = tag === HOP_TAG && iss === this.address && more.length === 0
    if (!hop || typeof sub !== 'string' || !Array.isArray(caveats) || typeof exp !== 'number') {
      throw new AcError('not-authorized', 'the agent signs only a hop of its held key')
    }
    const signed = await this.#client().sign(sub, caveats, exp)
    const same = JSON.stringify([signed.iss, signed.sub, signed.caveats, signed.exp])
    if (same !== JSON.stringify([iss, sub, caveats, exp])) {
      throw new AcError('bad-hop', 'the agent signed another hop than the one asked')
    }
    if (!verifyPreimage(this.address, preimage, signed.sig))
      throw new AcError('bad-sig', 'the hop is not signed by its held key')
    return signed.sig
  }
}

/** The principal's opener through the agent: whole envelopes only, and only what the read rule releases. */
export class AgentOpener implements Opener {
  readonly publicKey: Uint8Array
  readonly #mailbox: string
  readonly #client: () => AgentClient

  constructor(mailbox: string, publicKey: Uint8Array, client: () => AgentClient) {
    this.#mailbox = mailbox
    this.publicKey = publicKey
    this.#client = client
  }

  open(): never {
    throw new AcError('not-authorized', 'the agent opens an envelope, never a bare wrap')
  }

  openEnvelope(bytes: Uint8Array): Promise<SealedContent> {
    return this.#client().open(this.#mailbox, parseEnvelope(bytes).id, new TextDecoder().decode(bytes))
  }
}
