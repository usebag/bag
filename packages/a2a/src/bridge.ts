import { randomBytes } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { type AddressInfo, isIPv6 } from 'node:net'
import type { SessionHandler } from '@usebag/edge'
import { A2A_TYPE, MAX_RPC_BYTES, readResponseBody, requestBody } from './binding.ts'
import { agentCard, BRIDGE_CARD_PATH, type CardOptions, type CardRecord } from './card.ts'
import { failure, type JsonRpcId, type JsonRpcResponse, parseRequest } from './jsonrpc.ts'
import { A2A_VERSION, ERRORS } from './protocol.ts'

// The client's side of the binding: a local HTTP server that an unmodified A2A client calls as it would call any A2A
// agent over JSON-RPC (POST, application/json, an A2A-Version header), at the URL of the agent's card,
// http://127.0.0.1:7741/a2a/<address>. Each request is sealed to <address> as one A2A_TYPE envelope on a new thread
// and published through the bridge's edge; the agent's reply in that thread is opened and returned as the HTTP
// response. The relays between them carry ciphertext: the method, the params and the result are all sealed. The
// bridge also serves each agent's full AgentCard at /a2a/<address>/.well-known/agent-card.json, made from the address
// record its edge fetched and verified.
//
// The bridge signs as its edge's identity, for every local caller, and it has no caller authentication: so it
// listens on the loopback only (127.0.0.0/8, ::1 or localhost; any other `host` is refused before it listens, since
// on a network address every reachable machine could send as the identity), `agents` limits the addresses it will
// call, and it answers only requests whose Host names the loopback at its port and that carry no Origin, so that a
// web page cannot reach it through DNS rebinding or a cross-site request. Any process on this machine can call it,
// the same trust as the command line on the same home; a caller token is a later option.

/** The path under which the bridge serves one agent per address. */
export const BRIDGE_PATH = '/a2a/'
/** The bridge's port by default, the one the cards name. */
export const DEFAULT_PORT = 7741
const ADDRESS = /^ed25519:[0-9a-f]{64}$/

/** The refusal of a `host` that is not the loopback; the bridge and the process print it. */
export const LOOPBACK_ONLY =
  '--host must be a loopback address (127.0.0.0/8, ::1 or localhost): the bridge listens on loopback only; it has no caller authentication'

/**
 * Whether `host` names the loopback: an address in 127.0.0.0/8, ::1 in any written form, an IPv4-mapped
 * ::ffff:127.x.x.x, or the name `localhost` (in any case). Everything else, 0.0.0.0 and :: among it, is not.
 */
export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase()
  if (h === 'localhost') return true
  const v4 = /^(?:::ffff:)?127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4 !== null) return v4.slice(1).every((octet) => Number(octet) <= 255)
  // ::1 in any written form: eight groups, the first seven zero and the last 1, with one :: standing for the gap.
  if (!isIPv6(h) || h.includes('.')) return false
  const [head, tail] = h.split('::')
  const groups = (s: string): string[] => (s === '' ? [] : s.split(':'))
  const a = groups(head ?? '')
  const b = groups(tail ?? '')
  const all = tail === undefined ? a : [...a, ...new Array<string>(8 - a.length - b.length).fill('0'), ...b]
  return (
    all.length === 8 && all.slice(0, 7).every((g) => /^0{1,4}$/.test(g)) && /^0{0,3}1$/.test(all[7] ?? '')
  )
}

/** An agent's A2A endpoint at a bridge: <base>/a2a/<address>. */
export function endpointUrl(base: string, address: string): string {
  return `${base.replace(/\/+$/, '')}${BRIDGE_PATH}${address}`
}

/**
 * The part of an edge the bridge uses: a send on a thread it names, bound to its session, that session live, and the
 * resolver that fetches and verifies an address record (an Edge has all three).
 */
export interface BridgeEdge {
  send(input: {
    readonly to: readonly string[]
    readonly type: string
    readonly body: unknown
    readonly thread: { readonly id: string; readonly prev: readonly string[] }
    readonly session: string
  }): Promise<unknown>
  attach(handler: SessionHandler): void
  readonly resolver: { address(address: string): Promise<CardRecord | null> }
}

export interface A2aBridgeOptions {
  readonly edge: BridgeEdge
  /** The loopback address or name to listen on (default 127.0.0.1; 127.0.0.0/8, ::1 or localhost only). */
  readonly host?: string
  /** The port (default 7741; 0 takes a free port, read from `url`). */
  readonly port?: number
  /** How long a request waits for the agent's reply, in milliseconds (default 30,000). */
  readonly timeoutMs?: number
  /** The session id the replies are routed to (default "a2a-bridge"). */
  readonly session?: string
  /** The only addresses the bridge calls; any address when absent. */
  readonly agents?: readonly string[]
  /** The name, description, version and skills of the cards the bridge serves. */
  readonly card?: Omit<CardOptions, 'endpoint'>
  /** Counts each JSON-RPC answer: the request's method (`other` before it parses) and `ok` or its error's name. */
  readonly count?: (method: string, outcome: string) => void
}

interface Pending {
  readonly address: string
  readonly id: JsonRpcId
  readonly done: (response: JsonRpcResponse) => void
}

/** What a request is served with: the options, the reply session, the requests waiting, and where the bridge is. */
interface Context {
  readonly o: A2aBridgeOptions
  readonly session: string
  readonly pending: Map<string, Pending>
  base: string
  hosts: readonly string[]
}

const JSON_HEADERS = { 'content-type': 'application/json', 'cache-control': 'no-store' }

/** Each JSON-RPC error code's name in ERRORS; a code outside it is counted as `other`. */
const OUTCOMES = new Map(Object.entries(ERRORS).map(([name, code]) => [code as number, name]))

function refuse(
  res: ServerResponse,
  status: number,
  error: string,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { ...JSON_HEADERS, ...headers }).end(`${JSON.stringify({ error })}\n`)
}

/** The body as text, or null when it is over `max` bytes (the rest is not read); rejects when the client goes. */
function readBody(req: IncomingMessage, max: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > max) {
        resolve(null)
        req.removeAllListeners('data')
        req.resume()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    // After 'end' this changes nothing; before it, the client went away mid-body.
    req.on('close', () => reject(new Error('the client closed the request')))
  })
}

export class A2aBridge {
  /** The bridge's base URL, http://<host>:<port>. */
  readonly url: string
  readonly #server: ReturnType<typeof createServer>
  readonly #pending: Map<string, Pending>

  private constructor(url: string, server: ReturnType<typeof createServer>, pending: Map<string, Pending>) {
    this.url = url
    this.#server = server
    this.#pending = pending
  }

  /**
   * Starts a bridge on its edge: attaches the reply session and listens; rejects when the port is taken, and before
   * anything else when `host` is not the loopback (LOOPBACK_ONLY).
   */
  static async start(options: A2aBridgeOptions): Promise<A2aBridge> {
    const host = options.host ?? '127.0.0.1'
    if (!isLoopbackHost(host)) throw new Error(LOOPBACK_ONLY)
    const ctx: Context = {
      o: options,
      session: options.session ?? 'a2a-bridge',
      pending: new Map(),
      base: '',
      hosts: [],
    }
    options.edge.attach({
      session: ctx.session,
      deliver: (m) => {
        const p = m.type === A2A_TYPE ? ctx.pending.get(m.thread.id) : undefined
        // Only the agent the request went to answers it: its principal, or a key under a chain rooted at it (the
        // edge verified the chain, so its root acts for that address). Anything else on the thread is left unanswered.
        if (p === undefined || (m.principal !== p.address && m.root !== p.address)) return
        const why = 'the agent answered no JSON-RPC response to this request'
        p.done(readResponseBody(m.body, p.id) ?? failure(p.id, ERRORS.invalidAgentResponse, why))
      },
    })
    // A request whose client went away mid-body is dropped with its connection.
    const server = createServer((req, res) => serve(ctx, req, res).catch(() => res.destroy()))
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(options.port ?? DEFAULT_PORT, host, resolve)
    })
    const { port } = server.address() as AddressInfo
    ctx.base = `http://${host}:${port}`
    ctx.hosts = [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]
    return new A2aBridge(ctx.base, server, ctx.pending)
  }

  /** The A2A endpoint of an agent at this bridge. */
  endpoint(address: string): string {
    return endpointUrl(this.url, address)
  }

  /** Stops listening; a request still waiting is answered with an internal error. */
  async close(): Promise<void> {
    for (const p of [...this.#pending.values()]) {
      p.done(failure(p.id, ERRORS.internalError, 'the bridge closed'))
    }
    // Those answers are written on the next turns of the loop; then every connection goes.
    await new Promise((resolve) => setImmediate(resolve))
    await new Promise((resolve) => setImmediate(resolve))
    this.#server.closeAllConnections()
    await new Promise<void>((resolve) => this.#server.close(() => resolve()))
  }
}

async function serve(ctx: Context, req: IncomingMessage, res: ServerResponse): Promise<void> {
  // DNS rebinding and cross-site requests: only the loopback at this port, and no browser's Origin.
  if (!ctx.hosts.includes(String(req.headers.host).toLowerCase())) return refuse(res, 403, 'forbidden-host')
  if (req.headers.origin !== undefined) return refuse(res, 403, 'forbidden-origin')
  const path = new URL(String(req.url), 'http://bridge').pathname
  const rest = path.startsWith(BRIDGE_PATH) ? path.slice(BRIDGE_PATH.length) : ''
  const card = rest.endsWith(BRIDGE_CARD_PATH)
  const address = card ? rest.slice(0, -BRIDGE_CARD_PATH.length) : rest
  if (!ADDRESS.test(address) || (ctx.o.agents !== undefined && !ctx.o.agents.includes(address))) {
    return refuse(res, 404, 'not-found')
  }
  if (card) return serveCard(ctx, address, req, res)
  if (req.method !== 'POST') return refuse(res, 405, 'method-not-allowed', { allow: 'POST' })
  const type = `${String(req.headers['content-type']).split(';')[0]}`.trim().toLowerCase()
  if (type !== 'application/json') return refuse(res, 415, 'unsupported-media-type')
  const text = await readBody(req, MAX_RPC_BYTES)
  if (text === null) return refuse(res, 413, 'too-large')
  let method = 'other'
  const answer = (r: JsonRpcResponse): void => {
    ctx.o.count?.(method, 'error' in r ? (OUTCOMES.get(r.error.code) ?? 'other') : 'ok')
    res.writeHead(200, JSON_HEADERS).end(JSON.stringify(r))
  }
  const parsed = parseRequest(text)
  if (!parsed.ok) return answer(parsed.response)
  const { request } = parsed
  method = request.method
  // A2A-Version (section 3.2.6): an empty or absent header is read as 0.3 (section 3.6.2), which this bridge does not
  // speak; every version but 1.0 is VersionNotSupportedError. Node joins a repeated header with ", ".
  const version = String(req.headers['a2a-version'] ?? '').trim() || '0.3'
  if (version !== A2A_VERSION) {
    const why = `A2A version ${version} is not supported; this bridge speaks ${A2A_VERSION}`
    return answer(failure(request.id, ERRORS.versionNotSupported, why))
  }
  // The wait is registered before the send, so that a reply however quick finds it; the first answer wins.
  const thread = { id: randomBytes(32).toString('hex'), prev: [] }
  const ms = ctx.o.timeoutMs ?? 30_000
  const reply = Promise.withResolvers<JsonRpcResponse>()
  const done = (r: JsonRpcResponse): void => {
    clearTimeout(timer)
    ctx.pending.delete(thread.id)
    reply.resolve(r)
  }
  const late = failure(request.id, ERRORS.internalError, `no answer from ${address} within ${ms} ms`)
  const timer = setTimeout(() => done(late), ms)
  ctx.pending.set(thread.id, { address, id: request.id, done })
  const body = requestBody(request)
  try {
    await ctx.o.edge.send({ to: [address], type: A2A_TYPE, body, thread, session: ctx.session })
  } catch (e) {
    done(failure(request.id, ERRORS.internalError, `the agent could not be reached: ${(e as Error).message}`))
  }
  answer(await reply.promise)
}

/** GET <address>/.well-known/agent-card.json: the full card, from the record the edge fetched and verified. */
async function serveCard(
  ctx: Context,
  address: string,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  if (req.method !== 'GET') return refuse(res, 405, 'method-not-allowed', { allow: 'GET' })
  let record: CardRecord | null
  try {
    record = await ctx.o.edge.resolver.address(address)
  } catch {
    return refuse(res, 502, 'resolve-failed')
  }
  if (record === null || record.key !== address) return refuse(res, 404, 'no-record')
  const card = agentCard(record, { ...ctx.o.card, endpoint: ctx.base })
  res.writeHead(200, JSON_HEADERS).end(JSON.stringify(card))
}
