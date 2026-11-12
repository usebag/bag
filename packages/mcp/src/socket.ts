import { randomBytes, timingSafeEqual } from 'node:crypto'
import { chmodSync, closeSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync } from 'node:fs'
import type { Server, Socket } from 'node:net'
import { createServer } from 'node:net'
import { isAbsolute, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import {
  type ElicitRequestFormParams,
  type ElicitResult,
  ElicitResultSchema,
  type JSONRPCMessage,
} from '@modelcontextprotocol/sdk/types.js'
import { ConfigError } from './config.ts'
import type { Logger } from './log.ts'
import { ToolError } from './tools.ts'

// The bag service's socket side (docs/bag-service.md, sections 2 to 5): the run directory, the single-service lock,
// the socket path guard, the newline-delimited JSON-RPC framing, the hello, and one ServiceConnection per accepted
// connection with its dialogs. MCP messages pass through to a per-connection MCP server (service.ts) unchanged.

/** The contract versions this service speaks (hello's `contract`). */
export const CONTRACTS: readonly number[] = [1]
/** The longest line, in bytes, before its newline. */
export const MAX_LINE = 4 * 1024 * 1024
/** How long a connection may wait before its hello. */
export const HELLO_MS = 5000
/** The most connections at once. */
export const MAX_CONNECTIONS = 256
/** The longest a start waits for the service lock before it concludes busy (a shim's probe holds it an instant). */
export const LOCK_RETRY_MS = 1000
/** The key a dialog's handle travels under in `_meta`. */
export const DIALOG_META = 'bag.dev/dialog'

const HELLO_KEYS = ['contract', 'token', 'host', 'cwd', 'client_capabilities', 'input_hook', 'shim']

/** sun_path's size with its NUL: 104 on darwin (and the BSDs), 108 on Linux. */
export function socketPathMax(platform: NodeJS.Platform = process.platform): number {
  return (platform === 'linux' ? 108 : 104) - 1
}

/** The run directory, the socket, the lock, the token and the status file of a home. */
export function runPaths(home: string) {
  const dir = join(home, 'run')
  return {
    dir,
    sock: join(dir, 'service.sock'),
    lock: join(dir, 'service.lock'),
    token: join(dir, 'service.token'),
    json: join(dir, 'service.json'),
  }
}

/** Throws unsafe-path when the socket path does not fit sun_path (counted in UTF-8 bytes). */
export function checkSocketPath(path: string, platform: NodeJS.Platform = process.platform): void {
  const bytes = Buffer.byteLength(path, 'utf8')
  const max = socketPathMax(platform)
  if (!isAbsolute(path)) throw new ConfigError('unsafe-path', `the socket path ${path} is not absolute`)
  if (bytes > max)
    throw new ConfigError(
      'unsafe-path',
      `the socket path is ${bytes} bytes; this platform allows ${max}: set AC_HOME to a shorter home`,
    )
}

/**
 * Makes the run directory 0700 (under umask 077) when absent, then refuses it unless it is a directory, not a link,
 * owned by this user, with no group or other bit.
 */
export function ensureRunDir(dir: string, uid: number = process.getuid?.() ?? -1): void {
  const old = process.umask(0o077)
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  } finally {
    process.umask(old)
  }
  const st = lstatSync(dir)
  if (st.isSymbolicLink() || !st.isDirectory())
    throw new ConfigError('unsafe-path', `${dir} is a link or not a directory`)
  if (uid >= 0 && st.uid !== uid)
    throw new ConfigError('unsafe-path', `${dir} belongs to another user (uid ${st.uid})`)
  if ((st.mode & 0o077) !== 0) {
    const octal = (st.mode & 0o777).toString(8).padStart(4, '0')
    throw new ConfigError('unsafe-path', `${dir} has mode ${octal}; it must be 0700`)
  }
}

/** The single-service lock: held until release, never opened twice by this process (an fcntl lock drops on any close). */
export interface ServiceLock {
  release(): void
}

/**
 * Takes the exclusive lock on `path` (node:sqlite's fcntl lock in EXCLUSIVE locking mode, busy_timeout 0), retrying
 * for `retryMs` (a shim's probe may hold it an instant), else busy naming `holder()`. The kernel drops it at exit.
 */
export async function takeServiceLock(
  path: string,
  holder: () => string = () => 'another process',
  retryMs = LOCK_RETRY_MS,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<ServiceLock> {
  // Made 0600 before the lock, so the database file is never created with the umask's mode.
  closeSync(openSync(path, 'a', 0o600))
  const db = new DatabaseSync(path, { timeout: 0 })
  const deadline = Date.now() + retryMs
  for (;;) {
    try {
      db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE')
      db.exec(
        'CREATE TABLE IF NOT EXISTS held(at INTEGER); DELETE FROM held; INSERT INTO held VALUES (1); COMMIT',
      )
      break
    } catch (e) {
      if (Date.now() >= deadline || !/locked|busy/i.test((e as Error).message)) {
        db.close()
        if (/locked|busy/i.test((e as Error).message))
          throw new ConfigError('busy', `the bag service for this home already runs (${holder()})`)
        throw e
      }
      await sleep(50)
    }
  }
  let held = true
  return {
    release() {
      if (!held) return
      held = false
      db.close()
    },
  }
}

/** Splits a byte stream into lines of at most `max` bytes; `onLine` gets each, `onTooLong` ends the stream. */
export class LineReader {
  #parts: Buffer[] = []
  #size = 0
  #dead = false
  readonly onLine: (line: string) => void
  readonly onTooLong: () => void
  readonly max: number
  constructor(onLine: (line: string) => void, onTooLong: () => void, max = MAX_LINE) {
    this.onLine = onLine
    this.onTooLong = onTooLong
    this.max = max
  }

  push(chunk: Buffer): void {
    let rest = chunk
    while (!this.#dead) {
      const nl = rest.indexOf(10)
      const take = nl < 0 ? rest : rest.subarray(0, nl)
      if (this.#size + take.length > this.max) {
        this.#dead = true
        this.onTooLong()
        return
      }
      if (nl < 0) {
        if (take.length > 0) this.#parts.push(take)
        this.#size += take.length
        return
      }
      const line = Buffer.concat([...this.#parts, take]).toString('utf8')
      this.#parts = []
      this.#size = 0
      rest = rest.subarray(nl + 1)
      if (line.trim() !== '') this.onLine(line)
    }
  }
}

/** What a hello declares, checked. */
export interface Hello {
  readonly contract: number
  readonly host: string
  readonly cwd: string
  readonly capabilities: Readonly<Record<string, unknown>>
  readonly inputHook: boolean
}

/** One accepted connection, from its hello to its close (docs/bag-service.md, section 5a). */
export interface ServiceConnection {
  readonly handle: string
  readonly host: string
  readonly cwd: string
  readonly capabilities: {
    readonly elicitation: boolean
    readonly inputHook: boolean
    readonly raw: Readonly<Record<string, unknown>>
  }
  readonly closed: boolean
  onClose(listener: () => void): () => void
  elicit(
    params: ElicitRequestFormParams,
    options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
  ): Promise<ElicitResult>
  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void
  /** The omp consent bridge directory the service made for this connection (hello's bridge_dir); absent without one. */
  readonly bridgeDir?: string | undefined
}

/** A refusal on the stream: a bag code and a detail, with extra data. */
export class StreamError extends Error {
  readonly code: string
  readonly data: Readonly<Record<string, unknown>>
  constructor(code: string, detail: string, data: Readonly<Record<string, unknown>> = {}) {
    super(`${code}: ${detail}`)
    this.code = code
    this.data = data
  }
}

const RPC_CODE: Readonly<Record<string, number>> = {
  'bad-json': -32700,
  'bad-shape': -32600,
  usage: -32600,
  'body-too-large': -32600,
  'unknown-method': -32601,
}

type Rpc = Record<string, unknown>
const isObject = (v: unknown): v is Rpc => typeof v === 'object' && v !== null && !Array.isArray(v)

/** The JSON-RPC error a refusal is answered with. */
export function rpcError(id: unknown, e: StreamError): Rpc {
  const detail = e.message.slice(e.code.length + 2)
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: {
      code: RPC_CODE[e.code] ?? -32000,
      message: e.message,
      data: { code: e.code, detail, ...e.data },
    },
  }
}

/** What the service does with a connection: the hello's checks it owns, the service/ methods, the MCP side. */
export interface ConnectionHost {
  readonly token: Buffer
  readonly log: Logger
  /** Null when a hello may proceed, else the refusal (draining, the cap). */
  admit(): StreamError | null
  /** After a hello: wires the connection's MCP server; returns the transport messages go to. */
  attach(conn: Connection): Transport
  /** A service/ request; throws StreamError to refuse it. */
  request(conn: Connection, method: string, params: Rpc): Promise<Rpc>
  /** The handle a dialog was minted on, service-wide, to tell a foreign answer from an unknown one. */
  dialogOwner(handle: string): Connection | undefined
  registerDialog(handle: string, conn: Connection | null): void
  closed(conn: Connection): void
  /** A service/ notification (service/typed); counted only after a token-checked hello. */
  notification?(conn: Connection, method: string, params: Rpc): void
  /** What the service makes for a connection at its hello (the consent bridge), merged into the hello result. */
  prepare?(conn: Connection): Rpc
  /** The service's own facts for the hello result. */
  facts(): Rpc
  helloMs?: number
}

interface Pending {
  readonly id: string
  readonly handle: string
  readonly resolve: (r: ElicitResult) => void
  readonly reject: (e: unknown) => void
}

/** One socket connection: the framing, the hello, the dialogs, and the MCP transport. */
export class Connection implements ServiceConnection {
  readonly handle = randomBytes(16).toString('hex')
  bridgeDir: string | undefined = undefined
  #hello: Hello | null = null
  #closed = false
  #listeners = new Set<() => void>()
  #transport: (Transport & { deliver(m: JSONRPCMessage): void }) | null = null
  #dialog: Pending | null = null
  #queue: (() => void)[] = []
  #seq = 0
  #helloTimer: ReturnType<typeof setTimeout> | null

  readonly socket: Socket
  readonly host_: ConnectionHost

  constructor(socket: Socket, host_: ConnectionHost) {
    this.socket = socket
    this.host_ = host_
    const reader = new LineReader(
      (line) => this.#line(line),
      () => {
        this.#send(rpcError(null, new StreamError('body-too-large', `a line is over ${MAX_LINE} bytes`)))
        this.close()
      },
    )
    socket.on('data', (b: Buffer) => reader.push(b))
    socket.on('close', () => this.#end())
    socket.on('error', () => this.#end())
    this.#helloTimer = setTimeout(() => {
      if (this.#hello === null) this.close()
    }, host_.helloMs ?? HELLO_MS)
  }

  get host(): string {
    return this.#hello?.host ?? ''
  }
  get cwd(): string {
    return this.#hello?.cwd ?? ''
  }
  get capabilities() {
    const raw = this.#hello?.capabilities ?? {}
    return { elicitation: isObject(raw.elicitation), inputHook: this.#hello?.inputHook ?? false, raw }
  }
  get closed(): boolean {
    return this.#closed
  }
  get hello(): Hello | null {
    return this.#hello
  }

  onClose(listener: () => void): () => void {
    if (this.#closed) {
      listener()
      return () => {}
    }
    this.#listeners.add(listener)
    return () => this.#listeners.delete(listener)
  }

  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void {
    this.#send({ jsonrpc: '2.0', method, params })
  }

  /** Sends one dialog on this connection and resolves with its answer from this connection only. */
  elicit(
    params: ElicitRequestFormParams,
    options: { readonly signal?: AbortSignal; readonly timeoutMs?: number } = {},
  ): Promise<ElicitResult> {
    const { promise, resolve, reject } = Promise.withResolvers<ElicitResult>()
    const cancelled = (why: string): ToolError => new ToolError('cancelled', why)
    let timer: ReturnType<typeof setTimeout> | null = null
    let mine: Pending | null = null
    const finish = (): void => {
      if (timer !== null) clearTimeout(timer)
      options.signal?.removeEventListener('abort', onAbort)
      if (mine !== null) this.host_.registerDialog(mine.handle, null)
      if (this.#dialog === mine && mine !== null) {
        this.#dialog = null
        this.#queue.shift()?.()
      }
    }
    const abort = (why: string): void => {
      if (mine !== null && this.#dialog === mine)
        this.#send({
          jsonrpc: '2.0',
          method: 'notifications/cancelled',
          params: { requestId: mine.id, reason: why },
        })
      else this.#queue = this.#queue.filter((f) => f !== go)
      finish()
      reject(cancelled(why))
    }
    const onAbort = (): void => abort('the call was cancelled')
    const go = (): void => {
      if (this.#closed) return void reject(cancelled('the connection closed'))
      const handle = randomBytes(16).toString('hex')
      const id = `bag-dialog-${++this.#seq}`
      mine = {
        id,
        handle,
        resolve: (r) => {
          finish()
          resolve(r)
        },
        reject: (e) => {
          finish()
          reject(e)
        },
      }
      this.#dialog = mine
      this.host_.registerDialog(handle, this)
      const _meta = { ...(isObject(params._meta) ? params._meta : {}), [DIALOG_META]: handle }
      this.#send({ jsonrpc: '2.0', id, method: 'elicitation/create', params: { ...params, _meta } })
    }
    if (options.signal?.aborted) {
      reject(cancelled('the call was cancelled'))
      return promise
    }
    options.signal?.addEventListener('abort', onAbort, { once: true })
    if (options.timeoutMs !== undefined)
      timer = setTimeout(() => abort('no answer in time'), options.timeoutMs)
    if (this.#dialog === null) go()
    else this.#queue.push(go)
    return promise
  }

  /** Writes one message as a line; nothing after close. */
  send(message: Rpc | JSONRPCMessage): void {
    this.#send(message as Rpc)
  }

  close(): void {
    if (!this.#closed) this.socket.end()
    this.#end()
  }

  #send(message: Rpc): void {
    if (this.#closed || this.socket.destroyed) return
    this.socket.write(`${JSON.stringify(message)}\n`)
  }

  #end(): void {
    if (this.#closed) return
    this.#closed = true
    if (this.#helloTimer !== null) clearTimeout(this.#helloTimer)
    this.socket.destroy()
    const pending = this.#dialog
    this.#queue = []
    pending?.reject(new ToolError('cancelled', 'the connection closed'))
    for (const f of this.#listeners) f()
    this.#listeners.clear()
    this.#transport?.onclose?.()
    this.host_.closed(this)
  }

  #line(line: string): void {
    let msg: unknown
    try {
      msg = JSON.parse(line)
    } catch {
      this.#send(rpcError(null, new StreamError('bad-json', 'a line is not JSON')))
      return
    }
    if (!isObject(msg)) {
      this.#send(
        rpcError(null, new StreamError('bad-shape', 'a message is one JSON object; batches are not taken')),
      )
      return
    }
    if (this.#hello === null) {
      void this.#helloOf(msg)
      return
    }
    if (this.#foreign(msg)) return
    const method = msg.method
    if (typeof method !== 'string') {
      if (typeof msg.id === 'string' && msg.id.startsWith('bag-dialog-')) this.#answer(msg)
      else this.#transport?.deliver(msg as JSONRPCMessage)
      return
    }
    if (method === 'service/hello') {
      this.#refuse(msg.id, new StreamError('usage', 'service/hello is sent once'))
      return
    }
    if (method.startsWith('service/')) {
      if (msg.id === undefined) {
        this.host_.notification?.(this, method, isObject(msg.params) ? msg.params : {})
        return
      }
      const params = msg.params === undefined ? {} : msg.params
      if (!isObject(params)) {
        this.#refuse(msg.id, new StreamError('usage', 'params is an object'))
        return
      }
      this.host_
        .request(this, method, params)
        .then((result) => this.#send({ jsonrpc: '2.0', id: msg.id, result }))
        .catch((e) =>
          this.#refuse(msg.id, e instanceof StreamError ? e : new StreamError('internal', String(e))),
        )
      return
    }
    this.#transport?.deliver(msg as JSONRPCMessage)
  }

  #refuse(id: unknown, e: StreamError): void {
    this.#send(rpcError(id, e))
  }

  /** A message carrying another connection's dialog handle: refused not-authorized and logged. */
  #foreign(msg: Rpc): boolean {
    const meta = (isObject(msg.result) && msg.result._meta) || (isObject(msg.params) && msg.params._meta)
    const handle = isObject(meta) ? meta[DIALOG_META] : undefined
    if (typeof handle !== 'string') return false
    const owner = this.host_.dialogOwner(handle)
    if (owner === undefined || owner === this) return false
    this.host_.log.log('warn', 'dialog-foreign', { connection: this.handle })
    this.#refuse(null, new StreamError('not-authorized', 'that dialog belongs to another connection'))
    return true
  }

  /** The answer to this connection's open dialog: the response with its id, echoing its handle. */
  #answer(msg: Rpc): void {
    const d = this.#dialog
    if (d === null || msg.id !== d.id) {
      this.host_.log.log('warn', 'dialog-unknown', { connection: this.handle })
      return
    }
    if (msg.error !== undefined) {
      d.reject(new ToolError('cancelled', 'the host answered the dialog with an error'))
      return
    }
    const result = isObject(msg.result) ? msg.result : {}
    const echo = isObject(result._meta) ? result._meta[DIALOG_META] : undefined
    if (echo !== d.handle) {
      this.host_.log.log('warn', 'dialog-unechoed', { connection: this.handle })
      this.#refuse(
        null,
        new StreamError('usage', `a dialog answer echoes its handle in result._meta["${DIALOG_META}"]`),
      )
      return
    }
    const parsed = ElicitResultSchema.safeParse(result)
    if (!parsed.success) {
      d.reject(new ToolError('cancelled', 'the dialog answer is not an elicitation result'))
      return
    }
    d.resolve(parsed.data)
  }

  async #helloOf(msg: Rpc): Promise<void> {
    const id = msg.id
    const refuse = (e: StreamError): void => {
      this.host_.log.log('warn', 'hello-refused', { code: e.code })
      this.#refuse(id, e)
      this.close()
    }
    if (msg.method !== 'service/hello' || id === undefined)
      return refuse(new StreamError('usage', 'service/hello first'))
    const p = msg.params
    // The token first: a client without it learns nothing of the hello's shape or members.
    if (!isObject(p) || !tokenMatches(p.token, this.host_.token))
      return refuse(new StreamError('bad-auth', 'the launch token'))
    const extra = Object.keys(p).find((k) => !HELLO_KEYS.includes(k))
    if (extra !== undefined)
      return refuse(new StreamError('usage', `unknown member ${JSON.stringify(extra)}`))
    if (typeof p.contract !== 'number' || !CONTRACTS.includes(p.contract))
      return refuse(
        new StreamError('bad-version', `contract ${JSON.stringify(p.contract)}`, { supported: CONTRACTS }),
      )
    const caps = p.client_capabilities ?? {}
    if (typeof p.host !== 'string' || typeof p.cwd !== 'string' || !isAbsolute(p.cwd) || !isObject(caps))
      return refuse(
        new StreamError('usage', 'host is a string, cwd an absolute path, client_capabilities an object'),
      )
    if (p.input_hook !== undefined && typeof p.input_hook !== 'boolean')
      return refuse(new StreamError('usage', 'input_hook is true or false'))
    const admitted = this.host_.admit()
    if (admitted !== null) return refuse(admitted)
    this.#hello = {
      contract: p.contract,
      host: p.host,
      cwd: p.cwd,
      capabilities: caps,
      inputHook: p.input_hook === true,
    }
    if (this.#helloTimer !== null) clearTimeout(this.#helloTimer)
    this.#helloTimer = null
    let made: Rpc
    try {
      made = this.host_.prepare?.(this) ?? {}
    } catch (e) {
      this.#hello = null
      return refuse(new StreamError('unsafe-path', (e as Error).message))
    }
    const transport = this.host_.attach(this)
    this.#transport = transport as Transport & { deliver(m: JSONRPCMessage): void }
    this.#send({
      jsonrpc: '2.0',
      id,
      result: {
        contract: p.contract,
        ...this.host_.facts(),
        connection: this.handle,
        dialog_capable: this.capabilities.elicitation,
        ...made,
      },
    })
  }
}

/** The launch token, compared in constant time; anything but 64 hex characters is no match. */
export function tokenMatches(given: unknown, token: Buffer): boolean {
  if (typeof given !== 'string' || !/^[0-9a-f]{64}$/.test(given)) return false
  return timingSafeEqual(Buffer.from(given, 'hex'), token)
}

/** A transport for one connection's MCP server: what the server sends goes out as lines; deliver feeds it. */
export function connectionTransport(conn: Connection): Transport & { deliver(m: JSONRPCMessage): void } {
  const t: Transport & { deliver(m: JSONRPCMessage): void } = {
    start: async () => {},
    send: async (message) => conn.send(message),
    close: async () => conn.close(),
    deliver: (m) => t.onmessage?.(m),
  }
  return t
}

/**
 * Binds the socket at `sock` under umask 077, mode 0600, after removing a leftover socket (only a socket: anything
 * else there is unsafe-path). Call only while holding the service lock.
 */
export async function bindSocket(sock: string, onConnection: (s: Socket) => void): Promise<Server> {
  try {
    const st = lstatSync(sock)
    if (!st.isSocket()) throw new ConfigError('unsafe-path', `${sock} exists and is not a socket`)
    unlinkSync(sock)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e
  }
  const server = createServer(onConnection)
  const old = process.umask(0o077)
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(sock, () => {
        server.removeListener('error', reject)
        resolve()
      })
    })
  } finally {
    process.umask(old)
  }
  chmodSync(sock, 0o600)
  return server
}

/** Reads a token file's 64 hex characters, or null. */
export function readToken(path: string): string | null {
  try {
    const t = readFileSync(path, 'utf8').trim()
    return /^[0-9a-f]{64}$/.test(t) ? t : null
  } catch {
    return null
  }
}
