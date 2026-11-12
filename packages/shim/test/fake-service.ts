// A fake bag service for the shim's tests: a real unix socket under a short throwaway home (/tmp/bs-*, so the socket
// path fits sun_path), contract 1's hello with the launch token checked, an MCP initialize, and hooks a test drives:
// tool handlers, dialogs, rings, drains, a crash and a restart.
import { randomBytes } from 'node:crypto'
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { join } from 'node:path'
import { frame, Lines, type Message } from '../src/frames.ts'

export function shortHome(): string {
  const home = mkdtempSync('/tmp/bs-')
  return home
}

/** Moves a throwaway home to the Trash-free end of its life: everything under /tmp/bs-* only. */
export function dropHome(home: string): void {
  if (!home.startsWith('/tmp/bs-')) throw new Error(`not a test home: ${home}`)
  rmSync(home, { recursive: true, force: true })
}

export interface FakeConn {
  readonly socket: Socket
  readonly hello: Record<string, unknown> | null
  readonly got: Message[]
  send(m: Message): void
  closed: boolean
}

export type ToolHandler = (
  args: Record<string, unknown>,
  conn: FakeConn,
  id: unknown,
) => unknown | Promise<unknown>

export class FakeService {
  readonly home: string
  token = randomBytes(32).toString('hex')
  server: Server | null = null
  conns: FakeConn[] = []
  tools = new Map<string, ToolHandler>()
  /** Every hello seen, in order. */
  hellos: Record<string, unknown>[] = []
  /** Answers to service/use: a result object or an error {code}. */
  useAnswer: (params: Record<string, unknown>) => Record<string, unknown> = (p) => ({
    bound: true,
    as: p.label,
    address: 'ed25519:00',
    custody: 'home-key',
    granted: 'typed',
  })
  helloError: Record<string, unknown> | null = null
  initError: Record<string, unknown> | null = null
  /** The bridge folder the hello reply names (the service makes it), or none. */
  bridgeDir: string | null = null
  /** A hello result to answer with as it is, in place of the fake's own (the service's exact shape). */
  helloResult: Record<string, unknown> | null = null
  /** A service/use reply to send as it is (its result or error member), in place of useAnswer. */
  useRaw: Record<string, unknown> | null = null
  #waiters: { test: (m: Message, c: FakeConn) => boolean; resolve: (m: Message) => void }[] = []
  #seq = 0

  constructor(home: string) {
    this.home = home
    this.tools.set('echo', (args) => ({ content: [{ type: 'text', text: `echo ${String(args.text)}` }] }))
  }

  get socketPath(): string {
    return join(this.home, 'run', 'service.sock')
  }

  async start(): Promise<void> {
    mkdirSync(join(this.home, 'run'), { recursive: true, mode: 0o700 })
    rmSync(this.socketPath, { force: true })
    const server = createServer((s) => this.#accept(s))
    await new Promise<void>((resolve) => server.listen(this.socketPath, resolve))
    this.server = server
    const tmp = join(this.home, 'run', 'service.token.tmp')
    writeFileSync(tmp, `${this.token}\n`, { mode: 0o600 })
    renameSync(tmp, join(this.home, 'run', 'service.token'))
    writeFileSync(join(this.home, 'run', 'service.json'), JSON.stringify({ pid: process.pid, contract: 1 }), {
      mode: 0o600,
    })
  }

  /** Stops listening and drops every connection, as a crash does. */
  async crash(): Promise<void> {
    for (const c of this.conns) c.socket.destroy()
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()))
    this.server = null
    rmSync(this.socketPath, { force: true })
  }

  /** A crash, then a new service with a new token. */
  async restart(): Promise<void> {
    await this.crash()
    this.token = randomBytes(32).toString('hex')
    this.conns = []
    await this.start()
  }

  /** The newest connection that passed hello. */
  get conn(): FakeConn {
    const c = this.conns.filter((x) => x.hello !== null && !x.closed).at(-1)
    if (c === undefined) throw new Error('no connection')
    return c
  }

  /** Resolves with the first message (past or future) on any connection that passes test. */
  next(test: (m: Message, c: FakeConn) => boolean): Promise<Message> {
    for (const c of this.conns) for (const m of c.got) if (test(m, c)) return Promise.resolve(m)
    return new Promise((resolve) => this.#waiters.push({ test, resolve }))
  }

  /** Sends a request from the service on the newest connection; resolves with the shim's response. */
  ask(method: string, params: Record<string, unknown>): Promise<Message> {
    const id = `svc-${++this.#seq}`
    const c = this.conn
    c.send({ jsonrpc: '2.0', id, method, params })
    return this.next((m, cc) => cc === c && m.id === id && m.method === undefined)
  }

  notify(method: string, params: Record<string, unknown>): void {
    this.conn.send({ jsonrpc: '2.0', method, params })
  }

  async close(): Promise<void> {
    await this.crash()
  }

  #accept(socket: Socket): void {
    const lines = new Lines()
    const conn: FakeConn = {
      socket,
      hello: null,
      got: [],
      closed: false,
      send: (m) => {
        if (!socket.destroyed) socket.write(frame(m))
      },
    }
    this.conns.push(conn)
    socket.on('error', () => {})
    socket.on('close', () => {
      conn.closed = true
    })
    socket.on('data', (chunk: Buffer) => {
      for (const m of lines.push(chunk).messages) {
        conn.got.push(m)
        void this.#handle(conn, m)
        for (const w of [...this.#waiters]) {
          if (w.test(m, conn)) {
            this.#waiters.splice(this.#waiters.indexOf(w), 1)
            w.resolve(m)
          }
        }
      }
    })
  }

  async #handle(c: FakeConn, m: Message): Promise<void> {
    const id = m.id as string | number
    if (m.method === 'service/hello') {
      const p = m.params ?? {}
      this.hellos.push(p)
      if (this.helloError !== null) {
        c.send({ jsonrpc: '2.0', id, error: this.helloError as never })
        c.socket.end()
        return
      }
      if (p.token !== this.token) {
        c.send({
          jsonrpc: '2.0',
          id,
          error: { code: -32000, message: 'bad-auth: launch token', data: { code: 'bad-auth' } },
        })
        c.socket.end()
        return
      }
      ;(c as { hello: Record<string, unknown> | null }).hello = p
      if (this.helloResult !== null) {
        c.send({ jsonrpc: '2.0', id, result: this.helloResult })
        return
      }
      c.send({
        jsonrpc: '2.0',
        id,
        result: {
          contract: 1,
          service: { version: '0.4.0', pid: process.pid, started_at: '2026-11-12T12:00:00Z' },
          connection: 'c-1',
          dialog_capable: true,
          draining: false,
          ...(this.bridgeDir === null ? {} : { bridge_dir: this.bridgeDir }),
        },
      })
      return
    }
    if (c.hello === null) {
      c.send({
        jsonrpc: '2.0',
        id: m.id ?? null,
        error: { code: -32600, message: 'usage: service/hello first' },
      })
      c.socket.end()
      return
    }
    if (m.method === 'initialize') {
      if (this.initError !== null) {
        c.send({ jsonrpc: '2.0', id, error: this.initError as never })
        return
      }
      c.send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: (m.params?.protocolVersion as string) ?? '2025-06-18',
          capabilities: { tools: { listChanged: true }, logging: {} },
          serverInfo: { name: 'bag', version: '0.4.0' },
        },
      })
      return
    }
    if (m.method === 'service/use') {
      if (this.useRaw !== null) {
        c.send({ jsonrpc: '2.0', id, ...this.useRaw } as never)
        return
      }
      const a = this.useAnswer(m.params ?? {})
      if (typeof a.code === 'string') {
        c.send({
          jsonrpc: '2.0',
          id,
          error: { code: -32000, message: `${a.code}: no`, data: { code: a.code } },
        })
      } else c.send({ jsonrpc: '2.0', id, result: a })
      return
    }
    if (m.method === 'tools/list') {
      c.send({
        jsonrpc: '2.0',
        id,
        result: { tools: [...this.tools.keys()].map((name) => ({ name, inputSchema: { type: 'object' } })) },
      })
      return
    }
    if (m.method === 'tools/call') {
      const name = String(m.params?.name)
      const h = this.tools.get(name)
      if (h === undefined) {
        c.send({ jsonrpc: '2.0', id, error: { code: -32602, message: `unknown tool ${name}` } })
        return
      }
      const result = await h((m.params?.arguments ?? {}) as Record<string, unknown>, c, id)
      if (result !== undefined && !c.closed) c.send({ jsonrpc: '2.0', id, result })
    }
  }
}
