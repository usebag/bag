// The shim as a process, between a fake MCP host on its stdio and a fake service on a real unix socket.
import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { postBridge } from '../src/channel.ts'
import { frame, Lines, type Message } from '../src/frames.ts'
import { dropHome, FakeService, shortHome } from './fake-service.ts'

const MAIN = join(import.meta.dirname, '..', 'src', 'main.ts')

class FakeHost {
  readonly child: ChildProcessWithoutNullStreams
  readonly got: Message[] = []
  stderr = ''
  readonly exited: Promise<number | null>
  #waiters: { test: (m: Message) => boolean; resolve: (m: Message) => void }[] = []

  constructor(home: string, env: Record<string, string>, args: string[] = []) {
    this.child = spawn(process.execPath, [MAIN, '--dir', home, ...args], {
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, ...env },
      stdio: 'pipe',
    })
    const lines = new Lines()
    this.child.stdout.on('data', (c: Buffer) => {
      for (const m of lines.push(c).messages) {
        this.got.push(m)
        for (const w of [...this.#waiters]) {
          if (w.test(m)) {
            this.#waiters.splice(this.#waiters.indexOf(w), 1)
            w.resolve(m)
          }
        }
      }
    })
    this.child.stderr.on('data', (c: Buffer) => {
      this.stderr += c.toString()
    })
    this.exited = new Promise((resolve) => this.child.on('exit', (code) => resolve(code)))
  }

  send(m: Message): void {
    this.child.stdin.write(frame(m))
  }

  next(test: (m: Message) => boolean): Promise<Message> {
    const had = this.got.find(test)
    if (had !== undefined) return Promise.resolve(had)
    return new Promise((resolve) => this.#waiters.push({ test, resolve }))
  }

  byId(id: unknown): Promise<Message> {
    return this.next((m) => m.id === id && m.method === undefined)
  }

  async initialize(): Promise<Message> {
    this.send({
      jsonrpc: '2.0',
      id: 0,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: { elicitation: { form: {} } },
        clientInfo: { name: 'claude-code', version: '2.1.0' },
      },
    })
    const r = await this.byId(0)
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized' })
    return r
  }
}

function runHook(home: string, input: string): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [MAIN, 'hook', '--dir', home], {
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home },
    })
    let out = ''
    c.stdout.on('data', (d: Buffer) => {
      out += d.toString()
    })
    c.on('exit', (code) => resolve({ code, out }))
    c.stdin.end(input)
  })
}

let home: string
let svc: FakeService
let host: FakeHost | null = null

beforeEach(async () => {
  home = shortHome()
  svc = new FakeService(home)
  await svc.start()
})

afterEach(async () => {
  if (host !== null && host.child.exitCode === null) host.child.kill('SIGKILL')
  host = null
  await svc.close()
  dropHome(home)
})

describe('bag-shim between a host and the service', () => {
  it('initializes through the proxy, round-trips a tool call, a dialog with its handle and a ring', async () => {
    host = new FakeHost(home, { CLAUDECODE: '1' })
    const init = await host.initialize()
    expect(init.result).toMatchObject({ serverInfo: { name: 'bag' } })
    expect(svc.hellos[0]).toMatchObject({
      contract: 1,
      host: 'claude-code',
      token: svc.token,
      input_hook: false,
    })

    host.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'echo', arguments: { text: 'hi' } },
    })
    expect((await host.byId(1)).result).toEqual({ content: [{ type: 'text', text: 'echo hi' }] })

    const asked = svc.ask('elicitation/create', {
      message: 'pair with qrfolk?',
      requestedSchema: { type: 'object', properties: {} },
      _meta: { 'bag.dev/dialog': 'cd'.repeat(16) },
    })
    const shown = await host.next((m) => m.method === 'elicitation/create')
    expect(shown.params?._meta).toBeUndefined()
    host.send({ jsonrpc: '2.0', id: shown.id as string, result: { action: 'accept', content: {} } })
    expect((await asked).result).toEqual({
      action: 'accept',
      content: {},
      _meta: { 'bag.dev/dialog': 'cd'.repeat(16) },
    })

    const ringFile = join(home, 'run', 'shim', `${process.pid}.ring`)
    svc.notify('service/ring', { as: 'omp', unread: 1, speaking: true, at: '2026-11-12T12:45:10Z' })
    for (let i = 0; i < 50 && !existsSync(ringFile); i++) await new Promise((r) => setTimeout(r, 20))
    expect(statSync(ringFile).mode & 0o777).toBe(0o600)
    expect(JSON.parse(readFileSync(ringFile, 'utf8'))).toEqual({
      v: 1,
      n: 1,
      as: 'omp',
      unread: 1,
      speaking: true,
      at: '2026-11-12T12:45:10Z',
      shim: host.child.pid,
    })
    svc.notify('service/ring', { as: 'omp', unread: 2, speaking: false, at: '2026-11-12T12:45:11Z' })
    for (let i = 0; i < 50 && JSON.parse(readFileSync(ringFile, 'utf8')).n !== 2; i++) {
      await new Promise((r) => setTimeout(r, 20))
    }
    expect(JSON.parse(readFileSync(ringFile, 'utf8'))).toMatchObject({ n: 2, speaking: false, unread: 2 })
    expect(existsSync(join(home, 'state', 'omp', 'doorbell'))).toBe(false)

    host.child.stdin.end()
    expect(await host.exited).toBe(0)
    await new Promise((r) => setTimeout(r, 50))
    expect(svc.conns.every((c) => c.closed)).toBe(true)
    expect(existsSync(ringFile)).toBe(false)
  })

  it('fails a call in flight when the service restarts, and reconnects with the new token', async () => {
    host = new FakeHost(home, { CLAUDECODE: '1' })
    await host.initialize()
    svc.tools.set('send', () => undefined)
    host.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'send', arguments: { to: 'x' } },
    })
    await svc.next((m) => m.id === 2)
    await svc.restart()
    const r = await host.byId(2)
    expect(r.error?.message).toContain('was not sent again')
    await host.next((m) => m.method === 'notifications/tools/list_changed')
    expect(svc.hellos.at(-1)?.token).toBe(svc.token)
    // restart() starts a new connection list: the call reached the old service once and the new one never.
    expect(svc.conns.flatMap((c) => c.got).filter((m) => m.id === 2)).toHaveLength(0)
    host.child.kill('SIGTERM')
    expect(await host.exited).toBe(0)
  })

  it('closes cleanly on SIGTERM and on SIGHUP: the service sees the connection close', async () => {
    for (const sig of ['SIGTERM', 'SIGHUP'] as const) {
      host = new FakeHost(home, { CLAUDECODE: '1' })
      await host.initialize()
      const c = svc.conn
      host.child.kill(sig)
      expect(await host.exited).toBe(0)
      await new Promise((r) => setTimeout(r, 50))
      expect(c.closed).toBe(true)
      expect(host.stderr).toContain(`"reason":"${sig}"`)
    }
  })

  it('never writes the token to stderr or stdout', async () => {
    host = new FakeHost(home, { CLAUDECODE: '1' })
    await host.initialize()
    host.child.kill('SIGTERM')
    await host.exited
    expect(host.stderr).not.toContain(svc.token)
    expect(JSON.stringify(host.got)).not.toContain(svc.token)
  })

  it('carries the typed word from the hook to its own shim, which binds via typed; other prompts pass', async () => {
    host = new FakeHost(home, { CLAUDECODE: '1' }, ['--input-hook'])
    await host.initialize()
    expect(svc.hellos[0]).toMatchObject({ input_hook: true })
    const index = join(home, 'run', 'shim', `${process.pid}.json`)
    expect(statSync(index).mode & 0o777).toBe(0o600)
    expect(statSync(join(home, 'run', 'shim')).mode & 0o777).toBe(0o700)

    const bound = await runHook(home, JSON.stringify({ prompt: 'use omp-3', session_id: 's' }))
    expect(bound.code).toBe(0)
    expect(JSON.parse(bound.out)).toEqual({
      decision: 'block',
      reason: 'bag: this session now acts as omp-3.',
    })
    expect((await svc.next((m) => m.method === 'service/use')).params).toEqual({
      label: 'omp-3',
      via: 'typed',
    })

    expect(await runHook(home, JSON.stringify({ prompt: 'please use omp-3' }))).toEqual({ code: 0, out: '' })
    expect(await runHook(home, 'not json')).toEqual({ code: 0, out: '' })
    svc.useAnswer = () => ({ code: 'unknown-identity' })
    expect(await runHook(home, JSON.stringify({ prompt: 'use pandas' }))).toEqual({ code: 0, out: '' })
    svc.useAnswer = () => ({ code: 'busy' })
    const busy = await runHook(home, JSON.stringify({ prompt: 'USE omp' }))
    expect(JSON.parse(busy.out).reason).toBe('bag: this session was not bound to omp (busy).')

    host.child.stdin.end()
    expect(await host.exited).toBe(0)
    expect(readdirSync(join(home, 'run', 'shim'))).toEqual([])
    expect(await runHook(home, JSON.stringify({ prompt: 'use omp' }))).toEqual({ code: 0, out: '' })
  })

  it('gives an omp extension the bridge folder the service named, only after the hello reply', async () => {
    const folder = join(home, 'run', 'shim', 'c-9.consent')
    mkdirSync(folder, { recursive: true, mode: 0o700 })
    svc.bridgeDir = folder
    host = new FakeHost(home, { OMPCODE: '1' }, ['--input-hook'])
    const index = join(home, 'run', 'shim', `${process.pid}.json`)
    for (let i = 0; i < 100 && !existsSync(index); i++) await new Promise((r) => setTimeout(r, 20))
    expect(await postBridge(home, [process.pid])).toBeNull()
    host.send({
      jsonrpc: '2.0',
      id: 0,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'omp', version: '18' } },
    })
    await host.byId(0)
    expect(svc.hellos[0]?.client_capabilities).toEqual({ experimental: { 'bag.dev/consent-bridge': {} } })
    expect(await postBridge(home, [process.pid])).toBe(folder)
    host.child.kill('SIGTERM')
    expect(await host.exited).toBe(0)
  })

  it('answers a usage error and help', async () => {
    const r = await new Promise<number | null>((resolve) => {
      const c = spawn(process.execPath, [MAIN, '--bogus'], { stdio: 'ignore' })
      c.on('exit', resolve)
    })
    expect(r).toBe(2)
    // No shebang in the source: the bundle adds one (packages/bag/src/build.ts), and a second would not parse.
    expect(readFileSync(MAIN, 'utf8').startsWith('#!')).toBe(false)
  })
})
