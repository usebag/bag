import { mkdirSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { bridgeDirOf } from '../src/bridge.ts'
import type { Message } from '../src/frames.ts'
import type { Ring } from '../src/ring.ts'
import { socketConnect } from '../src/service.ts'
import { absentText, LOST_TEXT, RESUME_TOOL, Shim, type ShimDeps } from '../src/shim.ts'
import { readToken, SHIM_VERSION, socketOf, tokenFileOf } from '../src/wire.ts'
import { dropHome, FakeService, shortHome } from './fake-service.ts'

const INIT = {
  jsonrpc: '2.0' as const,
  id: 0,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: { elicitation: { form: {} } },
    clientInfo: { name: 'claude-code', version: '2.1.0' },
  },
}

function harness(home: string, more: Partial<ShimDeps> = {}) {
  const host: Message[] = []
  const logs: { event: string; fields?: Record<string, unknown> }[] = []
  const waiters: { test: (m: Message) => boolean; resolve: (m: Message) => void }[] = []
  const shim = new Shim({
    connect: socketConnect(socketOf(home)),
    toHost: (m) => {
      host.push(m)
      for (const w of [...waiters]) {
        if (w.test(m)) {
          waiters.splice(waiters.indexOf(w), 1)
          w.resolve(m)
        }
      }
    },
    log: (event, fields) => logs.push(fields === undefined ? { event } : { event, fields }),
    env: {},
    cwd: '/work/repo',
    pid: 4242,
    home,
    socketPath: socketOf(home),
    token: () => readToken(tokenFileOf(home)),
    retryMs: () => 30,
    startWaitMs: 300,
    ...more,
  })
  const next = (test: (m: Message) => boolean): Promise<Message> => {
    const had = host.find(test)
    if (had !== undefined) return Promise.resolve(had)
    return new Promise((resolve) => waiters.push({ test, resolve }))
  }
  const byId = (id: unknown) => next((m) => m.id === id && m.method === undefined)
  return { shim, host, logs, next, byId }
}

const call = (id: number, name: string, args: Record<string, unknown> = {}): Message => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name, arguments: args },
})

let home: string
let svc: FakeService

beforeEach(async () => {
  home = shortHome()
  svc = new FakeService(home)
  await svc.start()
})

afterEach(async () => {
  await svc.close()
  dropHome(home)
})

async function up(h: ReturnType<typeof harness>, init: Message = INIT) {
  h.shim.fromHost(init)
  const r = await h.byId(init.id)
  h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/initialized' })
  await svc.next((m) => m.method === 'notifications/initialized')
  return r
}

describe('the hello and initialize', () => {
  it('sends contract 1 hello with the host kind, cwd, token and capabilities, then the host initialize', async () => {
    const h = harness(home)
    const r = await up(h)
    expect(r.result).toMatchObject({ serverInfo: { name: 'bag' }, capabilities: { tools: {} } })
    expect(svc.hellos).toEqual([
      {
        contract: 1,
        token: svc.token,
        host: 'claude-code',
        cwd: '/work/repo',
        client_capabilities: { elicitation: { form: {} } },
        input_hook: false,
        shim: { version: SHIM_VERSION, pid: 4242 },
      },
    ])
    const init = await svc.next((m) => m.method === 'initialize')
    expect(init.params).toEqual(INIT.params)
    expect(h.shim.phase).toBe('up')
    h.shim.close()
  })

  it('reads the host kind from the environment first: OMPCODE beats CLAUDECODE; codex only from the client name', async () => {
    const h = harness(home, { env: { OMPCODE: '1', CLAUDECODE: '1' }, inputHook: true })
    await up(h)
    expect(svc.hellos[0]).toMatchObject({ host: 'omp', input_hook: true })
    h.shim.close()
    const c = harness(home)
    await up(c, {
      ...INIT,
      params: { ...INIT.params, clientInfo: { name: 'codex-mcp-client', version: '0.6' } },
    })
    expect(svc.hellos[1]).toMatchObject({ host: 'codex', input_hook: false })
    c.shim.close()
  })

  it('refuses a second initialize from the host', async () => {
    const h = harness(home)
    await up(h)
    h.shim.fromHost({ ...INIT, id: 9 })
    expect((await h.byId(9)).error?.code).toBe(-32600)
    h.shim.close()
  })
})

describe('a tool call round trip', () => {
  it('forwards a call unchanged and relays the result, progress passed through', async () => {
    const h = harness(home)
    await up(h)
    svc.tools.set('slow', async (_a, c) => {
      c.send({
        jsonrpc: '2.0',
        method: 'notifications/progress',
        params: { progressToken: 'p1', progress: 1 },
      })
      return { content: [{ type: 'text', text: 'done' }] }
    })
    h.shim.fromHost({
      ...call(5, 'slow'),
      params: { name: 'slow', arguments: {}, _meta: { progressToken: 'p1' } },
    })
    const r = await h.byId(5)
    expect(r.result).toEqual({ content: [{ type: 'text', text: 'done' }] })
    expect(h.host.find((m) => m.method === 'notifications/progress')?.params).toEqual({
      progressToken: 'p1',
      progress: 1,
    })
    const sent = await svc.next((m) => m.id === 5)
    expect(sent.params?._meta).toEqual({ progressToken: 'p1' })
    h.shim.close()
  })

  it('passes the host cancellation through and forgets the call', async () => {
    const h = harness(home)
    await up(h)
    svc.tools.set('hang', () => undefined)
    h.shim.fromHost(call(6, 'hang'))
    await svc.next((m) => m.id === 6)
    h.shim.fromHost({
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: { requestId: 6, reason: 'esc' },
    })
    const c = await svc.next((m) => m.method === 'notifications/cancelled')
    expect(c.params).toEqual({ requestId: 6, reason: 'esc' })
    svc.conn.send({ jsonrpc: '2.0', id: 6, result: { content: [] } })
    await svc.next((m) => m.method === 'ping' || m.method === 'notifications/cancelled')
    expect(h.host.some((m) => m.id === 6)).toBe(false)
    h.shim.close()
  })
})

describe('dialogs', () => {
  it('carries an elicitation to the host under its own id, without the handle, and echoes the handle back', async () => {
    const h = harness(home)
    await up(h)
    const asked = svc.ask('elicitation/create', {
      message: 'bind this session to omp-3?',
      requestedSchema: { type: 'object', properties: {} },
      _meta: { 'bag.dev/dialog': 'ab'.repeat(16), other: 1 },
    })
    const shown = await h.next((m) => m.method === 'elicitation/create')
    expect(shown.id).not.toBe('svc-1')
    expect(shown.params?._meta).toEqual({ other: 1 })
    h.shim.fromHost({ jsonrpc: '2.0', id: shown.id as string, result: { action: 'accept', content: {} } })
    const answer = await asked
    expect(answer.id).toBe('svc-1')
    expect(answer.result).toEqual({
      action: 'accept',
      content: {},
      _meta: { 'bag.dev/dialog': 'ab'.repeat(16) },
    })
    h.shim.close()
  })

  it('sets no timeout of its own: a dialog answered after a long wait still reaches the service', async () => {
    const h = harness(home)
    await up(h)
    const asked = svc.ask('elicitation/create', {
      message: 'x',
      requestedSchema: {},
      _meta: { 'bag.dev/dialog': 'h' },
    })
    const shown = await h.next((m) => m.method === 'elicitation/create')
    await new Promise((r) => setTimeout(r, 300))
    h.shim.fromHost({
      jsonrpc: '2.0',
      id: shown.id as string,
      error: { code: -1, message: 'declined by host' },
    })
    expect((await asked).error).toEqual({ code: -1, message: 'declined by host' })
    h.shim.close()
  })

  it('passes the service cancellation of a dialog to the host under the shim id', async () => {
    const h = harness(home)
    await up(h)
    void svc.ask('elicitation/create', { message: 'x', requestedSchema: {} })
    const shown = await h.next((m) => m.method === 'elicitation/create')
    svc.notify('notifications/cancelled', { requestId: 'svc-1', reason: 'two minutes' })
    const c = await h.next((m) => m.method === 'notifications/cancelled')
    expect(c.params).toEqual({ requestId: shown.id, reason: 'two minutes' })
    h.shim.fromHost({ jsonrpc: '2.0', id: shown.id as string, result: { action: 'accept' } })
    expect(h.logs.some((l) => l.event === 'host-answer-unknown')).toBe(true)
    h.shim.close()
  })

  it('refuses a dialog from a service that does not own the home', async () => {
    const h = harness(home, { owner: () => false })
    await up(h)
    const r = await svc.ask('elicitation/create', { message: 'x', requestedSchema: {} })
    expect(r.error?.data).toEqual({ code: 'not-authorized' })
    expect(h.host.some((m) => m.method === 'elicitation/create')).toBe(false)
    h.shim.close()
  })

  it('answers a ping from the service itself', async () => {
    const h = harness(home)
    await up(h)
    expect((await svc.ask('ping', {})).result).toEqual({})
    h.shim.close()
  })

  it('announces the bridge capability for omp, takes the folder from the reply, and writes no consent file', async () => {
    const folder = join(home, 'run', 'shim', 'c-1.consent')
    mkdirSync(folder, { recursive: true, mode: 0o700 })
    svc.bridgeDir = folder
    const h = harness(home, {
      env: { OMPCODE: '1' },
      consentBridge: true,
      bridgeDirOf: (g) => bridgeDirOf(home, g),
    })
    await up(h, { ...INIT, params: { ...INIT.params, capabilities: {} } })
    expect(svc.hellos[0]?.client_capabilities).toEqual({ experimental: { 'bag.dev/consent-bridge': {} } })
    // The folder is the service's, read back from the hello reply; the shim named none and writes nothing in it.
    expect(h.shim.bridgeDir).toBe(folder)
    expect(Object.keys(svc.hellos[0] ?? {})).not.toContain('bridgeDir')
    void svc.ask('elicitation/create', {
      message: 'm',
      requestedSchema: {},
      _meta: { 'bag.dev/dialog': 'hh' },
    })
    const shown = await h.next((m) => m.method === 'elicitation/create')
    expect(shown.params?._meta).toBeUndefined()
    expect(readdirSync(folder)).toEqual([])
    h.shim.close()
  })

  it('adds no bridge capability for a host with elicitation, or without the installer flag', async () => {
    const h = harness(home, { env: { OMPCODE: '1' }, consentBridge: true })
    await up(h)
    expect(svc.hellos[0]?.client_capabilities).toEqual({ elicitation: { form: {} } })
    h.shim.close()
    const g = harness(home, { env: { OMPCODE: '1' } })
    await up(g, { ...INIT, params: { ...INIT.params, capabilities: {} } })
    expect(svc.hellos[1]?.client_capabilities).toEqual({})
    g.shim.close()
  })
})

describe('rings and notices', () => {
  it('passes every ring on with a sequence number, and a quiet one also as a log notice', async () => {
    const rung: Ring[] = []
    const h = harness(home, { ring: (r) => rung.push(r) })
    await up(h)
    svc.notify('service/ring', { as: 'omp', unread: 2, speaking: true, at: 'x' })
    svc.notify('service/ring', { as: 'omp', unread: 3, speaking: false, at: 'y' })
    svc.notify('service/ring', { as: 'omp-3' })
    const quiet = await h.next((m) => m.method === 'notifications/message')
    expect(quiet.params).toMatchObject({ level: 'info', logger: 'bag' })
    for (let i = 0; i < 50 && rung.length < 3; i++) await new Promise((r) => setTimeout(r, 10))
    expect(rung).toEqual([
      { n: 1, as: 'omp', unread: 2, speaking: true, at: 'x' },
      { n: 2, as: 'omp', unread: 3, speaking: false, at: 'y' },
      { n: 3, as: 'omp-3', unread: null, speaking: true, at: null },
    ])
    svc.notify('service/bound', { as: 'omp', granted: 'typed' })
    svc.notify('service/what', {})
    svc.notify('notifications/tools/list_changed', {})
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    expect(h.shim.bound).toEqual(['omp'])
    expect(h.host.some((m) => m.method?.startsWith('service/'))).toBe(false)
    h.shim.close()
  })

  it('passes a local pair request count on, and words the quiet notice for a request with nothing unread', async () => {
    const rung: Ring[] = []
    const h = harness(home, { ring: (r) => rung.push(r) })
    await up(h)
    svc.notify('service/ring', { as: 'omp', unread: 0, requests: 1, speaking: false, at: 'x' })
    const quiet = await h.next((m) => m.method === 'notifications/message')
    expect((quiet.params as { data?: unknown }).data).toBe(
      'a request from your own identity waits for omp; another window asks your person',
    )
    expect(rung).toEqual([{ n: 1, as: 'omp', unread: 0, requests: 1, speaking: false, at: 'x' }])
    h.shim.close()
  })

  it('never moves the doorbell on a service connection', async () => {
    const h = harness(home, { ring: () => {} })
    await up(h)
    svc.notify('service/ring', { as: 'omp', unread: 1, speaking: true, at: 'x' })
    await new Promise((r) => setTimeout(r, 50))
    expect(() => statSync(join(home, 'state', 'omp', 'doorbell'))).toThrow()
    h.shim.close()
  })
})

describe('the typed word', () => {
  it('sends service/use via typed on the connection and returns what the service said', async () => {
    const h = harness(home, { inputHook: true })
    expect(await h.shim.use('omp')).toEqual({ bound: false, code: 'not-connected' })
    await up(h)
    expect(await h.shim.use('omp-3')).toEqual({ bound: true, as: 'omp-3' })
    expect((await svc.next((m) => m.method === 'service/use')).params).toEqual({
      label: 'omp-3',
      via: 'typed',
    })
    svc.useAnswer = () => ({ code: 'unknown-identity' })
    expect(await h.shim.use('nope')).toEqual({ bound: false, code: 'unknown-identity' })
    h.shim.close()
  })
})

describe('a service that is not there', () => {
  it('starts it once, then answers every tool with one readable error naming the start line and login agent', async () => {
    await svc.crash()
    let starts = 0
    const h = harness(home, {
      start: () => {
        starts++
        return false
      },
    })
    h.shim.fromHost(INIT)
    const r = await h.byId(0)
    expect(starts).toBe(1)
    expect(r.result).toMatchObject({
      protocolVersion: '2025-06-18',
      capabilities: { tools: { listChanged: true } },
    })
    h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/initialized' })
    h.shim.fromHost({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    expect((await h.byId(1)).result).toMatchObject({ tools: [{ name: 'status' }] })
    h.shim.fromHost(call(2, 'send'))
    const text = ((await h.byId(2)).result as { content: { text: string }[]; isError: boolean }).content[0]
      ?.text
    expect(text).toBe(absentText(home))
    expect(text).toContain(`bag service start --dir ${home}`)
    expect(text).toContain('login agent')
    for (const [id, method] of [
      [3, 'ping'],
      [4, 'resources/list'],
      [5, 'prompts/list'],
      [6, 'completion/complete'],
    ] as const) {
      h.shim.fromHost({ jsonrpc: '2.0', id, method })
      expect(await h.byId(id)).toBeDefined()
    }
    h.shim.close()
  })

  it('connects when the service comes up later and tells the host the tools changed', async () => {
    await svc.crash()
    const h = harness(home, { start: () => false, retryMs: () => 50 })
    h.shim.fromHost(INIT)
    await h.byId(0)
    h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/initialized' })
    await svc.start()
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    expect(h.shim.phase).toBe('up')
    await svc.next((m) => m.method === 'notifications/initialized')
    h.shim.fromHost(call(7, 'echo', { text: 'hi' }))
    expect((await h.byId(7)).result).toEqual({ content: [{ type: 'text', text: 'echo hi' }] })
    h.shim.close()
  })

  it('waits for a service a start launched, within the start wait', async () => {
    await svc.crash()
    const h = harness(home, {
      startWaitMs: 3000,
      start: () => {
        setTimeout(() => void svc.start(), 200)
        return true
      },
    })
    const r = await up(h)
    expect(r.result).toMatchObject({ serverInfo: { name: 'bag', version: '0.4.0' } })
    expect(h.shim.phase).toBe('up')
    h.shim.close()
  })

  it('says a socket path too long for sun_path, and never tries it', async () => {
    const long = `/tmp/${'x'.repeat(120)}`
    const h = harness(home, { socketPath: join(long, 'run', 'service.sock'), home: long })
    h.shim.fromHost(INIT)
    const r = await h.byId(0)
    expect((r.result as { instructions: string }).instructions).toMatch(/the socket path is \d+ bytes/)
    h.shim.close()
  })

  it('names a version mismatch and the fix', async () => {
    svc.helloError = {
      code: -32000,
      message: 'bad-version: 2',
      data: { code: 'bad-version', supported: [2] },
    }
    const h = harness(home)
    h.shim.fromHost(INIT)
    expect(((await h.byId(0)).result as { instructions: string }).instructions).toContain(
      'Re-run your install step',
    )
    h.shim.close()
  })

  it('treats a draining refusal as a retry later', async () => {
    svc.helloError = { code: -32000, message: 'draining', data: { code: 'draining', retry_after_ms: 40 } }
    const h = harness(home)
    h.shim.fromHost(INIT)
    expect(((await h.byId(0)).result as { instructions: string }).instructions).toContain('restarting')
    svc.helloError = null
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    expect(h.shim.phase).toBe('up')
    h.shim.close()
  })
})

describe('a service that restarts mid-call', () => {
  it('fails the call in flight with a readable error, never resends it, and reconnects unbound', async () => {
    const h = harness(home)
    await up(h)
    svc.tools.set('send', () => undefined)
    h.shim.fromHost(call(8, 'send', { to: 'qrfolk', body: 'hello' }))
    await svc.next((m) => m.id === 8)
    void svc.ask('elicitation/create', { message: 'x', requestedSchema: {} })
    const shown = await h.next((m) => m.method === 'elicitation/create')
    await svc.restart()
    const r = await h.byId(8)
    expect(r.error).toEqual({ code: -32000, message: LOST_TEXT })
    const cancelled = await h.next((m) => m.method === 'notifications/cancelled')
    expect(cancelled.params?.requestId).toBe(shown.id)
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    await svc.next((m, c) => c === svc.conn && m.method === 'notifications/initialized')
    expect(svc.hellos.at(-1)?.token).toBe(svc.token)
    // The new connection got the hello, the initialize and initialized again, and no tools/call: nothing resent.
    const methods = svc.conn.got.map((m) => m.method)
    expect(methods).toEqual(['service/hello', 'initialize', 'notifications/initialized'])
    h.shim.fromHost({ jsonrpc: '2.0', id: shown.id as string, result: { action: 'accept' } })
    expect(h.logs.some((l) => l.event === 'host-answer-unknown')).toBe(true)
    h.shim.close()
  })

  it('holds new calls during a drain and sends them on the next connection', async () => {
    const h = harness(home)
    await up(h)
    svc.notify('service/draining', { retry_after_ms: 50, reason: 'upgrade' })
    await new Promise((r) => setTimeout(r, 30))
    h.shim.fromHost(call(9, 'echo', { text: 'later' }))
    await new Promise((r) => setTimeout(r, 30))
    expect(svc.conn.got.some((m) => m.id === 9)).toBe(false)
    await svc.restart()
    expect((await h.byId(9)).result).toEqual({ content: [{ type: 'text', text: 'echo later' }] })
    h.shim.close()
  })

  it('drops a call the host cancels while it waits in the queue', async () => {
    const h = harness(home)
    await up(h)
    svc.notify('service/draining', { retry_after_ms: 50, reason: 'stop' })
    await new Promise((r) => setTimeout(r, 30))
    h.shim.fromHost(call(10, 'echo'))
    h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 10 } })
    await svc.restart()
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    expect(svc.conn.got.some((m) => m.id === 10)).toBe(false)
    h.shim.close()
  })
})

describe('resume tokens for a host with a short tool timeout (Codex)', () => {
  const codex = {
    ...INIT,
    params: { ...INIT.params, clientInfo: { name: 'codex-mcp-client', version: '0.6' } },
  }

  it('adds the resume tool, answers a long call with a token, and resume returns the result', async () => {
    const h = harness(home, { parkMs: 100, newToken: () => 'tok1' })
    await up(h, codex)
    h.shim.fromHost({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    const tools = ((await h.byId(1)).result as { tools: { name: string }[] }).tools.map((t) => t.name)
    expect(tools).toContain(RESUME_TOOL.name)
    let finish: (v: unknown) => void = () => {}
    svc.tools.set('wait', () => new Promise((r) => (finish = r)))
    h.shim.fromHost(call(2, 'wait'))
    const first = (await h.byId(2)).result as { content: { text: string }[] }
    expect(first.content[0]?.text).toContain('token "tok1"')
    h.shim.fromHost(call(3, 'resume', { token: 'tok1' }))
    const again = (await h.byId(3)).result as { content: { text: string }[] }
    expect(again.content[0]?.text).toContain('still running')
    h.shim.fromHost(call(4, 'resume', { token: 'tok1' }))
    finish({ content: [{ type: 'text', text: 'mail' }] })
    expect((await h.byId(4)).result).toEqual({ content: [{ type: 'text', text: 'mail' }] })
    h.shim.fromHost(call(5, 'resume', { token: 'tok1' }))
    expect(((await h.byId(5)).result as { isError: boolean }).isError).toBe(true)
    h.shim.close()
  })

  it('keeps a result that came before the resume, and a lost connection as the error of the token', async () => {
    let n = 0
    const h = harness(home, { parkMs: 60, newToken: () => `t${++n}` })
    await up(h, codex)
    let finish: (v: unknown) => void = () => {}
    svc.tools.set('wait', () => new Promise((r) => (finish = r)))
    h.shim.fromHost(call(2, 'wait'))
    await h.byId(2)
    finish({ content: [{ type: 'text', text: 'early' }] })
    await new Promise((r) => setTimeout(r, 50))
    h.shim.fromHost(call(3, 'resume', { token: 't1' }))
    expect((await h.byId(3)).result).toEqual({ content: [{ type: 'text', text: 'early' }] })
    svc.tools.set('hang', () => undefined)
    h.shim.fromHost(call(4, 'hang'))
    await h.byId(4)
    h.shim.fromHost(call(5, 'resume', { token: 't2' }))
    await svc.restart()
    expect((await h.byId(5)).error?.message).toBe(LOST_TEXT)
    h.shim.close()
  })
})

describe('close', () => {
  it('ends the connection, so the service sees the close; later host messages are ignored', async () => {
    const h = harness(home)
    await up(h)
    const c = svc.conn
    h.shim.close()
    h.shim.close()
    await new Promise((r) => setTimeout(r, 100))
    expect(c.closed).toBe(true)
    expect(h.shim.phase).toBe('closed')
    h.shim.fromHost(call(1, 'echo'))
    expect(h.host.some((m) => m.id === 1)).toBe(false)
  })
})

describe('the bridge folder', () => {
  it('reads bridge_dir from a hello reply in the service shape (packages/mcp/test/service.test.ts, the omp bridge)', async () => {
    const connection = 'c-1'
    const dir = join(home, 'run', 'shim', `${connection}.consent`)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    // The hello result as packages/mcp/src/service.ts answers an omp hello naming bag.dev/consent-bridge.
    const reply = {
      contract: 1,
      service: { version: '0.4.0', pid: process.pid, started_at: '2026-11-12T12:00:00.000Z' },
      connection,
      dialog_capable: false,
      draining: false,
      bridge_dir: dir,
    }
    svc.helloResult = reply
    const h = harness(home, {
      env: { OMPCODE: '1' },
      consentBridge: true,
      bridgeDirOf: (g) => bridgeDirOf(home, g),
    })
    await up(h, { ...INIT, params: { ...INIT.params, capabilities: {} } })
    expect(h.shim.bridgeDir).toBe(dir)
    h.shim.close()
  })

  it('refuses a folder the reply names outside the shape, and forgets it when the connection goes', async () => {
    svc.bridgeDir = '/tmp/elsewhere.consent'
    const h = harness(home, { env: { OMPCODE: '1' }, bridgeDirOf: (g) => bridgeDirOf(home, g) })
    await up(h)
    expect(h.shim.bridgeDir).toBeNull()
    expect(h.logs.some((l) => l.event === 'bridge-dir-refused')).toBe(true)
    h.shim.close()
    const folder = join(home, 'run', 'shim', 'c-2.consent')
    mkdirSync(folder, { recursive: true, mode: 0o700 })
    svc.bridgeDir = folder
    const g = harness(home, { env: { OMPCODE: '1' }, bridgeDirOf: (x) => bridgeDirOf(home, x) })
    await up(g)
    expect(g.shim.bridgeDir).toBe(folder)
    svc.bridgeDir = null
    await svc.restart()
    await g.next((m) => m.method === 'notifications/tools/list_changed')
    expect(g.shim.bridgeDir).toBeNull()
    g.shim.close()
  })
})

describe('the bound identities', () => {
  it('reports each change of the binding set, and none after the connection is lost', async () => {
    const seen: (readonly string[])[] = []
    const h = harness(home, { boundChanged: (l) => seen.push(l) })
    await up(h)
    svc.notify('service/bound', { as: 'omp', granted: 'dialog' })
    expect(await h.shim.use('omp-3')).toEqual({ bound: true, as: 'omp-3' })
    svc.notify('service/bound', { as: 'omp-3', granted: 'typed' })
    await new Promise((r) => setTimeout(r, 30))
    expect(seen).toEqual([['omp'], ['omp', 'omp-3']])
    await svc.restart()
    await h.next((m) => m.method === 'notifications/tools/list_changed')
    expect(seen.at(-1)).toEqual([])
    h.shim.close()
  })
})

describe('the edges', () => {
  it('reports a connect error that is not "absent" and the generic and busy refusals', async () => {
    const h = harness(home, {
      connect: () => Promise.reject(Object.assign(new Error('io'), { code: 'EIO' })),
      retryMs: () => 10_000,
    })
    h.shim.fromHost(INIT)
    expect(((await h.byId(0)).result as { instructions: string }).instructions).toContain('cannot reach')
    expect(h.shim.kind).toBe('claude-code')
    h.shim.close()
    svc.helloError = { code: -32000, message: 'busy: full', data: { code: 'busy' } }
    const b = harness(home, { retryMs: () => 10_000 })
    b.shim.fromHost(INIT)
    expect(((await b.byId(0)).result as { instructions: string }).instructions).toContain('full')
    b.shim.close()
    svc.helloError = { code: -32600, message: 'usage: no' }
    const u = harness(home)
    u.shim.fromHost(INIT)
    expect(((await u.byId(0)).result as { instructions: string }).instructions).toContain(
      'refused this session',
    )
    u.shim.close()
  })

  it('passes an initialize refusal to the host and stays down', async () => {
    svc.initError = { code: -32602, message: 'bad version' }
    const h = harness(home)
    h.shim.fromHost(INIT)
    expect((await h.byId(0)).error).toEqual({ code: -32602, message: 'bad version' })
    expect(h.shim.phase).toBe('down')
    h.shim.close()
  })

  it('waits out the gap between the socket and its token', async () => {
    let reads = 0
    const h = harness(home, { token: () => (++reads < 3 ? null : readToken(tokenFileOf(home))) })
    await up(h)
    expect(reads).toBeGreaterThanOrEqual(3)
    h.shim.close()
  })

  it('logs a ring with no identity and a doorbell that fails', async () => {
    const h = harness(home, {
      ring: () => {
        throw Object.assign(new Error('x'), { code: 'ELOOP' })
      },
    })
    await up(h)
    svc.notify('service/ring', { speaking: true })
    svc.notify('service/ring', { as: 'omp', speaking: true })
    await new Promise((r) => setTimeout(r, 50))
    expect(h.logs.map((l) => l.event)).toEqual(expect.arrayContaining(['ring-bad', 'ring-failed']))
    h.shim.close()
  })

  it('drops an unknown answer from the service and a typed notice when not up', async () => {
    const h = harness(home)
    expect(h.shim.typed()).toBe(false)
    await up(h)
    svc.conn.send({ jsonrpc: '2.0', id: 999, result: {} })
    expect(h.shim.typed()).toBe(true)
    await svc.next((m) => m.method === 'service/typed')
    for (let i = 0; i < 50 && !h.logs.some((l) => l.event === 'service-answer-unknown'); i++) {
      await new Promise((r) => setTimeout(r, 10))
    }
    expect(h.logs.some((l) => l.event === 'service-answer-unknown')).toBe(true)
    h.shim.close()
  })

  it('answers a second resume while one waits, and returns a parked error as an error', async () => {
    const codex = { ...INIT, params: { ...INIT.params, clientInfo: { name: 'codex', version: '1' } } }
    const h = harness(home, { parkMs: 60, newToken: () => 'tk' })
    await up(h, codex)
    let reply: (v: unknown) => void = () => {}
    svc.tools.set('wait', (_a, c, id) => {
      reply = (e) => c.send({ jsonrpc: '2.0', id: id as number, error: e as never })
      return undefined
    })
    h.shim.fromHost(call(1, 'wait'))
    await h.byId(1)
    h.shim.fromHost(call(2, 'resume', { token: 'tk' }))
    h.shim.fromHost(call(3, 'resume', { token: 'tk' }))
    expect(((await h.byId(2)).result as { content: { text: string }[] }).content[0]?.text).toContain(
      'still running',
    )
    reply({ code: -32000, message: 'not-bound: x' })
    expect((await h.byId(3)).error?.message).toBe('not-bound: x')
    h.shim.close()
  })
})

describe('the remaining error and edge branches', () => {
  it('takes an initialize with no params, answered by the service or by the shim alone', async () => {
    const bare = { jsonrpc: '2.0' as const, id: 0, method: 'initialize' }
    const h = harness(home)
    h.shim.fromHost(bare)
    expect((await h.byId(0)).result).toMatchObject({ serverInfo: { name: 'bag' } })
    expect(svc.hellos[0]).toMatchObject({ host: 'other', client_capabilities: {} })
    h.shim.close()
    await svc.crash()
    const d = harness(home, { start: () => false })
    d.shim.fromHost(bare)
    expect((await d.byId(0)).result).toMatchObject({ protocolVersion: '2025-11-25' })
    // While down: a notification other than initialized, and a response from the host, are dropped.
    d.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/roots/list_changed' })
    d.shim.fromHost({ jsonrpc: '2.0', id: 'nobody', result: {} })
    d.shim.close()
  })

  it('reads a typed bind refused without a bag code, and a result with no as', async () => {
    const h = harness(home)
    await up(h)
    svc.useRaw = { error: { code: -32603, message: 'internal' } }
    expect(await h.shim.use('omp')).toEqual({ bound: false, code: 'refused' })
    svc.useRaw = { result: { bound: true } }
    expect(await h.shim.use('omp')).toEqual({ bound: false, code: 'bad-answer' })
    h.shim.close()
  })

  it('takes a hello result without a service pid, and a wrong token until the start wait ends', async () => {
    svc.helloResult = { contract: 1 }
    const seen: number[] = []
    const h = harness(home, {
      owner: (pid) => {
        seen.push(pid)
        return false
      },
    })
    await up(h)
    const r = await svc.ask('elicitation/create', { message: 'm', requestedSchema: {} })
    expect(r.error?.data).toEqual({ code: 'not-authorized' })
    expect(seen).toEqual([0])
    h.shim.close()
    svc.helloResult = null
    const w = harness(home, { token: () => 'b'.repeat(64), start: () => true, startWaitMs: 200 })
    w.shim.fromHost(INIT)
    expect(((await w.byId(0)).result as { instructions: string }).instructions).toBe(absentText(home))
    w.shim.close()
  })

  it('passes service requests other than dialogs, and notices without params', async () => {
    const h = harness(home, { ring: () => {} })
    await up(h)
    const asked = svc.ask('roots/list', {})
    const shown = await h.next((m) => m.method === 'roots/list')
    h.shim.fromHost({ jsonrpc: '2.0', id: shown.id as string, result: { roots: [] } })
    expect((await asked).result).toEqual({ roots: [] })
    svc.conn.send({ jsonrpc: '2.0', id: 'svc-x', method: 'sampling/createMessage' } as never)
    const sampled = await h.next((m) => m.method === 'sampling/createMessage')
    expect(sampled.params).toEqual({})
    // A cancellation for no open dialog, one without a reason, and a message that is neither kind.
    svc.notify('notifications/cancelled', { requestId: 'nope' })
    svc.notify('notifications/cancelled', { requestId: 'svc-x' })
    const c = await h.next((m) => m.method === 'notifications/cancelled')
    expect(c.params).toEqual({ requestId: sampled.id })
    svc.conn.send({ jsonrpc: '2.0', id: 'odd' } as never)
    svc.conn.send({ jsonrpc: '2.0', method: 'service/ring' } as never)
    svc.notify('service/bound', { as: 'omp' })
    svc.conn.send({ jsonrpc: '2.0', method: 'service/draining' } as never)
    await new Promise((r) => setTimeout(r, 50))
    expect(h.logs.map((l) => l.event)).toEqual(expect.arrayContaining(['ring-bad', 'bound', 'draining']))
    expect(h.logs.find((l) => l.event === 'draining')?.fields).toEqual({ retry_after_ms: 2000 })
    h.shim.close()
  })

  it('forwards a host notification of its own and a cancellation for a call it does not hold', async () => {
    const h = harness(home)
    await up(h)
    h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/roots/list_changed' })
    h.shim.fromHost({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 404 } })
    await svc.next((m) => m.method === 'notifications/cancelled')
    expect(svc.conn.got.some((m) => m.method === 'notifications/roots/list_changed')).toBe(true)
    h.shim.close()
  })

  it('answers a resume with no token', async () => {
    const codex = { ...INIT, params: { ...INIT.params, clientInfo: { name: 'codex', version: '1' } } }
    const h = harness(home)
    await up(h, codex)
    h.shim.fromHost({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'resume' } })
    expect(((await h.byId(1)).result as { isError: boolean }).isError).toBe(true)
    h.shim.close()
  })
})
