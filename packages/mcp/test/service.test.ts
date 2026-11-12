import { AsyncLocalStorage } from 'node:async_hooks'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { parseEnvelope, serializeRecord, signHop } from '@usebag/core'
import { type EdgeKeys, generateEdgeKeys, HomeCustody, openIdentityKeys, setKeepAlive } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { NOT_BOUND } from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { Names } from '../src/names.ts'
import {
  launchAgentPlist,
  launchCommand,
  lockName,
  proxyOmitted,
  Service,
  type ServiceDeps,
  scrubbedEnv,
  scrubFailure,
  serveService,
} from '../src/service.ts'
import { DIALOG_META, runPaths, type ServiceConnection } from '../src/socket.ts'
import {
  acceptFrom,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The bag service over its socket (docs/bag-service.md): the hello and its refusals, MCP carried unchanged, dialogs
// owned by one connection, the CLI's lend and return, the drain, the lazy Keychain open and the scrubbed launch. A home
// is a short directory under /tmp, so its socket fits sun_path; it is removed after each test.

type Json = Record<string, unknown>

let home: string
let relay: MemoryRelay
let timers: ManualTimers
let log: MemoryLog
let files = 0
const live: Service[] = []
const sockets: Socket[] = []
const servers: Server[] = []

beforeEach(() => {
  home = mkdtempSync('/tmp/bsv-')
  relay = new MemoryRelay()
  timers = new ManualTimers()
  log = new MemoryLog()
})
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const s of servers.splice(0)) s.close()
  for (const s of live.splice(0)) await s.drain()
  rmSync(home, { recursive: true, force: true })
})

/** An identities file of the home: each label with its party's key, in this one home. */
function fileOf(ids: readonly [string, Party][], more: Json = {}): string {
  const file = join(home, `identities-${files++}.json`)
  const identities = ids.map(([label, p]) => {
    const held = ['keys', 'keychain', 'agent'].some((d) => existsSync(join(home, d, `${p.name}.json`)))
    if (!held) saveKeys(home, p)
    return { label, key: p.name, home, relays: [RELAY], trust_roots: [P.bob.address], ...more }
  })
  writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
  return file
}

const configOf = (file: string): ServerConfig =>
  parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig

function deps(more: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    clock: new FakeClock(),
    rng: seededRng('service'),
    relayFor: () => relay,
    records: fakeRecords(new Map()),
    timers,
    pid: 4242,
    alive: () => false,
    log,
    resubscribeDelayMs: () => 0,
    helloMs: 300,
    drainCallsMs: 200,
    returnWaitMs: 300,
    ...more,
  }
}

async function start(
  ids: readonly [string, Party][] = [['personal', P.alice]],
  more: Partial<ServiceDeps> = {},
): Promise<Service> {
  const file = fileOf(ids)
  const s = await Service.start(configOf(file), home, deps(more))
  live.push(s)
  await s.opening
  return s
}

/** Whether a child process can take the lock at `path` (and lets it go at once): got or busy. */
function otherProcessTakes(path: string): Promise<string> {
  const code = `
    const { DatabaseSync } = require('node:sqlite')
    const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 0 })
    try { db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT'); process.stdout.write('got') }
    catch { process.stdout.write('busy') }`
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--no-warnings', '-e', code], {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    let out = ''
    child.stdout.on('data', (b: Buffer) => {
      out += b.toString()
    })
    child.once('exit', () => resolve(out))
  })
}

/** A raw line client of the socket. */
interface Line {
  readonly socket: Socket
  send(m: Json | string): void
  next(pick?: (m: Json) => boolean): Promise<Json>
  closed: Promise<void>
  request(method: string, params?: Json): Promise<Json>
}

async function connect(s: Service): Promise<Line> {
  const socket = createConnection(s.paths.sock)
  sockets.push(socket)
  await new Promise<void>((r) => socket.once('connect', () => r()))
  const seen: Json[] = []
  const waiters: { pick: (m: Json) => boolean; resolve: (m: Json) => void }[] = []
  let buf = ''
  socket.on('data', (b: Buffer) => {
    buf += b.toString()
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const m = JSON.parse(buf.slice(0, i)) as Json
      buf = buf.slice(i + 1)
      const w = waiters.findIndex((x) => x.pick(m))
      if (w >= 0) waiters.splice(w, 1)[0]?.resolve(m)
      else seen.push(m)
    }
  })
  const closed = new Promise<void>((r) => socket.once('close', () => r()))
  let id = 100
  const line: Line = {
    socket,
    closed,
    send: (m) => socket.write(`${typeof m === 'string' ? m : JSON.stringify(m)}\n`),
    next: (pick = () => true) => {
      const i = seen.findIndex(pick)
      if (i >= 0) return Promise.resolve(seen.splice(i, 1)[0] as Json)
      return new Promise((resolve) => waiters.push({ pick, resolve }))
    },
    async request(method, params = {}) {
      const n = ++id
      line.send({ jsonrpc: '2.0', id: n, method, params })
      return line.next((m) => m.id === n)
    },
  }
  return line
}

const helloOf = (s: Service, more: Json = {}): Json => ({
  contract: 1,
  token: s.token.toString('hex'),
  host: 'claude-code',
  cwd: '/tmp/work',
  client_capabilities: { elicitation: { form: {} } },
  input_hook: false,
  ...more,
})

async function hello(s: Service, more: Json = {}): Promise<Line> {
  const l = await connect(s)
  const r = await l.request('service/hello', helloOf(s, more))
  expect(r.result, JSON.stringify(r)).toBeDefined()
  return l
}

/** A hello with an input hook, bound to `label` by the person's typed word (service/use via typed). */
async function bound(s: Service, label = 'personal', more: Json = {}): Promise<Line> {
  const l = await hello(s, { input_hook: true, ...more })
  const r = await l.request('service/use', { label, via: 'typed' })
  expect(r.result, JSON.stringify(r)).toMatchObject({ bound: true, as: label })
  return l
}

/** The default reader's answer for a fake key read: the class and address with the keys. */
const opened = (keys: EdgeKeys, custody: 'home-key' | 'keychain' = 'keychain') => ({
  custody,
  address: keys.signing.address,
  keys,
})

const codeOf = (r: Json): unknown => ((r.error as Json | undefined)?.data as Json | undefined)?.code

/** The service-side connection object of the newest connection. */
const lastConn = (s: Service): ServiceConnection => [...s.connections].at(-1) as ServiceConnection

describe('the start', () => {
  it('binds the socket 0600 in a 0700 run directory, writes the token and service.json, and a second service is busy', async () => {
    const s = await start()
    const { dir, sock, token, json } = runPaths(home)
    expect(
      execFileSync('stat', ['-f', '%Lp', dir, sock, token, json]).toString().split('\n').slice(0, 4),
    ).toEqual(['700', '600', '600', '600'])
    expect(readFileSync(token, 'utf8')).toBe(s.token.toString('hex'))
    expect(JSON.parse(readFileSync(json, 'utf8'))).toMatchObject({ pid: 4242, contract: 1, draining: false })
    expect(JSON.stringify(JSON.parse(readFileSync(json, 'utf8')))).not.toContain(s.token.toString('hex'))
    // The lock is still held, for another process, after everything the start touched: nothing in this process opened
    // service.lock a second time (a POSIX lock drops when any descriptor of the process to that file closes).
    expect(await otherProcessTakes(runPaths(home).lock)).toBe('busy')
    await expect(
      Service.start(configOf(fileOf([['personal', P.alice]])), home, deps({ lockRetryMs: 0 })),
    ).rejects.toThrow('busy: the bag service for this home already runs (pid 4242)')
    expect(existsSync(sock)).toBe(true)
  })

  it('holds each identity of the home, one service per home: the home of another identity is refused', () => {
    const other = mkdtempSync('/tmp/bsv-other-')
    try {
      const file = join(home, 'mixed.json')
      saveKeys(home, P.alice)
      writeFileSync(
        file,
        JSON.stringify({
          version: 1,
          identities: [
            { label: 'a', key: 'alice', home, relays: [RELAY] },
            { label: 'b', key: 'carol', home: other, relays: [RELAY] },
          ],
        }),
        { mode: 0o600 },
      )
      expect(() => configOf(file)).toThrow("is not the service's home")
      writeFileSync(
        file,
        JSON.stringify({
          version: 1,
          identities: [
            { label: 'a', key: 'alice', home, relays: [RELAY] },
            { label: 'b', key: 'alice', home, relays: [RELAY] },
          ],
        }),
        { mode: 0o600 },
      )
      expect(() => configOf(file)).toThrow('repeats the key "alice"')
      expect(() => parseServerConfig(['--service', '--identities', file], {})).toThrow(
        '--service takes --dir',
      )
      expect(() =>
        parseServerConfig(['--service', '--dir', home, '--identities', file, '--push', 'log'], {}),
      ).toThrow('--push does not go with --service')
    } finally {
      rmSync(other, { recursive: true, force: true })
    }
  })
})

describe('the hello', () => {
  it('is first: anything before it is usage and the connection closes', async () => {
    const s = await start()
    const l = await connect(s)
    l.send({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    const r = await l.next()
    expect(r).toMatchObject({
      id: 1,
      error: { code: -32600, data: { code: 'usage', detail: 'service/hello first' } },
    })
    await l.closed
  })

  it('refuses a wrong token bad-auth, an unknown contract bad-version with the supported list, an unknown member usage', async () => {
    const s = await start()
    const cases: [Json, string][] = [
      [{ token: 'ab'.repeat(32) }, 'bad-auth'],
      [{ token: undefined }, 'bad-auth'],
      [{ contract: 2 }, 'bad-version'],
      [{ extra: 1 }, 'usage'],
      [{ cwd: 'relative' }, 'usage'],
      [{ input_hook: 'yes' }, 'usage'],
    ]
    for (const [more, code] of cases) {
      const l = await connect(s)
      const r = await l.request('service/hello', helloOf(s, more))
      expect(codeOf(r), JSON.stringify(more)).toBe(code)
      if (code === 'bad-version') expect((r.error as Json).data).toMatchObject({ supported: [1] })
      await l.closed
    }
    expect(log.text()).not.toContain(s.token.toString('hex'))
    expect(log.lines.filter((x) => x.event === 'hello-refused').map((x) => x.fields.code)).toEqual(
      cases.map(([, c]) => c),
    )
  })

  it('checks the token before anything else: without it, an unknown member or a bad shape is bad-auth too', async () => {
    const s = await start()
    for (const params of [
      { ...helloOf(s, { token: 'ab'.repeat(32) }), extra: 1 },
      'not an object',
      { extra: 1 },
    ]) {
      const l = await connect(s)
      l.send({ jsonrpc: '2.0', id: 1, method: 'service/hello', params })
      expect(codeOf(await l.next())).toBe('bad-auth')
      await l.closed
    }
  })

  it('answers the contract, an opaque connection handle and whether it shows dialogs; a second hello is usage', async () => {
    const s = await start()
    const l = await connect(s)
    const r = await l.request('service/hello', helloOf(s))
    expect(r.result).toMatchObject({ contract: 1, dialog_capable: true, draining: false })
    expect((r.result as Json).connection).toMatch(/^[0-9a-f]{32}$/)
    expect(codeOf(await l.request('service/hello', helloOf(s)))).toBe('usage')
    expect(lastConn(s).capabilities).toMatchObject({ elicitation: true, inputHook: false })
  })

  it('closes a connection that sends no hello in time', async () => {
    const s = await start()
    const l = await connect(s)
    await l.closed
  })

  it('answers a line that is not JSON bad-json and stays; a batch bad-shape; a line over 4 MiB body-too-large and closes', async () => {
    const s = await start()
    const l = await hello(s)
    l.send('{not json')
    expect(codeOf(await l.next())).toBe('bad-json')
    l.send('[{"jsonrpc":"2.0"}]')
    expect(codeOf(await l.next())).toBe('bad-shape')
    expect(codeOf(await l.request('service/nothing'))).toBe('unknown-method')
    l.send('x'.repeat(4 * 1024 * 1024 + 1))
    const r = await l.next()
    expect(r).toMatchObject({ id: null, error: { code: -32600, data: { code: 'body-too-large' } } })
    await l.closed
  })
})

describe('MCP over the connection', () => {
  it('carries initialize and tools unchanged, and each call knows its connection', async () => {
    const s = await start()
    const l = await bound(s)
    const init = await l.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { elicitation: { form: {} } },
      clientInfo: { name: 'claude-code', version: '1' },
    })
    expect((init.result as Json).serverInfo).toMatchObject({ name: 'bag' })
    l.send({ jsonrpc: '2.0', method: 'notifications/initialized' })
    const tools = (await l.request('tools/list')).result as { tools: { name: string }[] }
    expect(tools.tools.map((t) => t.name)).toContain('status')
    const status = (await l.request('tools/call', { name: 'status', arguments: { as: 'personal' } }))
      .result as Json
    expect(status.isError).not.toBe(true)
    expect(JSON.stringify(status)).toContain(P.alice.address)
  })
})

describe('dialogs', () => {
  it('go to one connection and are answered only there, echoing their handle; a foreign answer is not-authorized', async () => {
    const s = await start()
    const a = await hello(s)
    const connA = lastConn(s)
    const b = await hello(s)
    const asked = connA.elicit({
      mode: 'form',
      message: 'bind?',
      requestedSchema: { type: 'object', properties: {} },
    })
    const req = await a.next((m) => m.method === 'elicitation/create')
    const handle = ((req.params as Json)._meta as Json)[DIALOG_META] as string
    expect(handle).toMatch(/^[0-9a-f]{32}$/)
    expect(req.id).toMatch(/^bag-dialog-/)
    // Another connection presents the handle: refused, and the dialog still waits for its own connection.
    b.send({
      jsonrpc: '2.0',
      id: req.id,
      result: { action: 'accept', content: {}, _meta: { [DIALOG_META]: handle } },
    })
    expect(codeOf(await b.next())).toBe('not-authorized')
    expect(log.lines.some((x) => x.event === 'dialog-foreign')).toBe(true)
    // Its own connection without the echo: usage, still waiting.
    a.send({ jsonrpc: '2.0', id: req.id, result: { action: 'accept', content: {} } })
    expect(codeOf(await a.next())).toBe('usage')
    a.send({
      jsonrpc: '2.0',
      id: req.id,
      result: { action: 'accept', content: {}, _meta: { [DIALOG_META]: handle } },
    })
    expect(await asked).toMatchObject({ action: 'accept' })
  })

  it('are cancelled by the caller (notifications/cancelled) and by the connection closing, one at a time per connection', async () => {
    const s = await start()
    const a = await hello(s)
    const conn = lastConn(s)
    const ctl = new AbortController()
    const form = {
      mode: 'form' as const,
      message: 'm',
      requestedSchema: { type: 'object' as const, properties: {} },
    }
    const first = conn.elicit(form, { signal: ctl.signal })
    const second = conn.elicit(form)
    const req = await a.next((m) => m.method === 'elicitation/create')
    ctl.abort()
    await expect(first).rejects.toThrow('cancelled')
    expect(await a.next((m) => m.method === 'notifications/cancelled')).toMatchObject({
      params: { requestId: req.id },
    })
    // The second was queued and goes out only now.
    const req2 = await a.next((m) => m.method === 'elicitation/create')
    expect(req2.id).not.toBe(req.id)
    a.socket.destroy()
    await expect(second).rejects.toThrow('cancelled')
    await hello(s)
    const timed = lastConn(s).elicit(form, { timeoutMs: 50 })
    await expect(timed).rejects.toThrow('cancelled: no answer in time')
  })
})

describe('the omp consent bridge', () => {
  it('is a directory the service makes per connection, 0700 under run/shim, whatever path the client names', async () => {
    const s = await start()
    const planted = join(home, 'planted')
    const l = await connect(s)
    const r = await l.request(
      'service/hello',
      helloOf(s, {
        host: 'omp',
        client_capabilities: { experimental: { 'bag.dev/consent-bridge': { dir: planted } } },
      }),
    )
    const result = r.result as Json
    const dir = join(home, 'run', 'shim', `${result.connection as string}.consent`)
    expect(result.bridge_dir).toBe(dir)
    expect(lastConn(s).bridgeDir).toBe(dir)
    expect(existsSync(planted)).toBe(false)
    expect(
      execFileSync('stat', ['-f', '%Lp', join(home, 'run', 'shim'), dir])
        .toString()
        .split('\n')
        .slice(0, 2),
    ).toEqual(['700', '700'])
    // A hello without the capability gets no bridge.
    const plain = await connect(s)
    expect(((await plain.request('service/hello', helloOf(s))).result as Json).bridge_dir).toBeUndefined()
  })
})

describe('the identities the service holds', () => {
  it('ServiceHome.identities never lists a principal, whatever the layout on disk', async () => {
    // An enterprise agent (session.json names it) in the home, one in a profile under orgs/, a pending sign-in's,
    // and the sub-keys <x>.signin and <x>.session, beside one plain identity.
    const ent = (dir: string, file: string, name: string): void => {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      writeFileSync(join(dir, file), JSON.stringify({ name }), { mode: 0o600 })
    }
    ent(join(home, 'enterprise'), 'session.json', 'carol')
    ent(join(home, 'orgs', 'example.com', 'enterprise'), 'session.json', 'jane')
    ent(join(home, 'enterprise'), 'pending.json', 'org')
    const file = fileOf([
      ['personal', P.alice],
      ['agent', P.carol],
      ['profile', P.jane],
      ['waiting', P.org],
    ])
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { identities: Json[] }
    saveKeys(home, P.bob, P.bob.keys, 'carol.signin')
    saveKeys(home, P.session, P.session.keys, 'alice.session')
    doc.identities.push({ label: 'signin', key: 'carol.signin', home, relays: [RELAY] })
    doc.identities.push({ label: 'session', key: 'alice.session', home, relays: [RELAY] })
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    const s = await Service.start(configOf(file), home, deps())
    live.push(s)
    await s.opening
    expect(s.identities().map((i) => i.label)).toEqual(['personal'])
    for (const label of ['agent', 'profile', 'waiting', 'signin', 'session']) expect(s.unit(label)).toBeNull()
    expect(log.lines.filter((x) => x.event === 'principal-skipped')).toHaveLength(5)
  })
})

describe('a tool call runs inside its connection', () => {
  it("names its connection after the handler awaits, through the mail lane's withConnection", async () => {
    const als = new AsyncLocalStorage<string>()
    const seen: (string | undefined)[] = []
    // The relay records the scope it is called in, after a wait of its own, deep in the lookup tool's awaits.
    const spy = new Proxy(relay, {
      get(target, key, receiver) {
        const v = Reflect.get(target, key, receiver) as unknown
        if (key === 'fetchRecord')
          return async (...a: unknown[]) => {
            await new Promise((r) => setTimeout(r, 5))
            seen.push(als.getStore())
            return (v as (...x: unknown[]) => unknown).apply(target, a)
          }
        return typeof v === 'function' ? v.bind(target) : v
      },
    })
    const s = await start([['personal', P.alice]], {
      relayFor: () => spy,
      mail: { withConnection: (h, run) => als.run(h, run) },
    })
    const l = await bound(s)
    const handle = lastConn(s).handle
    await l.request('tools/call', { name: 'lookup', arguments: { as: 'personal', address: P.bob.address } })
    expect(seen.length).toBeGreaterThan(0)
    expect(new Set(seen)).toEqual(new Set([handle]))
  })
})

describe('agent grants', () => {
  it('give every connection the same configured caveats, and refuse an agent identity with none', async () => {
    const file = fileOf([['personal', P.alice]], {
      grant_caveats: ['type=coding.*', 'type=coding.*', 'repo=bag'],
    })
    const s = await Service.start(configOf(file), home, deps())
    live.push(s)
    expect(s.grantCaveats('personal')).toEqual(['type=coding.*', 'repo=bag'])
    expect(s.grantCaveats('personal')).toEqual(s.grantCaveats('personal'))
    await s.drain()
    live.splice(live.indexOf(s), 1)
    const bare = await start([['personal', P.alice]], { lockRetryMs: 0 })
    expect(() => bare.grantCaveats('personal')).toThrow(
      'not-authorized: no grant caveats configured for personal: nothing is signed',
    )
    expect(() => bare.grantCaveats('nobody')).toThrow('unknown-identity')
    expect(() => configOf(fileOf([['research', P.carol]], { grant_caveats: [' '] }))).toThrow('empty caveat')
  })
})

describe('a connection that closes', () => {
  it("ends its own pairings through endFor with that connection, never the drain's cancel of every pairing", async () => {
    const s = await start()
    const ended: ServiceConnection[] = []
    s.setEndFor((c) => ended.push(c))
    const a = await hello(s)
    const connA = lastConn(s)
    await hello(s)
    a.socket.destroy()
    await until(() => ended.length === 1)
    expect(ended).toEqual([connA])
    expect(log.lines.some((x) => x.event === 'drain-pairings')).toBe(false)
    await s.drain()
    live.splice(live.indexOf(s), 1)
    expect(log.lines.filter((x) => x.event === 'drain-pairings')).toHaveLength(1)
  })
})

describe('the mail close hook', () => {
  it('is called off the close path: a busy markUsed is logged, and the close completes', async () => {
    const s = await start([['personal', P.alice]], {
      mail: { closed: async () => Promise.reject(Object.assign(new Error('held'), { code: 'busy' })) },
    })
    const l = await hello(s)
    l.socket.destroy()
    await until(() => s.connections.size === 0)
    await until(() => log.lines.some((x) => x.event === 'mail-closed' && x.fields.code === 'busy'))
    const s2 = await hello(s)
    expect(s.connections.size).toBe(1)
    void s2
  })
})

describe('service/typed', () => {
  it('reaches the wake router as the connection that typed, only after a token-checked hello', async () => {
    const typed: string[] = []
    const s = await start([['personal', P.alice]], { mail: { typed: (h) => typed.push(h) } })
    const pre = await connect(s)
    pre.send({ jsonrpc: '2.0', method: 'service/typed', params: {} })
    await pre.next()
    const l = await hello(s)
    l.send({ jsonrpc: '2.0', method: 'service/typed', params: {} })
    await until(() => typed.length === 1)
    expect(typed).toEqual([lastConn(s).handle])
  })
})

describe('the CLI lend and return', () => {
  const lockFile = (p: Party): string => join(home, 'state', p.name, 'mcp.lock')

  it('lends only to a cli hello, refuses unknown, held and repeated lends, and suspends the unit with its lock released', async () => {
    const s = await start([
      ['personal', P.alice],
      ['research', P.carol],
    ])
    expect(existsSync(lockFile(P.alice))).toBe(true)
    const win = await hello(s)
    expect(codeOf(await win.request('service/lend', { label: 'personal', verb: 'pair' }))).toBe(
      'not-authorized',
    )
    const cli = await hello(s, { host: 'cli' })
    expect(codeOf(await cli.request('service/lend', { label: 'nobody', verb: 'pair' }))).toBe(
      'unknown-identity',
    )
    expect(codeOf(await cli.request('service/lend', { label: 'personal' }))).toBe('usage')
    s.setHolders((label) => (label === 'research' ? [{ host: 'codex', cwd: '/w/r' }] : []))
    const held = await cli.request('service/lend', { label: 'research', verb: 'pair' })
    expect(codeOf(held)).toBe('busy')
    expect(((held.error as Json).data as Json).detail).toContain('in use in codex at /w/r')
    expect((await cli.request('service/lend', { label: 'personal', verb: 'pair' })).result).toEqual({
      lent: true,
      label: 'personal',
    })
    expect(existsSync(lockFile(P.alice))).toBe(false)
    expect(s.lent('personal')).toBe('pair')
    expect(codeOf(await cli.request('service/lend', { label: 'personal', verb: 'keys' }))).toBe('busy')
    // A bind of that identity answers busy naming the lend while it is lent (W1's table hears the lend).
    const r = await win.request('service/use', { label: 'personal', via: 'dialog' })
    expect(codeOf(r)).toBe('busy')
    expect(JSON.stringify(r)).toContain('lent to the bag command line (pair)')
  })

  it('returns by re-deriving from disk: no removed flag, a return without a lend is usage, the unit reopens with its lock', async () => {
    const s = await start()
    const cli = await hello(s, { host: 'cli' })
    expect(codeOf(await cli.request('service/return', { label: 'personal' }))).toBe('usage')
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(codeOf(await cli.request('service/return', { label: 'personal', removed: true }))).toBe('usage')
    expect((await cli.request('service/return', { label: 'personal' })).result).toEqual({
      returned: true,
      label: 'personal',
      open: true,
      removed: false,
    })
    expect(existsSync(lockFile(P.alice))).toBe(true)
    expect(s.unit('personal')?.opened).not.toBeNull()
  })

  it('drops an identity the CLI removed from disk, whatever it claims, and waits for the CLI to free the lock', async () => {
    const file = fileOf([['personal', P.alice]])
    let identities: ServerConfig['identities'] = configOf(file).identities
    const s = await Service.start(configOf(file), home, deps({ reread: () => identities }))
    live.push(s)
    await s.opening
    const cli = await hello(s, { host: 'cli' })
    identities = []
    await cli.request('service/lend', { label: 'personal', verb: 'identity remove' })
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({
      removed: true,
    })
    expect(s.unit('personal')).toBeNull()
    identities = configOf(fileOf([['research', P.carol]])).identities
    expect(identities).toHaveLength(1)
  })

  it('answers busy while the CLI still holds the lock at a return, and opens once it is freed', async () => {
    let cliAlive = true
    const s = await start([['personal', P.alice]], { alive: (pid) => pid === 999 && cliAlive })
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    mkdirSync(join(home, 'state', 'alice'), { recursive: true })
    writeFileSync(lockFile(P.alice), JSON.stringify({ pid: 999, started_at: new Date().toISOString() }))
    expect(codeOf(await cli.request('service/return', { label: 'personal' }))).toBe('busy')
    expect(s.lent('personal')).toBe('pair')
    cliAlive = false
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({ open: true })
  })

  it('returns by itself when the lending connection closes, and retries on the lock until the CLI frees it (L7)', async () => {
    let cliAlive = true
    const s = await start([['personal', P.alice]], {
      alive: (pid) => pid === 999 && cliAlive,
      lockPollMs: 77,
    })
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    mkdirSync(join(home, 'state', 'alice'), { recursive: true })
    writeFileSync(lockFile(P.alice), JSON.stringify({ pid: 999, started_at: new Date().toISOString() }))
    cli.socket.destroy()
    await cli.closed
    await until(() => s.lent('personal') === null)
    expect(s.unit('personal')?.opened).toBeNull()
    expect(timers.live()).toContain(77)
    cliAlive = false
    timers.fire((ms) => ms === 77)
    await until(() => s.unit('personal')?.opened !== null)
    const win = await bound(s)
    const r = (await win.request('tools/call', { name: 'status', arguments: { as: 'personal' } }))
      .result as Json
    expect(r.isError).not.toBe(true)
  })
})

async function until(test: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('the drain', () => {
  /** A wait in flight, which holds the drain at its wait for calls (its timer is manual, so it never returns alone). */
  const holdOpen = (l: Line): void =>
    l.send({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'wait', arguments: { as: 'personal', timeout_s: 1 } },
    })

  it('tells every connection, refuses hellos, lends and binds draining, and releases everything, the service lock last', async () => {
    const s = await start([['personal', P.alice]], { drainCallsMs: 1500 })
    const a = await bound(s)
    const cli = await hello(s, { host: 'cli' })
    holdOpen(a)
    await until(() => s.calls() === 1)
    const drained = s.drain('upgrade')
    expect(await a.next((m) => m.method === 'service/draining')).toMatchObject({
      params: { retry_after_ms: 2000, reason: 'upgrade' },
    })
    expect(JSON.parse(readFileSync(runPaths(home).json, 'utf8'))).toMatchObject({ draining: true })
    expect(codeOf(await cli.request('service/lend', { label: 'personal', verb: 'pair' }))).toBe('draining')
    const b = await connect(s)
    expect(codeOf(await b.request('service/hello', helloOf(s)))).toBe('draining')
    // The wait in flight is settled when its identity stops, before the connection closes.
    expect((await a.next((m) => m.id === 9)).result).toBeDefined()
    await drained
    live.splice(live.indexOf(s), 1)
    const { sock, token, json } = runPaths(home)
    expect([existsSync(sock), existsSync(token), existsSync(json)]).toEqual([false, false, false])
    expect(existsSync(join(home, 'state', 'alice', 'mcp.lock'))).toBe(false)
    // A new service takes the lock at once and opens the identity from the home, keys read fresh.
    let reads = 0
    const next = await start([['personal', P.alice]], {
      lockRetryMs: 0,
      openKeys: (h, n) => {
        reads++
        return openIdentityKeys(h, n)
      },
    })
    expect(reads).toBe(1)
    expect(next.token.equals(s.token)).toBe(false)
  })

  it('stops the subscriptions before the stores close: from then every acting tool answers draining', async () => {
    const s = await start([['personal', P.alice]], { drainCallsMs: 1500 })
    const a = await bound(s)
    expect(relay.subs.size).toBeGreaterThan(0)
    holdOpen(a)
    await until(() => s.calls() === 1)
    const unit = s.unit('personal') as NonNullable<ReturnType<Service['unit']>>
    const drained = s.drain()
    await a.next((m) => m.id === 9)
    expect(unit.opened).toBeNull()
    expect(relay.subs.size).toBe(0)
    await drained
    live.splice(live.indexOf(s), 1)
  })
})

describe('Keychain identities open lazily', () => {
  /** Moves a party's custody to the keychain: its pointer file, and its key file gone (one custody per name). */
  function keychain(...ps: Party[]): void {
    for (const p of ps) {
      mkdirSync(join(home, 'keychain'), { recursive: true, mode: 0o700 })
      rmSync(join(home, 'keys', `${p.name}.json`), { force: true })
      writeFileSync(join(home, 'keychain', `${p.name}.json`), JSON.stringify({ address: p.address }), {
        mode: 0o600,
      })
    }
  }
  const byName = new Map<string, EdgeKeys>([
    ['alice', P.alice.keys],
    ['carol', P.carol.keys],
  ])

  it('an unattended start raises no dialog; a bind raises exactly one; a timed-out read waits for the next bind', async () => {
    keychain(P.alice, P.carol)
    const reads: string[] = []
    let fail: string | null = null
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      {
        openKeys: async (_h, name) => {
          reads.push(name)
          if (fail !== null) throw Object.assign(new Error(fail), { code: fail })
          return opened(byName.get(name) as EdgeKeys)
        },
      },
    )
    expect(reads).toEqual([])
    expect(String(s.unit('research')?.failure)).toContain('opens when a window binds to it')
    // The person's typed bind opens it: one read, and a second bind or ensureOpen reads nothing more.
    const win = await bound(s)
    await until(() => s.unit('personal')?.opened !== null)
    expect(reads).toEqual(['alice'])
    expect(await s.ensureOpen('personal')).toBe(true)
    expect(reads).toEqual(['alice'])
    fail = 'ETIMEDOUT'
    expect(await s.ensureOpen('research')).toBe(false)
    expect(reads).toEqual(['alice', 'carol'])
    timers.fire()
    await new Promise((r) => setTimeout(r, 20))
    expect(reads).toEqual(['alice', 'carol'])
    fail = null
    expect(await s.ensureOpen('research')).toBe(true)
    expect(reads).toEqual(['alice', 'carol', 'carol'])
    void win
  })

  it("opens at start only on the person's keep-alive word, never for keep_alive_records alone", async () => {
    keychain(P.carol)
    const reads: string[] = []
    const openKeys = async (_h: string, name: string) => {
      reads.push(name)
      return opened(byName.get(name) as EdgeKeys)
    }
    const file = fileOf([['research', P.carol]], { keep_alive_records: true })
    const s = await Service.start(configOf(file), home, deps({ openKeys }))
    live.push(s)
    await s.opening
    expect(reads).toEqual([])
    await bound(s, 'research')
    await until(() => reads.length === 1)
    await s.drain()
    live.splice(live.indexOf(s), 1)
    // The person's word, keep true in the keep-alive table: it opens at start, no bind needed.
    setKeepAlive(home, 'research', true)
    const again = await Service.start(configOf(file), home, deps({ openKeys, lockRetryMs: 0 }))
    live.push(again)
    await again.opening
    expect(reads).toEqual(['carol', 'carol'])
    expect(again.unit('research')?.opened).not.toBeNull()
  })

  it("a pending first-bind open stalls no other connection's call: its tools answer busy meanwhile", async () => {
    keychain(P.alice, P.carol)
    let answer: () => void = () => {}
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      {
        openKeys: async (_h, name) =>
          name === 'carol'
            ? new Promise((resolve) => {
                answer = () => resolve(opened(P.carol.keys))
              })
            : opened(P.alice.keys),
      },
    )
    // A binds research: its Keychain dialog is up and stays up.
    const a = await bound(s, 'research')
    const waiting = (await a.request('tools/call', { name: 'status', arguments: {} })).result as Json
    expect(JSON.stringify(waiting)).toContain('a Keychain dialog may be waiting on this Mac')
    // B binds personal meanwhile: it opens and answers at once.
    const b = await bound(s, 'personal')
    await until(() => s.unit('personal')?.opened !== null, 1000)
    const t0 = Date.now()
    const mine = (await b.request('tools/call', { name: 'status', arguments: {} })).result as Json
    expect(mine.isError, JSON.stringify(mine)).not.toBe(true)
    expect(Date.now() - t0).toBeLessThan(1000)
    expect(s.unit('research')?.opened).toBeNull()
    answer()
    await until(() => s.unit('research')?.opened !== null)
    const now = (await a.request('tools/call', { name: 'status', arguments: {} })).result as Json
    expect(now.isError, JSON.stringify(now)).not.toBe(true)
  })
})

describe('the scrubbed launch', () => {
  it('fails closed on NODE_OPTIONS, a code-loading or inspect flag, or no --disable-sigusr1', () => {
    expect(scrubFailure({}, ['--disable-sigusr1'])).toBeNull()
    expect(scrubFailure({ NODE_OPTIONS: '' }, ['--disable-sigusr1'])).toBe('NODE_OPTIONS is set')
    expect(scrubFailure({}, ['--disable-sigusr1', '--inspect=9229'])).toBe('node was started with --inspect')
    expect(scrubFailure({}, ['--disable-sigusr1', '--import', 'x'])).toBe('node was started with --import')
    expect(scrubFailure({}, ['--disable-sigusr1', '-r', 'x'])).toBe('node was started with -r')
    expect(scrubFailure({}, [])).toBe('node was started without --disable-sigusr1')
    // The loader's families and every NODE_* but NODE_USE_ENV_PROXY.
    const ok = ['--disable-sigusr1']
    expect(scrubFailure({ DYLD_INSERT_LIBRARIES: '/x.dylib' }, ok)).toBe('DYLD_INSERT_LIBRARIES is set')
    expect(scrubFailure({ LD_PRELOAD: '/x.so' }, ok)).toBe('LD_PRELOAD is set')
    expect(scrubFailure({ NODE_EXTRA_CA_CERTS: '/ca.pem' }, ok)).toBe('NODE_EXTRA_CA_CERTS is set')
    expect(scrubFailure({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, ok)).toBe(
      'NODE_TLS_REJECT_UNAUTHORIZED is set',
    )
    expect(scrubFailure({ NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: 'http://p:1' }, ok)).toBeNull()
    expect(scrubbedEnv({ HOME: '/h', NODE_OPTIONS: '--require x', NODE_PATH: '/p', PATH: '/evil' })).toEqual({
      HOME: '/h',
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    })
  })

  it('runs in the run directory with no core dumps, no NODE_OPTIONS and SIGUSR1 opening no inspector', async () => {
    mkdirSync(runPaths(home).dir, { mode: 0o700 })
    const main = join(home, 'probe.mjs')
    writeFileSync(
      main,
      `import { execSync } from 'node:child_process'
      process.stdout.write(JSON.stringify({ cwd: process.cwd(), env: process.env, execArgv: process.execArgv,
        core: execSync('ulimit -c').toString().trim() }) + '\\n')
      setTimeout(() => {}, 800)`,
    )
    const cmd = launchCommand({
      node: process.execPath,
      main,
      home,
      identities: join(home, 'ids.json'),
      env: { HOME: home, NODE_OPTIONS: '--require /nonexistent', AC_HOME: home },
    })
    // Started from a shell whose core limit is raised, so the launch itself must bring it to 0.
    const child = spawn('/bin/sh', ['-c', 'ulimit -c unlimited && exec "$0" "$@"', cmd.file, ...cmd.args], {
      cwd: cmd.cwd,
      env: cmd.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let err = ''
    child.stderr.on('data', (b: Buffer) => {
      err += b.toString()
    })
    const out = await new Promise<Json>((resolve) =>
      child.stdout.once('data', (b: Buffer) => resolve(JSON.parse(b.toString()) as Json)),
    )
    child.kill('SIGUSR1')
    const code = await new Promise<number | null>((r) => child.once('exit', (c) => r(c)))
    expect(out.cwd).toBe(
      execFileSync('realpath', [runPaths(home).dir])
        .toString()
        .trim(),
    )
    expect(out.core).toBe('0')
    expect(out.execArgv).toEqual(['--disable-sigusr1'])
    expect(Object.keys(out.env as Json)).not.toContain('NODE_OPTIONS')
    expect(err).not.toContain('Debugger listening')
    expect(code).toBe(0)
  })

  it('refuses to serve an unscrubbed process (exit 2) before it takes any lock', async () => {
    const file = fileOf([['personal', P.alice]])
    const status = await serveService(configOf(file), deps(), {
      env: { NODE_OPTIONS: '--require x' },
      execArgv: ['--disable-sigusr1'],
      chdir: () => {},
      signals: { once: () => {} },
    })
    expect(status).toBe(2)
    expect(existsSync(runPaths(home).lock)).toBe(false)
  })

  it('prints a login-agent plist that launchd would accept: Core 0 both ways, the scrubbed env, the run directory', () => {
    const text = launchAgentPlist({
      label: 'dev.bag.service',
      node: '/opt/homebrew/bin/node',
      main: `${home}/package/versions/0.4.0/bag-mcp.js`,
      home,
      identities: `${home}/identities.json`,
      env: { HOME: '/Users/x', NODE_OPTIONS: '--inspect', AC_HOME: home },
    })
    expect(text).toContain('<key>SoftResourceLimits</key>\n  <dict>\n    <key>Core</key><integer>0</integer>')
    expect(text).toContain('<key>HardResourceLimits</key>\n  <dict>\n    <key>Core</key><integer>0</integer>')
    expect(text).toContain('<string>--disable-sigusr1</string>')
    expect(text).not.toContain('NODE_OPTIONS')
    expect(text).toContain(`<key>WorkingDirectory</key><string>${home}/run</string>`)
    expect(text).toContain('<key>SuccessfulExit</key><false/>')
    const file = join(home, 'agent.plist')
    writeFileSync(file, text)
    expect(execFileSync('plutil', ['-lint', file]).toString()).toContain('OK')
    // A proxy with a user name or password is left out of the printed text, and named.
    const env = {
      HTTPS_PROXY: 'http://user:secret@proxy:8080',
      http_proxy: 'http://proxy:8080',
      NO_PROXY: 'localhost',
    }
    expect(proxyOmitted(env)).toEqual(['HTTPS_PROXY'])
    const proxied = launchAgentPlist({ label: 'l', node: 'n', main: 'm', home, identities: 'i', env })
    expect(proxied).not.toContain('secret')
    expect(proxied).toContain('<key>http_proxy</key><string>http://proxy:8080</string>')
    expect(proxied).toContain('<key>NO_PROXY</key><string>localhost</string>')
  })
})

describe('bag-mcp --service as a process', () => {
  const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')

  /** Launches the real entry through the scrubbed launch; resolves its exit status, its stderr kept. */
  function launch(file: string): { exit: Promise<number | null>; err: () => string; pid: number } {
    const cmd = launchCommand({
      node: process.execPath,
      main: MAIN,
      home,
      identities: file,
      env: { HOME: home },
    })
    const child = spawn(cmd.file, cmd.args, {
      cwd: cmd.cwd,
      env: cmd.env,
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    let err = ''
    child.stderr.on('data', (b: Buffer) => {
      err += b.toString()
    })
    return {
      exit: new Promise((r) => child.once('exit', (c) => r(c))),
      err: () => err,
      pid: child.pid as number,
    }
  }

  it('serves a hello on its socket, refuses a second service busy, drains on SIGTERM (0) and SIGUSR2 (75)', async () => {
    mkdirSync(runPaths(home).dir, { recursive: true, mode: 0o700 })
    saveKeys(home, P.alice)
    const file = join(home, 'identities.json')
    const ids = [{ label: 'personal', key: 'alice', home, relays: ['http://127.0.0.1:9'] }]
    writeFileSync(file, JSON.stringify({ version: 1, identities: ids }), { mode: 0o600 })
    for (const [signal, status] of [
      ['SIGTERM', 0],
      ['SIGUSR2', 75],
    ] as const) {
      const first = launch(file)
      await until(() => existsSync(runPaths(home).token), 15_000)
      const token = readFileSync(runPaths(home).token, 'utf8')
      const socket = createConnection(runPaths(home).sock)
      sockets.push(socket)
      const answer = await new Promise<Json>((r) => {
        socket.once('data', (b: Buffer) => r(JSON.parse(b.toString()) as Json))
        socket.write(
          `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'service/hello', params: { contract: 1, token, host: 'codex', cwd: '/' } })}\n`,
        )
      })
      expect((answer.result as Json).service).toMatchObject({ pid: first.pid })
      if (signal === 'SIGTERM') {
        const second = launch(file)
        expect(await second.exit).toBe(1)
        expect(second.err()).toContain('the bag service for this home already runs')
      }
      process.kill(first.pid, signal)
      expect(await first.exit).toBe(status)
      expect(existsSync(runPaths(home).sock)).toBe(false)
    }
  }, 60_000)
})

/** A tool's answer on a line client: its structured value. */
async function call(l: Line, name: string, args: Json = {}): Promise<Json> {
  const r = await l.request('tools/call', { name, arguments: args })
  const result = r.result as { content?: { text: string }[] } | undefined
  if (result === undefined) throw new Error(JSON.stringify(r))
  return JSON.parse(result.content?.[0]?.text ?? '{}') as Json
}

/** Answers every dialog this line client is sent: the address question with an empty Yes, every other cancelled. */
function person(l: Line): void {
  const loop = async (): Promise<void> => {
    for (;;) {
      const req = await l.next((m) => m.method === 'elicitation/create')
      const params = req.params as Json
      const handle = (params._meta as Json)[DIALOG_META]
      const props = Object.keys(((params.requestedSchema as Json).properties as Json) ?? {})
      const result = props.join() === 'address' ? { action: 'accept', content: {} } : { action: 'cancel' }
      l.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } })
    }
  }
  void loop().catch(() => {})
}

describe('the wiring head: W1 table, mail hooks and the identities file in the service', () => {
  it("I1: two windows on one identity; B closes while A pairs; A's pairing runs on and only A cancels it", async () => {
    const s = await start([['personal', P.alice]], { pairPollMs: 2 })
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    person(a)
    const b = await bound(s, 'personal', { cwd: '/w/b' })
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    b.socket.destroy()
    await b.closed
    await until(() => s.connections.size === 1)
    await new Promise((r) => setTimeout(r, 30))
    // A new window of the same identity still finds A's pairing running: busy, naming A's window.
    const c = await bound(s, 'personal', { cwd: '/w/c' })
    const busy = await call(c, 'pair_invite', { name: 'jane' })
    expect(busy).toMatchObject({ error: 'busy', as: 'personal' })
    expect(String(busy.detail)).toContain('/w/a')
    expect(await call(a, 'pair_cancel')).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
  })

  it('an unbound connection: status answers bound false with how to bind; the other fifteen not-bound; no label', async () => {
    const file = fileOf([['personal', P.alice]], { allow_delegate: true })
    const s = await Service.start(configOf(file), home, deps())
    live.push(s)
    await s.opening
    const l = await hello(s)
    const tools = ((await l.request('tools/list')).result as { tools: { name: string }[] }).tools
    const CALLS: Record<string, Json> = {
      send: { to: [P.bob.address], type: 'chat.v1', body: 'hi' },
      wait: { timeout_s: 0 },
      delegate: { to: P.bob.address, caveats: ['type == "chat.v1"'], exp: '+60' },
      ask: { to: P.bob.address, body: 'q', timeout_s: 0 },
      handoff: { to: P.bob.address, threads: ['a'.repeat(64)] },
      lookup: { address: P.bob.address },
      receipts: { id: 'x' },
      pair_invite: { name: 'bob' },
      pair_accept: { name: 'carol' },
      connect: { code: 'not-a-code' },
      sign_in: { domain: 'example.com', instance: 'https://127.0.0.1' },
    }
    const names = tools.map((t) => t.name).filter((t) => t !== 'use')
    expect(names).toHaveLength(16)
    for (const tool of names) {
      const v = await call(l, tool, CALLS[tool] ?? {})
      const want =
        tool === 'status'
          ? { bound: false, note: NOT_BOUND, as: null }
          : { error: 'not-bound', detail: NOT_BOUND, as: null }
      expect([tool, v]).toEqual([tool, want])
      expect(JSON.stringify(v)).not.toMatch(/personal|ed25519:/)
    }
  })

  it('two connections on one agent identity get their own grants, each asked once, under the same caveats', async () => {
    const custody = new HomeCustody(home)
    custody.agent.create('carol', P.carol.keys)
    const asked: { session: string; caveats: readonly string[] }[] = []
    const agentConnect = () => ({
      grant: async (session: string, caveats: readonly string[], exp: number) => {
        asked.push({ session, caveats })
        return { ok: true as const, hop: { iss: P.carol.address, sub: session, caveats, exp, sig: 'x' } }
      },
      close: () => {},
    })
    const file = fileOf([['research', P.carol]], { grant_caveats: ['type=coding.*', 'repo=bag'] })
    const s = await Service.start(configOf(file), home, deps({ agentConnect } as Partial<ServiceDeps>))
    live.push(s)
    await s.opening
    await bound(s, 'research', { cwd: '/w/a' })
    const connA = lastConn(s)
    await bound(s, 'research', { cwd: '/w/b' })
    const connB = lastConn(s)
    const [ga, gb] = await Promise.all([
      s.table.grantOf(connA, 'research'),
      s.table.grantOf(connB, 'research'),
    ])
    expect(ga.keys.signing.address).not.toBe(gb.keys.signing.address)
    expect([ga.hop.sub, gb.hop.sub]).toEqual([ga.keys.signing.address, gb.keys.signing.address])
    expect(asked.map((x) => x.caveats)).toEqual([
      ['type=coding.*', 'repo=bag'],
      ['type=coding.*', 'repo=bag'],
    ])
    expect(await s.table.grantOf(connA, 'research')).toBe(ga)
    await expect(s.table.grantOf(connA, 'personal')).rejects.toThrow('not-bound')
  })

  it("an agent-bound window's act succeeds end to end through the window's grant; the unit opens through the seam", async () => {
    new HomeCustody(home).agent.create('carol', P.carol.keys)
    const rng = seededRng('agent')
    const hopTo = (sub: string, caveats: readonly string[], exp: number) =>
      signHop(P.carol.keys.signing, sub, [...caveats], exp)
    const agentConnect = () => ({
      grant: async (session: string, caveats: readonly string[], exp: number) => ({
        ok: true as const,
        hop: hopTo(session, caveats, exp),
      }),
      close: () => {},
    })
    // The unit's own opening (W1's session opening when wired): a fresh key under carol's hop.
    const agentOpening = async () => {
      const keys = generateEdgeKeys(rng)
      return { keys, hop: hopTo(keys.signing.address, ['type=chat.*'], T0 + 3600) }
    }
    // A fake agent on <home>/agent.sock that takes the thread registrations a send under agent custody makes.
    const ops: string[] = []
    const agent = createServer((sock) => {
      sock.write(`${JSON.stringify({ nonce: '00'.repeat(32) })}\n`)
      createInterface({ input: sock }).on('line', (line) => {
        ops.push(String((JSON.parse(line) as Json).op))
        sock.write(`${JSON.stringify({ ok: true })}\n`)
      })
    })
    agent.listen(join(home, 'agent.sock'))
    await new Promise((r) => agent.once('listening', r))
    servers.push(agent)
    await publishAddress(relay, P.bob)
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.bob)))
    const file = fileOf([['research', P.carol]], { grant_caveats: ['type=chat.*'] })
    const s = await Service.start(
      configOf(file),
      home,
      deps({ agentConnect, agentOpening } as Partial<ServiceDeps>),
    )
    live.push(s)
    await s.opening
    // An agent identity opens at its first bind (one y at its agent), never at an unattended start.
    expect(s.unit('research')?.opened).toBeNull()
    const a = await bound(s, 'research')
    await until(() => s.unit('research')?.opened !== null)
    const grant = await s.table.grantOf(lastConn(s), 'research')
    const before = new Set(relay.envelopes.keys())
    const r = await call(a, 'send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(r.error, JSON.stringify(r)).toBeUndefined()
    expect(r.as).toBe('research')
    const key = [...relay.envelopes.keys()].find((k) => !before.has(k)) as string
    const env = parseEnvelope(relay.envelopes.get(key) as Uint8Array)
    expect(env.from).toBe(grant.keys.signing.address)
    expect(env.auth.map((h) => [h.iss, h.sub])).toEqual([[P.carol.address, grant.keys.signing.address]])
    expect((await call(a, 'status')).mailbox).toBe(P.carol.address)
    expect(ops).toContain('register')
  })

  it('a name both custodies hold (a key file and a keychain pointer) is no identity: not listed, a bind refuses', async () => {
    const s = await start([
      ['personal', P.alice],
      ['research', P.carol],
    ])
    await s.drain()
    live.splice(live.indexOf(s), 1)
    mkdirSync(join(home, 'keychain'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'keychain', 'carol.json'), JSON.stringify({ address: P.carol.address }), {
      mode: 0o600,
    })
    const both = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      { lockRetryMs: 0 },
    )
    expect(both.identities().map((i) => i.label)).toEqual(['personal'])
    const l = await hello(both, { input_hook: true })
    expect(((await l.request('service/identities')).result as Json).identities).toEqual([
      { label: 'personal' },
    ])
    const r = await l.request('service/use', { label: 'research', via: 'typed' })
    expect(codeOf(r)).toBe('unknown-identity')
  })

  it('names.json is read on each use: a name added on disk is seen on the next call, no restart, no watcher', async () => {
    const s = await start()
    const l = await bound(s)
    expect((await call(l, 'status')).names).toEqual([])
    Names.read(home).save('bob', P.bob.address, 1_700_000_000)
    const names = (await call(l, 'status')).names as Json[]
    expect(names.map((n) => n.name)).toEqual(['bob'])
  })

  it('identities.json is read on each hello and use: an added entry binds at once; a removed one is refused, a bound window keeps it until it closes', async () => {
    const file = fileOf([['personal', P.alice]])
    let identities = configOf(file).identities
    const s = await Service.start(configOf(file), home, deps({ reread: () => identities }))
    live.push(s)
    await s.opening
    const a = await bound(s, 'personal')
    const early = await hello(s, { input_hook: true })
    identities = configOf(
      fileOf([
        ['personal', P.alice],
        ['research', P.carol],
      ]),
    ).identities
    // A window open since before reads it at its service/use; the next hello reads it too. No restart.
    expect((await early.request('service/use', { label: 'research', via: 'typed' })).result).toMatchObject({
      as: 'research',
    })
    early.socket.destroy()
    const b = await bound(s, 'research')
    await until(() => (s.unit('research')?.opened ?? null) !== null)
    expect((await call(b, 'status')).address).toBe(P.carol.address)
    // personal leaves the file: refused to a new bind, unlisted, but the window bound to it keeps acting as it.
    identities = configOf(fileOf([['research', P.carol]])).identities
    const c = await hello(s, { input_hook: true })
    expect(s.identities().map((i) => i.label)).toEqual(['research'])
    expect(codeOf(await c.request('service/use', { label: 'personal', via: 'typed' }))).toBe(
      'unknown-identity',
    )
    expect(s.identities().map((i) => i.label)).toEqual(['research'])
    expect((await call(a, 'status')).address).toBe(P.alice.address)
    expect(log.lines.some((x) => x.event === 'identity-removed' && x.fields.label === 'personal')).toBe(true)
    // Its last window closes: the unit stops, its lock released.
    a.socket.destroy()
    await until(() => s.unit('personal') === null)
    await until(() => !existsSync(join(home, 'state', 'alice', 'mcp.lock')))
  })
})

describe('the lock an identity holds', () => {
  it('is state/<name>.service/mcp.lock for an agent identity (its session), else state/<name>/mcp.lock', () => {
    expect(lockName('agent', 'carol')).toBe('carol.service')
    for (const c of ['home-key', 'keychain', 'grant', null] as const)
      expect(lockName(c, 'carol')).toBe('carol')
  })

  /** A stale session key as openAgentUnit leaves it: the key file with W1's mark (principal `principal`). */
  const staleSession = (x: string, key: typeof P.bob, principal = x): void => {
    new HomeCustody(home).agent.create(x, P.jane.keys)
    saveKeys(home, key, key.keys, `${x}.service`)
    const file = join(home, 'keys', `${x}.service.json`)
    const doc = JSON.parse(readFileSync(file, 'utf8')) as Json
    writeFileSync(file, JSON.stringify({ ...doc, kind: 'session-key', principal }), { mode: 0o600 })
    mkdirSync(join(home, 'state', `${x}.service`), { recursive: true })
  }

  it('a real x.service identity survives a start', async () => {
    // keys/build.service.json is an identity of its own (no agent pointer for build): never moved.
    saveKeys(home, P.bob, P.bob.keys, 'build.service')
    const before = readFileSync(join(home, 'keys', 'build.service.json'))
    // Even with an agent pointer and a grant.json, a listed x.service stays.
    staleSession('ci', P.carol)
    const doc = JSON.parse(readFileSync(fileOf([['personal', P.alice]]), 'utf8')) as { identities: Json[] }
    doc.identities.push({ label: 'ci', key: 'ci.service', home, relays: [RELAY] })
    const file = join(home, 'listed.json')
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    const s = await Service.start(configOf(file), home, deps())
    live.push(s)
    await s.opening
    expect(readFileSync(join(home, 'keys', 'build.service.json')).equals(before)).toBe(true)
    expect(existsSync(join(home, 'keys', 'ci.service.json'))).toBe(true)
  })

  it('a marked stale session key is moved, not deleted; a live-locked one stays', async () => {
    staleSession('ops', P.bob)
    staleSession('jane', P.jane)
    writeFileSync(
      join(home, 'state', 'jane.service', 'mcp.lock'),
      JSON.stringify({ pid: 999, started_at: new Date().toISOString() }),
    )
    // A mark naming another principal is not this agent's session key: it stays.
    staleSession('dev', P.carol, 'other')
    // A marked file whose principal has no agent pointer is not one either.
    saveKeys(home, P.org, P.org.keys, 'lost.service')
    const lost = join(home, 'keys', 'lost.service.json')
    writeFileSync(
      lost,
      JSON.stringify({
        ...(JSON.parse(readFileSync(lost, 'utf8')) as Json),
        kind: 'session-key',
        principal: 'lost',
      }),
      { mode: 0o600 },
    )
    await start([['personal', P.alice]], { alive: (pid) => pid === 999 })
    expect(existsSync(join(home, 'keys', 'ops.service.json'))).toBe(false)
    const gone = readdirSync(join(home, 'run', '.gone'))
    expect(gone.filter((f) => f.startsWith('ops.service.json.'))).toHaveLength(1)
    expect(
      execFileSync('stat', ['-f', '%Lp', join(home, 'run', '.gone')])
        .toString()
        .trim(),
    ).toBe('700')
    expect(existsSync(join(home, 'keys', 'jane.service.json'))).toBe(true)
    expect(existsSync(join(home, 'keys', 'dev.service.json'))).toBe(true)
    expect(existsSync(lost)).toBe(true)
    expect(existsSync(join(home, 'keys', 'alice.json'))).toBe(true)
  })
})

describe('--print-login-agent', () => {
  const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')
  /** Every path under `dir`, to show nothing was written. */
  const tree = (dir: string): string => execFileSync('find', [dir]).toString().split('\n').sort().join('\n')
  const run = (...args: string[]) => {
    const r = spawnSync(process.execPath, [MAIN, '--print-login-agent', ...args], {
      env: { HOME: home, HTTPS_PROXY: 'http://u:pw@proxy:8080', http_proxy: 'http://proxy:8080' },
      encoding: 'utf8',
    })
    return { status: r.status, out: r.stdout, err: r.stderr }
  }

  it('prints the plist (darwin) and the systemd user unit (linux) on stdout only, exit 0, nothing written', () => {
    mkdirSync(join(home, 'package'), { recursive: true })
    writeFileSync(join(home, 'package', 'current'), '0.4.0\n')
    const before = tree(home)
    // The node it names is the printing process's own (the child's execPath, resolved).
    const node = execFileSync(process.execPath, ['-p', 'process.execPath']).toString().trim()
    const mac = run('--dir', home, '--platform', 'darwin')
    expect(mac.status).toBe(0)
    expect(mac.out).toBe(
      launchAgentPlist({
        label: 'dev.bag.service',
        node,
        main: `${home}/package/bag-mcp.js`,
        home,
        identities: `${home}/identities.json`,
        // bag-mcp's useEnvProxy sets NODE_USE_ENV_PROXY=1 when a proxy is set, so the agent sends through it too.
        env: {
          HOME: home,
          HTTPS_PROXY: 'http://u:pw@proxy:8080',
          http_proxy: 'http://proxy:8080',
          NODE_USE_ENV_PROXY: '1',
        },
      }),
    )
    expect(mac.out).not.toContain('pw@')
    expect(mac.err).toContain('left out of the login agent: HTTPS_PROXY (it carries a user name or password)')
    const linux = run('--dir', home, '--platform', 'linux')
    expect(linux.status).toBe(0)
    expect(linux.out).toContain('# ~/.config/systemd/user/bag.service')
    expect(linux.out).toContain(
      `ExecStart="${node}" "--disable-sigusr1" "${home}/package/bag-mcp.js" "--service" "--dir" "${home}" "--identities" "${home}/identities.json"`,
    )
    for (const line of [
      'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD',
      'LimitCORE=0',
      'UMask=0077',
      'Restart=on-failure',
      `WorkingDirectory="${home}/run"`,
    ])
      expect(linux.out).toContain(line)
    expect(linux.out).toContain('Environment="http_proxy=http://proxy:8080"')
    expect(linux.out).not.toContain('pw@')
    expect(linux.out.endsWith('\n') && !linux.out.endsWith('\n\n')).toBe(true)
    expect(tree(home)).toBe(before)
  })

  it('is usage, exit 2, for a bad flag or a home with no current version, and prints nothing on stdout', () => {
    for (const args of [
      ['--dir', home],
      ['--dir', home, '--platform', 'win32'],
      ['--dir', home, '--x'],
    ]) {
      const r = run(...args)
      expect([args, r.status, r.out]).toEqual([args, 2, ''])
      expect(r.err).toContain('usage')
    }
  })
})
