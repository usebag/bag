import { AsyncLocalStorage } from 'node:async_hooks'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { parseEnvelope, SUITE, serializeRecord, signHop, signRecord, toHex } from '@usebag/core'
import {
  type EdgeKeys,
  generateEdgeKeys,
  HomeCustody,
  openIdentityKeys,
  type RelayClient,
  RelayError,
  STOP_ABORT,
  setKeepAlive,
  setTelemetry,
  telemetryEraseId,
  telemetryId,
} from '@usebag/edge'
import { OFF_USE_FORGET } from '@usebag/home'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { askListeners, askPerson } from '../src/ask.ts'
import {
  createdHere,
  NOT_BOUND,
  NOT_BOUND_DIALOG,
  pairingsOfTable,
  tableFor,
  UNBOUND_TOOLS,
} from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { Names } from '../src/names.ts'
import { type PairExtra, type Pairings, shortAddress } from '../src/pairing.ts'
import {
  launchAgentPlist,
  launchCommand,
  lockName,
  proxyOmitted,
  rereadOf,
  Service,
  type ServiceDeps,
  scrubbedEnv,
  scrubFailure,
  serveService,
  supervisorOf,
} from '../src/service.ts'
import { DIALOG_META, runPaths, type ServiceConnection } from '../src/socket.ts'
import { ACT_QUESTIONS, SHORT_NOTE, TOOL_NAMES, type ToolContext } from '../src/tools.ts'
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
    // The registering extension is the omp it names (socket-owner.ts peerIs answers match); a test changes it.
    peer: async () => 'match',
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

  it('accepts a hello whose shim member carries a surface, known or not (the parser of 0.4.3 reads no member of shim)', async () => {
    const s = await start()
    for (const surface of ['claude-vscode', 'claude-desktop', 'cli', 'something-else', 7]) {
      const l = await connect(s)
      const r = await l.request(
        'service/hello',
        helloOf(s, { shim: { version: '0.4.4', pid: 4242, surface } }),
      )
      expect(r.result, JSON.stringify(r)).toBeDefined()
    }
  })

  it("keeps the shim's surface on the connection when allow-listed, else none; a top-level surface is an unknown member", async () => {
    const s = await start()
    const surfaceOf = async (shim: Json | undefined): Promise<unknown> => {
      await hello(s, shim === undefined ? {} : { shim })
      return lastConn(s).surface
    }
    expect(await surfaceOf({ version: '0.4.4', pid: 1, surface: 'claude-vscode' })).toBe('claude-vscode')
    expect(await surfaceOf({ version: '0.4.4', pid: 1, surface: 'claude-desktop' })).toBe('claude-desktop')
    expect(await surfaceOf({ version: '0.4.4', pid: 1, surface: 'cli' })).toBe('cli')
    expect(await surfaceOf({ version: '0.4.4', pid: 1, surface: 'vscode' })).toBeNull()
    expect(await surfaceOf({ version: '0.4.3', pid: 1 })).toBeNull()
    expect(await surfaceOf(undefined)).toBeNull()
    const l = await connect(s)
    expect(codeOf(await l.request('service/hello', helloOf(s, { surface: 'claude-vscode' })))).toBe('usage')
    await l.closed
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
    const b = await hello(s)
    const timed = lastConn(s).elicit(form, { timeoutMs: 50 })
    const req3 = await b.next((m) => m.method === 'elicitation/create')
    await expect(timed).rejects.toThrow('cancelled: no answer in time')
    // An answer after the bound reaches nothing: the dialog is withdrawn, and its late Yes matches no open dialog.
    expect(await b.next((m) => m.method === 'notifications/cancelled')).toMatchObject({
      params: { requestId: req3.id },
    })
    const handle = ((req3.params as Json)._meta as Json)[DIALOG_META] as string
    b.send({
      jsonrpc: '2.0',
      id: req3.id,
      result: { action: 'accept', content: { confirm: true }, _meta: { [DIALOG_META]: handle } },
    })
    await vi.waitFor(() => expect(log.lines.some((x) => x.event === 'dialog-unknown')).toBe(true))
  })
})

describe('the omp pid in the hello (0.4.2: no bridge folder)', () => {
  it('a hello with the capability gets no bridge_dir and makes no folder; its pid is advertised (L2)', async () => {
    // The registering connection is not omp 4242's own (peerIs answers other).
    const s = await start(undefined, { peer: async () => 'other' })
    const planted = join(home, 'planted')
    const l = await connect(s)
    const r = await l.request(
      'service/hello',
      helloOf(s, {
        host: 'omp',
        client_capabilities: { experimental: { 'bag.dev/consent-bridge': { pid: 4242, dir: planted } } },
      }),
    )
    const result = r.result as Json
    expect(result.bridge_dir).toBeUndefined()
    expect(existsSync(join(home, 'run', 'shim', `${result.connection as string}.consent`))).toBe(false)
    expect(existsSync(planted)).toBe(false)
    // L2: the pid named in a hello takes no first registration afterwards from any process but omp 4242 itself;
    // the refused connection is closed.
    const ext = await connect(s)
    await ext.request('service/hello', helloOf(s, { host: 'omp' }))
    const reg = await ext.request('service/consent-register', { pid: 4242 })
    expect((reg.error as Json).data).toMatchObject({ code: 'not-authorized' })
    await ext.closed
    expect(existsSync(join(home, 'run', 'consent-4242.json'))).toBe(false)
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
  it("names its connection after the handler awaits, through the mail hooks' withConnection", async () => {
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
    // A bind of that identity answers busy naming the lend while it is lent (the binding table, binding.ts, hears it).
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

  it("names the holder (#lentWhy): a window's quiet to a lend, a CLI lend to a quiet, and a CLI lend at the return's deadline", async () => {
    let cliAlive = true
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      { alive: (pid) => pid === 999 && cliAlive },
    )
    const cli = await hello(s, { host: 'cli' })
    const end = await s.quiet('personal', 'unpair')
    const refused = await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(codeOf(refused)).toBe('busy')
    expect(String(((refused.error as Json).data as Json).detail)).toContain(
      'personal is held for unpair in a window: try again when it is done',
    )
    await end()
    expect((await cli.request('service/lend', { label: 'research', verb: 'pair' })).result).toMatchObject({
      lent: true,
    })
    await expect(s.quiet('research', 'unpair')).rejects.toThrow('research is lent to the CLI for pair')
    // The CLI holds on to its lock: the return runs to its deadline, which names the CLI's lend.
    mkdirSync(join(home, 'state', 'carol'), { recursive: true })
    writeFileSync(lockFile(P.carol), JSON.stringify({ pid: 999, started_at: new Date().toISOString() }))
    const held = await cli.request('service/return', { label: 'research' })
    expect(codeOf(held)).toBe('busy')
    expect(String(((held.error as Json).data as Json).detail)).toContain(
      'research is lent to the CLI for pair, which still holds it: return again once it has closed it',
    )
    cliAlive = false
    expect((await cli.request('service/return', { label: 'research' })).result).toMatchObject({ open: true })
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

/** The publish lines of `id` in alice's audit log, each with its detail (a JSON string in the line) parsed. */
function publishAudit(id: string): Json[] {
  return readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    .split('\n')
    .filter((x) => x !== '')
    .map((x) => JSON.parse(x) as Json)
    .filter((x) => x.event === 'publish' && x.id === id)
    .map((x) => ({ ...x, detail: JSON.parse(String(x.detail)) as Json }))
}

describe('the drain ends the process within a bounded time', () => {
  /**
   * The memory relay, with each envelope publish held open while `hold.on`: it never answers, and ends only when the
   * service's signal aborts it (as the HTTP client does, its reason in the detail), or never when `hold.deaf`.
   */
  const hold = { on: false, deaf: false, held: 0 }
  const holding = (_c: unknown, signal?: AbortSignal): RelayClient =>
    new Proxy(relay, {
      get(target, key, receiver) {
        const v = Reflect.get(target, key, receiver) as unknown
        if (key === 'publish')
          return (url: string, bytes: Uint8Array) => {
            if (!hold.on || 'kind' in (JSON.parse(Buffer.from(bytes).toString()) as Json))
              return target.publish(url, bytes)
            hold.held++
            return new Promise((_, no) => {
              if (hold.deaf) return
              signal?.addEventListener('abort', () => {
                const e = new RelayError(null, 0, null, `${url}: ${(signal.reason as Error).message}`)
                no(Object.assign(e, { stopped: STOP_ABORT }))
              })
            })
          }
        return typeof v === 'function' ? v.bind(target) : v
      },
    })
  const sendOn = (l: Line): void =>
    l.send({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'send', arguments: { to: [P.bob.address], type: 'chat.v1', body: 'held' } },
    })
  beforeEach(async () => {
    Object.assign(hold, { on: false, deaf: false, held: 0 })
    await publishAddress(relay, P.bob)
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.bob)))
  })

  it('aborts a never-answered relay request while the stores are open: relay-aborted at stop, kept', async () => {
    const s = await start([['personal', P.alice]], { relayFor: holding })
    const a = await bound(s)
    hold.on = true
    sendOn(a)
    await until(() => s.relayCalls().length === 1)
    expect(s.relayCalls()).toEqual(['personal publish'])
    const began = Date.now()
    await s.drain()
    live.splice(live.indexOf(s), 1)
    // drainCallsMs 200, then the abort: the drain ends well inside the calls' wait plus ABORT_SETTLE_MS (1 s).
    expect(Date.now() - began).toBeLessThan(1500)
    expect(s.relayCalls()).toEqual([])
    const events = log.lines.map((x) => x.event)
    expect(log.lines.find((x) => x.event === 'drain-abort')?.fields).toMatchObject({
      calls: ['personal publish'],
    })
    expect(log.lines.find((x) => x.event === 'relay-aborted')?.fields).toMatchObject({
      label: 'personal',
      call: 'publish',
      at: 'stop',
    })
    // Aborted while the stores were open: before the units stop and the service lock is released.
    expect(events.indexOf('relay-aborted')).toBeLessThan(events.indexOf('service-stop'))
    expect(events.indexOf('relay-aborted')).toBeLessThan(events.indexOf('stop'))
    // The send's answer came back before the connection closed: its target waits for a retry in the outbox.
    // H1: the window is answered with the retry line, never an error, so the model does not send it again.
    const result = (await a.next((m) => m.id === 7)).result as { isError?: boolean; structuredContent: Json }
    expect(result.isError).toBeUndefined()
    const answer = result.structuredContent
    expect(answer).toMatchObject({ retrying: true, targets: [{ status: 'retry', reason: 'unreachable' }] })
    // H2: the identity's audit line for that try names the stop.
    expect(publishAudit(String(answer.id))).toMatchObject([
      { decision: 'retry', reason: 'unreachable', detail: { status: 0, cause: STOP_ABORT } },
    ])
    // The next owner finds it in the outbox, due at its retry: the aborted send is not lost.
    const next = await start([['personal', P.alice]], { lockRetryMs: 0 })
    const store = next.unit('personal')?.opened?.store
    expect(store?.outboxTargets(String(answer.id))).toMatchObject([{ state: 'retry', reason: 'unreachable' }])
    const at = Number((answer.targets as Json[])[0]?.next_at)
    expect(store?.outboxDue(at).map((d) => d.target.id)).toContain(answer.id)
  })

  it('exits hard after the grace when a request ignores the abort, naming what was still open', async () => {
    hold.deaf = true
    const file = fileOf([['personal', P.alice]])
    const on = new Map<string, () => void>()
    const exits: number[] = []
    const served = serveService(configOf(file), deps({ relayFor: holding, exitGraceMs: 100 }), {
      env: {},
      execArgv: ['--disable-sigusr1'],
      chdir: () => {},
      signals: { once: (event, listener) => on.set(event, listener) },
      exit: (status) => exits.push(status),
      open: () => ['TCPSocketWrap', 'Timeout'],
    })
    await until(() => existsSync(runPaths(home).token), 5000)
    const token = Buffer.from(readFileSync(runPaths(home).token, 'utf8'), 'hex')
    const l = await connect({ paths: runPaths(home) } as Service)
    const hi = await l.request('service/hello', helloOf({ token } as Service, { input_hook: true }))
    expect(hi.result, JSON.stringify(hi)).toBeDefined()
    const use = await l.request('service/use', { label: 'personal', via: 'typed' })
    expect(use.result, JSON.stringify(use)).toMatchObject({ bound: true })
    hold.on = true
    sendOn(l)
    await until(() => hold.held === 1)
    ;(on.get('SIGTERM') as () => void)()
    expect(await served).toBe(0)
    expect(exits).toEqual([])
    await until(() => exits.length === 1)
    expect(exits).toEqual([0])
    expect(log.lines.find((x) => x.event === 'service-exit-hard')?.fields).toMatchObject({
      status: 0,
      open: ['TCPSocketWrap', 'Timeout'],
      relay_calls: ['personal publish'],
    })
  })

  it("a second service takes the free lock during the first's grace and still answers after the first's hard exit", async () => {
    const file = fileOf([['personal', P.alice]])
    const io = (on: Map<string, () => void>, exits: number[]) => ({
      env: {},
      execArgv: ['--disable-sigusr1'],
      chdir: () => {},
      signals: { once: (event: string, listener: () => void) => on.set(event, listener) },
      exit: (status: number) => exits.push(status),
      open: () => [],
    })
    const [on1, exits1] = [new Map<string, () => void>(), [] as number[]]
    const first = serveService(configOf(file), deps({ exitGraceMs: 400 }), io(on1, exits1))
    await until(() => existsSync(runPaths(home).token), 5000)
    const oldToken = readFileSync(runPaths(home).token, 'utf8')
    ;(on1.get('SIGTERM') as () => void)()
    expect(await first).toBe(0) // drained: the lock is free, the first's hard exit still pending
    expect(exits1).toEqual([])
    const [on2, exits2] = [new Map<string, () => void>(), [] as number[]]
    const second = serveService(configOf(file), deps({ pid: 5151 }), io(on2, exits2))
    await until(
      () => existsSync(runPaths(home).token) && readFileSync(runPaths(home).token, 'utf8') !== oldToken,
      5000,
    )
    const hello = async () => {
      const token = Buffer.from(readFileSync(runPaths(home).token, 'utf8'), 'hex')
      const l = await connect({ paths: runPaths(home) } as Service)
      return await l.request('service/hello', helloOf({ token } as Service, { input_hook: true }))
    }
    expect((await hello()).result).toBeDefined()
    await until(() => exits1.length === 1, 5000) // the first's grace ends while the second serves
    expect((await hello()).result).toBeDefined()
    expect(JSON.parse(readFileSync(runPaths(home).json, 'utf8'))).toMatchObject({ pid: 5151 })
    ;(on2.get('SIGTERM') as () => void)()
    expect(await second).toBe(0)
  })
})

describe("the login agent's copy stands by for a held lock", () => {
  const io = (on: Map<string, () => void>, more: Json = {}) => ({
    env: {},
    execArgv: ['--disable-sigusr1'],
    chdir: () => {},
    signals: { once: (event: string, listener: () => void) => on.set(event, listener) },
    exit: () => {},
    open: () => [],
    ...more,
  })
  const launchd = { platform: 'darwin', env: { XPC_SERVICE_NAME: 'dev.bag.service' }, ppid: 1 }

  it('takes launchd and systemd from the facts each sets, never from one of them alone', () => {
    const base = io(new Map())
    expect(supervisorOf({ ...base, ...launchd })).toBe('launchd')
    expect(supervisorOf({ ...base, ...launchd, ppid: 4242 })).toBeNull()
    expect(
      supervisorOf({ ...base, ...launchd, env: { XPC_SERVICE_NAME: 'application.com.apple.Terminal' } }),
    ).toBeNull()
    expect(supervisorOf({ ...base, ...launchd, platform: 'linux' })).toBeNull()
    const unit = '0::/user.slice/user-1000.slice/user@1000.service/app.slice/bag.service\n'
    const linux = { platform: 'linux', env: { INVOCATION_ID: 'a1' }, cgroup: () => unit }
    expect(supervisorOf({ ...base, ...linux })).toBe('systemd')
    expect(supervisorOf({ ...base, ...linux, env: {} })).toBeNull()
    const terminal =
      '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gnome-terminal-server.service\n'
    expect(supervisorOf({ ...base, ...linux, cgroup: () => terminal })).toBeNull()
    expect(supervisorOf(base)).toBeNull()
    // A scrubbed launch (a shim's or the CLI's) passes neither variable on.
    const scrubbed = scrubbedEnv({ XPC_SERVICE_NAME: 'dev.bag.service', INVOCATION_ID: 'a1', HOME: '/h' })
    expect(supervisorOf({ ...base, ...launchd, env: scrubbed })).toBeNull()
    expect(supervisorOf({ ...base, ...linux, env: scrubbed })).toBeNull()
  })

  it('a supervised start waits for the held lock, binds nothing meanwhile, and serves once the holder exits', async () => {
    const file = fileOf([['personal', P.alice]])
    const on1 = new Map<string, () => void>()
    const first = serveService(configOf(file), deps(), io(on1))
    await until(() => existsSync(runPaths(home).token), 5000)
    const oldToken = readFileSync(runPaths(home).token, 'utf8')
    const on2 = new Map<string, () => void>()
    const second = serveService(configOf(file), deps({ pid: 5151, lockRetryMs: 0 }), io(on2, launchd))
    await until(() => log.lines.some((x) => x.event === 'service-standby'), 5000)
    expect(log.lines.find((x) => x.event === 'service-standby')?.fields).toEqual({
      holder: 'pid 4242',
      by: 'launchd',
    })
    await new Promise((r) => setTimeout(r, 300))
    expect(readFileSync(runPaths(home).token, 'utf8')).toBe(oldToken)
    expect(JSON.parse(readFileSync(runPaths(home).json, 'utf8'))).toMatchObject({ pid: 4242 })
    expect(log.lines.filter((x) => x.event === 'service-standby')).toHaveLength(1)
    ;(on1.get('SIGTERM') as () => void)()
    expect(await first).toBe(0)
    await until(
      () => existsSync(runPaths(home).token) && readFileSync(runPaths(home).token, 'utf8') !== oldToken,
      5000,
    )
    expect(JSON.parse(readFileSync(runPaths(home).json, 'utf8'))).toMatchObject({ pid: 5151 })
    expect(log.lines.find((x) => x.event === 'service-takeover')?.fields?.waited_ms).toBeGreaterThan(0)
    ;(on2.get('SIGTERM') as () => void)()
    expect(await second).toBe(0)
  })

  it('an unsupervised start, or one with only the variable, still answers busy and exits 1', async () => {
    const file = fileOf([['personal', P.alice]])
    const on1 = new Map<string, () => void>()
    const first = serveService(configOf(file), deps(), io(on1))
    await until(() => existsSync(runPaths(home).token), 5000)
    for (const more of [{}, { ...launchd, ppid: 4242 }]) {
      const status = await serveService(
        configOf(file),
        deps({ pid: 5151, lockRetryMs: 0 }),
        io(new Map(), more),
      )
      expect(status).toBe(1)
    }
    const refused = log.lines.filter((x) => x.event === 'start' && x.level === 'error')
    expect(refused.map((x) => x.fields?.code)).toEqual(['busy', 'busy'])
    expect(log.lines.some((x) => x.event === 'service-standby')).toBe(false)
    ;(on1.get('SIGTERM') as () => void)()
    expect(await first).toBe(0)
  })

  it('a TERM while it stands by ends it with 0, the holder untouched', async () => {
    const file = fileOf([['personal', P.alice]])
    const on1 = new Map<string, () => void>()
    const first = serveService(configOf(file), deps(), io(on1))
    await until(() => existsSync(runPaths(home).token), 5000)
    const token = readFileSync(runPaths(home).token, 'utf8')
    const on2 = new Map<string, () => void>()
    const second = serveService(configOf(file), deps({ pid: 5151, lockRetryMs: 0 }), io(on2, launchd))
    await until(() => log.lines.some((x) => x.event === 'service-standby'), 5000)
    ;(on2.get('SIGTERM') as () => void)()
    expect(await second).toBe(0)
    expect(log.lines.some((x) => x.event === 'service-standby-stopped')).toBe(true)
    expect(log.lines.some((x) => x.event === 'service-takeover')).toBe(false)
    expect(readFileSync(runPaths(home).token, 'utf8')).toBe(token)
    expect(JSON.parse(readFileSync(runPaths(home).json, 'utf8'))).toMatchObject({ pid: 4242 })
    ;(on1.get('SIGTERM') as () => void)()
    expect(await first).toBe(0)
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

  it("is byte for byte the CLI's login-agent fixture, the one home's servicePlist is held to, for the same inputs", () => {
    // The two printers (this one and packages/home's servicePlist) are pinned to one fixture, so they cannot drift.
    const fixture = readFileSync(
      new URL('../../cli/test/fixtures/launch-agent-plist.txt', import.meta.url),
      'utf8',
    )
    const text = launchAgentPlist({
      label: 'dev.bag.service',
      node: '/opt/homebrew/bin/node',
      main: '/Users/x/.bag/package/bag-mcp.js',
      home: '/Users/x/.bag',
      identities: '/Users/x/.bag/identities.json',
      env: {
        HOME: '/Users/x',
        USER: 'x',
        LANG: 'C',
        AC_HOME: '/Users/x/.bag',
        NODE_OPTIONS: '--inspect',
        HTTPS_PROXY: 'http://proxy:8080',
        http_proxy: 'http://u:p@proxy:8080',
        NODE_USE_ENV_PROXY: '1',
      },
    })
    expect(text).toBe(fixture)
  })
})

describe('bag-mcp --service as a process', () => {
  const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')

  /** Launches the real entry through the scrubbed launch; resolves its exit status, its stderr kept. */
  function launch(
    file: string,
    more: string[] = [],
  ): { exit: Promise<number | null>; err: () => string; pid: number } {
    const cmd = launchCommand({
      node: process.execPath,
      main: MAIN,
      home,
      identities: file,
      env: { HOME: home },
    })
    const child = spawn(cmd.file, [...cmd.args, ...more], {
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

  it('ends within the grace of its lock release while a relay never answers, aborted at the stop', async () => {
    // A relay that answers bob's records and never answers an envelope's publish (the proof run's SIGSTOPped relay).
    // The envelope is large, so its request's own timeout (timeoutFor: 10 s plus 1 s per 16 KiB) outlasts the drain's
    // 10 s wait for calls: without the abort the process lived on to that timeout after releasing its lock.
    const now = Math.floor(Date.now() / 1000)
    let url = ''
    const records = (): Map<string, Uint8Array> =>
      new Map([
        [
          'address',
          serializeRecord(
            signRecord(P.bob.keys.signing, {
              kind: 'address',
              key: P.bob.address,
              sealing_key: toHex(P.bob.keys.sealing.publicKey),
              relays: [url],
              rotation_key: null,
              revoked: [],
              ttl: 86_400,
              iat: now - 60,
              rotated_from: null,
            }),
          ),
        ],
        [
          'accept-from',
          serializeRecord(
            signRecord(P.bob.keys.signing, {
              kind: 'accept-from',
              owner: P.bob.address,
              roots: ['*'],
              max_bytes: 196_608,
              ttl: 86_400,
              iat: now - 60,
            }),
          ),
        ],
      ])
    let held = 0
    const mute = createHttpServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (b: Buffer) => chunks.push(b))
      req.on('end', () => {
        const record = /^\/v0\/fetch\/record\/([^/]+)\/([a-z-]+)$/.exec(req.url ?? '')
        if (record !== null) {
          const bytes = record[1] === P.bob.address ? records().get(record[2] as string) : undefined
          res.writeHead(bytes === undefined ? 404 : 200).end(bytes ?? '{"error":"not-found"}')
        } else if (
          req.method === 'POST' &&
          'kind' in (JSON.parse(Buffer.concat(chunks).toString()) as Json)
        ) {
          res.writeHead(200).end('{"ok":true}')
        } else if (req.method === 'POST') held++
        else res.writeHead(404).end('{}')
      })
    })
    mute.on('upgrade', () => {})
    servers.push(mute as unknown as Server)
    await new Promise<void>((r) => mute.listen(0, '127.0.0.1', () => r()))
    url = `http://127.0.0.1:${(mute.address() as { port: number }).port}`
    mkdirSync(runPaths(home).dir, { recursive: true, mode: 0o700 })
    saveKeys(home, P.alice)
    const file = join(home, 'identities.json')
    const ids = [{ label: 'personal', key: 'alice', home, relays: [url], trust_roots: [P.bob.address] }]
    writeFileSync(file, JSON.stringify({ version: 1, identities: ids }), { mode: 0o600 })
    const first = launch(file, ['--allow-private-relays'])
    await until(() => existsSync(runPaths(home).token), 15_000)
    const token = readFileSync(runPaths(home).token, 'utf8')
    const l = await connect({ paths: runPaths(home) } as Service)
    const hi = await l.request('service/hello', {
      contract: 1,
      token,
      host: 'codex',
      cwd: '/',
      input_hook: true,
    })
    expect(hi.result, JSON.stringify(hi)).toBeDefined()
    const use = await l.request('service/use', { label: 'personal', via: 'typed' })
    expect(use.result, JSON.stringify(use)).toMatchObject({ bound: true })
    l.send({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'send', arguments: { to: [P.bob.address], type: 'chat.v1', body: 'x'.repeat(70_000) } },
    })
    await until(() => held === 1, 10_000)
    const term = Date.now()
    process.kill(first.pid, 'SIGTERM')
    let released = 0
    await until(() => {
      if (released === 0 && first.err().includes('"service-stop"')) released = Date.now()
      return released > 0
    }, 20_000)
    expect(await first.exit).toBe(0)
    const ended = Date.now()
    const lines = first.err().split('\n')
    // Within the grace (3 s) of the lock's release, and of the drain's 10 s wait plus the 1 s settle.
    expect(ended - released).toBeLessThan(3_500)
    expect(ended - term).toBeLessThan(10_000 + 1_000 + 3_000 + 1_000)
    expect(lines.find((x) => x.includes('"drain-abort"'))).toContain('"calls":["personal publish"]')
    expect(lines.find((x) => x.includes('"relay-aborted"'))).toContain('"call":"publish","at":"stop"')
    // H1: the window was answered before the connection closed with the retry line, never an error.
    const result = (await l.next((m) => m.id === 7)).result as { isError?: boolean; structuredContent: Json }
    expect(result.isError).toBeUndefined()
    expect(result.structuredContent).toMatchObject({ retrying: true, targets: [{ status: 'retry' }] })
    // H2: the real HTTP client marks the try its signal aborted; the audit line names the stop.
    expect(publishAudit(String(result.structuredContent.id))).toMatchObject([
      { decision: 'retry', reason: 'unreachable', detail: { status: 0, cause: STOP_ABORT } },
    ])
  }, 60_000)
})

/** A tool's answer on a line client: its structured value. */
async function call(l: Line, name: string, args: Json = {}): Promise<Json> {
  const r = await l.request('tools/call', { name, arguments: args })
  const result = r.result as { content?: { text: string }[] } | undefined
  if (result === undefined) throw new Error(JSON.stringify(r))
  return JSON.parse(result.content?.[0]?.text ?? '{}') as Json
}

/**
 * A person's pace (0.4.4): an answer sooner than FAST_ANSWER_MS after its dialog went out is unseen, and the service's
 * dialog clocks are the real one here, so a scripted answer waits this long first.
 */
const PERSON_MS = 300
const atPersonPace = (): Promise<void> => new Promise((r) => setTimeout(r, PERSON_MS))

/** Answers every dialog this line client is sent: the address question with an empty Yes, every other cancelled. */
function person(l: Line): void {
  const loop = async (): Promise<void> => {
    for (;;) {
      const req = await l.next((m) => m.method === 'elicitation/create')
      const params = req.params as Json
      const handle = (params._meta as Json)[DIALOG_META]
      const props = Object.keys(((params.requestedSchema as Json).properties as Json) ?? {})
      const result = props.join() === 'address' ? { action: 'accept', content: {} } : { action: 'cancel' }
      await atPersonPace()
      l.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } })
    }
  }
  void loop().catch(() => {})
}

describe('the wiring: the binding table, mail hooks and the identities file in the service', () => {
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

  it("the drain ends every window's pairing, of every identity, as the service: each audited as a close", async () => {
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      { pairPollMs: 2 },
    )
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    person(a)
    const b = await bound(s, 'research', { cwd: '/w/b' })
    person(b)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    expect(await call(b, 'pair_invite', { name: 'jane' })).toMatchObject({
      invite_open: true,
      as: 'research',
    })
    await s.drain()
    live.splice(live.indexOf(s), 1)
    for (const [name, window] of [
      ['alice', '/w/a'],
      ['carol', '/w/b'],
    ]) {
      const ends = readFileSync(join(home, 'state', name as string, 'audit.jsonl'), 'utf8')
        .split('\n')
        .filter((x) => x !== '')
        .map((x) => JSON.parse(x) as Json)
        .filter((x) => x.event === 'pair' && x.decision === 'reject')
        .map((x) => JSON.parse(String(x.detail)) as Json)
      expect([name, ends]).toEqual([
        name,
        [expect.objectContaining({ code: 'cancelled', reason: 'close', window: `claude-code ${window}` })],
      ])
    }
  })

  it("a lend refused for a running pairing names the pairing's own window, not the first window open", async () => {
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
        ['lab', P.jane],
      ],
      { pairPollMs: 2 },
    )
    // research's window opens first; personal's window, opened after it, runs the pairing.
    await bound(s, 'research', { cwd: '/w/first' })
    const a = await bound(s, 'personal', { cwd: '/w/pairing' })
    person(a)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    const cli = await hello(s, { host: 'cli' })
    const refused = await cli.request('service/lend', { label: 'lab', verb: 'pair' })
    expect(codeOf(refused)).toBe('busy')
    const detail = String(((refused.error as Json).data as Json).detail)
    expect(detail).toContain('/w/pairing')
    expect(detail).not.toContain('/w/first')
    expect(await call(a, 'pair_cancel')).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
    expect((await cli.request('service/lend', { label: 'lab', verb: 'pair' })).result).toMatchObject({
      lent: true,
    })
  })

  it('an unbound connection: status answers bound false with how to bind, identities its short list; every other not-bound; no label', async () => {
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
      identity_remove: { name: 'personal' },
      identity_relays: { relays: [RELAY] },
      keep_alive: { word: 'on' },
      local_delivery: { word: 'status' },
      unpair: { root: P.bob.address },
      names: { verb: 'list' },
      identity_create: { label: 'Not a label', relays: [RELAY] },
      telemetry: { word: 'status' },
      host_wire: { host: 'claude-code', folder: '/nowhere/else' },
      service: {},
    }
    const names = tools.map((t) => t.name).filter((t) => t !== 'use' && t !== 'unbind')
    expect(names).toHaveLength(28)
    const ids = await call(l, 'identities')
    expect(ids).toEqual({
      identities: [{ label: 'personal', address: shortAddress(P.alice.address) }],
      full: false,
      note: SHORT_NOTE,
      as: null,
    })
    for (const tool of names.filter((t) => t !== 'identities')) {
      const v = await call(l, tool, CALLS[tool] ?? {})
      // identity_create and telemetry run unbound: here each refuses its argument (a bad label; no HOME) as usage.
      const want =
        tool === 'status'
          ? { bound: false, note: NOT_BOUND_DIALOG, as: null }
          : ['identity_create', 'telemetry', 'host_wire', 'service'].includes(tool)
            ? { error: 'usage', detail: expect.any(String), as: null }
            : { error: 'not-bound', detail: NOT_BOUND_DIALOG, as: null }
      expect([tool, v]).toEqual([tool, want])
      expect(JSON.stringify(v)).not.toMatch(/personal|ed25519:/)
    }
  })

  /** An agent identity research (carol's keys in the agent), its fakes recording every y asked of the agent. */
  async function agentHome(opening: boolean) {
    new HomeCustody(home).agent.create('carol', P.carol.keys)
    const rng = seededRng('agent-quiet')
    const hopTo = (sub: string, caveats: readonly string[], exp: number) =>
      signHop(P.carol.keys.signing, sub, [...caveats], exp)
    const asked: string[] = []
    const agentConnect = () => ({
      grant: async (session: string, caveats: readonly string[], exp: number) => {
        asked.push(session)
        return { ok: true as const, hop: hopTo(session, caveats, exp) }
      },
      close: () => {},
    })
    const agentOpening = async () => {
      asked.push('opening')
      const keys = generateEdgeKeys(rng)
      return { keys, hop: hopTo(keys.signing.address, ['type=chat.*'], T0 + 3600) }
    }
    // A fake agent on <home>/agent.sock: any request the default agent opening makes of it is recorded.
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
    const file = fileOf([['research', P.carol]], { grant_caveats: ['type=chat.*'] })
    // A give-back wait of 30 s: no loaded run reaches the deadline branch by timing; the outcome alone is asserted.
    const more = {
      ...(opening ? { agentConnect, agentOpening } : { agentConnect }),
      returnWaitMs: 30_000,
    } as Partial<ServiceDeps>
    const s = await Service.start(configOf(file), home, deps(more))
    live.push(s)
    await s.opening
    return { s, asked, ops }
  }
  const returned = (label: string): boolean =>
    log.lines.some((l) => l.event === 'return' && l.fields.label === label && l.fields.removed === false)

  it("an agent identity that has opened, held quiet for a window's act, is given back open at once, its hold named as the window's", async () => {
    const { s } = await agentHome(true)
    await bound(s, 'research')
    await until(() => s.unit('research')?.opened !== null)
    const end = await s.quiet('research', 'unpair')
    // Every suspend from here on is recorded (the quiet's own suspend, before, is not among them); the clean path may
    // make none.
    const unit = s.unit('research') as NonNullable<ReturnType<typeof s.unit>>
    const suspend = vi.spyOn(unit, 'suspend')
    await end()
    const seen = suspend.mock.calls.map(([why]) => String((why as Error | undefined)?.message ?? why))
    suspend.mockRestore()
    // Opened again (open: true), by the return path, not its deadline.
    expect(returned('research')).toBe(true)
    expect(s.unit('research')?.opened).not.toBeNull()
    expect(s.lent('research')).toBeNull()
    expect(seen.every((m) => m.includes('research is held for unpair in a window'))).toBe(true)
    expect(seen.some((m) => m.includes('lent to the CLI'))).toBe(false)
  })

  it('an agent identity never opened, held quiet and given back, goes back to opening at its bind at once: no y asked', async () => {
    const { s, asked, ops } = await agentHome(false)
    expect(s.unit('research')?.opened).toBeNull()
    const end = await s.quiet('research', 'unpair')
    await end()
    // The return path, not the deadline (which logs no return and goes on to a reopen that would ask the agent).
    expect(returned('research')).toBe(true)
    expect(s.lent('research')).toBeNull()
    // opens_at bind: not opened, and answering that it opens at its bind.
    expect(s.unit('research')?.opened).toBeNull()
    expect(String((s.unit('research')?.failure as Error | undefined)?.message)).toContain(
      'research opens when a window binds to it (its agent asks for a y then)',
    )
    expect([asked, ops]).toEqual([[], []])
    expect(log.lines.some((l) => l.event === 'agent-preflight')).toBe(false)
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
    // The unit's own opening (session.ts openAgentUnit when wired): a fresh key under carol's hop.
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

  /** A stale session key as openAgentUnit leaves it: the key file marked kind session-key, principal `principal`. */
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
      `WorkingDirectory=${home}/run`,
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
      ['--dir', `${home}\nx`, '--platform', 'linux'],
      ['--dir', `${home}\u0001x`, '--platform', 'darwin'],
      ['--dir', home, '--x'],
    ]) {
      const r = run(...args)
      expect([args, r.status, r.out]).toEqual([args, 2, ''])
      expect(r.err).toContain('usage')
    }
  })
})

describe("service.json's live counts: pairings, lends and asking", () => {
  /** service.json as any reader sees it: the file alone, with no window of the test's own. */
  const status = (): Json => JSON.parse(readFileSync(runPaths(home).json, 'utf8')) as Json

  it('adds the three counts after draining, all 0 at the start, and keeps started_at at every rewrite', async () => {
    const clock = new FakeClock()
    const s = await start([['personal', P.alice]], { clock })
    const first = status()
    expect(Object.keys(first)).toEqual([
      'pid',
      'started_at',
      'contract',
      'version',
      'package_dir',
      'draining',
      'pairings',
      'lends',
      'asking',
    ])
    expect(first).toMatchObject({ pid: 4242, contract: 1, draining: false, pairings: 0, lends: 0, asking: 0 })
    clock.t += 3600
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(status()).toMatchObject({ lends: 1, started_at: first.started_at })
  })

  it('lends: 1 while lent, 0 at the return and at the give-back of a closed lender; a refused lend leaves the file as it was', async () => {
    const s = await start()
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(status()).toMatchObject({ lends: 1 })
    const ino = statSync(runPaths(home).json).ino
    expect(codeOf(await cli.request('service/lend', { label: 'personal', verb: 'keys' }))).toBe('busy')
    expect(statSync(runPaths(home).json).ino).toBe(ino)
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({
      returned: true,
    })
    expect(status()).toMatchObject({ lends: 0 })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(status()).toMatchObject({ lends: 1 })
    cli.socket.destroy()
    await cli.closed
    await until(() => s.lent('personal') === null)
    expect(status()).toMatchObject({ lends: 0 })
  })

  it('pairings counts every window of the service: started in A it reads 1 with no window, 2 with B, down at the cancel and the close', async () => {
    const s = await start(
      [
        ['personal', P.alice],
        ['research', P.carol],
      ],
      { pairPollMs: 2 },
    )
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    person(a)
    const b = await bound(s, 'research', { cwd: '/w/b' })
    person(b)
    expect(status()).toMatchObject({ pairings: 0 })
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    expect(status()).toMatchObject({ pairings: 1 })
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'research' })
    expect(status()).toMatchObject({ pairings: 2 })
    expect(await call(a, 'pair_cancel')).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
    expect(status()).toMatchObject({ pairings: 1 })
    b.socket.destroy()
    await b.closed
    await until(() => status().pairings === 0)
  })

  it('asking counts an ask of this home from before its dialog until its answer', async () => {
    await start()
    let answer: (r: Json) => void = () => {}
    const conn = {
      handle: 'w-ask',
      host: 'claude-code',
      cwd: '/w',
      capabilities: { elicitation: true, inputHook: false, raw: {} },
      elicit: () =>
        new Promise<Json>((r) => {
          answer = r
        }),
    } as unknown as ServiceConnection
    const ctx = {
      config: { home },
      clock: { now: () => T0 },
      // A person's pace (0.4.4): each read moves a second, so the cancel below is the person's, not unseen.
      mono: (
        (t) => () =>
          (t += 1000)
      )(0),
      log: { log: () => {} },
      opened: null,
      timers: new ManualTimers(),
    } as unknown as ToolContext
    const extra = { signal: new AbortController().signal } as unknown as PairExtra
    const asked = askPerson(
      ctx,
      extra,
      { act: 'test-act', kind: 'confirm', title: 'Yes', message: 'Do it?' },
      conn,
    )
    expect(status()).toMatchObject({ asking: 1 })
    answer({ action: 'cancel' })
    expect(await asked).toEqual({ said: 'none' })
    expect(status()).toMatchObject({ asking: 0 })
  })

  /**
   * A window whose root context was read for pairings before its first pair call (the lend's check reads every
   * window's), then bound to the home's one identity: its pair tools must use the service's counted Pairings.
   */
  async function readBeforePairing(s: Service): Promise<Line> {
    const a = await hello(s, { input_hook: true, cwd: '/w/a' })
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({
      returned: true,
    })
    const r = await a.request('service/use', { label: 'personal', via: 'typed' })
    expect(r.result, JSON.stringify(r)).toMatchObject({ bound: true, as: 'personal' })
    person(a)
    return a
  }

  it('a pairing started after a lend and its return, in a one-identity window, is counted: pairings 1', async () => {
    const s = await start([['personal', P.alice]], { pairPollMs: 2 })
    const a = await readBeforePairing(s)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    expect(status()).toMatchObject({ pairings: 1 })
  })

  it("such a window's close ends its pairing: pairings 0, and another window pairs at once", async () => {
    const s = await start([['personal', P.alice]], { pairPollMs: 2 })
    const a = await readBeforePairing(s)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true })
    expect(status()).toMatchObject({ pairings: 1 })
    a.socket.destroy()
    await a.closed
    await until(() => status().pairings === 0)
    const b = await bound(s, 'personal', { cwd: '/w/b' })
    person(b)
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
  })

  it("the drain's cancel ends a window's pairing: it counts 0 while the drain runs, and the close at its end removes the file", async () => {
    let free: () => void = () => {}
    const held = new Promise<void>((r) => {
      free = r
    })
    const s = await start([['personal', P.alice]], { pairPollMs: 2, mail: { drain: () => held } })
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    person(a)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true })
    const drained = s.drain('stop')
    await until(() => log.lines.some((x) => x.event === 'drain-pairings'))
    await new Promise((r) => setTimeout(r, 30))
    // The drain ends each window's pairing as the service (Pairings.drainStop), past pair_cancel's window check, so
    // none runs on while the drain waits.
    await until(() => status().pairings === 0)
    expect(status()).toMatchObject({ draining: true, pairings: 0 })
    free()
    await drained
    live.splice(live.indexOf(s), 1)
    expect(existsSync(runPaths(home).json)).toBe(false)
  })

  it("the drain ends the console's own ceremony too, which runs in no window: it counts 0 while the drain runs, ended as a close", async () => {
    let free: () => void = () => {}
    const held = new Promise<void>((r) => {
      free = r
    })
    const s = await start([['personal', P.alice]], { pairPollMs: 2, mail: { drain: () => held } })
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    // personal's Pairings in the service, made at its first pair call (none runs yet: nothing is cancelled).
    expect(await call(a, 'pair_cancel')).toMatchObject({ cancelled: false })
    const p = pairingsOfTable(s.table)[0] as Pairings
    const ceremony = p.consoleInvite({ ttl: 600, opened: () => {}, ask: async () => false })
    ceremony.catch(() => {})
    await until(() => status().pairings === 1)
    expect(p.runningIn()).toBeNull()
    const drained = s.drain('stop')
    await until(() => status().pairings === 0)
    expect(status()).toMatchObject({ draining: true, pairings: 0 })
    await expect(ceremony).rejects.toBeDefined()
    free()
    await drained
    live.splice(live.indexOf(s), 1)
    const ends = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
      .split('\n')
      .filter((x) => x !== '')
      .map((x) => JSON.parse(x) as Json)
      .filter((x) => x.event === 'pair' && x.decision === 'reject')
      .map((x) => JSON.parse(String(x.detail)) as Json)
    expect(ends).toEqual([expect.objectContaining({ code: 'cancelled', reason: 'close' })])
  })

  it("a start refused busy never hears the home's asks; the drain stops the live one hearing them", async () => {
    const s = await start()
    expect(askListeners(home)).toBe(1)
    await expect(
      Service.start(configOf(fileOf([['personal', P.alice]])), home, deps({ lockRetryMs: 0 })),
    ).rejects.toThrow('busy')
    expect(askListeners(home)).toBe(1)
    await s.drain()
    live.splice(live.indexOf(s), 1)
    expect(askListeners(home)).toBe(0)
  })

  it("a window's act held quiet counts as a lend: lends 1 while quiet holds it, 0 after its end", async () => {
    const s = await start()
    const end = await s.quiet('personal', 'unpair')
    expect(status()).toMatchObject({ lends: 1 })
    await end()
    expect(s.lent('personal')).toBeNull()
    expect(status()).toMatchObject({ lends: 0 })
  })

  it("a start refused busy in the same process leaves the live service's table: its pair tools and pairings still work", async () => {
    const s = await start([['personal', P.alice]], { pairPollMs: 2 })
    const a = await bound(s, 'personal', { cwd: '/w/a' })
    person(a)
    await expect(
      Service.start(configOf(fileOf([['personal', P.alice]])), home, deps({ lockRetryMs: 0 })),
    ).rejects.toThrow('busy')
    expect(tableFor(home)).toBe(s.table)
    expect(await call(a, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true, as: 'personal' })
    expect(status()).toMatchObject({ pairings: 1 })
    expect(await call(a, 'pair_cancel')).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
    expect(status()).toMatchObject({ pairings: 0 })
  })

  it('while draining: draining true with the lend still counted and started_at kept; after the drain no file', async () => {
    const clock = new FakeClock()
    let free: () => void = () => {}
    const held = new Promise<void>((r) => {
      free = r
    })
    const s = await start([['personal', P.alice]], { clock, mail: { drain: () => held } })
    const at = status().started_at
    const cli = await hello(s, { host: 'cli' })
    await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    clock.t += 3600
    const drained = s.drain('upgrade')
    await until(() => status().draining === true)
    expect(status()).toMatchObject({ draining: true, lends: 1, started_at: at })
    free()
    await drained
    live.splice(live.indexOf(s), 1)
    expect(existsSync(runPaths(home).json)).toBe(false)
  })
})

describe('an empty home: the service starts with no identity and serves only the unbound tools', () => {
  /** A service of a home with no identities file, its reread the file identity_create writes. */
  async function empty(): Promise<Service> {
    const file = join(home, 'identities.json')
    const config = configOf(file)
    const s = await Service.start(config, home, deps({ reread: rereadOf(file, config, home) }))
    live.push(s)
    await s.opening
    return s
  }

  /** Answers the next dialog of `l` with `content` (a Yes), and returns its message. */
  async function yes(l: Line, content: Json): Promise<string> {
    const req = await l.next((m) => m.method === 'elicitation/create')
    const params = req.params as Json
    const handle = (params._meta as Json)[DIALOG_META]
    await atPersonPace()
    l.send({
      jsonrpc: '2.0',
      id: req.id,
      result: { action: 'accept', content, _meta: { [DIALOG_META]: handle } },
    })
    return String(params.message)
  }

  it('T1: starts on a home with no identity, serves a window, and status answers with no identity, no throw', async () => {
    const s = await empty()
    expect(s.units.size).toBe(0)
    expect(log.lines.find((l) => l.event === 'service-start')?.fields).toMatchObject({ identities: 0 })
    const l = await hello(s, { input_hook: true })
    expect(await call(l, 'status')).toEqual({ bound: false, note: NOT_BOUND, as: null })
    expect(await call(l, 'identities')).toEqual({ identities: [], full: false, note: SHORT_NOTE, as: null })
    expect(tableFor(home)?.state(lastConn(s))).toBe('unbound')
  })

  it('an identities.json that lists none is an empty home too: the service starts on it, serving the unbound tools', async () => {
    const file = join(home, 'identities.json')
    writeFileSync(file, JSON.stringify({ version: 1, identities: [] }), { mode: 0o600 })
    const config = configOf(file)
    expect(config.identities).toEqual([])
    const s = await Service.start(config, home, deps({ reread: rereadOf(file, config, home) }))
    live.push(s)
    await s.opening
    expect(s.units.size).toBe(0)
    const l = await hello(s, { input_hook: true })
    expect(await call(l, 'status')).toEqual({ bound: false, note: NOT_BOUND, as: null })
    expect(log.lines.filter((x) => x.event === 'identities-reread')).toEqual([])
    // identity_create on it serves the new one at once, through the same reread.
    const made = call(l, 'identity_create', { label: 'jane', relays: [RELAY] })
    await yes(l, { confirm: true })
    expect(await made).toMatchObject({ as: null })
    // The unit attaches through the reread after the answer, as in T3: wait for it.
    await until(() => s.unit('jane') !== null)
    expect(s.unit('jane')).not.toBeNull()
  })

  it('a hello to a home with no identities file logs no identities-reread warn', async () => {
    const s = await empty()
    await hello(s, { input_hook: true })
    await hello(s, { input_hook: true })
    expect(log.lines.filter((x) => x.event === 'identities-reread')).toEqual([])
  })

  it('T2: every registered tool name, driven once (the full list): outside UNBOUND_TOOLS each answers not-bound; none reaches the null opened', async () => {
    const s = await empty()
    // No dialog on this host, so an unbound act refuses at once rather than waiting on a person.
    const l = await hello(s, { input_hook: true, client_capabilities: {} })
    const tools = ((await l.request('tools/list')).result as { tools: { name: string }[] }).tools
    const names = tools.map((t) => t.name).sort()
    // The full list: every tool but delegate (no identity allows it), and use and unbind.
    expect(names).toEqual([...TOOL_NAMES.filter((t) => t !== 'delegate'), 'use', 'unbind'].sort())
    const ARGS: Record<string, Json> = {
      send: { to: [P.bob.address], type: 'chat.v1', body: 'hi' },
      wait: { timeout_s: 0 },
      ask: { to: P.bob.address, body: 'q', timeout_s: 0 },
      handoff: { to: P.bob.address, threads: ['a'.repeat(64)] },
      lookup: { address: P.bob.address },
      receipts: { id: 'x' },
      pair_invite: { name: 'bob' },
      pair_accept: { name: 'carol' },
      connect: { code: 'not-a-code' },
      sign_in: { domain: 'example.com', instance: 'https://127.0.0.1' },
      identity_remove: { name: 'personal' },
      identity_relays: { relays: [RELAY] },
      keep_alive: { word: 'on' },
      local_delivery: { word: 'status' },
      unpair: { root: P.bob.address },
      names: { verb: 'list' },
      identity_create: { label: 'jane', relays: [RELAY] },
      telemetry: { word: 'status' },
      host_wire: { host: 'claude-code', folder: '/nowhere/else' },
    }
    const answers: [string, Json][] = []
    for (const tool of names) answers.push([tool, await call(l, tool, ARGS[tool] ?? {})])
    for (const [tool, v] of answers) {
      // A dereference of the null opened would be a TypeError, answered internal: never.
      expect([tool, v.error]).not.toEqual([tool, 'internal'])
      expect([tool, v.as]).toEqual([tool, null])
      if (!UNBOUND_TOOLS.includes(tool))
        expect([tool, v]).toEqual([tool, { error: 'not-bound', detail: NOT_BOUND, as: null }])
    }
    // The unbound ones answer their own way: status how to bind, identities none, the acts no dialog on this host.
    const of = new Map(answers)
    expect(of.get('status')).toEqual({ bound: false, note: NOT_BOUND, as: null })
    expect(of.get('identities')).toMatchObject({ identities: [] })
    expect(of.get('use')).toMatchObject({ error: 'no-elicitation' })
    expect(of.get('unbind')).toEqual({ unbound: [], as: null })
    expect(of.get('identity_create')).toMatchObject({ error: 'no-elicitation' })
    expect(of.get('telemetry')).toMatchObject({ error: 'usage' })
    expect(of.get('host_wire')).toMatchObject({ error: 'usage' })
    expect(of.get('service')).toMatchObject({ error: 'usage' })
    expect(
      await call(l, 'host_wire', { host: 'omp', folder: '/nowhere/else', action: 'unwire' }),
    ).toMatchObject({ error: 'usage', as: null })
    expect(existsSync(join(home, 'identities.json'))).toBe(false)
  })

  it('T3: identity_create after the Yes, then the reread serves the unit live and use binds it in the same window', async () => {
    const s = await empty()
    const l = await hello(s, { input_hook: true })
    const pending = call(l, 'identity_create', { label: 'jane', relays: [RELAY] })
    expect(await yes(l, { confirm: true })).toBe(
      (ACT_QUESTIONS.create('jane', ['http://relay.test']) as { message: string }).message,
    )
    const made = await pending
    expect(made).toMatchObject({ as: null })
    const address = (made.lines as string[])[0] as string
    expect(address).toMatch(/^ed25519:[0-9a-f]{64}$/)
    // Served at once: a unit, open, by the same address; this window is still bound to none.
    await until(() => {
      const u = s.unit('jane')
      return u !== null && u.opened !== null
    })
    expect(s.unit('jane')?.address).toBe(address)
    expect(tableFor(home)?.state(lastConn(s))).toBe('unbound')
    expect(await call(l, 'status')).toEqual({ bound: false, note: NOT_BOUND, as: null })
    // use opens the bind dialog in this window, and only the Yes there binds it.
    const use = call(l, 'use', { name: 'jane' })
    await yes(l, { bind: true })
    expect(await use).toMatchObject({ bound: true, as: 'jane', granted: 'dialog' })
    expect(await call(l, 'status')).toMatchObject({ as: 'jane', address })
  })

  it('T19: identity_create and telemetry on ask over an omp link too, in the same words; only the Yes writes', async () => {
    const machine = join(home, 'machine')
    const file = join(home, 'identities.json')
    const config = configOf(file)
    const s = await Service.start(
      config,
      home,
      deps({ reread: rereadOf(file, config, home), env: { HOME: machine } }),
    )
    live.push(s)
    await s.opening
    const ext = await connect(s)
    await ext.request('service/hello', helloOf(s, { host: 'omp' }))
    expect((await ext.request('service/consent-register', { pid: 777 })).result).toBeDefined()
    const w = await hello(s, {
      host: 'omp',
      input_hook: true,
      client_capabilities: { experimental: { 'bag.dev/consent-bridge': { pid: 777 } } },
    })
    const answer = async (accepted: boolean): Promise<Json> => {
      const ask = (await ext.next((m) => m.method === 'service/consent-ask')).params as Json
      await ext.request('service/consent-answer', { id: ask.id, accepted })
      return ask
    }
    const made = call(w, 'identity_create', { label: 'jane', relays: [RELAY] })
    expect(await answer(true)).toMatchObject(ACT_QUESTIONS.create('jane', ['http://relay.test']) ?? {})
    expect(await made).toMatchObject({
      lines: expect.arrayContaining([expect.stringMatching(/^ed25519:/)]),
      as: null,
    })
    const no = call(w, 'telemetry', { word: 'on' })
    expect(await answer(false)).toMatchObject(ACT_QUESTIONS.telemetryOn)
    expect(await no).toMatchObject({ error: 'declined', as: null })
    expect(existsSync(join(machine, '.bag', 'telemetry.json'))).toBe(false)
    const on = call(w, 'telemetry', { word: 'on' })
    await answer(true)
    const lines = (await on).lines as string[]
    expect(lines[0]).toMatch(/^telemetry on reason=file choice=on id=set spool=/)
    expect(JSON.stringify(lines)).not.toMatch(/[0-9a-f]{32}/)
  })

  it('T15, T16: telemetry on asks in the window; off and status ask nothing, and off runs while on is asked', async () => {
    const machine = join(home, 'machine')
    const s = await Service.start(
      configOf(join(home, 'identities.json')),
      home,
      deps({ env: { HOME: machine } }),
    )
    live.push(s)
    await s.opening
    const l = await hello(s, { input_hook: true })
    expect(await call(l, 'telemetry', { word: 'status' })).toEqual({
      lines: ['telemetry off reason=no-file choice=none id=none spool=0 sent=none'],
      as: null,
    })
    const on = call(l, 'telemetry', { word: 'on' })
    const req = await l.next((m) => m.method === 'elicitation/create')
    expect((req.params as Json).message).toBe(ACT_QUESTIONS.telemetryOn.message)
    // While that question is open, off answers at once and asks nothing.
    expect(await call(l, 'telemetry', { word: 'off' })).toEqual({
      lines: ['telemetry off reason=file choice=off id=none spool=0 sent=none'],
      as: null,
    })
    const handle = ((req.params as Json)._meta as Json)[DIALOG_META]
    await atPersonPace()
    l.send({ jsonrpc: '2.0', id: req.id, result: { action: 'cancel', _meta: { [DIALOG_META]: handle } } })
    expect(await on).toMatchObject({ error: 'cancelled', as: null })
    expect(await call(l, 'telemetry', { word: 'status' })).toEqual({
      lines: ['telemetry off reason=file choice=off id=none spool=0 sent=none'],
      as: null,
    })
    // After a Yes, off removes the id and says how to have the reports already sent erased.
    const yes = call(l, 'telemetry', { word: 'on' })
    const again = await l.next((m) => m.method === 'elicitation/create')
    await atPersonPace()
    l.send({
      jsonrpc: '2.0',
      id: again.id,
      result: {
        action: 'accept',
        content: { confirm: true },
        _meta: { [DIALOG_META]: ((again.params as Json)._meta as Json)[DIALOG_META] },
      },
    })
    // No answer of the tool carries the install id (it would reach the model and its provider): id=set, and off
    // names forget, the act that also erases the reports already sent.
    const onAnswer = await yes
    expect((onAnswer.lines as string[])[0]).toMatch(/^telemetry on reason=file choice=on id=set spool=/)
    const status = await call(l, 'telemetry', { word: 'status' })
    expect((status.lines as string[])[0]).toMatch(/^telemetry on reason=file choice=on id=set spool=/)
    const off = await call(l, 'telemetry', { word: 'off' })
    expect(off.lines).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      OFF_USE_FORGET,
    ])
    for (const v of [onAnswer, status, off]) expect(JSON.stringify(v)).not.toMatch(/[0-9a-f]{32}/)
  })

  it('forget through the tool asks nothing, turns off, then erases at the endpoint; a failure keeps the id; no id shown', async () => {
    const machine = join(home, 'machine')
    let status = 503
    const bodies: string[] = []
    const fetch = async (_url: string, init: RequestInit): Promise<Response> => {
      bodies.push(String(init.body))
      return new Response(null, { status })
    }
    const s = await Service.start(
      configOf(join(home, 'identities.json')),
      home,
      deps({ env: { HOME: machine }, enterprise: { fetch } }),
    )
    live.push(s)
    await s.opening
    // A window with no dialog: forget needs none.
    const l = await hello(s, { input_hook: true, client_capabilities: {} })
    expect(await call(l, 'telemetry', { word: 'forget' })).toMatchObject({ error: 'not-found', as: null })
    // Turned on outside the tool (it would ask), as the command line does.
    setTelemetry(join(machine, '.bag'), 'on', seededRng('forget'))
    const id = telemetryId(join(machine, '.bag')) as string
    const failed = await call(l, 'telemetry', { word: 'forget' })
    expect(failed).toMatchObject({ error: 'http-503', as: null })
    expect(String(failed.detail)).toContain('sending is off; ')
    expect(JSON.stringify(failed)).not.toMatch(/[0-9a-f]{32}/)
    expect(telemetryEraseId(join(machine, '.bag'))).toBe(id)
    status = 204
    const done = await call(l, 'telemetry', { word: 'forget' })
    expect(done).toEqual({
      lines: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        "telemetry forget: the erasure of this machine's id was accepted; telemetry off",
      ],
      as: null,
    })
    expect(JSON.stringify(done)).not.toMatch(/[0-9a-f]{32}/)
    expect(bodies).toEqual([JSON.stringify({ id }), JSON.stringify({ id })])
    expect(telemetryId(join(machine, '.bag'))).toBeNull()
  })

  it("forget through the tool: off is on disk before the endpoint is called; the failure's answer says retry, with no id", async () => {
    const machine = join(home, 'machine')
    const dir = join(machine, '.bag')
    let status = 502
    // The fake endpoint reads the consent file as it stands when the erasure is asked for.
    const seen: unknown[] = []
    const fetch = async (): Promise<Response> => {
      seen.push(JSON.parse(readFileSync(join(dir, 'telemetry.json'), 'utf8')))
      return new Response(null, { status })
    }
    const s = await Service.start(
      configOf(join(home, 'identities.json')),
      home,
      deps({ env: { HOME: machine }, enterprise: { fetch } }),
    )
    live.push(s)
    await s.opening
    const l = await hello(s, { input_hook: true, client_capabilities: {} })
    setTelemetry(dir, 'on', seededRng('forget-order'))
    const id = telemetryId(dir) as string
    const failed = await call(l, 'telemetry', { word: 'forget' })
    expect(failed).toMatchObject({
      error: 'http-502',
      detail:
        "sending is off; the erasure of this machine's id failed, so the id is kept: run forget again to retry",
      as: null,
    })
    expect(JSON.stringify(failed)).not.toContain(id)
    expect(seen).toEqual([{ version: 2, telemetry: 'off', erase: id }])
    expect([telemetryId(dir), telemetryEraseId(dir)]).toEqual([null, id])
    expect(await call(l, 'telemetry', { word: 'status' })).toEqual({
      lines: ['telemetry off reason=file choice=off id=none spool=0 sent=none'],
      as: null,
    })
    status = 204
    const done = await call(l, 'telemetry', { word: 'forget' })
    expect(seen).toEqual([
      { version: 2, telemetry: 'off', erase: id },
      { version: 2, telemetry: 'off', erase: id },
    ])
    expect(done).toEqual({
      lines: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        "telemetry forget: the erasure of this machine's id was accepted; telemetry off",
      ],
      as: null,
    })
    expect([telemetryId(dir), telemetryEraseId(dir)]).toEqual([null, null])
  })

  it("the created record: this connection's (label, address) pairs only, in no tool's answer, gone at its close", async () => {
    const s = await empty()
    const a = await hello(s, { input_hook: true })
    const conn = lastConn(s)
    const b = await hello(s, { input_hook: true })
    const other = lastConn(s)
    const pending = call(a, 'identity_create', { label: 'jane', relays: [RELAY] })
    await yes(a, { confirm: true })
    const address = ((await pending).lines as string[])[0] as string
    expect(createdHere(conn, 'jane', address)).toBe(true)
    // By the pair, never the label alone; and another window made nothing.
    expect(createdHere(conn, 'jane', P.bob.address)).toBe(false)
    expect(createdHere(other, 'jane', address)).toBe(false)
    // No tool's answer shows it: the window that made jane answers as the one that did not.
    for (const tool of ['status', 'identities'])
      expect([tool, await call(a, tool)]).toEqual([tool, await call(b, tool)])
    a.socket.destroy()
    await a.closed
    await until(() => s.connections.size === 1)
    expect(createdHere(conn, 'jane', address)).toBe(false)
  })
})

describe('a window keeps its identity through a restart (via restored)', () => {
  /** The address the service told a bound line in its service/bound notice: what a shim keeps in memory. */
  const addressOf = async (l: Line): Promise<string> =>
    ((await l.next((m) => m.method === 'service/bound')).params as Json).address as string

  /** Whether a service/unbound came on the line before it closed. */
  const unboundCame = (l: Line): Promise<boolean> =>
    Promise.race([l.next((m) => m.method === 'service/unbound').then(() => true), l.closed.then(() => false)])

  for (const reason of ['upgrade', 'stop'] as const)
    it(`after a drain for ${reason}: no service/unbound, and the next service restores the window, which acts as before`, async () => {
      const s = await start([['personal', P.alice]])
      const a = await bound(s)
      const address = await addressOf(a)
      await s.drain(reason)
      live.splice(live.indexOf(s), 1)
      expect(await unboundCame(a)).toBe(false)
      const n = await start([['personal', P.alice]], { lockRetryMs: 0 })
      const b = await hello(n, { input_hook: true })
      const r = await b.request('service/use', {
        label: 'personal',
        via: 'restored',
        address,
        subagent: false,
      })
      expect(r.result).toMatchObject({ bound: true, as: 'personal', granted: 'restored' })
      const st = await call(b, 'status')
      expect(st.as).toBe('personal')
      expect(st.notice).toEqual(['bag restarted; this window still acts as personal.'])
      expect(log.lines.filter((x) => x.event === 'bind-restored').map((x) => x.fields.label)).toEqual([
        'personal',
      ])
      expect(readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')).toContain(
        "a window's binding of personal restored after a service restart",
      )
    })

  it('a window that binds by dialog only (Codex: no input hook) is restored; one that can do neither is refused', async () => {
    const s = await start([['personal', P.alice]])
    const address = await addressOf(await bound(s))
    const codex = await hello(s, { host: 'codex', input_hook: false })
    expect(
      (await codex.request('service/use', { label: 'personal', via: 'restored', address })).result,
    ).toMatchObject({ granted: 'restored' })
    const neither = await hello(s, { host: 'other', input_hook: false, client_capabilities: {} })
    expect(
      codeOf(await neither.request('service/use', { label: 'personal', via: 'restored', address })),
    ).toBe('usage')
  })

  it('an identity removed and made again under the label does not come back, and the window is told why', async () => {
    const s = await start([['personal', P.alice]])
    const old = await addressOf(await bound(s))
    await s.drain()
    live.splice(live.indexOf(s), 1)
    const n = await start([['personal', P.carol]], { lockRetryMs: 0 })
    const b = await hello(n, { input_hook: true })
    expect(codeOf(await b.request('service/use', { label: 'personal', via: 'restored', address: old }))).toBe(
      'unknown-identity',
    )
    const st = await call(b, 'status')
    expect(st).toMatchObject({ bound: false, as: null })
    expect(st.note).toBe(
      `bag restarted and this window could not keep personal: it is no longer on this machine. ${NOT_BOUND}`,
    )
  })

  it('a lent identity is refused busy with the words; a second connection claiming a restore binds only itself', async () => {
    const s = await start([
      ['personal', P.alice],
      ['research', P.carol],
    ])
    const win = await bound(s, 'research')
    const research = await addressOf(win)
    const cli = await hello(s, { host: 'cli' })
    expect((await cli.request('service/lend', { label: 'personal', verb: 'pair' })).result).toBeDefined()
    const b = await hello(s, { input_hook: true })
    const alice = P.alice.keys.signing.address
    expect(
      codeOf(await b.request('service/use', { label: 'personal', via: 'restored', address: alice })),
    ).toBe('busy')
    expect((await call(b, 'status')).note).toBe(
      `bag restarted and this window could not keep personal: a bag command is using it; your user types use personal when it is done. ${NOT_BOUND}`,
    )
    // A connection that never bound research claims it: it gets its own binding, as the typed word would give it,
    // and the window that bound research is unchanged.
    const third = await hello(s, { input_hook: true })
    expect(
      (await third.request('service/use', { label: 'research', via: 'restored', address: research })).result,
    ).toMatchObject({ bound: true, as: 'research' })
    expect((await call(win, 'status')).as).toBe('research')
    expect((await call(third, 'status')).as).toBe('research')
  })
})

// An unbind the window or the agent's tool asked (design 2026-11-26, section 4.4): its audit lines, from the table's
// onEnd; a close writes none. And a tool unbind's note in a window still bound, on its next identity tool's result.
describe('an unbind is audited per identity; a close is not', () => {
  const unbinds = (): Json[] => log.lines.filter((x) => x.event === 'unbind').map((x) => x.fields as Json)
  const audit = (): string => readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')

  it("an unbind writes one service-log line and one policy line in the identity's log per label; a close writes none", async () => {
    const s = await start([['personal', P.alice]])
    const a = await bound(s)
    // The unit is open (its first act), so the identity's own log gets the line.
    expect((await call(a, 'status')).as).toBe('personal')
    const conn = lastConn(s)
    expect((await a.request('service/unbind', {})).result).toEqual({ unbound: ['personal'] })
    expect(unbinds()).toEqual([
      { label: 'personal', host: 'claude-code', connection: conn.handle, via: 'window' },
    ])
    const lines = audit()
      .split('\n')
      .filter((l) => l.includes('ended by unbind'))
    expect(lines).toHaveLength(1)
    const line = JSON.parse(lines[0] as string) as Json
    expect([line.event, line.decision, line.connection, JSON.parse(String(line.detail))]).toEqual([
      'policy',
      'route',
      conn.handle,
      { local: "a window's binding of personal ended by unbind", host: 'claude-code', via: 'window' },
    ])
    // The agent's tool (lane 2 calls the table so): via tool.
    const b = await bound(s)
    const other = lastConn(s)
    expect(s.table.unbind(other, 'personal', 'tool')).toEqual(['personal'])
    expect(unbinds().map((f) => [f.connection, f.via])).toEqual([
      [conn.handle, 'window'],
      [other.handle, 'tool'],
    ])
    // A close, and an unbind that ends nothing, write nothing.
    const c = await bound(s)
    expect((await b.request('service/unbind', { label: 'personal' })).result).toEqual({ unbound: [] })
    c.socket.destroy()
    await c.closed
    await until(() => s.connections.size === 2)
    expect(unbinds()).toHaveLength(2)
    expect(audit().split('ended by unbind').length - 1).toBe(2)
  })

  it("a switch is named in both logs: ended by a bind of work in its place, never as the person's unbind", async () => {
    const s = await start([
      ['personal', P.alice],
      ['work', P.carol],
    ])
    const a = await bound(s)
    expect((await call(a, 'status')).as).toBe('personal')
    const conn = lastConn(s)
    expect((await a.request('service/use', { label: 'work', via: 'typed' })).result).toMatchObject({
      as: 'work',
    })
    expect(unbinds()).toEqual([
      { label: 'personal', host: 'claude-code', connection: conn.handle, via: 'window', in_place: 'work' },
    ])
    expect(audit()).toContain("a window's binding of personal ended by a bind of work in its place")
    expect(audit()).not.toContain("a window's binding of personal ended by unbind")
  })

  it('after a tool unbind the next answer carries the notice once: on an identity tool of a window still bound', async () => {
    const s = await start([
      ['personal', P.alice],
      ['research', P.carol],
    ])
    const w = await hello(s, { input_hook: true })
    for (const [label, p] of [
      ['personal', P.alice],
      ['research', P.carol],
    ] as const)
      expect(
        (await w.request('service/use', { label, via: 'restored', address: p.keys.signing.address })).result,
      ).toMatchObject({ granted: 'restored' })
    const conn = lastConn(s)
    expect(s.table.unbind(conn, 'research', 'tool')).toEqual(['research'])
    const first = await call(w, 'status')
    expect(first.as).toBe('personal')
    const said = (first.notice as string[]).filter((l) => l.includes('unbound by'))
    expect(said).toEqual([
      expect.stringMatching(
        /^research unbound by an unbind call at \d\d:\d\d UTC: this window still acts as personal$/,
      ),
    ])
    const again = await call(w, 'status')
    expect(JSON.stringify(again.notice ?? [])).not.toContain('unbound by')
  })
})

describe('a restored Keychain identity opens at the window first act, never at the restore', () => {
  it('the restore reads no key; the first tool call opens it (one read) and acts', async () => {
    mkdirSync(join(home, 'keychain'), { recursive: true, mode: 0o700 })
    rmSync(join(home, 'keys', `${P.alice.name}.json`), { force: true })
    writeFileSync(
      join(home, 'keychain', `${P.alice.name}.json`),
      // A pointer as the keychain custody writes it (its address read without the item, so without a dialog).
      JSON.stringify({
        suite: SUITE,
        custody: 'keychain',
        address: P.alice.address,
        keychain: null,
        access: 'prompt',
      }),
      { mode: 0o600 },
    )
    const reads: string[] = []
    const s = await start([['personal', P.alice]], {
      openKeys: async (_h, name) => {
        reads.push(name)
        return opened(P.alice.keys)
      },
    })
    const b = await hello(s, { input_hook: true })
    const r = await b.request('service/use', { label: 'personal', via: 'restored', address: P.alice.address })
    expect(r.result, JSON.stringify(r)).toMatchObject({ bound: true, granted: 'restored' })
    await new Promise((x) => setTimeout(x, 30))
    expect(reads).toEqual([])
    expect((await call(b, 'status')).as).toBe('personal')
    expect(reads).toEqual(['alice'])
  })
})
