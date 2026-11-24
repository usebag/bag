import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import type { EdgeKeys } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { Service, type ServiceDeps } from '../src/service.ts'
import {
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  RELAY,
  saveKeys,
  seededRng,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The start's open queue: two event-loop turns
// before each identity, before the draining check, so that a greeting is answered between opens; a key-file identity
// still in the queue says so in plain words and status names it opening; a window's restore of such an identity
// binds and its first act runs once the identity is open.

type Json = Record<string, unknown>

let home: string
let relay: MemoryRelay
let log: MemoryLog
const live: Service[] = []
const sockets: Socket[] = []

beforeEach(() => {
  home = mkdtempSync('/tmp/bsy-')
  relay = new MemoryRelay()
  log = new MemoryLog()
})
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const s of live.splice(0)) await s.drain()
  rmSync(home, { recursive: true, force: true })
})

const IDS: readonly [string, Party][] = [
  ['a', P.alice],
  ['b', P.carol],
  ['c', P.jane],
]
const keysOf = new Map<string, EdgeKeys>(IDS.map(([, p]) => [p.name, p.keys]))

function config(ids: readonly [string, Party][] = IDS): ServerConfig {
  const file = join(home, 'identities.json')
  for (const [, p] of ids) saveKeys(home, p)
  const identities = ids.map(([label, p]) => ({
    label,
    key: p.name,
    home,
    relays: [RELAY],
    trust_roots: [P.bob.address],
  }))
  writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
  return parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
}

function deps(more: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    clock: new FakeClock(),
    rng: seededRng('service-start-yield'),
    relayFor: () => relay,
    records: fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4243,
    alive: () => false,
    peer: async () => 'match',
    log,
    resubscribeDelayMs: () => 0,
    helloMs: 3000,
    drainCallsMs: 200,
    returnWaitMs: 300,
    ...more,
  }
}

/** A key file's read as the service's reader answers it (openKeys stands in): its class, address and keys. */
const keyFile = (name: string) => {
  const keys = keysOf.get(name) as EdgeKeys
  return { custody: 'home-key' as const, address: keys.signing.address, keys }
}

/** Blocks this thread for `ms`, as a long audit check did inside an open. */
function block(ms: number): void {
  const until = performance.now() + ms
  while (performance.now() < until) {}
}

interface Line {
  request(method: string, params?: Json): Promise<Json>
  next(pick: (m: Json) => boolean): Promise<Json>
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
  let id = 0
  const next = (pick: (m: Json) => boolean): Promise<Json> => {
    const i = seen.findIndex(pick)
    if (i >= 0) return Promise.resolve(seen.splice(i, 1)[0] as Json)
    return new Promise((resolve) => waiters.push({ pick, resolve }))
  }
  return {
    next,
    request(method, params = {}) {
      const n = ++id
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: n, method, params })}\n`)
      return next((m) => m.id === n)
    },
  }
}

const helloOf = (s: Service, more: Json = {}): Json => ({
  contract: 1,
  token: s.token.toString('hex'),
  host: 'claude-code',
  cwd: '/tmp/work',
  client_capabilities: { elicitation: { form: {} } },
  input_hook: true,
  ...more,
})

async function call(l: Line, name: string, args: Json = {}): Promise<{ error: boolean; body: Json }> {
  const r = await l.request('tools/call', { name, arguments: args })
  const result = r.result as { content?: { text: string }[]; isError?: boolean } | undefined
  if (result === undefined) throw new Error(JSON.stringify(r))
  return { error: result.isError === true, body: JSON.parse(result.content?.[0]?.text ?? '{}') as Json }
}

async function until(test: () => boolean, ms = 5000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error('until: timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

/** An open that waits for its release: what each test holds an identity in the queue with. */
function gate(): { wait: Promise<void>; open: () => void } {
  let open = () => {}
  const wait = new Promise<void>((r) => {
    open = r
  })
  return { wait, open }
}

describe("the start's open queue", () => {
  it('answers a greeting between opens that each block the thread for a second, in under 2 s and before the last opens', async () => {
    const done: string[] = []
    const openKeys = async (_h: string, name: string) => {
      block(1000)
      done.push(name)
      return keyFile(name)
    }
    const t0 = performance.now()
    const s = await Service.start(config(), home, deps({ openKeys }))
    live.push(s)
    const l = await connect(s)
    const r = await l.request('service/hello', helloOf(s))
    const ms = performance.now() - t0
    // By turns of the event loop as well as by time: the answer came while an identity was still to open.
    const openedAtAnswer = done.length
    expect(r.result, JSON.stringify(r)).toBeDefined()
    expect(openedAtAnswer).toBeLessThan(3)
    expect(ms).toBeLessThan(2000)
    await s.opening
    expect(done).toEqual(['alice', 'carol', 'jane'])
  })

  it('opens nothing after a drain that begins in the turn before an identity (a stop mid-queue)', async () => {
    const reads: string[] = []
    let s: Service | null = null
    const openKeys = async (_h: string, name: string) => {
      reads.push(name)
      // The stop arrives in the next turn of the loop: after this open, before the queue's next identity.
      if (name === 'alice') setImmediate(() => void s?.drain('stop'))
      return keyFile(name)
    }
    s = await Service.start(config(), home, deps({ openKeys }))
    live.push(s)
    await s.opening
    await s.drain()
    expect(reads).toEqual(['alice'])
  })

  it('names an identity still in the queue opening, in plain words, then open', async () => {
    const g = gate()
    const openKeys = async (_h: string, name: string) => {
      if (name === 'alice') await g.wait
      return keyFile(name)
    }
    const s = await Service.start(config(), home, deps({ openKeys }))
    live.push(s)
    const unit = (label: string) => s.units.get(label)
    await until(() => unit('a')?.summary().state === 'opening')
    expect(unit('b')?.summary().state).toBe('opening')
    const l = await connect(s)
    await l.request('service/hello', helloOf(s))
    expect((await l.request('service/use', { label: 'a', via: 'typed' })).result).toMatchObject({
      bound: true,
    })
    const busy = await call(l, 'status')
    expect(busy.error).toBe(true)
    expect(busy.body).toMatchObject({
      error: 'busy',
      detail: 'the identity a is still opening: try again in a few seconds',
    })
    g.open()
    await s.opening
    await until(() => ['a', 'b', 'c'].every((x) => unit(x)?.summary().state === 'running'))
    const st = await call(l, 'status')
    expect(st.error).toBe(false)
    expect(st.body.as).toBe('a')
  })

  it('opens once an identity a window bound before the queue reached it', async () => {
    const g = gate()
    const reads: string[] = []
    const openKeys = async (_h: string, name: string) => {
      reads.push(name)
      if (name === 'alice') await g.wait
      return keyFile(name)
    }
    const s = await Service.start(config(), home, deps({ openKeys }))
    live.push(s)
    const l = await connect(s)
    await l.request('service/hello', helloOf(s))
    await l.request('service/use', { label: 'c', via: 'typed' })
    await until(() => s.units.get('c')?.opened !== null)
    g.open()
    await s.opening
    expect(reads.filter((r) => r === 'jane')).toHaveLength(1)
  })

  it("binds a window's restore of an identity still in the queue, and its first act runs once it is open", async () => {
    const g = gate()
    const openKeys = async (_h: string, name: string) => {
      if (name === 'alice') await g.wait
      return keyFile(name)
    }
    const s = await Service.start(config(), home, deps({ openKeys }))
    live.push(s)
    await until(() => s.units.get('a')?.summary().state === 'opening')
    const l = await connect(s)
    await l.request('service/hello', helloOf(s))
    const r = await l.request('service/use', {
      label: 'a',
      via: 'restored',
      address: P.alice.keys.signing.address,
    })
    expect(r.result, JSON.stringify(r)).toMatchObject({ bound: true, as: 'a', granted: 'restored' })
    const act = call(l, 'status')
    setTimeout(() => g.open(), 100)
    const st = await act
    expect(st.error, JSON.stringify(st.body)).toBe(false)
    expect(st.body.as).toBe('a')
    expect(st.body.notice).toEqual(['bag restarted; this window still acts as a.'])
  })
})
