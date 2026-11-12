import { existsSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { ElicitRequestFormParams, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import type { Rng } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  Bindings,
  bridgeOf,
  type Custody,
  NOT_BOUND,
  type ServiceConnection,
  serveBindings,
  TOOLS_BY_CUSTODY,
} from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { START_SPREAD_S, startIdentities } from '../src/server.ts'
import { registerTools, type ToolContext } from '../src/tools.ts'
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
  T0,
  tempDir,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The pair tools and the use tool on bag service connections (binding.ts, pairing.ts): one --identities server stands
// in for the service's home (personal: alice's key, research: carol's), and each fake ServiceConnection gets its own
// MCP server whose tools carry it in ToolContext.connection, as svc-core registers them. Dialogs go to the connection's
// own elicit; nothing is shown through the stdio client.

type Json = Record<string, unknown>
type Answer = ElicitResult | 'hang'

interface Window extends ServiceConnection {
  readonly dialogs: string[]
  readonly person: Answer[]
  close(): void
  call(tool: string, args?: Json): Promise<{ isError: boolean; value: Json }>
}

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let custody: Record<string, Custody>
let table: Bindings
let root: ToolContext
const stops: (() => Promise<void>)[] = []
let n = 0

const SPREAD = Math.floor(0.999_999_999 * START_SPREAD_S * 1000)
function high(label: string): Rng {
  const base = seededRng(label)
  return { bytes: (k) => (k === 4 ? new Uint8Array(4).fill(0xff) : base.bytes(k)) }
}

function id(label: string, p: Party): Json {
  const home = join(tmp.dir, label)
  saveKeys(home, p)
  return { label, key: p.name, home, relays: [RELAY], trust_roots: [P.bob.address], allow_delegate: true }
}

beforeEach(async () => {
  tmp = tempDir('binding-pairing')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  custody = { personal: 'home-key', research: 'home-key' }
  const file = join(tmp.dir, 'identities.json')
  const doc = { version: 1, identities: [id('personal', P.alice), id('research', P.carol)] }
  writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
  const running = await startIdentities(parseServerConfig(['--identities', file], {}) as ServerConfig, {
    clock,
    rng: high('svc'),
    relayFor: () => relay,
    records: fakeRecords(new Map()),
    timers,
    pid: 4242,
    alive: () => false,
    log: new MemoryLog(),
    resubscribeDelayMs: () => 0,
    pairPollMs: 2,
    mono: (
      (t) => () =>
        (t += 1000)
    )(0),
  })
  timers.fire((ms) => ms === SPREAD)
  await running.ready
  stops.push(() => running.stop())
  root = (running.units.get('personal') as { ctx: ToolContext }).ctx
  const home = {
    home: root.config.home,
    identities: () =>
      Object.entries(custody).map(([label, c]) => ({ label, address: null, custody: c as Custody })),
    draining: false,
  }
  table = new Bindings(home, {
    mono: (
      (t) => () =>
        (t += 1000)
    )(0),
    custody: (l) => custody[l] ?? null,
  })
  serveBindings(table, root.config.home)
})

afterEach(async () => {
  clock.t += 10_000
  await new Promise((r) => setTimeout(r, 30))
  for (const s of stops.splice(0)) await s()
  tmp.cleanup()
})

/** A service connection with its own MCP server and client; its person answers its dialogs (the address question empty). */
async function window(
  o: { host?: string; cwd?: string; elicit?: boolean; hook?: boolean; bridge?: boolean } = {},
): Promise<Window> {
  const closers = new Set<() => void>()
  const w = {
    handle: (n++).toString(16).padStart(32, 'f'),
    host: o.host ?? 'claude-code',
    cwd: o.cwd ?? '/work/a',
    capabilities: {
      elicitation: o.elicit ?? true,
      inputHook: o.hook ?? true,
      raw: o.bridge === true ? { experimental: { 'bag.dev/consent-bridge': {} } } : {},
    },
    closed: false,
    dialogs: [] as string[],
    person: [] as Answer[],
    onClose(fn: () => void) {
      closers.add(fn)
      return () => closers.delete(fn)
    },
    async elicit(params: ElicitRequestFormParams): Promise<ElicitResult> {
      w.dialogs.push(params.message)
      if (Object.keys(params.requestedSchema.properties).join() === 'address')
        return { action: 'accept', content: {} }
      const a = w.person.shift() ?? { action: 'cancel' }
      return a === 'hang' ? new Promise(() => {}) : a
    },
    notify() {},
    close() {
      ;(w as { closed: boolean }).closed = true
      for (const f of [...closers]) f()
    },
  } as unknown as Window
  const server = new McpServer({ name: 'svc', version: '0.0.0' })
  registerTools(server, { ...root, connection: w } as ToolContext)
  const [a, b] = InMemoryTransport.createLinkedPair()
  await server.connect(b)
  const client = new Client({ name: 'shim', version: '0.0.0' })
  await client.connect(a)
  stops.push(async () => {
    await client.close()
    await server.close()
  })
  ;(w as { call: Window['call'] }).call = async (tool, args = {}) => {
    const r = await client.callTool({ name: tool, arguments: args })
    const text = (r.content as { text: string }[])[0]?.text ?? '{}'
    if (!text.startsWith('{')) throw new Error(`${tool}: ${text}`)
    return { isError: r.isError === true, value: JSON.parse(text) as Json }
  }
  return w
}

/** A window bound to `label` by the typed word. */
async function boundTo(label: string, o: Parameters<typeof window>[0] = {}): Promise<Window> {
  const w = await window(o)
  table.bindByWord(w, label)
  return w
}

describe('results carry as', () => {
  it("a bound window's pair results carry as; an unbound one answers not-bound, as null, naming no label", async () => {
    const a = await boundTo('personal')
    const opened = await a.call('pair_invite', { name: 'bob' })
    expect(opened.value).toMatchObject({ invite_open: true, as: 'personal' })
    const loose = await window()
    const r = await loose.call('pair_invite', { name: 'bob' })
    expect(r.value).toEqual({ error: 'not-bound', detail: NOT_BOUND, as: null })
    expect(JSON.stringify(r.value)).not.toMatch(/personal|research/)
  })
})

describe('the use tool', () => {
  it('only opens the bind dialog: a dialog that did not reach the person binds nothing; a Yes binds', async () => {
    const w = await window({ hook: false })
    const missed = await w.call('use', { name: 'personal' })
    expect(missed.value).toMatchObject({ error: 'cancelled', as: null })
    expect(table.state(w)).toBe('unbound')
    expect((await w.call('pair_cancel')).value).toMatchObject({ error: 'not-bound' })
    w.person.push({ action: 'accept', content: { bind: true } })
    expect((await w.call('use', { name: 'personal' })).value).toEqual({
      bound: true,
      as: 'personal',
      granted: 'dialog',
    })
    expect(w.dialogs).toHaveLength(2)
  })
})

describe('pairing per identity and per connection', () => {
  it('dialogs go only to the window that started the pairing; another window of the same identity sees none', async () => {
    const a = await boundTo('personal')
    const b = await boundTo('personal', { cwd: '/work/b' })
    await a.call('pair_invite', { name: 'bob' })
    expect(a.dialogs[0]).toMatch(/make a code for a peer/)
    expect(b.dialogs).toEqual([])
  })

  it('busy is per identity and names the window by host kind and cwd, never its handle; two identities pair at once', async () => {
    const a = await boundTo('personal')
    expect((await a.call('pair_invite', { name: 'bob' })).value).toMatchObject({ invite_open: true })
    const b = await boundTo('personal', { host: 'omp', cwd: '/work/b' })
    const busy = await b.call('pair_invite', { name: 'jane' })
    expect(busy.value).toMatchObject({ error: 'busy', as: 'personal' })
    expect(busy.value.detail).toContain('the claude-code window at /work/a')
    expect(busy.value.detail).not.toContain(a.handle)
    const c = await boundTo('research', { cwd: '/work/c' })
    expect((await c.call('pair_invite', { name: 'bob' })).value).toMatchObject({
      invite_open: true,
      as: 'research',
    })
  })

  it('pair_cancel and resume work only from the window that started it; another gets a refusal naming that window', async () => {
    const a = await boundTo('personal')
    const opened = await a.call('pair_invite', { name: 'bob' })
    const b = await boundTo('personal', { cwd: '/work/b' })
    const refused = await b.call('pair_cancel')
    expect(refused.value).toMatchObject({ error: 'not-authorized', as: 'personal' })
    expect(refused.value.detail).toContain('the claude-code window at /work/a')
    expect((await b.call('pair_invite', { resume: opened.value.resume })).value).toMatchObject({
      error: 'usage',
    })
    expect((await a.call('pair_cancel')).value).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
  })

  it("a window's close ends its pairing as pair_cancel does: the identity can pair again from another window", async () => {
    const a = await boundTo('personal')
    await a.call('pair_invite', { name: 'bob' })
    a.close()
    const b = await boundTo('personal', { cwd: '/work/b' })
    let r = await b.call('pair_invite', { name: 'bob' })
    for (let i = 0; i < 50 && r.value.error === 'busy'; i++) {
      await new Promise((s) => setTimeout(s, 10))
      r = await b.call('pair_invite', { name: 'bob' })
    }
    expect(r.value).toMatchObject({ invite_open: true, as: 'personal' })
  })

  it('a grant binding gets no pair tool: not-authorized, re-checked on the call', async () => {
    const a = await boundTo('research')
    custody.research = 'grant'
    expect((await a.call('pair_invite', { name: 'bob' })).value).toMatchObject({
      error: 'not-authorized',
      as: 'research',
    })
  })
})

describe('the omp consent bridge per connection', () => {
  it("writes a pairing's consent request only into the bridge of the window that started it", async () => {
    const a = await boundTo('personal', { host: 'omp', elicit: false, bridge: true })
    // As svc-core does at the hello: the service's own folder, whose path the hello reply carries.
    const dir = bridgeOf(a, root.config.home) as string
    writeFileSync(
      join(dir, '.bridge'),
      JSON.stringify({ v: 1, pid: process.pid, at: new Date(T0 * 1000).toISOString() }),
    )
    expect((await a.call('pair_accept', { name: 'bob' })).value).toMatchObject({
      asked: true,
      as: 'personal',
    })
    await until('the request', () => readdirSync(dir).some((f) => f.endsWith('.json')))
    expect(existsSync(join(root.config.home, 'state', root.config.as, 'consent'))).toBe(false)
    a.close()
  })

  it('an omp window without a bridge of its own cannot pair: no-elicitation', async () => {
    const a = await boundTo('personal', { host: 'omp', elicit: false })
    expect((await a.call('pair_accept', { name: 'bob' })).value).toMatchObject({ error: 'no-elicitation' })
  })
})

describe('every tool on a service connection goes through the binding (H1)', () => {
  /** Each of the sixteen tools with arguments that pass its input schema; none reaches a network but the memory relay. */
  const CALLS: [string, Json][] = [
    ['send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' }],
    ['inbox', {}],
    ['wait', { timeout_s: 0 }],
    ['delegate', { to: P.bob.address, caveats: ['type == "chat.v1"'], exp: '+60' }],
    ['ask', { to: P.bob.address, body: 'q', timeout_s: 0 }],
    ['handoff', { to: P.bob.address, threads: ['a'.repeat(64)] }],
    ['status', {}],
    ['facts', {}],
    ['lookup', { address: P.bob.address }],
    ['receipts', { id: 'x' }],
    ['pair_invite', { name: 'bob' }],
    ['pair_accept', { name: 'carol' }],
    ['pair_cancel', {}],
    ['connect', { code: 'not-a-code' }],
    ['sign_in', { domain: 'example.com', instance: 'https://127.0.0.1' }],
    ['enterprise_status', {}],
  ]

  it('on an unbound connection status answers bound false; the other fifteen answer not-bound; none names a label', async () => {
    const w = await window()
    for (const [tool, args] of CALLS) {
      const r = await w.call(tool, args)
      const want =
        tool === 'status'
          ? { bound: false, note: NOT_BOUND, as: null }
          : { error: 'not-bound', detail: NOT_BOUND, as: null }
      expect([tool, r.value]).toEqual([tool, want])
      expect(JSON.stringify(r.value)).not.toMatch(/personal|research|ed25519:/)
    }
  })

  for (const c of ['home-key', 'keychain', 'agent', 'grant'] as Custody[])
    it(`a ${c} binding: the tools of its list act with as stamped, the others answer not-authorized`, async () => {
      custody.personal = c
      const w = await boundTo('personal')
      for (const [tool, args] of CALLS) {
        const r = await w.call(tool, args)
        expect([tool, r.value.as]).toEqual([tool, 'personal'])
        if (TOOLS_BY_CUSTODY[c].includes(tool))
          expect([tool, r.value.error]).not.toEqual([tool, 'not-authorized'])
        else expect([tool, r.value.error]).toEqual([tool, 'not-authorized'])
      }
      if (TOOLS_BY_CUSTODY[c].includes('pair_cancel')) await w.call('pair_cancel')
    })
})
