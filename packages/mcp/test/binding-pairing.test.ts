import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, sep } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { ElicitRequestFormParams, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { isAddress, serializeRecord } from '@usebag/core'
import { keepAliveChoice, type Rng } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  Bindings,
  type Custody,
  FULL_QUESTION,
  FULL_TITLE,
  fullShown,
  NOT_BOUND,
  type ServiceConnection,
  serveBindings,
  TOOLS_BY_CUSTODY,
  unboundAddress,
} from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { KEEP_ALIVE_LAPSE_S, keepAliveOn } from '../src/keepalive.ts'
import { BUSY, BUSY_HERE, shortAddress } from '../src/pairing.ts'
import { START_SPREAD_S, startIdentities } from '../src/server.ts'
import {
  ACT_QUESTIONS,
  FULL_NOTE,
  RELAY_NOT_PLAIN,
  registerTools,
  SHORT_NOTE,
  TOO_MANY_RELAYS,
  type ToolContext,
} from '../src/tools.ts'
import {
  acceptFrom,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The pair tools and the use tool on bag service connections (binding.ts, pairing.ts): one --identities server stands
// in for the service's home (personal: alice's key, research: carol's), and each fake ServiceConnection gets its own
// MCP server whose tools carry it in ToolContext.connection, as service.ts registers them. Dialogs go to the
// connection's own elicit; nothing is shown through the stdio client.

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

  it('busy in the window that started the pairing carries a fresh resume that goes on with it; each token serves one call and dies at once on cancel', async () => {
    const a = await boundTo('personal')
    const opened = await a.call('pair_invite', { name: 'bob' })
    const busy = await a.call('pair_accept', { name: 'jane' })
    expect(busy.value).toEqual({
      error: 'busy',
      detail: BUSY_HERE('pair_invite'),
      resume: busy.value.resume,
      as: 'personal',
    })
    expect(busy.value.resume).not.toBe(opened.value.resume)
    expect((await a.call('pair_invite', { resume: opened.value.resume })).value).toMatchObject({
      error: 'usage',
    })
    // The fresh token waits the window and answers pending with the next one.
    const waiting = a.call('pair_invite', { resume: busy.value.resume })
    for (let i = 0; i < 400 && !timers.live().includes(25_000); i++)
      await new Promise((r) => setTimeout(r, 5))
    timers.fire((ms) => ms === 25_000)
    const pending = (await waiting).value
    expect(pending).toMatchObject({ pending: true, as: 'personal' })
    expect([typeof pending.resume, pending.resume === busy.value.resume]).toEqual(['string', false])
    expect((await a.call('pair_invite', { resume: busy.value.resume })).value).toMatchObject({
      error: 'usage',
    })
    expect((await a.call('pair_cancel', { resume: pending.resume })).value).toEqual({
      cancelled: true,
      was: 'invite',
      as: 'personal',
    })
    // Dead once its pairing ended.
    expect((await a.call('pair_invite', { resume: pending.resume })).value).toMatchObject({ error: 'usage' })
  })

  it("busy in another window of the identity carries no resume, and the starting window's token is refused there", async () => {
    const a = await boundTo('personal')
    await a.call('pair_invite', { name: 'bob' })
    const b = await boundTo('personal', { cwd: '/work/b' })
    const busy = await b.call('pair_invite', { name: 'jane' })
    expect(busy.value).toEqual({
      error: 'busy',
      detail: `${BUSY} (it runs in the claude-code window at /work/a)`,
      as: 'personal',
    })
    const here = await a.call('pair_accept', { name: 'jane' })
    expect(typeof here.value.resume).toBe('string')
    expect((await b.call('pair_invite', { resume: here.value.resume })).value).toMatchObject({
      error: 'usage',
      as: 'personal',
    })
    expect(b.dialogs).toEqual([])
    // The refused copy spent nothing: the token still works in its own window.
    expect((await a.call('pair_cancel', { resume: here.value.resume })).value).toMatchObject({
      cancelled: true,
    })
    // Another identity in a third window is not busy at all, and its token is its own.
    const c = await boundTo('research', { cwd: '/work/c' })
    const own = await c.call('pair_invite', { name: 'bob' })
    expect(own.value).toMatchObject({ invite_open: true, as: 'research' })
    expect(own.value.resume).not.toBe(here.value.resume)
  })

  it('pair_cancel asks nothing and its audit line names the reason and the window; a close is audited as close', async () => {
    const a = await boundTo('personal')
    await a.call('pair_invite', { name: 'bob' })
    a.person.push('hang')
    const asked = a.dialogs.length
    expect((await a.call('pair_cancel')).value).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
    expect(a.dialogs).toHaveLength(asked)
    const b = await boundTo('personal', { host: 'omp', cwd: '/work/b' })
    await b.call('pair_invite', { name: 'bob' })
    b.close()
    const path = join(root.config.home, 'state', root.config.as, 'audit.jsonl')
    const cancels = (): unknown[] =>
      readFileSync(path, 'utf8')
        .split('\n')
        .filter((l) => l.includes('"pair"') && l.includes('cancelled'))
        .map((l) => JSON.parse(JSON.parse(l).detail))
    for (let i = 0; i < 200 && cancels().length < 2; i++) await new Promise((r) => setTimeout(r, 5))
    expect(cancels()).toEqual([
      { step: 'refuse', code: 'cancelled', reason: 'cancel', window: 'claude-code /work/a' },
      { step: 'refuse', code: 'cancelled', reason: 'close', window: 'omp /work/b' },
    ])
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

describe('an omp window pairs only over its own registered link (0.4.2)', () => {
  it('an omp window with no link (here: no bag service) cannot pair: no-elicitation, and no consent folder anywhere', async () => {
    const a = await boundTo('personal', { host: 'omp', elicit: false, bridge: true })
    expect((await a.call('pair_accept', { name: 'bob' })).value).toMatchObject({ error: 'no-elicitation' })
    expect((await a.call('pair_invite', { name: 'bob' })).value).toMatchObject({ error: 'no-elicitation' })
    expect(existsSync(join(root.config.home, 'state', root.config.as, 'consent'))).toBe(false)
    const shim = join(root.config.home, 'run', 'shim')
    expect(existsSync(shim) ? readdirSync(shim).filter((f) => f.endsWith('.consent')) : []).toEqual([])
    a.close()
  })

  it('an omp window without the capability cannot pair either: no-elicitation', async () => {
    const a = await boundTo('personal', { host: 'omp', elicit: false })
    expect((await a.call('pair_accept', { name: 'bob' })).value).toMatchObject({ error: 'no-elicitation' })
  })
})

/**
 * Each tool with arguments that pass its input schema; none reaches a network but the memory relay, and none of the
 * home's acts changes anything (each refuses or is cancelled: its dialog is not answered).
 */
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
  ['identities', {}],
  ['identity_remove', { name: 'nobody' }],
  ['identity_relays', { relays: ['not a url'] }],
  ['keep_alive', { word: 'on' }],
  ['local_delivery', { word: 'status' }],
  ['unpair', { root: 'not-a-root' }],
  ['names', { verb: 'list' }],
  ['identity_create', { label: 'Not a label', relays: ['not a url'] }],
  ['telemetry', { word: 'status' }],
  ['host_wire', { host: 'claude-code', folder: '/nowhere/else' }],
  ['host_wire', { host: 'claude-code', folder: '/nowhere/else', action: 'unwire' }],
  ['service', {}],
  ['connect', { code: 'not-a-code' }],
  ['sign_in', { domain: 'example.com', instance: 'https://127.0.0.1' }],
  ['sign_out', {}],
  ['enterprise_status', {}],
]

describe('every tool on a service connection goes through the binding (H1)', () => {
  it('on an unbound connection status answers bound false, identities its short list; every other not-bound; none names a label', async () => {
    const w = await window()
    for (const [tool, args] of CALLS.filter(([t]) => t !== 'identities')) {
      const r = await w.call(tool, args)
      // identity_create and telemetry run unbound: here each refuses its argument (a bad label; no HOME) as usage.
      const want =
        tool === 'status'
          ? { bound: false, note: NOT_BOUND, as: null }
          : ['identity_create', 'telemetry', 'host_wire', 'service'].includes(tool)
            ? { error: 'usage', detail: expect.any(String), as: null }
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

describe('a window bound to no identity sees short addresses, unless its person said Yes in it', () => {
  const full = [P.alice.address, P.carol.address]
  const yes: Answer = { action: 'accept', content: { confirm: true } }
  const no: Answer = { action: 'decline' }
  /** The labels and addresses of an identities answer. */
  const listed = (v: Json): [unknown, unknown][] =>
    (v.identities as Json[]).map((i) => [i.label, i.address] as [unknown, unknown])

  it('(1) every surface of an unbound window names the home identities by the short form only', async () => {
    const w = await window()
    const r = await w.call('identities')
    expect(listed(r.value)).toEqual([
      ['personal', shortAddress(P.alice.address)],
      ['research', shortAddress(P.carol.address)],
    ])
    expect(r.value).toMatchObject({ full: false, note: SHORT_NOTE, as: null })
    // status, every refusal's detail and every result of every other tool: no full address of the home.
    const seen = [JSON.stringify(r.value)]
    for (const [tool, args] of CALLS) seen.push(JSON.stringify((await w.call(tool, args)).value))
    const server = new McpServer({ name: 'list', version: '0.0.0' })
    registerTools(server, { ...root, connection: w } as ToolContext)
    const [ca, cb] = InMemoryTransport.createLinkedPair()
    await server.connect(cb)
    const client = new Client({ name: 'list', version: '0.0.0' })
    await client.connect(ca)
    stops.push(async () => {
      await client.close()
      await server.close()
    })
    const { tools } = await client.listTools()
    // The tool text: no description carries an address as an example.
    for (const d of tools.map((t) => t.description ?? '')) seen.push(d)
    for (const text of seen) for (const a of full) expect(text).not.toContain(a)
    for (const d of tools.map((t) => t.description ?? '')) expect(d).not.toMatch(/ed25519:[0-9a-f]{8}/)
  })

  it('(2) the Yes is held by that window alone, never on disk, and ends with it; a No, no answer or no dialog keeps it short', async () => {
    const files = (): string[] => [root.config.home, join(tmp.dir, 'research')].flatMap((d) => walk(d))
    const before = files()
    const a = await window()
    const b = await window()
    a.person.push(yes)
    const shown = await a.call('identities', { full: true })
    expect(listed(shown.value)).toEqual([
      ['personal', P.alice.address],
      ['research', P.carol.address],
    ])
    expect(shown.value).toMatchObject({ full: true, note: FULL_NOTE, as: null })
    expect(a.dialogs).toEqual([FULL_QUESTION])
    // Held for that window: asked once; the next call shows them without a dialog. Another window stays short.
    expect((await a.call('identities')).value).toMatchObject({ full: true })
    expect(a.dialogs).toHaveLength(1)
    expect((await b.call('identities')).value).toMatchObject({ full: false })
    expect(listed((await b.call('identities')).value)[0]).toEqual(['personal', shortAddress(P.alice.address)])
    // Nothing on disk holds it: the homes' files are the same before and after.
    expect(files()).toEqual(before)
    // It ends with its window.
    expect(fullShown(a)).toBe(true)
    a.close()
    expect(fullShown(a)).toBe(false)
    // A No, a cancel, and a host with no dialog: still short, with why; nothing else turns it on.
    for (const [answer, why] of [
      [no, 'your user said No: the addresses stay short'],
      [{ action: 'cancel' }, 'the dialog was not answered: the addresses stay short'],
    ] as const) {
      const c = await window()
      c.person.push(answer)
      const r = await c.call('identities', { full: true })
      expect([r.value.full, r.value.note, listed(r.value)[1]]).toEqual([
        false,
        why,
        ['research', shortAddress(P.carol.address)],
      ])
    }
    const blind = await window({ elicit: false })
    const r = await blind.call('identities', { full: true })
    expect([r.value.full, String(r.value.note)]).toEqual([false, expect.stringContaining('stay short')])
    expect(blind.dialogs).toEqual([])
  })

  it('(3) its asks are limited per window in their own bucket; a refused ask shows nothing more', async () => {
    const w = await window()
    for (let i = 0; i < 3; i++) {
      w.person.push(no)
      expect((await w.call('identities', { full: true })).value).toMatchObject({ full: false })
    }
    const refused = await w.call('identities', { full: true })
    expect(refused.value).toMatchObject({ error: 'rate-limited', as: null })
    expect(refused.value.identities).toBeUndefined()
    expect(JSON.stringify(refused.value)).not.toMatch(/personal|research|ed25519:/)
    expect(w.dialogs).toHaveLength(3)
    // Its own act: the same window, bound, still asks another act's question.
    table.bindByWord(w, 'personal')
    await w.call('keep_alive', { word: 'on' })
    expect(w.dialogs).toHaveLength(4)
    // And another window has its own count.
    const other = await window()
    other.person.push(no)
    expect((await other.call('identities', { full: true })).value).toMatchObject({ full: false })
  })

  it('(4) two addresses with the same short form are told apart by label, and no short form is an address', async () => {
    const hex = (mid: string): string => `ed25519:01234567${mid.repeat(52)}cdef`
    const [x, y] = [hex('a'), hex('b')]
    const w = await window()
    expect([unboundAddress({ address: x }, w), unboundAddress({ address: y }, w)]).toEqual([
      'ed25519:01234567\u2026cdef',
      'ed25519:01234567\u2026cdef',
    ])
    expect(unboundAddress({ address: null }, w)).toBeNull()
    expect([isAddress(x), isAddress(shortAddress(x))]).toEqual([true, false])
    // The identities answer keeps one row per label, whatever the short form.
    expect(listed((await w.call('identities')).value).map(([l]) => l)).toEqual(['personal', 'research'])
    // A bound window's send of a short form is refused before anything is sent: it names no address or name.
    const bound = await boundTo('personal')
    const sent = await bound.call('send', { to: [shortAddress(P.carol.address)], type: 'chat.v1', body: 'x' })
    expect(sent.isError).toBe(true)
    expect(relay.published).toEqual([])
  })

  it('(5) a bound window and a server of its own see the full addresses, with no question', async () => {
    const w = await boundTo('personal')
    const r = await w.call('identities')
    expect(listed(r.value)).toEqual([
      ['personal', P.alice.address],
      ['research', P.carol.address],
    ])
    expect(r.value).toMatchObject({ full: true, as: 'personal' })
    expect(w.dialogs).toEqual([])
    // unboundAddress outside a window (no connection): the short form, never the full one by default.
    expect(unboundAddress({ address: P.alice.address }, undefined)).toBe(shortAddress(P.alice.address))
  })

  it('(6) after the Yes the result says what the model must not do with the full addresses', async () => {
    const w = await window()
    w.person.push(yes)
    const r = await w.call('identities', { full: true })
    expect(r.value.note).toBe(FULL_NOTE)
    expect(FULL_NOTE).toContain("never put one identity's address in a message sent as another")
  })
})

/**
 * Every file under `dir` but its identities' state folders (their stores and logs, which the running units write),
 * sorted: where a held Yes would have to be written to outlive its window.
 */
function walk(dir: string): string[] {
  if (!existsSync(dir)) return []
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name))
    .filter((f) => !f.slice(dir.length).startsWith(`${sep}state${sep}`))
    .sort()
}

describe("the home's acts in a bound window: asked there first, the CLI's words, then done", () => {
  const yes: Answer = { action: 'accept', content: { confirm: true } }

  it('keep_alive writes the word after the Yes; a No changes nothing', async () => {
    const w = await boundTo('personal')
    w.person.push(yes)
    // This home has no identities file of its own (the server's is beside it), so the table names the key: alice.
    expect((await w.call('keep_alive', { word: 'on' })).value).toEqual({
      lines: ['keep-alive alice on'],
      as: 'personal',
    })
    expect(w.dialogs[0]).toBe(ACT_QUESTIONS.keepAlive('personal', 'on').message)
    expect(keepAliveChoice(root.config.home, 'alice').keep).toBe(true)
    w.person.push({ action: 'decline' })
    expect((await w.call('keep_alive', { word: 'off' })).value).toMatchObject({
      error: 'declined',
      lines: [],
    })
    expect(keepAliveChoice(root.config.home, 'alice').keep).toBe(true)
  })

  it('local_delivery reads its status with no question, and asks for each change', async () => {
    const w = await boundTo('personal')
    const file = join(root.config.home, 'run', 'local.json')
    expect((await w.call('local_delivery', { word: 'status' })).value).toEqual({
      local_delivery: 'on',
      hidden: [],
      as: 'personal',
    })
    expect(w.dialogs).toEqual([])
    for (const [word, line] of [
      ['off', `local_delivery off: ${file}`],
      ['hide', `hidden alice: ${file}`],
      ['show', `shown alice: ${file}`],
      ['on', `local_delivery on: ${file}`],
    ] as const) {
      w.person.push(yes)
      const r = await w.call('local_delivery', {
        word,
        ...(word === 'hide' || word === 'show' ? { name: 'alice' } : {}),
      })
      expect([word, r.value]).toEqual([word, { lines: [line], as: 'personal' }])
    }
    expect(w.dialogs).toHaveLength(4)
    expect(w.dialogs[3]).toBe(ACT_QUESTIONS.local('on', 'personal', '').message)
    expect((await w.call('local_delivery', { word: 'hide' })).value).toMatchObject({ error: 'usage' })
    expect((await w.call('local_delivery', { word: 'hide', name: 'nobody' })).value).toMatchObject({
      error: 'ENOENT',
    })
    expect(w.dialogs).toHaveLength(4)
  })

  it('names lists with no question, and adds and forgets after the Yes; a bad name is refused before any question', async () => {
    const w = await boundTo('personal')
    expect((await w.call('names', { verb: 'list' })).value).toEqual({ names: [], as: 'personal' })
    expect(
      (await w.call('names', { verb: 'add', name: 'Bad Name', address: P.bob.address })).value,
    ).toMatchObject({
      error: 'bad-name',
    })
    expect((await w.call('names', { verb: 'add', name: 'bob' })).value).toMatchObject({ error: 'usage' })
    expect(w.dialogs).toEqual([])
    w.person.push(yes)
    expect((await w.call('names', { verb: 'add', name: 'bob', address: P.bob.address })).value).toEqual({
      lines: [`bob ${P.bob.address}`],
      as: 'personal',
    })
    expect(w.dialogs[0]).toBe(ACT_QUESTIONS.namesAdd('bob', P.bob.address, null).message)
    const listed = (await w.call('names', { verb: 'list' })).value.names as Json[]
    expect(listed.map((n) => [n.name, n.address])).toEqual([['bob', P.bob.address]])
    w.person.push(yes)
    expect(
      (await w.call('names', { verb: 'add', name: 'bob', address: P.carol.address, replace: true })).value,
    ).toEqual({
      lines: [`bob ${P.carol.address}`],
      as: 'personal',
    })
    expect(w.dialogs[1]).toBe(ACT_QUESTIONS.namesAdd('bob', P.carol.address, P.bob.address).message)
    w.person.push(yes)
    expect((await w.call('names', { verb: 'forget', name: 'bob' })).value).toEqual({
      lines: [`forgot bob ${P.carol.address}`],
      as: 'personal',
    })
    expect((await w.call('names', { verb: 'list' })).value).toEqual({ names: [], as: 'personal' })
    expect((await w.call('names', { verb: 'forget' })).value).toMatchObject({ error: 'usage' })
  })

  it('identity_relays and unpair refuse what is not theirs before any question', async () => {
    const w = await boundTo('personal')
    expect((await w.call('identity_relays', { relays: ['ftp://x'] })).value).toMatchObject({ error: 'usage' })
    expect((await w.call('unpair', { root: 'not-a-root' })).value).toMatchObject({ error: 'usage' })
    expect((await w.call('unpair', { root: P.alice.address })).value).toMatchObject({
      error: 'usage',
      detail: `${P.alice.address} is alice itself`,
    })
    expect(w.dialogs).toEqual([])
  })
})

describe("every home-act question fits omp's widget: a title of one line and a message of 3, each at most 60", () => {
  const fits = (what: string, q: { title: string; message: string }): void => {
    expect([what, q.title.includes('\n'), q.title.length <= 60], q.title).toEqual([what, false, true])
    const lines = q.message.split('\n')
    expect([what, lines.length <= 3, lines.every((l) => l.length <= 60)], q.message).toEqual([
      what,
      true,
      true,
    ])
  }
  // The longest of each: a 32-character label, a 64-character name, a long domain, three long relay URLs.
  const label = 'l'.repeat(32)
  const name = 'n'.repeat(64)
  const domain = `domain:${'d'.repeat(60)}.example`
  // The three longest relays a person might name: each host whole, or no question at all.
  const relays = [
    'https://relay-one.example.com',
    'https://relay-two.example.com',
    'https://relay-three.example.com:8443',
  ]
  const hosts = relays.map((r) => new URL(r).host)

  it('pins each question with the longest values, the full-address question included', () => {
    fits('identities full', { title: FULL_TITLE, message: FULL_QUESTION })
    // identity_relays: the three ordinary hosts fit the two lines after the question, each whole, never cut.
    const q = ACT_QUESTIONS.relays(label, hosts) as { title: string; message: string }
    fits('identity_relays', q)
    expect(q.message.split('\n').slice(1)).toEqual([
      'relay-one.example.com, relay-two.example.com,',
      'relay-three.example.com:8443',
    ])
    expect(q.message).not.toContain('...')
    // Too many to fit two lines whole: no question at all.
    expect(ACT_QUESTIONS.relays(label, [...hosts, ...hosts])).toBeNull()
    expect(ACT_QUESTIONS.relays(label, [`${'h'.repeat(61)}.example`])).toBeNull()
    for (const word of ['on', 'off', 'default'] as const)
      fits(`keep_alive ${word}`, ACT_QUESTIONS.keepAlive(label, word))
    for (const word of ['on', 'off', 'hide', 'show'] as const)
      fits(`local_delivery ${word}`, ACT_QUESTIONS.local(word, label, name))
    fits('unpair address', ACT_QUESTIONS.unpair(label, P.bob.address))
    fits('unpair domain', ACT_QUESTIONS.unpair(label, domain))
    fits('names add', ACT_QUESTIONS.namesAdd(name, P.bob.address, null))
    fits('names add replace', ACT_QUESTIONS.namesAdd(name, P.bob.address, P.carol.address))
    fits('names forget', ACT_QUESTIONS.namesForget(name, P.bob.address))
    // identity_create: the Yes publishes, so the question says so. The 32-character label breaks its line after the
    // label, leaving one line for the relays: two long relays fit whole; the three long ones do not, and refuse.
    const two = ACT_QUESTIONS.create(label, hosts.slice(0, 2)) as { title: string; message: string }
    fits('identity_create', two)
    expect(two).toEqual({
      title: `Yes: make ${label} and publish it`,
      message: [
        `Make ${label}`,
        'and publish it to these relays?',
        'relay-one.example.com, relay-two.example.com',
      ].join('\n'),
    })
    expect(ACT_QUESTIONS.create(label, hosts)).toBeNull()
    // The longest label that keeps the question on one line (23) takes the three long relays, each whole.
    const short = 'l'.repeat(23)
    const three = ACT_QUESTIONS.create(short, hosts) as { title: string; message: string }
    fits('identity_create 23', three)
    expect(three.message).toBe(
      [
        `Make ${short} and publish it to these relays?`,
        'relay-one.example.com, relay-two.example.com,',
        'relay-three.example.com:8443',
      ].join('\n'),
    )
    expect(ACT_QUESTIONS.create(label, [...hosts, ...hosts])).toBeNull()
    expect(ACT_QUESTIONS.create(label, [`${'h'.repeat(61)}.example`])).toBeNull()
    // host_wire and unwire: a folder of 60 (the longest shown whole) on its own line, the 32-character label, each host.
    const folder = `/${'f'.repeat(59)}`
    for (const host of ['claude-code', 'omp']) {
      fits(`host_wire ${host}`, ACT_QUESTIONS.wire(host, folder, label))
      fits(`host_wire typed ${host}`, ACT_QUESTIONS.wireTyped(host, folder))
      fits(`unwire ${host}`, ACT_QUESTIONS.unwire(host, folder, label))
    }
    expect(ACT_QUESTIONS.wire('claude-code', folder, label)).toEqual({
      title: 'Yes: wire claude-code in this folder',
      message: ['Every new window in', folder, `will propose ${label}.`].join('\n'),
    })
    expect(ACT_QUESTIONS.wireTyped('claude-code', folder)).toEqual({
      title: 'Type the label to wire claude-code in this folder',
      message: ['Every new window in', folder, 'will propose the identity you type here.'].join('\n'),
    })
    expect(ACT_QUESTIONS.unwire('omp', folder, label)).toEqual({
      title: 'Yes: unwire omp from this folder',
      message: ['Agent sessions in', folder, `will no longer act as ${label}.`].join('\n'),
    })
    // sign_out: the 32-character label and the longest organisation that fits whole on its own line (59); a longer
    // one refuses.
    const org = `${'o'.repeat(51)}.example`
    fits('sign_out', ACT_QUESTIONS.signOut(label, org) as { title: string; message: string })
    expect(ACT_QUESTIONS.signOut(label, org)).toEqual({
      title: `Yes: sign ${label} out for good`,
      message: [
        "Sign out and revoke this agent's key at",
        `${org}?`,
        'A new sign-in needs the organisation again.',
      ].join('\n'),
    })
    expect(ACT_QUESTIONS.signOut(label, `${'o'.repeat(52)}.example`)).toBeNull()
    expect(ACT_QUESTIONS.signOut(name, org)).toBeNull()
    // service: the login agent starts bag at every login; the Yes loads nothing.
    fits('service', ACT_QUESTIONS.service)
    expect(ACT_QUESTIONS.service).toEqual({
      title: 'Yes: start bag at every login',
      message: [
        'Write the login agent that starts the bag service',
        'at every login and after a crash? You then run',
        'one line in a terminal to load it.',
      ].join('\n'),
    })
    // telemetry on: what is sent and where.
    fits('telemetry on', ACT_QUESTIONS.telemetryOn)
    expect(ACT_QUESTIONS.telemetryOn).toEqual({
      title: 'Yes: turn telemetry on for this machine',
      message: [
        'Send one report a day to telemetry.bag.dev?',
        'It holds the version, the OS and counts, under a',
        'random id; never an address, a key or a message.',
      ].join('\n'),
    })
    // identity_remove, its three forms at the longest values: no held mail, one, and many (a 4-digit count).
    const removeAt = (held: number, line: string) => {
      const q = ACT_QUESTIONS.remove(name, P.bob.address, held)
      fits(`identity_remove held ${held}`, q)
      expect(q).toEqual({
        title: `Yes: remove ${'n'.repeat(25)}... and tell its relays`,
        message: [
          `Remove ${'n'.repeat(29)}... from this machine?`,
          `Address: ${shortAddress(P.bob.address)}`,
          line,
        ].join('\n'),
      })
    }
    removeAt(0, 'Its files move to a folder; its relays are told.')
    removeAt(1, 'Its files move to a folder; 1 held message is lost.')
    removeAt(9999, 'Its files move to a folder; 9999 held messages are lost.')
    fits('identity_remove no address', ACT_QUESTIONS.remove(name, null, 9999))
    expect(ACT_QUESTIONS.remove('research', P.carol.address, 0)).toEqual({
      title: 'Yes: remove research and tell its relays',
      message: [
        'Remove research from this machine?',
        `Address: ${shortAddress(P.carol.address)}`,
        'Its files move to a folder; its relays are told.',
      ].join('\n'),
    })
    // Each names its act and the identity it is about.
    expect(ACT_QUESTIONS.relays('personal', ['relay.test'])?.message).toContain('relays of personal')
    // keep_alive default states the service's rule (keepalive.ts:88-90, keepAliveOn, with KEEP_ALIVE_LAPSE_S at
    // keepalive.ts:80): on while bound, and for KEEP_ALIVE_LAPSE_S after the last close. A change of the rule breaks this.
    expect(ACT_QUESTIONS.keepAlive('personal', 'default').message).toContain(
      `is bound to it, and for ${KEEP_ALIVE_LAPSE_S / 3600} hours after.`,
    )
    const none = { keep: null, used_at: 1000 }
    expect([
      keepAliveOn({ keep: null, used_at: null }, 1000, true),
      keepAliveOn(none, 1000 + KEEP_ALIVE_LAPSE_S, false),
      keepAliveOn(none, 1000 + KEEP_ALIVE_LAPSE_S + 1, false),
    ]).toEqual([true, true, false])
    expect(ACT_QUESTIONS.keepAlive('personal', 'off').message).toContain('Keep-alive off for personal')
    expect(ACT_QUESTIONS.local('hide', 'personal', 'kim').message).toContain('Hide kim')
    expect(ACT_QUESTIONS.local('on', 'personal', '').message).toContain('Asked from personal')
    expect(ACT_QUESTIONS.unpair('personal', P.bob.address).message).toContain(shortAddress(P.bob.address))
  })

  it('refuses before any dialog: relays whose hosts do not fit, and a value with a line break or a control character', async () => {
    const w = await boundTo('personal')
    const long = (n: number) => `https://relay-${n}-${'x'.repeat(30)}.example.com`
    expect((await w.call('identity_relays', { relays: [long(1), long(2), long(3)] })).value).toMatchObject({
      error: 'usage',
      detail: TOO_MANY_RELAYS,
    })
    for (const r of [
      'https://user@relay.test',
      'https://relay.test/?x=1',
      'https://relay.test/#f',
      'https://u:p@relay.test',
    ])
      expect([r, (await w.call('identity_relays', { relays: [r] })).value]).toMatchObject([
        r,
        { error: 'usage', detail: RELAY_NOT_PLAIN },
      ])
    expect((await w.call('identity_relays', { relays: ['https://relay.test\n'] })).value).toMatchObject({
      error: 'usage',
    })
    expect(
      (await w.call('names', { verb: 'add', name: 'bob\nYes', address: P.bob.address })).value,
    ).toMatchObject({
      error: 'bad-name',
    })
    expect((await w.call('local_delivery', { word: 'hide', name: 'alice\u0007' })).value).toMatchObject({
      error: 'usage',
    })
    expect(w.dialogs).toEqual([])
  })

  it('shows each relay whole, by host and path, with http:// for a plain one, and never splits one across lines', async () => {
    const w = await boundTo('personal')
    // An identities file of this home, so the act reaches its question; the person does not answer it.
    writeFileSync(
      join(root.config.home, 'identities.json'),
      JSON.stringify({
        version: 1,
        identities: [{ label: 'personal', key: 'alice', home: root.config.home, relays: [RELAY] }],
      }),
      { mode: 0o600 },
    )
    const relaysOf = [
      'https://shared.example.com/bag/',
      'http://relay.test:8080',
      'https://relay-three.example.com:8443',
    ]
    await w.call('identity_relays', { relays: relaysOf })
    expect(w.dialogs).toHaveLength(1)
    const lines = (w.dialogs[0] as string).split('\n')
    expect(lines).toEqual([
      'Set the relays of personal to:',
      'shared.example.com/bag, http://relay.test:8080,',
      'relay-three.example.com:8443',
    ])
    // Every relay appears whole on one line.
    for (const r of ['shared.example.com/bag', 'http://relay.test:8080', 'relay-three.example.com:8443'])
      expect(lines.filter((l) => l.includes(r))).toHaveLength(1)
  })

  it('and every dialog a bound window is shown by these tools fits too', async () => {
    const w = await boundTo('personal')
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice, [P.bob.address])))
    for (const word of ['on', 'off', 'default'] as const) await w.call('keep_alive', { word })
    for (const word of ['on', 'off'] as const) await w.call('local_delivery', { word })
    await w.call('local_delivery', { word: 'hide', name: 'alice' })
    await w.call('unpair', { root: P.bob.address })
    await w.call('names', { verb: 'add', name: 'bob', address: P.bob.address })
    expect(w.dialogs).toHaveLength(8)
    for (const d of w.dialogs) fits('dialog', { title: '', message: d })
  })
})
