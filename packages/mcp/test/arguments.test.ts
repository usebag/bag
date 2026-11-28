import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { setTelemetry, systemRng } from '@usebag/edge'
import { unknownArguments } from '@usebag/enterprise-client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { rereadOf, Service } from '../src/service.ts'
import {
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
  type TestServer,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Every tool refuses an argument its schema does not define, before it does anything (tools.ts closeArguments): the
// MCP library's object schema would drop the key, and an optional key that narrows an act, once dropped, widens it
// (unbind without name ends every identity of the window). The refusal is usage, names the keys and the tool's own
// argument names from its schema, and never a value. The tools are taken from tools/list itself, so a tool registered
// without the check turns these red.

type Json = Record<string, unknown>

/** A value no refusal, log line or count may hold: values can be secrets (a code, a body). */
const MARKER = 'MARKER-7f3a-never-echoed'

/** A misspelling of `key` that no tool defines: its first two letters swapped, else doubled. */
const typo = (key: string, keys: readonly string[]): string => {
  const swapped = key.length > 1 ? `${key[1]}${key[0]}${key.slice(2)}` : `${key}${key}`
  return swapped === key || keys.includes(swapped) ? `${key}_x` : swapped
}

describe('unknownArguments: keys only, printable, cut, at most eight', () => {
  it('names one key and the tool argument names', () => {
    expect(unknownArguments('inbox', ['as', 'since'], ['cursor'])).toBe(
      'unknown argument "cursor": inbox takes as, since',
    )
    expect(unknownArguments('service', [], ['x'])).toBe('unknown argument "x": service takes no argument')
  })

  it('cuts each key to 64 characters, shows at most 8, counts the rest and the keys it cannot print', () => {
    const long = 'k'.repeat(100)
    const keys = [long, ...Array.from({ length: 9 }, (_, i) => `k${i}`), 'bad\u0000key']
    const text = unknownArguments('send', ['to'], keys)
    expect(text).toContain(JSON.stringify('k'.repeat(64)))
    expect(text).not.toContain('k'.repeat(65))
    expect(text).not.toContain('bad')
    expect(text).toMatch(/ and 3 more: send takes to$/)
    expect(unknownArguments('send', ['to'], ['\u0007'])).toBe(
      'unknown argument (1 not printable): send takes to',
    )
  })
})

describe('a stdio server: an unknown key is refused, and nothing is read', () => {
  let root: string
  let relay: MemoryRelay
  let clock: FakeClock
  let timers: ManualTimers
  const servers: TestServer[] = []

  beforeEach(() => {
    root = mkdtempSync('/tmp/bar-')
    relay = new MemoryRelay()
    clock = new FakeClock()
    timers = new ManualTimers()
  })
  afterEach(async () => {
    for (const s of servers.splice(0)) await s.close()
    rmSync(root, { recursive: true, force: true })
  })

  async function serverFor(p: Party, args: readonly string[], env?: Json): Promise<TestServer> {
    const home = join(root, p.name)
    saveKeys(home, p)
    await publishAddress(relay, p)
    const s = await testServer({
      home,
      name: p.name,
      relay,
      clock,
      timers,
      args,
      ...(env === undefined ? {} : { env: env as Record<string, string> }),
    })
    servers.push(s)
    return s
  }

  it('inbox with a guessed paging key: refused naming since and cursor, nothing marked read; then since reads it', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const alice = await serverFor(P.alice, [])
    for (const n of [1, 2, 3]) await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: n })
    await until('three arrive', () => bob.running.desk.counts().counts.unread === 3)
    const out = await bob.call('inbox', { offset: 24 })
    expect(out.isError).toBe(true)
    expect(out.value).toEqual({
      error: 'usage',
      detail: 'unknown argument "offset": inbox takes as, since, cursor, limit, thread, handed_off, newest',
    })
    expect(bob.running.desk.counts().counts.unread).toBe(3)
    const page = await bob.call('inbox', { since: 0 })
    expect((page.value.messages as unknown[]).length).toBe(3)
  })

  it('the value is never in the refusal, the log or the counts; counted as the tool with code usage', async () => {
    const HOME = join(root, 'machine')
    setTelemetry(join(HOME, '.bag'), 'on', systemRng)
    const carol = await serverFor(P.carol, [], { HOME })
    const out = await carol.call('inbox', { since: 0, cursro: MARKER, [MARKER]: 1 })
    expect(out.value.error).toBe('usage')
    expect(String(out.value.detail)).toBe(
      `unknown arguments "cursro", ${JSON.stringify(MARKER)}: inbox takes as, since, cursor, limit, thread, handed_off, newest`,
    )
    // A key is echoed (the caller wrote it as a name); the marker as a value never is.
    const valueOnly = await carol.call('connect', { code: 'x', coed: MARKER })
    expect(valueOnly.value.error).toBe('usage')
    expect(JSON.stringify(valueOnly.result)).not.toContain(MARKER)
    expect(carol.log.text()).not.toContain(MARKER)
    expect(carol.log.lines.at(-1)).toMatchObject({
      event: 'tool',
      fields: { tool: 'connect', ok: false, code: 'usage' },
    })
    const counts = (await carol.call('status')).value.telemetry_counts as Record<string, number>
    expect(counts).toMatchObject({ 'mcp inbox usage': 1, 'mcp connect usage': 1 })
    expect(JSON.stringify(counts)).not.toContain(MARKER)
    expect(JSON.stringify(counts)).not.toContain('cursro')
  })

  it('a known key with a wrong value is still the library refusal, as before; null for an optional key stays refused', async () => {
    const carol = await serverFor(P.carol, [])
    const wrong = await carol.call('inbox', { limit: 'ten' })
    expect(wrong.isError).toBe(true)
    expect(String(wrong.value.text)).toContain('Input validation error')
    const nulled = await carol.call('inbox', { thread: null })
    expect(nulled.isError).toBe(true)
    expect(String(nulled.value.text)).toContain('Input validation error')
  })
})

describe('the bag service: every listed tool refuses a misspelt key, and nothing happens', () => {
  let root: string
  let home: string
  let relay: MemoryRelay
  let clock: FakeClock
  let log: MemoryLog
  const live: Service[] = []
  const sockets: Socket[] = []

  beforeEach(() => {
    root = mkdtempSync('/tmp/bas-')
    home = join(root, 'h')
    mkdirSync(home, { mode: 0o700 })
    relay = new MemoryRelay()
    clock = new FakeClock()
    log = new MemoryLog()
  })
  afterEach(async () => {
    for (const s of sockets.splice(0)) s.destroy()
    for (const s of live.splice(0)) await s.drain()
    rmSync(root, { recursive: true, force: true })
  })

  async function start(ids: readonly [string, Party][]): Promise<Service> {
    const file = join(home, 'identities.json')
    const identities = ids.map(([label, p]) => {
      saveKeys(home, p)
      return { label, key: p.name, home, relays: [RELAY], trust_roots: [P.bob.address] }
    })
    writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
    for (const [, p] of ids) await publishAddress(relay, p)
    const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
    const s = await Service.start(config, home, {
      clock,
      rng: seededRng('arguments'),
      relayFor: () => relay,
      records: fakeRecords(new Map()),
      timers: new ManualTimers(),
      pid: 4242,
      alive: () => false,
      peer: async () => 'match',
      log,
      resubscribeDelayMs: () => 0,
      helloMs: 300,
      drainCallsMs: 200,
      returnWaitMs: 300,
      reread: rereadOf(file, config, home),
    })
    live.push(s)
    await s.opening
    return s
  }

  /** A window of the service over its socket: requests by id; every other frame it gets is kept in `seen`. */
  async function window(
    s: Service,
  ): Promise<{ request(method: string, params?: Json): Promise<Json>; seen: Json[] }> {
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((r) => socket.once('connect', () => r()))
    const seen: Json[] = []
    const waiting = new Map<number, (m: Json) => void>()
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        const m = JSON.parse(buf.slice(0, i)) as Json
        buf = buf.slice(i + 1)
        const w = waiting.get(m.id as number)
        if (w !== undefined && !('method' in m)) {
          waiting.delete(m.id as number)
          w(m)
        } else seen.push(m)
      }
    })
    let id = 100
    const request = (method: string, params: Json = {}): Promise<Json> => {
      const n = ++id
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: n, method, params })}\n`)
      return new Promise((resolve) => waiting.set(n, resolve))
    }
    const hello = await request('service/hello', {
      contract: 1,
      token: s.token.toString('hex'),
      host: 'claude-code',
      cwd: '/tmp/work',
      client_capabilities: { elicitation: { form: {} } },
      input_hook: true,
    })
    expect(hello.result, JSON.stringify(hello)).toBeDefined()
    return { request, seen }
  }

  /** Every file under `dir` with its size and mtime: a write anywhere in the home changes it. */
  const tree = (dir: string): Record<string, string> => {
    const out: Record<string, string> = {}
    for (const e of readdirSync(dir, { withFileTypes: true, recursive: true })) {
      const p = join(e.parentPath, e.name)
      if (e.isFile()) out[p] = `${statSync(p).size} ${statSync(p).mtimeMs}`
    }
    return out
  }

  it('generated: each optional key of every tool, misspelt, is refused usage with as; no write, send, read, dialog or unbind', async () => {
    const s = await start([
      ['personal', P.alice],
      ['work', P.carol],
    ])
    const w = await window(s)
    const used = await w.request('service/use', { label: 'personal', via: 'typed' })
    expect(used.result).toMatchObject({ bound: true, as: 'personal' })
    const listed = (await w.request('tools/list')).result as {
      tools: { name: string; inputSchema: { properties?: Json; required?: string[] } }[]
    }
    const names = listed.tools.map((t) => t.name)
    expect(names).toEqual(
      expect.arrayContaining(['inbox', 'send', 'unbind', 'use', 'local_delivery', 'names']),
    )
    // The desk's counts (unread among them), the home's files, the relay's records and the window's dialogs, before.
    const desk = () => s.unit('personal')?.desk?.counts().counts
    const before = {
      tree: tree(home),
      records: relay.records.size,
      desk: JSON.stringify(desk()),
      seen: w.seen.length,
    }
    let cases = 0
    for (const t of listed.tools) {
      const keys = Object.keys(t.inputSchema.properties ?? {})
      const optional = keys.filter((k) => !(t.inputSchema.required ?? []).includes(k))
      const misspelt = optional.length === 0 ? ['zz'] : optional.map((k) => typo(k, keys))
      for (const bad of misspelt) {
        const r = (await w.request('tools/call', { name: t.name, arguments: { [bad]: MARKER } })).result as {
          isError?: boolean
          content: { text: string }[]
        }
        const text = r.content[0]?.text ?? ''
        expect(r.isError, `${t.name} ${bad}`).toBe(true)
        expect(JSON.parse(text), `${t.name} ${bad}`).toEqual({
          error: 'usage',
          detail: `unknown argument ${JSON.stringify(bad)}: ${t.name} takes ${keys.length === 0 ? 'no argument' : keys.join(', ')}`,
          as: 'personal',
        })
        expect(text).not.toContain(MARKER)
        cases++
      }
    }
    expect(cases).toBeGreaterThan(names.length)
    // Nothing happened: no file written in the home, no record published, nothing read, no dialog, still bound.
    expect(tree(home)).toEqual(before.tree)
    expect(relay.records.size).toBe(before.records)
    expect(JSON.stringify(desk())).toBe(before.desk)
    expect(w.seen.slice(before.seen).filter((m) => m.method === 'elicitation/create')).toEqual([])
    expect(log.text()).not.toContain(MARKER)
    const status = (await w.request('tools/call', { name: 'status', arguments: {} })).result as {
      content: { text: string }[]
    }
    expect(JSON.parse(status.content[0]?.text ?? '{}')).toMatchObject({ as: 'personal' })
  })

  it('unbind with a misspelt name ends no identity (dropped, it would end every one)', async () => {
    const s = await start([['personal', P.alice]])
    const w = await window(s)
    await w.request('service/use', { label: 'personal', via: 'typed' })
    const r = (await w.request('tools/call', { name: 'unbind', arguments: { nmae: 'personal' } })).result as {
      content: { text: string }[]
    }
    expect(JSON.parse(r.content[0]?.text ?? '{}')).toEqual({
      error: 'usage',
      detail: 'unknown argument "nmae": unbind takes name',
      as: 'personal',
    })
    const status = (await w.request('tools/call', { name: 'status', arguments: {} })).result as {
      content: { text: string }[]
    }
    expect(JSON.parse(status.content[0]?.text ?? '{}')).toMatchObject({ as: 'personal' })
  })
})
