import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { type HostProcess, installClaude, migrate } from '@usebag/home'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { rereadOf, Service } from '../src/service.ts'
import { DIALOG_META } from '../src/socket.ts'
import {
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  RELAY,
  saveKeys,
  seededRng,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// A folder wired the old way (a per-folder server of an identity of the home), moved by home's real host migrate on
// the person's yes: the proposal it writes is read by the bag service at its start, so a new window in that folder has
// the identity preset in its bind dialog, unbound and asked nothing until a bind is asked.

type Json = Record<string, unknown>

let root: string
let home: string
const live: Service[] = []
const sockets: Socket[] = []

beforeEach(() => {
  root = mkdtempSync('/tmp/bpm-')
  home = join(root, 'h')
  mkdirSync(home, { mode: 0o700 })
})
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const s of live.splice(0)) await s.drain()
  rmSync(root, { recursive: true, force: true })
})

/** A line client of the service's socket after its hello: requests by id, other frames kept for next. */
async function connect(s: Service, cwd: string) {
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
  let id = 100
  const send = (m: Json) => socket.write(`${JSON.stringify(m)}\n`)
  const next = (pick: (m: Json) => boolean): Promise<Json> => {
    const i = seen.findIndex(pick)
    if (i >= 0) return Promise.resolve(seen.splice(i, 1)[0] as Json)
    return new Promise((resolve) => waiters.push({ pick, resolve }))
  }
  const request = (method: string, params: Json = {}): Promise<Json> => {
    const n = ++id
    send({ jsonrpc: '2.0', id: n, method, params })
    return next((m) => m.id === n)
  }
  const call = async (name: string, args: Json = {}): Promise<Json> => {
    const r = (await request('tools/call', { name, arguments: args })).result as {
      content?: { text: string }[]
    }
    return JSON.parse(r.content?.[0]?.text ?? '{}') as Json
  }
  const hello = await request('service/hello', {
    contract: 1,
    token: s.token.toString('hex'),
    host: 'claude-code',
    cwd,
    client_capabilities: { elicitation: { form: {} } },
    input_hook: true,
  })
  expect(hello.result, JSON.stringify(hello)).toBeDefined()
  return { send, next, call }
}

describe("host migrate's proposal, read by the bag service", () => {
  it('a folder migrated by the real host migrate presets its identity in a new window there, unbound and asked nothing', async () => {
    // carol, an identity of the home (its key file), wired into the folder the old way: its per-folder server.
    saveKeys(home, P.carol)
    mkdirSync(join(root, 'proj'))
    // The folder as a window reports its cwd, and as migrate records it: its real path.
    const dir = realpathSync(join(root, 'proj'))
    const proc: HostProcess = { node: '/n/node', execPath: '/n/node', pid: 4242, uid: process.getuid?.() }
    const mains = { cli: '/p/bag.js', mcp: '/p/bag-mcp.js', omp: '/p/bag-omp-wake.js', copied: null }
    installClaude(proc, mains, dir, { label: 'carol', home, relays: [RELAY] }, [])
    expect(existsSync(join(dir, '.mcp.json'))).toBe(true)

    // host migrate on the person's yes: the folder's server goes to the shim, carol into identities.json, the folder
    // into proposals.json.
    const clock = new FakeClock()
    const said: string[] = []
    const io = {
      say: (l: string) => said.push(l),
      warn: (l: string) => said.push(l),
      ask: async () => true,
      clock,
      rng: seededRng('migrate'),
      env: { HOME: join(root, 'user') },
      relay: () => {
        throw new Error('migrate reaches no relay')
      },
    }
    mkdirSync(io.env.HOME)
    const build = {
      packaged: false,
      version: '0.4.2',
      cli: '/p/bag.js',
      mcp: '/p/bag-mcp.js',
      omp: '/p/bag-omp-wake.js',
      shim: '/p/bag-shim.js',
    }
    await migrate(io, { home, given: [dir], sandbox: false, build, proc })
    const rows = JSON.parse(readFileSync(join(home, 'proposals.json'), 'utf8')).proposals as Json[]
    expect(rows).toMatchObject([{ folder: dir, host: 'claude-code', label: 'carol', from: 'migrate' }])
    expect(JSON.stringify(JSON.parse(readFileSync(join(dir, '.mcp.json'), 'utf8')))).not.toContain(
      'bag-mcp.js',
    )

    // The bag service started on that home, from the identities file migrate wrote.
    const file = join(home, 'identities.json')
    const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
    const relay = new MemoryRelay()
    const s = await Service.start(config, home, {
      clock,
      rng: seededRng('service'),
      relayFor: () => relay,
      records: fakeRecords(new Map()),
      timers: new ManualTimers(),
      pid: 4242,
      alive: () => false,
      log: new MemoryLog(),
      resubscribeDelayMs: () => 0,
      helloMs: 300,
      drainCallsMs: 200,
      returnWaitMs: 300,
      reread: rereadOf(file, config, home),
    })
    live.push(s)
    await s.opening

    // A new window in that folder: unbound, and nothing asks it until a bind is asked.
    const w = await connect(s, dir)
    let asked = false
    const first = w.next((m) => m.method === 'elicitation/create')
    void first.then(() => {
      asked = true
    })
    expect(await w.call('status')).toMatchObject({ as: null })
    await new Promise((r) => setTimeout(r, 100))
    expect(asked).toBe(false)
    // Its bind dialog, asked with no label, presets carol; the person still chooses.
    const use = w.call('use', {})
    const req = await first
    const params = req.params as Json
    expect(((params.requestedSchema as Json).properties as Json).identity).toMatchObject({ default: 'carol' })
    const handle = (params._meta as Json)[DIALOG_META]
    w.send({ jsonrpc: '2.0', id: req.id, result: { action: 'cancel', _meta: { [DIALOG_META]: handle } } })
    expect((await use).error).toBeDefined()
    expect(await w.call('status')).toMatchObject({ as: null })
    // A window in a folder under it is not preset.
    expect(s.table.propose({ cwd: join(dir, 'sub'), host: 'claude-code' } as never)).toBeNull()
  })
})
