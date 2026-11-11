import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { createServer, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { addTelemetryCounts, RELAY_TURNS, SqliteStore, setTelemetry, systemRng } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runShell } from '../src/chain.ts'
import { type Config, ConfigError, parseConfig, USAGE } from '../src/config.ts'
import { realTimers } from '../src/desk.ts'
import { inboxUri } from '../src/resource.ts'
import {
  HELD_RETRY_MS,
  lockHost,
  PARENT_CHECK_MS,
  type ProcessIo,
  processIo,
  serve,
  startServer,
  watchedParents,
} from '../src/server.ts'
import {
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'
import { frames, StreamClientTransport } from './support/streams.ts'

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay

beforeEach(async () => {
  tmp = tempDir('server')
  relay = new MemoryRelay()
  saveKeys(tmp.dir, P.alice)
  saveKeys(tmp.dir, P.bob)
  await publishAddress(relay, P.alice)
  await publishAddress(relay, P.bob)
})

afterEach(() => {
  tmp.cleanup()
})

interface TestIo extends ProcessIo {
  readonly stdin: PassThrough
  readonly stdout: PassThrough
  readonly out: Buffer[]
  readonly err: string[]
  readonly emitter: EventEmitter
  readonly fakeConsole: Record<'log' | 'info' | 'debug' | 'warn' | 'error', (...a: unknown[]) => void>
}

function io(argv: readonly string[], over: Partial<ProcessIo> = {}): TestIo {
  const stdin = new PassThrough()
  const stdout = new PassThrough()
  const out: Buffer[] = []
  stdout.on('data', (chunk: Buffer) => out.push(chunk))
  const err: string[] = []
  const emitter = new EventEmitter()
  const fakeConsole = { log: () => {}, info: () => {}, debug: () => {}, warn: () => {}, error: () => {} }
  return {
    argv,
    env: {},
    stdin,
    stdout,
    stderr: { write: (t: string) => err.push(t) },
    clock: new FakeClock(),
    rng: seededRng('serve'),
    relay: () => relay,
    timers: realTimers,
    pid: 4242,
    alive: () => false,
    signals: emitter as unknown as ProcessIo['signals'],
    console: fakeConsole,
    out,
    err,
    emitter,
    fakeConsole,
    ...over,
  } as TestIo
}

const args = (...more: string[]): string[] => ['--as', 'alice', '--dir', tmp.dir, '--relay', RELAY, ...more]
const errLines = (t: TestIo): Record<string, unknown>[] =>
  t.err
    .join('')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as Record<string, unknown>)

describe('serve: the server on stdio', () => {
  it('refuses a bad flag with exit 2 and one JSON line on stderr, writing nothing to stdout', async () => {
    const t = io(['--relay', RELAY])
    expect(await serve(t)).toBe(2)
    expect(Buffer.concat(t.out).length).toBe(0)
    expect(errLines(t)).toEqual([
      {
        ts: expect.any(String),
        level: 'error',
        event: 'start',
        code: 'usage',
        detail: '--as <key name> or --session auto|auto:codex|<name> is required',
      },
    ])
  })

  it("sends the machine's due telemetry day once at start through its io's fetch, and none without one", async () => {
    const home = join(tmp.dir, 'machine')
    setTelemetry(join(home, '.bag'), 'on', systemRng)
    // T0 is 2027-01-15 08:00 UTC, so 2027-01-14 is due.
    addTelemetryCounts({ HOME: home }, '2027-01-14', { pairing: { ok: 1 } })
    const bodies: string[] = []
    const fetch = (async (_url: unknown, init?: RequestInit) => {
      bodies.push(String(init?.body))
      return new Response(null, { status: 204 })
    }) as typeof globalThis.fetch
    const without = io(args(), { env: { HOME: home } })
    const first = serve(without)
    await until('the server started', () =>
      errLines(without).some((l) => l.event === 'start' && l.level === 'info'),
    )
    without.stdin.end()
    expect(await first).toBe(0)
    expect(bodies).toEqual([])
    const t = io(args(), { env: { HOME: home }, fetch })
    const done = serve(t)
    await until('the report was sent', () => bodies.length === 1)
    t.stdin.end()
    expect(await done).toBe(0)
    expect(JSON.parse(bodies[0] as string)).toMatchObject({ date: '2027-01-14', pairing: { ok: 1 } })
  })

  it('prints the usage on stderr for --help and exits 0', async () => {
    const t = io(['--help'])
    expect(await serve(t)).toBe(0)
    expect([t.err.join(''), Buffer.concat(t.out).length]).toEqual([`${USAGE}\n`, 0])
  })

  it('exits 1 when the chain command of a session fails, naming chain-cmd-failed and not the command', async () => {
    const t = io(
      [
        '--as',
        'alice',
        '--dir',
        tmp.dir,
        '--relay',
        RELAY,
        '--chain-cmd',
        'helper --token s3cr3t',
        '--mailbox',
        P.bob.address,
      ],
      {
        run: async () => {
          throw new ConfigError('chain-cmd-failed', 'it exited with 1')
        },
      },
    )
    expect(await serve(t)).toBe(1)
    expect(errLines(t)).toMatchObject([
      { level: 'error', event: 'start', code: 'chain-cmd-failed', detail: 'it exited with 1' },
    ])
    expect(t.err.join('')).not.toContain('s3cr3t')
  })

  it("exits 1 with busy while another writer holds the identity's store (the edge's writer lock)", async () => {
    const state = join(tmp.dir, 'state', 'alice')
    mkdirSync(state, { recursive: true, mode: 0o700 })
    const other = new SqliteStore(join(state, 'edge.sqlite'))
    try {
      const t = io(args())
      expect(await serve(t)).toBe(1)
      expect(errLines(t)).toMatchObject([{ level: 'error', event: 'start', code: 'busy' }])
    } finally {
      other.close()
    }
    // The server let go of its own lock, so it starts once the other writer has closed.
    const t = io(args())
    const done = serve(t)
    await until('the server started', () =>
      errLines(t).some((l) => l.event === 'start' && l.level === 'info'),
    )
    t.stdin.end()
    expect(await done).toBe(0)
  })

  it('a second server of the same fixed identity stays up: status says held_by, every other tool the held-by error, and it takes over once the holder ends', async () => {
    const first = io(args('--trust-root', P.bob.address))
    const done = serve(first)
    await until('the first server started', () =>
      errLines(first).some((l) => l.event === 'start' && l.level === 'info'),
    )
    const timers = new ManualTimers()
    const second = io(args('--trust-root', P.bob.address), {
      pid: 4343,
      alive: (p) => p === 4242,
      timers,
      records: fakeRecords(new Map()),
    })
    const secondDone = serve(second)
    const client = new Client({ name: 'omp', version: '0.0.0' })
    await client.connect(new StreamClientTransport(second.stdin, second.stdout))
    const held =
      /^bag: the identity alice is held by another session \(pid 4242, started \S+\) in .+; close that session or run bag in its own folder$/
    const status = await client.callTool({ name: 'status', arguments: {} })
    expect(status.structuredContent).toMatchObject({
      held: true,
      held_by: { pid: 4242, started_at: expect.any(String), cwd: expect.any(String), host: null },
    })
    expect((status.structuredContent as { message: string }).message).toMatch(held)
    const inbox = await client.callTool({ name: 'inbox', arguments: {} })
    expect(inbox.isError).toBe(true)
    expect(inbox.structuredContent).toMatchObject({ error: 'busy', detail: expect.stringMatching(held) })
    expect(errLines(second).filter((l) => l.event === 'held')).toHaveLength(1)
    // The first server's host note: it wrote started_at, cwd and ppid beside its pid.
    const lock = JSON.parse(readFileSync(join(tmp.dir, 'state', 'alice', 'mcp.lock'), 'utf8'))
    expect(lock).toMatchObject({ pid: 4242, started_at: expect.any(String), cwd: process.cwd() })
    // The retry while the holder lives changes nothing; after it ends, the next retry takes the identity over.
    timers.fire((ms) => ms === HELD_RETRY_MS)
    await until('the retry ran', () => timers.live().includes(HELD_RETRY_MS))
    first.stdin.end()
    expect(await done).toBe(0)
    timers.fire((ms) => ms === HELD_RETRY_MS)
    await until('the second took over', () => errLines(second).some((l) => l.event === 'takeover'))
    expect(JSON.parse(readFileSync(join(tmp.dir, 'state', 'alice', 'mcp.lock'), 'utf8'))).toMatchObject({
      pid: 4343,
      host: 'omp',
    })
    const after = await client.callTool({ name: 'status', arguments: {} })
    expect(after.structuredContent).toMatchObject({ address: P.alice.address })
    second.stdin.end()
    expect(await secondDone).toBe(0)
  })

  it('an orphaned server (its parent pid changed, stdin still open) logs one line, exits 0 and releases its lock', async () => {
    let parent = 900
    const timers = new ManualTimers()
    const t = io(args('--trust-root', P.bob.address), { timers, parentPid: () => parent })
    const done = serve(t)
    await until('the server started', () =>
      errLines(t).some((l) => l.event === 'start' && l.level === 'info'),
    )
    const lock = join(tmp.dir, 'state', 'alice', 'mcp.lock')
    expect(existsSync(lock)).toBe(true)
    timers.fire((ms) => ms === PARENT_CHECK_MS)
    expect(errLines(t).some((l) => l.event === 'orphaned')).toBe(false)
    parent = 1
    await until('the check re-armed', () => timers.live().includes(PARENT_CHECK_MS))
    timers.fire((ms) => ms === PARENT_CHECK_MS)
    expect(await done).toBe(0)
    expect(errLines(t).filter((l) => l.event === 'orphaned')).toEqual([
      { ts: expect.any(String), level: 'warn', event: 'orphaned', parent: 900, now: 1 },
    ])
    expect(existsSync(lock)).toBe(false)
  })

  it('names the host kind for the lock from the MCP client name', () => {
    expect(
      ['omp-coding-agent', 'claude-code', 'codex-mcp-client', 'zed', undefined].map((n) => lockHost(n)),
    ).toEqual(['omp', 'claude-code', 'codex', 'other', 'other'])
  })

  it('a held server: a takeover that fails other than held is tried again with a longer wait; stop cancels the retry; its inbox resource reads empty', async () => {
    const first = io(args('--trust-root', P.bob.address))
    const done = serve(first)
    await until('the first server started', () =>
      errLines(first).some((l) => l.event === 'start' && l.level === 'info'),
    )
    const timers = new ManualTimers()
    const second = io(args('--trust-root', P.bob.address, '--push', 'resource'), {
      pid: 4343,
      alive: (p) => p === 4242,
      timers,
      records: fakeRecords(new Map()),
    })
    const secondDone = serve(second)
    const client = new Client({ name: 'omp', version: '0.0.0' })
    await client.connect(new StreamClientTransport(second.stdin, second.stdout))
    const read = await client.readResource({ uri: new URL(inboxUri('alice')).href })
    expect(JSON.parse(String((read.contents[0] as { text: string }).text))).toEqual(expect.anything())
    first.stdin.end()
    expect(await done).toBe(0)
    // Another writer holds the store when the lock is free: the takeover fails with busy (not held) and is tried again.
    const state = join(tmp.dir, 'state', 'alice')
    const other = new SqliteStore(join(state, 'edge.sqlite'))
    try {
      timers.fire((ms) => ms === HELD_RETRY_MS)
      await until('it armed a longer retry', () => timers.live().includes(2 * HELD_RETRY_MS))
      expect(existsSync(join(state, 'mcp.lock'))).toBe(false) // a failed opening let go of its lock
    } finally {
      other.close()
    }
    timers.fire((ms) => ms === 2 * HELD_RETRY_MS)
    await until('the second took over', () => errLines(second).some((l) => l.event === 'takeover'))
    second.stdin.end()
    expect(await secondDone).toBe(0)
  })

  it('ending a held server cancels its retry', async () => {
    const first = io(args('--trust-root', P.bob.address))
    const done = serve(first)
    await until('the first server started', () =>
      errLines(first).some((l) => l.event === 'start' && l.level === 'info'),
    )
    const timers = new ManualTimers()
    const second = io(args('--trust-root', P.bob.address), { pid: 4343, alive: (p) => p === 4242, timers })
    const secondDone = serve(second)
    await until('it is held', () => errLines(second).some((l) => l.event === 'held'))
    expect(timers.live()).toEqual([HELD_RETRY_MS])
    second.stdin.end()
    expect(await secondDone).toBe(0)
    expect(timers.live()).toEqual([])
    first.stdin.end()
    expect(await done).toBe(0)
  })

  it('watches the parent and the launchers above it, read at start', () => {
    const rows: Record<number, { ppid: number; comm: string }> = {
      10: { ppid: 20, comm: '/usr/bin/node' },
      20: { ppid: 30, comm: '/bin/sh' },
      30: { ppid: 40, comm: 'npx' },
      40: { ppid: 1, comm: 'claude' },
    }
    expect(watchedParents(10, (p) => rows[p] ?? null)).toEqual([20, 30, 40])
    // The host is not a launcher: its own parent (a terminal) is not watched.
    rows[30] = { ppid: 40, comm: 'omp' }
    expect(watchedParents(10, (p) => rows[p] ?? null)).toEqual([20, 30])
    expect(watchedParents(10, () => ({ ppid: 1, comm: 'node' }))).toEqual([])
  })

  it('exits 1 when the identity cannot be opened: a key that does not exist', async () => {
    const t = io(['--as', 'nobody', '--dir', tmp.dir, '--relay', RELAY])
    expect(await serve(t)).toBe(1)
    expect(errLines(t)).toMatchObject([{ level: 'error', event: 'start', code: 'ENOENT' }])
    expect(Buffer.concat(t.out).length).toBe(0)
  })

  it('serves MCP on its streams until stdin ends: only frames on stdout, the console sent to stderr, exit 0', async () => {
    const write = vi.spyOn(process.stdout, 'write')
    try {
      const t = io(args('--trust-root', P.bob.address), { records: fakeRecords(new Map()) })
      const done = serve(t)
      const client = new Client({ name: 'in-process', version: '0.0.0' })
      await client.connect(new StreamClientTransport(t.stdin, t.stdout))
      // Without --allow-delegate the delegate tool is not listed: fourteen tools, the pair and enterprise tools among them.
      expect((await client.listTools()).tools).toHaveLength(14)
      const status = await client.callTool({ name: 'status', arguments: {} })
      expect(status.structuredContent).toMatchObject({ address: P.alice.address, default_handler: 'queue' })
      const waited = await client.callTool({ name: 'wait', arguments: { timeout_s: 0.01 } })
      expect(waited.structuredContent).toEqual({
        timed_out: true,
        pending: false,
        resume: expect.any(String),
      })
      const bad = await client.callTool({ name: 'send', arguments: { to: [] } })
      expect(bad.isError).toBe(true)
      t.fakeConsole.log('a stray line from a dependency')
      t.fakeConsole.warn('a warning, %d', 2)
      t.fakeConsole.error(new Error('an error'))
      await client.close()
      expect(await done).toBe(0)
      const checked = frames(Buffer.concat(t.out))
      expect(checked.bad).toEqual([])
      expect(checked.lines).toBeGreaterThanOrEqual(5)
      const consoled = errLines(t).filter((l) => l.event === 'console')
      expect(consoled.map((l) => [l.level, String(l.text).split('\n')[0]])).toEqual([
        ['info', 'a stray line from a dependency'],
        ['warn', 'a warning, 2'],
        ['error', 'Error: an error'],
      ])
      expect(
        errLines(t)
          .filter((l) => l.event === 'start' || l.event === 'stop')
          .map((l) => l.event),
      ).toEqual(['start', 'stop'])
      expect(t.fakeConsole.log).toBe(t.fakeConsole.log)
      expect(write).not.toHaveBeenCalled()
    } finally {
      write.mockRestore()
    }
  })

  it('stops on SIGTERM, on SIGINT and when stdin closes, and warns when it trusts no root', async () => {
    for (const stop of ['SIGTERM', 'SIGINT', 'close'] as const) {
      const t = io(args())
      const done = serve(t)
      await until('the server started', () => errLines(t).some((l) => l.event === 'start'))
      if (stop === 'close') t.stdin.destroy()
      else t.emitter.emit(stop)
      expect(await done).toBe(0)
      expect(t.emitter.listenerCount('SIGTERM') + t.emitter.listenerCount('SIGINT')).toBe(0)
      const events = errLines(t).map((l) => l.event)
      expect(events.filter((e) => e !== 'subscription')).toEqual(['start', 'no-trust-root', 'stop'])
    }
  })

  it('restores the console after the run', async () => {
    const t = io(args())
    const original = t.fakeConsole.log
    const done = serve(t)
    await until('the server started', () => errLines(t).some((l) => l.event === 'start'))
    expect(t.fakeConsole.log).not.toBe(original)
    t.stdin.end()
    await done
    expect(t.fakeConsole.log).toBe(original)
  })
})

describe('startServer', () => {
  function config(): Config {
    return parseConfig(args(), {}) as Config
  }

  const deps = (log: MemoryLog) => ({
    clock: new FakeClock(),
    rng: seededRng('start'),
    relay,
    timers: new ManualTimers(),
    pid: 4242,
    alive: () => false,
    log,
  })

  it('fails, and lets go of the identity, when the edge cannot finish a row a crash left behind', async () => {
    const state = join(tmp.dir, 'state', 'alice')
    mkdirSync(state, { recursive: true, mode: 0o700 })
    const store = new SqliteStore(join(state, 'edge.sqlite'))
    const row = store.inboxAdd(RELAY, P.alice.address, 1, new TextEncoder().encode('garbage'), 0)
    store.inboxPut(row, { state: 'verified', content: '{}' }, 0)
    store.close()
    await expect(startServer(config(), deps(new MemoryLog()))).rejects.toThrow()
    const again = new SqliteStore(join(state, 'edge.sqlite'))
    again.inboxPut(row, { state: 'rejected', reason: 'bad-json' }, 0)
    again.close()
    const running = await startServer(config(), deps(new MemoryLog()))
    await running.stop()
    await running.stop()
  })

  it('logs an accepted row the desk could not take, and keeps serving', async () => {
    const clock = new FakeClock()
    const timers = new ManualTimers()
    const bob = await testServer({
      home: tmp.dir,
      name: 'bob',
      relay,
      clock,
      timers,
      args: ['--trust-root', P.alice.address],
    })
    const alice = await testServer({ home: tmp.dir, name: 'alice', relay, clock, timers, pid: 4343 })
    try {
      bob.running.desk.take = () => {
        throw new Error('cannot read the row')
      }
      await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: {} })
      await until('the notice error', () => bob.log.lines.some((l) => l.event === 'notice'))
      expect(bob.log.lines.find((l) => l.event === 'notice')?.fields).toMatchObject({
        relay: RELAY,
        cursor: 1,
        code: 'internal',
        detail: 'cannot read the row',
      })
      expect((await bob.call('status')).isError).toBe(false)
    } finally {
      await alice.close()
      await bob.close()
    }
  })
})

describe('processIo', () => {
  it("gives every identity's relay client the process's turns, since they share its connection pool", async () => {
    const held: ServerResponse[] = []
    const server = createServer((_req, res) => held.push(res))
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    const p = processIo()
    const clients = [p.relay(() => 1), p.relay(() => 1), p.relay(() => 1)]
    const calls = Array.from({ length: RELAY_TURNS * 3 }, (_, i) =>
      clients[i % 3]?.fetchRecord(url, `a${i}`, 'address'),
    )
    await vi.waitFor(() => expect(held).toHaveLength(RELAY_TURNS))
    await new Promise((done) => setTimeout(done, 50))
    expect(held).toHaveLength(RELAY_TURNS)
    const answer = setInterval(() => {
      for (const res of held.splice(0)) res.writeHead(404).end()
    }, 1)
    await Promise.all(calls)
    clearInterval(answer)
    server.closeAllConnections()
    server.close()
  })

  it("is the process's own: its arguments, streams, environment, signals, console and the system ports", () => {
    const p = processIo()
    expect([p.stdin, p.stdout, p.stderr, p.env, p.signals, p.console, p.pid]).toEqual([
      process.stdin,
      process.stdout,
      process.stderr,
      process.env,
      process,
      console,
      process.pid,
    ])
    expect(p.argv).toEqual(process.argv.slice(2))
    // The real relay client, with the pair rendezvous calls (edge pair-code).
    expect(Object.keys(p.relay()).sort()).toEqual([
      'fetch',
      'fetchRecord',
      'health',
      'pairClaim',
      'pairOpen',
      'publish',
      'subscribe',
    ])
    expect(Math.abs(p.clock.now() - Date.now() / 1000)).toBeLessThan(2)
    expect(p.rng.bytes(8)).toHaveLength(8)
    expect([p.timers, p.alive(process.pid), p.run]).toEqual([realTimers, true, runShell])
  })
})
