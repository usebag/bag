import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { boundOf, watchRing } from '../src/commands/wake-hook.ts'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The CLI as a client of the bag service (docs/bag-service.md, service/lend and service/return): a fake service on a
// unix socket under a short temporary home (a socket path must fit sun_path), speaking the contract's NDJSON JSON-RPC.

const base = mkdtempSync('/tmp/bs-')
afterAll(() => rmSync(base, { recursive: true, force: true }))
const RELAY = 'http://127.0.0.1:9'
const TOKEN = 'ab'.repeat(32)
let n = 0

interface Fake {
  readonly home: string
  readonly calls: { method: string; params: Record<string, unknown> }[]
  /** What service/lend answers: null lends, a code refuses. */
  lend: string | null
  close(): Promise<void>
}

/** A home with bob, and a fake service at <home>/run/service.sock that records every call. */
async function fake(): Promise<Fake & { io: ReturnType<typeof testIo> }> {
  const home = join(base, `h${n++}`)
  const io = testIo(new MemoryRelay(), {})
  expect((await cli(io, 'keygen', 'bob', '--dir', home)).code).toBe(0)
  mkdirSync(join(home, 'run'), { mode: 0o700 })
  writeFileSync(join(home, 'run', 'service.token'), `${TOKEN}\n`, { mode: 0o600 })
  const calls: Fake['calls'] = []
  const sockets: Socket[] = []
  const f: Fake & { io: typeof io } = {
    home,
    io,
    calls,
    lend: null,
    close: () =>
      new Promise((done) => {
        for (const s of sockets) s.destroy()
        server.close(() => done())
      }),
  }
  const answer = (s: Socket, id: unknown, body: Record<string, unknown>) =>
    s.write(`${JSON.stringify({ jsonrpc: '2.0', id, ...body })}\n`)
  const refuse = (s: Socket, id: unknown, code: string, detail: string) =>
    answer(s, id, { error: { code: -32000, message: `${code}: ${detail}`, data: { code, detail } } })
  const server: Server = createServer((s) => {
    sockets.push(s)
    let buf = ''
    s.on('data', (c) => {
      buf += c.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        const m = JSON.parse(buf.slice(0, i)) as {
          id: unknown
          method: string
          params: Record<string, unknown>
        }
        buf = buf.slice(i + 1)
        calls.push({ method: m.method, params: m.params })
        if (m.method === 'service/hello') {
          if (m.params.token !== TOKEN) refuse(s, m.id, 'bad-auth', 'the launch token is wrong')
          else
            answer(s, m.id, {
              result: { contract: 1, service: { version: '0.4.0', pid: 5151 }, connection: 'c-1' },
            })
        } else if (m.method === 'service/lend') {
          if (f.lend === null) answer(s, m.id, { result: { lent: true, label: m.params.label } })
          else refuse(s, m.id, f.lend, 'bound in claude-code at /Users/x/repo')
        } else if (m.method === 'service/return') {
          answer(s, m.id, { result: { returned: true, label: m.params.label, open: true, removed: false } })
        }
      }
    })
  })
  await new Promise<void>((done) => server.listen(join(home, 'run', 'service.sock'), done))
  return f
}

const inbox = (io: ReturnType<typeof testIo>, home: string) =>
  cli(io, 'inbox', '--as', 'bob', '--relay', RELAY, '--once', '--dir', home)

describe('the CLI as a client of the bag service', () => {
  it('lends the identity for an act, runs it as today, and gives it back on the same connection', async () => {
    const f = await fake()
    const ran = await inbox(f.io, f.home)
    expect(ran.code).toBe(0)
    expect(ran.err).toContain('the bag service (pid 5151) lent bob to this command; it takes it back after')
    expect(f.calls.map((c) => c.method)).toEqual(['service/hello', 'service/lend', 'service/return'])
    const hello = f.calls[0]?.params as Record<string, unknown>
    expect([hello.contract, hello.token, hello.host, hello.input_hook]).toEqual([1, TOKEN, 'cli', false])
    expect(f.calls[1]?.params).toEqual({ label: 'bob', verb: 'inbox' })
    expect(f.calls[2]?.params).toEqual({ label: 'bob' })
    await f.close()
  })

  it('names identity remove by its positional, and lends nothing for a command that acts on no identity', async () => {
    const f = await fake()
    f.io.tty = false
    const removed = await cli(f.io, 'identity', 'remove', 'bob', '--relay', RELAY, '--dir', f.home)
    expect(removed.err.at(-1)).toMatch(/no-tty/)
    expect(f.calls.filter((c) => c.method === 'service/lend').map((c) => c.params)).toEqual([
      { label: 'bob', verb: 'identity-remove' },
    ])
    const before = f.calls.length
    expect((await cli(f.io, 'address', 'bob', '--dir', f.home)).code).toBe(0)
    expect(f.calls.length).toBe(before)
    await f.close()
  })

  it("prints a busy lend as today's held, runs nothing, and asks once (no retry loop)", async () => {
    const f = await fake()
    f.lend = 'busy'
    const ran = await inbox(f.io, f.home)
    expect(ran.code).toBe(1)
    expect(ran.err[0]).toBe(
      'bag: held: the identity bob is held by the bag service (busy: bound in claude-code at /Users/x/repo); close that window, then run this again',
    )
    expect(f.calls.filter((c) => c.method === 'service/lend').length).toBe(1)
    expect(f.calls.some((c) => c.method === 'service/return')).toBe(false)
    await f.close()
  })

  it('refuses with the service code on a wrong launch token, and acts as today with no socket or a dead one', async () => {
    const f = await fake()
    writeFileSync(join(f.home, 'run', 'service.token'), 'cd'.repeat(32), { mode: 0o600 })
    expect((await inbox(f.io, f.home)).err[0]).toBe('bag: bad-auth: the launch token is wrong')
    await f.close()
    // The socket file left by a service that is gone: connect fails, so no service runs.
    writeFileSync(join(f.home, 'run', 'service.sock'), '')
    expect((await inbox(f.io, f.home)).code).toBe(0)
  })

  it('status --as names the service from its hello, and asks it for no lend', async () => {
    const f = await fake()
    const ran = await cli(f.io, 'status', '--as', 'bob', '--dir', f.home)
    expect(ran.out).toContain(`service bag 0.4.0 pid 5151 contract 1 ${join(f.home, 'run', 'service.sock')}`)
    expect(f.calls.map((c) => c.method)).toEqual(['service/hello'])
    await f.close()
  })
})

describe('wake-hook --session service: the identity of this session is the one its shim is bound to', () => {
  it("reads the shim's .bound file of the first ancestor that has one, and none means unbound", () => {
    const home = join(base, 'wake')
    mkdirSync(join(home, 'run', 'shim'), { recursive: true })
    const parents: Record<number, number> = { 300: 200, 200: 100 }
    const parent = (pid: number) => parents[pid] ?? null
    const live = (pid: number) => pid === 4242
    const bound = (doc: unknown) => writeFileSync(join(home, 'run', 'shim', '200.bound'), JSON.stringify(doc))
    expect(boundOf(home, 300, parent, live)).toEqual([])
    bound({ v: 1, as: ['omp-3'], shim: 4242 })
    expect(boundOf(home, 300, parent, live)).toEqual(['omp-3'])
    bound({ v: 1, as: ['omp', 'omp-3'], shim: 4242 })
    expect(boundOf(home, 300, parent, live)).toEqual(['omp', 'omp-3'])
    bound({ v: 1, as: ['omp-3'], shim: 999 })
    expect(boundOf(home, 300, parent, live)).toEqual([])
    bound({ v: 2, as: ['omp-3'], shim: 4242 })
    expect(boundOf(home, 300, parent, live)).toEqual([])
    bound({ v: 1, as: ['../keys'], shim: 4242 })
    expect(boundOf(home, 300, parent, live)).toEqual([])
  })

  it('ends at once, silent, in a session whose shim is not bound', async () => {
    const io = testIo(new MemoryRelay(), {})
    const at = Date.now()
    const ran = await cli(
      io,
      'wake-hook',
      '--session',
      'service',
      '--dir',
      join(base, 'wake'),
      '--max',
      '600',
    )
    expect([ran.code, ran.out, ran.err]).toEqual([0, [], []])
    expect(Date.now() - at).toBeLessThan(5000)
    expect((await cli(io, 'wake-hook', '--session', 'service', '--as', 'bob')).err[0]).toBe(
      'bag: usage: --session service takes no --as: the shim names it',
    )
  })
})

describe('wake-hook --session service: the ring file, one speaking window', () => {
  const dir = join(base, 'ring')
  const shim = join(dir, 'run', 'shim')
  mkdirSync(shim, { recursive: true })
  const live = (pid: number) => pid === 4242
  const ring = (n: number, speaking: boolean, shimPid = 4242) =>
    writeFileSync(
      join(shim, '7.ring'),
      JSON.stringify({ v: 1, n, as: 'omp-3', unread: 1, speaking, at: 'x', shim: shimPid }),
    )
  const watch = (ms: number) => {
    const io = testIo(new MemoryRelay(), {})
    const w = { end: Date.now() + ms, signal: new AbortController().signal, pollMs: 10, code: 2 }
    return watchRing(io, dir, 7, w, live).then((code) => ({ code, err: io.stderr }))
  }
  const later = (ms: number, f: () => void) => setTimeout(f, ms)
  writeFileSync(join(shim, '7.bound'), JSON.stringify({ v: 1, as: ['omp-3'], shim: 4242 }))

  it('takes the ring there at its first run as the baseline, then wakes on a newer speaking ring with the wake line', async () => {
    ring(5, true)
    expect(await watch(60)).toEqual({ code: 0, err: [] })
    later(30, () => ring(6, true))
    expect(await watch(2000)).toEqual({
      code: 2,
      err: ['bag: a message was delivered to omp-3; read it with the inbox tool and report it'],
    })
  })

  it('never wakes twice for one n, and a ring that is not speaking is handled with no turn', async () => {
    expect(await watch(60)).toEqual({ code: 0, err: [] })
    later(30, () => ring(7, false))
    expect(await watch(200)).toEqual({ code: 0, err: [] })
    expect(readFileSync(join(shim, '7.ring-seen'), 'utf8')).toBe('4242 7\n')
  })

  it('takes any n of another live shim as new (a restarted shim counts from 1), and keeps <shim> <n> as seen', async () => {
    const live2 = (pid: number) => pid === 4242 || pid === 5353
    const io = testIo(new MemoryRelay(), {})
    later(30, () => ring(1, true, 5353))
    const w = { end: Date.now() + 2000, signal: new AbortController().signal, pollMs: 10, code: 2 }
    expect(await watchRing(io, dir, 7, w, live2)).toBe(2)
    expect(readFileSync(join(shim, '7.ring-seen'), 'utf8')).toBe('5353 1\n')
  })

  it('ignores a ring of a dead shim, and ends at once when the session is unbound (.bound gone)', async () => {
    later(30, () => ring(9, true, 999))
    expect(await watch(200)).toEqual({ code: 0, err: [] })
    later(30, () => rmSync(join(shim, '7.bound')))
    const at = Date.now()
    expect(await watch(5000)).toEqual({ code: 0, err: [] })
    expect(Date.now() - at).toBeLessThan(2000)
  })
})

describe('every verb that writes an identity lends it, or refuses held, while a service runs', () => {
  const lent = (f: Fake) => f.calls.filter((c) => c.method === 'service/lend').map((c) => c.params)
  const cases: [string[], string][] = [
    [['pair', '--as', 'bob', '--relay', RELAY], 'pair'],
    [['send', '--as', 'bob', '--to', 'x', '--relay', RELAY, '--body', '{}'], 'send'],
    [['unpair', 'ed25519:00', '--as', 'bob', '--relay', RELAY], 'unpair'],
    [['resend', '--as', 'bob', '--relay', RELAY], 'resend'],
    [['held', 'list', '--as', 'bob', '--relay', RELAY], 'held'],
    [['peer', 'invite', '--as', 'bob', '--relay', RELAY, '--name', 'p'], 'peer'],
    [['lookup', 'ed25519:00', '--as', 'bob', '--relay', RELAY], 'lookup'],
    [['logout', '--as', 'bob'], 'logout'],
    [['record', 'keep', '--as', 'bob', '--relay', RELAY, '--once'], 'record-keep'],
    [['init', 'bob', '--relay', RELAY], 'init'],
    [['restore', 'bob'], 'restore'],
    [['onboard', 'bob', '--domain', 'x.example', '--relay', RELAY, '--accept', '*'], 'onboard'],
    [['keys', 'rotate', 'bob', '--relay', RELAY], 'keys-rotate'],
    [['keys', 'prune', 'bob'], 'keys-prune'],
    [['record', 'address', 'bob', '--relay', RELAY], 'record-address'],
    [['record', 'accept-from', 'bob', '--root', '*', '--max-bytes', '1', '--ttl', '1'], 'record-accept-from'],
    [['group', 'rotate', 'bob'], 'group-rotate'],
    [['identity', 'relays', 'bob', '--relay', RELAY], 'identity-relays'],
    [['identity', 'custody', 'bob', '--to', 'file'], 'identity-custody'],
  ]
  for (const [argv, verb] of cases) {
    it(`${argv.slice(0, 2).join(' ')} lends bob as ${verb}`, async () => {
      const f = await fake()
      await cli(f.io, ...argv, '--dir', f.home)
      expect(lent(f)).toEqual([{ label: 'bob', verb }])
      await f.close()
    })
  }

  it('refuses held for publish and for an act that names no identity, and lends nothing for a print-only job', async () => {
    const f = await fake()
    const pub = await cli(f.io, 'publish', RELAY, '/nonexistent', '--dir', f.home)
    expect(pub.err[0]).toMatch(
      /^bag: held: the bag service \(pid 5151\) holds the identities of .*publish names none it can lend/,
    )
    const all = await cli(f.io, 'record', 'keep', '--identities', '/x/ids.json', '--once', '--dir', f.home)
    expect(all.err[0]).toMatch(/^bag: held: /)
    await cli(f.io, 'record', 'keep', '--as', 'bob', '--relay', RELAY, '--plist', '--dir', f.home)
    expect(lent(f)).toEqual([])
    await f.close()
  })

  it("login lends nothing: it is the agent on agent.sock, the service's agent unit its client (no deadlock)", async () => {
    const f = await fake()
    const ran = await cli(f.io, 'login', '--as', 'bob', '--relay', RELAY, '--dir', f.home)
    expect(lent(f)).toEqual([])
    // It ran as today: its own refusal (no terminal), not held.
    expect(ran.err.at(-1)).not.toMatch(/held/)
    expect(ran.err.some((l) => l.includes('lent bob'))).toBe(false)
    const out = await cli(f.io, 'logout', '--as', 'bob', '--dir', f.home)
    expect(lent(f)).toEqual([{ label: 'bob', verb: 'logout' }])
    void out
    await f.close()
  })

  it('runs as today for an identity the service does not hold (unknown-identity)', async () => {
    const f = await fake()
    f.lend = 'unknown-identity'
    const ran = await cli(f.io, 'keys', 'list', '--dir', f.home)
    expect(ran.code).toBe(0)
    expect((await cli(f.io, 'address', 'bob', '--dir', f.home)).code).toBe(0)
    const ok = await inbox(f.io, f.home)
    expect(ok.code).toBe(0)
    expect(f.calls.some((c) => c.method === 'service/return')).toBe(false)
    await f.close()
  })
})
