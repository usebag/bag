import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { boundOf, endWindow, hostOf, watchRing } from '../src/commands/wake-hook.ts'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The CLI as a client of the bag service (docs/bag-service.md, "The command line beside the service"): a fake service
// on a unix socket under a short temporary home (a socket path must fit sun_path), speaking the service's NDJSON
// JSON-RPC.

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
  expect((await cli(io, 'keygen', '--new', 'bob', '--dir', home)).code).toBe(0)
  mkdirSync(join(home, 'run'), { mode: 0o700 })
  writeFileSync(join(home, 'run', 'service.token'), `${TOKEN}\n`, { mode: 0o600 })
  const calls: Fake['calls'] = []
  const lent = new Set<string>()
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
          const label = String(m.params.label)
          // As the service: a label already lent is busy (bag identity remove's probe reads its own lease so).
          if (lent.has(label)) refuse(s, m.id, 'busy', `${label} is lent to the CLI for ${m.params.verb}`)
          else if (f.lend === null) {
            lent.add(label)
            answer(s, m.id, { result: { lent: true, label } })
          } else refuse(s, m.id, f.lend, 'bound in claude-code at /Users/x/repo')
        } else if (m.method === 'service/return') {
          lent.delete(String(m.params.label))
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

  it('identity remove beside the service leaves the rows for it and moves held mail to the other side (C2)', async () => {
    const f = await fake()
    f.io.tty = true
    f.io.answers.push(true)
    const bob = (await cli(f.io, 'address', 'bob', '--dir', f.home)).out[0] as string
    const lab = (await cli(f.io, 'keygen', '--new', 'lab', '--dir', f.home)).out[0] as string
    // bob's first touch of lab, held for lab's person in lab's own spool, named by the row.
    const id = 'e'.repeat(64)
    const labHeld = join(f.home, 'state', 'lab', 'local-spool', 'held')
    mkdirSync(labHeld, { recursive: true })
    writeFileSync(join(labHeld, `${id}.env`), 'x')
    const row = { a: 'bob', b: 'lab', a_addr: bob, b_addr: lab, added_at: 1, state: 'requested', held: [id] }
    const table = `${JSON.stringify({ version: 1, pairs: [row] })}\n`
    writeFileSync(join(f.home, 'run', 'local-peers.json'), table, { mode: 0o600 })
    const to = join(base, `left-${n}`)
    const r = await cli(f.io, 'identity', 'remove', 'lab', '--relay', RELAY, '--to', to, '--dir', f.home)
    expect(r.code, r.err.join('\n')).toBe(0)
    expect(f.io.asked[0]).toContain(
      '  its held local mail (1): the bag service fails it to the senders when this command gives lab back',
    )
    expect(r.out).toContain(
      'the bag service tells the senders of its held mail when this command gives lab back to it',
    )
    expect(r.out.some((l) => l.startsWith('dropped the local pairs'))).toBe(false)
    // The rows are the service's to drop at the give-back; the held file waits where its #dropRemoved reads it.
    expect(readFileSync(join(f.home, 'run', 'local-peers.json'), 'utf8')).toBe(table)
    expect(readFileSync(join(f.home, 'state', 'bob', 'local-spool', 'held', `${id}.env`), 'utf8')).toBe('x')
    // The lease's lend, the command's probe (busy: its own lease holds lab), the probe again after the y (lentAgain:
    // the identity holds mail, so a service that changed its answer while asked would be busy), the lease's return.
    expect(f.calls.filter((c) => c.method !== 'service/hello').map((c) => [c.method, c.params])).toEqual([
      ['service/lend', { label: 'lab', verb: 'identity-remove' }],
      ['service/lend', { label: 'lab', verb: 'identity-remove' }],
      ['service/lend', { label: 'lab', verb: 'identity-remove' }],
      ['service/return', { label: 'lab' }],
    ])
    await f.close()
  })

  it('identity remove beside a service that does not serve the identity fails the held mail itself (C2, N2)', async () => {
    const f = await fake()
    f.lend = 'unknown-identity'
    f.io.tty = true
    f.io.answers.push(true)
    const bob = (await cli(f.io, 'address', 'bob', '--dir', f.home)).out[0] as string
    const lab = (await cli(f.io, 'keygen', '--new', 'lab', '--dir', f.home)).out[0] as string
    const id = 'e'.repeat(64)
    const labHeld = join(f.home, 'state', 'lab', 'local-spool', 'held')
    mkdirSync(labHeld, { recursive: true })
    writeFileSync(join(labHeld, `${id}.env`), 'x')
    const row = { a: 'bob', b: 'lab', a_addr: bob, b_addr: lab, added_at: 1, state: 'requested', held: [id] }
    writeFileSync(join(f.home, 'run', 'local-peers.json'), JSON.stringify({ version: 1, pairs: [row] }), {
      mode: 0o600,
    })
    const to = join(base, `left-${n}`)
    const r = await cli(f.io, 'identity', 'remove', 'lab', '--relay', RELAY, '--to', to, '--dir', f.home)
    expect(r.code, r.err.join('\n')).toBe(0)
    expect(f.io.asked[0]).toContain(
      '  its held local mail (1): failed to the senders, in their audit logs, and deleted',
    )
    // An envelope that does not read names no sender: dropped, and the rows leave here (no service will see the remove).
    expect(r.out).toContain(`dropped held mail ${id}`)
    expect(r.out).toContain('dropped the local pairs of lab')
    expect(JSON.parse(readFileSync(join(f.home, 'run', 'local-peers.json'), 'utf8')).pairs).toEqual([])
    expect(f.calls.some((c) => c.method === 'service/return')).toBe(false)
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

describe('wake-hook --session service: two Codex windows under one host process', () => {
  // Codex 0.167 runs one server process (200) for all of its TUI windows; each window's shim keys its files by the
  // window's session id, which the Stop hook's input carries as session_id.
  const [A, B] = ['0a1b2c3d-0000-4000-8000-00000000000a', '0a1b2c3d-0000-4000-8000-00000000000b']
  const home = join(base, 'codex')
  const shim = join(home, 'run', 'shim')
  mkdirSync(shim, { recursive: true })
  const parents: Record<number, number> = { 300: 200, 200: 100 }
  const parent = (pid: number) => parents[pid] ?? null
  const live = (pid: number) => pid === 4242 || pid === 5353

  it("finds its own window's file by the session id, and a hook with no keyed file takes the host's own", () => {
    writeFileSync(join(shim, `200-${A}.bound`), JSON.stringify({ v: 1, as: ['id-a'], shim: 4242 }))
    writeFileSync(join(shim, `200-${B}.bound`), JSON.stringify({ v: 1, as: ['id-b'], shim: 5353 }))
    expect(hostOf(home, 300, parent, A)).toBe(`200-${A}`)
    expect(boundOf(home, 300, parent, live, A)).toEqual(['id-a'])
    expect(boundOf(home, 300, parent, live, B.toUpperCase())).toEqual(['id-b'])
    // No session id, or one that is not a uuid: the host pid's own file only (Claude Code, omp), here none.
    expect(boundOf(home, 300, parent, live)).toEqual([])
    expect(boundOf(home, 300, parent, live, `${A}/..`)).toEqual([])
    // B unbinds: B's hook ends unbound, A's still finds id-a.
    rmSync(join(shim, `200-${B}.bound`))
    expect(boundOf(home, 300, parent, live, B)).toEqual([])
    expect(boundOf(home, 300, parent, live, A)).toEqual(['id-a'])
    // One process per window (Claude Code): its session id names no keyed file, and the host's .bound is read.
    writeFileSync(join(shim, '200.bound'), JSON.stringify({ v: 1, as: ['cc'], shim: 4242 }))
    expect(boundOf(home, 300, parent, live, B)).toEqual(['cc'])
    rmSync(join(shim, '200.bound'))
  })

  it("wakes a window only for its own window's ring", async () => {
    const io = testIo(new MemoryRelay(), {})
    const w = (ms: number) => ({
      end: Date.now() + ms,
      signal: new AbortController().signal,
      pollMs: 10,
      code: 2,
    })
    const ringOf = (key: string, as: string, n: number, pid: number) =>
      writeFileSync(
        join(shim, `${key}.ring`),
        JSON.stringify({ v: 1, n, as, unread: 1, speaking: true, at: 'x', shim: pid }),
      )
    writeFileSync(join(shim, `200-${B}.bound`), JSON.stringify({ v: 1, as: ['id-b'], shim: 5353 }))
    expect(await watchRing(io, home, `200-${A}`, w(40), live)).toBe(0)
    expect(await watchRing(io, home, `200-${B}`, w(40), live)).toBe(0)
    setTimeout(() => ringOf(`200-${B}`, 'id-b', 1, 5353), 30)
    // B's mail: A's hook stays silent, B's wakes with its own name.
    expect(await watchRing(io, home, `200-${A}`, w(200), live)).toBe(0)
    expect(io.stderr).toEqual([])
    expect(await watchRing(io, home, `200-${B}`, w(2000), live)).toBe(2)
    expect(io.stderr).toEqual([
      'bag: a message was delivered to id-b; read it with the inbox tool and report it',
    ])
  })

  it("reads the window's session id from the Stop hook's input", async () => {
    const host = process.ppid
    writeFileSync(join(shim, `${host}-${A}.bound`), JSON.stringify({ v: 1, as: ['id-a'], shim: process.pid }))
    const run = async (sid: string) => {
      const io = testIo(new MemoryRelay(), {})
      io.lines.push(JSON.stringify({ session_id: sid, hook_event_name: 'Stop' }))
      const at = Date.now()
      const ran = await cli(io, 'wake-hook', '--session', 'service', '--dir', home, '--max', '3')
      // A wait of --max is 3 s; "waited" is 2.7 s or more, so a slow start under a gate's load (2 s seen) is never one.
      return { code: ran.code, err: ran.err, waited: Date.now() - at >= 2700 }
    }
    // Window A is bound: its hook waits out --max. Window B's has no file of its own: unbound, it ends at once.
    expect(await run(A)).toEqual({ code: 0, err: [], waited: true })
    expect(await run(B)).toEqual({ code: 0, err: [], waited: false })
    rmSync(join(shim, `${host}-${A}.bound`))
  }, 15_000)
})

describe("wake-hook --session service --end: Codex's SessionEnd releases the ended session's binding only", () => {
  const [A, B] = ['0a1b2c3d-0000-4000-8000-00000000000a', '0a1b2c3d-0000-4000-8000-00000000000b']
  const home = join(base, 'end')
  const shim = join(home, 'run', 'shim')
  mkdirSync(shim, { recursive: true })
  // The hook (300) and both shims (4242, 5353) are children of Codex's shared server process, 200.
  const parents: Record<number, number> = { 300: 200, 200: 100, 4242: 200, 5353: 200, 7777: 1 }
  const parent = (pid: number) => parents[pid] ?? null
  const live = (pid: number) => pid === 4242 || pid === 5353 || pid === 7777 || pid === 6464
  // Each live pid's start time as ps would print it; the shim writes its own into .bound as `started`.
  const starts: Record<number, string> = {
    4242: 'Fri Nov 13 01:00:00 2026',
    5353: 'Fri Nov 13 01:00:05 2026',
  }
  const end = (sid: string | null) => {
    const hit: number[] = []
    endWindow(
      home,
      300,
      sid,
      parent,
      live,
      (pid) => hit.push(pid),
      (pid) => starts[pid] ?? null,
    )
    return hit
  }
  const bind = (sid: string, shimPid: number, started: string | null = starts[shimPid] ?? null) =>
    writeFileSync(
      join(shim, `200-${sid}.bound`),
      JSON.stringify({ v: 1, as: ['id'], shim: shimPid, ...(started === null ? {} : { started }) }),
    )

  it('signals the shim of its own session file, never another window or the host pid file', () => {
    bind(A, 4242)
    bind(B, 5353)
    writeFileSync(join(shim, '200.bound'), JSON.stringify({ v: 1, as: ['cc'], shim: 4242 }))
    expect(end(A)).toEqual([4242])
    expect(end(B.toUpperCase())).toEqual([5353])
    expect(end(null)).toEqual([])
    expect(end('not-a-uuid')).toEqual([])
    rmSync(join(shim, '200.bound'))
    rmSync(join(shim, `200-${B}.bound`))
    expect(end(B)).toEqual([])
  })

  it("signals the window's own shim, never a sub-agent's shim that runs under the same host with the same session id", () => {
    // A sub-agent's shim (6464) has the window's session id but keeps no wake files (packages/shim run.ts), so the
    // window's file names the window's shim, and --end signals that one only.
    parents[6464] = 200
    starts[6464] = 'Fri Nov 13 01:10:00 2026'
    bind(A, 4242)
    expect(end(A)).toEqual([4242])
    rmSync(join(shim, `200-${A}.bound`))
  })

  it('/new: the old session ends after the shim moved to the new id, nothing; before it moved, the release', () => {
    // Before the move: the old id's file is the shim's, and the shim is released (it connects again unbound).
    bind(A, 4242)
    expect(end(A)).toEqual([4242])
    // After the move (the new session's first tool call): the old id names no file, the window's binding stays.
    rmSync(join(shim, `200-${A}.bound`))
    bind(B, 4242)
    expect(end(A)).toEqual([])
    rmSync(join(shim, `200-${B}.bound`))
  })

  it('signals no dead shim, no pid not under that host, and no reused pid (another start time, or none)', () => {
    bind(A, 999)
    expect(end(A)).toEqual([])
    bind(A, 7777)
    expect(end(A)).toEqual([])
    // 4242 now is another process under the Codex host: kill 0 and the walk pass, the start time does not.
    bind(A, 4242, 'Thu Nov 12 22:00:00 2026')
    expect(end(A)).toEqual([])
    bind(A, 4242, null)
    expect(end(A)).toEqual([])
    bind(A, 4242)
    expect(end(A)).toEqual([4242])
    rmSync(join(shim, `200-${A}.bound`))
  })

  it('ends 0, silent, and --end is for --session service only', async () => {
    const io = testIo(new MemoryRelay(), {})
    io.lines.push(JSON.stringify({ session_id: A, hook_event_name: 'SessionEnd' }))
    const ran = await cli(io, 'wake-hook', '--session', 'service', '--end', '--dir', home)
    expect([ran.code, ran.out, ran.err]).toEqual([0, [], []])
    expect((await cli(io, 'wake-hook', '--as', 'bob', '--end')).err[0]).toBe(
      'bag: usage: --end is for --session service only',
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
