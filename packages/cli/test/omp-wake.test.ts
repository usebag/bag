import { randomBytes } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { createServer, type Server } from 'node:net'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { SqliteStore } from '@usebag/edge'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import bagWake, {
  type Arrival,
  ASK_WIDGET,
  arrivals,
  awayText,
  boundIn,
  CHANNEL_MS,
  CONSENT_STATUS,
  type ConsentUi,
  consentLink,
  holderOf,
  IDLE_MS,
  LOOP_AT,
  LOOP_S,
  loopLines,
  mtimeOf,
  namesOf,
  OMP_FAST_MS,
  OMP_MCP_DEFAULT_MS,
  ompCallMs,
  ompConfirm,
  ompInput,
  PENDING_TEXT,
  POLL_MS,
  RELINK_MAX_MS,
  RELINK_MS,
  RING_POLL_MS,
  type RingDoc,
  RingLoop,
  type RingSeen,
  refusal,
  ringIn,
  SETTLE_MS,
  seenIn,
  shimHomeOf,
  targetOf,
  typedName,
  WAKE_STATUS,
  WakeLoop,
  wakeText,
  writeFacts,
} from '../src/omp-wake.ts'
import { tempDir } from './support/io.ts'

// The omp wake extension (packages/cli/src/omp-wake.ts): its state machine with a fake doorbell and session, and the
// pieces it reads and writes. Temp directories only.

const tmp = tempDir('omp-wake')
afterAll(() => tmp.cleanup())
// omp's user-level mcp.json (shimHomeOf) is read from here, never from the real ~/.omp.
process.env.PI_CODING_AGENT_DIR = join(tmp.dir, 'omp-agent')
let n = 0

/** A fake world: a doorbell mtime, wake-seen, an idle flag, and a timer queue run by hand. */
function fake(seen = Number.NaN) {
  const w = {
    bell: 0,
    seen,
    idle: true,
    fired: 0,
    shown: 0,
    away: null as { pid: number } | null,
    timers: [] as { fn: () => void; ms: number }[],
  }
  const loop = new WakeLoop({
    doorbell: () => w.bell,
    seen: () => w.seen,
    remember: (m) => {
      w.seen = m
    },
    idle: () => w.idle,
    fire: () => {
      w.fired++
    },
    away: () => w.away,
    show: () => {
      w.shown++
    },
    later: (fn, ms) => {
      w.timers.push({ fn, ms })
    },
  })
  /** Runs the timers due now, and those they schedule, until none is left. */
  const tick = () => {
    for (let i = 0; i < 100 && w.timers.length > 0; i++) (w.timers.shift() as { fn: () => void }).fn()
  }
  return { w, loop, tick }
}

describe('WakeLoop', () => {
  it('a first session makes wake-seen the doorbell and does not wake for older mail', () => {
    const { w, loop, tick } = fake()
    w.bell = 100
    loop.start()
    tick()
    expect([w.seen, w.fired]).toEqual([100, 0])
  })

  it('a session after omp was closed wakes once for mail that came meanwhile', () => {
    const { w, loop, tick } = fake(100)
    w.bell = 200
    loop.start()
    tick()
    expect([w.seen, w.fired]).toEqual([200, 1])
  })

  it('one ring, idle: one turn after SETTLE_MS, and the same mtime never wakes again', () => {
    const { w, loop, tick } = fake(100)
    w.bell = 150
    loop.ring()
    expect(w.timers[0]?.ms).toBe(SETTLE_MS)
    tick()
    expect(w.fired).toBe(1)
    loop.ring()
    loop.ring()
    tick()
    expect(w.fired).toBe(1)
  })

  it('a burst is one turn, and its last ring is the one remembered (problem 9)', () => {
    const { w, loop, tick } = fake(100)
    w.bell = 150
    loop.ring()
    w.bell = 151
    loop.ring()
    w.bell = 152
    loop.ring()
    tick()
    expect([w.fired, w.seen]).toEqual([1, 152])
    loop.ring()
    tick()
    expect(w.fired).toBe(1)
  })

  it('a ring while a turn runs waits, and fires once when the session is idle again', () => {
    const { w, loop, tick } = fake(100)
    w.idle = false
    w.bell = 150
    loop.ring()
    tick()
    expect([w.fired, loop.pending, w.seen]).toEqual([0, true, 100])
    w.bell = 160
    loop.ring()
    tick()
    loop.idle()
    expect(w.timers[0]?.ms).toBe(IDLE_MS)
    tick()
    expect(w.fired).toBe(0)
    w.idle = true
    loop.idle()
    tick()
    expect([w.fired, loop.pending, w.seen]).toEqual([1, false, 160])
  })

  it('agent_end while busy keeps looking until idle, without a second wait', () => {
    const { w, loop, tick } = fake(100)
    w.idle = false
    w.bell = 150
    loop.ring()
    tick()
    let looks = 0
    const busyFor = 3
    const idleOf = () => ++looks > busyFor
    Object.defineProperty(w, 'idle', { get: idleOf })
    loop.idle()
    loop.idle()
    tick()
    expect(w.fired).toBe(1)
  })

  it('a ring while the server runs in another session is shown, not turned', () => {
    const { w, loop, tick } = fake(100)
    w.away = { pid: 4242 }
    w.bell = 150
    loop.ring()
    tick()
    expect([w.fired, w.shown, w.seen]).toEqual([0, 1, 150])
  })

  it('a wake-seen in whole ms (Bun) and a doorbell with a fraction (Node) are the same ring', () => {
    const { w, loop, tick } = fake(1_794_400_776_934)
    w.bell = 1_794_400_776_934 + 0.000015
    loop.ring()
    tick()
    expect(w.fired).toBe(0)
  })

  it('no doorbell is no ring', () => {
    const { w, loop, tick } = fake(100)
    loop.ring()
    tick()
    expect(w.fired).toBe(0)
  })
})

describe('the pieces', () => {
  it('targetOf reads --as and --dir of the bag server in .omp/mcp.json, --dir defaulting as bag does', () => {
    const cwd = join(tmp.dir, `t${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    expect(targetOf(cwd)).toBeNull()
    const write = (args: unknown) =>
      writeFileSync(join(cwd, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { bag: { args } } }))
    write(['m', '--as', 'omp', '--dir', '/h/.bag'])
    expect(targetOf(cwd)).toEqual({ name: 'omp', home: '/h/.bag' })
    write(['m', '--as', 'omp'])
    expect(targetOf(cwd, { HOME: '/u' })).toEqual({ name: 'omp', home: '/u/.bag' })
    expect(targetOf(cwd, { AC_HOME: '/a', HOME: '/u' })).toEqual({ name: 'omp', home: '/a' })
    write(['m', '--relay', 'x'])
    expect(targetOf(cwd)).toBeNull()
    writeFileSync(join(cwd, '.omp', 'mcp.json'), 'not json')
    expect(targetOf(cwd)).toBeNull()
  })

  it('holderOf names a live holder that is not this session, and none for ours, a dead pid or no lock', () => {
    const dir = join(tmp.dir, `l${n++}`)
    mkdirSync(dir)
    const lock = join(dir, 'mcp.lock')
    expect(holderOf(lock)).toBeNull()
    writeFileSync(lock, JSON.stringify({ pid: process.pid, cwd: '/x', host: 'omp' }))
    expect(holderOf(lock, 1, () => 999)).toEqual({ pid: process.pid, cwd: '/x', host: 'omp' })
    expect(holderOf(lock, 999, () => 999)).toBeNull()
    writeFileSync(lock, JSON.stringify({ pid: process.pid, ppid: 77 }))
    expect(holderOf(lock, 77)).toBeNull()
    writeFileSync(lock, JSON.stringify({ pid: 2 ** 31 - 2 }))
    expect(holderOf(lock, 1, () => 999)).toBeNull()
    writeFileSync(lock, `${process.pid}\n`)
    expect(holderOf(lock, 1, () => 999)).toBeNull()
  })

  it('refusal lets only the main interactive session wake', () => {
    expect(refusal('tui', 'main')).toBeNull()
    expect(refusal('print', 'main')).toContain('print')
    expect(refusal('rpc', 'main')).toContain('--mode rpc')
    expect(refusal('tui', 'sub')).toContain('spawned')
  })

  it('writeFacts merges into host-facts.json, mode 0600, keeping fields it does not refresh', () => {
    const state = join(tmp.dir, `f${n++}`, 'state', 'bob')
    writeFacts(state, { model: 'p/m', cost_usd: 0.5 }, new Date('2026-11-11T12:00:00Z'))
    writeFacts(state, { context_percent: 12 }, new Date('2026-11-11T12:01:00Z'))
    const file = join(state, 'host-facts.json')
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({
      v: 1,
      host: 'omp',
      updated_at: '2026-11-11T12:01:00.000Z',
      model: 'p/m',
      cost_usd: 0.5,
      context_percent: 12,
    })
    expect(statSync(file).mode & 0o777).toBe(0o600)
  })

  it('mtimeOf reads a missing doorbell as 0, and holderOf finds this process its own parent through ps', () => {
    expect(mtimeOf(join(tmp.dir, 'no-such-bell'))).toBe(0)
    const dir = join(tmp.dir, `l${n++}`)
    mkdirSync(dir)
    writeFileSync(join(dir, 'mcp.lock'), JSON.stringify({ pid: process.pid }))
    expect(holderOf(join(dir, 'mcp.lock'), process.ppid)).toBeNull()
    expect(holderOf(join(dir, 'mcp.lock'), 1)).toEqual({ pid: process.pid })
  })

  it('seenIn reads what wake-hook writes', () => {
    const f = join(tmp.dir, `s${n++}`)
    writeFileSync(f, '1731322800123.456\n')
    expect(seenIn(f)).toBe(1731322800123.456)
    writeFileSync(f, 'x')
    expect(seenIn(f)).toBeNaN()
  })

  it('the texts name the identity, and the holder when it is elsewhere', () => {
    expect(wakeText('omp')).toBe(
      'bag: mail arrived for omp: read it with the bag inbox tool and show it to your person. ' +
        'Answer only when your person asks, or when it plainly asks a question they already told you to answer.',
    )
    expect(wakeText('omp')).not.toMatch(/answer it|then answer|reply to it/i)
    expect(wakeText('omp', ['L1', 'L2'])).toMatch(/answer\. L1 L2$/)
    expect(awayText('omp', { pid: 9, cwd: '/w', host: 'omp' })).toContain('(pid 9, /w, omp)')
  })
})

describe('the extension factory', () => {
  /** A fake omp: handlers by event, the messages sent, timers run by hand. */
  function omp(cwd: string, mode = 'tui', kind = 'main') {
    const handlers = new Map<string, ((e: unknown, ctx: unknown) => void)[]>()
    const sent: { content: string; options: unknown }[] = []
    const timers: { fn: () => void; ms: number; every: boolean }[] = []
    const ctx = {
      cwd,
      mode,
      agent: { kind },
      model: { provider: 'deepinfra', id: 'm' },
      idle: true,
      isIdle() {
        return this.idle
      },
      getContextUsage: () => ({ tokens: 10, percent: 1 }),
      sessionManager: { getSessionId: () => 's1', getUsageStatistics: () => ({ cost: 0.25 }) },
      setTimeout: (fn: () => void, ms: number) => timers.push({ fn, ms, every: false }),
      setInterval: (fn: () => void, ms: number) => timers.push({ fn, ms, every: true }),
    }
    const pi = {
      on: (event: string, h: (e: unknown, ctx: unknown) => void) =>
        handlers.set(event, [...(handlers.get(event) ?? []), h]),
      sendMessage: (m: { content: string }, options: unknown) => sent.push({ content: m.content, options }),
    }
    bagWake(pi as never)
    const emit = (event: string) => {
      for (const h of handlers.get(event) ?? []) h({}, ctx)
    }
    const runOnce = () => {
      const due = timers.filter((t) => !t.every)
      timers.splice(0, timers.length, ...timers.filter((t) => t.every))
      for (const t of due) t.fn()
    }
    return { ctx, sent, timers, emit, runOnce, handlers }
  }

  function project(home: string): string {
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    writeFileSync(
      join(cwd, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['m', '--as', 'bob', '--dir', home] } } }),
    )
    return cwd
  }

  it('wakes the main session on a ring, polls every POLL_MS, and writes the host facts', async () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    writeFileSync(join(state, 'doorbell'), '')
    const o = omp(project(home))
    o.emit('session_start')
    expect(o.timers.some((t) => t.every && t.ms === POLL_MS)).toBe(true)
    o.runOnce()
    expect(o.sent.map((s) => s.content)).toEqual([wakeText('bob')])
    expect(o.sent[0]?.options).toEqual({ triggerTurn: true })
    const facts = JSON.parse(readFileSync(join(state, 'host-facts.json'), 'utf8'))
    expect([facts.host, facts.main_session, facts.model, facts.context_percent]).toEqual([
      'omp',
      true,
      'deepinfra/m',
      1,
    ])
    expect([facts.cost_usd, facts.session_id, facts.host_pid]).toEqual([0.25, 's1', process.pid])
    expect([facts.v, facts.host_version, typeof facts.updated_at, facts.context_tokens]).toEqual([
      1,
      null,
      'string',
      10,
    ])
    o.emit('agent_end')
    o.emit('session_shutdown')
  })

  it('a wake carries the loop line for 3 unseen from one peer, and not after the person types', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    const peer = `ed25519:${'d'.repeat(64)}`
    writeFileSync(
      join(home, 'names.json'),
      JSON.stringify({ version: 1, names: { carol: { address: peer } } }),
    )
    new SqliteStore(join(state, 'edge.sqlite'), { lock: false }).close()
    const db = new DatabaseSync(join(state, 'edge.sqlite'))
    const t = Math.floor(Date.now() / 1000) - 5
    for (const i of [1, 2, 3])
      db.prepare(
        `INSERT INTO inbox (relay, mailbox, cursor, bytes, id, state, content, received_at, updated_at)
         VALUES ('r', 'm', ?, ?, ?, 'acked', '{}', ?, 0)`,
      ).run(i, Buffer.from(JSON.stringify({ from: peer, auth: [] })), `x${i}`, t)
    db.close()
    writeFileSync(join(state, 'wake-seen'), '1\n')
    const bell = join(state, 'doorbell')
    writeFileSync(bell, '')
    const o = omp(project(home))
    o.emit('session_start')
    o.runOnce()
    expect(o.sent[0]?.content).toBe(
      `${wakeText('bob')} 3 unread from carol in ten minutes: this looks like a loop: show your person and do not answer.`,
    )
    const input = (source: string) => {
      for (const h of o.handlers.get('input') ?? []) h({ type: 'input', text: 'hi', source }, o.ctx)
    }
    input('rpc')
    utimesSync(bell, new Date(Date.now() + 5000), new Date(Date.now() + 5000))
    o.timers.find((x) => x.ms === POLL_MS)?.fn()
    o.runOnce()
    expect(o.sent[1]?.content).toContain('this looks like a loop')
    input('interactive')
    utimesSync(bell, new Date(Date.now() + 9000), new Date(Date.now() + 9000))
    o.timers.find((x) => x.ms === POLL_MS)?.fn()
    o.runOnce()
    expect(o.sent[2]?.content).toBe(wakeText('bob'))
    o.emit('session_shutdown')
  })

  /** Waits up to 3 s for the file event to schedule the settle; failing that, runs the poll, which rings the same. */
  async function rung(o: ReturnType<typeof omp>): Promise<void> {
    for (let i = 0; i < 150 && !o.timers.some((t) => !t.every); i++)
      await new Promise((r) => setTimeout(r, 20))
    if (!o.timers.some((t) => !t.every)) for (const t of o.timers.filter((t) => t.ms === POLL_MS)) t.fn()
  }

  it('a file event on the doorbell rings, agent_end writes the facts, and a ring after a pending one is handled once', async () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    const o = omp(project(home))
    o.emit('session_start')
    o.runOnce()
    expect(o.sent.length).toBe(0)
    const bell = join(state, 'doorbell')
    writeFileSync(bell, '')
    await rung(o)
    o.runOnce()
    expect(o.sent.map((s) => s.content)).toEqual([wakeText('bob')])
    o.ctx.idle = false
    utimesSync(bell, new Date(Date.now() + 5000), new Date(Date.now() + 5000))
    await rung(o)
    o.runOnce()
    expect(o.sent.length).toBe(1)
    o.ctx.idle = true
    o.emit('agent_end')
    o.runOnce()
    expect(o.sent.length).toBe(2)
    const facts = JSON.parse(readFileSync(join(state, 'host-facts.json'), 'utf8'))
    expect(facts.main_session).toBe(true)
    o.emit('session_shutdown')
  }, 20_000)

  it('a ring while the server runs in another session is shown as a next-turn message, not a turn', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    writeFileSync(join(state, 'doorbell'), '')
    writeFileSync(
      join(state, 'mcp.lock'),
      JSON.stringify({ pid: process.pid, ppid: 1, cwd: '/elsewhere', host: 'omp' }),
    )
    const o = omp(project(home))
    o.emit('session_start')
    o.runOnce()
    expect(o.sent.map((s) => s.options)).toEqual([{ deliverAs: 'nextTurn' }])
    expect(o.sent[0]?.content).toContain('(pid')
  })

  it('a print session neither wakes, watches nor writes the facts, and says why', () => {
    const home = join(tmp.dir, `h${n++}`)
    const o = omp(project(home), 'print')
    const err: string[] = []
    const write = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((s: string) => {
      err.push(String(s))
      return true
    }) as typeof process.stderr.write
    try {
      o.emit('session_start')
    } finally {
      process.stderr.write = write
    }
    expect(err.join('')).toContain('no wake for bob here: a print session')
    expect(o.timers.some((t) => t.ms === POLL_MS)).toBe(false)
    expect(existsSync(join(home, 'state', 'bob', 'host-facts.json'))).toBe(false)
  })

  it('a folder without a bag server in .omp/mcp.json does nothing', () => {
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(cwd)
    const o = omp(cwd)
    o.emit('session_start')
    expect([o.sent.length, o.timers.length]).toEqual([0, 0])
  })
})

describe('the loop guard', () => {
  const A = `ed25519:${'a'.repeat(64)}`
  const B = `ed25519:${'b'.repeat(64)}`
  const NOW = 1_800_000_000
  const at = (peer: string, n: number, t = NOW, tag = 'm'): Arrival[] =>
    Array.from({ length: n }, (_, i) => ({ id: `${tag}${peer.at(-1)}${i}`, peer, at: t - i }))
  const names = new Map([[A, 'alice']])
  const LOOP = 'this looks like a loop: show your person and do not answer.'

  it('counts unread per peer: nothing at 0 and 2, a line at 3 and 7', () => {
    expect([LOOP_S, LOOP_AT]).toEqual([600, 3])
    expect(loopLines([], NOW, 0, names)).toEqual([])
    expect(loopLines(at(A, 2), NOW, 0, names)).toEqual([])
    expect(loopLines(at(A, 3), NOW, 0, names)).toEqual([`3 unread from alice in ten minutes: ${LOOP}`])
    expect(loopLines(at(A, 7), NOW, 0, names)).toEqual([`7 unread from alice in ten minutes: ${LOOP}`])
  })

  it('counts two peers apart, names an unknown one by its short address, and counts an id once', () => {
    expect(loopLines([...at(A, 2), ...at(B, 2)], NOW, 0, names)).toEqual([])
    const lines = loopLines([...at(A, 3), ...at(B, 4), ...at(B, 4)], NOW, 0, names)
    expect(lines).toEqual([
      `3 unread from alice in ten minutes: ${LOOP}`,
      `4 unread from ed25519:bbbbbbbb... in ten minutes: ${LOOP}`,
    ])
    expect(lines.join(' ')).not.toContain(B)
  })

  it('leaves out messages older than ten minutes and those before the person last typed', () => {
    const old = at(A, 5, NOW - LOOP_S - 1, 'o')
    expect(loopLines([...old, ...at(A, 2)], NOW, 0, names)).toEqual([])
    expect(loopLines(at(A, 3, NOW - LOOP_S + 2), NOW, 0, names)).toHaveLength(1)
    const seen = [...at(A, 4, NOW - 100, 'r'), ...at(A, 2, NOW, 'u')]
    expect(loopLines(seen, NOW, NOW - 50, names)).toEqual([])
    expect(loopLines(seen, NOW, NOW - 200, names)).toEqual([`6 unread from alice in ten minutes: ${LOOP}`])
  })

  it('reads accepted rows from edge.sqlite beside a writer, by principal, and [] for no store', () => {
    const state = join(tmp.dir, `st${n++}`)
    mkdirSync(state, { recursive: true })
    new SqliteStore(join(state, 'edge.sqlite'), { lock: false }).close()
    const db = new DatabaseSync(join(state, 'edge.sqlite'))
    const put = db.prepare(
      `INSERT INTO inbox (relay, mailbox, cursor, bytes, id, state, reason, content, received_at, updated_at)
       VALUES ('r', 'm', ?, ?, ?, ?, ?, ?, ?, 0)`,
    )
    const env = (from: string, auth: object[] = []) => Buffer.from(JSON.stringify({ from, auth }))
    const S = `ed25519:${'c'.repeat(64)}`
    put.run(1, env(A), 'i1', 'acked', null, '{}', NOW)
    put.run(2, env(S, [{ iss: B, sub: S }]), 'i2', 'routed', null, '{}', NOW - 10)
    put.run(3, env(A), 'i3', 'acked', 'duplicate', '{}', NOW)
    put.run(4, env(A), 'i4', 'rejected', 'bad-sig', null, NOW)
    put.run(5, env(A), 'i5', 'received', null, null, NOW)
    put.run(6, env(A), 'i6', 'acked', null, '{}', NOW - LOOP_S - 1)
    expect(arrivals(state, NOW)).toEqual([
      { id: 'i1', peer: A, at: NOW },
      { id: 'i2', peer: B, at: NOW - 10 },
    ])
    db.close()
    expect(arrivals(join(tmp.dir, 'none'), NOW)).toEqual([])
  })

  it('names come from the book, and an unreadable book names nothing', () => {
    const home = join(tmp.dir, `nb${n++}`)
    mkdirSync(home, { recursive: true })
    expect(namesOf(home).size).toBe(0)
    writeFileSync(join(home, 'names.json'), JSON.stringify({ version: 1, names: { alice: { address: A } } }))
    expect(namesOf(home).get(A)).toBe('alice')
  })
})

// The bag service (packages/shim/README.md): the shim's channel (a fake one here, on a real unix
// socket under a short /tmp home, as packages/shim's tests do), its .bound and .ring files, and the per-folder mode
// left as it was when they are absent.
describe('the service: channel, bridge and ring', () => {
  const short = mkdtempSync('/tmp/bow-')
  const servers: Server[] = []
  afterAll(() => {
    for (const s of servers) s.close()
    rmSync(short, { recursive: true, force: true })
  })
  const DEAD = 2 ** 31 - 2

  /** A fake shim: its channel socket and index for this process, answering each request line with `answer` (undefined: never). */
  async function shim(answer: (r: Record<string, unknown>) => unknown) {
    const home = join(short, `h${n++}`)
    const dir = join(home, 'run', 'shim')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const sock = `${randomBytes(4).toString('hex')}.sock`
    const secret = randomBytes(32).toString('hex')
    const got: Record<string, unknown>[] = []
    const server = createServer((c) => {
      let buf = ''
      c.setEncoding('utf8')
      c.on('error', () => undefined)
      c.on('data', (d: string) => {
        buf += d
        const nl = buf.indexOf('\n')
        if (nl < 0) return
        const r = JSON.parse(buf.slice(0, nl)) as Record<string, unknown>
        got.push(r)
        const a = answer(r)
        if (a !== undefined) c.end(`${JSON.stringify(a)}\n`)
      })
    })
    servers.push(server)
    await new Promise<void>((r) => server.listen(join(dir, sock), () => r()))
    writeFileSync(join(dir, `${process.pid}.json`), JSON.stringify({ v: 1, sock, secret, shim: process.pid }))
    return { home, dir, secret, got }
  }

  /** A project whose bag server is the shim (service mode), or the per-folder line with `as`. */
  function project(home: string, as?: string): string {
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    const args =
      as === undefined
        ? ['/pkg/bag-shim.js', '--dir', home, '--input-hook']
        : ['m', '--as', as, '--dir', home]
    writeFileSync(join(cwd, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { bag: { args } } }))
    // Service mode as host install omp --user leaves it: the shim entry at user level too (the test's own agent dir,
    // never the real ~/.omp), since a project entry alone counts only for the default home. A per-folder project
    // clears it, so no earlier test's entry decides for it.
    const user = join(process.env.PI_CODING_AGENT_DIR as string, 'mcp.json')
    mkdirSync(dirname(user), { recursive: true })
    if (as === undefined) writeFileSync(user, JSON.stringify({ mcpServers: { bag: { args } } }))
    else rmSync(user, { force: true })
    return cwd
  }

  /** A fake omp session; with `bridge` a tui session that may answer consent (hasUI). */
  function session(cwd: string, bridge = false) {
    const handlers = new Map<string, ((e: unknown, ctx: unknown) => unknown)[]>()
    const sent: { content: string; options: unknown }[] = []
    const timers: { fn: () => void; ms: number; every: boolean }[] = []
    const status: (string | undefined)[] = []
    const notes: string[] = []
    const ctx = {
      cwd,
      mode: 'tui',
      hasUI: bridge,
      agent: { kind: 'main' },
      ui: {
        confirm: async () => true,
        input: async () => undefined,
        setStatus: (key: string, text: string | undefined) => {
          if (key === WAKE_STATUS) status.push(text)
        },
        setWidget: () => undefined,
        notify: (m: string) => notes.push(m),
      },
      idle: true,
      isIdle() {
        return this.idle
      },
      setTimeout: (fn: () => void, ms: number) => timers.push({ fn, ms, every: false }),
      setInterval: (fn: () => void, ms: number) => timers.push({ fn, ms, every: true }),
    }
    bagWake({
      on: (e: string, h: (e: unknown, ctx: unknown) => unknown) =>
        handlers.set(e, [...(handlers.get(e) ?? []), h]),
      sendMessage: (m: { content: string }, options: unknown) => sent.push({ content: m.content, options }),
    } as never)
    const emit = (e: string) => {
      for (const h of handlers.get(e) ?? []) h({}, ctx)
    }
    const input = (text: string, source = 'interactive') =>
      (handlers.get('input') ?? []).map((h) => h({ type: 'input', text, images: [], source }, ctx))[0]
    const runOnce = () => {
      const due = timers.filter((t) => !t.every)
      timers.splice(0, timers.length, ...timers.filter((t) => t.every))
      for (const t of due) t.fn()
    }
    const poll = () => {
      for (const t of timers.filter((t) => t.ms === RING_POLL_MS)) t.fn()
      runOnce()
    }
    return { ctx, sent, status, notes, emit, input, runOnce, poll, timers }
  }

  const until = async (ok: () => boolean) => {
    for (let i = 0; i < 150 && !ok(); i++) await new Promise((r) => setTimeout(r, 20))
  }

  const stderr = async (fn: () => Promise<unknown>): Promise<string> => {
    const err: string[] = []
    const write = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((s: string) => {
      err.push(String(s))
      return true
    }) as typeof process.stderr.write
    try {
      await fn()
    } finally {
      process.stderr.write = write
    }
    return err.join('')
  }

  it('typedName takes the bind word as the shim does, and shimHomeOf finds a shim entry and its home', () => {
    expect([
      typedName('use omp-3'),
      typedName('  USE omp.x_1  '),
      typedName('use Omp'),
      typedName('use omp now'),
    ]).toEqual(['omp-3', 'omp.x_1', null, null])
    const cwd = project('/h/.bag')
    // a project entry counts only when its --dir is the default home
    expect(shimHomeOf(cwd, {})).toBeNull()
    expect(shimHomeOf(cwd, { HOME: '/h' })).toBe('/h/.bag')
    expect(shimHomeOf(cwd, { HOME: '/other' })).toBeNull()
    const agent = join(tmp.dir, `a${n++}`)
    mkdirSync(agent)
    writeFileSync(
      join(agent, 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['/v/bag-shim.js'] } } }),
    )
    const plain = join(tmp.dir, `p${n++}`)
    mkdirSync(plain)
    expect(shimHomeOf(plain, { PI_CODING_AGENT_DIR: agent, HOME: '/u' })).toBe('/u/.bag')
    expect(shimHomeOf(plain, { PI_CODING_AGENT_DIR: agent, AC_HOME: '/a' })).toBe('/a')
    expect(shimHomeOf(project('/h/.bag', 'bob'), {})).toBeNull()
    // the user-level entry wins over a planted project entry naming another home
    const planted = project('/evil/.bag')
    expect(shimHomeOf(planted, { PI_CODING_AGENT_DIR: agent, HOME: '/u' })).toBe('/u/.bag')
    expect(shimHomeOf(planted, { HOME: '/u' })).toBeNull()
  })

  it('use <name> is sent on the channel and the prompt is handled', async () => {
    const s = await shim(() => ({ bound: true, as: 'omp-3' }))
    const o = session(project(s.home))
    expect(await o.input('use omp-3')).toEqual({ handled: true })
    expect(s.got).toEqual([{ v: 1, kind: 'use', name: 'omp-3', secret: s.secret }])
    expect(o.notes).toEqual(['bag: this session now acts as omp-3'])
  })

  it('use of an unknown identity goes on to the model; another refusal is still handled', async () => {
    const s = await shim((r) => ({
      bound: false,
      code: r.name === 'pandas' ? 'unknown-identity' : 'not-allowed',
    }))
    const o = session(project(s.home))
    expect(await o.input('use pandas')).toBeUndefined()
    expect(await o.input('use omp')).toEqual({ handled: true })
  })

  it('any other interactive prompt is sent as typed and not handled', async () => {
    const s = await shim(() => ({ typed: true }))
    const o = session(project(s.home))
    expect(o.input('hello there')).toBeUndefined()
    await until(() => s.got.length > 0)
    expect(s.got).toEqual([{ v: 1, kind: 'typed', secret: s.secret }])
  })

  it('an rpc prompt is not sent and not handled', async () => {
    const s = await shim(() => ({ bound: true, as: 'omp-3' }))
    const o = session(project(s.home))
    expect(o.input('use omp-3', 'rpc')).toBeUndefined()
    await new Promise((r) => setTimeout(r, 100))
    expect(s.got).toEqual([])
  })

  it('a dead or a slow shim does not hold the prompt past CHANNEL_MS and does not handle it; logged once', async () => {
    const slow = await shim(() => undefined)
    const o = session(project(slow.home))
    let took = 0
    const err = await stderr(async () => {
      const t = Date.now()
      expect(await o.input('use omp-3')).toBeUndefined()
      took = Date.now() - t
      expect(await o.input('use omp-3')).toBeUndefined()
    })
    expect(took).toBeGreaterThanOrEqual(CHANNEL_MS - 50)
    expect(took).toBeLessThan(CHANNEL_MS + 1000)
    expect(err.match(/did not answer/g)?.length).toBe(1)
    const dead = await shim(() => ({ bound: true, as: 'x' }))
    rmSync(join(dead.dir, JSON.parse(readFileSync(join(dead.dir, `${process.pid}.json`), 'utf8')).sock))
    const d = session(project(dead.home))
    const t = Date.now()
    expect(await d.input('use omp-3')).toBeUndefined()
    expect(Date.now() - t).toBeLessThan(1000)
  }, 20_000)

  /** A home with this process's .bound (shim alive) and a ring file of the given members. */
  function files(home: string) {
    const dir = join(home, 'run', 'shim')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const f = (ext: string) => join(dir, `${process.pid}.${ext}`)
    return {
      f,
      bound: (doc: unknown = { v: 1, as: ['bob'], shim: process.pid }) =>
        writeFileSync(f('bound'), typeof doc === 'string' ? doc : JSON.stringify(doc)),
      ring: (o: Record<string, unknown> = {}) =>
        writeFileSync(
          f('ring'),
          JSON.stringify({
            v: 1,
            n: 1,
            as: 'bob',
            unread: 2,
            speaking: true,
            at: null,
            shim: process.pid,
            ...o,
          }),
        ),
    }
  }

  it('5b rule 2 and 5a: a ring or bound file that does not parse, has v 2, or names a dead shim is none', () => {
    const home = join(tmp.dir, `h${n++}`)
    const x = files(home)
    x.ring()
    x.bound()
    expect(ringIn(home)?.n).toBe(1)
    expect(boundIn(home)).toEqual(['bob'])
    for (const bad of [{ v: 2 }, { shim: DEAD }]) {
      x.ring(bad)
      expect(ringIn(home)).toBeNull()
    }
    writeFileSync(x.f('ring'), '{"v":1,')
    expect(ringIn(home)).toBeNull()
    for (const bad of [{ v: 2, as: ['bob'], shim: process.pid }, { v: 1, as: ['bob'], shim: DEAD }, 'nope']) {
      x.bound(bad)
      expect(boundIn(home)).toBeNull()
    }
  })

  /** RingLoop over a fake ring file and session. */
  function rings() {
    const w = {
      bound: true,
      ring: null as RingDoc | null,
      seen: null as RingSeen | null,
      idle: true,
      fired: [] as string[],
      quiet: [] as RingDoc[],
      timers: [] as (() => void)[],
    }
    const loop = new RingLoop({
      bound: () => w.bound,
      ring: () => w.ring,
      seen: () => w.seen,
      remember: (s) => {
        w.seen = s
      },
      idle: () => w.idle,
      fire: (as) => w.fired.push(as),
      quiet: (r) => w.quiet.push(r),
      later: (fn) => w.timers.push(fn),
    })
    const tick = () => {
      for (let i = 0; i < 100 && w.timers.length > 0; i++) (w.timers.shift() as () => void)()
    }
    const at = (n: number, shim = 10, speaking = true): RingDoc => ({
      n,
      as: 'omp',
      unread: 1,
      speaking,
      shim,
    })
    return { w, loop, tick, at }
  }

  it('5b rule 3: only a higher n of the same shim, or any n of another shim pid, is handled', () => {
    const { w, loop, tick, at } = rings()
    w.ring = at(2)
    loop.ring()
    tick()
    expect([w.fired, w.seen]).toEqual([['omp'], { shim: 10, n: 2 }])
    for (const r of [at(2), at(1)]) {
      w.ring = r
      loop.ring()
      tick()
    }
    expect(w.fired.length).toBe(1)
    w.ring = at(3)
    loop.ring()
    tick()
    expect(w.fired.length).toBe(2)
    w.ring = at(1, 11)
    loop.ring()
    tick()
    expect([w.fired.length, w.seen]).toEqual([3, { shim: 11, n: 1 }])
  })

  it('5b rule 4: speaking true is one turn (pending while busy), speaking false the notice and no turn', () => {
    const { w, loop, tick, at } = rings()
    w.idle = false
    w.ring = at(1)
    loop.ring()
    tick()
    expect([w.fired.length, loop.pending]).toEqual([0, true])
    w.idle = true
    loop.idle()
    tick()
    expect([w.fired, loop.pending]).toEqual([['omp'], false])
    w.idle = false
    w.ring = at(2, 10, false)
    loop.ring()
    tick()
    expect([w.fired.length, w.quiet.map((r) => r.n), loop.pending]).toEqual([1, [2], false])
    w.bound = false
    w.ring = at(3)
    loop.ring()
    tick()
    expect(w.fired.length).toBe(1)
  })

  it('with a valid .bound the ring file is the only wake: the doorbell does not wake, a ring does, once', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    writeFileSync(join(state, 'doorbell'), '')
    const x = files(home)
    x.bound()
    const o = session(project(home, 'bob'))
    o.emit('session_start')
    o.runOnce()
    expect(o.sent).toEqual([])
    x.ring()
    o.poll()
    expect(o.sent).toEqual([{ content: wakeText('bob'), options: { triggerTurn: true } }])
    expect(readFileSync(x.f('ring-seen'), 'utf8')).toBe(`${process.pid} 1\n`)
    o.poll()
    expect(o.sent.length).toBe(1)
    o.emit('session_shutdown')
  })

  it('a .bound that comes while a doorbell ring settles stops that wake', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    writeFileSync(join(state, 'doorbell'), '')
    const x = files(home)
    const o = session(project(home, 'bob'))
    o.emit('session_start')
    x.bound()
    o.runOnce()
    expect(o.sent).toEqual([])
    o.emit('session_shutdown')
  }, 20_000)

  it('a session that starts bound takes its first doorbell look only once unbound: old mail does not wake', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'doorbell'), '')
    const x = files(home)
    x.bound()
    const o = session(project(home, 'bob'))
    o.emit('session_start')
    o.runOnce()
    rmSync(x.f('bound'))
    for (const t of o.timers.filter((t) => t.ms === POLL_MS)) t.fn()
    o.runOnce()
    expect(o.sent).toEqual([])
    expect(seenIn(join(state, 'wake-seen'))).toBe(mtimeOf(join(state, 'doorbell')))
    o.emit('session_shutdown')
  }, 20_000)

  it('no .bound (or a dead one) means the doorbell as today, and the ring file is not read', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    writeFileSync(join(state, 'doorbell'), '')
    const x = files(home)
    x.ring({ as: 'other' })
    x.bound({ v: 1, as: ['bob'], shim: DEAD })
    const o = session(project(home, 'bob'))
    o.emit('session_start')
    o.runOnce()
    o.poll()
    expect(o.sent.map((s) => s.content)).toEqual([wakeText('bob')])
    expect(existsSync(x.f('ring-seen'))).toBe(false)
    o.emit('session_shutdown')
  })

  it('speaking false shows the quiet notice in the footer and starts no turn; typing clears it', async () => {
    const home = join(tmp.dir, `h${n++}`)
    const x = files(home)
    x.bound()
    const o = session(project(home))
    o.emit('session_start')
    x.ring({ speaking: false, unread: 3 })
    o.poll()
    expect(o.sent).toEqual([])
    expect(o.status).toEqual([
      'bag: 3 unread for bob, shown in the window you last typed in for bob; type here to have the next mail shown here',
    ])
    o.input('hi')
    expect(o.status.at(-1)).toBeUndefined()
    o.emit('session_shutdown')
  })

  it('a quiet ring for a local pair request with nothing unread says a request waits, not 0 unread', () => {
    const home = join(tmp.dir, `h${n++}`)
    const x = files(home)
    x.bound()
    const o = session(project(home))
    o.emit('session_start')
    x.ring({ speaking: false, unread: 0, requests: 1 })
    o.poll()
    expect(o.sent).toEqual([])
    expect(o.status).toEqual([
      'bag: a request from your own identity waits for bob; the window you last typed in for bob asks you',
    ])
    o.emit('session_shutdown')
  })

  it('a .ring-seen the shim removed is written again at the next ring, and the old ring does not wake again', () => {
    const home = join(tmp.dir, `h${n++}`)
    const x = files(home)
    x.bound()
    const o = session(project(home))
    o.emit('session_start')
    x.ring()
    o.poll()
    rmSync(x.f('ring-seen'))
    o.poll()
    expect(o.sent.length).toBe(1)
    x.ring({ n: 2 })
    o.poll()
    expect(o.sent.map((s) => s.content)).toEqual([wakeText('bob'), wakeText('bob')])
    expect(readFileSync(x.f('ring-seen'), 'utf8')).toBe(`${process.pid} 2\n`)
    o.emit('session_shutdown')
  })
})

describe("ompConfirm: a link question's answer (L1)", () => {
  /** omp's confirm as the research read it: resolves the person's choice, else false once its signal aborts. */
  const ui = (said: boolean | 'wait' | 'throw', opened: unknown[] = []): Pick<ConsentUi, 'confirm'> => ({
    confirm: (_t, _m, options) => {
      opened.push(options?.initialIndex)
      if (said === 'throw') return Promise.reject(new Error('ui gone'))
      if (said !== 'wait') return Promise.resolve(said)
      return new Promise((r) => options?.signal?.addEventListener('abort', () => r(false)))
    },
  })

  /** A clock that moves `ms` between the confirm's open and its answer. */
  const after = (ms: number) => {
    let t = 0
    return () => {
      t += ms
      return t
    }
  }

  it('Yes is true and an explicit No (or an Esc, which omp cannot tell apart) is false, opening on No', async () => {
    const opened: unknown[] = []
    expect(await ompConfirm(ui(true, opened), 'T', 'M', 1000, undefined, after(OMP_FAST_MS))).toBe(true)
    expect(await ompConfirm(ui(false, opened), 'T', 'M', 1000, undefined, after(OMP_FAST_MS))).toBe(false)
    expect(opened).toEqual([1, 1])
  })

  it("a false faster than any person (omp's aborted session signal resolves at once) is null, never a No (9b)", async () => {
    expect(await ompConfirm(ui(false), 'T', 'M', 1000, undefined, after(1))).toBeNull()
  })

  it('a true faster than any person is null too, never a Yes: no host answers for the person (0.4.4)', async () => {
    expect(await ompConfirm(ui(true), 'T', 'M', 1000, undefined, after(1))).toBeNull()
    expect(await ompConfirm(ui(true), 'T', 'M', 1000, undefined, after(OMP_FAST_MS - 1))).toBeNull()
    expect(await ompConfirm(ui(true), 'T', 'M', 1000, undefined, after(OMP_FAST_MS))).toBe(true)
  })

  it('a confirm its own timeout aborted, or one that throws, is null: no answer, never a No', async () => {
    expect(await ompConfirm(ui('wait'), 'T', 'M', 20)).toBeNull()
    expect(await ompConfirm(ui('throw'), 'T', 'M', 1000)).toBeNull()
  })

  it('a confirm the service withdraws is dismissed at once and is null (item j)', async () => {
    const withdrawn = new AbortController()
    const asked = ompConfirm(ui('wait'), 'T', 'M', 60_000, withdrawn.signal)
    withdrawn.abort()
    expect(await asked).toBeNull()
  })
})

describe('the consent link to the bag service (item 7, C2)', () => {
  it('registers for its pid, answers each ask over the link, after a restart presents the secret', async () => {
    const home = join('/tmp', `bwl-${process.pid}-${n++}`)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'run', 'service.token'), 'ab'.repeat(32))
    const got: Record<string, unknown>[] = []
    const conns: import('node:net').Socket[] = []
    const server: Server = createServer((c) => {
      conns.push(c)
      let buf = ''
      c.on('data', (b: Buffer) => {
        buf += b.toString()
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          const m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
          buf = buf.slice(i + 1)
          got.push(m)
          const answer =
            m.method === 'service/consent-register' ? { secret: 'f'.repeat(64) } : { contract: 1 }
          if (m.id !== undefined && m.method !== 'service/consent-answer')
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: answer })}\n`)
        }
      })
    })
    await new Promise<void>((r) => server.listen(join(home, 'run', 'service.sock'), () => r()))
    const asked: string[] = []
    let dismissed = false
    const l = consentLink(
      home,
      4242,
      async (title, message, _ms, withdrawn) => {
        asked.push(`${title} | ${message}`)
        // W: a confirm left open until the service withdraws it.
        if (title === 'W')
          return new Promise((r) =>
            withdrawn.addEventListener('abort', () => {
              dismissed = true
              r(null)
            }),
          )
        return title === 'T' ? true : null
      },
      30_000,
    )
    const until = async (f: () => boolean, ms = 3000) => {
      for (let i = 0; i < ms / 10 && !f(); i++) await new Promise((r) => setTimeout(r, 10))
    }
    const registers = () => got.filter((m) => m.method === 'service/consent-register').map((m) => m.params)
    await until(() => registers().length === 1)
    expect(got[0]?.params).toMatchObject({ token: 'ab'.repeat(32), host: 'omp' })
    expect(registers()).toEqual([{ pid: 4242, kinds: ['confirm'], call_ms: 30_000 }])
    const ask = { method: 'service/consent-ask', params: { id: 'q1', title: 'T', message: 'M', ms: 1000 } }
    conns[0]?.write(`${JSON.stringify({ jsonrpc: '2.0', ...ask })}\n`)
    await until(() => got.some((m) => m.method === 'service/consent-answer'))
    expect(asked).toEqual(['T | M'])
    expect(got.find((m) => m.method === 'service/consent-answer')?.params).toEqual({
      id: 'q1',
      accepted: true,
    })
    // No answer (an aborted confirm) goes over the link as accepted null, never false.
    const none = { method: 'service/consent-ask', params: { id: 'q2', title: 'U', message: 'M', ms: 1000 } }
    conns[0]?.write(`${JSON.stringify({ jsonrpc: '2.0', ...none })}\n`)
    const answers = () => got.filter((m) => m.method === 'service/consent-answer')
    await until(() => answers().length === 2)
    expect(answers()[1]?.params).toEqual({ id: 'q2', accepted: null })
    // A withdraw (the tool call ended, or the wait ran out) dismisses the open confirm, and no answer is sent for it.
    const open = { method: 'service/consent-ask', params: { id: 'q3', title: 'W', message: 'M', ms: 25_000 } }
    conns[0]?.write(`${JSON.stringify({ jsonrpc: '2.0', ...open })}\n`)
    await until(() => asked.length === 3)
    conns[0]?.write(
      `${JSON.stringify({ jsonrpc: '2.0', method: 'service/consent-withdraw', params: { id: 'q3' } })}\n`,
    )
    await until(() => dismissed)
    expect(dismissed).toBe(true)
    await new Promise((r) => setTimeout(r, 50))
    expect(answers().map((m) => (m.params as { id: string }).id)).toEqual(['q1', 'q2'])
    // The service restarts (the link's connection ends): it opens again and presents the secret, kept in memory only.
    conns[0]?.destroy()
    await until(() => registers().length === 2, RELINK_MS + 2000)
    expect(registers()[1]).toEqual({ pid: 4242, secret: 'f'.repeat(64), kinds: ['confirm'], call_ms: 30_000 })
    expect(readdirSync(join(home, 'run')).sort()).toEqual(['service.sock', 'service.token'])
    l.close()
    for (const c of conns) c.destroy()
    await new Promise<void>((r) => server.close(() => r()))
    rmSync(home, { recursive: true, force: true })
  }, 10_000)
})

describe('the link in 0.4.2: text, show and call_ms', () => {
  /** A fake service on a unix socket: answers hello and register, and records every message. */
  async function service() {
    const home = join('/tmp', `bwl2-${process.pid}-${n++}`)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'run', 'service.token'), 'ab'.repeat(32))
    const got: Record<string, unknown>[] = []
    const conns: import('node:net').Socket[] = []
    const server: Server = createServer((c) => {
      conns.push(c)
      let buf = ''
      c.on('data', (b: Buffer) => {
        buf += b.toString()
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          const m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
          buf = buf.slice(i + 1)
          got.push(m)
          if (m.id !== undefined && m.method !== 'service/consent-answer')
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} })}\n`)
        }
      })
    })
    await new Promise<void>((r) => server.listen(join(home, 'run', 'service.sock'), () => r()))
    const send = (method: string, params: Record<string, unknown>) =>
      conns[0]?.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`)
    const answers = () => got.filter((m) => m.method === 'service/consent-answer').map((m) => m.params)
    const close = async () => {
      for (const c of conns) c.destroy()
      await new Promise<void>((r) => server.close(() => r()))
      rmSync(home, { recursive: true, force: true })
    }
    return { home, got, conns, send, answers, close }
  }
  const until = async (f: () => boolean, ms = 3000) => {
    for (let i = 0; i < ms / 10 && !f(); i++) await new Promise((r) => setTimeout(r, 10))
  }

  it('registers kinds and call_ms; a text ask answers its text, a show sets the widget and a withdraw clears it', async () => {
    const svc = await service()
    const widgets: (string[] | undefined)[] = []
    const inputs: unknown[][] = []
    let closedOpen = false
    const l = consentLink(
      svc.home,
      4243,
      {
        confirm: async () => true,
        input: async (title, placeholder, ms, withdrawn, message) => {
          if (title === 'wait')
            return new Promise((r) =>
              withdrawn.addEventListener('abort', () => {
                closedOpen = true
                r(null)
              }),
            )
          inputs.push([title, placeholder, ms, message])
          return title === 'none' ? null : 'pasted-code'
        },
        show: (lines) => widgets.push(lines),
      },
      130_000,
    )
    await until(() => svc.got.some((m) => m.method === 'service/consent-register'))
    expect(svc.got.find((m) => m.method === 'service/consent-register')?.params).toEqual({
      pid: 4243,
      kinds: ['confirm', 'text', 'show'],
      call_ms: 130_000,
    })
    svc.send('service/consent-ask', {
      id: 't1',
      kind: 'text',
      title: 'paste',
      message: 'M',
      ms: 120_000,
      placeholder: 'invite or code',
      max: 512,
    })
    await until(() => svc.answers().length === 1)
    // The question's message reaches the extension, which shows it beside omp's input (a title only).
    expect(inputs).toEqual([['paste', 'invite or code', 120_000, 'M']])
    expect(svc.answers()[0]).toEqual({ id: 't1', accepted: true, text: 'pasted-code' })
    svc.send('service/consent-ask', { id: 't2', kind: 'text', title: 'none', message: 'M', ms: 1000 })
    await until(() => svc.answers().length === 2)
    expect(svc.answers()[1]).toEqual({ id: 't2', accepted: null })
    svc.send('service/consent-ask', {
      id: 's1',
      kind: 'show',
      title: 'bag: pairing',
      message: 'code',
      lines: ['code 1', 'x'],
      ms: 600_000,
    })
    await until(() => widgets.length === 1)
    expect(widgets).toEqual([['code 1', 'x']])
    // A withdraw for another id leaves the widget; the show's own withdraw clears it at once. A show is never answered.
    svc.send('service/consent-withdraw', { id: 'other' })
    svc.send('service/consent-withdraw', { id: 's1' })
    await until(() => widgets.length === 2)
    expect(widgets[1]).toBeUndefined()
    // A closed link clears a widget too.
    svc.send('service/consent-ask', {
      id: 's2',
      kind: 'show',
      title: 'bag: pairing',
      message: 'code',
      lines: ['code 2'],
      ms: 600_000,
    })
    await until(() => widgets.length === 3)
    // A text field still open when the link closes is closed at once, and nothing is answered for it.
    svc.send('service/consent-ask', { id: 't3', kind: 'text', title: 'wait', message: 'M', ms: 120_000 })
    await new Promise((r) => setTimeout(r, 30))
    svc.conns[0]?.destroy()
    await until(() => widgets.length === 4 && closedOpen)
    expect(widgets[3]).toBeUndefined()
    expect(closedOpen).toBe(true)
    expect(svc.answers().map((a) => (a as { id: string }).id)).toEqual(['t1', 't2'])
    l.close()
    await svc.close()
  }, 10_000)

  it('ompInput: a trimmed answer; empty or too long asked once more, then null; Esc, timeout, withdraw and too fast are null', async () => {
    const seen: unknown[] = []
    const ui = (answers: (string | undefined | 'wait')[]): Pick<ConsentUi, 'input'> => ({
      input: (_t, _p, options) => {
        seen.push(options?.timeout)
        const a = answers.shift()
        if (a !== 'wait') return Promise.resolve(a)
        return new Promise((r) => options?.signal?.addEventListener('abort', () => r(undefined)))
      },
    })
    let t = 0
    const slow = () => (t += 1000)
    expect(await ompInput(ui([' 472-tulip-orbit-cedar ']), 'T', 'p', 60_000, undefined, slow)).toBe(
      '472-tulip-orbit-cedar',
    )
    expect(typeof seen[0]).toBe('number')
    expect(await ompInput(ui(['', 'x'.repeat(513)]), 'T', 'p', 60_000, undefined, slow)).toBeNull()
    expect(await ompInput(ui(['', 'ok']), 'T', 'p', 60_000, undefined, slow)).toBe('ok')
    expect(await ompInput(ui([undefined]), 'T', 'p', 60_000, undefined, slow)).toBeNull()
    // Answered faster than any person (a forced test build's input): no answer, never the code.
    let f = 0
    const fast = () => (f += OMP_FAST_MS / 10)
    expect(await ompInput(ui(['472-tulip-orbit-cedar']), 'T', 'p', 60_000, undefined, fast)).toBeNull()
    const withdrawn = new AbortController()
    const asked = ompInput(ui(['wait']), 'T', 'p', 60_000, withdrawn.signal)
    withdrawn.abort()
    expect(await asked).toBeNull()
    expect(await ompInput(ui(['wait']), 'T', 'p', 30)).toBeNull()
  })

  it('ompCallMs: OMP_MCP_TIMEOUT_MS first, then the user-level bag entry timeout, then omp default', () => {
    const agent = join(tmp.dir, `agent${n++}`)
    mkdirSync(agent, { recursive: true })
    const env = { PI_CODING_AGENT_DIR: agent }
    expect(ompCallMs(env)).toBe(OMP_MCP_DEFAULT_MS)
    writeFileSync(join(agent, 'mcp.json'), JSON.stringify({ mcpServers: { bag: { timeout: 130000 } } }))
    expect(ompCallMs(env)).toBe(130_000)
    expect(ompCallMs({ ...env, OMP_MCP_TIMEOUT_MS: '30000' })).toBe(30_000)
    expect(ompCallMs({ ...env, OMP_MCP_TIMEOUT_MS: '0' })).toBe(0)
    expect(ompCallMs({ ...env, OMP_MCP_TIMEOUT_MS: 'soon' })).toBe(130_000)
    writeFileSync(join(agent, 'mcp.json'), JSON.stringify({ mcpServers: { bag: { timeout: -1 } } }))
    expect(ompCallMs(env)).toBe(OMP_MCP_DEFAULT_MS)
  })
})

describe("a session's consent link: the question's words and the pending line", () => {
  // An empty user-level omp folder: a shim entry an earlier test left there would send the link to another home.
  const agentDir = process.env.PI_CODING_AGENT_DIR
  beforeAll(() => {
    process.env.PI_CODING_AGENT_DIR = join(tmp.dir, `omp-agent-empty-${n++}`)
  })
  afterAll(() => {
    process.env.PI_CODING_AGENT_DIR = agentDir
  })
  /**
   * A fake bag service on a unix socket (hello and register answered) and a fake omp in tui mode whose ui records
   * every widget and status call. Each dialog settles only when the test says so, as a host slow to take a dismiss
   * would; a title starting "prompt" settles at once when its signal aborts, as a prompt host does.
   */
  async function session() {
    const home = join('/tmp', `bwl3-${process.pid}-${n++}`)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'run', 'service.token'), 'ab'.repeat(32))
    const conns: import('node:net').Socket[] = []
    const server: Server = createServer((c) => {
      conns.push(c)
      let buf = ''
      c.on('data', (b: Buffer) => {
        buf += b.toString()
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          const m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
          buf = buf.slice(i + 1)
          if (m.id !== undefined && m.method !== 'service/consent-answer')
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} })}\n`)
        }
      })
    })
    await new Promise<void>((r) => server.listen(join(home, 'run', 'service.sock'), () => r()))
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    writeFileSync(
      join(cwd, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['m', '--as', 'bob', '--dir', home] } } }),
    )
    const open = new Map<string, { signal: AbortSignal | undefined; settle: (v: never) => void }>()
    const hold = <T>(title: string, signal: AbortSignal | undefined, aborted: T): Promise<T> =>
      new Promise<T>((r) => {
        open.set(title, { signal, settle: r as (v: never) => void })
        if (title.startsWith('prompt')) signal?.addEventListener('abort', () => r(aborted))
      })
    const calls: [string, string, unknown][] = []
    const ui = {
      confirm: (title: string, _message: string, o?: { signal?: AbortSignal }) =>
        hold(title, o?.signal, false),
      input: (title: string, _placeholder?: string, o?: { signal?: AbortSignal }) =>
        hold<string | undefined>(title, o?.signal, undefined),
      setStatus: (key: string, text: string | undefined) => calls.push(['status', key, text]),
      setWidget: (key: string, content: string[] | undefined) => calls.push(['widget', key, content]),
      notify: () => {},
    }
    const ctx = {
      cwd,
      mode: 'tui',
      hasUI: true,
      ui,
      agent: { kind: 'main' },
      isIdle: () => true,
      setTimeout: () => undefined,
      setInterval: () => undefined,
    }
    const handlers = new Map<string, ((e: unknown, ctx: unknown) => void)[]>()
    bagWake({
      on: (event: string, h: (e: unknown, ctx: unknown) => void) =>
        handlers.set(event, [...(handlers.get(event) ?? []), h]),
      sendMessage: () => {},
    } as never)
    const emit = (event: string) => {
      for (const h of handlers.get(event) ?? []) h({}, ctx)
    }
    const until = async (f: () => boolean, ms = 3000) => {
      for (let i = 0; i < ms / 10 && !f(); i++) await new Promise((r) => setTimeout(r, 10))
    }
    const send = (conn: number, method: string, params: Record<string, unknown>) =>
      conns[conn]?.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`)
    const ask = async (conn: number, id: string, kind: string, title: string, message: string) => {
      send(conn, 'service/consent-ask', { id, kind, title, message, ms: 60_000 })
      await until(() => open.has(title))
    }
    const settle = async (title: string, v: unknown) => {
      open.get(title)?.settle(v as never)
      await new Promise((r) => setTimeout(r, 30))
    }
    const last = (kind: string, key: string) => calls.filter((c) => c[0] === kind && c[1] === key).at(-1)?.[2]
    const words = () => last('widget', ASK_WIDGET)
    const status = () => last('status', CONSENT_STATUS)
    const close = async () => {
      emit('session_shutdown')
      for (const c of conns) c.destroy()
      await new Promise<void>((r) => server.close(() => r()))
      rmSync(home, { recursive: true, force: true })
    }
    return { conns, open, emit, until, send, ask, settle, words, status, close }
  }

  it('only the newest text question clears its words: a withdrawn one settling late, or a confirm, moves nothing; the count never starts again', async () => {
    const s = await session()
    s.emit('session_start')
    await s.until(() => s.conns.length === 1)
    await s.ask(0, 't1', 'text', 'q1', 'one\nwords')
    expect([s.words(), s.status()]).toEqual([['one', 'words'], PENDING_TEXT])
    // The service withdraws q1 and asks q2; this host is slow to dismiss q1.
    s.send(0, 'service/consent-withdraw', { id: 't1' })
    await s.ask(0, 't2', 'text', 'q2', 'two')
    expect(s.words()).toEqual(['two'])
    // A confirm counts no text question and touches no words.
    await s.ask(0, 'c1', 'confirm', 'c1', 'sure?')
    await s.settle('c1', true)
    expect(s.words()).toEqual(['two'])
    await s.settle('q1', undefined)
    expect([s.words(), s.status()]).toEqual([['two'], PENDING_TEXT])
    await s.settle('q2', undefined)
    expect([s.words(), s.status()]).toEqual([undefined, undefined])
    // A new session in the same process: its first question sets its words and clears them as the newest.
    s.emit('session_shutdown')
    s.emit('session_start')
    await s.until(() => s.conns.length === 2)
    await s.ask(1, 't3', 'text', 'q3', 'three')
    expect([s.words(), s.status()]).toEqual([['three'], PENDING_TEXT])
    await s.settle('q3', undefined)
    expect([s.words(), s.status()]).toEqual([undefined, undefined])
    await s.close()
  }, 10_000)

  it("a question still open when its session ends, settling after the next session's question opened, leaves that question's words and pending line", async () => {
    const s = await session()
    s.emit('session_start')
    await s.until(() => s.conns.length === 1)
    await s.ask(0, 't1', 'text', 'q1', 'old')
    s.emit('session_shutdown')
    // The link's close aborts the open input's signal and returns: the input has not settled yet.
    expect(s.open.get('q1')?.signal?.aborted).toBe(true)
    expect([s.words(), s.status()]).toEqual([['old'], PENDING_TEXT])
    s.emit('session_start')
    await s.until(() => s.conns.length === 2)
    await s.ask(1, 't2', 'text', 'q2', 'new')
    await s.settle('q1', undefined)
    expect([s.words(), s.status()]).toEqual([['new'], PENDING_TEXT])
    await s.settle('q2', undefined)
    expect([s.words(), s.status()]).toEqual([undefined, undefined])
    // A host that settles on the abort: still after close returns, and with no newer question its own words and
    // pending line go, so none is left standing in the next session.
    await s.ask(1, 't3', 'text', 'prompt-q3', 'gone')
    s.emit('session_shutdown')
    expect([s.words(), s.status()]).toEqual([['gone'], PENDING_TEXT])
    s.emit('session_start')
    await s.until(() => s.conns.length === 3)
    await new Promise((r) => setTimeout(r, 30))
    expect([s.words(), s.status()]).toEqual([undefined, undefined])
    await s.close()
  }, 10_000)
})

describe('the relink after a refused registration', () => {
  it('a refused link is opened again after 2 s, then 4 s; a taken link resets the wait to 2 s', async () => {
    expect(RELINK_MAX_MS).toBe(60_000)
    const home = join('/tmp', `bwl3-${process.pid}-${n++}`)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'run', 'service.token'), 'ab'.repeat(32))
    /** When each registration came; the first two are refused and their connections closed, as the service does. */
    const at: number[] = []
    const conns: import('node:net').Socket[] = []
    const server: Server = createServer((c) => {
      conns.push(c)
      let buf = ''
      c.on('data', (b: Buffer) => {
        buf += b.toString()
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          const m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
          buf = buf.slice(i + 1)
          if (m.method === 'service/hello')
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { contract: 1 } })}\n`)
          if (m.method !== 'service/consent-register') continue
          at.push(Date.now())
          if (at.length > 2) c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} })}\n`)
          else {
            const error = { code: -32000, message: 'not-authorized', data: { code: 'not-authorized' } }
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, error })}\n`)
            c.end()
          }
        }
      })
    })
    await new Promise<void>((r) => server.listen(join(home, 'run', 'service.sock'), () => r()))
    const l = consentLink(home, 4244, async () => null, 30_000)
    const until = async (f: () => boolean, ms: number) => {
      for (let i = 0; i < ms / 10 && !f(); i++) await new Promise((r) => setTimeout(r, 10))
    }
    await until(() => at.length === 3, 9000)
    expect(at).toHaveLength(3)
    const gap = (i: number) => (at[i] ?? 0) - (at[i - 1] ?? 0)
    expect(gap(1)).toBeGreaterThanOrEqual(RELINK_MS - 100)
    expect(gap(1)).toBeLessThan(2 * RELINK_MS - 100)
    expect(gap(2)).toBeGreaterThanOrEqual(2 * RELINK_MS - 100)
    // The third was taken: its link's end (a service restart) is opened again after RELINK_MS, not 8 s.
    conns.at(-1)?.destroy()
    await until(() => at.length === 4, 2 * RELINK_MS + 1000)
    expect(gap(3)).toBeLessThan(2 * RELINK_MS)
    l.close()
    for (const c of conns) c.destroy()
    await new Promise<void>((r) => server.close(() => r()))
    rmSync(home, { recursive: true, force: true })
  }, 20_000)

  it('a registration refused busy is opened again after 2 s, whatever came before, and leaves the doubling where it was', async () => {
    const home = join('/tmp', `bwl3-${process.pid}-${n++}`)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'run', 'service.token'), 'ab'.repeat(32))
    /** Refused not-authorized twice, then busy, then not-authorized again, then taken. */
    const answers = ['not-authorized', 'not-authorized', 'busy', 'not-authorized']
    const at: number[] = []
    const conns: import('node:net').Socket[] = []
    const server: Server = createServer((c) => {
      conns.push(c)
      let buf = ''
      c.on('data', (b: Buffer) => {
        buf += b.toString()
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          const m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
          buf = buf.slice(i + 1)
          if (m.method === 'service/hello')
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { contract: 1 } })}\n`)
          if (m.method !== 'service/consent-register') continue
          const code = answers[at.length]
          at.push(Date.now())
          if (code === undefined) c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} })}\n`)
          else {
            const error = { code: -32000, message: code, data: { code } }
            c.write(`${JSON.stringify({ jsonrpc: '2.0', id: m.id, error })}\n`)
            c.end()
          }
        }
      })
    })
    await new Promise<void>((r) => server.listen(join(home, 'run', 'service.sock'), () => r()))
    const l = consentLink(home, 4245, async () => null, 30_000)
    const until = async (f: () => boolean, ms: number) => {
      for (let i = 0; i < ms / 10 && !f(); i++) await new Promise((r) => setTimeout(r, 10))
    }
    await until(() => at.length === 5, 22_000)
    expect(at).toHaveLength(5)
    const gap = (i: number) => (at[i] ?? 0) - (at[i - 1] ?? 0)
    const near = (i: number, ms: number) => {
      expect(gap(i)).toBeGreaterThanOrEqual(ms - 100)
      expect(gap(i)).toBeLessThan(ms + RELINK_MS - 100)
    }
    // Two refusals: 2 s, then 4 s. A busy one after them: 2 s, not 8.
    near(1, RELINK_MS)
    near(2, 2 * RELINK_MS)
    near(3, RELINK_MS)
    // The third not-authorized in a row doubles from where the second left it: 8 s.
    near(4, 4 * RELINK_MS)
    l.close()
    for (const c of conns) c.destroy()
    await new Promise<void>((r) => server.close(() => r()))
    rmSync(home, { recursive: true, force: true })
  }, 30_000)
})
