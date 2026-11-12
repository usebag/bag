import { randomBytes } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
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
import { afterAll, describe, expect, it } from 'vitest'
import bagWake, {
  type Arrival,
  arrivals,
  awayText,
  boundIn,
  CHANNEL_MS,
  CONSENT_POLL_MS,
  CONSENT_STATUS,
  ConsentLoop,
  type ConsentUi,
  consentFiles,
  holderOf,
  IDLE_MS,
  LOOP_AT,
  LOOP_S,
  loopLines,
  mtimeOf,
  namesOf,
  PENDING_TEXT,
  POLL_MS,
  RING_POLL_MS,
  type RingDoc,
  RingLoop,
  type RingSeen,
  refusal,
  requestOf,
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

describe('the consent bridge (decision 83h)', () => {
  const ID = 'aaaaaaaaaaaaaaaa'
  const T = Date.parse('2026-11-11T15:40:00Z')
  const request = (o: Record<string, unknown> = {}) =>
    JSON.stringify({
      v: 1,
      id: ID,
      kind: 'pair-accept',
      peer: { name: 'bob', address: 'ed25519:bb', root: 'ed25519:bb' },
      code: '123456',
      relay: 'https://relay.test',
      asked_at: new Date(T).toISOString(),
      expires_at: new Date(T + 120_000).toISOString(),
      ...o,
    })

  /** A fake ui recording every call, answering confirm and input from queues. */
  function fakeUi(confirms: boolean[] = [], inputs: (string | undefined)[] = []) {
    const calls: unknown[][] = []
    const status: (string | undefined)[] = []
    const widgets: (string[] | undefined)[] = []
    const ui: ConsentUi = {
      confirm: async (title, message, options) => {
        calls.push(['confirm', title, message, options?.initialIndex, options?.signal instanceof AbortSignal])
        return confirms.shift() ?? false
      },
      input: async (title, placeholder) => {
        calls.push(['input', title, placeholder])
        return inputs.shift()
      },
      setStatus: (key, text) => {
        if (key === CONSENT_STATUS) status.push(text)
      },
      setWidget: (key, content) => {
        if (key === CONSENT_STATUS) widgets.push(content)
      },
    }
    return { ui, calls, status, widgets }
  }

  function loop(text: string | null, ui: ConsentUi, now = () => T) {
    const answers: [string, boolean, string | null][] = []
    const dropped: string[] = []
    const l = new ConsentLoop({
      name: 'alice',
      ui,
      ids: () => (text === null ? [] : [ID]),
      read: () => text,
      answer: (id, accepted, code) => answers.push([id, accepted, code]),
      drop: (id) => dropped.push(id),
      now,
    })
    return { l, answers, dropped }
  }

  it('pair-accept with check digits: the confirm shows them, Yes answers accepted with no code, the status clears', async () => {
    const f = fakeUi([true])
    const { l, answers } = loop(request(), f.ui)
    await l.look()
    expect(f.calls).toEqual([
      [
        'confirm',
        'bag: bob asks to pair as alice',
        'check digits 123 456: do they match what bob reads? accept?',
        1,
        true,
      ],
    ])
    expect(answers).toEqual([[ID, true, null]])
    expect(f.status).toEqual([PENDING_TEXT, undefined])
  })

  it('pair-accept answered No is accepted false; a request is asked once', async () => {
    const f = fakeUi([false, true])
    const { l, answers } = loop(request(), f.ui)
    await l.look()
    await l.look()
    expect(answers).toEqual([[ID, false, null]])
    expect(f.calls.length).toBe(1)
  })

  it('pair-accept with no code asks for the six digits after Yes; anything but six digits is a refusal', async () => {
    const f = fakeUi([true], ['654 321'])
    const ok = loop(
      request({ code: null, peer: { name: null, address: 'ed25519:cc', root: 'ed25519:cc' } }),
      f.ui,
    )
    await ok.l.look()
    expect(f.calls[0]?.slice(0, 3)).toEqual(['confirm', 'bag: ed25519:cc asks to pair as alice', 'accept?'])
    expect(f.calls[1]).toEqual(['input', 'bag: the six digits ed25519:cc reads to you', '123 456'])
    expect(ok.answers).toEqual([[ID, true, '654321']])
    const g = fakeUi([true], ['12 34'])
    const bad = loop(request({ code: null }), g.ui)
    await bad.l.look()
    expect(bad.answers).toEqual([[ID, false, null]])
  })

  it("the inviter's side (code null): No asks for no digits, and a cancelled digits input is a refusal", async () => {
    const acceptor = { name: 'carol', address: 'ed25519:cc', root: 'ed25519:cc' }
    const no = fakeUi([false])
    const refused = loop(request({ code: null, peer: acceptor }), no.ui)
    await refused.l.look()
    expect(no.calls.map((c) => c[0])).toEqual(['confirm'])
    expect(refused.answers).toEqual([[ID, false, null]])
    const gone = fakeUi([true], [undefined])
    const cancelled = loop(request({ code: null, peer: acceptor }), gone.ui)
    await cancelled.l.look()
    expect(gone.calls.map((c) => c.slice(0, 2))).toEqual([
      ['confirm', 'bag: carol asks to pair as alice'],
      ['input', 'bag: the six digits carol reads to you'],
      ['input', 'bag: the six digits carol reads to you'],
    ])
    expect(cancelled.answers).toEqual([[ID, false, null]])
  })

  it('pair-accept-code asks the person to paste the invite and returns it trimmed; empty, too long (over 512) or cancelled refuses', async () => {
    const paste = (inputs: (string | undefined)[]) => {
      const f = fakeUi([], inputs)
      return { f, x: loop(request({ kind: 'pair-accept-code', peer: null, code: null }), f.ui) }
    }
    const long = paste(['a'.repeat(512)])
    await long.x.l.look()
    expect(long.x.answers).toEqual([[ID, true, 'a'.repeat(512)]])
    const ok = paste(['  ac-peer1:abcDEF_123  '])
    await ok.x.l.look()
    expect(ok.f.calls).toEqual([
      ['input', 'bag: paste the invite or code you received to pair as alice', 'invite or code'],
    ])
    expect(ok.x.answers).toEqual([[ID, true, 'ac-peer1:abcDEF_123']])
    expect(ok.f.status).toEqual([PENDING_TEXT, undefined])
    for (const typed of ['   ', undefined, 'x'.repeat(513)]) {
      const no = paste([typed])
      await no.x.l.look()
      expect(no.x.answers).toEqual([[ID, false, null]])
    }
    const old = loop(
      request({
        kind: 'pair-accept-code',
        peer: null,
        code: null,
        expires_at: new Date(T - 1).toISOString(),
      }),
      fakeUi().ui,
    )
    await old.l.look()
    expect([old.dropped, old.answers]).toEqual([[ID], []])
    expect(requestOf(request({ kind: 'pair-accept-code', peer: null, code: '123456' }), ID)).toBeNull()
    expect(requestOf(request({ kind: 'pair-accept', peer: null }), ID)).toBeNull()
  })

  it('every confirm opens on No with an expiry signal; a wrong or empty input is asked once more, then refused', async () => {
    const f = fakeUi([true], ['', '654 321'])
    const again = loop(request({ code: null }), f.ui)
    await again.l.look()
    expect(f.calls.map((c) => c[0])).toEqual(['confirm', 'input', 'input'])
    expect(f.calls[0]?.slice(3)).toEqual([1, true])
    expect(again.answers).toEqual([[ID, true, '654321']])
    const g = fakeUi([true], ['12', 'x'])
    const twice = loop(request({ code: null }), g.ui)
    await twice.l.look()
    expect(g.calls.map((c) => c[0])).toEqual(['confirm', 'input', 'input'])
    expect(twice.answers).toEqual([[ID, false, null]])
  })

  it('a pair-accept shows what is asked in a widget before the confirm, and clears it after', async () => {
    const f = fakeUi([false])
    const order: string[] = []
    const confirm = f.ui.confirm
    f.ui.confirm = async (...a) => {
      order.push(`confirm with widget ${JSON.stringify(f.widgets.at(-1)?.[0] ?? null)}`)
      return confirm(...a)
    }
    const { l } = loop(request(), f.ui)
    await l.look()
    expect(order).toEqual(['confirm with widget "bag: bob (ed25519:bb) asks to pair as alice"'])
    expect(f.widgets.at(-1)).toBeUndefined()
  })

  it('pair-invite-show shows the word code as the server sends it, asks that it was given, and clears the widget', async () => {
    const f = fakeUi([true])
    const { l, answers } = loop(
      request({ kind: 'pair-invite-show', peer: null, code: '760-dimly-straw-cough' }),
      f.ui,
    )
    await l.look()
    expect(f.widgets[0]?.[0]).toBe('bag: your invite code: 760-dimly-straw-cough')
    expect(f.widgets.at(-1)).toBeUndefined()
    expect(f.calls[0]?.slice(0, 3)).toEqual([
      'confirm',
      'bag: your invite code is shown above',
      'was it given to your peer?',
    ])
    expect(answers).toEqual([[ID, true, null]])
  })

  it('pair-accept check digits as the edge prints them, 227 500, are read as six digits', async () => {
    const r = requestOf(request({ code: '227 500' }), ID)
    expect(r?.code).toBe('227500')
    const f = fakeUi([true])
    const { l } = loop(request({ code: '227 500' }), f.ui)
    await l.look()
    expect(f.calls[0]?.[2]).toBe('check digits 227 500: do they match what bob reads? accept?')
    expect(requestOf(request({ code: '22 75 00 1' }), ID)).toBeNull()
  })

  it('a request the server withdraws while its dialog is open closes the dialog and is not answered', async () => {
    let present = true
    const answers: unknown[] = []
    let aborted = false
    let l: ConsentLoop | null = null
    const ui: ConsentUi = {
      confirm: (_t, _m, options) =>
        new Promise((resolve) => {
          options?.signal?.addEventListener('abort', () => {
            aborted = true
            resolve(false)
          })
          present = false
          void l?.look()
        }),
      input: async () => undefined,
      setStatus: () => undefined,
      setWidget: () => undefined,
    }
    l = new ConsentLoop({
      name: 'alice',
      ui,
      ids: () => (present ? [ID] : []),
      read: () => request(),
      answer: (...a) => answers.push(a),
      drop: () => undefined,
      now: () => T,
    })
    await l.look()
    expect([aborted, answers]).toEqual([true, []])
  })

  it('an expired request is dropped unasked; a malformed one or one naming another id is ignored', async () => {
    const f = fakeUi([true])
    const old = loop(request({ expires_at: new Date(T - 1).toISOString() }), f.ui)
    await old.l.look()
    expect([old.dropped, old.answers, f.calls]).toEqual([[ID], [], []])
    for (const text of [
      'not json',
      request({ id: 'bbbbbbbbbbbbbbbb' }),
      request({ kind: 'other' }),
      request({ v: 2 }),
    ]) {
      const x = loop(text, f.ui)
      await x.l.look()
      expect([x.dropped, x.answers]).toEqual([[], []])
    }
    expect(f.calls).toEqual([])
    expect(requestOf(request(), ID)?.peer?.name).toBe('bob')
  })

  it('an answer given after the request expired is not written', async () => {
    let t = T
    const f = fakeUi()
    f.ui.confirm = async () => {
      t = T + 121_000
      return true
    }
    const { l, answers } = loop(request(), f.ui, () => t)
    await l.look()
    expect(answers).toEqual([])
  })

  it('consentFiles lists only request ids, writes the answer 0600 whole, and drops a request with its answer', () => {
    const dir = join(tmp.dir, `c${n++}`)
    mkdirSync(dir)
    for (const f of [`${ID}.json`, `${ID}.answer.json`, '.bridge', 'x.json', `${ID}.json.1.tmp`])
      writeFileSync(join(dir, f), '{}')
    const files = consentFiles(dir, () => T)
    expect(files.ids()).toEqual([ID])
    files.answer(ID, true, null)
    const answer = join(dir, `${ID}.answer.json`)
    expect(JSON.parse(readFileSync(answer, 'utf8'))).toEqual({
      v: 1,
      id: ID,
      accepted: true,
      code: null,
      answered_at: new Date(T).toISOString(),
    })
    expect(statSync(answer).mode & 0o777).toBe(0o600)
    files.drop(ID)
    expect([existsSync(join(dir, `${ID}.json`)), existsSync(answer)]).toEqual([false, false])
  })

  it('the factory writes .bridge for a tui session with a ui, answers a request through it, and removes .bridge at the end', async () => {
    const home = join(tmp.dir, `h${n++}`)
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    writeFileSync(
      join(cwd, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['m', '--as', 'bob', '--dir', home] } } }),
    )
    const dir = join(home, 'state', 'bob', 'consent')
    const f = fakeUi([true])
    const intervals: { fn: () => void; ms: number }[] = []
    const handlers = new Map<string, (e: unknown, ctx: unknown) => void>()
    const ctx = {
      cwd,
      mode: 'tui',
      hasUI: true,
      ui: f.ui,
      agent: { kind: 'main' },
      isIdle: () => true,
      setTimeout: () => undefined,
      setInterval: (fn: () => void, ms: number) => intervals.push({ fn, ms }),
    }
    bagWake({
      on: (e: string, h: (e: unknown, ctx: unknown) => void) => handlers.set(e, h),
      sendMessage: () => undefined,
    } as never)
    handlers.get('session_start')?.({}, ctx)
    const bridge = JSON.parse(readFileSync(join(dir, '.bridge'), 'utf8'))
    expect([bridge.v, bridge.pid, bridge.host, bridge.mode]).toEqual([1, process.pid, 'omp', 'tui'])
    expect(statSync(join(dir, '.bridge')).mode & 0o777).toBe(0o600)
    const soon = new Date(Date.now() + 60_000).toISOString()
    writeFileSync(join(dir, `${ID}.json`), request({ expires_at: soon }), { mode: 0o600 })
    const answer = join(dir, `${ID}.answer.json`)
    for (let i = 0; i < 150 && !existsSync(answer); i++) await new Promise((r) => setTimeout(r, 20))
    // A slow fs event under load: the 2 s poll, run here, looks the same way.
    if (!existsSync(answer)) for (const t of intervals.filter((t) => t.ms === CONSENT_POLL_MS)) t.fn()
    for (let i = 0; i < 150 && !existsSync(answer); i++) await new Promise((r) => setTimeout(r, 20))
    expect(JSON.parse(readFileSync(answer, 'utf8')).accepted).toBe(true)
    handlers.get('session_shutdown')?.({}, ctx)
    expect(existsSync(join(dir, '.bridge'))).toBe(false)
  }, 20_000)

  it('an rpc session writes no bridge even with hasUI true (nothing may answer there)', () => {
    const home = join(tmp.dir, `h${n++}`)
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    writeFileSync(
      join(cwd, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['m', '--as', 'bob', '--dir', home] } } }),
    )
    const handlers = new Map<string, (e: unknown, ctx: unknown) => void>()
    const ctx = {
      cwd,
      mode: 'rpc',
      hasUI: true,
      ui: fakeUi().ui,
      agent: { kind: 'main' },
      isIdle: () => true,
      setTimeout: () => undefined,
      setInterval: () => undefined,
    }
    bagWake({
      on: (e: string, h: (e: unknown, ctx: unknown) => void) => handlers.set(e, h),
      sendMessage: () => undefined,
    } as never)
    handlers.get('session_start')?.({}, ctx)
    expect(existsSync(join(home, 'state', 'bob', 'consent', '.bridge'))).toBe(false)
  })

  it('a session without a ui (print) writes no bridge', () => {
    const home = join(tmp.dir, `h${n++}`)
    const cwd = join(tmp.dir, `p${n++}`)
    mkdirSync(join(cwd, '.omp'), { recursive: true })
    writeFileSync(
      join(cwd, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['m', '--as', 'bob', '--dir', home] } } }),
    )
    const handlers = new Map<string, (e: unknown, ctx: unknown) => void>()
    const ctx = {
      cwd,
      mode: 'tui',
      hasUI: false,
      agent: { kind: 'main' },
      isIdle: () => true,
      setTimeout: () => undefined,
      setInterval: () => undefined,
    }
    bagWake({
      on: (e: string, h: (e: unknown, ctx: unknown) => void) => handlers.set(e, h),
      sendMessage: () => undefined,
    } as never)
    handlers.get('session_start')?.({}, ctx)
    expect(existsSync(join(home, 'state', 'bob', 'consent', '.bridge'))).toBe(false)
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

  it('the bridge folder comes from the channel: .bridge is written there and a request is answered there', async () => {
    const s0 = await shim(() => ({ bridge: null }))
    const folder = join(s0.dir, 'c0nn.consent')
    mkdirSync(folder, { mode: 0o700 })
    const s = await shim(() => ({ bridge: folder }))
    const o = session(project(s.home, 'bob'), true)
    o.emit('session_start')
    await until(() => existsSync(join(folder, '.bridge')))
    expect(JSON.parse(readFileSync(join(folder, '.bridge'), 'utf8')).host).toBe('omp')
    expect(s.got).toEqual([{ v: 1, kind: 'bridge', secret: s.secret }])
    expect(existsSync(join(s.home, 'state', 'bob', 'consent'))).toBe(false)
    const id = 'aaaaaaaaaaaaaaaa'
    const expires = new Date(Date.now() + 60_000).toISOString()
    writeFileSync(
      join(folder, `${id}.json`),
      JSON.stringify({
        v: 1,
        id,
        kind: 'pair-invite-show',
        peer: null,
        code: '760-a-b-c',
        relay: 'r',
        asked_at: expires,
        expires_at: expires,
      }),
    )
    for (const t of o.timers.filter((t) => t.ms === CONSENT_POLL_MS)) t.fn()
    await until(() => existsSync(join(folder, `${id}.answer.json`)))
    expect(JSON.parse(readFileSync(join(folder, `${id}.answer.json`), 'utf8')).accepted).toBe(true)
    o.emit('session_shutdown')
    expect(existsSync(join(folder, '.bridge'))).toBe(false)
  }, 20_000)

  it('a null bridge is no bridge (not the identity folder), said once, and asked again at the next turn', async () => {
    let folder: string | null = null
    const s = await shim(() => ({ bridge: folder }))
    const o = session(project(s.home, 'bob'), true)
    const err = await stderr(async () => {
      o.emit('session_start')
      await until(() => s.got.length > 0)
      await new Promise((r) => setTimeout(r, 50))
    })
    expect(err).toContain('no consent bridge for this session yet')
    expect(existsSync(join(s.home, 'state', 'bob', 'consent', '.bridge'))).toBe(false)
    folder = join(s.dir, 'c1.consent')
    mkdirSync(folder, { mode: 0o700 })
    o.emit('agent_end')
    await until(() => existsSync(join(folder as string, '.bridge')))
    expect(existsSync(join(folder, '.bridge'))).toBe(true)
    o.emit('session_shutdown')
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
  })

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
  })

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
