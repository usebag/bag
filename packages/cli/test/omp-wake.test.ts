import { existsSync, mkdirSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import bagWake, {
  awayText,
  CONSENT_POLL_MS,
  CONSENT_STATUS,
  ConsentLoop,
  type ConsentUi,
  consentFiles,
  holderOf,
  IDLE_MS,
  mtimeOf,
  PENDING_TEXT,
  POLL_MS,
  refusal,
  requestOf,
  SETTLE_MS,
  seenIn,
  targetOf,
  WakeLoop,
  wakeText,
  writeFacts,
} from '../src/omp-wake.ts'
import { tempDir } from './support/io.ts'

// The omp wake extension (packages/cli/src/omp-wake.ts): its state machine with a fake doorbell and session, and the
// pieces it reads and writes. Temp directories only.

const tmp = tempDir('omp-wake')
afterAll(() => tmp.cleanup())
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
      'bag: mail arrived for omp. Read it with the bag inbox tool, then answer it.',
    )
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
