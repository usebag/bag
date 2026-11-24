import { mkdirSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import bagWake, { POLL_MS, RING_POLL_MS, wakeText } from '../src/omp-wake.ts'
import { tempDir } from './support/io.ts'

// The omp extension's session end (packages/cli/src/omp-wake.ts): it opens no fs watcher, so a session end has
// nothing to close and returns at once, and a ring written just before or just after a session end wakes the next
// session once, never twice and never not at all. fs.watch is replaced here by one whose close blocks for
// blockMs, as an FSEvents stream's close did on a busy Mac (up to about 10 s a close): an extension that opens
// a watcher again is caught by the counts and by the time the session end takes.

const watched = vi.hoisted(() => ({ opened: 0, closed: 0, blockMs: 1500 }))
vi.mock('node:fs', async (importOriginal) => {
  const fs = await importOriginal<typeof import('node:fs')>()
  const watch = () => {
    watched.opened++
    const w = {
      on: () => w,
      close: () => {
        const until = Date.now() + watched.blockMs
        while (Date.now() < until) {
          // the blocking close of an FSEvents stream
        }
        watched.closed++
      },
    }
    return w
  }
  return { ...fs, default: { ...fs, watch }, watch }
})

const tmp = tempDir('omp-wake-shutdown')
afterAll(() => tmp.cleanup())
process.env.PI_CODING_AGENT_DIR = join(tmp.dir, 'omp-agent')
let n = 0

/** A fake omp session on `cwd`: its handlers, the turns it was asked to start, and its timers run by hand. */
function omp(cwd: string) {
  const handlers = new Map<string, ((e: unknown, ctx: unknown) => void)[]>()
  const sent: string[] = []
  const timers: { fn: () => void; ms: number; every: boolean }[] = []
  const ctx = {
    cwd,
    mode: 'tui',
    agent: { kind: 'main' },
    isIdle: () => true,
    setTimeout: (fn: () => void, ms: number) => timers.push({ fn, ms, every: false }),
    setInterval: (fn: () => void, ms: number) => timers.push({ fn, ms, every: true }),
  }
  bagWake({
    on: (event: string, h: (e: unknown, ctx: unknown) => void) =>
      handlers.set(event, [...(handlers.get(event) ?? []), h]),
    sendMessage: (m: { content: string }) => sent.push(m.content),
  } as never)
  const emit = (event: string) => {
    for (const h of handlers.get(event) ?? []) h({}, ctx)
  }
  /** One poll of the doorbell and the ring file, then the settles it scheduled. */
  const poll = () => {
    for (const t of timers.filter((t) => t.every && (t.ms === POLL_MS || t.ms === RING_POLL_MS))) t.fn()
    const due = timers.filter((t) => !t.every)
    timers.splice(0, timers.length, ...timers.filter((t) => t.every))
    for (const t of due) t.fn()
  }
  return { sent, emit, poll }
}

/** A per-folder project for identity bob at `home`, or a service-mode one (the shim's .bound and .ring) with `shim`. */
function project(home: string, shim = false): string {
  const cwd = join(tmp.dir, `p${n++}`)
  mkdirSync(join(cwd, '.omp'), { recursive: true })
  const args = shim ? ['/pkg/bag-shim.js', '--dir', home] : ['m', '--as', 'bob', '--dir', home]
  writeFileSync(join(cwd, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { bag: { args } } }))
  mkdirSync(process.env.PI_CODING_AGENT_DIR as string, { recursive: true })
  const user = join(process.env.PI_CODING_AGENT_DIR as string, 'mcp.json')
  writeFileSync(user, JSON.stringify(shim ? { mcpServers: { bag: { args } } } : {}))
  return cwd
}

describe("the omp extension's session end", () => {
  it('opens no watcher, so a session end returns at once and leaves none open, per folder and bound', () => {
    for (const shim of [false, true]) {
      const home = join(tmp.dir, `h${n++}`)
      mkdirSync(join(home, 'state', 'bob'), { recursive: true })
      mkdirSync(join(home, 'run', 'shim'), { recursive: true })
      if (shim)
        writeFileSync(
          join(home, 'run', 'shim', `${process.pid}.bound`),
          JSON.stringify({ v: 1, as: ['bob'], shim: process.pid }),
        )
      const o = omp(project(home, shim))
      o.emit('session_start')
      o.poll()
      const t = Date.now()
      o.emit('session_shutdown')
      expect(Date.now() - t, `shim ${shim}`).toBeLessThan(watched.blockMs / 2)
    }
    expect([watched.opened, watched.closed]).toEqual([0, 0])
  })

  it('a doorbell ring just before a session end and one just after each wake the next session once', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1\n')
    const bell = join(state, 'doorbell')
    const cwd = project(home)
    const a = omp(cwd)
    a.emit('session_start')
    a.poll()
    expect(a.sent).toEqual([])
    // Before the end: the ring lands, and the session ends before its poll reads it.
    writeFileSync(bell, '')
    a.emit('session_shutdown')
    const b = omp(cwd)
    b.emit('session_start')
    b.poll()
    b.poll()
    expect(b.sent).toEqual([wakeText('bob')])
    // After the end: a new ring wakes the next session once, however often it polls.
    utimesSync(bell, new Date(Date.now() + 5000), new Date(Date.now() + 5000))
    b.poll()
    b.poll()
    expect([a.sent, b.sent]).toEqual([[], [wakeText('bob'), wakeText('bob')]])
    // Handled before its session ended: the next session does not wake for it again.
    b.emit('session_shutdown')
    const c = omp(cwd)
    c.emit('session_start')
    c.poll()
    c.poll()
    expect(c.sent).toEqual([])
    c.emit('session_shutdown')
  })

  it('a ring file written just before a session end and one just after each wake the next bound session once', () => {
    const home = join(tmp.dir, `h${n++}`)
    const dir = join(home, 'run', 'shim')
    mkdirSync(dir, { recursive: true })
    const file = (ext: string) => join(dir, `${process.pid}.${ext}`)
    writeFileSync(file('bound'), JSON.stringify({ v: 1, as: ['bob'], shim: process.pid }))
    const ring = (count: number) =>
      writeFileSync(
        file('ring'),
        JSON.stringify({ v: 1, n: count, as: 'bob', unread: 1, speaking: true, at: null, shim: process.pid }),
      )
    const cwd = project(home, true)
    const a = omp(cwd)
    a.emit('session_start')
    a.poll()
    ring(1)
    a.emit('session_shutdown')
    const b = omp(cwd)
    b.emit('session_start')
    b.poll()
    b.poll()
    expect(b.sent).toEqual([wakeText('bob')])
    ring(2)
    b.poll()
    b.poll()
    expect([a.sent, b.sent]).toEqual([[], [wakeText('bob'), wakeText('bob')]])
    // Handled before its session ended: the next session does not wake for it again.
    b.emit('session_shutdown')
    const c = omp(cwd)
    c.emit('session_start')
    c.poll()
    c.poll()
    expect(c.sent).toEqual([])
    c.emit('session_shutdown')
  })
})

describe("a session's timers, if omp keeps them past its session", () => {
  /**
   * One omp process whose timers outlive their session (Ctx.setInterval gives no handle to clear). Each session gets
   * its own extension (omp calls the factory once per session it binds) and its own turns, `sent[i]` for the i-th.
   */
  function process1(cwd: string) {
    const sent: string[][] = []
    const timers: { fn: () => void; every: boolean }[] = []
    const ctx = {
      cwd,
      mode: 'tui',
      agent: { kind: 'main' },
      isIdle: () => true,
      setTimeout: (fn: () => void) => timers.push({ fn, every: false }),
      setInterval: (fn: () => void) => timers.push({ fn, every: true }),
    }
    let emit: (event: string) => void = () => {}
    const start = () => {
      const handlers = new Map<string, ((e: unknown, ctx: unknown) => void)[]>()
      const mine: string[] = []
      sent.push(mine)
      bagWake({
        on: (event: string, h: (e: unknown, ctx: unknown) => void) =>
          handlers.set(event, [...(handlers.get(event) ?? []), h]),
        sendMessage: (m: { content: string }) => mine.push(m.content),
      } as never)
      emit = (event: string) => {
        for (const h of handlers.get(event) ?? []) h({}, ctx)
      }
      emit('session_start')
    }
    const end = () => emit('session_shutdown')
    /** Every interval ever set, the ended session's first, then every settle they scheduled. */
    const tick = () => {
      for (const t of timers.filter((t) => t.every)) t.fn()
      const due = timers.filter((t) => !t.every)
      timers.splice(0, timers.length, ...timers.filter((t) => t.every))
      for (const t of due) t.fn()
    }
    return { sent, start, end, tick }
  }

  it('start, end, start and one doorbell ring: one wake, in the new session', () => {
    const home = join(tmp.dir, `h${n++}`)
    const state = join(home, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'wake-seen'), '1000\n')
    writeFileSync(join(state, 'doorbell'), '')
    utimesSync(join(state, 'doorbell'), new Date(1000), new Date(1000))
    const o = process1(project(home))
    o.start()
    o.tick()
    o.end()
    o.start()
    o.tick()
    utimesSync(join(state, 'doorbell'), new Date(Date.now() + 5000), new Date(Date.now() + 5000))
    o.tick()
    o.tick()
    expect(o.sent).toEqual([[], [wakeText('bob')]])
    o.end()
  })

  it('start, end, start and one ring of a bound window: one wake, in the new session', () => {
    const home = join(tmp.dir, `h${n++}`)
    const dir = join(home, 'run', 'shim')
    mkdirSync(dir, { recursive: true })
    const file = (ext: string) => join(dir, `${process.pid}.${ext}`)
    writeFileSync(file('bound'), JSON.stringify({ v: 1, as: ['bob'], shim: process.pid }))
    const o = process1(project(home, true))
    o.start()
    o.tick()
    o.end()
    o.start()
    o.tick()
    writeFileSync(
      file('ring'),
      JSON.stringify({ v: 1, n: 1, as: 'bob', unread: 1, speaking: true, at: null, shim: process.pid }),
    )
    o.tick()
    o.tick()
    expect(o.sent).toEqual([[], [wakeText('bob')]])
    o.end()
  })
})
