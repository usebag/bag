import { join } from 'node:path'
import type { CallToolResult, Progress } from '@modelcontextprotocol/sdk/types.js'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type ProgressExtra, startProgress } from '../src/progress.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// During a wait or ask call the server sends notifications/progress every --progress-seconds
// (15 s by default) when the host's request carries a progressToken: progress the seconds elapsed, total the call's
// window. None without a token, none under --progress-seconds 0, and the call's result is the one it was without
// them. The timers are fired by hand (ManualTimers), so no test waits on a clock.

const fifteen = (ms: number): boolean => ms === 15_000

describe('startProgress: the ticks of one call', () => {
  const sent: unknown[] = []
  const extra = (token?: string | number, fail = false): ProgressExtra => ({
    ...(token === undefined ? {} : { _meta: { progressToken: token } }),
    sendNotification: async (n) => {
      sent.push(n)
      if (fail) throw new Error('not connected')
    },
  })
  beforeEach(() => {
    sent.length = 0
  })

  it('sends at 15 s and 30 s inside a 40 s window, then nothing more, with the token, elapsed and window', async () => {
    const timers = new ManualTimers()
    const stop = startProgress({
      tool: 'wait',
      extra: extra('t1'),
      every: 15,
      window: 40,
      timers,
      log: new MemoryLog(),
    })
    expect(timers.live()).toEqual([15_000])
    timers.fire()
    expect(timers.live()).toEqual([15_000])
    timers.fire()
    expect(timers.live()).toEqual([])
    await until('both are sent', () => sent.length === 2)
    expect(sent).toEqual(
      [15, 30].map((s) => ({
        method: 'notifications/progress',
        params: {
          progressToken: 't1',
          progress: s,
          total: 40,
          message: `wait: nothing yet, ${s} s of this call's 40 s`,
        },
      })),
    )
    stop()
  })

  it('sends one tick in the default 25 s window, none at the window end, and stop cancels a pending tick', async () => {
    const timers = new ManualTimers()
    const stop = startProgress({
      tool: 'ask',
      extra: extra(7),
      every: 15,
      window: 25,
      timers,
      log: new MemoryLog(),
    })
    timers.fire()
    expect(timers.live()).toEqual([])
    await until('the tick is sent', () => sent.length === 1)
    expect(sent).toMatchObject([{ params: { progressToken: 7, progress: 15, total: 25 } }])
    stop()
    const again = startProgress({
      tool: 'ask',
      extra: extra(8),
      every: 15,
      window: 30,
      timers,
      log: new MemoryLog(),
    })
    expect(timers.live()).toEqual([15_000])
    again()
    expect(timers.live()).toEqual([])
    // A window no longer than one period sends nothing: the call returns first.
    const short = startProgress({
      tool: 'wait',
      extra: extra(9),
      every: 15,
      window: 15,
      timers,
      log: new MemoryLog(),
    })
    expect(timers.live()).toEqual([])
    short()
    expect(sent).toHaveLength(1)
  })

  it('sends nothing without a progressToken, and nothing under --progress-seconds 0', () => {
    const timers = new ManualTimers()
    startProgress({ tool: 'wait', extra: extra(), every: 15, window: 40, timers, log: new MemoryLog() })()
    startProgress({ tool: 'wait', extra: extra('t'), every: 0, window: 40, timers, log: new MemoryLog() })()
    expect(timers.live()).toEqual([])
    expect(sent).toEqual([])
  })

  it('logs a notification the transport refuses and goes on ticking', async () => {
    const timers = new ManualTimers()
    const log = new MemoryLog()
    const stop = startProgress({ tool: 'wait', extra: extra('t', true), every: 15, window: 40, timers, log })
    timers.fire()
    await until('the refusal is logged', () => log.lines.length === 2)
    expect(log.lines).toEqual([
      { level: 'info', event: 'progress', fields: { tool: 'wait', every_s: 15, window_s: 40 } },
      { level: 'warn', event: 'progress-failed', fields: { tool: 'wait', detail: 'Error: not connected' } },
    ])
    expect(timers.live()).toEqual([15_000])
    stop()
    // A send that throws at once, before any promise, is logged the same way and never leaves the timer's callback.
    const sync = new MemoryLog()
    const throwing: ProgressExtra = {
      _meta: { progressToken: 's' },
      sendNotification: () => {
        throw new Error('closed')
      },
    }
    startProgress({ tool: 'ask', extra: throwing, every: 15, window: 40, timers, log: sync })
    expect(() => timers.fire()).not.toThrow()
    await until('the throw is logged', () => sync.lines.length === 2)
    expect(sync.lines[1]).toEqual({
      level: 'warn',
      event: 'progress-failed',
      fields: { tool: 'ask', detail: 'Error: closed' },
    })
  })
})

describe('the server: wait and ask send progress to a host that asks for it', () => {
  let tmp: ReturnType<typeof tempDir>
  let relay: MemoryRelay
  let clock: FakeClock
  let timers: ManualTimers
  const servers: TestServer[] = []
  const stdout = watchStdout()

  async function serverFor(p: Party, args: readonly string[] = [], pid = 4242): Promise<TestServer> {
    const s = await testServer({ home: join(tmp.dir, p.name), name: p.name, relay, clock, timers, args, pid })
    servers.push(s)
    return s
  }

  /** A tools/call whose request carries a progressToken (the SDK client sets one when onprogress is given). */
  async function callWithProgress(
    s: TestServer,
    tool: string,
    args: Record<string, unknown>,
    got: Progress[],
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    const result = (await s.client.callTool({ name: tool, arguments: args }, undefined, {
      onprogress: (p) => got.push(p),
      ...(signal === undefined ? {} : { signal }),
    })) as CallToolResult
    return JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>
  }

  beforeEach(async () => {
    stdout.start()
    tmp = tempDir('progress')
    relay = new MemoryRelay()
    clock = new FakeClock()
    timers = new ManualTimers()
    for (const p of [P.alice, P.bob]) {
      saveKeys(join(tmp.dir, p.name), p)
      await publishAddress(relay, p)
    }
  })

  afterEach(async () => {
    for (const s of servers.splice(0)) await s.close()
    tmp.cleanup()
    stdout.check()
  })

  it('wait in a 40 s window: notifications at 15 s and 30 s, and the result is the one without them', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address, '--max-tool-seconds', '40'])
    expect((await bob.call('status')).value.progress_seconds).toBe(15)
    const got: Progress[] = []
    const waiting = callWithProgress(bob, 'wait', { timeout_s: 40 }, got)
    await until('the wait and its first tick are pending', () => timers.live().length === 2)
    expect(timers.live()).toEqual([15_000, 40_000])
    timers.fire(fifteen)
    await until('the first notification arrives', () => got.length === 1)
    timers.fire(fifteen)
    await until('the second notification arrives', () => got.length === 2)
    expect(timers.live()).toEqual([40_000])
    expect(got).toEqual([
      { progress: 15, total: 40, message: "wait: nothing yet, 15 s of this call's 40 s" },
      { progress: 30, total: 40, message: "wait: nothing yet, 30 s of this call's 40 s" },
    ])
    timers.fire()
    const withProgress = await waiting
    expect(withProgress).toEqual({ timed_out: true, pending: false, resume: `r1.0.${T0 + 40}.any` })
    // The same call without a token: no tick is scheduled, and the result is the same.
    const plain = bob.call('wait', { timeout_s: 40 })
    await until('the plain wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([40_000])
    timers.fire()
    expect((await plain).value).toEqual(withProgress)
  })

  it('sends nothing under --progress-seconds 0, though the host asked', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address, '--progress-seconds', '0'])
    const got: Progress[] = []
    const waiting = callWithProgress(bob, 'wait', {}, got)
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    expect(await waiting).toEqual({ timed_out: true, pending: false, resume: `r1.0.${T0 + 25}.any` })
    expect(got).toEqual([])
  })

  it('stops ticking when a message ends the wait inside the window', async () => {
    const alice = await serverFor(P.alice, [], 1)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const got: Progress[] = []
    const waiting = callWithProgress(bob, 'wait', { timeout_s: 60 }, got)
    await until('the wait and its tick are pending', () => timers.live().length === 2)
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(await waiting).toMatchObject({ message: { body: 'hi' } })
    expect(timers.live()).toEqual([])
    expect(got).toEqual([])
  })

  it('stops ticking when the wait of the desk throws while a tick is pending, and the call fails as a tool error', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const { promise, reject } = Promise.withResolvers<null>()
    const wait = vi.spyOn(bob.running.desk, 'wait').mockReturnValueOnce(promise)
    const got: Progress[] = []
    const waiting = callWithProgress(bob, 'wait', { timeout_s: 60 }, got)
    await until('the tick is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([15_000])
    reject(new Error('store gone'))
    expect(await waiting).toMatchObject({ error: expect.any(String) })
    expect(timers.live()).toEqual([])
    expect(got).toEqual([])
    wait.mockRestore()
  })

  it('stops ticking when the host cancels the call, and sends nothing after', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const got: Progress[] = []
    const cancel = new AbortController()
    const waiting = callWithProgress(bob, 'wait', { timeout_s: 60 }, got, cancel.signal)
    await until('the wait and its tick are pending', () => timers.live().length === 2)
    cancel.abort('host timeout')
    await expect(waiting).rejects.toBeDefined()
    await until('the server let go of both timers', () => timers.live().length === 0)
    timers.fire()
    expect(got).toEqual([])
  })

  it('ask: a notification at 15 s that names ask, then pending at the 25 s window with the question', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], 1)
    await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const got: Progress[] = []
    const asked = callWithProgress(alice, 'ask', { to: P.bob.address, body: 'q', timeout_s: 90 }, got)
    await until('the ask and its tick are pending', () => timers.live().length === 2)
    timers.fire(fifteen)
    await until('the notification arrives', () => got.length === 1)
    expect(got).toEqual([{ progress: 15, total: 25, message: "ask: nothing yet, 15 s of this call's 25 s" }])
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    const pending = await asked
    expect(pending).toMatchObject({ timed_out: false, pending: true, remaining_s: 90, question: {} })
    expect(timers.live()).toEqual([])
    // The resumed ask counts its own wait from 0, and its notifications name ask too.
    const resumedGot: Progress[] = []
    const resumed = callWithProgress(alice, 'ask', { resume: pending.resume }, resumedGot)
    await until('the resumed ask and its tick are pending', () => timers.live().length === 2)
    timers.fire(fifteen)
    await until('the resumed notification arrives', () => resumedGot.length === 1)
    expect(resumedGot).toEqual([
      { progress: 15, total: 25, message: "ask: nothing yet, 15 s of this call's 25 s" },
    ])
    timers.fire()
    expect(await resumed).toMatchObject({ timed_out: false, pending: true, resume: pending.resume })
  })
})
