import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { AgentClient, AgentError, DESK_RETRY_MS } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LOST_PROBE_MS } from '../src/server.ts'
import { P, type TestServer, testServer } from './support/fixtures.ts'
import {
  type AgentHome,
  agentHome,
  eventually,
  grantedSession,
  sessionServer,
  sessionServerOf,
  TREE,
} from './support/sessions.ts'

// The session paths the other files leave: the probe that comes back every LOST_PROBE_MS, a thread the replay could not
// register, a regrant the human declines, a stop before the y, a desk whose retry of held rows or whose timer fails, a
// grant the agent refuses for its shape, and a session that cannot start (its process readers or its session file).

let h: AgentHome
const servers: TestServer[] = []
const later = async (s: Promise<TestServer>): Promise<TestServer> => {
  const t = await s
  servers.push(t)
  return t
}
const logged = (s: TestServer, event: string): boolean => s.log.lines.some((l) => l.event === event)

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
})

afterEach(async () => {
  vi.restoreAllMocks()
  for (const s of servers.splice(0)) await s.close()
  await h.agent.close()
  h.tmp.cleanup()
})

describe('a granted session', () => {
  it('probes the agent every LOST_PROBE_MS, the timer set again each time', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    const probe = vi.spyOn(s.running.opened.agent as NonNullable<typeof s.running.opened.agent>, 'probe')
    h.timers.fire((ms) => ms === LOST_PROBE_MS)
    h.timers.fire((ms) => ms === LOST_PROBE_MS)
    expect(probe).toHaveBeenCalledTimes(2)
    expect(h.timers.live()).toContain(LOST_PROBE_MS)
  })

  it('probes on a thread of its own, drawn at random: a fixed id would be a capability anyone could name', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    const other = await later(grantedSession(h, 's-two', 2))
    const register = vi.spyOn(AgentClient.prototype, 'register')
    s.running.opened.agent?.probe()
    other.running.opened.agent?.probe()
    await eventually('both probes', async () => register.mock.calls.length >= 2)
    const [mine, theirs] = register.mock.calls.map(([thread]) => thread)
    expect(mine).toMatch(/^[0-9a-f]{64}$/)
    expect(mine).not.toBe('00'.repeat(32))
    expect(theirs).not.toBe(mine)
  })

  it('logs each old thread the regrant could not register again, and opens all the same', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    const thread = 'cd'.repeat(32)
    vi.spyOn(s.running.opened.agent as NonNullable<typeof s.running.opened.agent>, 'threads').mockReturnValue(
      [thread],
    )
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the waiting line', async () => (await s.call('status')).value.error === 'grant-pending')
    // The probe has asked; the next register is the replay's, after the y.
    vi.spyOn(AgentClient.prototype, 'register').mockRejectedValueOnce(new Error('the socket closed'))
    h.type('y')
    await eventually('the replay line', async () => logged(s, 'replay'))
    expect(s.log.lines.find((l) => l.event === 'replay')?.fields).toMatchObject({ thread })
    await eventually('the session open again', async () => !(await s.call('status')).isError)
  })

  it('logs a regrant the human declines, and answers its refusal from then on', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the waiting line', async () => (await s.call('status')).value.error === 'grant-pending')
    h.type('n')
    await eventually(
      'the regrant error',
      async () => logged(s, 'regrant') && s.log.lines.some((l) => l.level === 'error'),
    )
    expect((await s.call('status')).value).toMatchObject({ error: 'declined' })
  })

  it('does not count an open that failed on a closed agent socket as a lost grant', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    const bob = await later(
      testServer({
        home: h.tmp.dir,
        name: 'bob',
        relay: h.relay,
        clock: h.clock,
        timers: h.timers,
        args: ['--trust-root', P.jane.address],
        pid: 3,
      }),
    )
    // The opener's next call fails on the socket itself (a plain error, not the agent's refusal).
    vi.spyOn(AgentClient.prototype, 'open').mockRejectedValueOnce(new Error('the socket closed'))
    expect((await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'a root' })).isError).toBe(
      false,
    )
    await eventually('the root held back for a later retry', async () =>
      s.running.opened.store
        .inboxList(['received'])
        .some((r) => r.nextAt !== null && r.nextAt > h.clock.now()),
    )
    expect(logged(s, 'regrant')).toBe(false)
  })
  it('neither regrants nor probes on an open the agent refuses for another reason', async () => {
    const s = await later(grantedSession(h, 's-one', 1))
    const bob = await later(
      testServer({
        home: h.tmp.dir,
        name: 'bob',
        relay: h.relay,
        clock: h.clock,
        timers: h.timers,
        args: ['--trust-root', P.jane.address],
        pid: 3,
      }),
    )
    const probe = vi.spyOn(s.running.opened.agent as NonNullable<typeof s.running.opened.agent>, 'probe')
    const open = vi
      .spyOn(AgentClient.prototype, 'open')
      .mockRejectedValueOnce(new AgentError('rate-limited', 'too many opens'))
    expect((await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'a root' })).isError).toBe(
      false,
    )
    await eventually('the agent asked to open', async () => open.mock.calls.length > 0)
    await new Promise((r) => setTimeout(r, 50)) // the refusal's handling, if any, runs now
    expect(probe).not.toHaveBeenCalled()
    expect(logged(s, 'regrant')).toBe(false)
  })
})

describe('a session that waits for its y', () => {
  it('opens nothing when it stops before the y, and the y after the stop changes nothing', async () => {
    const s = await sessionServer(h, 's-one', 1)
    const stopped = s.close()
    h.type('y')
    await stopped
    expect(s.log.lines.some((l) => l.event === 'start' && l.level === 'info')).toBe(false)
  })

  it('names the refusal of a grant the agent will not give for its shape: an exp past the window', async () => {
    const s = await later(sessionServer(h, 's-one', 1, '--grant-exp', '+31536000'))
    await eventually('the refusal', async () => (await s.call('status')).value.error === 'exp-not-monotone')
    expect((await s.call('status')).value).toMatchObject({
      detail: expect.stringContaining('the agent refused'),
    })
  })
})

describe('the front desk of two sessions', () => {
  it('logs a retry of the held rows that failed when a session becomes the desk', async () => {
    const one = await grantedSession(h, 's-one', 1)
    const two = await later(grantedSession(h, 's-two', 2))
    vi.spyOn(two.running.opened.edge.receiver, 'recover').mockRejectedValueOnce(
      new Error('the store is busy'),
    )
    await one.close()
    h.timers.fire((ms) => ms === DESK_RETRY_MS)
    await eventually('the desk-retry line', async () => logged(two, 'desk-retry'))
    expect(two.running.front?.desk).toBe(true)
  })

  it('logs a fault of the desk timer and keeps trying', async () => {
    const one = await grantedSession(h, 's-one', 1)
    const two = await later(grantedSession(h, 's-two', 2))
    await one.close()
    mkdirSync(join(h.tmp.dir, 'state', 'jane', 'desk.lock')) // not a lock file: taking it fails
    h.timers.fire((ms) => ms === DESK_RETRY_MS)
    await eventually('the desk line', async () => logged(two, 'desk'))
    expect(h.timers.live()).toContain(DESK_RETRY_MS)
  })
})

describe('a session that cannot start', () => {
  it('passes on a fault of the process readers that is not a missing session', async () => {
    const broken = {
      ...TREE,
      info: () => {
        throw new Error('ps failed')
      },
    }
    await expect(sessionServerOf(h, 'auto', 600, broken)).rejects.toThrow('ps failed')
  })

  it('gives its mcp.lock back when its session file cannot be written', async () => {
    mkdirSync(join(h.tmp.dir, 'state'), { recursive: true })
    writeFileSync(join(h.tmp.dir, 'state', 'sessions'), 'not a directory')
    await expect(sessionServerOf(h, 'auto', 600, TREE)).rejects.toThrow()
    // A second start meets the same file, not a held lock: the first one released it.
    await expect(sessionServerOf(h, 'auto', 600, TREE)).rejects.not.toMatchObject({ code: 'busy' })
  })
})
