import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateEdgeKeys, HomeCustody } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { GRANT_RETRY_MS } from '../src/session.ts'
import { P, type TestServer, testServer, until } from './support/fixtures.ts'
import { seededRng } from './support/ports.ts'
import { type AgentHome, agentHome, eventually, grantedSession, sessionServer } from './support/sessions.ts'

// A grant the agent no longer holds (r11 red team 1): after ac logout and a new ac login the session's old hop is not in
// the new window's grant-set. The session finds out (a probe), asks a new grant (one more y) under a fresh key, since
// the logout revoked the old one (spec/SPEC.md §13.5, "Re-grant after a revocation"), opens its edge again and
// registers its threads again, so a reply on a thread it sent on before the logout still reaches it.

let h: AgentHome
let s: TestServer
let bob: TestServer

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
  s = await grantedSession(h, 's-one', 1)
  bob = await testServer({
    home: h.tmp.dir,
    name: 'bob',
    relay: h.relay,
    clock: h.clock,
    timers: h.timers,
    args: ['--trust-root', P.jane.address, '--honor', 'coding'],
    pid: 3,
  })
})

afterEach(async () => {
  await s.close()
  await bob.close()
  await h.agent.close()
  h.tmp.cleanup()
})

/** The address of a session's key file now. */
const keyOf = (name: string): string => new HomeCustody(h.tmp.dir).files.entry(name).address

/** The subject of the hop in a session's grant.json. */
function subOf(name: string): unknown {
  const file = join(h.tmp.dir, 'state', name, 'grant.json')
  return (JSON.parse(readFileSync(file, 'utf8')) as { sub?: unknown }[])[0]?.sub
}

/** The agent refuses `revoked` a grant for `address`, as for a key in the principal's revoked list; asks are noted. */
function revokedAt(address: string): string[] {
  const asked: string[] = []
  const real = h.core.prepareGrant.bind(h.core)
  vi.spyOn(h.core, 'prepareGrant').mockImplementation((g) => {
    asked.push(g.session)
    return g.session === address ? { ok: false, code: 'revoked' } : real(g)
  })
  return asked
}

describe('a new login while a session is open', () => {
  it('asks a new grant under a fresh key, opens again, and registers the old threads again', async () => {
    const before = keyOf('s-one')
    // A thread the session sends on before the logout; bob will reply on it after the regrant.
    const pending = bob.call('wait', { timeout_s: 30 })
    expect((await s.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'before' })).isError).toBe(
      false,
    )
    const got = (await pending).value.message as { reply: Record<string, unknown> }
    const codes = h.codes().length
    // The logout drops the window's grants and registrations; the new login opens an empty window.
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the waiting line with a new request code', async () => {
      const r = await s.call('status')
      return r.isError && String(r.value.detail).includes('request') && h.codes().length === codes + 1
    })
    const [, code] = [codes, h.codes()[codes]]
    expect((await s.call('status')).value).toMatchObject({
      error: 'grant-pending',
      detail: `s-one: waiting for y at the agent, request ${code}`,
    })
    h.type('y')
    await eventually('the session open again', async () => !(await s.call('status')).isError)
    // A fresh key, never the revoked one, and the new grant names it.
    const after = keyOf('s-one')
    expect(after).not.toBe(before)
    expect(subOf('s-one')).toBe(after)
    // The reply on the old thread: released to this session only because the thread was registered again.
    await bob.call('send', { ...got.reply, type: 'chat.v1', body: 'after the regrant' })
    await until('the session accepts the reply', () => s.running.desk.counts().counts.accepted >= 1)
  })

  it('asks again every retry while no agent window is open (a logout, no login yet)', async () => {
    h.core.logout()
    s.running.opened.agent?.probe()
    await eventually('the no-agent line', async () =>
      String((await s.call('status')).value.detail).includes('run ac login'),
    )
    h.agent.login(P.jane.keys)
    h.timers.fire((ms) => ms === GRANT_RETRY_MS)
    await eventually('the prompt', async () => h.codes().length === 2)
    h.type('y')
    await eventually('the session open again', async () => !(await s.call('status')).isError)
  })

  it('does not ask a new grant while the grant is live: a probe changes nothing', async () => {
    s.running.opened.agent?.probe()
    await new Promise((r) => setTimeout(r, 50))
    expect((await s.call('status')).isError).toBe(false)
    expect(h.codes()).toHaveLength(1)
  })

  it('is not the desk while it waits for its new y: the lock goes, and comes back with the grant', async () => {
    const lock = join(h.tmp.dir, 'state', 'jane', 'desk.lock')
    expect(existsSync(lock)).toBe(true)
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the waiting line', async () => (await s.call('status')).value.error === 'grant-pending')
    expect(existsSync(lock)).toBe(false) // the others take roots while this session waits
    h.type('y')
    await eventually('the session open again', async () => !(await s.call('status')).isError)
    expect(existsSync(lock)).toBe(true)
  })

  it('gives up the desk lock only after the old receiver has halted, as at stop', async () => {
    const order: string[] = []
    const edge = s.running.opened.edge
    const stop = edge.stop.bind(edge)
    vi.spyOn(edge, 'stop').mockImplementation(async () => {
      order.push('edge stopped')
      return stop()
    })
    const front = s.running.front as NonNullable<typeof s.running.front>
    const pause = front.pause.bind(front)
    vi.spyOn(front, 'pause').mockImplementation(() => {
      order.push('desk paused')
      pause()
    })
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the waiting line', async () => (await s.call('status')).value.error === 'grant-pending')
    await eventually('the old edge stopped and the desk paused', async () => order.length === 2)
    expect(order).toEqual(['edge stopped', 'desk paused'])
    h.type('y')
    await eventually('the session open again', async () => !(await s.call('status')).isError)
  })

  it('replaces a kept key the agent refuses revoked, and asks once more under the fresh key: one prompt', async () => {
    // A key left by an earlier server of this session, named by its grant.json, from before a logout.
    const keys = generateEdgeKeys(seededRng('kept'))
    const kept = keys.signing.address
    new HomeCustody(h.tmp.dir).create('s-two', keys, { custody: 'file' })
    mkdirSync(join(h.tmp.dir, 'state', 's-two'), { recursive: true, mode: 0o700 })
    writeFileSync(join(h.tmp.dir, 'state', 's-two', 'grant.json'), JSON.stringify([{ sub: kept }]), {
      mode: 0o600,
    })
    const asked = revokedAt(kept)
    const codes = h.codes().length
    const two = await sessionServer(h, 's-two', 2)
    h.type('y')
    await two.running.ready
    const fresh = keyOf('s-two')
    expect(fresh).not.toBe(kept)
    expect(asked).toEqual([kept, fresh])
    expect(subOf('s-two')).toBe(fresh)
    expect(h.codes()).toHaveLength(codes + 1) // the agent refused the kept key before its prompt
    await two.close()
    expect(existsSync(join(h.tmp.dir, 'keys', 's-two.json'))).toBe(false) // the session's own key goes at close
  })

  it('never replaces a key file the person made: its revoked grant is refused revoked, naming the way out', async () => {
    const keys = generateEdgeKeys(seededRng('own'))
    const own = keys.signing.address
    new HomeCustody(h.tmp.dir).create('s-three', keys, { custody: 'file' })
    revokedAt(own)
    const three = await sessionServer(h, 's-three', 2)
    await expect(three.running.ready).rejects.toMatchObject({ code: 'revoked' })
    const r = await three.call('status')
    expect(r.value.error).toBe('revoked')
    expect(String(r.value.detail)).toContain('keys/s-three.json predates this server')
    await three.close()
    expect(keyOf('s-three')).toBe(own)
  })

  it('at a re-grant, leaves a key file the person made and refuses revoked', async () => {
    const keys = generateEdgeKeys(seededRng('own'))
    const own = keys.signing.address
    new HomeCustody(h.tmp.dir).create('s-four', keys, { custody: 'file' })
    const four = await grantedSession(h, 's-four', 2)
    h.core.logout()
    h.agent.login(P.jane.keys)
    four.running.opened.agent?.probe()
    await eventually('the revoked refusal', async () => (await four.call('status')).value.error === 'revoked')
    expect(keyOf('s-four')).toBe(own)
    await four.close()
    expect(keyOf('s-four')).toBe(own)
  })

  it('finds out at once when a send meets a closed agent socket, and asks again every retry', async () => {
    await h.agent.close() // the agent process went away: its window and its grants with it
    await s.running.opened.agent?.register('ab'.repeat(32)).catch(() => {}) // what a send does first
    await eventually('the no-agent line', async () =>
      String((await s.call('status')).value.detail).includes('run ac login'),
    )
  })
})
