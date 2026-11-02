import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { DESK_RETRY_MS } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { P, type TestServer, testServer, until } from './support/fixtures.ts'
import { type AgentHome, agentHome, grantedSession } from './support/sessions.ts'

// Two sessions of one principal under one agent: one session, the holder of desk.lock, takes root
// messages; the unit tests of the desk itself are the edge's (packages/edge/test/agent/front-desk.test.ts). A reply
// goes to the session that registered its thread, and the desk hands over at close with no root answered twice.

describe('two sessions of jane under one agent', () => {
  let h: AgentHome
  let one: TestServer | null
  let two: TestServer
  let bob: TestServer

  beforeEach(async () => {
    h = await agentHome()
    h.agent.login(P.jane.keys)
    one = await grantedSession(h, 's-one', 1)
    two = await grantedSession(h, 's-two', 2)
    const args = ['--trust-root', P.jane.address, '--honor', 'coding']
    bob = await testServer({
      home: h.tmp.dir,
      name: 'bob',
      relay: h.relay,
      clock: h.clock,
      timers: h.timers,
      args,
      pid: 3,
    })
  })

  afterEach(async () => {
    await one?.close()
    await two.close()
    await bob.close()
    await h.agent.close()
    h.tmp.cleanup()
  })

  const counts = (s: TestServer | null): { accepted: number; rejected: number } => {
    const { accepted, rejected } = (s as TestServer).running.desk.counts().counts
    return { accepted, rejected }
  }

  it('makes the first session the desk: a root from a peer is accepted there only', async () => {
    expect((await (one as TestServer).call('status')).value).toMatchObject({ session: 's-one', desk: true })
    expect((await two.call('status')).value).toMatchObject({ session: 's-two', desk: false })
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'a root' })
    await until('the desk accepts it', () => counts(one).accepted === 1)
    expect((await (one as TestServer).call('inbox')).value.messages).toMatchObject([{ body: 'a root' }])
    expect(counts(two)).toEqual({ accepted: 0, rejected: 0 })
  })

  it('routes a reply to the session that sent on its thread, never to the desk', async () => {
    const two_ = two
    const pending = bob.call('wait', { timeout_s: 30 })
    expect(
      (await two_.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'from two' })).isError,
    ).toBe(false)
    const got = (await pending).value.message as { reply: Record<string, unknown> }
    await bob.call('send', { ...got.reply, type: 'chat.v1', body: 'back to two' })
    await until('two accepts the reply', () => counts(two_).accepted === 1)
    await until('the desk refuses it', () => counts(one).rejected === 1)
    expect(counts(one).accepted).toBe(0)
  })

  it('hands the desk over at close: the waiting root not in the ledger is accepted, none twice', async () => {
    const two_ = two
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'first' })
    await until('the desk accepts the first', () => counts(one).accepted === 1)
    await one?.close()
    one = null
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'second' })
    // two held both roots back; it takes the desk at its next try and retries them at once: no clock moves, so the
    // outbox's backoff (up to an hour) has not come due.
    h.timers.fire((ms) => ms === DESK_RETRY_MS)
    expect((await two_.call('status')).value).toMatchObject({ desk: true })
    await until('two accepts the second', () => counts(two_).accepted === 1, 10_000)
    await until('two refuses the first', () => counts(two_).rejected === 1, 10_000)
    expect((await two_.call('inbox')).value.messages).toMatchObject([{ body: 'second' }])
  })

  it('releases the desk lock only after the receiver has halted (the edge stopped)', async () => {
    const lock = join(h.tmp.dir, 'state', 'jane', 'desk.lock')
    const edge = (one as TestServer).running.opened.edge
    const stop = edge.stop.bind(edge)
    const seen: boolean[] = []
    edge.stop = async () => {
      seen.push(existsSync(lock)) // held while the receiver is still running
      await stop()
      seen.push(existsSync(lock)) // and still held when it has halted
    }
    await (one as TestServer).running.stop()
    expect(seen).toEqual([true, true])
    expect(existsSync(lock)).toBe(false)
  })

  it('retries the roots it held back at once when it becomes the desk, with the clock not moved', async () => {
    const two_ = two
    // The desk's receiver is halted but it still holds the lock, so only the second session sees the root: it holds it
    // back, a retry due a second later on the (fake, fixed) clock.
    await (one as TestServer).running.opened.edge.stop()
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'held' })
    const store = two_.running.opened.store
    await until('the second session holds the root back', () =>
      store.inboxList(['received']).some((r) => r.nextAt !== null && r.nextAt > h.clock.t),
    )
    expect(counts(two_)).toEqual({ accepted: 0, rejected: 0 })
    await one?.close()
    one = null
    h.timers.fire((ms) => ms === DESK_RETRY_MS)
    await until('the root is accepted without the clock moving', () => counts(two_).accepted === 1)
    expect((await two_.call('inbox')).value.messages).toMatchObject([{ body: 'held' }])
  })
})
