import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import type { InboundMessage, SessionHandler } from '../src/ports.ts'
import { Router } from '../src/router.ts'
import { FakeClock, P, T0, tempDir } from './support/fixtures.ts'

const tmp = tempDir('router')
afterAll(() => tmp.cleanup())

function message(thread: string, prev: readonly string[] = []): InboundMessage {
  return {
    id: 'ee'.repeat(32),
    from: P.session.address,
    principal: P.jane.address,
    root: P.org.address,
    to: [P.bob.address],
    ts: T0,
    type: 'chat.v1',
    thread: { id: thread, prev },
    body: null,
    caveats: [],
    relay: 'http://r',
  }
}

function sink(session: string, into: string[]): SessionHandler {
  return { session, deliver: (m) => void into.push(`${session} ${m.thread.id.slice(0, 2)}`) }
}

describe('Router (spec/SPEC.md §9.6)', () => {
  it('keeps threads(thread_id, session_id) across a fresh store instance, so replies reach the opener', async () => {
    const path = join(tmp.dir, 'router.sqlite')
    const first = new SqliteStore(path)
    const r1 = new Router(first, new FakeClock())
    const got: string[] = []
    r1.register('aa'.repeat(32), sink('coder-1', got))
    r1.bind('bb'.repeat(32), 'coder-1')
    r1.bind('bb'.repeat(32), 'someone-else')
    first.close()

    const second = new SqliteStore(path)
    const r2 = new Router(second, new FakeClock())
    expect(await r2.route(message('aa'.repeat(32), ['cc'.repeat(32)]))).toEqual({
      state: 'queued',
      session: null,
      error: null,
    })
    r2.attach(sink('coder-1', got))
    expect(await r2.route(message('aa'.repeat(32), ['cc'.repeat(32)]))).toEqual({
      state: 'routed',
      session: 'coder-1',
      error: null,
    })
    expect(await r2.route(message('bb'.repeat(32), ['cc'.repeat(32)]))).toMatchObject({ session: 'coder-1' })
    expect(got).toEqual(['coder-1 aa', 'coder-1 bb'])
    second.close()
  })

  it('records each use of a bound thread: a bind of a bound thread, a register and a route to it', async () => {
    const store = new SqliteStore(':memory:')
    const clock = new FakeClock()
    const router = new Router(store, clock)
    const [a, b] = ['aa'.repeat(32), 'bb'.repeat(32)]
    router.bind(a, 'coder-1')
    clock.advance(10)
    router.bind(a, 'someone-else')
    expect(store.threadGet(a)).toBe('coder-1')
    expect(store.threadsPrune(T0 + 10)).toBe(0)
    clock.advance(10)
    router.register(b, sink('coder-2', []))
    clock.advance(10)
    // coder-1 is not live: the reply queues, and the thread counts as used.
    expect(await router.route(message(a, ['cc'.repeat(32)]))).toMatchObject({ state: 'queued' })
    expect(store.threadsPrune(T0 + 21)).toBe(1)
    expect([store.threadGet(a), store.threadGet(b)]).toEqual(['coder-1', null])
    expect(store.threadsPrune(T0 + 31)).toBe(1)
  })

  it('sends a root on an unknown thread to the default handler, binding the thread to it', async () => {
    const store = new SqliteStore(':memory:')
    const router = new Router(store, new FakeClock())
    const got: string[] = []
    expect(await router.route(message('dd'.repeat(32)))).toMatchObject({ state: 'queued' })
    router.setDefault(sink('inbox', got))
    expect(await router.route(message('dd'.repeat(32)))).toMatchObject({ state: 'routed', session: 'inbox' })
    expect(store.threadGet('dd'.repeat(32))).toBe('inbox')
    router.setDefault(null)
    expect(await router.route(message('ff'.repeat(32)))).toMatchObject({ state: 'queued' })
    expect(await router.route(message('dd'.repeat(32), ['01'.repeat(32)]))).toMatchObject({ state: 'routed' })
  })
})
