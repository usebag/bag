import { describe, expect, it } from 'vitest'
import { quietNotice, RING, type Ringable, SETTLE_MS, WakeRouter } from '../src/wake-router.ts'
import { FakeClock, ManualTimers, T0 } from './support/fixtures.ts'

// The wake router: mail for an identity rings the connection the person last typed in for it, speaking: true, and
// the others speaking: false; one ring per connection per batch; nothing for a connection bound to another identity.

interface Conn extends Ringable {
  readonly got: { method: string; params: Record<string, unknown> }[]
}

function conn(handle: string, fail = false): Conn {
  const got: Conn['got'] = []
  return {
    handle,
    got,
    notify(method, params) {
      if (fail) throw new Error('closed')
      got.push({ method, params: { ...params } })
    },
  }
}

function router(unread = 2): { r: WakeRouter; clock: FakeClock; timers: ManualTimers } {
  const clock = new FakeClock()
  const timers = new ManualTimers()
  return { r: new WakeRouter({ clock, timers, unread: () => unread }), clock, timers }
}

const at = (t: number): string => new Date(t * 1000).toISOString()

describe('the wake router', () => {
  it('rings the window the person last typed in, a quiet notice to the other, and nothing to another identity', () => {
    const { r, clock } = router()
    const [a, b, c] = [conn('c-a'), conn('c-b'), conn('c-c')]
    r.bind('omp', a)
    clock.t += 1
    r.bind('omp', b)
    r.bind('omp-3', c)
    clock.t += 1
    r.typed('c-a')
    expect(r.speaking('omp')).toBe('c-a')
    r.ring('omp')
    expect(a.got).toEqual([
      { method: RING, params: { as: 'omp', unread: 2, speaking: true, at: at(T0 + 2) } },
    ])
    expect(b.got).toEqual([
      { method: 'service/ring', params: { as: 'omp', unread: 2, speaking: false, at: at(T0 + 2) } },
    ])
    expect(c.got).toEqual([])
  })

  it('counts a bind as typing, breaks a tie by the later act, and moves the speaker with each typed word', () => {
    const { r } = router()
    r.bind('omp', conn('c-a'))
    r.bind('omp', conn('c-b'))
    expect(r.speaking('omp')).toBe('c-b')
    r.typed('c-a')
    expect(r.speaking('omp')).toBe('c-a')
    r.typed('c-b')
    expect(r.speaking('omp')).toBe('c-b')
  })

  it('hands the speaking seat on when its connection closes, and rings no one once none is bound', () => {
    const { r, clock } = router()
    const [a, b] = [conn('c-a'), conn('c-b')]
    r.bind('omp', a)
    clock.t += 1
    r.bind('omp', b)
    r.unbind('c-b')
    expect(r.speaking('omp')).toBe('c-a')
    r.unbind('c-a', 'omp')
    expect([r.speaking('omp'), r.ring('omp').size]).toEqual([null, 0])
  })

  it('makes one ring per connection of a burst, after the settle wait, and none when a wait took it all', () => {
    const { r, timers } = router()
    const a = conn('c-a')
    r.bind('omp', a)
    r.arrived('omp')
    r.arrived('omp')
    r.arrived('omp')
    expect([timers.live(), a.got.length]).toEqual([[SETTLE_MS], 0])
    timers.fire()
    expect(a.got).toHaveLength(1)
    const empty = router(0)
    const b = conn('c-b')
    empty.r.bind('omp', b)
    empty.r.arrived('omp')
    empty.timers.fire()
    expect(b.got).toEqual([])
  })

  it('gives a window that is not speaking the one quiet notice line, no question in it', () => {
    expect(quietNotice('omp', 2)).toBe(
      'bag: 2 unread for omp, shown in the window you last typed in for omp; type here to have the next mail shown here',
    )
  })

  it('rings the rest when one connection fails under the ring', () => {
    const { r } = router()
    const ok = conn('c-ok')
    r.bind('omp', conn('c-gone', true))
    r.bind('omp', ok)
    expect([...r.ring('omp').keys()]).toEqual(['c-ok'])
    expect(ok.got).toHaveLength(1)
  })
})
