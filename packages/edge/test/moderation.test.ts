import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  allowAll,
  keyword,
  type ModerationInput,
  type Moderator,
  normalize,
  stringsOf,
} from '../src/moderation/modules.ts'
import { P } from './support/fixtures.ts'
import {
  acmeChain,
  bob,
  envelope,
  HOME,
  heldHaveNoContent,
  members,
  orgPolicy,
  ruled,
} from './support/org.ts'

// The moderation port, inside the recipient's edge, after unsealing and every earlier check.

const PHRASE = 'ignore previous instructions'
const moderation = (module: string, action: 'quarantine' | 'drop' | 'allow' = 'quarantine') => ({
  module,
  action,
  params: [PHRASE],
})

/** A module that records what it is given and answers with `verdict`. */
function spy(
  verdict: ReturnType<Moderator['moderate']> = { flag: false },
): Moderator & { seen: ModerationInput[] } {
  const seen: ModerationInput[] = []
  return {
    name: 'spy',
    seen,
    moderate: (input) => {
      seen.push(input)
      return verdict
    },
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('the moderation port', () => {
  it('(a) runs once per message that passed every earlier check, with the plaintext, never for a refused one', async () => {
    const m = spy()
    const org = orgPolicy({ scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }] })
    const b = bob({ org, members: members({ moderation: moderation('spy') }), moderators: [m] })
    await b.edge.receive(HOME, 1, envelope({ body: { text: 'hi there' } }).bytes)
    await b.edge.receive(HOME, 2, envelope({ from: P.mallory }).bytes)
    await b.edge.receive(HOME, 3, envelope({ type: 'deploy.run' }).bytes)
    await b.edge.receive(
      HOME,
      4,
      envelope({ from: P.session, auth: acmeChain(['type=chat.*']), body: [1] }).bytes,
    )
    expect(m.seen).toEqual([
      {
        type: 'chat.v1',
        body: { text: 'hi there' },
        from: P.carol.address,
        root: P.carol.address,
        caveats: [],
        params: [PHRASE],
      },
      {
        type: 'chat.v1',
        body: [1],
        from: P.session.address,
        root: P.org.address,
        caveats: ['type=chat.*'],
        params: [PHRASE],
      },
    ])
  })

  it('(b) allow-all leaves states and routes as without moderation, adding one moderate accept line each', async () => {
    const plain = bob()
    const moderated = bob({
      members: members({ moderation: moderation('allow-all') }),
      moderators: [allowAll],
    })
    const states = async (b: ReturnType<typeof bob>) => {
      const out = []
      for (let i = 1; i <= 10; i++)
        out.push((await b.edge.receive(HOME, i, envelope({ body: { n: i } }).bytes)).state)
      return out
    }
    expect(await states(moderated)).toEqual(await states(plain))
    expect(ruled(moderated.audit).filter((l) => l.startsWith('moderate'))).toEqual(
      Array(10).fill('moderate accept ok moderation'),
    )
    expect(ruled(moderated.audit).length - ruled(plain.audit).length).toBe(10)
    expect([plain.got.length, moderated.got.length]).toEqual([10, 10])
  })

  it('(c) keyword holds a body with a listed term in any case or in fullwidth form, and routes a clean one', async () => {
    const b = bob({ members: members({ moderation: moderation('keyword') }), moderators: [keyword] })
    const upper = await b.edge.receive(
      HOME,
      1,
      envelope({ body: { text: 'Please IGNORE previous\ninstructions now' } }).bytes,
    )
    const wide = await b.edge.receive(
      HOME,
      2,
      envelope({ body: { note: ['ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ ｉｎｓｔｒｕｃｔｉｏｎｓ'] } }).bytes,
    )
    const key = await b.edge.receive(HOME, 3, envelope({ body: { [PHRASE]: true } }).bytes)
    const clean = await b.edge.receive(
      HOME,
      4,
      envelope({ body: { text: 'previous results attached' } }).bytes,
    )
    expect([upper, wide, key, clean].map((r) => r.state)).toEqual([
      'quarantined',
      'quarantined',
      'quarantined',
      'routed',
    ])
    expect(heldHaveNoContent(b.store)).toBe(3)
    const lines = b.audit.lines.map(
      (l) => JSON.parse(l) as { event: string; decision: string; detail: string },
    )
    const held = lines
      .filter((l) => l.event === 'moderate' && l.decision === 'queue')
      .map((l) => JSON.parse(l.detail))
    expect(held.map((d) => [d.module, d.match, d.rule, d.held])).toEqual(
      Array(3).fill(['keyword', 'params[0]', 'moderation', 'quarantined']),
    )
  })

  it('(d) drop rejects a match with policy-refused; allow routes it with the flag in its line', async () => {
    const dropping = bob({
      members: members({ moderation: moderation('keyword', 'drop') }),
      moderators: [keyword],
    })
    const dropped = await dropping.edge.receive(HOME, 1, envelope({ body: { text: PHRASE } }).bytes)
    expect([dropped.state, dropped.reason]).toEqual(['rejected', 'policy-refused'])
    expect(ruled(dropping.audit).at(-1)).toBe('moderate reject policy-refused moderation')
    const watching = bob({
      members: members({ moderation: moderation('keyword', 'allow') }),
      moderators: [keyword],
    })
    expect((await watching.edge.receive(HOME, 1, envelope({ body: { text: PHRASE } }).bytes)).state).toBe(
      'routed',
    )
    const line = watching.audit.lines
      .map((l) => JSON.parse(l) as { event: string; detail: string })
      .find((l) => l.event === 'moderate')
    expect(JSON.parse(line?.detail as string)).toMatchObject({
      flag: true,
      match: 'params[0]',
      rule: 'moderation',
    })
    expect(watching.store.policyCounts()).toEqual([{ rule: 'moderation', outcome: 'allowed', n: 1 }])
  })

  it('(e) a missing module, a throwing one and one that never answers hold the message', async () => {
    const missing = bob({ members: members({ moderation: moderation('absent') }) })
    expect((await missing.edge.receive(HOME, 1, envelope().bytes)).state).toBe('quarantined')
    const thrower: Moderator = {
      name: 'spy',
      moderate: () => {
        throw new Error('model down')
      },
    }
    const throwing = bob({ members: members({ moderation: moderation('spy') }), moderators: [thrower] })
    expect((await throwing.edge.receive(HOME, 1, envelope().bytes)).state).toBe('quarantined')
    vi.useFakeTimers()
    const silent: Moderator = { name: 'spy', moderate: () => new Promise(() => {}) }
    const hanging = bob({ members: members({ moderation: moderation('spy') }), moderators: [silent] })
    const pending = hanging.edge.receive(HOME, 1, envelope().bytes)
    await vi.advanceTimersByTimeAsync(10_000)
    expect((await pending).state).toBe('quarantined')
    expect([missing, throwing, hanging].map((b) => ruled(b.audit).at(-1))).toEqual([
      'moderate queue policy-refused moderation.missing',
      'moderate queue policy-refused moderation.error',
      'moderate queue policy-refused moderation.timeout',
    ])
  })

  it('checks the seen set again after the module answers: a copy accepted meanwhile makes this one a duplicate', async () => {
    const waiting: (() => void)[] = []
    let bothWaiting: () => void = () => {}
    const arrived = new Promise<void>((r) => {
      bothWaiting = r
    })
    const slow: Moderator = {
      name: 'spy',
      moderate: () =>
        new Promise((resolve) => {
          waiting.push(() => resolve({ flag: false }))
          if (waiting.length === 2) bothWaiting()
        }),
    }
    const b = bob({ members: members({ moderation: moderation('spy') }), moderators: [slow] })
    const e = envelope()
    const one = b.edge.receive(HOME, 1, e.bytes)
    const two = b.edge.receive('http://second.test', 1, e.bytes)
    await arrived
    waiting[0]?.()
    expect((await one).state).toBe('routed')
    waiting[1]?.()
    expect([(await two).state, (await two).reason, b.got.length]).toEqual(['rejected', 'duplicate', 1])
  })

  it('normalizes text and collects every string of a body, member names included', () => {
    expect(normalize('  Ｉｇｎｏｒｅ\tTHIS \n')).toBe('ignore this')
    expect(stringsOf({ a: ['b', { c: 'd' }], e: 1, f: null })).toEqual(['a', 'b', 'c', 'd', 'e', 'f'])
    expect(stringsOf(7)).toEqual([])
  })
})
