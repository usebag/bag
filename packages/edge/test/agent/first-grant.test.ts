import { AcError } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  clampLife,
  EXP_TEXT,
  expOf,
  type GrantReply,
  MIN_LIFE,
  requestGrant,
  WINDOW_MAX,
} from '../../src/agent/index.ts'
import { FakeClock, P, T0 } from '../support/fixtures.ts'

// A session's first grant: the exp as a flag spells it, and the ask that halves its life until the login
// window admits it.

const HOP = { iss: P.jane.address, sub: P.session.address, caveats: ['type=chat.*'], exp: T0 + 60, sig: 'aa' }

/** Connections whose grant answers each reply in turn (an Error is thrown), recording the exps asked and the closes. */
function connections(replies: readonly (GrantReply | Error)[]) {
  const asked: number[] = []
  const state = { closed: 0 }
  const connect = () => ({
    grant: async (_s: string, _c: readonly string[], exp: number, onCode?: (code: string) => void) => {
      onCode?.('K7')
      asked.push(exp)
      const r = replies[asked.length - 1] as GrantReply | Error
      if (r instanceof Error) throw r
      return r
    },
    close: () => {
      state.closed++
    },
  })
  return { connect, asked, state }
}

const refusal = { ok: false, code: 'exp-not-monotone' } as GrantReply

describe('EXP_TEXT and expOf', () => {
  it('takes unix seconds or +seconds and nothing else', () => {
    for (const ok of ['1800003600', '+3600', '1']) expect(EXP_TEXT.test(ok)).toBe(true)
    for (const bad of ['soon', '-60', '+0', '0', '1.5', '+', '', '12345678901234567']) {
      expect(EXP_TEXT.test(bad)).toBe(false)
    }
    expect(expOf('1800003600', T0)).toBe(1_800_003_600)
    expect(expOf('+3600', T0)).toBe(T0 + 3600)
  })
})

describe('requestGrant', () => {
  const ask = (c: ReturnType<typeof connections>, exp: string | null, codes: string[] = []) =>
    requestGrant(c.connect, P.session.address, ['type=chat.*'], exp, new FakeClock(), (code) =>
      codes.push(code),
    )

  it('asks for the window longest life, passes the code on, and closes the connection', async () => {
    const c = connections([{ ok: true, hop: HOP }])
    const codes: string[] = []
    expect(await ask(c, null, codes)).toEqual({ ok: true, hop: HOP })
    expect(c.asked).toEqual([T0 + WINDOW_MAX])
    expect(codes).toEqual(['K7'])
    expect(c.state.closed).toBe(1)
  })

  it('halves the life while the agent says exp-not-monotone', async () => {
    const c = connections([refusal, refusal, { ok: true, hop: HOP }])
    expect(await ask(c, null)).toMatchObject({ ok: true })
    expect(c.asked).toEqual([T0 + 28_800, T0 + 14_400, T0 + 7200])
    expect(c.state.closed).toBe(3)
  })

  it('stops halving at a minute, and never halves an exp it was given', async () => {
    const down = connections(Array.from({ length: 12 }, () => refusal))
    expect(await ask(down, null)).toEqual(refusal)
    expect(down.asked.at(-1)).toBe(T0 + 56)
    const given = connections([refusal])
    expect(await ask(given, '+3600')).toEqual(refusal)
    expect(given.asked).toEqual([T0 + 3600])
  })

  it('returns other refusals as they are, and null when no agent answers', async () => {
    const declined = { ok: false, code: 'declined' } as GrantReply
    expect(await ask(connections([declined]), null)).toEqual(declined)
    const none = connections([new Error('ENOENT')])
    expect(await ask(none, null)).toBeNull()
    expect(none.state.closed).toBe(1)
  })
})

describe('requestGrant: the hop must be the key asked for', () => {
  it('refuses bad-hop for a hop to another subject, and passes the same subject', async () => {
    const other = { ...HOP, sub: P.bob.address }
    const c = connections([{ ok: true, hop: other }])
    const r = await requestGrant(
      c.connect,
      P.session.address,
      ['type=chat.*'],
      null,
      new FakeClock(),
      () => {},
    )
    expect(r).toEqual({ ok: false, code: 'bad-hop' })
  })
})

describe('clampLife: a renewal clamped by the agent answer', () => {
  const past = new AcError('exp-not-monotone', 'exp is past the window')

  it('halves while the exp is past the window, down to the shortest life, then throws', async () => {
    const asked: number[] = []
    const got = await clampLife(28_800, async (life) => {
      asked.push(life)
      if (life > 3600) throw past
      return life
    })
    expect(got).toBe(3600)
    expect(asked).toEqual([28_800, 14_400, 7200, 3600])
    const floor: number[] = []
    await expect(
      clampLife(240, async (life) => {
        floor.push(life)
        throw past
      }),
    ).rejects.toBe(past)
    expect(floor).toEqual([240, 120, 60])
    expect(MIN_LIFE).toBe(60)
  })

  it('does not retry any other error', async () => {
    const calls: number[] = []
    const other = new AcError('rate-limited', 'slow down')
    await expect(
      clampLife(600, async (life) => {
        calls.push(life)
        throw other
      }),
    ).rejects.toBe(other)
    expect(calls).toEqual([600])
  })
})
