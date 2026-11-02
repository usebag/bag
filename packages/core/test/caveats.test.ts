import { describe, expect, it } from 'vitest'
import {
  type CaveatContext,
  type CaveatEvaluator,
  type CaveatVerdict,
  evaluateCaveats,
} from '../src/caveats.ts'
import { P, T0 } from './support/fixtures.ts'

const ctx: CaveatContext = { from: P.session.address, to: [P.bob.address], ts: T0, root: P.org.address }

function fixed(answers: Record<string, CaveatVerdict>): CaveatEvaluator {
  return { name: 'fixed', evaluate: (caveat) => answers[caveat] ?? 'unknown' }
}

describe('evaluateCaveats', () => {
  it('is ok when every caveat holds, and for no caveats at all', () => {
    expect(evaluateCaveats(['a', 'b'], [fixed({ a: 'hold', b: 'hold' })], ctx)).toEqual({ ok: true })
    expect(evaluateCaveats([], [], ctx)).toEqual({ ok: true })
  })

  it('fails closed on a caveat no evaluator knows', () => {
    expect(evaluateCaveats(['a', 'z'], [fixed({ a: 'hold' })], ctx)).toEqual({
      ok: false,
      code: 'unknown-caveat',
      caveat: 'z',
    })
    expect(evaluateCaveats(['a'], [], ctx)).toEqual({ ok: false, code: 'unknown-caveat', caveat: 'a' })
  })

  it('fails a caveat that does not hold', () => {
    expect(evaluateCaveats(['a'], [fixed({ a: 'fail' })], ctx)).toEqual({
      ok: false,
      code: 'caveat-failed',
      caveat: 'a',
    })
  })

  it('fails a caveat that needs the sealed part: the edge evaluates after unsealing', () => {
    expect(evaluateCaveats(['a'], [fixed({ a: 'needs-sealed' })], ctx)).toEqual({
      ok: false,
      code: 'caveat-failed',
      caveat: 'a',
    })
  })

  it('stops at the first caveat that does not hold, in chain order', () => {
    const r = evaluateCaveats(['a', 'b', 'c'], [fixed({ a: 'hold', b: 'fail', c: 'unknown' })], ctx)
    expect(r).toEqual({ ok: false, code: 'caveat-failed', caveat: 'b' })
  })

  it('needs one hold and no fail across evaluators', () => {
    const yes = fixed({ a: 'hold' })
    const no = fixed({ a: 'fail' })
    const blind = fixed({})
    expect(evaluateCaveats(['a'], [blind, yes], ctx)).toEqual({ ok: true })
    expect(evaluateCaveats(['a'], [yes, no], ctx).ok).toBe(false)
    expect(evaluateCaveats(['a'], [no, yes], ctx).ok).toBe(false)
  })

  it('treats an evaluator that throws as a fail', () => {
    const broken: CaveatEvaluator = {
      name: 'broken',
      evaluate: () => {
        throw new Error('boom')
      },
    }
    expect(evaluateCaveats(['a'], [fixed({ a: 'hold' }), broken], ctx)).toEqual({
      ok: false,
      code: 'caveat-failed',
      caveat: 'a',
    })
  })

  it('treats an answer outside the four verdicts as unknown', () => {
    const odd: CaveatEvaluator = { name: 'odd', evaluate: () => 'maybe' as CaveatVerdict }
    expect(evaluateCaveats(['a'], [odd], ctx)).toEqual({ ok: false, code: 'unknown-caveat', caveat: 'a' })
  })
})
