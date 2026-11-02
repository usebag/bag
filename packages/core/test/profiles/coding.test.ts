import { describe, expect, it } from 'vitest'
import { type CaveatContext, evaluateCaveats } from '../../src/caveats.ts'
import { codingEvaluator, evaluateCodingCaveat } from '../../src/profiles/coding.ts'
import { P, T0 } from '../support/fixtures.ts'

const outer = { from: P.session.address, to: [P.bob.address], ts: T0, root: P.org.address }
const thread = { id: '00'.repeat(32), prev: [] }
const withSealed = (type: string, body: unknown): CaveatContext => ({
  ...outer,
  sealed: { type, thread, body },
})

describe('the coding profile', () => {
  it.each([
    ['type=coding.task.v1', 'coding.task.v1', 'hold'],
    ['type=coding.task.v1', 'coding.task.v2', 'fail'],
    ['type=coding.*', 'coding.task.v1', 'hold'],
    ['type=coding.*', 'coding', 'fail'],
    ['type=coding.*', 'codingx.task', 'fail'],
    ['type=coding.task.*', 'coding.task.v1', 'hold'],
    ['type=coding.task.*', 'coding.result.v1', 'fail'],
  ] as const)('%s against type %s: %s', (caveat, type, verdict) => {
    expect(evaluateCodingCaveat(caveat, withSealed(type, {}))).toBe(verdict)
  })

  it.each([
    [{ repo: 'acme/api' }, 'hold'],
    [{ repo: 'acme/web' }, 'fail'],
    [{ repo: 7 }, 'fail'],
    [{}, 'fail'],
    ['acme/api', 'fail'],
    [['acme/api'], 'fail'],
    [null, 'fail'],
  ] as const)('repo=acme/api against body %j: %s', (body, verdict) => {
    expect(evaluateCodingCaveat('repo=acme/api', withSealed('coding.task.v1', body))).toBe(verdict)
  })

  it('needs the sealed part for type= and repo=', () => {
    expect(evaluateCodingCaveat('type=coding.*', outer)).toBe('needs-sealed')
    expect(evaluateCodingCaveat('repo=acme/api', outer)).toBe('needs-sealed')
  })

  it.each([
    'type=',
    'type=*',
    'type=.*',
    'type=a*b',
    'type=a.*.*',
    'repo=',
    'exp=1800000000',
    'scope=all',
    'Type=x',
  ])('does not know %s', (caveat) => {
    expect(evaluateCodingCaveat(caveat, withSealed('coding.task.v1', { repo: 'acme/api' }))).toBe('unknown')
  })

  it('works as an evaluator: conjunction, fail closed', () => {
    const ctx = withSealed('coding.task.v1', { repo: 'acme/api' })
    expect(codingEvaluator.name).toBe('coding')
    expect(evaluateCaveats(['type=coding.*', 'repo=acme/api'], [codingEvaluator], ctx)).toEqual({ ok: true })
    expect(evaluateCaveats(['type=coding.*', 'repo=acme/web'], [codingEvaluator], ctx).ok).toBe(false)
    expect(evaluateCaveats(['type=coding.*', 'net=none'], [codingEvaluator], ctx)).toEqual({
      ok: false,
      code: 'unknown-caveat',
      caveat: 'net=none',
    })
  })
})
