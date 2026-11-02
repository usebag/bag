import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import {
  checkChainShape,
  HOP_TAG,
  type Hop,
  hopPreimage,
  hopTuple,
  MAX_CAVEAT_BYTES,
  MAX_CAVEATS,
  MAX_HOPS,
  signHop,
  verifyChain,
} from '../src/chain.ts'
import { verifyPreimage } from '../src/keys.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, HOUR, P, SIXTEEN, T0 } from './support/fixtures.ts'

const orgJane = signHop(P.org.key, P.jane.address, ['type=coding.*'], T0 + 30 * DAY)
const janeSession = signHop(P.jane.key, P.session.address, ['repo=acme/api'], T0 + 8 * HOUR)

describe('hops', () => {
  it('are signed by iss over ["ac/hop/1", iss, sub, caveats, exp]', () => {
    expect(hopPreimage(orgJane)).toEqual([
      HOP_TAG,
      P.org.address,
      P.jane.address,
      ['type=coding.*'],
      T0 + 30 * DAY,
    ])
    expect(verifyPreimage(P.org.address, hopPreimage(orgJane), orgJane.sig)).toBe(true)
    expect(canonical(hopTuple(orgJane))).toBe(
      canonical([orgJane.iss, orgJane.sub, orgJane.caveats, orgJane.exp, orgJane.sig]),
    )
  })

  it('refuse to sign a hop that could not pass the shape rules', () => {
    expectAcError(() => signHop(P.org.key, 'jane', [], T0), 'bad-hop')
    expectAcError(() => signHop(P.org.key, P.jane.address, [''], T0), 'bad-hop')
    expectAcError(() => signHop(P.org.key, P.jane.address, [], -1), 'bad-hop')
    expectAcError(
      () => signHop(P.org.key, P.jane.address, Array(MAX_CAVEATS + 1).fill('c'), T0),
      'too-many-caveats',
    )
    expectAcError(
      () => signHop(P.org.key, P.jane.address, ['x'.repeat(MAX_CAVEAT_BYTES + 1)], T0),
      'caveat-too-long',
    )
  })
})

describe('verifyChain', () => {
  it('reads an empty chain as self-rooted', () => {
    expect(verifyChain([], P.jane.address, T0)).toEqual({
      root: P.jane.address,
      principal: P.jane.address,
      caveats: [],
    })
  })

  it('returns the root, the principal and the caveats in chain order', () => {
    expect(verifyChain([orgJane, janeSession], P.session.address, T0)).toEqual({
      root: P.org.address,
      principal: P.jane.address,
      caveats: ['type=coding.*', 'repo=acme/api'],
    })
  })

  it('accepts the caps: 8 hops, 32 caveats, 256-byte caveats', () => {
    const chain = Array.from({ length: MAX_HOPS }, (_, i) =>
      signHop(
        (SIXTEEN[i] as (typeof SIXTEEN)[number]).key,
        (SIXTEEN[i + 1] as (typeof SIXTEEN)[number]).address,
        [],
        T0 + DAY,
      ),
    )
    expect(verifyChain(chain, (SIXTEEN[MAX_HOPS] as (typeof SIXTEEN)[number]).address, T0).root).toBe(
      SIXTEEN[0]?.address,
    )
    const wide = signHop(P.jane.key, P.session.address, [...Array(31).fill('c'), 'é'.repeat(128)], T0 + DAY)
    expect(verifyChain([wide], P.session.address, T0).caveats).toHaveLength(32)
  })

  it('judges validity at ts, inclusive', () => {
    expect(verifyChain([orgJane, janeSession], P.session.address, T0 + 8 * HOUR).root).toBe(P.org.address)
    expectAcError(
      () => verifyChain([orgJane, janeSession], P.session.address, T0 + 8 * HOUR + 1),
      'hop-expired',
    )
  })

  it('fails each rule with its own code', () => {
    const nine = Array(9).fill(orgJane) as Hop[]
    expectAcError(() => verifyChain(nine, P.session.address, T0), 'too-many-hops')
    expectAcError(() => verifyChain([{ ...orgJane, iss: 'org' }], P.jane.address, T0), 'bad-hop')
    expectAcError(
      () => verifyChain([{ ...orgJane, caveats: Array(33).fill('c') }], P.jane.address, T0),
      'too-many-caveats',
    )
    expectAcError(
      () => verifyChain([{ ...orgJane, caveats: ['é'.repeat(129)] }], P.jane.address, T0),
      'caveat-too-long',
    )
    expectAcError(() => verifyChain([janeSession, orgJane], P.jane.address, T0), 'chain-broken')
    expectAcError(() => verifyChain([orgJane], P.session.address, T0), 'chain-not-to-sender')
    const late = signHop(P.jane.key, P.session.address, [], T0 + 31 * DAY)
    expectAcError(() => verifyChain([orgJane, late], P.session.address, T0), 'exp-not-monotone')
    expectAcError(() => verifyChain([orgJane], P.jane.address, T0 + 31 * DAY), 'hop-expired')
    expectAcError(() => verifyChain([{ ...orgJane, caveats: [] }], P.jane.address, T0), 'bad-hop-sig')
  })

  it('checks its arguments', () => {
    expectAcError(() => verifyChain([], 'jane', T0), 'bad-address')
    expectAcError(() => verifyChain([], P.jane.address, -1), 'bad-shape')
    expectAcError(() => checkChainShape('hops'), 'bad-shape')
  })

  it.each([
    ['null', null],
    ['a list', ['a']],
    ['a missing sig', { iss: P.org.address, sub: P.jane.address, caveats: [], exp: T0 }],
    ['caveats not a list', { ...orgJane, caveats: 'x' }],
    ['a number caveat', { ...orgJane, caveats: [1] }],
    ['a lone surrogate in a caveat', { ...orgJane, caveats: ['\ud800'] }],
    ['a sig in upper case', { ...orgJane, sig: orgJane.sig.toUpperCase() }],
    ['exp a string', { ...orgJane, exp: '1' }],
  ])('rule 2 rejects %s', (_, hop) => {
    expectAcError(() => checkChainShape([hop]), 'bad-hop')
  })

  it('returns copies of the hops', () => {
    const [copy] = checkChainShape([orgJane])
    expect(copy).toEqual(orgJane)
    expect(copy).not.toBe(orgJane)
  })
})
