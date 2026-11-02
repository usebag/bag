import { describe, expect, it } from 'vitest'
import * as core from '../src/index.ts'

describe('@usebag/core', () => {
  it('names its package', () => {
    expect(core.packageName()).toBe('@usebag/core')
  })

  it('exports the main API by name', () => {
    const names = [
      'encodeAddress',
      'decodeAddress',
      'canonical',
      'sha256hex',
      'signingKeyFromSeed',
      'generateSigningKey',
      'verifySig',
      'sealingKeyFromSeed',
      'generateSealingKey',
      'hpkeSeal',
      'hpkeOpen',
      'sealTo',
      'openSealed',
      'sealedHash',
      'signHop',
      'envelopeId',
      'buildEnvelope',
      'parseEnvelope',
      'verifyOuter',
      'verifyChain',
      'evaluateCaveats',
      'codingEvaluator',
      'signRecord',
      'verifyRecord',
      'verifyRotation',
      'AcError',
      'newThread',
      'replyThread',
    ]
    for (const name of names)
      expect(typeof (core as Record<string, unknown>)[name], name).not.toBe('undefined')
  })

  it('exports the constants of the spec', () => {
    expect([
      core.ENVELOPE_VERSION,
      core.SUITE,
      core.MAX_ENVELOPE_BYTES,
      core.DEFAULT_TTL,
      core.DEFAULT_SKEW,
    ]).toEqual([1, 1, 65_536, 604_800, 300])
    expect([
      core.MAX_RECIPIENTS,
      core.MAX_HOPS,
      core.MAX_CAVEATS,
      core.MAX_CAVEAT_BYTES,
      core.MAX_PREV,
    ]).toEqual([16, 8, 32, 256, 64])
    expect([core.MAX_RELAYS, core.MAX_REVOKED, core.MAX_ADDRESS_TTL]).toEqual([64, 1024, 86_400])
    expect(core.DEFAULT_WINDOW).toEqual({ ttl: 604_800, skew: 300 })
    expect(core.RECORD_KINDS).toEqual(['address', 'accept-from', 'key'])
    expect([core.SEAL_INFO, core.HOP_TAG, core.FETCH_TAG, core.SUBSCRIBE_TAG]).toEqual([
      'ac/seal/1',
      'ac/hop/1',
      'ac/fetch/1',
      'ac/sub/1',
    ])
    expect(core.WILDCARD_ROOT).toBe('*')
  })
})
