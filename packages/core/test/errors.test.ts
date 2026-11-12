import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { encodeAddress } from '../src/address.ts'
import { canonical } from '../src/canonical.ts'
import { evaluateCaveats } from '../src/caveats.ts'
import { checkChainShape, signHop, verifyChain } from '../src/chain.ts'
import { checkEnvelope, checkId, checkSig, checkTs, parseEnvelope } from '../src/envelope.ts'
import {
  AC_ERROR_CODES,
  AcError,
  CORE_ERROR_CODES,
  type CoreErrorCode,
  EDGE_ERROR_CODES,
  isAcError,
  isAcErrorCode,
  RELAY_ERROR_CODES,
} from '../src/errors.ts'
import { fromHex } from '../src/hex.ts'
import { hpkeOpen } from '../src/hpke.ts'
import { SigningKey } from '../src/keys.ts'
import { type AddressRecord, checkRecord, verifyRecord, verifyRotation } from '../src/records.ts'
import { checkRecipients, decodeContent, openSealed } from '../src/seal.ts'
import { checkThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, HOUR, opener, P, T0 } from './support/fixtures.ts'
import { casesOf, readVectors, SPEC_DIR } from './support/vectors.ts'

interface EnvelopeVector {
  readonly expected: { readonly bytes: string; readonly envelope: Parameters<typeof checkId>[0] }
}

const envelopeFile = readVectors('envelope.json')
const e1 = casesOf<EnvelopeVector>(envelopeFile)[0] as EnvelopeVector
const bytes1 = e1.expected.bytes
const env1 = parseEnvelope(bytes1)
const records = readVectors('records.json')
const recordCases = casesOf<{ readonly record: AddressRecord }>(records)
const orgRecord = (recordCases[0] as { readonly record: AddressRecord }).record
const jsonOf = (f: (e: Record<string, unknown>) => void): string => {
  const e = JSON.parse(bytes1) as Record<string, unknown>
  f(e)
  return JSON.stringify(e)
}
const hop = signHop(P.org.key, P.jane.address, [], T0 + DAY)

/**
 * One call that raises each code the core raises. The mapped type makes the list exhaustive: a new core code without
 * a trigger here fails tsc.
 */
const TRIGGERS: { readonly [C in CoreErrorCode]: () => unknown } = {
  'bad-canonical': () => canonical(1.5),
  'bad-hex': () => fromHex('ABCD'),
  'bad-address': () => checkRecipients(['ed25519:00']),
  'bad-key': () => new SigningKey(new Uint8Array(31)),
  'bad-json': () => parseEnvelope('{'),
  'bad-shape': () => parseEnvelope('[]'),
  'bad-version': () => parseEnvelope(jsonOf((e) => Object.assign(e, { v: 2 }))),
  'bad-suite': () => parseEnvelope(jsonOf((e) => Object.assign(e, { suite: 2 }))),
  'envelope-too-large': () => parseEnvelope(`${bytes1}${' '.repeat(196_608)}`),
  'too-many-recipients': () =>
    checkRecipients(Array.from({ length: 17 }, (_, i) => encodeAddress(new Uint8Array(32).fill(i)))),
  'bad-id': () => checkId({ ...env1, ts: env1.ts + 1 }),
  'bad-sig': () => checkSig({ ...env1, sig: '00'.repeat(64) }),
  'stale-ts': () => checkTs(T0, T0 + 10 * DAY),
  'future-ts': () => checkTs(T0 + HOUR, T0),
  'too-many-hops': () => checkChainShape(Array(9).fill(hop)),
  'bad-hop': () => checkChainShape([{}]),
  'too-many-caveats': () => checkChainShape([{ ...hop, caveats: Array(33).fill('c') }]),
  'caveat-too-long': () => checkChainShape([{ ...hop, caveats: ['x'.repeat(257)] }]),
  'chain-broken': () => verifyChain([hop, hop], P.jane.address, T0),
  'chain-not-to-sender': () => verifyChain([hop], P.bob.address, T0),
  'exp-not-monotone': () =>
    verifyChain([hop, signHop(P.jane.key, P.session.address, [], T0 + 2 * DAY)], P.session.address, T0),
  'hop-expired': () => verifyChain([hop], P.jane.address, T0 + 2 * DAY),
  'bad-hop-sig': () => verifyChain([{ ...hop, caveats: ['x'] }], P.jane.address, T0),
  'unknown-caveat': () => {
    const r = evaluateCaveats(['x'], [], { from: P.jane.address, to: [], ts: T0, root: P.jane.address })
    if (!r.ok) throw new AcError(r.code)
  },
  'caveat-failed': () => {
    const fail = { name: 'f', evaluate: () => 'fail' as const }
    const r = evaluateCaveats(['x'], [fail], { from: P.jane.address, to: [], ts: T0, root: P.jane.address })
    if (!r.ok) throw new AcError(r.code)
  },
  'not-recipient': () => openSealed(env1, opener(P.carol)),
  'open-failed': () =>
    hpkeOpen(
      new Uint8Array(32),
      new Uint8Array(32),
      new Uint8Array(0),
      new Uint8Array(0),
      new Uint8Array(16),
    ),
  'bad-content': () => decodeContent(new TextEncoder().encode('[]')),
  'bad-thread': () => checkThread({ id: 'x', prev: [] }),
  'too-many-prev': () =>
    checkThread({
      id: '00'.repeat(32),
      prev: Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(64, '0')),
    }),
  'bad-record': () => checkRecord({ kind: 'org' }),
  'too-many-relays': () =>
    checkRecord({ ...orgRecord, relays: Array.from({ length: 65 }, (_, i) => `https://r${i}.example`) }),
  'too-many-revoked': () =>
    checkRecord({
      ...orgRecord,
      revoked: Array.from({ length: 1025 }, (_, i) => encodeAddress(new Uint8Array(32).fill(i % 256))),
    }),
  'bad-record-sig': () => verifyRecord({ ...orgRecord, ttl: 1 }, T0),
  'future-iat': () => verifyRecord(orgRecord, T0 - DAY),
  'record-expired': () => verifyRecord(orgRecord, T0 + 2 * DAY),
  'bad-rotation': () => verifyRotation(orgRecord, orgRecord),
}

describe('AcError', () => {
  it('carries its code, a detail in the message, and the name AcError', () => {
    const e = new AcError('bad-hex', 'odd length')
    expect(e).toBeInstanceOf(Error)
    expect(e.code).toBe('bad-hex')
    expect(e.message).toBe('bad-hex: odd length')
    expect(e.name).toBe('AcError')
    expect(new AcError('bad-id').message).toBe('bad-id')
  })

  it('isAcError tells AcErrors from other values, with or without a code', () => {
    const e = new AcError('bad-sig')
    expect(isAcError(e)).toBe(true)
    expect(isAcError(e, 'bad-sig')).toBe(true)
    expect(isAcError(e, 'bad-id')).toBe(false)
    expect(isAcError(new Error('bad-sig'))).toBe(false)
    expect(isAcError('bad-sig')).toBe(false)
  })

  it('isAcErrorCode knows every code and nothing else', () => {
    for (const code of AC_ERROR_CODES) expect(isAcErrorCode(code)).toBe(true)
    expect(isAcErrorCode('bad-thing')).toBe(false)
    expect(isAcErrorCode(7)).toBe(false)
  })
})

describe('the closed set of codes', () => {
  it('is the core, relay and edge lists, with no code twice and every code in kebab case', () => {
    expect(AC_ERROR_CODES).toEqual([...CORE_ERROR_CODES, ...RELAY_ERROR_CODES, ...EDGE_ERROR_CODES])
    expect(new Set(AC_ERROR_CODES).size).toBe(AC_ERROR_CODES.length)
    for (const code of AC_ERROR_CODES) expect(code).toMatch(/^[a-z]+(-[a-z0-9]+)*$/)
  })

  it.each(CORE_ERROR_CODES)('the core raises %s', (code) => {
    expectAcError(TRIGGERS[code], code)
  })

  it('every code has a row in spec/SPEC.md Appendix A, and the table names no other code', () => {
    const spec = readFileSync(new URL('SPEC.md', SPEC_DIR), 'utf8')
    const section = spec.slice(spec.indexOf('## Appendix A.'))
    const rows = [...section.matchAll(/^\| `([a-z0-9-]+)` \|/gm)].map((m) => m[1])
    expect(new Set(rows)).toEqual(new Set(AC_ERROR_CODES))
    expect(rows.length).toBe(AC_ERROR_CODES.length)
  })

  it('checkEnvelope rejects a non-object directly', () => {
    expectAcError(() => checkEnvelope(null), 'bad-shape')
  })
})
