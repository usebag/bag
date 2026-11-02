import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import {
  checkHandleRecord,
  HANDLE_TAG,
  HANDLES_PATH,
  type HandleRecord,
  handlePath,
  handleRecordPreimage,
  isHandle,
  MAX_HANDLE_LOCAL,
  parseHandle,
  parseHandleRecord,
  SPECIAL_USE_TLDS,
  serializeHandleRecord,
  signHandleRecord,
  type UnsignedHandleRecord,
  verifyHandleRecord,
} from '../src/handles.ts'
import { utf8 } from '../src/hex.ts'
import { parseRecord } from '../src/records.ts'
import { expectAcError, outcome } from './support/assert.ts'
import { DAY, HOUR, P, type Party, T0 } from './support/fixtures.ts'

// Handles and handle records (spec/SPEC.md §12.3 and §12.4): the form, the preimage, signing and the order of the checks. The
// shared vectors (spec/vectors/discovery.json) are read by vectors.test.ts.

const JANE = 'jane@acme.example'

function signed(org: Party, handle: string, address: string, ttl = HOUR): HandleRecord {
  return signHandleRecord(org.key, { kind: 'handle', org: org.address, handle, address, iat: T0, ttl })
}

describe('a handle', () => {
  it('parses by its form and nothing else', () => {
    expect(parseHandle('j.doe-2_x@acme.example')).toEqual({ local: 'j.doe-2_x', domain: 'acme.example' })
    expect(handlePath('j.doe-2_x@acme.example')).toBe(`${HANDLES_PATH}j.doe-2_x.json`)
    expect(HANDLES_PATH).toBe('/.well-known/bag/handles/')
    expect(isHandle(`${'a'.repeat(MAX_HANDLE_LOCAL)}@acme.example`)).toBe(true)
    const bad = [
      `${'a'.repeat(65)}@acme.example`,
      'Jane@acme.example',
      'jane@ACME.example',
      'jane@acme',
      'jane@192.0.2.1',
      '@acme.example',
      'jane@',
      'jane@@acme.example',
      'ja ne@acme.example',
      'jane@acme.example.',
      '.jane@acme.example',
      'jane.@acme.example',
      '-jane@acme.example',
      'jane+tag@acme.example',
      'jané@acme.example',
      'jane',
      P.jane.address,
      7,
      'jane@acme.example:443',
      'jane@[2001:db8::1]',
      'jane@acme.0x1f',
      ...SPECIAL_USE_TLDS.map((tld) => `jane@acme.${tld}`),
    ]
    for (const value of bad)
      expect(
        outcome(() => parseHandle(value)),
        String(value),
      ).toBe('bad-address')
    expect(SPECIAL_USE_TLDS).toEqual(['alt', 'arpa', 'internal', 'invalid', 'local', 'localhost', 'onion'])
    expect(isHandle('jane@acme.local.example') && isHandle('jane@acme.e2e.test')).toBe(true)
  })
})

describe('a handle record', () => {
  it('round-trips and signs its preimage', () => {
    const r = signed(P.org, JANE, P.jane.address, DAY)
    const bytes = serializeHandleRecord(r)
    expect(new TextDecoder().decode(bytes)).toMatch(/^\{"kind":"handle","org":"ed25519:/)
    expect(parseHandleRecord(bytes)).toEqual(r)
    expect(canonical(handleRecordPreimage(r))).toBe(
      JSON.stringify([HANDLE_TAG, P.org.address, JANE, P.jane.address, T0, DAY]),
    )
    const unsigned: UnsignedHandleRecord = {
      kind: 'handle',
      org: P.org.address,
      handle: JANE,
      address: P.jane.address,
      iat: T0,
      ttl: DAY,
    }
    expectAcError(() => signHandleRecord(P.mallory.key, unsigned), 'bad-key')
  })

  it('is checked in its order', () => {
    const r = signed(P.org, JANE, P.jane.address)
    const expect_ = { org: P.org.address, handle: JANE }
    const at = (value: unknown, now: number, e = expect_) => outcome(() => verifyHandleRecord(value, e, now))
    expect(at(r, T0)).toBe('ok')
    expect(at(r, T0 + HOUR)).toBe('ok')
    expect(at(r, T0 + HOUR + 1)).toBe('record-expired')
    expect(at(r, T0 - 300)).toBe('ok')
    expect(at(r, T0 - 301)).toBe('future-iat')
    expect(at(r, T0, { ...expect_, org: P.orgNext.address })).toBe('resolve-failed')
    expect(at(r, T0, { ...expect_, handle: 'bob@acme.example' })).toBe('resolve-failed')
    expect(at(r, T0, { ...expect_, handle: 'jane@globex.example' })).toBe('resolve-failed')
    expect(outcome(() => verifyHandleRecord(r, { ...expect_, revoked: [P.jane.address] }, T0))).toBe(
      'revoked',
    )
    expect(at({ ...r, address: P.mallory.address }, T0)).toBe('bad-record-sig')
    expect(at({ ...r, ttl: DAY + 1 }, T0)).toBe('bad-record')
    expect(at(signed(P.mallory, JANE, P.jane.address), T0)).toBe('resolve-failed')
  })

  it('breaks its form as bad-record, and is no record a relay keeps', () => {
    const r = signed(P.org, JANE, P.jane.address)
    const breaches: Record<string, unknown>[] = [
      { kind: 'address' },
      { org: 'jane' },
      { handle: 'Jane@acme.example' },
      { handle: 1 },
      { address: 'ed25519:00' },
      { iat: -1 },
      { ttl: 0 },
      { ttl: DAY + 1 },
      { sig: '00' },
      { extra: true },
      { sig: undefined },
    ]
    for (const b of breaches) {
      const value = JSON.parse(JSON.stringify({ ...r, ...b }))
      expect(
        outcome(() => checkHandleRecord(value)),
        JSON.stringify(b),
      ).toBe('bad-record')
    }
    expectAcError(() => checkHandleRecord([1]), 'bad-record')
    expectAcError(() => parseHandleRecord('{'), 'bad-json')
    expectAcError(() => parseRecord(utf8(JSON.stringify(r))), 'bad-record')
  })
})
