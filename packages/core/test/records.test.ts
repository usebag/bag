import { describe, expect, it } from 'vitest'
import { sha256hex } from '../src/hash.ts'
import { toHex } from '../src/hex.ts'
import {
  ACCEPT_FROM_TAG,
  ADDRESS_RECORD_TAG,
  type AddressRecord,
  checkAcceptRoot,
  checkRecord,
  countersignRotation,
  DOMAIN_ROOT_PREFIX,
  domainOfRoot,
  isAcceptRoot,
  isDomainHost,
  KEY_RECORD_TAG,
  MAX_DOMAIN_LENGTH,
  MAX_KEY_LIFETIME,
  MAX_ROOTS,
  parseRecord,
  recordPreimage,
  recordSigner,
  serializeRecord,
  signRecord,
  type UnsignedAddressRecord,
  verifyRecord,
  verifyRotation,
  verifyRotationClaim,
} from '../src/records.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, HOUR, P, T0 } from './support/fixtures.ts'

const sealingKey = toHex(P.jane.sealing?.publicKey ?? new Uint8Array(32))
const orgUnsigned: UnsignedAddressRecord = {
  kind: 'address',
  key: P.org.address,
  sealing_key: null,
  relays: ['https://relay.acme.example'],
  rotation_key: P.rotation.address,
  revoked: [P.mallory.address],
  ttl: DAY,
  iat: T0,
  rotated_from: null,
}
const org = signRecord(P.org.key, orgUnsigned)
const accept = signRecord(P.bob.key, {
  kind: 'accept-from',
  owner: P.bob.address,
  roots: [P.org.address],
  max_bytes: 65_536,
  ttl: 7 * DAY,
  iat: T0,
})
const wildcard = signRecord(P.carol.key, {
  kind: 'accept-from',
  owner: P.carol.address,
  roots: ['*'],
  max_bytes: 1,
  ttl: 1,
  iat: T0,
})
const key = signRecord(P.jane.key, {
  kind: 'key',
  key: P.jane.address,
  sealing_key: sealingKey,
  iat: T0,
  exp: T0 + HOUR,
})
const nextUnsigned: UnsignedAddressRecord = {
  ...orgUnsigned,
  key: P.orgNext.address,
  revoked: [],
  iat: T0 + DAY,
  rotated_from: P.org.address,
}
const next = signRecord(P.orgNext.key, nextUnsigned)

describe('records', () => {
  it('have their preimages and signers', () => {
    expect(recordPreimage(org)).toEqual([
      ADDRESS_RECORD_TAG,
      P.org.address,
      null,
      ['https://relay.acme.example'],
      P.rotation.address,
      [P.mallory.address],
      DAY,
      T0,
      null,
    ])
    expect(recordPreimage(accept)).toEqual([
      ACCEPT_FROM_TAG,
      P.bob.address,
      [P.org.address],
      65_536,
      7 * DAY,
      T0,
    ])
    expect(recordPreimage(key)).toEqual([KEY_RECORD_TAG, P.jane.address, sealingKey, T0, T0 + HOUR])
    expect([recordSigner(org), recordSigner(accept), recordSigner(key)]).toEqual([
      P.org.address,
      P.bob.address,
      P.jane.address,
    ])
  })

  it('are signed by their own key, an address record with no rotation_sig', () => {
    expect(org.rotation_sig).toBeNull()
    expect(Object.keys(org)).toEqual([
      'kind',
      'key',
      'sealing_key',
      'relays',
      'rotation_key',
      'revoked',
      'ttl',
      'iat',
      'rotated_from',
      'rotation_sig',
      'sig',
    ])
    expectAcError(() => signRecord(P.mallory.key, orgUnsigned), 'bad-key')
    expectAcError(() => signRecord(P.org.key, { ...orgUnsigned, ttl: DAY + 1 }), 'bad-record')
  })

  it('verify in their window and expire: address at iat + ttl, key at exp, accept-from never', () => {
    expect(verifyRecord(org, T0)).toEqual(org)
    expect(() => verifyRecord(org, T0 + DAY)).not.toThrow()
    expectAcError(() => verifyRecord(org, T0 + DAY + 1), 'record-expired')
    expectAcError(() => verifyRecord(key, T0 + HOUR + 1), 'record-expired')
    expect(() => verifyRecord(accept, T0 + 1000 * DAY)).not.toThrow()
    expect(() => verifyRecord(wildcard, T0)).not.toThrow()
  })

  it('refuse an iat ahead of the clock by more than the skew', () => {
    expect(() => verifyRecord(org, T0 - 300)).not.toThrow()
    expectAcError(() => verifyRecord(org, T0 - 301), 'future-iat')
    expectAcError(() => verifyRecord(org, T0 - 11, 10), 'future-iat')
  })

  it('refuse a signature by another key or over other fields', () => {
    expectAcError(() => verifyRecord({ ...org, revoked: [] }, T0), 'bad-record-sig')
    expectAcError(() => verifyRecord({ ...accept, sig: org.sig }, T0), 'bad-record-sig')
  })

  it('serialize and parse back', () => {
    for (const r of [org, accept, key, next]) expect(parseRecord(serializeRecord(r))).toEqual(r)
    expect(parseRecord(new TextDecoder().decode(serializeRecord(key)))).toEqual(key)
    expectAcError(() => parseRecord('{'), 'bad-json')
  })
})

describe('checkRecord', () => {
  it.each([
    ['not an object', null, 'bad-record'],
    ['an unknown kind', { ...org, kind: 'org' }, 'bad-record'],
    ['an extra member', { ...org, domain: 'acme.example' }, 'bad-record'],
    ['a key that is not an address', { ...org, key: 'org' }, 'bad-record'],
    ['a sealing_key of 31 bytes', { ...org, sealing_key: '00'.repeat(31) }, 'bad-record'],
    ['relays not a list', { ...org, relays: 'https://relay.acme.example' }, 'bad-record'],
    [
      'sixty-five relays',
      { ...org, relays: Array.from({ length: 65 }, (_, i) => `https://r${i}.example`) },
      'too-many-relays',
    ],
    ['a relay that is not http', { ...org, relays: ['ftp://relay.acme.example'] }, 'bad-record'],
    [
      'a relay with a control character',
      { ...org, relays: ['https://relay.acme.example/\u0085'] },
      'bad-record',
    ],
    ['a relay that is a number', { ...org, relays: [7] }, 'bad-record'],
    ['a relay listed twice', { ...org, relays: ['https://a.example', 'https://a.example'] }, 'bad-record'],
    ['a rotation_key that is not an address', { ...org, rotation_key: 'rot' }, 'bad-record'],
    ['revoked not a list', { ...org, revoked: null }, 'bad-record'],
    ['1,025 revoked', { ...org, revoked: Array(1025).fill(P.mallory.address) }, 'too-many-revoked'],
    ['a revoked key listed twice', { ...org, revoked: [P.mallory.address, P.mallory.address] }, 'bad-record'],
    ['a ttl over 24 hours', { ...org, ttl: DAY + 1 }, 'bad-record'],
    ['a ttl of zero', { ...org, ttl: 0 }, 'bad-record'],
    ['an iat that is a fraction', { ...org, iat: 1.5 }, 'bad-record'],
    ['a rotated_from that is not an address', { ...org, rotated_from: 'org' }, 'bad-record'],
    [
      'a rotation_sig that is not hex',
      { ...org, rotated_from: P.org.address, rotation_sig: 'x' },
      'bad-record',
    ],
    ['a rotation_sig without rotated_from', { ...org, rotation_sig: org.sig }, 'bad-record'],
    ['a sig that is not hex', { ...org, sig: 'x' }, 'bad-record'],
    ['accept-from with an extra member', { ...accept, x: 1 }, 'bad-record'],
    ['accept-from with an owner that is not an address', { ...accept, owner: 'bob' }, 'bad-record'],
    ['accept-from with no roots', { ...accept, roots: [] }, 'bad-record'],
    ['accept-from with roots not a list', { ...accept, roots: '*' }, 'bad-record'],
    ['accept-from with a root that is not an address', { ...accept, roots: ['org'] }, 'bad-record'],
    [
      'accept-from with a root listed twice',
      { ...accept, roots: [P.org.address, P.org.address] },
      'bad-record',
    ],
    [
      'accept-from with the wildcard beside an address',
      { ...accept, roots: ['*', P.org.address] },
      'bad-record',
    ],
    ['accept-from with max_bytes of zero', { ...accept, max_bytes: 0 }, 'bad-record'],
    ['accept-from with a ttl of zero', { ...accept, ttl: 0 }, 'bad-record'],
    ['accept-from with a negative iat', { ...accept, iat: -1 }, 'bad-record'],
    ['accept-from with a short sig', { ...accept, sig: '00' }, 'bad-record'],
    ['a key record with an extra member', { ...key, ttl: 1 }, 'bad-record'],
    ['a key record with a key that is not an address', { ...key, key: 'jane' }, 'bad-record'],
    ['a key record with a null sealing_key', { ...key, sealing_key: null }, 'bad-record'],
    ['a key record with an iat that is a string', { ...key, iat: '1' }, 'bad-record'],
    ['a key record with exp before iat', { ...key, exp: T0 - 1 }, 'bad-record'],
    ['a key record with a short sig', { ...key, sig: '00' }, 'bad-record'],
  ] as const)('rejects %s', (_, value, code) => {
    expectAcError(() => checkRecord(value), code)
  })

  it('accepts http relays, for a local relay', () => {
    expect(checkRecord({ ...org, relays: ['http://127.0.0.1:7700'] })).toBeTruthy()
  })
})

describe('rotation', () => {
  it('is accepted when countersigned by the previous key or its rotation key', () => {
    expect(() => verifyRotation(org, countersignRotation(P.org.key, next))).not.toThrow()
    expect(() => verifyRotation(org, countersignRotation(P.rotation.key, next))).not.toThrow()
    expect(() => verifyRecord(countersignRotation(P.org.key, next), T0 + DAY)).not.toThrow()
  })

  it('is rejected bare, countersigned by another key, or naming another key', () => {
    expectAcError(() => verifyRotation(org, next), 'bad-rotation')
    expectAcError(() => verifyRotation(org, countersignRotation(P.mallory.key, next)), 'bad-rotation')
    const elsewhere = countersignRotation(
      P.org.key,
      signRecord(P.orgNext.key, { ...nextUnsigned, rotated_from: P.jane.address }),
    )
    expectAcError(() => verifyRotation(org, elsewhere), 'bad-rotation')
    const noRotationKey: AddressRecord = signRecord(P.org.key, { ...orgUnsigned, rotation_key: null })
    expectAcError(
      () => verifyRotation(noRotationKey, countersignRotation(P.rotation.key, next)),
      'bad-rotation',
    )
  })

  it('links address records only, and needs rotated_from to countersign', () => {
    expectAcError(() => verifyRotation(org, accept as unknown as AddressRecord), 'bad-record')
    expectAcError(() => countersignRotation(P.org.key, org), 'bad-record')
    expectAcError(() => countersignRotation(P.org.key, key as unknown as AddressRecord), 'bad-record')
  })
})

// The host grammar's cases, the same lists as crates/ac-core/src/records/tests.rs.
const A63 = 'a'.repeat(63)
const VALID_HOSTS: readonly string[] = [
  'acme.example',
  'a.b',
  'relay-acme.usuals.now',
  'acme.e2e.test',
  'xn--bcher-kva.example',
  '1password.com',
  'a1.b2',
  '123.example',
  '0x7f.example',
  `${'a'.repeat(63)}.example`,
  [A63, A63, A63, 'a'.repeat(61)].join('.'),
]
const INVALID_HOSTS: readonly string[] = [
  'Acme.example',
  'ACME.EXAMPLE',
  '127.0.0.1',
  '10.0.0.1',
  '127.1',
  '0177.0.0.1',
  '0x7f.1',
  '1.0x7f',
  'example.0x',
  'acme.example.',
  'localhost',
  'example',
  '',
  '.',
  '.example',
  'acme..example',
  '-acme.example',
  'acme-.example',
  `${'a'.repeat(64)}.example`,
  [A63, A63, A63, 'a'.repeat(62)].join('.'),
  'acme.example:443',
  'acme_corp.example',
  'acme.example/x',
  'user@acme.example',
  '::1',
  '[::1]',
  'acme .example',
  '\u00e1cme.example',
]

describe('domain roots', () => {
  it.each(VALID_HOSTS.map((h) => [h]))('take the host %j', (host) => {
    expect(isDomainHost(host)).toBe(true)
    expect(domainOfRoot(`${DOMAIN_ROOT_PREFIX}${host}`)).toBe(host)
    expect(isAcceptRoot(`domain:${host}`)).toBe(true)
  })

  it.each(INVALID_HOSTS.map((h) => [h]))('refuse the host %j', (host) => {
    expect(isDomainHost(host)).toBe(false)
    expect(domainOfRoot(`domain:${host}`)).toBeNull()
    expectAcError(() => checkAcceptRoot(`domain:${host}`), 'bad-record')
  })

  it('count 11 valid and 28 invalid hosts, the longest valid one 253 characters', () => {
    expect([VALID_HOSTS.length, INVALID_HOSTS.length]).toEqual([11, 28])
    expect(Math.max(...VALID_HOSTS.map((h) => h.length))).toBe(MAX_DOMAIN_LENGTH)
    expect(INVALID_HOSTS.filter((h) => h.length > MAX_DOMAIN_LENGTH).map((h) => h.length)).toEqual([254])
  })

  it('are an entry beside addresses, never a bare host, another prefix or a non-string', () => {
    expect([isAcceptRoot('*'), isAcceptRoot(P.org.address), isAcceptRoot('domain:acme.example')]).toEqual([
      true,
      true,
      true,
    ])
    for (const root of ['acme.example', 'Domain:acme.example', 'domain: acme.example', 'domain:', 'dns:a.b'])
      expect(isAcceptRoot(root), root).toBe(false)
    expect([domainOfRoot(7), domainOfRoot(null), isDomainHost(7)]).toEqual([null, null, false])
    expect(checkAcceptRoot('domain:acme.example')).toBe('domain:acme.example')
    expect(expectAcError(() => checkAcceptRoot('acme.example'), 'bad-record').message).toBe(
      'bad-record: "acme.example" is not an address, "*" or domain:<host>',
    )
    expect(expectAcError(() => checkAcceptRoot(7), 'bad-record').message).toContain('a number is not')
  })

  it('are signed, verified and written back in their order, mixed with addresses', () => {
    const roots = ['domain:acme.example', P.org.address, 'domain:globex.example']
    const r = signRecord(P.bob.key, { ...accept, roots })
    expect(recordPreimage(r)).toEqual([ACCEPT_FROM_TAG, P.bob.address, roots, 65_536, 7 * DAY, T0])
    expect(verifyRecord(r, T0)).toEqual(r)
    expect(parseRecord(serializeRecord(r))).toEqual(r)
    expect(checkRecord({ ...accept, roots: ['domain:acme.example'] })).toBeTruthy()
  })

  it.each([
    ['a domain listed twice', ['domain:acme.example', 'domain:acme.example']],
    ['the wildcard beside a domain', ['*', 'domain:acme.example']],
    ['an upper-case host', ['domain:ACME.example']],
    ['an IP literal', ['domain:127.0.0.1']],
    ['a trailing dot', ['domain:acme.example.']],
    ['no dot', ['domain:localhost']],
    ['a port', ['domain:acme.example:443']],
    ['a bare host', ['acme.example']],
  ] as const)('make the record bad-record with %s', (_, roots) => {
    expectAcError(() => checkRecord({ ...accept, roots }), 'bad-record')
  })
})

// Changed 2026-10-25: accept-from roots capped at 1,024, a key record lives a day at most, and a
// reader that holds no record of rotated_from checks the rotation_sig a record claims.
describe('the caps on accept-from roots and key records, and the rotation check', () => {
  const roots = (n: number): string[] =>
    Array.from({ length: n }, (_, i) => `ed25519:${sha256hex(`root ${i}`)}`)

  it('take 1,024 roots, addresses and domains, and refuse 1,025 with bad-record', () => {
    expect(MAX_ROOTS).toBe(1024)
    const full = signRecord(P.bob.key, { ...accept, roots: roots(MAX_ROOTS) })
    expect(() => verifyRecord(full, T0)).not.toThrow()
    expect(parseRecord(serializeRecord(full))).toEqual(full)
    expectAcError(() => checkRecord({ ...accept, roots: roots(MAX_ROOTS + 1) }), 'bad-record')
    const mixed = [...roots(MAX_ROOTS), 'domain:acme.example']
    expectAcError(() => checkRecord({ ...accept, roots: mixed }), 'bad-record')
    expect(() => checkRecord({ ...accept, roots: mixed.slice(1) })).not.toThrow()
  })

  it('take a key record of iat to iat + 86,400 and refuse one a second longer with bad-record', () => {
    expect(MAX_KEY_LIFETIME).toBe(86_400)
    const day = signRecord(P.jane.key, { ...key, exp: T0 + MAX_KEY_LIFETIME })
    expect(() => verifyRecord(day, T0 + MAX_KEY_LIFETIME)).not.toThrow()
    expectAcError(() => verifyRecord(day, T0 + MAX_KEY_LIFETIME + 1), 'record-expired')
    expect(() => checkRecord({ ...key, exp: T0 })).not.toThrow()
    expectAcError(() => checkRecord({ ...key, exp: T0 + MAX_KEY_LIFETIME + 1 }), 'bad-record')
    expectAcError(() => signRecord(P.jane.key, { ...key, exp: T0 + 2 * DAY }), 'bad-record')
  })
})

describe('verifyRotationClaim, without the previous record', () => {
  const byPrevious = countersignRotation(P.org.key, next)

  it('takes a rotation countersigned by rotated_from, and a record that claims none', () => {
    expect(() => verifyRotationClaim(byPrevious)).not.toThrow()
    expect(() => verifyRotationClaim(org)).not.toThrow()
  })

  it('refuses a bare rotation and a countersignature by any other key with bad-rotation', () => {
    expectAcError(() => verifyRotationClaim(next), 'bad-rotation')
    expectAcError(() => verifyRotationClaim(countersignRotation(P.mallory.key, next)), 'bad-rotation')
    expectAcError(() => verifyRotationClaim(countersignRotation(P.orgNext.key, next)), 'bad-rotation')
  })

  it('refuses a rotation-key countersignature, which only a reader holding the previous record can check', () => {
    const byRotationKey = countersignRotation(P.rotation.key, next)
    expectAcError(() => verifyRotationClaim(byRotationKey), 'bad-rotation')
    expect(() => verifyRotation(org, byRotationKey)).not.toThrow()
  })

  it('reads address records only, and checks their form first', () => {
    expectAcError(() => verifyRotationClaim(accept as unknown as AddressRecord), 'bad-record')
    expectAcError(() => verifyRotationClaim({ ...byPrevious, ttl: 0 }), 'bad-record')
  })
})
