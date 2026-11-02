import { describe, expect, it } from 'vitest'
import { ADDRESS_PREFIX, decodeAddress, encodeAddress, isAddress, SUITE_1 } from '../src/address.ts'
import { expectAcError } from './support/assert.ts'

describe('addresses', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i)

  it('are ed25519: and 64 lowercase hex characters', () => {
    const a = encodeAddress(key)
    expect(a).toBe(`ed25519:${'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'}`)
    expect(a.startsWith(ADDRESS_PREFIX)).toBe(true)
    expect(isAddress(a)).toBe(true)
    expect(decodeAddress(a)).toEqual(key)
  })

  it('encode only 32-byte keys', () => {
    expectAcError(() => encodeAddress(new Uint8Array(31)), 'bad-key')
  })

  it.each([
    ['upper-case hex', `ed25519:${'AB'.repeat(32)}`],
    ['another prefix', `x25519:${'ab'.repeat(32)}`],
    ['no prefix', 'ab'.repeat(32)],
    ['31 bytes', `ed25519:${'ab'.repeat(31)}`],
    ['33 bytes', `ed25519:${'ab'.repeat(33)}`],
    ['a trailing newline', `ed25519:${'ab'.repeat(32)}\n`],
    ['an upper-case prefix', `ED25519:${'ab'.repeat(32)}`],
  ])('reject %s', (_, value) => {
    expect(isAddress(value)).toBe(false)
    expectAcError(() => decodeAddress(value), 'bad-address')
  })

  it('are strings only', () => {
    expect(isAddress(undefined)).toBe(false)
  })

  it('belong to suite 1, the only suite of v0', () => {
    expect(SUITE_1).toEqual({
      id: 1,
      addressPrefix: 'ed25519:',
      signature: 'Ed25519',
      kem: 0x20,
      kdf: 1,
      aead: 2,
    })
  })
})
