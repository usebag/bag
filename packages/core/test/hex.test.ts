import { describe, expect, it } from 'vitest'
import { bytesEqual, concatBytes, fromHex, isHex, toHex, utf8 } from '../src/hex.ts'
import { expectAcError } from './support/assert.ts'

describe('hex', () => {
  it('round-trips bytes through lowercase hex', () => {
    const bytes = Uint8Array.of(0, 1, 15, 16, 127, 128, 255)
    expect(toHex(bytes)).toBe('00010f107f80ff')
    expect(fromHex('00010f107f80ff')).toEqual(bytes)
    expect(toHex(new Uint8Array(0))).toBe('')
    expect(fromHex('')).toEqual(new Uint8Array(0))
  })

  it('reads a view of a larger buffer without its neighbours', () => {
    const big = Uint8Array.of(1, 2, 3, 4)
    expect(toHex(big.subarray(1, 3))).toBe('0203')
  })

  it('returns a plain Uint8Array', () => {
    expect(Object.getPrototypeOf(fromHex('00'))).toBe(Uint8Array.prototype)
  })

  it.each([
    ['upper case', 'AB'],
    ['an odd length', 'abc'],
    ['a non-hex character', 'zz'],
    ['white space', 'ab '],
    ['a 0x prefix', '0xab'],
  ])('rejects %s', (_, value) => {
    expect(isHex(value)).toBe(false)
    expectAcError(() => fromHex(value), 'bad-hex')
  })

  it('checks the length when one is given', () => {
    expect(isHex('00'.repeat(32), 32)).toBe(true)
    expect(isHex('00'.repeat(31), 32)).toBe(false)
    expect(fromHex('00'.repeat(4), 4)).toHaveLength(4)
    expect(expectAcError(() => fromHex('00', 4), 'bad-hex').message).toContain('4 bytes')
  })

  it('rejects a value that is not a string', () => {
    expect(isHex(7)).toBe(false)
    expect(isHex(null)).toBe(false)
  })
})

describe('bytes', () => {
  it('encodes UTF-8', () => {
    expect(toHex(utf8('é😀'))).toBe('c3a9f09f9880')
  })

  it('concatenates', () => {
    expect(concatBytes(Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2, 3))).toEqual(
      Uint8Array.of(1, 2, 3),
    )
    expect(concatBytes()).toEqual(new Uint8Array(0))
  })

  it('compares', () => {
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true)
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false)
    expect(bytesEqual(Uint8Array.of(1), Uint8Array.of(1, 2))).toBe(false)
  })
})
