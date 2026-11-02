import { describe, expect, it } from 'vitest'
import {
  type CanonicalValue,
  canonical,
  isCanonicalInteger,
  MAX_CANONICAL_INTEGER,
} from '../src/canonical.ts'
import { expectAcError } from './support/assert.ts'

describe('canonical', () => {
  it('writes lists with no white space', () => {
    expect(canonical([])).toBe('[]')
    expect(canonical([1, 'a', null, [[]]])).toBe('[1,"a",null,[[]]]')
  })

  it('writes integers in decimal, 0 to 2^53 - 1', () => {
    expect(canonical(0)).toBe('0')
    expect(canonical(MAX_CANONICAL_INTEGER)).toBe('9007199254740991')
    expect(canonical(-0)).toBe('0')
  })

  it('escapes only the quotation mark, the backslash and U+0000 to U+001F, as JSON.stringify does', () => {
    expect(canonical('"\\')).toBe('"\\"\\\\"')
    expect(canonical('\b\f\n\r\t')).toBe('"\\b\\f\\n\\r\\t"')
    expect(canonical('\u0000\u001f')).toBe('"\\u0000\\u001f"')
    expect(canonical('\u007f /é😀')).toBe('"\u007f /é😀"')
    for (let c = 0; c < 0x80; c++) {
      const s = String.fromCharCode(c)
      expect(canonical(s)).toBe(JSON.stringify(s))
    }
  })

  it('does not normalize', () => {
    expect(canonical('é')).not.toBe(canonical('é'))
  })

  it.each([
    ['a fraction', 1.5],
    ['a negative integer', -1],
    ['2^53', 2 ** 53],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['true', true],
    ['an object', {}],
    ['undefined', undefined],
    ['a bigint', 1n],
    ['a byte array', new Uint8Array(1)],
    ['a lone high surrogate', '\ud800'],
    ['a lone low surrogate', '\udc00'],
    ['a nested object', [1, [{}]]],
  ])('rejects %s', (_, value) => {
    expectAcError(() => canonical(value as CanonicalValue), 'bad-canonical')
  })

  it('rejects a hole in a sparse list instead of skipping it', () => {
    // biome-ignore lint/suspicious/noSparseArray: the hole is the point of the test
    const sparse = [1, , 2] as CanonicalValue
    expectAcError(() => canonical(sparse), 'bad-canonical')
  })

  it('names the type of what it rejects, never the value of a string', () => {
    expect(expectAcError(() => canonical({} as CanonicalValue), 'bad-canonical').message).toContain('object')
    expect(
      expectAcError(() => canonical(undefined as unknown as CanonicalValue), 'bad-canonical').message,
    ).toContain('undefined')
  })
})

describe('isCanonicalInteger', () => {
  it('accepts 0 to 2^53 - 1 only', () => {
    expect(isCanonicalInteger(0)).toBe(true)
    expect(isCanonicalInteger(MAX_CANONICAL_INTEGER)).toBe(true)
    expect(isCanonicalInteger(-1)).toBe(false)
    expect(isCanonicalInteger(0.5)).toBe(false)
    expect(isCanonicalInteger(2 ** 53)).toBe(false)
    expect(isCanonicalInteger('1')).toBe(false)
  })
})
