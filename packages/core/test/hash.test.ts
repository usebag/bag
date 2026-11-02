import { describe, expect, it } from 'vitest'
import { preimageDigest, sha256, sha256hex } from '../src/hash.ts'
import { toHex, utf8 } from '../src/hex.ts'

describe('sha256', () => {
  it('matches the FIPS 180-2 examples', () => {
    expect(sha256hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(sha256hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('hashes a string as its UTF-8 bytes', () => {
    expect(sha256('é')).toEqual(sha256(utf8('é')))
    expect(sha256(Uint8Array.of(0xc3, 0xa9))).toHaveLength(32)
  })

  it('digests a preimage as sha256(utf8(canonical(preimage)))', () => {
    expect(toHex(preimageDigest(['ac/hop/1', 1]))).toBe(sha256hex('["ac/hop/1",1]'))
  })
})
