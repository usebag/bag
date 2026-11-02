import { createPublicKey, verify } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { encodeAddress } from '../src/address.ts'
import { signHop, verifyChain } from '../src/chain.ts'
import { buildEnvelope, type Envelope, envelopeId, verifyOuter } from '../src/envelope.ts'
import { preimageDigest, sha256 } from '../src/hash.ts'
import { fromHex, toHex, utf8 } from '../src/hex.ts'
import { SigningKey, SMALL_ORDER_POINTS, signPreimage, verifyPreimage, verifySig } from '../src/keys.ts'
import { type KeyRecord, recordPreimage, verifyRecord } from '../src/records.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError, outcome } from './support/assert.ts'
import {
  bytesOf,
  decodeLoose,
  encode,
  IDENTITY,
  le,
  mul,
  orderOf,
  type Point,
  FIELD_P as p,
  ORDER_L as q,
  same,
} from './support/ed25519.ts'
import { DAY, P, recipient, seed, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// Line F7(b)(c): OpenSSL (node:crypto, and Python's cryptography) accepts a small-order or non-canonically encoded
// public key or R, so R = identity, S = 0 "signed" any message under the identity. verifySig now refuses them before
// OpenSSL sees anything, as the Rust core's verify_strict does (spec/SPEC.md §10, "Malleability"). The RFC 8032
// point arithmetic that derives the constants below is support/ed25519.ts, shared with the vector generator.

const hex = (b: Uint8Array): string => toHex(b)
const SMALL = SMALL_ORDER_POINTS.map(hex)
/** x = 0 with the sign bit set: not valid encodings, but OpenSSL reads them as the identity and the order-2 point. */
const SIGN_ALIASES = [`01${'00'.repeat(30)}80`, `ec${'ff'.repeat(31)}`]
/** y + p, both signs, for the two small-order y below 19: the identity (y = 1) and the order-4 points (y = 0). */
const PLUS_P = [
  `ee${'ff'.repeat(30)}7f`,
  `ee${'ff'.repeat(31)}`,
  `ed${'ff'.repeat(30)}7f`,
  `ed${'ff'.repeat(31)}`,
]
const DEGENERATE = [...SMALL, ...SIGN_ALIASES, ...PLUS_P]
const ID = SMALL[0] as string
const FORGED_SIG = fromHex(ID + '00'.repeat(32), 64) // R = identity, S = 0

/** What node:crypto alone says, as verifySig did before it refused the F7 keys. */
function opensslVerifies(publicKey: string, message: Uint8Array, sig: Uint8Array): boolean {
  const spki = Buffer.from(`302a300506032b6570032100${publicKey}`, 'hex')
  return verify(null, message, createPublicKey({ key: spki, format: 'der', type: 'spki' }), sig)
}

describe('SMALL_ORDER_POINTS, derived from RFC 8032 §6', () => {
  it('are the eight distinct points P with [8]P = identity: orders 1, 2, 4, 4, 8, 8, 8, 8', () => {
    const points = SMALL_ORDER_POINTS.map((b) => decodeLoose(b) as Point)
    expect(points.map(orderOf)).toEqual([1, 2, 4, 4, 8, 8, 8, 8])
    expect(points.map((pt) => hex(encode(pt)))).toEqual(SMALL)
    expect(new Set(SMALL).size).toBe(8)
  })

  it('are exactly the torsion subgroup: [q]B0 for a point B0 of order 8q, and its multiples', () => {
    let y = 2n
    let t: Point = IDENTITY
    while (orderOf(t) !== 8) {
      y += 1n
      const pt = decodeLoose(bytesOf(y))
      if (pt !== null) t = mul(q, pt)
    }
    const derived = Array.from({ length: 8 }, (_, k) => hex(encode(mul(BigInt(k), t))))
    expect(derived.sort()).toEqual([...SMALL].sort())
  })

  it('contain no honest key, and no honest key has small order', () => {
    for (let s = 1; s <= 24; s++) {
      const key = new SigningKey(seed(s))
      expect(SMALL).not.toContain(hex(key.publicKey))
      expect(orderOf(decodeLoose(key.publicKey) as Point)).toBe(0)
      expect(verifySig(key.publicKey, utf8('m'), key.sign(utf8('m')))).toBe(true)
    }
  })

  it('have a y + p alias only for y = 0 and y = 1, and verifySig refuses each alias as the key and as R', () => {
    for (const e of SMALL_ORDER_POINTS) {
      const n = le(e)
      const y = n & ((1n << 255n) - 1n)
      const alias = y + p
      if (y >= 19n) {
        expect(alias >= 1n << 255n).toBe(true)
        continue
      }
      const b = bytesOf(alias | (n & (1n << 255n)))
      expect(PLUS_P).toContain(hex(b))
      expect(same(decodeLoose(b) as Point, decodeLoose(e) as Point)).toBe(true)
      expect(verifySig(b, utf8('m'), FORGED_SIG)).toBe(false)
      expect(verifySig(fromHex(ID), utf8('m'), Uint8Array.from([...b, ...new Uint8Array(32)]))).toBe(false)
    }
  })

  it('refuse every encoding with y >= p (all 19 values of y, both signs) as the key and as R', () => {
    const honest = new SigningKey(seed(0x31))
    const sig = honest.sign(utf8('m'))
    for (let k = 0n; k < 19n; k++) {
      for (const sign of [0n, 1n << 255n]) {
        const b = bytesOf((p + k) | sign)
        expect(verifySig(b, utf8('m'), sig)).toBe(false)
        expect(verifySig(honest.publicKey, utf8('m'), Uint8Array.from([...b, ...sig.subarray(32)]))).toBe(
          false,
        )
      }
    }
  })
})

describe('verifySig refuses the forged signatures of line F7', () => {
  const messages = Array.from({ length: 64 }, (_, i) => sha256(utf8(`message ${i}`)))

  it('R = identity, S = 0 under the identity: OpenSSL accepts every message, verifySig none', () => {
    expect(messages.filter((m) => opensslVerifies(ID, m, FORGED_SIG))).toHaveLength(64)
    expect(messages.filter((m) => verifySig(fromHex(ID), m, FORGED_SIG))).toHaveLength(0)
  })

  it.each(DEGENERATE)('R = identity, S = 0 under %s: refused for every message', (key) => {
    expect(messages.filter((m) => verifySig(fromHex(key), m, FORGED_SIG))).toHaveLength(0)
  })

  it.each(DEGENERATE)('R = %s under an honest key: refused', (r) => {
    const key = new SigningKey(seed(0x32))
    const sig = Uint8Array.from([...fromHex(r), ...key.sign(utf8('m')).subarray(32)])
    expect(verifySig(key.publicKey, utf8('m'), sig)).toBe(false)
  })

  it('an S at or above L is refused before OpenSSL; below L the honest signature verifies', () => {
    const key = new SigningKey(seed(0x33))
    const sig = key.sign(utf8('m'))
    const withS = (s: bigint): Uint8Array => Uint8Array.from([...sig.subarray(0, 32), ...bytesOf(s)])
    expect(verifySig(key.publicKey, utf8('m'), withS(le(sig.subarray(32))))).toBe(true)
    for (const s of [q, q + 1n, le(sig.subarray(32)) + q, (1n << 256n) - 1n])
      expect(verifySig(key.publicKey, utf8('m'), withS(s))).toBe(false)
  })

  it('keys that only resemble a forbidden encoding still reach OpenSSL, and a forged signature fails there', () => {
    // byte 31 is 0x7f but a middle byte is not 0xff; the first 31 bytes of the identity but another top byte
    for (const key of [
      `${'00'.repeat(31)}7f`,
      `01${'00'.repeat(30)}01`,
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e',
    ])
      expect(verifySig(fromHex(key), utf8('m'), FORGED_SIG)).toBe(false)
  })

  it('verifyPreimage refuses the forgery by address', () => {
    for (const key of DEGENERATE)
      expect(
        verifyPreimage(`ed25519:${key}`, ['ac/fetch/1', `ed25519:${key}`, 'ab', 1], hex(FORGED_SIG)),
      ).toBe(false)
  })
})

describe('the verifiers refuse a small-order or non-canonical signer', () => {
  const thread = newThread(xorshiftRng(5))
  const built = buildEnvelope({
    from: P.session.key,
    to: [recipient(P.bob)],
    type: 'coding.task.v1',
    thread,
    body: { repo: 'acme/api' },
    ts: T0,
    rng: xorshiftRng(6),
  })

  it.each(DEGENERATE)('an envelope whose from is %s, R = identity, S = 0, is bad-sig', (key) => {
    const forged = { ...built.envelope, from: `ed25519:${key}`, sig: hex(FORGED_SIG) }
    const e: Envelope = { ...forged, id: envelopeId(forged) }
    if (key === ID) expect(opensslVerifies(key, fromHex(e.id), FORGED_SIG)).toBe(true)
    expectAcError(() => verifyOuter(e, T0), 'bad-sig')
  })

  it.each(DEGENERATE)('a hop whose iss is %s, R = identity, S = 0, is bad-hop-sig', (key) => {
    const honest = signHop(P.org.key, P.session.address, ['type=coding.*'], T0 + DAY)
    const hop = { ...honest, iss: `ed25519:${key}`, sig: hex(FORGED_SIG) }
    expectAcError(() => verifyChain([hop], P.session.address, T0), 'bad-hop-sig')
  })

  it.each(DEGENERATE)('a key record whose key is %s, R = identity, S = 0, is bad-record-sig', (key) => {
    const r: KeyRecord = {
      kind: 'key',
      key: `ed25519:${key}`,
      sealing_key: hex(P.bob.sealing?.publicKey as Uint8Array),
      iat: T0,
      exp: T0 + DAY,
      sig: hex(FORGED_SIG),
    }
    if (key === ID) expect(opensslVerifies(key, preimageDigest(recordPreimage(r)), FORGED_SIG)).toBe(true)
    expectAcError(() => verifyRecord(r, T0), 'bad-record-sig')
  })

  it('an honest envelope, hop and record still verify', () => {
    expect(outcome(() => verifyOuter(built.envelope, T0))).toBe('ok')
    const hop = signHop(P.org.key, P.session.address, [], T0 + DAY)
    expect(verifyChain([hop], P.session.address, T0).root).toBe(P.org.address)
    const unsigned = {
      kind: 'key',
      key: P.jane.address,
      sealing_key: '00'.repeat(32),
      iat: T0,
      exp: T0 + DAY,
    } as const
    const r: KeyRecord = { ...unsigned, sig: signPreimage(P.jane.key, recordPreimage(unsigned)) }
    expect(outcome(() => verifyRecord(r, T0))).toBe('ok')
    expect(encodeAddress(P.jane.key.publicKey)).toBe(P.jane.address)
  })
})
