import { inspect } from 'node:util'
import { describe, expect, it } from 'vitest'
import { fromHex, toHex, utf8 } from '../src/hex.ts'
import { hpkeSeal } from '../src/hpke.ts'
import {
  generateSealingKey,
  generateSigningKey,
  SealingKey,
  SigningKey,
  sealingKeyFromSeed,
  signingKeyFromSeed,
  signPreimage,
  verifyPreimage,
  verifySig,
} from '../src/keys.ts'
import { expectAcError } from './support/assert.ts'
import { seed } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// RFC 8032 §7.1, test 1 and test 2.
const RFC8032 = [
  {
    secret: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    public: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: '',
    signature:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    secret: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    public: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message: '72',
    signature:
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
]

describe('signing keys', () => {
  it.each(RFC8032)('reproduce RFC 8032 §7.1 (public key $public)', (v) => {
    const key = signingKeyFromSeed(fromHex(v.secret))
    expect(toHex(key.publicKey)).toBe(v.public)
    expect(key.address).toBe(`ed25519:${v.public}`)
    expect(toHex(key.sign(fromHex(v.message)))).toBe(v.signature)
    expect(verifySig(key.publicKey, fromHex(v.message), fromHex(v.signature))).toBe(true)
  })

  it('never print the seed: inspect and JSON show the address only', () => {
    const key = new SigningKey(seed(0x01))
    const secret = toHex(seed(0x01))
    expect(inspect(key)).toBe(`SigningKey { address: '${key.address}' }`)
    expect(JSON.stringify({ key })).toBe(`{"key":{"address":"${key.address}"}}`)
    expect(inspect(key, { showHidden: true, depth: 5 })).not.toContain(secret)
    expect(JSON.stringify(key)).not.toContain(secret)
  })

  it('export a copy of the seed for a key store', () => {
    const key = new SigningKey(seed(0x01))
    const copy = key.exportSeed()
    expect(copy).toEqual(seed(0x01))
    copy.fill(0)
    expect(key.exportSeed()).toEqual(seed(0x01))
  })

  it('keep their own copy of the seed', () => {
    const s = seed(0x05)
    const key = new SigningKey(s)
    s.fill(0)
    expect(key.exportSeed()).toEqual(seed(0x05))
  })

  it('come from 32 bytes of an rng', () => {
    const a = generateSigningKey(xorshiftRng(1))
    const b = generateSigningKey(xorshiftRng(1))
    expect(a.address).toBe(b.address)
    expect(generateSigningKey(xorshiftRng(2)).address).not.toBe(a.address)
  })

  it('need a 32-byte seed', () => {
    expectAcError(() => signingKeyFromSeed(new Uint8Array(31)), 'bad-key')
    expectAcError(() => new SigningKey('seed' as unknown as Uint8Array), 'bad-key')
    expectAcError(() => generateSigningKey(() => new Uint8Array(16)), 'bad-key')
  })
})

describe('verifySig', () => {
  const key = new SigningKey(seed(0x02))
  const message = utf8('hello')
  const sig = key.sign(message)

  it('accepts the signer and nothing else', () => {
    expect(verifySig(key.publicKey, message, sig)).toBe(true)
    expect(verifySig(new SigningKey(seed(0x03)).publicKey, message, sig)).toBe(false)
    expect(verifySig(key.publicKey, utf8('hellp'), sig)).toBe(false)
    const flipped = Uint8Array.from(sig)
    flipped[0] = (flipped[0] as number) ^ 1
    expect(verifySig(key.publicKey, message, flipped)).toBe(false)
  })

  it('is false for malformed input, never a throw', () => {
    expect(verifySig(new Uint8Array(31), message, sig)).toBe(false)
    expect(verifySig(key.publicKey, message, sig.subarray(0, 63))).toBe(false)
    expect(verifySig(new Uint8Array(32).fill(0xff), message, sig)).toBe(false)
  })

  it('rejects a non-canonical S (S + L), so a signature cannot be malleated', () => {
    const L = (1n << 252n) + 27742317777372353535851937790883648493n
    let s = 0n
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i] as number)
    let t = s + L
    const malleated = Uint8Array.from(sig)
    for (let i = 0; i < 32; i++) {
      malleated[32 + i] = Number(t & 0xffn)
      t >>= 8n
    }
    expect(verifySig(key.publicKey, message, malleated)).toBe(false)
  })
})

describe('preimage signatures', () => {
  const key = new SigningKey(seed(0x04))

  it('sign the digest of a preimage and verify by address', () => {
    const sig = signPreimage(key, ['ac/fetch/1', key.address, 'ab', 1])
    expect(sig).toMatch(/^[0-9a-f]{128}$/)
    expect(verifyPreimage(key.address, ['ac/fetch/1', key.address, 'ab', 1], sig)).toBe(true)
    expect(verifyPreimage(key.address, ['ac/fetch/1', key.address, 'ab', 2], sig)).toBe(false)
  })

  it('are false for a malformed address, signature or preimage', () => {
    const sig = signPreimage(key, ['x'])
    expect(verifyPreimage('nobody', ['x'], sig)).toBe(false)
    expect(verifyPreimage(key.address, ['x'], sig.toUpperCase())).toBe(false)
    expect(verifyPreimage(key.address, ['\ud800'], sig)).toBe(false)
  })
})

describe('sealing keys', () => {
  it('derive the X25519 public key (RFC 7748 §6.1)', () => {
    const alice = sealingKeyFromSeed(
      fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
    )
    expect(toHex(alice.publicKey)).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
  })

  it('open what was sealed to them', () => {
    const key = new SealingKey(seed(0x12))
    const { enc, ct } = hpkeSeal(key.publicKey, utf8('info'), utf8('aad'), utf8('content key'))
    expect(new TextDecoder().decode(key.open(enc, utf8('info'), utf8('aad'), ct))).toBe('content key')
  })

  it('never print the private key', () => {
    const key = new SealingKey(seed(0x12))
    const secret = toHex(seed(0x12))
    expect(inspect(key)).toBe(`SealingKey { sealing_key: '${toHex(key.publicKey)}' }`)
    expect(JSON.stringify(key)).toBe(`{"sealing_key":"${toHex(key.publicKey)}"}`)
    expect(inspect(key, { showHidden: true })).not.toContain(secret)
    expect(key.exportSeed()).toEqual(seed(0x12))
  })

  it('come from 32 bytes of an rng, and need 32', () => {
    expect(toHex(generateSealingKey(xorshiftRng(3)).publicKey)).toBe(
      toHex(generateSealingKey(xorshiftRng(3)).publicKey),
    )
    expectAcError(() => sealingKeyFromSeed(new Uint8Array(33)), 'bad-key')
  })
})
