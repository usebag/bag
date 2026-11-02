import { describe, expect, it } from 'vitest'
import { fromHex, toHex, utf8 } from '../src/hex.ts'
import {
  aeadOpen,
  aeadSeal,
  computeNonce,
  decap,
  deriveKeyPair,
  encap,
  exportSecret,
  HPKE_AEAD_ID,
  HPKE_KDF_ID,
  HPKE_KEM_ID,
  HPKE_MODE_BASE,
  hkdfExpand,
  hkdfExtract,
  hpkeOpen,
  hpkeSeal,
  i2osp,
  keySchedule,
  x25519,
  x25519PublicKey,
} from '../src/hpke.ts'
import { expectAcError } from './support/assert.ts'
import { seed } from './support/fixtures.ts'
import { type RfcCase, rebuildRfcCase } from './support/rfc9180.ts'
import { casesOf, readVectors } from './support/vectors.ts'

const subset = readVectors('hpke-rfc9180-subset.json')
const rfcCases = casesOf<RfcCase>(subset)

describe('the RFC 9180 subset', () => {
  it('records its upstream source and holds the one case for suite 1', () => {
    const source = subset.source as Record<string, unknown>
    expect(source.url).toBe(
      'https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json',
    )
    expect(source.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(source.kept_cases).toBe(rfcCases.length)
    expect(rfcCases).toHaveLength(1)
    for (const c of rfcCases) {
      expect([c.mode, c.kem_id, c.kdf_id, c.aead_id]).toEqual([
        HPKE_MODE_BASE,
        HPKE_KEM_ID,
        HPKE_KDF_ID,
        HPKE_AEAD_ID,
      ])
    }
  })

  describe.each(rfcCases.map((c, i) => [i, c] as const))('case %i', (_, c) => {
    const r = deriveKeyPair(fromHex(c.ikmR))
    const e = deriveKeyPair(fromHex(c.ikmE))

    it('derives both key pairs from their ikm', () => {
      expect([toHex(r.sk), toHex(r.pk), toHex(e.sk), toHex(e.pk)]).toEqual([c.skRm, c.pkRm, c.skEm, c.pkEm])
    })

    it('encapsulates and decapsulates the shared secret', () => {
      const { sharedSecret, enc } = encap(fromHex(c.pkRm), fromHex(c.skEm))
      expect(toHex(enc)).toBe(c.enc)
      expect(toHex(sharedSecret)).toBe(c.shared_secret)
      expect(toHex(decap(fromHex(c.enc), fromHex(c.skRm)))).toBe(c.shared_secret)
    })

    it('runs the key schedule', () => {
      const ks = keySchedule(fromHex(c.shared_secret), fromHex(c.info))
      expect(toHex(ks.keyScheduleContext)).toBe(c.key_schedule_context)
      expect(toHex(ks.secret)).toBe(c.secret)
      expect(toHex(ks.key)).toBe(c.key)
      expect(toHex(ks.baseNonce)).toBe(c.base_nonce)
      expect(toHex(ks.exporterSecret)).toBe(c.exporter_secret)
    })

    it(`seals and opens all ${c.encryptions.length} encryptions, by sequence number`, () => {
      const key = fromHex(c.key)
      let passed = 0
      for (const [seq, x] of c.encryptions.entries()) {
        const nonce = computeNonce(fromHex(c.base_nonce), seq)
        expect(toHex(nonce)).toBe(x.nonce)
        expect(toHex(aeadSeal(key, nonce, fromHex(x.aad), fromHex(x.pt)))).toBe(x.ct)
        expect(toHex(aeadOpen(key, nonce, fromHex(x.aad), fromHex(x.ct)))).toBe(x.pt)
        passed++
      }
      expect(passed).toBe(c.encryptions.length)
    })

    it(`exports all ${c.exports.length} secrets`, () => {
      for (const x of c.exports) {
        expect(toHex(exportSecret(fromHex(c.exporter_secret), fromHex(x.exporter_context), x.L))).toBe(
          x.exported_value,
        )
      }
    })

    it('single-shot seal and open are sequence number 0', () => {
      const first = c.encryptions[0]
      if (first === undefined) throw new Error('no encryption')
      const sealed = hpkeSeal(
        fromHex(c.pkRm),
        fromHex(c.info),
        fromHex(first.aad),
        fromHex(first.pt),
        fromHex(c.skEm),
      )
      expect([toHex(sealed.enc), toHex(sealed.ct)]).toEqual([c.enc, first.ct])
      expect(
        toHex(
          hpkeOpen(fromHex(c.skRm), fromHex(c.enc), fromHex(c.info), fromHex(first.aad), fromHex(first.ct)),
        ),
      ).toBe(first.pt)
    })

    it('is rebuilt field for field from its inputs alone', () => {
      expect(rebuildRfcCase(c)).toEqual(c)
    })
  })
})

describe('X25519', () => {
  // RFC 7748 §6.1.
  const aliceSk = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
  const bobSk = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

  it('agrees on the RFC 7748 shared secret', () => {
    expect(toHex(x25519PublicKey(bobSk))).toBe(
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    )
    expect(toHex(x25519(aliceSk, x25519PublicKey(bobSk)))).toBe(shared)
    expect(toHex(x25519(bobSk, x25519PublicKey(aliceSk)))).toBe(shared)
  })

  it('refuses a small-order public key and keys of the wrong length', () => {
    expectAcError(() => x25519(aliceSk, new Uint8Array(32)), 'bad-key')
    expectAcError(() => x25519(aliceSk, Uint8Array.of(1, ...new Uint8Array(31))), 'bad-key')
    expectAcError(() => x25519(aliceSk, new Uint8Array(31)), 'bad-key')
    expectAcError(() => x25519PublicKey(new Uint8Array(16)), 'bad-key')
  })
})

describe('HKDF-SHA256', () => {
  it('matches RFC 5869 test case 1', () => {
    const prk = hkdfExtract(fromHex('000102030405060708090a0b0c'), fromHex('0b'.repeat(22)))
    expect(toHex(prk)).toBe('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5')
    expect(toHex(hkdfExpand(prk, fromHex('f0f1f2f3f4f5f6f7f8f9'), 42))).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    )
  })

  it('gives at most 255 blocks', () => {
    expect(hkdfExpand(new Uint8Array(32), new Uint8Array(0), 255 * 32)).toHaveLength(8160)
    expect(hkdfExpand(new Uint8Array(32), new Uint8Array(0), 0)).toHaveLength(0)
    expectAcError(() => hkdfExpand(new Uint8Array(32), new Uint8Array(0), 255 * 32 + 1), 'bad-key')
    expectAcError(() => hkdfExpand(new Uint8Array(32), new Uint8Array(0), -1), 'bad-key')
    expectAcError(() => exportSecret(new Uint8Array(32), new Uint8Array(0), 1.5), 'bad-key')
  })
})

describe('I2OSP and the nonce', () => {
  it('writes big-endian', () => {
    expect(toHex(i2osp(0, 2))).toBe('0000')
    expect(toHex(i2osp(0x0102, 2))).toBe('0102')
    expect(toHex(i2osp(2 ** 40 + 5, 12))).toBe('000000000000010000000005')
  })

  it('XORs the sequence number into the base nonce', () => {
    expect(toHex(computeNonce(new Uint8Array(12), 0x0102))).toBe('000000000000000000000102')
  })
})

describe('single-shot HPKE', () => {
  const skR = seed(0x14)
  const pkR = x25519PublicKey(skR)
  const info = utf8('ac/seal/1')
  const aad = utf8('ed25519:recipient')
  const pt = Uint8Array.from({ length: 32 }, (_, i) => i)

  it('round-trips with a fresh ephemeral key, which differs every time', () => {
    const a = hpkeSeal(pkR, info, aad, pt)
    const b = hpkeSeal(pkR, info, aad, pt)
    expect(toHex(a.enc)).not.toBe(toHex(b.enc))
    expect(a.ct).toHaveLength(48)
    expect(hpkeOpen(skR, a.enc, info, aad, a.ct)).toEqual(pt)
  })

  it('is deterministic with an injected ephemeral key', () => {
    const skE = seed(0x21)
    expect(toHex(hpkeSeal(pkR, info, aad, pt, skE).ct)).toBe(toHex(hpkeSeal(pkR, info, aad, pt, skE).ct))
  })

  it('does not open with another key, info, aad, enc or ciphertext', () => {
    const { enc, ct } = hpkeSeal(pkR, info, aad, pt)
    expectAcError(() => hpkeOpen(seed(0x15), enc, info, aad, ct), 'open-failed')
    expectAcError(() => hpkeOpen(skR, enc, utf8('ac/seal/2'), aad, ct), 'open-failed')
    expectAcError(() => hpkeOpen(skR, enc, info, utf8('ed25519:other'), ct), 'open-failed')
    expectAcError(() => hpkeOpen(skR, x25519PublicKey(seed(0x22)), info, aad, ct), 'open-failed')
    const tampered = Uint8Array.from(ct)
    tampered[0] = (tampered[0] as number) ^ 1
    expectAcError(() => hpkeOpen(skR, enc, info, aad, tampered), 'open-failed')
    expectAcError(() => hpkeOpen(skR, enc, info, aad, ct.subarray(0, 15)), 'open-failed')
  })

  it('treats a malformed or small-order enc as a failed open', () => {
    const { ct } = hpkeSeal(pkR, info, aad, pt)
    expectAcError(() => hpkeOpen(skR, new Uint8Array(31), info, aad, ct), 'open-failed')
    expectAcError(() => hpkeOpen(skR, new Uint8Array(32), info, aad, ct), 'open-failed')
  })

  it('refuses keys of the wrong length and a small-order recipient key', () => {
    expectAcError(() => hpkeSeal(new Uint8Array(31), info, aad, pt), 'bad-key')
    expectAcError(() => hpkeSeal(new Uint8Array(32), info, aad, pt), 'bad-key')
    expectAcError(() => hpkeSeal(pkR, info, aad, pt, new Uint8Array(31)), 'bad-key')
    expectAcError(
      () => hpkeOpen(new Uint8Array(31), new Uint8Array(32), info, aad, new Uint8Array(48)),
      'bad-key',
    )
  })

  it('AES-256-GCM refuses a key, nonce or tag of the wrong length', () => {
    const ct = aeadSeal(new Uint8Array(32), new Uint8Array(12), aad, pt)
    expectAcError(() => aeadOpen(new Uint8Array(16), new Uint8Array(12), aad, ct), 'open-failed')
    expectAcError(() => aeadOpen(new Uint8Array(32), new Uint8Array(8), aad, ct), 'open-failed')
    expect(aeadOpen(new Uint8Array(32), new Uint8Array(12), aad, ct)).toEqual(pt)
  })
})
