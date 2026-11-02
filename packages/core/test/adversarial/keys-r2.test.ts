import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  chainVerdict,
  DEGENERATE_KEYS,
  DEGENERATE_SIG,
  mixedKey,
  mixedSign,
  outerVerdict,
  recordVerdict,
  SMALL_ORDER,
} from '../../scripts/gen-adversarial.ts'
import { fromHex, toHex } from '../../src/hex.ts'
import { SMALL_ORDER_POINTS, verifySig } from '../../src/keys.ts'
import { xorshiftRng } from '../support/rng.ts'
import { type AdvCase, bytesOf, label, lineCases } from './support.ts'

// Round-2 line T4 in the TypeScript core: the 14 degenerate Ed25519 keys never verify, and a key of mixed order is
// not refused for itself: its signature verifies exactly when k = 0 mod 8 (spec/SPEC.md §2.3). Every scalar and
// message comes from xorshiftRng with the seed written in the test (V2).

const L = 2n ** 252n + 27742317777372353535851937790883648493n

function scalarOf(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number)
  const s = n % L
  return s === 0n ? 1n : s
}

function verdictOf(c: AdvCase): string {
  if (c.kind === 'record') return recordVerdict(bytesOf(c), c.input.now as number)
  if (c.kind === 'chain') return chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number)
  return outerVerdict(bytesOf(c), c.input.now as number, c.input.ttl as number, c.input.skew as number)
}

describe('T4: degenerate and mixed-order keys', () => {
  it('lists 14 degenerate keys: the 8 small-order points of the core, 2 sign-bit aliases and 4 y + p encodings', () => {
    expect(DEGENERATE_KEYS.length).toBe(14)
    expect(new Set(DEGENERATE_KEYS.map(([, h]) => h)).size).toBe(14)
    expect(new Set(SMALL_ORDER.map(([, h]) => h))).toEqual(new Set(SMALL_ORDER_POINTS.map((p) => toHex(p))))
  })

  it('never verifies a degenerate key with R the identity and S = 0, over 64 seeded messages each (seed 1604)', () => {
    const rng = xorshiftRng(1604)
    for (const [name, pub] of DEGENERATE_KEYS) {
      for (let i = 0; i < 64; i++) {
        expect(verifySig(fromHex(pub, 32), rng(32), fromHex(DEGENERATE_SIG, 64)), name).toBe(false)
      }
    }
  })

  it('verifies a mixed-order signature exactly when k = 0 mod 8: one time in eight over 256 messages per torsion point (seed 1606)', () => {
    const rng = xorshiftRng(1606)
    const order8 = SMALL_ORDER.filter(([name]) => name.startsWith('order-8'))
    expect(order8.length).toBe(4)
    for (const [name, torsion] of order8) {
      const key = mixedKey(scalarOf(rng(64)), torsion)
      const pub = fromHex(key.address.slice(8), 32)
      expect(SMALL_ORDER_POINTS.some((p) => toHex(p) === key.address.slice(8))).toBe(false)
      let ok = 0
      let zero = 0
      for (let i = 0; i < 256; i++) {
        const message = rng(32)
        const { sig, k8 } = mixedSign(key, scalarOf(rng(64)), message)
        const verified = verifySig(pub, message, fromHex(sig, 64))
        expect(verified, `${name} message ${i}, k mod 8 = ${k8}`).toBe(k8 === 0)
        if (verified) ok++
        if (k8 === 0) zero++
      }
      expect(ok).toBe(zero)
      expect(ok).toBeGreaterThan(12)
      expect(ok).toBeLessThan(56)
    }
  })

  it('signs like RFC 8032 for a torsion-free key: the identity as T gives an ordinary key that always verifies', () => {
    const rng = xorshiftRng(1608)
    const identity = SMALL_ORDER[0][1]
    const key = mixedKey(scalarOf(rng(64)), identity)
    for (let i = 0; i < 16; i++) {
      const message = createHash('sha256').update(rng(16)).digest()
      const { sig } = mixedSign(key, scalarOf(rng(64)), message)
      expect(verifySig(fromHex(key.address.slice(8), 32), message, fromHex(sig, 64))).toBe(true)
    }
  })

  it('gives every committed T4 case its pre-registered verdict, the 14 refused in all three places', () => {
    const all = lineCases('round2-keys.json', 'T4')
    expect(all.length).toBe(111)
    expect(all.filter((c) => verdictOf(c) !== c.expected).map((c) => c.name)).toEqual([])
    const degenerate = all.filter((c) => !label(c).includes('mixed') && !label(c).includes('control'))
    expect(degenerate.length).toBe(14 * 2 * 3)
    expect(degenerate.every((c) => c.expected !== 'ok')).toBe(true)
    const pinned = all.filter((c) => label(c).includes('k-0-mod-8'))
    expect(pinned.length).toBe(12)
    expect(pinned.every((c) => c.expected === 'ok')).toBe(true)
    expect(all.filter((c) => label(c).includes('k-not-0-mod-8')).every((c) => c.expected !== 'ok')).toBe(true)
  })
})
