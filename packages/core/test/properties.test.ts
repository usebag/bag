import { describe, expect, it } from 'vitest'
import { decodeAddress, encodeAddress } from '../src/address.ts'
import { type CanonicalValue, canonical } from '../src/canonical.ts'
import { evaluateCaveats } from '../src/caveats.ts'
import { type Hop, signHop, verifyChain } from '../src/chain.ts'
import { fromHex, isHex, toHex } from '../src/hex.ts'
import type { Rng } from '../src/keys.ts'
import { codingEvaluator } from '../src/profiles/coding.ts'
import { DAY, P, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// Property tests: 200 cases each, from a seeded xorshift128+, so a failure reproduces exactly.
const RUNS = 200

function int(rng: Rng, n: number): number {
  const b = rng(4)
  return (
    (((b[0] as number) | ((b[1] as number) << 8) | ((b[2] as number) << 16)) + (b[3] as number) * 2 ** 24) % n
  )
}

function pick<T>(rng: Rng, items: readonly T[]): T {
  return items[int(rng, items.length)] as T
}

const ALPHABET = [
  'a',
  'Z',
  '0',
  ' ',
  '"',
  '\\',
  '/',
  '\n',
  '\t',
  '\u0000',
  '\u001f',
  '\u007f',
  'é',
  'é',
  '日',
  ' ',
  '😀',
  '😀',
]

function randomString(rng: Rng): string {
  return Array.from({ length: int(rng, 12) }, () => pick(rng, ALPHABET)).join('')
}

function randomValue(rng: Rng, depth: number): CanonicalValue {
  const kind = int(rng, depth > 2 ? 3 : 4)
  if (kind === 0) return null
  if (kind === 1) return randomString(rng)
  if (kind === 2) {
    const b = rng(7)
    let n = 0
    for (let i = 0; i < 7; i++) n = n * 256 + (b[i] as number)
    return n % 2 ** 53
  }
  return Array.from({ length: int(rng, 5) }, () => randomValue(rng, depth + 1))
}

describe('properties', () => {
  it(`canonical form round-trips and equals JSON.stringify on its values (${RUNS} cases)`, () => {
    const rng = xorshiftRng(0xc0ffee)
    for (let i = 0; i < RUNS; i++) {
      const v = randomValue(rng, 0)
      const c = canonical(v)
      expect(JSON.parse(c)).toEqual(v)
      expect(canonical(JSON.parse(c) as CanonicalValue)).toBe(c)
      expect(c).toBe(JSON.stringify(v))
    }
  })

  it(`hex round-trips (${RUNS} cases)`, () => {
    const rng = xorshiftRng(0x4e4)
    for (let i = 0; i < RUNS; i++) {
      const bytes = rng(int(rng, 65))
      const hex = toHex(bytes)
      expect(isHex(hex, bytes.length)).toBe(true)
      expect(fromHex(hex, bytes.length)).toEqual(bytes)
    }
  })

  it(`addresses round-trip (${RUNS} cases)`, () => {
    const rng = xorshiftRng(0xadd)
    for (let i = 0; i < RUNS; i++) {
      const key = rng(32)
      expect(decodeAddress(encodeAddress(key))).toEqual(key)
    }
  })

  it(`appending a caveat never turns a failing chain into a holding one (${RUNS} cases)`, () => {
    const rng = xorshiftRng(0xa77e)
    const caveatPool = [
      'type=coding.*',
      'type=coding.task.*',
      'type=coding.task.v1',
      'type=coding.result.v1',
      'repo=acme/api',
      'repo=acme/web',
      'net=none',
      'type=*',
    ]
    const types = ['coding.task.v1', 'coding.result.v1', 'chat.message.v1']
    const repos = ['acme/api', 'acme/web']
    let turnedToFail = 0
    for (let i = 0; i < RUNS; i++) {
      const first = Array.from({ length: int(rng, 3) }, () => pick(rng, caveatPool))
      const second = Array.from({ length: int(rng, 3) }, () => pick(rng, caveatPool))
      const chain: Hop[] = [
        signHop(P.org.key, P.jane.address, first, T0 + 30 * DAY),
        signHop(P.jane.key, P.session.address, second, T0 + DAY),
      ]
      const sealed = {
        type: pick(rng, types),
        thread: { id: '00'.repeat(32), prev: [] },
        body: { repo: pick(rng, repos) },
      }
      const ctx = { from: P.session.address, to: [P.bob.address], ts: T0, root: P.org.address, sealed }
      const before = evaluateCaveats(
        verifyChain(chain, P.session.address, T0).caveats,
        [codingEvaluator],
        ctx,
      )
      const added = pick(rng, caveatPool)
      const longer = [chain[0] as Hop, signHop(P.jane.key, P.session.address, [...second, added], T0 + DAY)]
      const after = evaluateCaveats(
        verifyChain(longer, P.session.address, T0).caveats,
        [codingEvaluator],
        ctx,
      )
      if (!before.ok) expect(after.ok).toBe(false)
      if (after.ok) expect(before.ok).toBe(true)
      if (before.ok && !after.ok) turnedToFail++
    }
    // The property is only interesting if appending sometimes narrows: some passing chains must start failing.
    expect(turnedToFail).toBeGreaterThan(0)
  })
})
