import { describe, expect, it } from 'vitest'
import { outerVerdict, recordVerdict } from '../../scripts/gen-adversarial.ts'
import { DEFAULT_SKEW, DEFAULT_TTL } from '../../src/envelope.ts'
import { signRecord, verifyRecord } from '../../src/records.ts'
import { outcome } from '../support/assert.ts'
import { bytesOf, DAY, item, label, lineCases, MAX, NOW, send, T0, world } from './support.ts'

// Adversarial lines R2 (the ts window at its bounds) and D3 (a record's validity window), in the core.

const WINDOW = DEFAULT_TTL + DEFAULT_SKEW

describe('R2: ts at the bounds of the window', () => {
  it('stale one second below the window, accepted at both bounds, future one second above (seed 521)', () => {
    const w = world(521)
    const { bytes } = send(w, 1, 0)
    expect(outerVerdict(bytes)).toBe('ok')
    expect(outerVerdict(bytes, T0 + WINDOW + 1)).toBe('stale-ts')
    expect(outerVerdict(bytes, T0 + WINDOW)).toBe('ok')
    expect(outerVerdict(bytes, T0 - DEFAULT_SKEW)).toBe('ok')
    expect(outerVerdict(bytes, T0 - DEFAULT_SKEW - 1)).toBe('future-ts')
  })

  it('ts 0 and 2^53 - 1 (seed 522)', () => {
    const w = world(522)
    const zero = send(w, 1, 0, 0)
    const max = send(w, 1, 0, MAX)
    expect(outerVerdict(zero.bytes, NOW)).toBe('stale-ts')
    expect(outerVerdict(zero.bytes, 60)).toBe('ok')
    expect(outerVerdict(max.bytes, NOW)).toBe('future-ts')
    expect(outerVerdict(max.bytes, MAX)).toBe('ok')
  })

  const want: Record<string, string> = {
    'stale-by-one': 'stale-ts',
    'stale-bound': 'ok',
    'future-bound': 'ok',
    'future-by-one': 'future-ts',
    'ts-0-now-t0': 'stale-ts',
    'ts-0-now-60': 'ok',
    'ts-0-now-0': 'ok',
    'ts-max-now-t0': 'future-ts',
    'ts-max-now-max': 'ok',
  }
  it.each(lineCases('envelope-mutations.json', 'R2'))('$name', (c) => {
    expect(outerVerdict(bytesOf(c), c.input.now as number)).toBe(want[label(c)])
  })
})

describe('D3: a record past its iat + ttl, or ahead of the clock', () => {
  const want: Record<string, string> = {
    'address-iat-now-minus-ttl-plus-1': 'ok',
    'address-iat-now-minus-ttl': 'ok',
    'address-iat-now-minus-ttl-minus-1': 'record-expired',
    'address-iat-now-plus-skew': 'ok',
    'address-iat-now-plus-skew-plus-1': 'future-iat',
    'key-exp-now': 'ok',
    'key-exp-now-minus-1': 'record-expired',
  }
  it.each(lineCases('record-mutations.json', 'D3'))('$name', (c) => {
    expect(recordVerdict(bytesOf(c), c.input.now as number)).toBe(want[label(c)])
  })

  it('a fresh address record across its window (seed 523)', () => {
    const w = world(523)
    const key = item(w.signers, 0)
    const r = signRecord(key, {
      kind: 'address',
      key: key.address,
      sealing_key: null,
      relays: [],
      rotation_key: null,
      revoked: [],
      ttl: DAY,
      iat: T0,
      rotated_from: null,
    })
    expect(outcome(() => verifyRecord(r, T0))).toBe('ok')
    expect(outcome(() => verifyRecord(r, T0 + DAY))).toBe('ok')
    expect(outcome(() => verifyRecord(r, T0 + DAY + 1))).toBe('record-expired')
    expect(outcome(() => verifyRecord(r, T0 - DEFAULT_SKEW))).toBe('ok')
    expect(outcome(() => verifyRecord(r, T0 - DEFAULT_SKEW - 1))).toBe('future-iat')
  })
})
