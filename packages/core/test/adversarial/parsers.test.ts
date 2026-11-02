import { describe, expect, it } from 'vitest'
import {
  jsonVerdict,
  outerVerdict,
  parseVerdict,
  recordVerdict,
  rotationVerdict,
} from '../../scripts/gen-adversarial.ts'
import { type CanonicalValue, canonical } from '../../src/canonical.ts'
import { sha256hex } from '../../src/hash.ts'
import { outcome } from '../support/assert.ts'
import { xorshiftRng } from '../support/rng.ts'
import { type AdvCase, bytesOf, label, lineCases } from './support.ts'

// Adversarial lines P1, P2, P3, D1, D4, D5 (the form half) and D6, in the TypeScript core.

describe('P1: the canonical form', () => {
  const all = lineCases('canonical-fuzz.json', 'P1')
  const valid = all.filter((c) => c.expected === 'ok')
  const invalid = all.filter((c) => c.expected !== 'ok')

  it('holds 2,000 valid values and 300 invalid ones', () => {
    expect(valid.length).toBe(2000)
    expect(invalid.length).toBe(300)
  })

  it('writes the committed bytes and SHA-256 for every valid value, and the bytes read back to the value', () => {
    const wrong: string[] = []
    for (const c of valid) {
      const text = canonical(c.input.value as CanonicalValue)
      if (text !== c.input.canonical || sha256hex(text) !== c.input.sha256) wrong.push(c.name)
      if (canonical(JSON.parse(text) as CanonicalValue) !== text) wrong.push(`${c.name} (round trip)`)
      if (JSON.stringify(JSON.parse(text)) !== JSON.stringify(c.input.value)) wrong.push(`${c.name} (value)`)
    }
    expect(wrong).toEqual([])
  })

  it('escapes exactly the §2.2 set: no U+007F, U+2028, U+2029, solidus or non-ASCII escape, lowercase \\u00xx', () => {
    for (let i = 0; i < 32; i++) {
      const short: Record<number, string> = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' }
      const want = short[i] ?? `\\u00${i.toString(16).padStart(2, '0')}`
      expect(canonical(String.fromCharCode(i))).toBe(`"${want}"`)
    }
    for (const ch of ['\u007f', ' ', ' ', '/', 'é', 'é', '😀', '﻿']) {
      expect(canonical(ch)).toBe(`"${ch}"`)
    }
    expect(canonical(['"', '\\'])).toBe('["\\"","\\\\"]')
  })

  it('refuses every invalid value with bad-canonical', () => {
    expect(invalid.filter((c) => c.expected !== 'bad-canonical').map((c) => c.name)).toEqual([])
  })

  it('refuses a list with a hole and a lone surrogate written fresh', () => {
    const holey: string[] = ['a']
    holey[2] = 'b'
    expect(outcome(() => canonical(holey))).toBe('bad-canonical')
    expect(outcome(() => canonical(['\ud800']))).toBe('bad-canonical')
    expect(outcome(() => canonical([0.5]))).toBe('bad-canonical')
    expect(outcome(() => canonical(-0))).toBe('ok')
  })

  it('round-trips 500 seeded nested values (seed 531)', () => {
    const rng = xorshiftRng(531)
    const draw = (depth: number): CanonicalValue => {
      const b = rng(2)
      const r = (b[0] as number) % (depth > 6 ? 3 : 4)
      if (r === 0) return String.fromCharCode(...rng(1 + ((b[1] as number) % 6)))
      if (r === 1) return (b[1] as number) * 65_537
      if (r === 2) return null
      return Array.from({ length: (b[1] as number) % 4 }, () => draw(depth + 1))
    }
    for (let i = 0; i < 500; i++) {
      const v = draw(0)
      const text = canonical(v)
      expect(text).toBe(JSON.stringify(v))
      expect(canonical(JSON.parse(text) as CanonicalValue)).toBe(text)
    }
  })
})

// P2: the spec's requirement per spelling (§2.5 as changed): a number where a canonical
// integer is expected is taken only when written `0` or `[1-9][0-9]*` and at most 2^53 - 1. Every other spelling is
// refused with its place's code (v bad-version, suite bad-suite, ts bad-shape, a hop's exp bad-hop, a record member
// bad-record); `01` and `1e400` are not JSON numbers a reader can hold and are bad-json. No reader differs, so no
// case carries `allowed`.
function p2Verdict(c: AdvCase): string {
  return c.kind === 'record'
    ? recordVerdict(bytesOf(c), c.input.now as number)
    : outerVerdict(bytesOf(c), c.input.now as number)
}
const p2 = [...lineCases('envelope-mutations.json', 'P2'), ...lineCases('record-mutations.json', 'P2')]
const PLACE: readonly (readonly [string, string])[] = [
  ['v-', 'bad-version'],
  ['suite-', 'bad-suite'],
  ['ts-', 'bad-shape'],
  ['hop-exp-', 'bad-hop'],
  ['address-iat-', 'bad-record'],
  ['accept-ttl-', 'bad-record'],
  ['key-exp-', 'bad-record'],
]
function placeOf(c: AdvCase): readonly [string, string] {
  const p = PLACE.find(([prefix]) => label(c).startsWith(prefix))
  if (p === undefined) throw new Error(`${c.name}: no place`)
  return p
}
const spelling = (c: AdvCase): string => label(c).slice(placeOf(c)[0].length)

describe('P2: number readings', () => {
  it('covers 12 spellings in each of 7 places, with no allowed divergence', () => {
    expect(p2.length).toBe(84)
    expect(p2.filter((c) => c.allowed !== undefined).map((c) => c.name)).toEqual([])
  })
  it.each(p2.filter((c) => ['01', '1e400'].includes(spelling(c))))('$name is bad-json', (c) => {
    expect(p2Verdict(c)).toBe('bad-json')
  })
  it.each(p2.filter((c) => !['01', '1e400'].includes(spelling(c))))(
    "$name is refused with its place's code",
    (c) => {
      expect(p2Verdict(c)).toBe(placeOf(c)[1])
    },
  )
})

describe('P3: bytes that are not JSON text', () => {
  const json = lineCases('envelope-mutations.json', 'P3').filter((c) => c.kind === 'json')
  const parse = lineCases('envelope-mutations.json', 'P3').filter((c) => c.kind === 'parse')
  const VALUES = ['null', 'empty-list', 'number', 'string']
  it.each(json.filter((c) => !VALUES.includes(label(c))))('json: $name is bad-json', (c) => {
    expect(jsonVerdict(bytesOf(c))).toBe('bad-json')
  })
  it.each(json.filter((c) => VALUES.includes(label(c))))('json: $name is one JSON value', (c) => {
    expect(jsonVerdict(bytesOf(c))).toBe('ok')
  })
  it.each(parse)('parse: $name', (c) => {
    expect(parseVerdict(bytesOf(c))).toBe(VALUES.includes(label(c)) ? 'bad-shape' : 'bad-json')
  })
})

describe('D1: a rotation without a valid countersignature', () => {
  it.each(lineCases('record-mutations.json', 'D1'))('$name', (c) => {
    const want = label(c).startsWith('countersigned-by') ? 'ok' : 'bad-rotation'
    expect(rotationVerdict(bytesOf(c, 'prev_bytes_hex'), bytesOf(c, 'next_bytes_hex'))).toBe(want)
  })
})

describe('D4: caps and bounds', () => {
  const want: Record<string, string> = {
    'address-ttl-0': 'bad-record',
    'address-ttl-86401': 'bad-record',
    'address-ttl-86400': 'ok',
    'address-8-relays': 'ok',
    'address-65-relays': 'too-many-relays',
    'address-1024-revoked': 'ok',
    'address-1025-revoked': 'too-many-revoked',
    'accept-ttl-max': 'ok',
    'accept-max-bytes-0': 'bad-record',
    'key-exp-before-iat': 'bad-record',
  }
  it.each(lineCases('record-mutations.json', 'D4'))('$name', (c) => {
    expect(recordVerdict(bytesOf(c), c.input.now as number)).toBe(want[label(c)])
  })
})

describe('D5: hostile relay URLs, the form half', () => {
  const want: Record<string, string> = {
    'relay-javascript': 'bad-record',
    'relay-ftp': 'bad-record',
    'relay-http-with-space': 'bad-record',
    'relay-http-empty-host': 'bad-record',
    'relay-http-loopback': 'ok',
    'relay-http-link-local-metadata': 'ok',
    'relay-https-ipv6-loopback': 'ok',
    'relay-http-tab': 'bad-record',
    'relay-http-del': 'bad-record',
    'relay-http-c1-control': 'bad-record',
    'relay-upper-case-scheme': 'bad-record',
  }
  it.each(lineCases('record-mutations.json', 'D5').filter((c) => label(c) in want))('$name', (c) => {
    expect(recordVerdict(bytesOf(c), c.input.now as number)).toBe(want[label(c)])
  })
  it('measure: a URL with user information passes the form (recorded, not a rule)', () => {
    const c = lineCases('record-mutations.json', 'D5', 'relay-http-userinfo')[0] as AdvCase
    expect(recordVerdict(bytesOf(c), c.input.now as number)).toBe(c.expected)
  })
})

// D6, flipped on 2026-10-25: every reader refuses a member name given twice, so
// each case is bad-json. Until then the last value won: bad-id for two-id-valid-first, two-ts-valid-first and
// hop-two-exp-valid-first, bad-record for two-ttl-valid-first, bad-record-sig for two-ttl-both-valid-other-last and
// two-sig-valid-first, ok for the other five.
describe('D6: duplicate members are bad-json', () => {
  const cases = [...lineCases('envelope-mutations.json', 'D6'), ...lineCases('record-mutations.json', 'D6')]
  it('are the eleven cases of envelopes and records', () => {
    expect(cases.map(label)).toEqual([
      'two-id-valid-first',
      'two-id-valid-last',
      'two-ts-valid-last',
      'two-ts-valid-first',
      'hop-two-exp-valid-last',
      'hop-two-exp-valid-first',
      'two-ttl-valid-last',
      'two-ttl-valid-first',
      'two-ttl-both-valid-other-last',
      'two-sig-valid-last',
      'two-sig-valid-first',
    ])
  })
  it.each(cases)('$name', (c) => {
    const v =
      c.kind === 'record' ? recordVerdict(bytesOf(c), c.input.now as number) : outerVerdict(bytesOf(c))
    expect(v).toBe('bad-json')
  })
})
