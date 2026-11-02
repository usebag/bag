import { describe, expect, it } from 'vitest'
import {
  jsonVerdict,
  type OpenInput,
  openVerdict,
  outerVerdict,
  parseVerdict,
  recordVerdict,
  rotationClaimVerdict,
} from '../../scripts/gen-adversarial.ts'
import { utf8 } from '../../src/hex.ts'
import { hasDuplicateMember, parseJson } from '../../src/json.ts'
import { decodeContent } from '../../src/seal.ts'
import { newThread } from '../../src/thread.ts'
import { outcome } from '../support/assert.ts'
import { xorshiftRng } from '../support/rng.ts'
import { type AdvCase, bytesOf, label, lineCases } from './support.ts'

// Round-2 lines T5 and T6 in the TypeScript core: a member named twice is refused wherever it is (bad-json, and
// bad-content in the sealed content), and the sealed body's I-JSON freedom (§4.2) carries a lawful non-I-JSON value
// but never reopens a duplicate. Every random value comes from xorshiftRng with the seed written in the test (V2).

const FILE = 'round2-duplicates.json'

function verdictOf(c: AdvCase): string {
  const i = c.input
  switch (c.kind) {
    case 'json':
      return jsonVerdict(bytesOf(c))
    case 'parse':
      return parseVerdict(bytesOf(c))
    case 'outer':
      return outerVerdict(bytesOf(c), i.now as number, i.ttl as number, i.skew as number)
    case 'record':
      return recordVerdict(bytesOf(c), i.now as number)
    case 'rotation-claim':
      return rotationClaimVerdict(bytesOf(c), i.now as number, i.skew as number)
    case 'open':
      return openVerdict(i as unknown as OpenInput)
    default:
      throw new Error(`${c.name}: kind ${c.kind}`)
  }
}

/** A seeded JSON text of nested objects and lists with no duplicate, and another in which one object names a member twice. */
function seededPair(rng: (n: number) => Uint8Array): [string, string] {
  const draw = (): number => rng(1)[0] as number
  let planted = false
  const value = (depth: number, plant: boolean): string => {
    const r = draw() % (depth > 3 ? 3 : 5)
    if (r === 0) return String(draw())
    if (r === 1) return JSON.stringify(`s${draw()}`)
    if (r === 2) return ['1.5', '-0', '1e3', 'true', 'null'][draw() % 5] as string
    if (r === 3) return `[${Array.from({ length: draw() % 3 }, () => value(depth + 1, plant)).join(',')}]`
    const names = Array.from({ length: 1 + (draw() % 4) }, (_, k) => `m${k}`)
    const members = names.map((n) => `${JSON.stringify(n)}:${value(depth + 1, plant)}`)
    if (plant && !planted && draw() % 2 === 0) {
      planted = true
      const again = names[draw() % names.length] as string
      members.push(
        `${draw() % 2 === 0 ? JSON.stringify(again) : `"\\u006d${again.slice(1)}"`}:${value(depth + 1, false)}`,
      )
    }
    return `{${members.join(',')}}`
  }
  for (;;) {
    planted = false
    const plain = `{"root":${value(0, false)}}`
    const dup = `{"root":${value(0, true)}}`
    if (planted) return [plain, dup]
  }
}

describe('T5: a member named twice is refused wherever it is', () => {
  it('refuses 300 seeded texts with one duplicate planted at any depth, bad-json and bad-content, and keeps their twins (seed 1605)', () => {
    const rng = xorshiftRng(1605)
    for (let i = 0; i < 300; i++) {
      const [plain, dup] = seededPair(rng)
      expect(
        outcome(() => parseJson(plain)),
        plain,
      ).toBe('ok')
      expect(hasDuplicateMember(plain)).toBe(false)
      expect(
        outcome(() => parseJson(dup)),
        dup,
      ).toBe('bad-json')
      expect(outcome(() => parseJson(dup, 'bad-content', { strictIntegers: false }))).toBe('bad-content')
      expect(hasDuplicateMember(dup)).toBe(true)
    }
  })

  it('gives every committed T5 case its pre-registered verdict: 0 duplicate accepted in any place', () => {
    const all = lineCases(FILE, 'T5')
    expect(all.filter((c) => verdictOf(c) !== c.expected).map((c) => c.name)).toEqual([])
    const refusals = all.filter((c) => c.expected !== 'ok')
    expect(refusals.length).toBeGreaterThan(0)
    expect(refusals.every((c) => ['bad-json', 'bad-content'].includes(c.expected))).toBe(true)
    expect(
      all.filter((c) => c.kind === 'open' && c.expected !== 'ok').every((c) => c.expected === 'bad-content'),
    ).toBe(true)
    for (const kind of ['parse', 'outer', 'record', 'rotation-claim', 'json', 'open']) {
      expect(
        all.some((c) => c.kind === kind && c.expected !== 'ok'),
        kind,
      ).toBe(true)
      expect(
        all.some((c) => c.kind === kind && c.expected === 'ok'),
        `${kind} control`,
      ).toBe(true)
    }
  })
})

describe('T6: the sealed body carries a lawful non-I-JSON value and never a duplicate', () => {
  const thread = JSON.stringify(newThread(xorshiftRng(1609)))
  const content = (body: string, type = '"type":"t"'): Uint8Array =>
    utf8(`{${type},"thread":${thread},"body":${body}}`)

  it('decodes fractions, -0, exponents and 2^53 + 1 in the body as JSON.parse reads them', () => {
    for (const body of ['1.5', '1.0', '-0', '1e0', '1e+16', '-1', '9007199254740993', '1e-400']) {
      expect(Object.is(decodeContent(content(body)).body, JSON.parse(body)), body).toBe(true)
    }
    expect(decodeContent(content('{"x":[1.5,-2,{"y":1e3}]}')).body).toEqual({ x: [1.5, -2, { y: 1000 }] })
    expect(decodeContent(content('[true,false]')).body).toEqual([true, false])
  })

  it('refuses a duplicate inside the body, and a content naming type or thread twice, as bad-content', () => {
    for (const body of [
      '{"a":1,"a":2}',
      '[{"a":1,"a":1}]',
      '{"a":1,"\\u0061":1}',
      '{"x":{"y":[{"q":0.5,"q":-0}]}}',
    ]) {
      expect(
        outcome(() => decodeContent(content(body))),
        body,
      ).toBe('bad-content')
    }
    expect(outcome(() => decodeContent(content('1.5', '"type":"t","type":"u"')))).toBe('bad-content')
    expect(
      outcome(() => decodeContent(utf8(`{"type":"t","thread":${thread},"thread":${thread},"body":-0}`))),
    ).toBe('bad-content')
    expect(outcome(() => decodeContent(content('{"a":{"k":1.5},"b":{"k":1.5}}')))).toBe('ok')
  })

  it('gives every committed T6 case its pre-registered verdict, each open case with a JSON-reader twin of its plaintext', () => {
    const all = lineCases(FILE, 'T6')
    expect(all.filter((c) => verdictOf(c) !== c.expected).map((c) => c.name)).toEqual([])
    const opens = all.filter((c) => c.kind === 'open')
    expect(opens.filter((c) => label(c).startsWith('body-carried-')).every((c) => c.expected === 'ok')).toBe(
      true,
    )
    for (const o of opens) {
      const twin = all.find((c) => c.kind === 'json' && label(c) === `${label(o)}-plaintext`)
      expect(twin?.expected, o.name).toBe(o.expected === 'bad-content' ? 'bad-json' : 'ok')
    }
  })
})
