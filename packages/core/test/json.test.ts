import { describe, expect, it } from 'vitest'
import { buildEnvelope, parseEnvelope } from '../src/envelope.ts'
import { utf8 } from '../src/hex.ts'
import { hasDuplicateMember, parseJson } from '../src/json.ts'
import { parseRecord } from '../src/records.ts'
import { decodeContent, openSealed } from '../src/seal.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError, outcome } from './support/assert.ts'
import { opener, P, recipient, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'
import { casesOf, readVectors } from './support/vectors.ts'

// spec/SPEC.md §2.5 (changed 2026-10-25): a number is read only when written as a plain decimal integer,
// `0` or `[1-9][0-9]*`, of at most 2^53 - 1. Every other spelling is refused where the reader reads it, with that
// place's code; `01` is not JSON and `1e400` is past a double's range, both bad-json. The sealed body is exempt.

/** Spellings that are JSON numbers but no plain decimal integer of at most 2^53 - 1. */
const NOT_PLAIN = ['1.0', '1e0', '1E0', '-0', '-1', '0.5', '1e-400', '9007199254740990.9', '9007199254740992']
/** Spellings every reader calls bad-json. */
const NOT_JSON = ['01', '1e400', '-1e400']
const PLAIN: readonly [string, number][] = [
  ['0', 0],
  ['1', 1],
  ['9007199254740991', 9_007_199_254_740_991],
]

/** The text with the first `"field":<digits>` given another spelling. */
function respell(text: string, field: string, spelling: string): string {
  const re = new RegExp(`"${field}":[0-9]+`)
  expect(re.test(text), field).toBe(true)
  return text.replace(re, `"${field}":${spelling}`)
}

describe('parseJson: the integer rule of §2.5', () => {
  it('keeps 0, 1 and 2^53 - 1, wherever they stand', () => {
    for (const [text, n] of PLAIN) {
      expect(parseJson(text)).toBe(n)
      expect(parseJson(`{"a":[${text},{"b":${text}}]}`)).toEqual({ a: [n, { b: n }] })
    }
  })

  it('reads every other number as NaN, which no reader takes for an integer', () => {
    for (const text of NOT_PLAIN) {
      expect(parseJson(text), text).toBeNaN()
      expect((parseJson(`{"a":[${text}]}`) as { a: number[] }).a[0], text).toBeNaN()
    }
    expect(parseJson('["1.0","-0"]')).toEqual(['1.0', '-0'])
  })

  it('calls 01 and a number past the range of a double bad-json, or the code it is given', () => {
    for (const text of NOT_JSON) {
      expectAcError(() => parseJson(text), 'bad-json')
      expectAcError(() => parseJson(utf8(`[${text}]`), 'bad-content'), 'bad-content')
    }
  })

  it('reads finite numbers as JSON.parse does when strict integers are off', () => {
    expect(
      parseJson('[1.0,1e0,-0,1.5,9007199254740990.9,1e-400,1e308,1e+16,9007199254740993]', 'bad-json', {
        strictIntegers: false,
      }),
    ).toEqual([1, 1, -0, 1.5, 9_007_199_254_740_991, 0, 1e308, 1e16, 9_007_199_254_740_992])
    expect(parseJson('1.7976931348623157e308', 'bad-json', { strictIntegers: false })).toBe(Number.MAX_VALUE)
    expectAcError(() => parseJson('01', 'bad-json', { strictIntegers: false }), 'bad-json')
  })
})

// Changed 2026-10-25: the sealed body is exempt from the integer rule only (§4.2), so a number past the
// range of a double, which JSON.parse reads as Infinity, is refused there with the caller's code, as everywhere (§2.5).
describe('parseJson: a number past the range of a double, with strict integers off', () => {
  const past = [
    '1e400',
    '-1e400',
    '1E400',
    '1.7976931348623159e308',
    `1${'0'.repeat(400)}`,
    `-1${'0'.repeat(400)}`,
  ]
  it.each(past)('refuses %s with the code it is given, alone and nested', (n) => {
    expectAcError(() => parseJson(n, 'bad-json', { strictIntegers: false }), 'bad-json')
    expectAcError(
      () => parseJson(utf8(`{"x":[1.5,{"y":${n}}]}`), 'bad-content', { strictIntegers: false }),
      'bad-content',
    )
    expectAcError(() => parseJson(`[${n}]`), 'bad-json')
  })

  it('refuses it in the sealed body as bad-content and carries a finite one', () => {
    const thread = JSON.stringify(newThread(xorshiftRng(18)))
    const content = (body: string): Uint8Array => utf8(`{"type":"t","thread":${thread},"body":${body}}`)
    for (const n of past) {
      expectAcError(() => decodeContent(content(n)), 'bad-content')
      expectAcError(() => decodeContent(content(`{"a":[0,${n}]}`)), 'bad-content')
    }
    for (const [n, v] of [
      ['1e-400', 0],
      ['1e308', 1e308],
      ['1.5', 1.5],
      ['-0', -0],
    ] as const) {
      expect(decodeContent(content(n)).body).toBe(v)
    }
  })
})

const envelopeText = (
  casesOf<{ expected: { bytes: string } }>(readVectors('envelope.json'))[1] as {
    expected: { bytes: string }
  }
).expected.bytes

describe('the envelope reader', () => {
  const want: Record<string, string> = {
    v: 'bad-version',
    suite: 'bad-suite',
    ts: 'bad-shape',
    exp: 'bad-hop',
  }
  it.each(Object.keys(want))(
    'refuses every non-plain spelling of %s with its code, and bad-json for the others',
    (field) => {
      for (const s of NOT_PLAIN)
        expect(
          outcome(() => parseEnvelope(respell(envelopeText, field, s))),
          s,
        ).toBe(want[field])
      for (const s of NOT_JSON)
        expect(
          outcome(() => parseEnvelope(respell(envelopeText, field, s))),
          s,
        ).toBe('bad-json')
    },
  )

  it('takes ts and a hop exp of 0, 1 and 2^53 - 1', () => {
    for (const field of ['ts', 'exp']) {
      for (const [s] of PLAIN)
        expect(outcome(() => parseEnvelope(respell(envelopeText, field, s)))).toBe('ok')
    }
  })
})

describe('the record reader', () => {
  const records = casesOf<{ record: Record<string, unknown> }>(readVectors('records.json'))
  const of = (kind: string): string =>
    JSON.stringify((records.find((c) => c.record.kind === kind) as { record: unknown }).record)
  const fields: readonly [string, string][] = [
    ['address', 'iat'],
    ['address', 'ttl'],
    ['accept-from', 'max_bytes'],
    ['accept-from', 'ttl'],
    ['accept-from', 'iat'],
    ['key', 'iat'],
    ['key', 'exp'],
  ]
  it.each(fields)(
    'refuses every non-plain spelling in a %s record, member %s, with bad-record',
    (kind, field) => {
      for (const s of NOT_PLAIN)
        expect(
          outcome(() => parseRecord(respell(of(kind), field, s))),
          s,
        ).toBe('bad-record')
      for (const s of NOT_JSON)
        expect(
          outcome(() => parseRecord(respell(of(kind), field, s))),
          s,
        ).toBe('bad-json')
    },
  )

  it('takes an iat of 0 and 2^53 - 1, and a key record exp of at most iat + 86,400', () => {
    expect(outcome(() => parseRecord(respell(of('address'), 'iat', '0')))).toBe('ok')
    expect(outcome(() => parseRecord(respell(of('accept-from'), 'iat', '9007199254740991')))).toBe('ok')
    expect(outcome(() => parseRecord(respell(of('key'), 'exp', String(T0 + 86_400))))).toBe('ok')
    // Changed 2026-10-25: a key record lives a day at most, so 2^53 - 1 is now bad-record.
    expect(outcome(() => parseRecord(respell(of('key'), 'exp', '9007199254740991')))).toBe('bad-record')
  })
})

describe('the sealed content: the body is exempt, the thread is not', () => {
  const thread = newThread(xorshiftRng(7))
  const content = (body: string, t = JSON.stringify(thread)): Uint8Array =>
    utf8(`{"type":"t","thread":${t},"body":${body}}`)

  it('opens and decodes a body of {"x": 1.5} and of [1e0]', () => {
    const { envelope } = buildEnvelope({
      from: P.jane.key,
      to: [recipient(P.bob)],
      type: 'note.v1',
      thread,
      body: { x: 1.5 },
      ts: T0,
      rng: xorshiftRng(8),
    })
    expect(openSealed(envelope, opener(P.bob)).body).toEqual({ x: 1.5 })
    expect(decodeContent(content('[1e0]')).body).toEqual([1])
    expect(decodeContent(content('{"x":1.5,"y":-0,"z":9007199254740990.9}')).body).toEqual({
      x: 1.5,
      y: -0,
      z: 9_007_199_254_740_991,
    })
  })

  it('refuses a number in the thread (bad-thread) or as the type (bad-content)', () => {
    for (const s of [...NOT_PLAIN, ...PLAIN.map(([t]) => t)]) {
      expectAcError(() => decodeContent(content('null', `{"id":${s},"prev":[]}`)), 'bad-thread')
      expectAcError(() => decodeContent(content('null', `{"id":"${thread.id}","prev":[${s}]}`)), 'bad-thread')
      expectAcError(
        () => decodeContent(utf8(`{"type":${s},"thread":${JSON.stringify(thread)},"body":1}`)),
        'bad-content',
      )
    }
    expectAcError(() => decodeContent(content('01')), 'bad-content')
  })
})

// spec/SPEC.md §2.5 (changed 2026-10-25): every reader refuses an object that names a member twice, in
// every peer text, the sealed content included, with the code of the place that reads it.
describe('parseJson: a member name given twice', () => {
  const twice = [
    '{"a":1,"a":2}',
    '{"a":1,"\\u0061":2}',
    '{"\\u00e9":1,"\u00e9":2}',
    '{"\\ud83d\\ude00":1,"\u{1f600}":2}',
    '{"a\\"":1,"a\\"":2}',
    '{"a\\\\":1,"a\\\\":2}',
    '{"x":{"a":1,"b":2,"a":3}}',
    '[1,{"a":1,"a":1}]',
    '{"a":[1,{"b":2}],"a":2}',
    '{"a":{},"b":[],"a":null}',
    '{"":1,"":2}',
  ]
  it.each(twice)('refuses %s with the code it is given', (text) => {
    expect(hasDuplicateMember(text)).toBe(true)
    expectAcError(() => parseJson(text), 'bad-json')
    expectAcError(() => parseJson(utf8(text), 'bad-content', { strictIntegers: false }), 'bad-content')
  })

  const once = [
    '{"a":1,"b":2}',
    '[{"a":1},{"a":1}]',
    '{"a":{"a":{"a":1}}}',
    '{"a":"a","b":"a"}',
    '{"a":["a","a",{"a":"a"}],"b":{"a":1}}',
    '{"x":"{\\"a\\":1,\\"a\\":2}","y":"[,]"}',
    '{"a\\\\":1,"a":2}',
    '{"\\u0061b":1,"a":2}',
    '{}',
    '[]',
    '"a"',
    '7',
    '[[],{},[{}]]',
  ]
  it.each(once)('takes %s', (text) => {
    expect(hasDuplicateMember(text)).toBe(false)
    expect(parseJson(text)).toEqual(JSON.parse(text))
  })

  it('reads numbers and surrogates as the strict reviver and the full walk do, by one scan of the text', () => {
    // The parser runs the reviver only when a number is not a plain safe integer, and walks the value for lone surrogates
    // only when the text has a surrogate escape; each reading must equal the slow one.
    expect(parseJson('{"a":[0,1,9007199254740991],"b":"x"}')).toEqual({
      a: [0, 1, 9_007_199_254_740_991],
      b: 'x',
    })
    expect(parseJson('[9007199254740991,9007199254740992,1.5,-1]')).toEqual([
      9_007_199_254_740_991,
      Number.NaN,
      Number.NaN,
      Number.NaN,
    ])
    expectAcError(() => parseJson('[1e400]', 'bad-json', { strictIntegers: false }), 'bad-json')
    expect(parseJson('[1.5,7]', 'bad-json', { strictIntegers: false })).toEqual([1.5, 7])
    expectAcError(() => parseJson('[1,1e400]'), 'bad-json')
    expect(parseJson('["\\ud83d\\ude00","\\\\ud800"]')).toEqual(['\u{1f600}', '\\ud800'])
    expectAcError(() => parseJson('["\\ud800"]'), 'bad-json')
    expectAcError(() => parseJson('["a\ud800"]', 'bad-content'), 'bad-content')
    expectAcError(() => parseJson('{"\\udc00":1}'), 'bad-json')
  })

  it('refuses a duplicate in an envelope, a record and the sealed content, the body included', () => {
    const doubled = envelopeText.replace('"ts":', '"ts":1,"ts":')
    expect(outcome(() => parseEnvelope(doubled))).toBe('bad-json')
    const record = (casesOf<{ record: unknown }>(readVectors('records.json'))[0] as { record: unknown })
      .record
    expect(outcome(() => parseRecord(JSON.stringify(record).replace('"ttl":', '"ttl":1,"ttl":')))).toBe(
      'bad-json',
    )
    const thread = JSON.stringify(newThread(xorshiftRng(9)))
    for (const text of [
      `{"type":"","type":"t","thread":${thread},"body":null}`,
      `{"type":"t","thread":${thread},"body":{"repo":"a","repo":"b"}}`,
      `{"type":"t","thread":{"id":"00","id":"11","prev":[]},"body":1}`,
    ]) {
      expectAcError(() => decodeContent(utf8(text)), 'bad-content')
    }
  })
})
