import {
  type CaveatEvaluator,
  codingEvaluator,
  hopPreimage,
  isAcError,
  preimageDigest,
  type SealedContent,
  toHex,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  checkGrant,
  decideRead,
  deriveHop,
  grantLimit,
  grantLines,
  hasCaveatPrefix,
  hopDigest,
  WINDOW_MAX,
} from '../../src/agent/index.ts'
import { P, T0 } from '../support/fixtures.ts'

// The pure rules of the agent: the derived hop by exact prefix and its fixed check order, the first
// grant's checks, the read rule and the grant's printed lines.

const J = P.jane.address
const B = P.bob.address
const EFFECTIVE = ['type=coding.*', 'repo=r']

function code(f: () => unknown): string {
  try {
    f()
  } catch (e) {
    return isAcError(e) ? e.code : String((e as { code?: unknown }).code)
  }
  return 'no error'
}

describe('hopDigest and the exact prefix', () => {
  it('digests the hop preimage', () => {
    const h = { iss: J, sub: B, caveats: ['a'], exp: T0 }
    expect(hopDigest(h)).toBe(toHex(preimageDigest(hopPreimage(h))))
  })

  it('takes equal or appended caveats and nothing else, string for string', () => {
    expect(hasCaveatPrefix(EFFECTIVE, EFFECTIVE)).toBe(true)
    expect(hasCaveatPrefix([...EFFECTIVE, 'type=coding.task.v1'], EFFECTIVE)).toBe(true)
    expect(hasCaveatPrefix(['x'], [])).toBe(true)
    expect(hasCaveatPrefix([], [])).toBe(false)
    expect(hasCaveatPrefix(['repo=r', 'type=coding.*'], EFFECTIVE)).toBe(false)
    expect(hasCaveatPrefix(['type=coding.*'], EFFECTIVE)).toBe(false)
    // never semantic: a narrower type is not a prefix of a wider one
    expect(hasCaveatPrefix(['type=coding.task.v1', 'repo=r'], EFFECTIVE)).toBe(false)
    expect(hasCaveatPrefix(['type=coding.* ', 'repo=r'], EFFECTIVE)).toBe(false)
  })
})

describe('deriveHop', () => {
  const ok = { sub: B, caveats: [...EFFECTIVE, 'x=1'], exp: T0 + 60 }

  it('returns the unsigned hop under the principal', () => {
    expect(deriveHop(J, EFFECTIVE, ok, T0 + 60)).toEqual({ iss: J, ...ok })
  })

  it('checks the hop shape first, then the prefix, then exp, one code each', () => {
    const late = T0
    expect(code(() => deriveHop(J, EFFECTIVE, { ...ok, sub: 'x', caveats: [] }, late))).toBe('bad-hop')
    const many = Array.from({ length: 33 }, (_, i) => `c${i}`)
    expect(code(() => deriveHop(J, EFFECTIVE, { ...ok, caveats: many }, late))).toBe('too-many-caveats')
    const long = ['x'.repeat(257)]
    expect(code(() => deriveHop(J, EFFECTIVE, { ...ok, caveats: long }, late))).toBe('caveat-too-long')
    expect(code(() => deriveHop(J, EFFECTIVE, { ...ok, caveats: ['repo=r'] }, late))).toBe('not-in-grant')
    expect(code(() => deriveHop(J, EFFECTIVE, { ...ok, caveats: [] }, late))).toBe('not-in-grant')
    expect(code(() => deriveHop(J, EFFECTIVE, ok, late))).toBe('exp-not-monotone')
  })
})

describe('checkGrant', () => {
  const req = { session: P.session.address, caveats: ['type=coding.*'], exp: T0 + 60 }

  it('returns the first grant unsigned', () => {
    const hop = { iss: J, sub: req.session, caveats: req.caveats, exp: req.exp }
    expect(checkGrant(J, req, T0 + 60)).toEqual(hop)
  })

  it('refuses no caveat bad-shape, a bad hop with its shape code, and a late exp exp-not-monotone', () => {
    expect(code(() => checkGrant(J, { ...req, caveats: [] }, T0))).toBe('bad-shape')
    expect(code(() => checkGrant(J, { ...req, session: 'x' }, T0))).toBe('bad-hop')
    expect(code(() => checkGrant(J, req, T0 + 59))).toBe('exp-not-monotone')
  })

  it('bounds an exp by the window end and by now + 8 hours', () => {
    expect(grantLimit(T0, T0 + 60)).toBe(T0 + 60)
    expect(grantLimit(T0, T0 + WINDOW_MAX + 1)).toBe(T0 + WINDOW_MAX)
  })
})

describe('decideRead', () => {
  const thread = { id: 'aa'.repeat(32), prev: [] }
  const reply = { id: 'aa'.repeat(32), prev: ['bb'.repeat(32)] }
  const task: SealedContent = { type: 'coding.task.v1', thread, body: {} }
  const ctx = { from: B, to: [J], ts: T0, root: B }
  const none = new Set<string>()
  const evaluators: readonly CaveatEvaluator[] = [codingEvaluator]

  it('releases a registered thread, root or reply, before any caveat', () => {
    const registered = new Set([thread.id])
    const d = decideRead({ ...task, thread: reply }, registered, ['zzz'], evaluators, ctx)
    expect(d).toEqual({ release: true, rule: 'thread' })
  })

  it('withholds an unregistered reply, whatever its caveats', () => {
    const d = decideRead({ ...task, thread: reply }, none, ['type=coding.*'], evaluators, ctx)
    expect(d).toEqual({ release: false, rule: 'thread', reason: 'not-in-grant' })
  })

  it('releases a root message every caveat holds for, and withholds the rest with the precise reason', () => {
    const coding = ['type=coding.*']
    expect(decideRead(task, none, coding, evaluators, ctx)).toEqual({ release: true, rule: 'root' })
    const chat = { ...task, type: 'chat.v1' }
    expect(decideRead(chat, none, coding, evaluators, ctx)).toMatchObject({ reason: 'caveat-failed' })
    expect(decideRead(task, none, ['zzz=1'], evaluators, ctx)).toMatchObject({ reason: 'unknown-caveat' })
    expect(decideRead(task, none, ['type=coding.*'], [], ctx)).toMatchObject({ reason: 'unknown-caveat' })
    const empty = decideRead(task, none, [], evaluators, ctx)
    expect(empty).toEqual({ release: false, rule: 'root', reason: 'not-in-grant' })
  })
})

describe('grantLines', () => {
  it('prints the session, the caveats as JSON and the exp in Unix seconds and UTC', () => {
    const lines = grantLines({ iss: J, sub: B, caveats: ['type=coding.*', 'repo=r'], exp: T0 })
    expect(lines).toEqual([
      `grant to session ${B}`,
      'caveats "type=coding.*" "repo=r"',
      `until ${T0} (2027-01-15T08:00:00.000Z)`,
      'sign this grant? type y to sign',
    ])
  })

  // controls, separators, bidirectional controls, and the invisible format characters and tags
  const unsafe = [0x1b, 0x7f, 0x85, 0x9b, 0x2028, 0x2029, 0x202e, 0x2066, 0x200f, 0xad, 0x200b]
  unsafe.push(0x200c, 0x200d, 0x2060, 0x2064, 0xfeff, 0xe0000, 0xe0001, 0xe0041, 0xe007f)
  const units = (c: number) => String.fromCodePoint(c).split('')
  const caveatsOf = (caveat: string) => grantLines({ iss: J, sub: B, caveats: [caveat], exp: T0 })[1]

  it('escapes every control, separator, format and tag character a caveat holds, one \\u per UTF-16 unit', () => {
    const shown = caveatsOf(unsafe.map((c) => `a${String.fromCodePoint(c)}b`).join('|'))
    const hex = (u: string) => `\\u${u.charCodeAt(0).toString(16).padStart(4, '0')}`
    const expected = unsafe.map((c) => `a${units(c).map(hex).join('')}b`).join('|')
    expect(shown).toBe(`caveats "${expected}"`)
    expect([...(shown ?? '')].every((ch) => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) < 0x7f)).toBe(true)
  })

  it('prints two caveats differing by one invisible character differently', () => {
    const plain = caveatsOf('type=a')
    for (const c of unsafe) expect(caveatsOf(`type=a${String.fromCodePoint(c)}`)).not.toBe(plain)
  })
})
