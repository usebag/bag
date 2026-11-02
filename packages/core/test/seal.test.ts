import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import { fromHex, toHex, utf8 } from '../src/hex.ts'
import { aeadSeal, hpkeSeal } from '../src/hpke.ts'
import {
  checkRecipients,
  checkSealed,
  contentAad,
  decodeContent,
  encodeContent,
  MAX_RECIPIENTS,
  openSealed,
  SEAL_INFO,
  type Sealed,
  type SealedContent,
  sealedHash,
  sealedHashPreimage,
  sealTo,
} from '../src/seal.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { opener, P, recipient, SIXTEEN } from './support/fixtures.ts'
import { replayRng, xorshiftRng } from './support/rng.ts'

const content: SealedContent = {
  type: 'coding.task.v1',
  thread: newThread(xorshiftRng(1)),
  body: { repo: 'acme/api', note: 'naïve ✓' },
}
const from = P.jane.address

function sealed(
  to = [P.bob, P.carol],
  seed = 5,
): { readonly to: readonly string[]; readonly from: string; readonly sealed: Sealed } {
  return {
    to: to.map((p) => p.address),
    from,
    sealed: sealTo(to.map(recipient), from, content, xorshiftRng(seed)),
  }
}

/** A sealed part whose content ciphertext holds `plaintext`, under a content key every listed recipient can open. */
function sealedWith(plaintext: Uint8Array, contentKey = new Uint8Array(32).fill(7)) {
  const nonce = new Uint8Array(12)
  const to = [P.bob.address]
  const { enc, ct } = hpkeSeal(recipient(P.bob).sealingKey, utf8(SEAL_INFO), utf8(P.bob.address), contentKey)
  const s: Sealed = {
    wraps: [{ to: P.bob.address, enc: toHex(enc), ct: toHex(ct) }],
    nonce: toHex(nonce),
    ct: toHex(
      aeadSeal(
        contentKey.length === 32 ? contentKey : new Uint8Array(32),
        nonce,
        contentAad(to, from),
        plaintext,
      ),
    ),
  }
  return { to, from, sealed: s }
}

describe('sealing', () => {
  it('every recipient opens the same content', () => {
    const e = sealed()
    expect(openSealed(e, opener(P.bob))).toEqual(content)
    expect(openSealed(e, opener(P.carol))).toEqual(content)
    expect(e.sealed.wraps.map((w) => w.to)).toEqual(e.to)
    expect(e.sealed.wraps.every((w) => w.ct.length === 96 && w.enc.length === 64)).toBe(true)
    expect(e.sealed.nonce).toHaveLength(24)
  })

  it('draws the content key, the nonce, then one ephemeral key per recipient', () => {
    const draws = [
      new Uint8Array(32).fill(1),
      new Uint8Array(12).fill(2),
      new Uint8Array(32).fill(3),
      new Uint8Array(32).fill(4),
    ]
    const s = sealTo([recipient(P.bob), recipient(P.carol)], from, content, replayRng(draws))
    expect(s.nonce).toBe('02'.repeat(12))
    const again = sealTo([recipient(P.bob), recipient(P.carol)], from, content, replayRng(draws))
    expect(again).toEqual(s)
  })

  it('seals to up to 16 recipients', () => {
    const e = sealed([...SIXTEEN], 6)
    expect(e.sealed.wraps).toHaveLength(MAX_RECIPIENTS)
    expect(openSealed(e, opener(SIXTEEN[15] as (typeof SIXTEEN)[number]))).toEqual(content)
  })

  it('refuses bad recipients, a bad sender, a bad sealing key and a short rng', () => {
    expectAcError(() => sealTo([], from, content, xorshiftRng(1)), 'bad-shape')
    expectAcError(
      () => sealTo([recipient(P.bob), recipient(P.bob)], from, content, xorshiftRng(1)),
      'bad-shape',
    )
    expectAcError(
      () => sealTo([{ address: 'bob', sealingKey: new Uint8Array(32) }], from, content, xorshiftRng(1)),
      'bad-address',
    )
    expectAcError(() => sealTo([recipient(P.bob)], 'jane', content, xorshiftRng(1)), 'bad-address')
    expectAcError(
      () =>
        sealTo([{ address: P.bob.address, sealingKey: new Uint8Array(31) }], from, content, xorshiftRng(1)),
      'bad-key',
    )
    expectAcError(() => sealTo([recipient(P.bob)], from, content, () => new Uint8Array(1)), 'bad-key')
    const seventeen = [...SIXTEEN, P.bob].map(recipient)
    expectAcError(() => sealTo(seventeen, from, content, xorshiftRng(1)), 'too-many-recipients')
  })

  it('binds the content to [v, to, from]: another to or from does not open', () => {
    const e = sealed()
    expectAcError(() => openSealed({ ...e, from: P.carol.address }, opener(P.bob)), 'open-failed')
    expectAcError(() => openSealed({ ...e, to: [P.bob.address] }, opener(P.bob)), 'open-failed')
    expect(new TextDecoder().decode(contentAad(e.to, from))).toBe(canonical([1, e.to, from]))
  })

  it('binds each wrap to its recipient address: a wrap moved to another recipient does not open', () => {
    const e = sealed()
    const [bobWrap] = e.sealed.wraps
    if (bobWrap === undefined) throw new Error('no wrap')
    const moved = { ...e, sealed: { ...e.sealed, wraps: [{ ...bobWrap, to: P.carol.address }] } }
    expectAcError(() => openSealed(moved, opener(P.carol)), 'open-failed')
  })

  it('is not-recipient for an address with no wrap', () => {
    expectAcError(() => openSealed(sealed(), opener(P.dave)), 'not-recipient')
  })

  it('is open-failed for a tampered wrap or content, or malformed hex', () => {
    const e = sealed()
    const flip = (hex: string): string => `${hex.slice(0, -2)}${hex.endsWith('00') ? '01' : '00'}`
    const wraps = e.sealed.wraps.map((w) => ({ ...w, ct: flip(w.ct) }))
    expectAcError(() => openSealed({ ...e, sealed: { ...e.sealed, wraps } }, opener(P.bob)), 'open-failed')
    expectAcError(
      () => openSealed({ ...e, sealed: { ...e.sealed, ct: flip(e.sealed.ct) } }, opener(P.bob)),
      'open-failed',
    )
    expectAcError(
      () => openSealed({ ...e, sealed: { ...e.sealed, nonce: 'zz' } }, opener(P.bob)),
      'open-failed',
    )
  })

  it('is open-failed when the wrapped key is not 32 bytes', () => {
    const e = sealedWith(utf8('{}'), new Uint8Array(31))
    expectAcError(() => openSealed(e, opener(P.bob)), 'open-failed')
  })

  it.each([
    ['not JSON', 'nope', 'bad-content'],
    ['a list', '[]', 'bad-content'],
    ['a missing body', '{"type":"t","thread":{"id":"00","prev":[]}}', 'bad-content'],
    ['an empty type', `{"type":"","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`, 'bad-content'],
    ['a malformed thread', '{"type":"t","thread":{"id":"00","prev":[]},"body":1}', 'bad-thread'],
    [
      'a lone surrogate',
      `{"type":"\\ud800","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
    // The control-character rule (SPEC §5.2): the escape is six characters in the JSON, so each type parses to one
    // forbidden character. A C1, DEL and the separators are legal raw JSON, so the rule is what refuses them.
    [
      'an escaped C0 control in the type',
      `{"type":"a\\u0001b","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
    [
      'a C1 control in the type',
      `{"type":"a\\u009bb","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
    [
      'DEL in the type',
      `{"type":"a\\u007fb","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
    [
      'a line separator in the type',
      `{"type":"a\\u2028b","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
    [
      'a paragraph separator in the type',
      `{"type":"a\\u2029b","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":1}`,
      'bad-content',
    ],
  ] as const)('a plaintext that is %s is %s', (_, plaintext, code) => {
    expectAcError(() => openSealed(sealedWith(utf8(plaintext)), opener(P.bob)), code)
  })

  it('opens a well-formed plaintext built by hand', () => {
    const plaintext = `{"type":"t","thread":{"id":"${'00'.repeat(32)}","prev":[]},"body":null}`
    expect(openSealed(sealedWith(utf8(plaintext)), opener(P.bob))).toEqual({
      type: 't',
      thread: { id: '00'.repeat(32), prev: [] },
      body: null,
    })
  })
})

describe('the content', () => {
  it('is JSON.stringify({type, thread, body}) and decodes back', () => {
    const bytes = encodeContent(content)
    expect(new TextDecoder().decode(bytes)).toBe(
      JSON.stringify({ type: content.type, thread: content.thread, body: content.body }),
    )
    expect(decodeContent(bytes)).toEqual(content)
  })

  it.each([
    ['an empty type', { ...content, type: '' }],
    ['a type that is not a string', { ...content, type: 7 }],
    ['a C0 control in the type', { ...content, type: 'a\u0001b' }],
    ['a C1 control in the type', { ...content, type: 'a\u009bb' }],
    ['DEL in the type', { ...content, type: 'a\u007fb' }],
    ['a line separator in the type', { ...content, type: 'a\u2028b' }],
    ['a paragraph separator in the type', { ...content, type: 'a\u2029b' }],
    ['no body', { ...content, body: undefined }],
    ['a function body', { ...content, body: () => 1 }],
    ['a symbol body', { ...content, body: Symbol('x') }],
    ['a bigint body', { ...content, body: { n: 1n } }],
  ])('refuses %s', (_, value) => {
    expectAcError(() => encodeContent(value as SealedContent), 'bad-content')
  })

  it('refuses a malformed thread', () => {
    expectAcError(() => encodeContent({ ...content, thread: { id: 'x', prev: [] } }), 'bad-thread')
  })

  it.each([
    ['a MIME-like type', 'application/vnd.acme+json'],
    ['a non-breaking space (Zs, not a control char)', 'a\u00a0b'],
    ['a non-ASCII letter', 'héllo'],
  ])('accepts %s at encode and decode (the rule bans only Cc, U+2028 and U+2029)', (_, type) => {
    const round = decodeContent(encodeContent({ ...content, type }))
    expect(round.type).toBe(type)
  })
})

describe('the sealed hash', () => {
  it('is sha256 of canonical([wraps as [[to, enc, ct]...], nonce, ct]) and changes with any byte', () => {
    const e = sealed()
    expect(sealedHashPreimage(e.sealed)).toEqual([
      e.sealed.wraps.map((w) => [w.to, w.enc, w.ct]),
      e.sealed.nonce,
      e.sealed.ct,
    ])
    expect(sealedHash(e.sealed)).toMatch(/^[0-9a-f]{64}$/)
    expect(sealedHash({ ...e.sealed, nonce: '00'.repeat(12) })).not.toBe(sealedHash(e.sealed))
  })
})

describe('checkRecipients and checkSealed', () => {
  const e = sealed()
  const wire = JSON.parse(JSON.stringify(e.sealed)) as Record<string, unknown>

  it('accept a well-formed sealed part', () => {
    expect(checkSealed(wire, e.to)).toEqual(e.sealed)
    expect(checkRecipients(e.to)).toEqual(e.to)
  })

  it.each([
    ['a list', [], 'bad-shape'],
    ['a missing nonce', { wraps: wire.wraps, ct: wire.ct }, 'bad-shape'],
    ['wraps not a list', { ...wire, wraps: {} }, 'bad-shape'],
    ['one wrap short', { ...wire, wraps: (wire.wraps as unknown[]).slice(1) }, 'bad-shape'],
    ['a wrap that is a list', { ...wire, wraps: [[], (wire.wraps as unknown[])[1]] }, 'bad-shape'],
    ['wraps out of order', { ...wire, wraps: [...(wire.wraps as unknown[])].reverse() }, 'bad-shape'],
    [
      'an enc of 31 bytes',
      {
        ...wire,
        wraps: (wire.wraps as Record<string, unknown>[]).map((w) => ({ ...w, enc: '00'.repeat(31) })),
      },
      'bad-hex',
    ],
    [
      'an enc that is a number',
      { ...wire, wraps: (wire.wraps as Record<string, unknown>[]).map((w) => ({ ...w, enc: 1 })) },
      'bad-shape',
    ],
    ['a nonce in upper case', { ...wire, nonce: String(wire.nonce).toUpperCase() }, 'bad-hex'],
    ['a ct of 15 bytes', { ...wire, ct: '00'.repeat(15) }, 'bad-hex'],
    ['a ct that is not hex', { ...wire, ct: 'zz' }, 'bad-hex'],
  ] as const)('reject %s (%s)', (_, value, code) => {
    expectAcError(() => checkSealed(value, e.to), code)
  })

  it('accept a ct that is exactly the tag', () => {
    expect(checkSealed({ ...wire, ct: '00'.repeat(16) }, e.to).ct).toBe('00'.repeat(16))
  })

  it('reject recipients that are not a list, not strings, not addresses, repeated or too many', () => {
    expectAcError(() => checkRecipients('x'), 'bad-shape')
    expectAcError(() => checkRecipients([1]), 'bad-shape')
    expectAcError(() => checkRecipients(['bob']), 'bad-address')
    expectAcError(() => checkRecipients([from, from]), 'bad-shape')
    expectAcError(() => checkRecipients([...SIXTEEN, P.bob].map((p) => p.address)), 'too-many-recipients')
  })

  it('fromHex of a wrap reads the encapsulated key', () => {
    expect(fromHex(e.sealed.wraps[0]?.enc ?? '', 32)).toHaveLength(32)
  })
})
