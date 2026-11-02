import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import { signHop } from '../src/chain.ts'
import {
  buildEnvelope,
  checkEnvelope,
  checkId,
  checkSig,
  checkTs,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  ENVELOPE_VERSION,
  type Envelope,
  envelopeId,
  envelopeIdPreimage,
  MAX_ENVELOPE_BYTES,
  parseEnvelope,
  SUITE,
  serializeEnvelope,
  verifyOuter,
} from '../src/envelope.ts'
import { sha256hex } from '../src/hash.ts'
import { toHex } from '../src/hex.ts'
import { openSealed, sealedHash } from '../src/seal.ts'
import { newThread, replyThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, HOUR, opener, P, recipient, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

const thread = newThread(xorshiftRng(1))
const chain = [
  signHop(P.org.key, P.jane.address, ['type=coding.*'], T0 + 30 * DAY),
  signHop(P.jane.key, P.session.address, ['repo=acme/api'], T0 + 8 * HOUR),
]
const built = buildEnvelope({
  from: P.session.key,
  to: [recipient(P.bob), recipient(P.carol)],
  auth: chain,
  type: 'coding.task.v1',
  thread,
  body: { repo: 'acme/api' },
  ts: T0,
  rng: xorshiftRng(2),
})
const e = built.envelope
const text = new TextDecoder().decode(built.bytes)

describe('buildEnvelope', () => {
  it('builds v 1, suite 1, an id over the preimage and a sig over the id', () => {
    expect([e.v, e.suite]).toEqual([ENVELOPE_VERSION, SUITE])
    expect(envelopeIdPreimage(e)).toEqual([
      1,
      e.to,
      e.from,
      chain.map((h) => [h.iss, h.sub, h.caveats, h.exp, h.sig]),
      1,
      T0,
      sealedHash(e.sealed),
    ])
    expect(e.id).toBe(sha256hex(canonical(envelopeIdPreimage(e))))
    expect(e.id).toBe(envelopeId(e))
    expect(() => checkSig(e)).not.toThrow()
  })

  it('serializes the members in wire order, with no white space', () => {
    expect(Object.keys(JSON.parse(text))).toEqual([
      'v',
      'id',
      'to',
      'from',
      'auth',
      'suite',
      'ts',
      'sealed',
      'sig',
    ])
    expect(serializeEnvelope(e)).toEqual(built.bytes)
    expect(text).not.toMatch(/\s/)
  })

  it('round-trips through parseEnvelope, from bytes or from text', () => {
    expect(parseEnvelope(built.bytes)).toEqual(e)
    expect(parseEnvelope(text)).toEqual(e)
    expect(checkEnvelope(JSON.parse(text))).toEqual(e)
  })

  it('is opened by each recipient', () => {
    const content = { type: 'coding.task.v1', thread, body: { repo: 'acme/api' } }
    expect(openSealed(e, opener(P.bob))).toEqual(content)
    expect(openSealed(e, opener(P.carol))).toEqual(content)
  })

  it('defaults to the empty chain and carries a reply thread', () => {
    const reply = buildEnvelope({
      from: P.bob.key,
      to: [recipient(P.jane)],
      type: 'coding.result.v1',
      thread: replyThread(thread, [e.id]),
      body: 'ok',
      ts: T0 + 1,
      rng: xorshiftRng(3),
    }).envelope
    expect(reply.auth).toEqual([])
    expect(openSealed(reply, opener(P.jane)).thread.prev).toEqual([e.id])
  })

  it('builds an envelope whose chain is wrong: the receiver judges the chain', () => {
    const stale = buildEnvelope({ ...base(), auth: [chain[0] as (typeof chain)[0]], ts: T0 }).envelope
    expect(stale.auth).toHaveLength(1)
  })

  it('refuses what parseEnvelope would reject', () => {
    expectAcError(() => buildEnvelope({ ...base(), ts: -1 }), 'bad-shape')
    expectAcError(() => buildEnvelope({ ...base(), auth: Array(9).fill(chain[0]) }), 'too-many-hops')
    expectAcError(() => buildEnvelope({ ...base(), to: [] }), 'bad-shape')
    expectAcError(
      () => buildEnvelope({ ...base(), body: 'x'.repeat(MAX_ENVELOPE_BYTES) }),
      'envelope-too-large',
    )
  })

  it('refuses a signer whose signature is not 64 bytes of hex (bad-hex), from assembleEnvelope', () => {
    for (const length of [0, 10, 63, 65]) {
      const from = { address: P.session.address, sign: () => new Uint8Array(length) }
      expectAcError(() => buildEnvelope({ ...base(), from }), 'bad-hex')
    }
  })

  it('refuses a null or malformed input, signer or recipient list as bad-shape, not a TypeError', () => {
    expectAcError(() => buildEnvelope(null as never), 'bad-shape')
    expectAcError(() => buildEnvelope({ ...base(), from: null as never }), 'bad-shape')
    expectAcError(() => buildEnvelope({ ...base(), to: null as never }), 'bad-shape')
    expectAcError(() => buildEnvelope({ ...base(), to: [null] as never }), 'bad-shape')
    expectAcError(() => buildEnvelope({ ...base(), to: [1] as never }), 'bad-shape')
  })

  it('keeps the ts and chain codes ahead of a malformed signer or recipient list, as before the guards', () => {
    const badHop = { ...signHop(P.org.key, P.session.address, [], T0 + DAY), sig: 'zz' }
    const nine = Array.from({ length: 9 }, () => signHop(P.org.key, P.session.address, [], T0 + DAY))
    const build = (o: object) => () => buildEnvelope({ ...base(), ...o } as never)
    for (const bad of [{ to: [1] }, { from: null }, { to: null }]) {
      expectAcError(build({ ...bad, auth: [badHop] }), 'bad-hop')
      expectAcError(build({ ...bad, auth: nine }), 'too-many-hops')
      expectAcError(build({ ...bad, ts: -1 }), 'bad-shape')
    }
  })
})

function base() {
  return {
    from: P.session.key,
    to: [recipient(P.bob)],
    type: 'coding.task.v1',
    thread,
    body: {},
    ts: T0,
    rng: xorshiftRng(4),
  }
}

describe('parseEnvelope', () => {
  it('measures the cap in UTF-8 bytes, for text and for bytes', () => {
    const padded = text + ' '.repeat(MAX_ENVELOPE_BYTES - built.bytes.length)
    expect(parseEnvelope(padded)).toEqual(e)
    expectAcError(() => parseEnvelope(`${padded} `), 'envelope-too-large')
    expectAcError(() => parseEnvelope(new Uint8Array(MAX_ENVELOPE_BYTES + 1)), 'envelope-too-large')
    const multibyte = `${text}${'é'.repeat((MAX_ENVELOPE_BYTES - built.bytes.length) / 2 + 1)}`
    expectAcError(() => parseEnvelope(multibyte), 'envelope-too-large')
  })

  it('rejects text that is not UTF-8 JSON', () => {
    expectAcError(() => parseEnvelope(Uint8Array.of(0x7b, 0xff, 0x7d)), 'bad-json')
    expectAcError(() => parseEnvelope('{"v":1,'), 'bad-json')
  })

  it('checks v and suite before the members', () => {
    expectAcError(() => parseEnvelope('{"v":2}'), 'bad-version')
    expectAcError(() => parseEnvelope('{"v":1,"suite":"1"}'), 'bad-shape')
    expectAcError(() => parseEnvelope('{"v":1,"suite":2}'), 'bad-suite')
    expectAcError(() => parseEnvelope('{"v":1,"suite":1}'), 'bad-shape')
  })

  it('rejects a sig that is not a string', () => {
    const value = JSON.parse(text) as Record<string, unknown>
    expectAcError(() => checkEnvelope({ ...value, sig: 1 }), 'bad-shape')
    expectAcError(() => checkEnvelope({ ...value, from: 1 }), 'bad-shape')
  })
})

describe('the outer checks', () => {
  it('pass in the window and fail outside it', () => {
    expect(() => verifyOuter(e, T0)).not.toThrow()
    expect(() => verifyOuter(e, T0 + DEFAULT_TTL + DEFAULT_SKEW)).not.toThrow()
    expectAcError(() => verifyOuter(e, T0 + DEFAULT_TTL + DEFAULT_SKEW + 1), 'stale-ts')
    expectAcError(() => verifyOuter(e, T0 - DEFAULT_SKEW - 1), 'future-ts')
  })

  it('take a window', () => {
    expect(() => checkTs(T0, T0 + 60, { ttl: 30, skew: 30 })).not.toThrow()
    expectAcError(() => checkTs(T0, T0 + 61, { ttl: 30, skew: 30 }), 'stale-ts')
    expectAcError(() => verifyOuter(e, T0 + 61, { ttl: 30, skew: 30 }), 'stale-ts')
  })

  it('catch every change after signing', () => {
    expectAcError(() => verifyOuter({ ...e, ts: T0 + 1 }, T0), 'bad-id')
    expectAcError(() => verifyOuter({ ...e, auth: [] }, T0), 'bad-id')
    expectAcError(() => verifyOuter({ ...e, to: [P.bob.address] }, T0), 'bad-id')
    expectAcError(() => checkId({ ...e, sealed: { ...e.sealed, nonce: '00'.repeat(12) } }), 'bad-id')
  })

  it('catch a signature by another key, over another id, or malformed', () => {
    const other = toHex(P.mallory.key.sign(Buffer.from(e.id, 'hex')))
    expectAcError(() => verifyOuter({ ...e, sig: other }, T0), 'bad-sig')
    const hand: Envelope = { ...e, id: 'x' }
    expectAcError(() => checkSig(hand), 'bad-sig')
    expectAcError(() => checkSig({ ...e, sig: 'x' }), 'bad-sig')
  })

  it('re-check the recipients of an envelope built by hand', () => {
    expectAcError(() => verifyOuter({ ...e, to: [] }, T0), 'bad-shape')
  })
})
