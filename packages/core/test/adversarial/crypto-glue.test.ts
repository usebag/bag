import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  DEGENERATE_SIG,
  NON_CANONICAL,
  type OpenInput,
  openVerdict,
  plusL,
  SMALL_ORDER,
  X25519_SMALL_ORDER,
} from '../../scripts/gen-adversarial.ts'
import { canonical } from '../../src/canonical.ts'
import { buildEnvelope } from '../../src/envelope.ts'
import { preimageDigest } from '../../src/hash.ts'
import { fromHex, toHex } from '../../src/hex.ts'
import { verifyPreimage, verifySig } from '../../src/keys.ts'
import { auditPreimage, fetchAuthPreimage, subscribePreimage } from '../../src/proofs.ts'
import { recordPreimage } from '../../src/records.ts'
import { openSealed } from '../../src/seal.ts'
import { newThread } from '../../src/thread.ts'
import { outcome } from '../support/assert.ts'
import { recordingRng, replayRng, xorshiftRng } from '../support/rng.ts'
import { DAY, item, label, lineCases, opener, recipient, send, T0, world } from './support.ts'

// Adversarial lines P4 (HPKE binding), P5 (freshness), P6 (domain separation) and F7 against verifySig and
// verifyPreimage directly.

describe('P4: HPKE binding', () => {
  const p4 = lineCases('open-cases.json', 'P4')
  const want = (l: string): string =>
    l.startsWith('genuine')
      ? 'ok'
      : l.startsWith('outsider')
        ? 'not-recipient'
        : l === 'content-bad-thread'
          ? 'bad-thread'
          : l.startsWith('content-')
            ? 'bad-content'
            : 'open-failed'
  it.each(p4)('$name', (c) => {
    expect(openVerdict(c.input as unknown as OpenInput)).toBe(want(label(c)))
  })
  it('covers (a) to (e) and all eight small-order enc values', () => {
    for (const p of ['a-', 'b-', 'c-', 'd-', 'e-']) expect(p4.some((c) => label(c).startsWith(p))).toBe(true)
    expect(p4.filter((c) => label(c).startsWith('c-enc-small-order')).length).toBe(X25519_SMALL_ORDER.length)
  })
  it('F2: the sealed part under the attacker as from does not open', () => {
    for (const c of lineCases('open-cases.json', 'F2')) {
      expect(openVerdict(c.input as unknown as OpenInput)).toBe('open-failed')
    }
  })
  // D6, flipped on 2026-10-25: a sealed content with two type members is
  // bad-content whichever comes last; until then the last value won, and two-type-valid-last opened ok.
  it('D6: a sealed content with two type members is bad-content', () => {
    const [last, first] = lineCases('open-cases.json', 'D6')
    expect(openVerdict(last?.input as unknown as OpenInput)).toBe('bad-content')
    expect(openVerdict(first?.input as unknown as OpenInput)).toBe('bad-content')
  })
})

describe('P5: freshness (the one test that reads real randomness: node:crypto randomBytes)', () => {
  it('1,000 seals draw 1,000 distinct content keys, nonces and enc values', () => {
    const w = world(551)
    const from = item(w.signers, 0)
    const to = [recipient(item(w.parties, 0))]
    const keys = new Set<string>()
    const nonces = new Set<string>()
    const encs = new Set<string>()
    for (let i = 0; i < 1000; i++) {
      const rec = recordingRng((n) => new Uint8Array(randomBytes(n)))
      const { envelope } = buildEnvelope({
        from,
        to,
        type: 't',
        thread: newThread(xorshiftRng(i + 1)),
        body: null,
        ts: T0,
        rng: rec.rng,
      })
      keys.add(toHex(item(rec.drawn, 0)))
      nonces.add(envelope.sealed.nonce)
      encs.add(item(envelope.sealed.wraps, 0).enc)
    }
    expect([keys.size, nonces.size, encs.size]).toEqual([1000, 1000, 1000])
  })

  it('the same rng bytes replayed give the same envelope: the core trusts its rng (seed 552)', () => {
    const w = world(552)
    const rec = recordingRng(xorshiftRng(552))
    const input = {
      from: item(w.signers, 0),
      to: [recipient(item(w.parties, 0))],
      type: 't',
      thread: newThread(xorshiftRng(1)),
      body: null,
      ts: T0,
    }
    const a = buildEnvelope({ ...input, rng: rec.rng })
    const b = buildEnvelope({ ...input, rng: replayRng(rec.drawn) })
    expect(toHex(b.bytes)).toBe(toHex(a.bytes))
  })
})

describe('P6: every preimage kind has a distinct prefix', () => {
  it('envelope [1,; hop, address, accept-from, key, subscribe, fetch by tag; the audit line a bare integer', () => {
    const w = world(556)
    const s = send(w, 1, 1)
    const a = w.signers[0]?.address as string
    const id = s.envelope.id
    const prefixes = [
      canonical([1, s.envelope.to, s.envelope.from]).slice(0, 3),
      canonical(['ac/hop/1', a, a, [], T0]).slice(0, 11),
      canonical(
        recordPreimage({
          kind: 'address',
          key: a,
          sealing_key: null,
          relays: [],
          rotation_key: null,
          revoked: [],
          ttl: DAY,
          iat: T0,
          rotated_from: null,
        }),
      ).slice(0, 12),
      canonical(
        recordPreimage({ kind: 'accept-from', owner: a, roots: ['*'], max_bytes: 1, ttl: 1, iat: T0 }),
      ).slice(0, 14),
      canonical(
        recordPreimage({ kind: 'key', key: a, sealing_key: '00'.repeat(32), iat: T0, exp: T0 }),
      ).slice(0, 11),
      canonical(subscribePreimage('00'.repeat(32), a, a, null)).slice(0, 11),
      canonical(fetchAuthPreimage(a, id, T0, 'https://relay.acme.example')).slice(0, 13),
    ]
    expect(prefixes).toEqual([
      '[1,',
      '["ac/hop/1"',
      '["ac/addr/1"',
      '["ac/accept/1"',
      '["ac/key/1"',
      '["ac/sub/1"',
      '["ac/fetch/1"',
    ])
    const audit = canonical(
      auditPreimage({
        seq: 1,
        prev: '00'.repeat(32),
        ts: T0,
        event: 'receive',
        decision: 'accept',
        reason: 'ok',
        id,
        from: a,
        root: a,
        detail: null,
      }),
    )
    expect(audit).toMatch(/^\[1,"[0-9a-f]{64}",/)
  })
})

describe('F7 at the primitive: verifySig and verifyPreimage', () => {
  const message = fromHex('11'.repeat(32), 32)
  it('S + L is refused, the genuine signature accepted (seed 557)', () => {
    const w = world(557)
    const k = item(w.signers, 0)
    const sig = toHex(k.sign(message))
    expect(verifySig(k.publicKey, message, fromHex(sig))).toBe(true)
    expect(verifySig(k.publicKey, message, fromHex(plusL(sig)))).toBe(false)
  })
  it.each(SMALL_ORDER.map(([name, pub]) => ({ name, pub })))(
    'verifySig refuses R = identity, S = 0 under the small-order key $name',
    ({ pub }) => {
      const accepted = [0, 1, 2, 3, 4, 5, 6, 7].some((i) =>
        verifySig(fromHex(pub), fromHex(i.toString(16).padStart(2, '0').repeat(32)), fromHex(DEGENERATE_SIG)),
      )
      expect(accepted).toBe(false)
    },
  )
  it.each(NON_CANONICAL.map(([name, pub]) => ({ name, pub })))(
    'verifySig refuses R = identity, S = 0 under the non-canonical encoding $name',
    ({ pub }) => {
      expect(verifySig(fromHex(pub), message, fromHex(DEGENERATE_SIG))).toBe(false)
    },
  )
  it('verifyPreimage refuses the identity as a signer of any preimage', () => {
    const identity = `ed25519:${item(SMALL_ORDER, 0)[1]}`
    const preimage = ['ac/hop/1', identity, identity, [], T0]
    expect(preimageDigest(preimage).length).toBe(32)
    expect(verifyPreimage(identity, preimage, DEGENERATE_SIG)).toBe(false)
  })
  it('the genuine open still works next to the degenerate cases (seed 558)', () => {
    const w = world(558)
    const s = send(w, 1, 0)
    expect(outcome(() => openSealed(s.envelope, opener(item(s.to, 0))))).toBe('ok')
  })
})
