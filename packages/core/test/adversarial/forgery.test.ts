import { describe, expect, it } from 'vitest'
import {
  chainVerdict,
  type OpenInput,
  openVerdict,
  outerVerdict,
  plusL,
  recordVerdict,
} from '../../scripts/gen-adversarial.ts'
import { canonical } from '../../src/canonical.ts'
import { type Hop, hopPreimage, verifyChain } from '../../src/chain.ts'
import { type Envelope, envelopeId, parseEnvelope, serializeEnvelope } from '../../src/envelope.ts'
import { sha256hex } from '../../src/hash.ts'
import { fromHex, toHex, utf8 } from '../../src/hex.ts'
import type { SigningKey } from '../../src/keys.ts'
import { signPreimage } from '../../src/keys.ts'
import { openSealed } from '../../src/seal.ts'
import { outcome } from '../support/assert.ts'
import {
  type AdvCase,
  bytesOf,
  chain,
  DAY,
  item,
  label,
  lineCases,
  NOW,
  opener,
  send,
  T0,
  world,
} from './support.ts'

// Adversarial lines F1 to F9: every attack on the envelope and the chain meets the refusal the spec names. Each test
// starts from an input that verifies ok (V1) and asserts the mutation changed it. Seeds are written in each test.

const ENVELOPE_CODES = new Set([
  'bad-json',
  'bad-shape',
  'bad-hex',
  'bad-address',
  'bad-version',
  'bad-suite',
  'bad-id',
  'bad-sig',
  'too-many-recipients',
  'too-many-hops',
  'bad-hop',
  'too-many-caveats',
  'caveat-too-long',
  'chain-broken',
  'chain-not-to-sender',
  'exp-not-monotone',
  'hop-expired',
  'bad-hop-sig',
])

const clone = (e: Envelope): Record<string, unknown> =>
  JSON.parse(JSON.stringify(e)) as Record<string, unknown>
const hopsOf = (u: Record<string, unknown>): Record<string, unknown>[] => u.auth as Record<string, unknown>[]
const wrapsOf = (u: Record<string, unknown>): Record<string, unknown>[] =>
  (u.sealed as Record<string, unknown>).wraps as Record<string, unknown>[]

function resign(u: Record<string, unknown>, by: SigningKey): Uint8Array {
  const e = u as unknown as Envelope
  const id = envelopeId(e)
  return serializeEnvelope({ ...e, id, sig: toHex(by.sign(fromHex(id, 32))) })
}

// F1 is one test per (envelope shape, family of change), so none runs near vitest's 5 s default timeout
// under a loaded gate. The three envelopes come from ONE world(501), built in the original order: send()
// draws on the world's shared rng, so a fresh world per test would test different envelopes.
const F1_SHAPES = [
  [1, 0],
  [5, 3],
  [16, 8],
] as const

let f1Built: readonly Uint8Array[] | undefined
function f1Envelopes(): readonly Uint8Array[] {
  if (f1Built === undefined) {
    const w = world(501)
    f1Built = F1_SHAPES.map(([nTo, nHops]) => send(w, nTo, nHops).bytes)
  }
  return f1Built
}

const isHexDigit = (byte: number): boolean => nextHex(byte) !== undefined

const F1_FAMILIES = [
  {
    name: 'every byte flipped at bit (position mod 8)',
    change: (original: number, p: number): number | undefined => original ^ (1 << (p % 8)),
    count: (bytes: Uint8Array): number => bytes.length,
  },
  {
    name: 'every hex character substituted by the next digit',
    change: (original: number): number | undefined => nextHex(original),
    count: (bytes: Uint8Array): number => bytes.filter(isHexDigit).length,
  },
] as const

const F1_CASES = F1_SHAPES.flatMap(([nTo, nHops], shape) =>
  F1_FAMILIES.map((family) => ({
    label: `${family.name}, in an envelope of ${nTo} recipients and ${nHops} hops (seed 501)`,
    shape,
    family,
  })),
)

describe('F1: no single-byte change to an envelope verifies', () => {
  it.each(F1_CASES)('$label', ({ shape, family }) => {
    const bytes = item(f1Envelopes(), shape)
    expect(outerVerdict(bytes)).toBe('ok')
    const m = Uint8Array.from(bytes)
    const seen = new Map<string, number>()
    let tried = 0
    for (let p = 0; p < m.length; p++) {
      const original = m[p] as number
      const changed = family.change(original, p)
      if (changed === undefined) continue
      m[p] = changed
      expect(m[p]).not.toBe(original)
      const v = outerVerdict(m)
      seen.set(v, (seen.get(v) ?? 0) + 1)
      tried++
      m[p] = original
    }
    // The loop's count must equal the family's size, counted apart from the loop: none silently skipped.
    expect(tried).toBe(family.count(bytes))
    expect(seen.get('ok') ?? 0).toBe(0)
    expect([...seen.keys()].filter((k) => !ENVELOPE_CODES.has(k))).toEqual([])
  })

  it('every committed F1 case is refused with an envelope or chain code', () => {
    const all = lineCases('envelope-mutations.json', 'F1')
    const accepted = all.filter((c) => outerVerdict(bytesOf(c)) === 'ok').map((c) => c.name)
    expect(accepted).toEqual([])
    expect(all.filter((c) => !ENVELOPE_CODES.has(c.expected)).map((c) => c.name)).toEqual([])
  })
})

function nextHex(byte: number): number | undefined {
  const digits = '0123456789abcdef'
  const i = digits.indexOf(String.fromCharCode(byte))
  return i === -1 ? undefined : digits.charCodeAt((i + 1) % 16)
}

describe('F2: the sealed part re-signed by another key', () => {
  it('verifies at the core (no one can tell), and every recipient fails to open it (seed 502)', () => {
    const w = world(502)
    const s = send(w, 2, 2)
    expect(outerVerdict(s.bytes)).toBe('ok')
    const u = clone(s.envelope)
    u.from = w.attacker.address
    u.auth = []
    const forged = resign(u, w.attacker)
    expect(toHex(forged)).not.toBe(toHex(s.bytes))
    expect(outerVerdict(forged)).toBe('ok')
    const e = parseEnvelope(forged)
    for (const p of s.to) expect(outcome(() => openSealed(e, opener(p)))).toBe('open-failed')
    for (const p of s.to) expect(outcome(() => openSealed(s.envelope, opener(p)))).toBe('ok')
  })
})

describe('F3: hops swapped, reversed or rotated', () => {
  it.each(lineCases('chain-mutations.json', 'F3'))('$name', (c) => {
    expect(['chain-broken', 'chain-not-to-sender']).toContain(
      chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number),
    )
  })
})

describe('F4: one caveat dropped, appended or edited, the sig kept', () => {
  it.each(lineCases('chain-mutations.json', 'F4'))('$name is exactly bad-hop-sig', (c) => {
    expect(chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number)).toBe('bad-hop-sig')
  })

  it('in a fresh chain of 4 hops (seed 504)', () => {
    const w = world(504)
    const from = item(w.signers, 11)
    const hops = chain(w, from, 4)
    expect(outcome(() => verifyChain(hops, from.address, T0))).toBe('ok')
    for (let i = 0; i < hops.length; i++) {
      const h = item(hops, i)
      for (const caveats of [[], [...h.caveats, 'repo=x'], [`${item(h.caveats, 0)}x`]]) {
        const changed = hops.map((x, j) => (j === i ? { ...x, caveats } : x))
        expect(outcome(() => verifyChain(changed, from.address, T0))).toBe('bad-hop-sig')
      }
    }
  })
})

describe('F5: one hop exp raised', () => {
  it.each(lineCases('chain-mutations.json', 'F5'))('$name', (c) => {
    const auth = c.input.auth as Hop[]
    const i = Number(/hop(\d+)/.exec(c.name)?.[1])
    const prev = i > 0 ? item(auth, i - 1).exp : undefined
    const want = prev !== undefined && item(auth, i).exp > prev ? 'exp-not-monotone' : 'bad-hop-sig'
    expect(chainVerdict(auth, c.input.from as string, c.input.ts as number)).toBe(want)
  })
})

describe('F6: a self-rooted attacker posing as a principal', () => {
  it('(a) an empty chain from the attacker verifies at the core, rooted at the attacker: the refusal is the relay or edge root policy', () => {
    const c = item(lineCases('chain-mutations.json', 'F6', 'a-'), 0)
    expect(verifyChain([], c.input.from as string, c.input.ts as number).root).toBe(c.input.from)
  })
  it.each([
    ...lineCases('chain-mutations.json', 'F6', 'b-'),
    ...lineCases('chain-mutations.json', 'F6', 'c-'),
  ])('$name is bad-hop-sig', (c) => {
    expect(chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number)).toBe('bad-hop-sig')
  })
})

describe('F7(a): S + L, the malleated signature', () => {
  it.each(lineCases('chain-mutations.json', 'F7', 'a-'))('$name', (c) => {
    const v =
      c.kind === 'chain'
        ? chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number)
        : outerVerdict(bytesOf(c))
    expect(v).toBe(c.kind === 'chain' || label(c).includes('hop') ? 'bad-hop-sig' : 'bad-sig')
  })
  it('a record signature with S + L', () => {
    const c = item(lineCases('record-mutations.json', 'F7', 'a-'), 0)
    expect(recordVerdict(bytesOf(c), c.input.now as number)).toBe('bad-record-sig')
  })
  it('a fresh envelope and hop (seed 507)', () => {
    const w = world(507)
    const s = send(w, 1, 1)
    const u = clone(s.envelope)
    u.sig = plusL(s.envelope.sig)
    expect(outerVerdict(utf8(JSON.stringify(u)))).toBe('bad-sig')
    const h = clone(s.envelope)
    const hop = item(hopsOf(h), 0)
    hop.sig = plusL(hop.sig as string)
    expect(outerVerdict(resign(h, s.from))).toBe('bad-hop-sig')
  })
})

// F7(b) and (c): the spec requires a refusal (§10, "verified strictly"; Appendix B item 32 for the reference relay).
// Each placement and each key is its own test, so a red one names exactly what was accepted.
function degenerateVerdict(c: AdvCase): string {
  if (c.kind === 'chain') return chainVerdict(c.input.auth, c.input.from as string, c.input.ts as number)
  if (c.kind === 'record') return recordVerdict(bytesOf(c), c.input.now as number)
  return outerVerdict(bytesOf(c))
}
const REFUSAL: Record<string, string> = { chain: 'bad-hop-sig', record: 'bad-record-sig', outer: 'bad-sig' }

describe('F7(b): a signature under a small-order public key (R the identity, S = 0) is refused', () => {
  it.each([
    ...lineCases('chain-mutations.json', 'F7', 'b-'),
    ...lineCases('record-mutations.json', 'F7', 'b-'),
  ])('$name', (c) => {
    expect(degenerateVerdict(c)).toBe(REFUSAL[c.kind])
  })
})

describe('F7(c): a signature under a non-canonical encoding (y + p) is refused', () => {
  it.each([
    ...lineCases('chain-mutations.json', 'F7', 'c-'),
    ...lineCases('record-mutations.json', 'F7', 'c-'),
  ])('$name', (c) => {
    expect(degenerateVerdict(c)).toBe(REFUSAL[c.kind])
  })
})

describe('F8: a wrap for the wrong recipient', () => {
  it('(a) wraps swapped, id kept: bad-id; (b) resigned by the sender: verifies, and neither recipient opens (seed 508)', () => {
    const w = world(508)
    const s = send(w, 2, 0)
    expect(outerVerdict(s.bytes)).toBe('ok')
    const u = clone(s.envelope)
    const [a, b] = [item(wrapsOf(u), 0), item(wrapsOf(u), 1)]
    ;[a.enc, b.enc, a.ct, b.ct] = [b.enc, a.enc, b.ct, a.ct]
    const kept = utf8(JSON.stringify(u))
    expect(toHex(kept)).not.toBe(toHex(s.bytes))
    expect(outerVerdict(kept)).toBe('bad-id')
    const resigned = resign(u, s.from)
    expect(outerVerdict(resigned)).toBe('ok')
    const e = parseEnvelope(resigned)
    for (const p of s.to) expect(outcome(() => openSealed(e, opener(p)))).toBe('open-failed')
  })
  it.each(lineCases('open-cases.json', 'F8'))('$name is open-failed', (c) => {
    expect(openVerdict(c.input as unknown as OpenInput)).toBe('open-failed')
  })
})

describe('F9: the recipient list changed', () => {
  it.each(lineCases('envelope-mutations.json', 'F9'))('$name', (c) => {
    const want = label(c).startsWith('seventeen')
      ? 'too-many-recipients'
      : label(c).startsWith('to-and-wraps')
        ? 'bad-id'
        : 'bad-shape'
    expect(outerVerdict(bytesOf(c))).toBe(want)
  })
})

describe('P6: a signature replayed across kinds', () => {
  it("a hop's sig as an envelope's sig over the hop digest is bad-id; a record's sig as a hop's is bad-hop-sig (seed 516)", () => {
    const w = world(516)
    const s = send(w, 1, 1)
    const hop = item(s.envelope.auth, 0)
    const u = clone(s.envelope)
    u.from = hop.iss
    u.auth = []
    u.id = sha256hex(canonical(hopPreimage(hop)))
    u.sig = hop.sig
    expect(outerVerdict(utf8(JSON.stringify(u)))).toBe('bad-id')
    const signer = item(w.signers, 0)
    const recordSig = signPreimage(signer, ['ac/key/1', signer.address, '00'.repeat(32), T0, T0 + DAY])
    const forged = { iss: signer.address, sub: s.from.address, caveats: [], exp: NOW + DAY, sig: recordSig }
    expect(outcome(() => verifyChain([forged], s.from.address, T0))).toBe('bad-hop-sig')
  })
})
