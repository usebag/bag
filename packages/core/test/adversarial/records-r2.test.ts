import { describe, expect, it } from 'vitest'
import { recordVerdict, rotationClaimVerdict, rotationVerdict } from '../../scripts/gen-adversarial.ts'
import { toHex, utf8 } from '../../src/hex.ts'
import { generateSealingKey, generateSigningKey, type Rng, type SigningKey } from '../../src/keys.ts'
import {
  type AddressRecord,
  checkAcceptRoot,
  countersignRotation,
  isAcceptRoot,
  isDomainHost,
  MAX_KEY_LIFETIME,
  MAX_ROOTS,
  serializeRecord,
  signRecord,
  verifyRecord,
  verifyRotation,
  verifyRotationClaim,
} from '../../src/records.ts'
import { expectAcError, outcome } from '../support/assert.ts'
import { xorshiftRng } from '../support/rng.ts'
import { bytesOf, DAY, label, lineCases, NOW, T0 } from './support.ts'

// Round-2 lines W7, T1, T2 and T3 in the TypeScript core: malformed domain: roots, the rotation claim at a reader
// that holds no previous record, its key binding, and the caps of roots and of a key record's lifetime. Every key
// comes from xorshiftRng with the seed written in the test (V2); each refusal stands beside an accepted control (V1).

const FILE = 'round2-records.json'

function addressRecord(rng: Rng, key: SigningKey, over: Partial<AddressRecord> = {}): AddressRecord {
  return signRecord(key, {
    kind: 'address',
    key: key.address,
    sealing_key: toHex(generateSealingKey(rng).publicKey),
    relays: ['https://relay.example'],
    rotation_key: null,
    revoked: [],
    ttl: DAY,
    iat: T0,
    rotated_from: null,
    ...over,
  })
}

describe('W7: a malformed domain: root is bad-record in an accept-from record', () => {
  const named = [
    '127.0.0.1',
    'example.com.',
    'Example.com',
    'localhost',
    `${'a'.repeat(63)}.`.repeat(3) + 'a'.repeat(62),
    '',
  ]

  it('refuses the six named hosts, one by one and as roots, and accepts their lawful neighbours', () => {
    expect(named.at(4)?.length).toBe(254)
    for (const host of named) {
      expect(isDomainHost(host)).toBe(false)
      expect(isAcceptRoot(`domain:${host}`)).toBe(false)
      expectAcError(() => checkAcceptRoot(`domain:${host}`), 'bad-record')
    }
    const lawful = [
      'example.com',
      `${'a'.repeat(63)}.`.repeat(3) + 'a'.repeat(61),
      '1.2.3.example',
      'xn--bcher-kva.example',
    ]
    expect(lawful[1]?.length).toBe(253)
    for (const host of lawful) {
      expect(isDomainHost(host)).toBe(true)
      expect(checkAcceptRoot(`domain:${host}`)).toBe(`domain:${host}`)
    }
  })

  it('gives every committed W7 case its pre-registered verdict: 0 malformed root accepted', () => {
    const all = lineCases('round2-domains.json', 'W7')
    const refused = all.filter((c) => !label(c).startsWith('control-'))
    const controls = all.filter((c) => label(c).startsWith('control-'))
    expect(refused.length).toBeGreaterThanOrEqual(6)
    expect(controls.length).toBeGreaterThan(0)
    expect(refused.every((c) => c.expected === 'bad-record')).toBe(true)
    expect(controls.every((c) => c.expected === 'ok')).toBe(true)
    const wrong = all.filter((c) => recordVerdict(bytesOf(c), NOW) !== c.expected).map((c) => c.name)
    expect(wrong).toEqual([])
  })

  it('refuses every seeded mutation of a lawful host into an uppercase, a trailing-dot or an IP-literal form (seed 1607)', () => {
    const rng = xorshiftRng(1607)
    const letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    const labelOf = (): string => {
      const b = rng(1 + ((rng(1)[0] as number) % 20))
      const s = [...b].map((x) => letters[x % letters.length]).join('')
      return /^[0-9]+$/.test(s) ? `x${s}` : s
    }
    for (let i = 0; i < 300; i++) {
      const host = Array.from({ length: 2 + ((rng(1)[0] as number) % 3) }, labelOf).join('.')
      expect(isDomainHost(host), host).toBe(true)
      const at = (rng(1)[0] as number) % host.length
      const upper = host.slice(0, at) + host.charAt(at).toUpperCase() + host.slice(at + 1)
      if (upper !== host) expect(isDomainHost(upper), upper).toBe(false)
      expect(isDomainHost(`${host}.`)).toBe(false)
      expect(isDomainHost(`${host}.${(rng(1)[0] as number) % 256}`)).toBe(false)
      expect(isDomainHost(host.split('.')[0])).toBe(false)
    }
  })
})

describe('T1: a rotation claim to a reader that holds no record of rotated_from', () => {
  it('is bad-rotation unless rotation_sig verifies under rotated_from itself, over 32 seeded rotations (seed 1601)', () => {
    const rng = xorshiftRng(1601)
    let refused = 0
    for (let i = 0; i < 32; i++) {
      const [prevKey, rotationKey, nextKey, unrelated] = Array.from({ length: 4 }, () =>
        generateSigningKey(rng),
      ) as [SigningKey, SigningKey, SigningKey, SigningKey]
      const prev = addressRecord(rng, prevKey, { rotation_key: rotationKey.address })
      const next = addressRecord(rng, nextKey, { rotated_from: prevKey.address, iat: T0 + 1 })
      expect(outcome(() => verifyRecord(next, NOW))).toBe('ok')
      expect(outcome(() => verifyRotationClaim(countersignRotation(prevKey, next)))).toBe('ok')
      for (const k of [rotationKey, nextKey, unrelated]) {
        expect(outcome(() => verifyRotationClaim(countersignRotation(k, next)))).toBe('bad-rotation')
        refused++
      }
      expect(outcome(() => verifyRotationClaim(next))).toBe('bad-rotation')
      refused++
      // The rotation key's path: only a reader that holds the previous record takes it.
      expect(outcome(() => verifyRotation(prev, countersignRotation(rotationKey, next)))).toBe('ok')
      expect(outcome(() => verifyRotation(prev, countersignRotation(nextKey, next)))).toBe('bad-rotation')
    }
    expect(refused).toBe(128)
  })

  it('gives every committed T1 case its pre-registered verdict, the claim and the held-previous path apart', () => {
    const all = lineCases(FILE, 'T1')
    const wrong = all
      .filter((c) => {
        const got =
          c.kind === 'rotation'
            ? rotationVerdict(bytesOf(c, 'prev_bytes_hex'), bytesOf(c, 'next_bytes_hex'))
            : rotationClaimVerdict(bytesOf(c), c.input.now as number, c.input.skew as number)
        return got !== c.expected
      })
      .map((c) => c.name)
    expect(wrong).toEqual([])
    expect(all.filter((c) => c.kind === 'rotation-claim' && c.expected === 'bad-rotation').length).toBe(6)
    expect(all.filter((c) => c.expected === 'ok').length).toBeGreaterThanOrEqual(3)
  })
})

describe('T2: the claim is bound to rotated_from, never to a key the submitter writes', () => {
  it('refuses 64 seeded self-countersigned claims by key or by rotation_key, and accepts the victim countersigning (seed 1602)', () => {
    const rng = xorshiftRng(1602)
    let accepted = 0
    for (let i = 0; i < 64; i++) {
      const [victim, attacker, attacker2] = Array.from({ length: 3 }, () => generateSigningKey(rng)) as [
        SigningKey,
        SigningKey,
        SigningKey,
      ]
      const rotationKey = [attacker, attacker2, victim][i % 3] as SigningKey
      const claim = addressRecord(rng, attacker, {
        rotated_from: victim.address,
        rotation_key: rotationKey.address,
        iat: T0 + 1,
      })
      for (const k of [attacker, attacker2, rotationKey]) {
        if (k === victim) continue
        if (outcome(() => verifyRotationClaim(countersignRotation(k, claim))) === 'ok') accepted++
      }
      expect(outcome(() => verifyRotationClaim(countersignRotation(victim, claim)))).toBe('ok')
    }
    expect(accepted).toBe(0)
  })

  it('gives every committed T2 case its pre-registered verdict', () => {
    const all = lineCases(FILE, 'T2')
    const verdict = (c: (typeof all)[number]): string =>
      c.kind === 'rotation'
        ? rotationVerdict(bytesOf(c, 'prev_bytes_hex'), bytesOf(c, 'next_bytes_hex'))
        : rotationClaimVerdict(bytesOf(c), c.input.now as number, c.input.skew as number)
    expect(all.filter((c) => verdict(c) !== c.expected).map((c) => c.name)).toEqual([])
    expect(all.filter((c) => c.expected === 'bad-rotation').length).toBe(6)
  })
})

describe('T3: the caps of roots and of a key record lifetime', () => {
  const rng = xorshiftRng(1603)
  const owner = generateSigningKey(rng)
  const roots = (n: number): string[] =>
    Array.from({ length: n }, (_, i) =>
      i % 2 === 0 ? `domain:r${i}.example` : generateSigningKey(rng).address,
    )

  it('holds MAX_ROOTS at 1,024 and MAX_KEY_LIFETIME at 86,400', () => {
    expect(MAX_ROOTS).toBe(1024)
    expect(MAX_KEY_LIFETIME).toBe(86_400)
  })

  it('signs and verifies 1,024 roots, and refuses 1,025 as bad-record at the writer and at the reader', () => {
    const unsigned = {
      kind: 'accept-from',
      owner: owner.address,
      max_bytes: 65_536,
      ttl: 604_800,
      iat: T0,
    } as const
    const ok = signRecord(owner, { ...unsigned, roots: roots(1024) })
    expect(outcome(() => verifyRecord(ok, NOW))).toBe('ok')
    expectAcError(() => signRecord(owner, { ...unsigned, roots: roots(1025) }), 'bad-record')
    const over = { ...ok, roots: [...ok.roots, 'domain:extra.example'] }
    expect(recordVerdict(utf8(JSON.stringify(over)), NOW)).toBe('bad-record')
  })

  it('accepts a key record living 86,400 s or 0 s, and refuses 86,401 s and exp before iat', () => {
    const sealing = toHex(generateSealingKey(rng).publicKey)
    const key = (iat: number, exp: number) =>
      ({ kind: 'key', key: owner.address, sealing_key: sealing, iat, exp }) as const
    expect(outcome(() => verifyRecord(signRecord(owner, key(T0, T0 + DAY)), NOW))).toBe('ok')
    expect(outcome(() => verifyRecord(signRecord(owner, key(T0, T0)), T0))).toBe('ok')
    expectAcError(() => signRecord(owner, key(T0, T0 + DAY + 1)), 'bad-record')
    expectAcError(() => signRecord(owner, key(T0, T0 - 1)), 'bad-record')
    const signed = signRecord(owner, key(T0, T0 + DAY))
    expect(recordVerdict(utf8(JSON.stringify({ ...signed, exp: T0 + DAY + 1 })), NOW)).toBe('bad-record')
    expect(recordVerdict(serializeRecord(signed), NOW)).toBe('ok')
  })

  it('gives every committed T3 case its pre-registered verdict', () => {
    const all = lineCases(FILE, 'T3')
    const wrong = all
      .filter((c) => recordVerdict(bytesOf(c), c.input.now as number) !== c.expected)
      .map((c) => c.name)
    expect(wrong).toEqual([])
    expect(all.filter((c) => c.expected === 'ok').length).toBe(4)
  })
})
