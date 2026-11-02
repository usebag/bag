import { describe, expect, it } from 'vitest'
import { isAddress } from '../src/address.ts'
import { type CanonicalValue, canonical } from '../src/canonical.ts'
import { evaluateCaveats } from '../src/caveats.ts'
import { type Hop, hopPreimage, verifyChain } from '../src/chain.ts'
import { checkDiscovered, discover, parseTxtPresentation, txtName } from '../src/discovery.ts'
import {
  buildEnvelope,
  envelopeId,
  envelopeIdPreimage,
  parseEnvelope,
  serializeEnvelope,
  verifyOuter,
} from '../src/envelope.ts'
import {
  checkHandleRecord,
  type HandleRecord,
  handlePath,
  handleRecordPreimage,
  parseHandle,
  parseHandleRecord,
  verifyHandleRecord,
} from '../src/handles.ts'
import { preimageDigest, sha256hex } from '../src/hash.ts'
import { fromHex, isHex, toHex, utf8 } from '../src/hex.ts'
import { sealingKeyFromSeed, signingKeyFromSeed, verifyPreimage } from '../src/keys.ts'
import { codingEvaluator } from '../src/profiles/coding.ts'
import { verifyFetchAuth } from '../src/proofs.ts'
import {
  type AcRecord,
  type AddressRecord,
  checkRecord,
  parseRecord,
  recordPreimage,
  recordSigner,
  verifyRecord,
  verifyRotation,
  verifyRotationClaim,
} from '../src/records.ts'
import {
  contentAad,
  encodeContent,
  openSealed,
  SEAL_INFO,
  type Sealed,
  type SealedContent,
  sealedHash,
  sealedHashPreimage,
  sealTo,
} from '../src/seal.ts'
import { outcome } from './support/assert.ts'
import { replayRng } from './support/rng.ts'
import { casesOf, readVectors } from './support/vectors.ts'

// Every committed vector, checked through the public API: what the generator wrote must be what the core does.

const text = (b: Uint8Array): string => new TextDecoder().decode(b)
const FILES = [
  'canonical.json',
  'envelope.json',
  'sealed-multi.json',
  'chain-valid.json',
  'chain-invalid.json',
  'records.json',
  'hpke-rfc9180-subset.json',
  'discovery.json',
]

interface EnvelopeVector {
  readonly name: string
  readonly inputs: {
    readonly from: string
    readonly from_seed: string
    readonly to: readonly {
      readonly address: string
      readonly sealing_key: string
      readonly sealing_seed: string
    }[]
    readonly auth: readonly Hop[]
    readonly content: SealedContent
    readonly ts: number
    readonly content_key: string
    readonly nonce: string
    readonly ephemeral_seeds: readonly string[]
  }
  readonly expected: {
    readonly plaintext: string
    readonly content_aad: string
    readonly hops: readonly { readonly canonical: string; readonly digest: string }[]
    readonly sealed_hash_canonical: string
    readonly sealed_hash: string
    readonly id_canonical: string
    readonly id: string
    readonly sig: string
    readonly chain: unknown
    readonly coding_profile: unknown
    readonly envelope: unknown
    readonly bytes: string
    readonly size: number
  }
}

function checkEnvelopeVector(v: EnvelopeVector): void {
  const bytes = utf8(v.expected.bytes)
  const e = parseEnvelope(bytes)
  expect(e).toEqual(v.expected.envelope)
  expect(serializeEnvelope(e)).toEqual(bytes)
  expect(bytes.length).toBe(v.expected.size)
  expect(canonical(sealedHashPreimage(e.sealed))).toBe(v.expected.sealed_hash_canonical)
  expect(sealedHash(e.sealed)).toBe(v.expected.sealed_hash)
  expect(canonical(envelopeIdPreimage(e))).toBe(v.expected.id_canonical)
  expect(envelopeId(e)).toBe(v.expected.id)
  expect(sha256hex(v.expected.id_canonical)).toBe(v.expected.id)
  expect(e.sig).toBe(v.expected.sig)
  verifyOuter(e, v.inputs.ts)
  const chain = verifyChain(e.auth, e.from, e.ts)
  expect(chain).toEqual(v.expected.chain)
  expect(
    e.auth.map((h) => ({
      canonical: canonical(hopPreimage(h)),
      digest: toHex(preimageDigest(hopPreimage(h))),
    })),
  ).toEqual(v.expected.hops)
  expect(text(contentAad(e.to, e.from))).toBe(v.expected.content_aad)
  expect(text(encodeContent(v.inputs.content))).toBe(v.expected.plaintext)
  for (const [i, r] of v.inputs.to.entries()) {
    const key = sealingKeyFromSeed(fromHex(r.sealing_seed))
    expect(toHex(key.publicKey)).toBe(r.sealing_key)
    expect(openSealed(e, { address: r.address, key })).toEqual(v.inputs.content)
    const wrap = e.sealed.wraps[i]
    if (wrap === undefined) throw new Error('a wrap is missing')
    expect(toHex(key.open(fromHex(wrap.enc), utf8(SEAL_INFO), utf8(r.address), fromHex(wrap.ct)))).toBe(
      v.inputs.content_key,
    )
  }
  const ctx = { from: e.from, to: e.to, ts: e.ts, root: chain.root, sealed: v.inputs.content }
  expect(evaluateCaveats(chain.caveats, [codingEvaluator], ctx)).toEqual(v.expected.coding_profile)
  const from = signingKeyFromSeed(fromHex(v.inputs.from_seed))
  expect(from.address).toBe(v.inputs.from)
  const rng = replayRng([
    fromHex(v.inputs.content_key),
    fromHex(v.inputs.nonce),
    ...v.inputs.ephemeral_seeds.map((s) => fromHex(s)),
  ])
  const rebuilt = buildEnvelope({
    from,
    to: v.inputs.to.map((r) => ({ address: r.address, sealingKey: fromHex(r.sealing_key) })),
    auth: v.inputs.auth,
    ...v.inputs.content,
    ts: v.inputs.ts,
    rng,
  })
  expect(text(rebuilt.bytes)).toBe(v.expected.bytes)
}

describe('the committed vectors', () => {
  it.each(FILES)('%s carries the header', (name) => {
    const file = readVectors(name)
    expect(file.generated_by).toBe('packages/core/scripts/gen-vectors.ts')
    expect(file.suite).toBe(1)
    expect(String(file.description).length).toBeGreaterThan(40)
    expect(String(file.test_data)).toContain('test data')
  })

  describe('canonical.json', () => {
    const file = readVectors('canonical.json')
    it.each(casesOf<{ name: string; value: CanonicalValue; canonical: string; sha256: string }>(file))(
      '$name',
      (c) => {
        expect(canonical(c.value)).toBe(c.canonical)
        expect(sha256hex(c.canonical)).toBe(c.sha256)
      },
    )
    it.each(casesOf<{ name: string; value?: unknown; utf16_hex?: string; result: string }>(file, 'invalid'))(
      'rejects $name',
      (c) => {
        const value =
          c.utf16_hex === undefined
            ? c.value
            : String.fromCharCode(...(c.utf16_hex.match(/.{4}/g) ?? []).map((u) => Number.parseInt(u, 16)))
        expect(outcome(() => canonical(value as CanonicalValue))).toBe(c.result)
      },
    )
    it.each(
      casesOf<{
        table: string
        preimage: CanonicalValue
        canonical: string
        sha256: string
        signer?: string
        sig?: string
      }>(file, 'preimages'),
    )('the $table table', (c) => {
      expect(canonical(c.preimage)).toBe(c.canonical)
      expect(sha256hex(c.canonical)).toBe(c.sha256)
      if (c.signer !== undefined) expect(verifyPreimage(c.signer, c.preimage, c.sig ?? '')).toBe(true)
    })
    // The proof holds for one accepted base exactly when the verdict is past the id and the signature (spec §8.3).
    it.each(
      casesOf<{
        name: string
        accepted: string[]
        id: string
        headers: Record<string, string>
        result: string
      }>(file, 'fetch_proofs'),
    )('fetch proof: $name', (c) => {
      const signer = c.headers['ac-signer'] ?? ''
      const ts = Number(c.headers['ac-ts'])
      const sig = c.headers['ac-sig'] ?? ''
      const holds =
        isHex(c.id, 32) &&
        isAddress(signer) &&
        c.accepted.some((base) => verifyFetchAuth(signer, c.id, ts, base, sig))
      expect(holds).toBe(c.result !== 'bad-hex' && c.result !== 'bad-auth')
    })
  })

  describe.each(['envelope.json', 'sealed-multi.json'])('%s', (name) => {
    it.each(casesOf<EnvelopeVector>(readVectors(name)))('$name', (v) => checkEnvelopeVector(v))
  })

  describe('envelope.json parse and verify', () => {
    const file = readVectors('envelope.json')
    it.each(
      casesOf<{ name: string; bytes?: string; bytes_hex?: string; pad_with_spaces?: number; result: string }>(
        file,
        'parse',
      ),
    )('parse: $name', (c) => {
      const input =
        c.bytes_hex === undefined
          ? (c.bytes ?? '') + ' '.repeat(c.pad_with_spaces ?? 0)
          : fromHex(c.bytes_hex)
      expect(outcome(() => parseEnvelope(input))).toBe(c.result)
    })
    it.each(
      casesOf<{ name: string; bytes: string; now: number; ttl: number; skew: number; result: string }>(
        file,
        'verify',
      ),
    )('verify: $name', (c) => {
      expect(outcome(() => verifyOuter(parseEnvelope(c.bytes), c.now, { ttl: c.ttl, skew: c.skew }))).toBe(
        c.result,
      )
    })
  })

  describe('envelope.json open and seal', () => {
    const file = readVectors('envelope.json')
    it.each(
      casesOf<{
        name: string
        to: string[]
        from: string
        sealed: Sealed
        address: string
        sealing_seed: string
        result: string
        content?: SealedContent
      }>(file, 'open'),
    )('open: $name', (c) => {
      const me = { address: c.address, key: sealingKeyFromSeed(fromHex(c.sealing_seed)) }
      let content: SealedContent | undefined
      expect(
        outcome(() => {
          content = openSealed(c, me)
        }),
      ).toBe(c.result)
      expect(content).toEqual(c.content)
    })
    it.each(
      casesOf<{
        name: string
        from: string
        to: { address: string; sealing_key: string }[]
        content: SealedContent
        content_key: string
        nonce: string
        ephemeral_seeds: string[]
        result: string
      }>(file, 'seal'),
    )('seal: $name', (c) => {
      const rng = replayRng([
        fromHex(c.content_key),
        fromHex(c.nonce),
        ...c.ephemeral_seeds.map((s) => fromHex(s)),
      ])
      const to = c.to.map((r) => ({ address: r.address, sealingKey: fromHex(r.sealing_key) }))
      expect(outcome(() => sealTo(to, c.from, c.content, rng))).toBe(c.result)
    })
  })

  describe('chain-valid.json caveats', () => {
    it.each(
      casesOf<{ name: string; caveats: string[]; content: SealedContent; result: string; caveat?: string }>(
        readVectors('chain-valid.json'),
        'caveats',
      ),
    )('$name', (c) => {
      // The coding profile reads the sealed part only; the outer fields are placeholders.
      const ctx = { from: '', to: [], ts: 0, root: '', sealed: c.content }
      const r = evaluateCaveats(c.caveats, [codingEvaluator], ctx)
      expect(r.ok ? { result: 'ok' } : { result: r.code, caveat: r.caveat }).toEqual(
        c.result === 'ok' ? { result: 'ok' } : { result: c.result, caveat: c.caveat },
      )
    })
  })

  describe('chain-valid.json', () => {
    it.each(
      casesOf<{
        name: string
        from: string
        ts: number
        auth: Hop[]
        hops: { canonical: string; digest: string }[]
        chain: unknown
      }>(readVectors('chain-valid.json')),
    )('$name', (c) => {
      expect(verifyChain(c.auth, c.from, c.ts)).toEqual(c.chain)
      expect(c.auth.map((h) => canonical(hopPreimage(h)))).toEqual(c.hops.map((h) => h.canonical))
      expect(c.auth.map((h) => toHex(preimageDigest(hopPreimage(h))))).toEqual(c.hops.map((h) => h.digest))
    })
  })

  describe('chain-invalid.json', () => {
    it.each(
      casesOf<{ name: string; from: string; ts: number; auth: Hop[]; result: string }>(
        readVectors('chain-invalid.json'),
      ),
    )('$name', (c) => {
      expect(outcome(() => verifyChain(c.auth, c.from, c.ts))).toBe(c.result)
    })
  })

  describe('records.json', () => {
    const file = readVectors('records.json')
    it.each(
      casesOf<{
        name: string
        record: AcRecord
        canonical: string
        digest: string
        signer: string
        checks: { now: number; skew: number; result: string }[]
      }>(file),
    )('$name', (c) => {
      expect(canonical(recordPreimage(c.record))).toBe(c.canonical)
      expect(toHex(preimageDigest(recordPreimage(c.record)))).toBe(c.digest)
      expect(recordSigner(c.record)).toBe(c.signer)
      for (const k of c.checks) expect(outcome(() => verifyRecord(c.record, k.now, k.skew))).toBe(k.result)
    })
    it.each(casesOf<{ name: string; record: unknown; result: string }>(file, 'invalid'))(
      'invalid: $name',
      (c) => {
        expect(outcome(() => checkRecord(c.record))).toBe(c.result)
      },
    )
    it.each(
      casesOf<{ name: string; prev: AddressRecord; next: AddressRecord; result: string }>(file, 'rotations'),
    )('rotation: $name', (c) => {
      expect(outcome(() => verifyRotation(c.prev, c.next))).toBe(c.result)
    })
    it.each(casesOf<{ name: string; bytes?: string; bytes_hex?: string; result: string }>(file, 'parse'))(
      'parse: $name',
      (c) => {
        const input = c.bytes_hex === undefined ? (c.bytes ?? '') : fromHex(c.bytes_hex)
        expect(outcome(() => parseRecord(input))).toBe(c.result)
      },
    )
    it.each(casesOf<{ name: string; next: AddressRecord; result: string }>(file, 'rotation_claims'))(
      'rotation claim: $name',
      (c) => {
        expect(outcome(() => verifyRotationClaim(c.next))).toBe(c.result)
      },
    )
  })

  describe('discovery.json', () => {
    const file = readVectors('discovery.json')
    const hexOf = (s: string): string => toHex(Uint8Array.from(s, (ch) => ch.charCodeAt(0)))
    it.each(
      casesOf<{ name: string; text: string; result: string; strings_hex?: string[] }>(file, 'presentation'),
    )('presentation: $name', (c) => {
      expect(outcome(() => parseTxtPresentation(c.text))).toBe(c.result)
      if (c.result === 'ok') expect(parseTxtPresentation(c.text).map(hexOf)).toEqual(c.strings_hex)
    })
    it.each(
      casesOf<{
        name: string
        domain: string
        txt_name: string | null
        records: string[][]
        result: string
        key?: string | null
        url?: string
        origin?: string
      }>(file, 'txt'),
    )('txt: $name', (c) => {
      expect(txtName(c.domain)).toBe(c.txt_name)
      expect(outcome(() => discover(c.records, c.domain))).toBe(c.result)
      if (c.result === 'ok')
        expect(discover(c.records, c.domain)).toEqual({ key: c.key, url: c.url, origin: c.origin })
    })
    // A record agrees with its TXT by its key or by one rotation the TXT key countersigned; the pin
    // then moves only by §7.3.
    const pinAfter = (pinned: AddressRecord | null, record: AddressRecord): string => {
      if (pinned === null || pinned.key === record.key) return record.key
      return outcome(() => verifyRotation(pinned, record)) === 'ok' ? record.key : pinned.key
    }
    it.each(
      casesOf<{
        name: string
        txt_key: string | null
        record: AddressRecord
        pinned: AddressRecord | null
        result: string
        pin: string | null
      }>(file, 'agreement'),
    )('agreement: $name', (c) => {
      const found = { key: c.txt_key, url: '', origin: '' }
      expect(outcome(() => checkDiscovered(c.record, found))).toBe(c.result)
      expect(c.result === 'ok' ? pinAfter(c.pinned, c.record) : (c.pinned?.key ?? null)).toBe(c.pin)
    })
    it.each(
      casesOf<{
        name: string
        handle: string
        result: string
        local?: string
        domain?: string
        path?: string
      }>(file, 'handles'),
    )('handle: $name', (c) => {
      expect(outcome(() => parseHandle(c.handle))).toBe(c.result)
      if (c.result === 'ok') {
        expect(parseHandle(c.handle)).toEqual({ local: c.local, domain: c.domain })
        expect(handlePath(c.handle)).toBe(c.path)
      }
    })
    it.each(
      casesOf<{
        name: string
        record: HandleRecord
        canonical: string
        digest: string
        signer: string
        checks: {
          now: number
          skew: number
          org: string
          handle: string
          revoked: string[]
          result: string
        }[]
      }>(file),
    )('handle record: $name', (c) => {
      expect(canonical(handleRecordPreimage(c.record))).toBe(c.canonical)
      expect(toHex(preimageDigest(handleRecordPreimage(c.record)))).toBe(c.digest)
      expect(c.record.org).toBe(c.signer)
      for (const k of c.checks) {
        const expected = { org: k.org, handle: k.handle, revoked: k.revoked }
        expect(outcome(() => verifyHandleRecord(c.record, expected, k.now, k.skew))).toBe(k.result)
      }
    })
    it.each(casesOf<{ name: string; record: unknown; result: string }>(file, 'invalid'))(
      'invalid handle record: $name',
      (c) => {
        expect(outcome(() => checkHandleRecord(c.record))).toBe(c.result)
      },
    )
    it.each(casesOf<{ name: string; bytes: string; result: string }>(file, 'parse'))(
      'handle record parse: $name',
      (c) => {
        expect(outcome(() => parseHandleRecord(c.bytes))).toBe(c.result)
      },
    )
  })
})
