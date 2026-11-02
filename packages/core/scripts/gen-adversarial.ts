/**
 * Writes the differential cases, spec/adversarial/*.json (contract: spec/adversarial/README.md), from the
 * one seed 20261025. Every key in them comes from xorshiftRng(20261025) and is test data by construction. It also
 * writes the round2-*.json files (W7, T1 to T7), from the same stream after the first five files' last draw; their
 * `expected` is the pre-registered verdict, not the TypeScript core's ("Round 2" below).
 *
 *   node packages/core/scripts/gen-adversarial.ts           rewrite spec/adversarial
 *   node packages/core/scripts/gen-adversarial.ts --check   regenerate into a temporary directory and fail unless every
 *                                                           file is byte-identical to spec/adversarial (line G2)
 *
 * Each case's `expected` is what the TypeScript core says now (parseEnvelope, the outer checks, verifyChain, the
 * record checks and openSealed, with AcError caught). It is not the spec's requirement: the tests under
 * packages/core/test/adversarial/ assert that. Every mutation starts from an input that verifies ok, asserted here
 * as it is generated (V1), and a mutation that leaves the input unchanged stops the generator.
 *
 * F1 flips every byte of 200 envelopes (one bit per position, bit p mod 8) and substitutes every hex character of
 * their hex fields with the next hex digit. That is over 20,000 mutations, so the file keeps, per (pass, region,
 * verdict), the first three met in order of envelope size, smallest first; the summary prints the verdicts of all.
 * The files are written in process as JSON.stringify(value, null, 2) plus a newline, with no Biome child: twice on
 * 2026-10-25 a `biome format --stdin-file-path` child stalled in a gate run. biome.json leaves them unformatted.
 * Temporary files go under AC_TEST_TMP (default the system temporary directory), removed unless AC_KEEP_TMP=1.
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { aeadSeal, hpkeSeal } from '../src/hpke.ts'
import {
  type AcRecord,
  type AddressRecord,
  buildEnvelope,
  type CanonicalValue,
  canonical,
  checkId,
  checkSig,
  checkTs,
  contentAad,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Envelope,
  encodeContent,
  envelopeId,
  envelopeIdPreimage,
  fromHex,
  generateSealingKey,
  generateSigningKey,
  type Hop,
  hopPreimage,
  isAcError,
  newThread,
  openSealed,
  parseEnvelope,
  parseRecord,
  type Rng,
  recordPreimage,
  type Sealed,
  type SealedContent,
  SealingKey,
  type SigningKey,
  sealedHashPreimage,
  sealTo,
  serializeEnvelope,
  sha256hex,
  signHop,
  signPreimage,
  toHex,
  utf8,
  verifyChain,
  verifyRecord,
  verifyRotation,
  verifyRotationClaim,
} from '../src/index.ts'
import { parseJson } from '../src/json.ts'
import { xorshiftRng } from '../test/support/rng.ts'

export const SEED = 20261025
export const ADVERSARIAL_DIR = fileURLToPath(new URL('../../../spec/adversarial/', import.meta.url))
export const FILES = [
  'canonical-fuzz.json',
  'envelope-mutations.json',
  'chain-mutations.json',
  'record-mutations.json',
  'open-cases.json',
  'round2-domains.json',
  'round2-records.json',
  'round2-keys.json',
  'round2-duplicates.json',
  'round2-numbers.json',
] as const
export type FileName = (typeof FILES)[number]
/** Files in spec/adversarial that the generator does not write. */
const HAND_WRITTEN = ['README.md', 'rng-expected.json']

const T0 = 1_800_000_000
const NOW = T0 + 60
const DAY = 86_400
const TTL = DEFAULT_TTL
const SKEW = DEFAULT_SKEW
const MAX = Number.MAX_SAFE_INTEGER
const F1_ENVELOPES = 200
const F1_KEEP = 3

type J = Record<string, unknown>

// ---- the seeded stream ------------------------------------------------------------------------------------------

let rng: Rng = xorshiftRng(SEED)

function int(n: number): number {
  const b = rng(4)
  return (
    (((b[0] as number) | ((b[1] as number) << 8) | ((b[2] as number) << 16)) + (b[3] as number) * 2 ** 24) % n
  )
}

function pick<T>(items: readonly T[]): T {
  return at(items, int(items.length))
}

function at<T>(items: readonly T[], i: number): T {
  const v = items[i]
  if (v === undefined) throw new Error(`gen-adversarial: no item ${i} of ${items.length}`)
  return v
}

function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items]
  for (let i = out.length - 1; i > 0; i--) {
    const j = int(i + 1)
    const t = out[i] as T
    out[i] = out[j] as T
    out[j] = t
  }
  return out
}

/** A 53-bit integer from 7 bytes of the stream. */
function int53(): number {
  let n = 0n
  for (const b of rng(7)) n = (n << 8n) | BigInt(b)
  return Number(n & ((1n << 53n) - 1n))
}

// ---- verdicts ---------------------------------------------------------------------------------------------------

export function outcome(fn: () => unknown): string {
  try {
    fn()
    return 'ok'
  } catch (e) {
    if (isAcError(e)) return e.code
    throw e
  }
}

const text = (b: Uint8Array): string => new TextDecoder().decode(b)

/** The `outer` kind: §5.4, §5.5 steps 1 to 3, chain rules 1 to 9 at ts, §5.5 step 4 (the relay's in-core order). */
export function outerVerdict(bytes: Uint8Array, now = NOW, ttl = TTL, skew = SKEW): string {
  return outcome(() => {
    const e = parseEnvelope(bytes)
    checkId(e)
    checkSig(e)
    verifyChain(e.auth, e.from, e.ts)
    checkTs(e.ts, now, { ttl, skew })
  })
}

export function parseVerdict(bytes: Uint8Array): string {
  return outcome(() => parseEnvelope(bytes))
}

export function jsonVerdict(bytes: Uint8Array): string {
  return outcome(() => parseJson(bytes))
}

export function chainVerdict(auth: unknown, from: string, ts: number): string {
  return outcome(() => verifyChain(auth as Hop[], from, ts))
}

export function recordVerdict(bytes: Uint8Array, now = NOW, skew = SKEW): string {
  return outcome(() => verifyRecord(parseRecord(bytes), now, skew))
}

export function rotationVerdict(prev: Uint8Array, next: Uint8Array): string {
  return outcome(() => verifyRotation(parseJson(prev) as AddressRecord, parseJson(next) as AddressRecord))
}

export interface OpenInput {
  readonly v: number
  readonly to: readonly string[]
  readonly from: string
  readonly sealed: Sealed
  readonly address: string
  readonly seal_seed: string
}

export function openVerdict(i: OpenInput): string {
  return outcome(() => openSealed(i, { address: i.address, key: new SealingKey(fromHex(i.seal_seed, 32)) }))
}

// ---- cases ------------------------------------------------------------------------------------------------------

class Cases {
  readonly list: J[] = []
  readonly #counters = new Map<string, number>()

  add(line: string, kind: string, label: string, input: J, expected: string, allowed?: J): void {
    const n = (this.#counters.get(line) ?? 0) + 1
    this.#counters.set(line, n)
    const c: J = { name: `${line}/${n}/${label}`, line, kind, input, expected }
    if (allowed !== undefined) c.allowed = allowed
    this.list.push(c)
  }
}

function fileOf(description: string, cases: Cases): J {
  return {
    description,
    generated_by: 'packages/core/scripts/gen-adversarial.ts',
    seed: SEED,
    test_data:
      'Every seed, private key, content key and nonce in this file is test data: each comes from xorshiftRng(20261025) (packages/core/test/support/rng.ts). They are public; never let them protect anything real.',
    cases: cases.list,
  }
}

function controlOk(what: string, verdict: string): void {
  if (verdict !== 'ok') throw new Error(`gen-adversarial: positive control "${what}" is ${verdict}, not ok`)
}

function differs(what: string, a: Uint8Array | string, b: Uint8Array | string): void {
  const x = typeof a === 'string' ? a : toHex(a)
  const y = typeof b === 'string' ? b : toHex(b)
  if (x === y) throw new Error(`gen-adversarial: the mutation "${what}" leaves the input unchanged`)
}

/** Replaces exactly one occurrence of `from` in `s`. */
function replaceOnce(s: string, from: string, to: string): string {
  const i = s.indexOf(from)
  if (i === -1 || s.indexOf(from, i + 1) !== -1) {
    throw new Error(`gen-adversarial: "${from.slice(0, 40)}" is not in the text exactly once`)
  }
  return s.slice(0, i) + to + s.slice(i + from.length)
}

// ---- the cast ---------------------------------------------------------------------------------------------------

interface Party {
  readonly key: SigningKey
  readonly address: string
  readonly seal: SealingKey
}

interface Cast {
  readonly signers: readonly SigningKey[]
  readonly parties: readonly Party[]
  readonly attacker: SigningKey
}

function makeCast(): Cast {
  const signers = Array.from({ length: 24 }, () => generateSigningKey(rng))
  const parties = Array.from({ length: 32 }, () => {
    const key = generateSigningKey(rng)
    return { key, address: key.address, seal: generateSealingKey(rng) }
  })
  return { signers, parties, attacker: generateSigningKey(rng) }
}

const CAVEATS = ['type=coding.*', 'type=coding.task.v1', 'repo=acme/api', 'repo=acme/web', 'type=chat.*']
const TYPES = ['coding.task.v1', 'coding.review.v1', 'chat.message.v1']

function content(): SealedContent {
  return { type: pick(TYPES), thread: newThread(rng), body: { repo: 'acme/api', n: int(1000) } }
}

/** A chain of n hops ending at `from`, from distinct signers, exp non-increasing and after ts. */
function chainTo(cast: Cast, from: SigningKey, n: number, ts: number): Hop[] {
  const issuers = shuffled(cast.signers).slice(0, n)
  return issuers.map((iss, i) => {
    const sub = i + 1 < n ? at(issuers, i + 1).address : from.address
    const caveats = Array.from({ length: int(3) }, () => pick(CAVEATS))
    return signHop(iss, sub, caveats, ts + DAY * (20 - i))
  })
}

interface Built {
  readonly bytes: Uint8Array
  readonly envelope: Envelope
  readonly from: SigningKey
  readonly to: readonly Party[]
}

function envelope(cast: Cast, nTo: number, nHops: number, ts = T0): Built {
  const to = shuffled(cast.parties).slice(0, nTo)
  const from = pick(cast.signers)
  const auth = chainTo(cast, from, nHops, ts > MAX - 30 * DAY ? ts - 30 * DAY : ts).map((h) => ({ ...h }))
  const built = buildEnvelope({
    from,
    to: to.map((p) => ({ address: p.address, sealingKey: p.seal.publicKey })),
    auth,
    ...content(),
    ts,
    rng,
  })
  return { ...built, from, to }
}

/** The envelope re-signed by `signer` after `change` (the id recomputed). */
function resigned(e: Envelope, signer: SigningKey, change: (u: J) => void): Uint8Array {
  const u = JSON.parse(JSON.stringify(e)) as J
  change(u)
  const unsigned = u as unknown as Envelope
  const id = envelopeId(unsigned)
  const signed: Envelope = { ...unsigned, id, sig: toHex(signer.sign(fromHex(id, 32))) }
  return serializeEnvelope(signed)
}

/** The envelope's JSON text with `change` applied, id and sig kept. */
function edited(e: Envelope, change: (u: J) => void): Uint8Array {
  const u = JSON.parse(JSON.stringify(e)) as J
  change(u)
  return utf8(JSON.stringify(u))
}

const obj = (v: unknown): J => v as J
const list = (v: unknown): unknown[] => v as unknown[]

// ---- Ed25519 degenerate encodings (F7) ---------------------------------------------------------------------------

const L = 2n ** 252n + 27742317777372353535851937790883648493n
const FF30 = 'ff'.repeat(30)
/** The eight small-order points, canonically encoded: identity, order 2, two of order 4, four of order 8. */
export const SMALL_ORDER = [
  ['identity', `01${'00'.repeat(31)}`],
  ['order-2', `ec${FF30}7f`],
  ['order-4-a', '00'.repeat(32)],
  ['order-4-b', `${'00'.repeat(31)}80`],
  ['order-8-a', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['order-8-b', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'],
  ['order-8-c', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['order-8-d', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'],
] as const
/** Non-canonical encodings (y + p): of the identity (y = 1), and of the order-4 point y = 0, each sign. */
export const NON_CANONICAL = [
  ['identity-y-plus-p', `ee${FF30}7f`],
  ['identity-y-plus-p-sign', `ee${FF30}ff`],
  ['order-4-y-plus-p', `ed${FF30}7f`],
  ['order-4-y-plus-p-sign', `ed${FF30}ff`],
] as const
/** R the identity, S = 0: a signature every cofactorless verifier accepts under A when [k]A is the identity. */
export const DEGENERATE_SIG = `01${'00'.repeat(31)}${'00'.repeat(32)}`

function leInt(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number)
  return n
}

function leBytes(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let v = n
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** k = SHA-512(R || A || M) mod L, the challenge scalar of RFC 8032 §5.1.7. */
function challenge(sigHex: string, publicHex: string, message: Uint8Array): bigint {
  const h = createHash('sha512')
    .update(fromHex(sigHex.slice(0, 64)))
    .update(fromHex(publicHex))
    .update(message)
    .digest()
  return leInt(new Uint8Array(h)) % L
}

/** True when the degenerate signature passes a cofactorless check under every small-order A for this message. */
function ground(publicHex: string, message: Uint8Array): boolean {
  return challenge(DEGENERATE_SIG, publicHex, message) % 8n === 0n
}

/** The signature with S replaced by S + L (still under 2^256): the malleated twin of F7(a). */
export function plusL(sigHex: string): string {
  const s = leInt(fromHex(sigHex.slice(64)))
  return sigHex.slice(0, 64) + toHex(leBytes(s + L, 32))
}

// ---- P2's number spellings ---------------------------------------------------------------------------------------

/**
 * Each spelling, and the canonical integer the case is built around (signed over), so that a reader that took the
 * spelling for that integer would accept it. Since §2.5 every reader must refuse every one with its place's
 * code, `01` and `1e400` as bad-json, so no case carries `allowed`.
 */
const SPELLINGS: readonly (readonly [string, number | null])[] = [
  ['1.0', 1],
  ['1e0', 1],
  ['1E0', 1],
  ['-0', 0],
  ['0.5', null],
  ['1.5', null],
  ['-1', null],
  ['01', null],
  ['9007199254740992', null],
  ['9007199254740990.9', MAX],
  ['1e400', null],
  ['1e-400', 0],
]

function spellingLabel(s: string): string {
  return s.replace(/\./g, 'p').replace(/-/g, 'm')
}

// ---- canonical-fuzz.json (P1) -----------------------------------------------------------------------------------

const CONTROL_CHARS = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i))
const ALPHABET = [
  ...CONTROL_CHARS,
  '"',
  '\\',
  '/',
  '\u007f',
  ' ',
  ' ',
  'é',
  'é',
  'ß',
  '漢',
  '😀',
  '\u{1f468}‍\u{1f469}',
  'a',
  'Z',
  '0',
  ' ',
  '<',
  ' ',
  '﻿',
  '￿',
]

function randomString(): string {
  const n = int(16)
  let s = ''
  for (let i = 0; i < n; i++) {
    if (int(5) === 0) {
      let cp = 0x20 + int(0xfffe - 0x20)
      if (cp >= 0xd800 && cp <= 0xdfff) cp -= 0x800
      s += String.fromCodePoint(cp)
    } else {
      s += pick(ALPHABET)
    }
  }
  return s
}

function randomInt(): number {
  return pick([0, 1, MAX, MAX - 1, 2 ** 31, 2 ** 32, int(1000), int53()])
}

function randomValue(depth: number): CanonicalValue {
  const r = int(depth >= 8 ? 3 : 4)
  if (r === 0) return randomString()
  if (r === 1) return randomInt()
  if (r === 2) return int(4) === 0 ? null : randomString()
  return Array.from({ length: int(5) }, () => randomValue(depth + 1))
}

function nested(depth: number, leaf: CanonicalValue): CanonicalValue {
  let v: CanonicalValue = leaf
  for (let i = 0; i < depth; i++) v = [v]
  return v
}

function utf16Hex(s: string): string {
  let out = ''
  for (let i = 0; i < s.length; i++) out += s.charCodeAt(i).toString(16).padStart(4, '0')
  return out
}

function canonicalFile(preimages: readonly CanonicalValue[]): J {
  const cases = new Cases()
  const valid = (label: string, value: CanonicalValue): void => {
    const c = canonical(value)
    cases.add('P1', 'canonical', label, { value, canonical: c, sha256: sha256hex(c) }, 'ok')
  }
  for (const [i, ch] of CONTROL_CHARS.entries()) valid(`control-u00${i.toString(16).padStart(2, '0')}`, ch)
  for (const [label, ch] of [
    ['quote', '"'],
    ['backslash', '\\'],
    ['solidus', '/'],
    ['u007f', '\u007f'],
    ['u2028', ' '],
    ['u2029', ' '],
    ['precomposed', 'é'],
    ['decomposed', 'é'],
    ['surrogate-pair', '😀'],
    ['bom-char', '﻿'],
    ['empty', ''],
  ] as const)
    valid(`string-${label}`, ch)
  for (const [label, n] of [
    ['zero', 0],
    ['one', 1],
    ['max', MAX],
  ] as const)
    valid(`int-${label}`, n)
  valid('null', null)
  valid('empty-list', [])
  for (let d = 1; d <= 8; d++) valid(`depth-${d}`, nested(d, 'x'))
  valid('every-control-char', CONTROL_CHARS.join(''))
  while (cases.list.length < 1800) valid('random', randomValue(0))
  for (let i = 0; i < 200; i++) valid('preimage', at(preimages, i % preimages.length))
  const invalid = (label: string, input: J): void => {
    const value = 'utf16_hex' in input ? fromUtf16(input.utf16_hex as string) : input.value
    cases.add(
      'P1',
      'canonical',
      label,
      input,
      outcome(() => canonical(value as CanonicalValue)),
    )
  }
  for (let i = 0; i < 60; i++) {
    const f = int(1000) + (int(999) + 1) / 1000
    invalid('fraction', { value: i % 2 === 0 ? f : [randomString(), f] })
  }
  for (let i = 0; i < 50; i++) invalid('negative', { value: i % 2 === 0 ? -(int(1000) + 1) : [-int53() - 1] })
  for (const v of [2 ** 53, 2 ** 53 + 2, 2 ** 60, 1e21, 1.7976931348623157e308])
    invalid('too-big', { value: v })
  for (let i = 0; i < 25; i++) invalid('too-big', { value: [2 ** 53 + 2 * int(1000)] })
  for (let i = 0; i < 40; i++)
    invalid('boolean', { value: nested(int(4), (i % 2 === 0) as unknown as CanonicalValue) })
  for (let i = 0; i < 50; i++)
    invalid('object', {
      value: nested(int(3), (i % 2 === 0 ? {} : { a: randomInt() }) as unknown as CanonicalValue),
    })
  for (let i = 0; i < 69; i++) {
    const lone = String.fromCharCode((i % 2 === 0 ? 0xd800 : 0xdc00) + int(0x400))
    const s = i % 3 === 0 ? lone : `${pick(ALPHABET)}${lone}${pick(ALPHABET)}`
    invalid('lone-surrogate', { utf16_hex: utf16Hex(s) })
  }
  const sparse: CanonicalValue[] = ['a']
  sparse[2] = 'b'
  cases.add(
    'P1',
    'canonical',
    'sparse-list',
    {
      sparse_list: {
        length: 3,
        items: [
          [0, 'a'],
          [2, 'b'],
        ],
      },
    },
    outcome(() => canonical(sparse)),
  )
  return fileOf(
    'P1: differential cases of the canonical form (spec/SPEC.md §2). 2,000 valid values, each with the canonical string the TypeScript core writes and its SHA-256: every escape class of §2.2, U+0000 to U+001F, U+007F, U+2028, U+2029, non-ASCII, surrogate pairs, 0, 1 and 2^53 - 1, null, lists to depth 8, and 200 real hop, record, envelope-id and sealed-hash preimages. 300 invalid ones: fractions, negatives, integers from 2^53, booleans, objects, lone surrogates (utf16_hex) and one sparse list.',
    cases,
  )
}

function fromUtf16(hex: string): string {
  let s = ''
  for (let i = 0; i < hex.length; i += 4) s += String.fromCharCode(Number.parseInt(hex.slice(i, i + 4), 16))
  return s
}

// ---- envelope-mutations.json (F1, F2, F8, F9, D6, P2, P3, R2) -------------------------------------------------

const HEX_REGIONS = new Set([
  'id',
  'to',
  'from',
  'auth.iss',
  'auth.sub',
  'auth.sig',
  'wraps.to',
  'wraps.enc',
  'wraps.ct',
  'nonce',
  'sealed.ct',
  'sig',
])

/** The region of each byte of the serialized envelope, from a serializer that mirrors serializeEnvelope. */
function regions(e: Envelope, bytes: Uint8Array): string[] {
  const parts: [string, string][] = []
  const put = (t: string, region: string): void => {
    parts.push([t, region])
  }
  const str = (s: string, region: string): void => {
    put('"', 'syntax')
    put(s, region)
    put('"', 'syntax')
  }
  const strs = (items: readonly string[], region: string): void => {
    put('[', 'syntax')
    items.forEach((s, i) => {
      if (i > 0) put(',', 'syntax')
      str(s, region)
    })
    put(']', 'syntax')
  }
  put('{"v":', 'syntax')
  put(String(e.v), 'v')
  put(',"id":', 'syntax')
  str(e.id, 'id')
  put(',"to":', 'syntax')
  strs(e.to, 'to')
  put(',"from":', 'syntax')
  str(e.from, 'from')
  put(',"auth":[', 'syntax')
  e.auth.forEach((h, i) => {
    put(i > 0 ? ',{"iss":' : '{"iss":', 'syntax')
    str(h.iss, 'auth.iss')
    put(',"sub":', 'syntax')
    str(h.sub, 'auth.sub')
    put(',"caveats":', 'syntax')
    strs(h.caveats, 'auth.caveats')
    put(',"exp":', 'syntax')
    put(String(h.exp), 'auth.exp')
    put(',"sig":', 'syntax')
    str(h.sig, 'auth.sig')
    put('}', 'syntax')
  })
  put('],"suite":', 'syntax')
  put(String(e.suite), 'suite')
  put(',"ts":', 'syntax')
  put(String(e.ts), 'ts')
  put(',"sealed":{"wraps":[', 'syntax')
  e.sealed.wraps.forEach((w, i) => {
    put(i > 0 ? ',{"to":' : '{"to":', 'syntax')
    str(w.to, 'wraps.to')
    put(',"enc":', 'syntax')
    str(w.enc, 'wraps.enc')
    put(',"ct":', 'syntax')
    str(w.ct, 'wraps.ct')
    put('}', 'syntax')
  })
  put('],"nonce":', 'syntax')
  str(e.sealed.nonce, 'nonce')
  put(',"ct":', 'syntax')
  str(e.sealed.ct, 'sealed.ct')
  put('},"sig":', 'syntax')
  str(e.sig, 'sig')
  put('}', 'syntax')
  if (parts.map((p) => p[0]).join('') !== text(bytes)) {
    throw new Error('gen-adversarial: the region map does not reproduce the envelope bytes')
  }
  const out: string[] = []
  for (const [t, region] of parts) for (const _ of utf8(t)) out.push(region)
  return out
}

const NEXT_HEX: Record<string, string> = Object.fromEntries(
  [...'0123456789abcdef'].map((c, i) => [c, at([...'0123456789abcdef'], (i + 1) % 16)]),
)

export interface F1Summary {
  envelopes: number
  mutations: number
  verdicts: Record<string, number>
  kept: number
}

function f1(cast: Cast, cases: Cases): F1Summary {
  const built = Array.from({ length: F1_ENVELOPES }, (_, i) => envelope(cast, 1 + (i % 16), i % 9))
  for (const [i, b] of built.entries()) controlOk(`F1 envelope ${i}`, outerVerdict(b.bytes))
  const order = built.map((b, i) => [b, i] as const).sort((x, y) => x[0].bytes.length - y[0].bytes.length)
  const summary: F1Summary = { envelopes: built.length, mutations: 0, verdicts: {}, kept: 0 }
  const kept = new Map<string, number>()
  const consider = (key: string, label: string, mutated: Uint8Array, verdict: string): void => {
    summary.mutations++
    summary.verdicts[verdict] = (summary.verdicts[verdict] ?? 0) + 1
    const n = kept.get(key) ?? 0
    if (n >= F1_KEEP && verdict !== 'ok') return
    kept.set(key, n + 1)
    summary.kept++
    cases.add('F1', 'outer', label, { bytes_hex: toHex(mutated), now: NOW, ttl: TTL, skew: SKEW }, verdict)
  }
  for (const [b, index] of order) {
    const region = regions(b.envelope, b.bytes)
    const m = Uint8Array.from(b.bytes)
    for (let p = 0; p < m.length; p++) {
      const original = m[p] as number
      const mask = 1 << (p % 8)
      m[p] = original ^ mask
      if (m[p] === original) throw new Error('gen-adversarial: an F1 flip leaves the byte unchanged')
      const r = at(region, p)
      const verdict = outerVerdict(m)
      consider(`flip:${r}:${verdict}`, `env${index}-flip-${p}-x${mask.toString(16)}-${r}`, m, verdict)
      m[p] = original
    }
    for (let p = 0; p < m.length; p++) {
      const r = at(region, p)
      const ch = String.fromCharCode(m[p] as number)
      const next = NEXT_HEX[ch]
      if (!HEX_REGIONS.has(r) || next === undefined) continue
      const original = m[p] as number
      m[p] = next.charCodeAt(0)
      if (m[p] === original)
        throw new Error('gen-adversarial: an F1 hex substitution leaves the byte unchanged')
      const verdict = outerVerdict(m)
      consider(`hex:${r}:${verdict}`, `env${index}-hex-${p}-${r}`, m, verdict)
      m[p] = original
    }
  }
  return summary
}

function outerCase(
  cases: Cases,
  line: string,
  label: string,
  bytes: Uint8Array,
  now = NOW,
  allowed?: J,
): void {
  cases.add(
    line,
    'outer',
    label,
    { bytes_hex: toHex(bytes), now, ttl: TTL, skew: SKEW },
    outerVerdict(bytes, now),
    allowed,
  )
}

function envelopeFile(cast: Cast): { file: J; f1: F1Summary } {
  const cases = new Cases()
  const summary = f1(cast, cases)

  // F2: the sealed part re-signed by an attacker, chain [] (the open half is in open-cases.json).
  for (const nTo of [1, 2, 5]) {
    const b = envelope(cast, nTo, 2)
    controlOk('F2 base', outerVerdict(b.bytes))
    const forged = resigned(b.envelope, cast.attacker, (u) => {
      u.from = cast.attacker.address
      u.auth = []
    })
    differs('F2', forged, b.bytes)
    outerCase(cases, 'F2', `resigned-by-attacker-${nTo}-recipients`, forged)
  }

  // F8: wraps swapped between two recipients.
  {
    const b = envelope(cast, 2, 1)
    controlOk('F8 base', outerVerdict(b.bytes))
    const swap = (u: J): void => {
      const w = list(obj(u.sealed).wraps).map(obj)
      const [w0, w1] = [at(w, 0), at(w, 1)]
      ;[w0.enc, w1.enc] = [w1.enc, w0.enc]
      ;[w0.ct, w1.ct] = [w1.ct, w0.ct]
    }
    const a = edited(b.envelope, swap)
    differs('F8a', a, b.bytes)
    outerCase(cases, 'F8', 'wraps-swapped-id-kept', a)
    const s = resigned(b.envelope, b.from, swap)
    outerCase(cases, 'F8', 'wraps-swapped-resigned-by-sender', s)
  }

  // F9: the recipient list changed.
  {
    const b = envelope(cast, 3, 1)
    controlOk('F9 base', outerVerdict(b.bytes))
    const extra = cast.parties.find((p) => !b.envelope.to.includes(p.address)) as Party
    const variants: [string, (u: J) => void][] = [
      ['to-one-added', (u) => list(u.to).push(extra.address)],
      ['to-one-dropped', (u) => list(u.to).pop()],
      [
        'to-two-reordered',
        (u) => {
          const t = list(u.to)
          ;[t[0], t[1]] = [t[1], t[0]]
        },
      ],
      ['to-one-duplicated', (u) => list(u.to).splice(1, 1, at(list(u.to), 0))],
    ]
    for (const [label, f] of variants) {
      const m = edited(b.envelope, f)
      differs(label, m, b.bytes)
      outerCase(cases, 'F9', label, m)
    }
    const matched: [string, (u: J) => void][] = [
      [
        'to-and-wraps-one-dropped',
        (u) => {
          list(u.to).pop()
          list(obj(u.sealed).wraps).pop()
        },
      ],
      [
        'to-and-wraps-reordered',
        (u) => {
          const t = list(u.to)
          const w = list(obj(u.sealed).wraps)
          ;[t[0], t[1]] = [t[1], t[0]]
          ;[w[0], w[1]] = [w[1], w[0]]
        },
      ],
      [
        'to-and-wraps-one-added',
        (u) => {
          list(u.to).push(extra.address)
          list(obj(u.sealed).wraps).push({ ...obj(at(list(obj(u.sealed).wraps), 0)), to: extra.address })
        },
      ],
    ]
    for (const [label, f] of matched) {
      const m = edited(b.envelope, f)
      differs(label, m, b.bytes)
      outerCase(cases, 'F9', label, m)
    }
    const big = envelope(cast, 16, 0)
    const seventeen = edited(big.envelope, (u) => {
      const p = cast.parties.find((q) => !big.envelope.to.includes(q.address)) as Party
      list(u.to).push(p.address)
      list(obj(u.sealed).wraps).push({ ...obj(at(list(obj(u.sealed).wraps), 0)), to: p.address })
    })
    outerCase(cases, 'F9', 'seventeen-recipients', seventeen)
  }

  // D6: duplicate members in the envelope (the last value is the one TypeScript keeps).
  {
    const b = envelope(cast, 2, 1)
    controlOk('D6 base', outerVerdict(b.bytes))
    const t = text(b.bytes)
    const e = b.envelope
    const badId = e.id.slice(0, -1) + NEXT_HEX[e.id.slice(-1)]
    const hop = at(e.auth, 0)
    const dup: [string, string, string][] = [
      ['two-id-valid-first', `"id":"${e.id}"`, `"id":"${e.id}","id":"${badId}"`],
      ['two-id-valid-last', `"id":"${e.id}"`, `"id":"${badId}","id":"${e.id}"`],
      ['two-ts-valid-last', `"ts":${e.ts}`, `"ts":${e.ts + 1},"ts":${e.ts}`],
      ['two-ts-valid-first', `"ts":${e.ts}`, `"ts":${e.ts},"ts":${e.ts + 1}`],
      ['hop-two-exp-valid-last', `"exp":${hop.exp}`, `"exp":${hop.exp + 1},"exp":${hop.exp}`],
      ['hop-two-exp-valid-first', `"exp":${hop.exp}`, `"exp":${hop.exp},"exp":${hop.exp + 1}`],
    ]
    for (const [label, from, to] of dup) {
      const m = utf8(replaceOnce(t, from, to))
      differs(label, m, b.bytes)
      outerCase(cases, 'D6', label, m)
    }
  }

  // P2: number spellings of v, suite, ts and a hop's exp.
  for (const [spelling, reads] of SPELLINGS) {
    const x = reads ?? 1
    const label = spellingLabel(spelling)
    {
      const b = envelope(cast, 1, 0)
      controlOk('P2 v base', outerVerdict(b.bytes))
      const m = utf8(replaceOnce(text(b.bytes), '{"v":1,', `{"v":${spelling},`))
      outerCase(cases, 'P2', `v-${label}`, m, NOW)
      const s = utf8(replaceOnce(text(b.bytes), '"suite":1,', `"suite":${spelling},`))
      outerCase(cases, 'P2', `suite-${label}`, s, NOW)
    }
    {
      const b = envelope(cast, 1, 0, x)
      const now = x === MAX ? MAX : x + 60
      controlOk('P2 ts base', outerVerdict(b.bytes, now))
      const m = utf8(replaceOnce(text(b.bytes), `"ts":${x},`, `"ts":${spelling},`))
      outerCase(cases, 'P2', `ts-${label}`, m, now)
    }
    {
      const to = [pick(cast.parties)]
      const from = pick(cast.signers)
      const hop = signHop(
        at(cast.signers, 0) === from ? at(cast.signers, 1) : at(cast.signers, 0),
        from.address,
        [],
        x,
      )
      const b = buildEnvelope({
        from,
        to: to.map((p) => ({ address: p.address, sealingKey: p.seal.publicKey })),
        auth: [hop],
        ...content(),
        ts: 0,
        rng,
      })
      controlOk('P2 exp base', outerVerdict(b.bytes, 60))
      const m = utf8(replaceOnce(text(b.bytes), `"exp":${x},`, `"exp":${spelling},`))
      outerCase(cases, 'P2', `hop-exp-${label}`, m, 60)
    }
  }

  // R2: the ts window at its bounds, and at 0 and 2^53 - 1.
  {
    const b = envelope(cast, 1, 0)
    controlOk('R2 base', outerVerdict(b.bytes))
    const ts = b.envelope.ts
    for (const [label, now] of [
      ['stale-by-one', ts + TTL + SKEW + 1],
      ['stale-bound', ts + TTL + SKEW],
      ['future-bound', ts - SKEW],
      ['future-by-one', ts - SKEW - 1],
    ] as const)
      outerCase(cases, 'R2', label, b.bytes, now)
    const zero = envelope(cast, 1, 0, 0)
    outerCase(cases, 'R2', 'ts-0-now-t0', zero.bytes, NOW)
    outerCase(cases, 'R2', 'ts-0-now-60', zero.bytes, 60)
    outerCase(cases, 'R2', 'ts-0-now-0', zero.bytes, 0)
    const max = envelope(cast, 1, 0, MAX)
    outerCase(cases, 'R2', 'ts-max-now-t0', max.bytes, NOW)
    outerCase(cases, 'R2', 'ts-max-now-max', max.bytes, MAX)
  }

  // P3: bytes that are not JSON text, through the JSON reader alone and through envelope parsing.
  {
    const b = envelope(cast, 1, 0)
    const t = text(b.bytes)
    const id = b.envelope.id
    const inject = (raw: number[]): Uint8Array => {
      const before = utf8(t.slice(0, t.indexOf(id)))
      const after = utf8(t.slice(t.indexOf(id) + 2))
      return Uint8Array.from([...before, ...raw, ...after])
    }
    const inputs: [string, Uint8Array][] = [
      ['bom', Uint8Array.from([0xef, 0xbb, 0xbf, ...b.bytes])],
      ['overlong-c0-80', inject([0xc0, 0x80])],
      ['lone-continuation-80', inject([0x80, 0x30])],
      ['truncated-three-byte', inject([0xe2, 0x82])],
      ['utf8-high-surrogate-ed-a0-80', inject([0xed, 0xa0, 0x80])],
      ['utf8-low-surrogate-ed-b0-80', inject([0xed, 0xb0, 0x80])],
      [
        'escaped-high-surrogate-in-value',
        utf8(replaceOnce(t, `"id":"${id}"`, `"id":"\\ud800${id.slice(6)}"`)),
      ],
      [
        'escaped-low-surrogate-in-value',
        utf8(replaceOnce(t, `"id":"${id}"`, `"id":"\\udc00${id.slice(6)}"`)),
      ],
      ['escaped-surrogate-in-name', utf8(replaceOnce(t, '{"v":1,', '{"v":1,"\\ud800":0,'))],
      ['escaped-low-surrogate-in-name', utf8(replaceOnce(t, '{"v":1,', '{"v":1,"x\\udc00":0,'))],
      ['two-values', utf8(`${t} ${t}`)],
      ['trailing-garbage', utf8(`${t}x`)],
      ['trailing-nul', Uint8Array.from([...b.bytes, 0])],
      ['raw-nul-in-string', inject([0x00, 0x30])],
      ['empty', new Uint8Array(0)],
      ['whitespace-only', utf8(' \n')],
      ['null', utf8('null')],
      ['empty-list', utf8('[]')],
      ['number', utf8('1')],
      ['string', utf8('"x"')],
      ['nan', utf8('NaN')],
      ['single-quoted', utf8(t.replace(/"/g, "'"))],
    ]
    for (const [label, bytes] of inputs) {
      cases.add('P3', 'json', label, { bytes_hex: toHex(bytes) }, jsonVerdict(bytes))
      cases.add('P3', 'parse', label, { bytes_hex: toHex(bytes) }, parseVerdict(bytes))
    }
  }

  return {
    file: fileOf(
      `Envelope mutations. F1: every byte of ${F1_ENVELOPES} envelopes (1 to 16 recipients, 0 to 8 hops) flipped at bit (position mod 8), and every hex character of their hex fields replaced by the next hex digit: ${summary.mutations} mutations, kept here per (pass, region, verdict), at most ${F1_KEEP} each, smallest envelopes first, plus any that verified ok. F2: the sealed part re-signed by another key. F8: wraps swapped between recipients. F9: the recipient list changed. D6: duplicate members. P2: number spellings of v, suite, ts and a hop's exp. R2: ts at the window's bounds. P3: bytes that are not JSON text, through the JSON reader alone and through envelope parsing.`,
      cases,
    ),
    f1: summary,
  }
}

// ---- chain-mutations.json (F3 to F7) ----------------------------------------------------------------------------

function chainCase(cases: Cases, line: string, label: string, auth: unknown, from: string, ts: number): void {
  cases.add(line, 'chain', label, { auth, from, ts }, chainVerdict(auth, from, ts))
}

function hopsJ(hops: readonly Hop[]): J[] {
  return hops.map((h) => ({ iss: h.iss, sub: h.sub, caveats: [...h.caveats], exp: h.exp, sig: h.sig }))
}

/** A hop under a degenerate key: the degenerate signature, its exp ground so that k is 0 mod 8 when asked. */
function degenerateHop(iss: string, sub: string, caveats: string[], exp0: number, grind: boolean): J {
  for (let exp = exp0; exp < exp0 + 4096; exp++) {
    const h = { iss, sub, caveats, exp }
    const digest = fromHex(sha256hex(canonical(hopPreimage(h))), 32)
    if (!grind || ground(iss.slice(8), digest)) return { ...h, sig: DEGENERATE_SIG }
  }
  throw new Error('gen-adversarial: no ground exp found')
}

function chainFile(cast: Cast): { file: J; preimages: CanonicalValue[] } {
  const cases = new Cases()
  const preimages: CanonicalValue[] = []
  const ts = T0
  const chains: { hops: Hop[]; from: SigningKey }[] = []
  for (let n = 2; n <= 8; n++) {
    for (let k = 0; k < 2; k++) {
      const from = pick(cast.parties).key
      const hops = chainTo(cast, from, n, ts)
      controlOk(`chain of ${n}`, chainVerdict(hopsJ(hops), from.address, ts))
      chains.push({ hops, from })
      for (const h of hops) preimages.push(hopPreimage(h))
    }
  }

  // F3: hops swapped, reversed, rotated.
  for (const [ci, { hops, from }] of chains.entries()) {
    const n = hops.length
    for (let i = 0; i + 1 < n; i++) {
      const s = [...hops]
      ;[s[i], s[i + 1]] = [s[i + 1] as Hop, s[i] as Hop]
      chainCase(cases, 'F3', `c${ci}-n${n}-swap-${i}`, hopsJ(s), from.address, ts)
    }
    chainCase(cases, 'F3', `c${ci}-n${n}-reverse`, hopsJ([...hops].reverse()), from.address, ts)
    for (let r = 1; r < n; r++) {
      chainCase(
        cases,
        'F3',
        `c${ci}-n${n}-rotate-${r}`,
        hopsJ([...hops.slice(r), ...hops.slice(0, r)]),
        from.address,
        ts,
      )
    }
  }

  // F4: a caveat dropped, appended or edited by a byte, the hop's sig kept.
  for (const [ci, { hops, from }] of chains.slice(0, 9).entries()) {
    for (let i = 0; i < hops.length; i++) {
      const h = at(hops, i)
      const variants: [string, string[]][] = [['append', [...h.caveats, 'type=anything.*']]]
      if (h.caveats.length > 0) {
        variants.push(['drop', h.caveats.slice(1)])
        const c = at(h.caveats, 0)
        variants.push([
          'edit-byte',
          [`${c.slice(0, -1)}${c.endsWith('*') ? 'x' : '*'}`, ...h.caveats.slice(1)],
        ])
      }
      for (const [label, caveats] of variants) {
        const s = hopsJ(hops)
        at(s, i).caveats = caveats
        chainCase(cases, 'F4', `c${ci}-hop${i}-${label}`, s, from.address, ts)
      }
    }
  }

  // F5: one hop's exp raised.
  for (const [ci, { hops, from }] of chains.slice(0, 9).entries()) {
    for (let i = 0; i < hops.length; i++) {
      for (const [label, exp] of [
        ['plus-1', at(hops, i).exp + 1],
        ['plus-day', at(hops, i).exp + DAY],
        ['max', MAX],
      ] as const) {
        const s = hopsJ(hops)
        at(s, i).exp = exp
        chainCase(cases, 'F5', `c${ci}-hop${i}-${label}`, s, from.address, ts)
      }
    }
  }

  // F6: a self-rooted attacker posing as a principal.
  {
    const a = cast.attacker
    const { hops } = at(chains, 0)
    const root = at(hops, 0)
    chainCase(cases, 'F6', 'a-empty-chain-from-attacker', [], a.address, ts)
    const posing = { iss: root.iss, sub: a.address, caveats: [], exp: ts + DAY }
    chainCase(
      cases,
      'F6',
      'b-hop-from-root-signed-by-attacker',
      [{ ...posing, sig: signPreimage(a, hopPreimage(posing)) }],
      a.address,
      ts,
    )
    const tail = { iss: root.sub, sub: a.address, caveats: [], exp: root.exp }
    chainCase(
      cases,
      'F6',
      'c-genuine-hop-then-attacker-hop',
      [hopsJ([root])[0], { ...tail, sig: signPreimage(a, hopPreimage(tail)) }],
      a.address,
      ts,
    )
  }

  // F7(a): S + L on hop signatures.
  for (const [ci, { hops, from }] of chains.slice(0, 7).entries()) {
    for (let i = 0; i < hops.length; i++) {
      const s = hopsJ(hops)
      at(s, i).sig = plusL(at(hops, i).sig)
      chainCase(cases, 'F7', `a-c${ci}-hop${i}-s-plus-l`, s, from.address, ts)
    }
  }

  // F7(b), F7(c): degenerate and non-canonical keys as a hop's iss, arbitrary and ground digests.
  {
    const from = pick(cast.parties).key
    for (const [label, pub] of [...SMALL_ORDER, ...NON_CANONICAL]) {
      const line = (SMALL_ORDER as readonly (readonly [string, string])[]).some((s) => s[1] === pub)
        ? 'b'
        : 'c'
      for (const grind of [false, true]) {
        const h = degenerateHop(`ed25519:${pub}`, from.address, ['type=coding.*'], ts + DAY, grind)
        chainCase(cases, 'F7', `${line}-hop-iss-${label}${grind ? '-ground' : ''}`, [h], from.address, ts)
      }
    }
  }

  // F7 on the envelope: S + L on the outer sig, and a degenerate or non-canonical `from`.
  {
    const b = envelope(cast, 2, 2)
    controlOk('F7 envelope base', outerVerdict(b.bytes))
    const m = edited(b.envelope, (u) => {
      u.sig = plusL(b.envelope.sig)
    })
    differs('F7a envelope', m, b.bytes)
    outerCase(cases, 'F7', 'a-envelope-sig-s-plus-l', m)
    const hopMalleated = resigned(b.envelope, b.from, (u) => {
      const h = obj(at(list(u.auth), 0))
      h.sig = plusL(h.sig as string)
    })
    outerCase(cases, 'F7', 'a-hop-sig-s-plus-l-resigned', hopMalleated)
    const to = shuffled(cast.parties).slice(0, 2)
    for (const [label, pub] of [...SMALL_ORDER, ...NON_CANONICAL]) {
      const line = (SMALL_ORDER as readonly (readonly [string, string])[]).some((s) => s[1] === pub)
        ? 'b'
        : 'c'
      const from = `ed25519:${pub}`
      const sealed = sealTo(
        to.map((p) => ({ address: p.address, sealingKey: p.seal.publicKey })),
        from,
        content(),
        rng,
      )
      for (const grind of [false, true]) {
        let found: Uint8Array | undefined
        for (let t = T0; t < T0 + 300 && found === undefined; t++) {
          const unsigned = {
            v: 1,
            to: to.map((p) => p.address),
            from,
            auth: [],
            suite: 1,
            ts: t,
            sealed,
          } as const
          const id = envelopeId(unsigned)
          if (grind && !ground(pub, fromHex(id, 32))) continue
          found = serializeEnvelope({ ...unsigned, id, sig: DEGENERATE_SIG })
        }
        if (found === undefined) throw new Error('gen-adversarial: no ground ts found')
        outerCase(cases, 'F7', `${line}-envelope-from-${label}${grind ? '-ground' : ''}`, found)
      }
    }
    preimages.push(envelopeIdPreimage(b.envelope), sealedHashPreimage(b.envelope.sealed))
  }

  return {
    file: fileOf(
      'Chain mutations (spec/SPEC.md §6.2), from chains of 2 to 8 hops that verify. F3: hops swapped, reversed, rotated. F4: a caveat dropped, appended or edited, the sig kept. F5: one exp raised. F6: an attacker posing as a principal. F7: (a) S + L on hop and envelope signatures; (b) the eight small-order Ed25519 points as a hop iss and as an envelope from, with R the identity and S = 0, over an arbitrary digest and over one ground so that the challenge k is 0 mod 8; (c) non-canonical encodings (y + p) of the identity and of the order-4 point, likewise.',
      cases,
    ),
    preimages,
  }
}

// ---- record-mutations.json (D1, D3, D4, D5, D6, P2, F7) ---------------------------------------------------------

/** Signs any record object over its preimage, form unchecked, so a record can break its form and keep a good sig. */
function signLoose(key: SigningKey, r: J): J {
  return { ...r, sig: signPreimage(key, recordPreimage(r as unknown as AcRecord)) }
}

function recordBytes(r: J): Uint8Array {
  return utf8(JSON.stringify(r))
}

function recordCase(
  cases: Cases,
  line: string,
  label: string,
  bytes: Uint8Array,
  now = NOW,
  allowed?: J,
): void {
  cases.add(
    line,
    'record',
    label,
    { bytes_hex: toHex(bytes), now, skew: SKEW },
    recordVerdict(bytes, now),
    allowed,
  )
}

function addressRecord(cast: Cast, key: SigningKey, over: J = {}): J {
  const base: J = {
    kind: 'address',
    key: key.address,
    sealing_key: toHex(pick(cast.parties).seal.publicKey),
    relays: ['https://relay.example'],
    rotation_key: null,
    revoked: [at(cast.signers, 5).address],
    ttl: DAY,
    iat: T0,
    rotated_from: null,
    rotation_sig: null,
    ...over,
  }
  return signLoose(key, base)
}

function recordFile(cast: Cast): { file: J; preimages: CanonicalValue[] } {
  const cases = new Cases()
  const preimages: CanonicalValue[] = []
  const owner = at(cast.signers, 10)
  const addr = addressRecord(cast, owner)
  controlOk('address record', recordVerdict(recordBytes(addr)))
  const accept = signLoose(owner, {
    kind: 'accept-from',
    owner: owner.address,
    roots: [at(cast.signers, 0).address],
    max_bytes: 65_536,
    ttl: TTL,
    iat: T0,
  })
  controlOk('accept-from record', recordVerdict(recordBytes(accept)))
  // A key record lives a day at most since 2026-10-25: exp was T0 + 30 days.
  const keyRec = signLoose(owner, {
    kind: 'key',
    key: owner.address,
    sealing_key: toHex(pick(cast.parties).seal.publicKey),
    iat: T0,
    exp: T0 + DAY,
  })
  controlOk('key record', recordVerdict(recordBytes(keyRec)))
  for (const r of [addr, accept, keyRec]) preimages.push(recordPreimage(r as unknown as AcRecord))

  // D3: the address record's validity window and the key record's exp.
  for (const [label, iat] of [
    ['iat-now-minus-ttl-plus-1', NOW - DAY + 1],
    ['iat-now-minus-ttl', NOW - DAY],
    ['iat-now-minus-ttl-minus-1', NOW - DAY - 1],
    ['iat-now-plus-skew', NOW + SKEW],
    ['iat-now-plus-skew-plus-1', NOW + SKEW + 1],
  ] as const)
    recordCase(cases, 'D3', `address-${label}`, recordBytes(addressRecord(cast, owner, { iat })))
  for (const [label, exp] of [
    ['exp-now', NOW],
    ['exp-now-minus-1', NOW - 1],
  ] as const) {
    // iat was T0 - DAY until 2026-10-25: NOW - DAY keeps each record within a day of its iat.
    const r = signLoose(owner, { ...keyRec, iat: NOW - DAY, exp })
    recordCase(cases, 'D3', `key-${label}`, recordBytes(r))
  }

  // D4: caps and bounds.
  const manyRelays = Array.from({ length: 65 }, (_, i) => `https://relay${i}.example`)
  const revoked = Array.from({ length: 1025 }, (_, i) => `ed25519:${sha256hex(`revoked ${i}`)}`)
  recordCase(cases, 'D4', 'address-ttl-0', recordBytes(addressRecord(cast, owner, { ttl: 0 })))
  recordCase(cases, 'D4', 'address-ttl-86401', recordBytes(addressRecord(cast, owner, { ttl: DAY + 1 })))
  recordCase(cases, 'D4', 'address-ttl-86400', recordBytes(addressRecord(cast, owner, { ttl: DAY })))
  recordCase(
    cases,
    'D4',
    'address-8-relays',
    recordBytes(addressRecord(cast, owner, { relays: manyRelays.slice(0, 8) })),
  )
  recordCase(
    cases,
    'D4',
    'address-65-relays',
    recordBytes(addressRecord(cast, owner, { relays: manyRelays })),
  )
  recordCase(
    cases,
    'D4',
    'address-1024-revoked',
    recordBytes(addressRecord(cast, owner, { revoked: revoked.slice(0, 1024) })),
  )
  recordCase(cases, 'D4', 'address-1025-revoked', recordBytes(addressRecord(cast, owner, { revoked })))
  recordCase(cases, 'D4', 'accept-ttl-max', recordBytes(signLoose(owner, { ...accept, ttl: MAX })))
  recordCase(cases, 'D4', 'accept-max-bytes-0', recordBytes(signLoose(owner, { ...accept, max_bytes: 0 })))
  recordCase(cases, 'D4', 'key-exp-before-iat', recordBytes(signLoose(owner, { ...keyRec, exp: T0 - 1 })))

  // D5: hostile relay URLs (the form half).
  for (const [label, url] of [
    ['javascript', 'javascript:alert(1)'],
    ['ftp', 'ftp://relay.example/'],
    ['http-with-space', 'http://relay example/'],
    ['http-empty-host', 'http:///'],
    ['http-userinfo', 'http://user:pw@relay.example/'],
    ['http-loopback', 'http://127.0.0.1:8080/'],
    ['http-link-local-metadata', 'http://169.254.169.254/'],
    ['https-ipv6-loopback', 'https://[::1]:8443/'],
    ['http-tab', 'http://relay.example/\t'],
    ['http-del', 'http://relay.example/\u007f'],
    ['http-c1-control', 'http://relay.example/\u0085'],
    ['upper-case-scheme', 'HTTP://relay.example/'],
  ] as const)
    recordCase(cases, 'D5', `relay-${label}`, recordBytes(addressRecord(cast, owner, { relays: [url] })))

  // D6: duplicate members in a record.
  {
    const t = text(recordBytes(addr))
    for (const [label, to] of [
      ['two-ttl-valid-last', `"ttl":0,"ttl":${DAY}`],
      ['two-ttl-valid-first', `"ttl":${DAY},"ttl":0`],
      ['two-ttl-both-valid-other-last', `"ttl":${DAY},"ttl":${DAY - 1}`],
    ] as const) {
      const m = utf8(replaceOnce(t, `"ttl":${DAY}`, to))
      recordCase(cases, 'D6', label, m)
    }
    const s = addr.sig as string
    const otherSig = plusL(s)
    recordCase(
      cases,
      'D6',
      'two-sig-valid-last',
      utf8(replaceOnce(t, `"sig":"${s}"`, `"sig":"${otherSig}","sig":"${s}"`)),
    )
    recordCase(
      cases,
      'D6',
      'two-sig-valid-first',
      utf8(replaceOnce(t, `"sig":"${s}"`, `"sig":"${s}","sig":"${otherSig}"`)),
    )
  }

  // P2: spellings of an address record's iat, an accept-from record's ttl and a key record's exp.
  for (const [spelling, reads] of SPELLINGS) {
    const x = reads ?? 1
    const label = spellingLabel(spelling)
    {
      const r = addressRecord(cast, owner, { iat: x })
      const now = x === MAX ? MAX : x + 10
      controlOk('P2 iat base', recordVerdict(recordBytes(r), now))
      const m = utf8(replaceOnce(text(recordBytes(r)), `"iat":${x},`, `"iat":${spelling},`))
      recordCase(cases, 'P2', `address-iat-${label}`, m, now)
    }
    {
      const ttl = x === 0 ? 1 : x
      const r = signLoose(owner, { ...accept, ttl })
      controlOk('P2 ttl base', recordVerdict(recordBytes(r)))
      const m = utf8(replaceOnce(text(recordBytes(r)), `"ttl":${ttl},`, `"ttl":${spelling},`))
      recordCase(cases, 'P2', `accept-ttl-${label}`, m, NOW)
    }
    {
      // A key record lives a day at most: for the largest spelling, iat follows exp (it was 0).
      const iat = Math.max(0, x - DAY)
      const r = signLoose(owner, { ...keyRec, iat, exp: x })
      controlOk('P2 exp base', recordVerdict(recordBytes(r), iat))
      const m = utf8(replaceOnce(text(recordBytes(r)), `"exp":${x},`, `"exp":${spelling},`))
      recordCase(cases, 'P2', `key-exp-${label}`, m, iat)
    }
  }

  // F7: S + L on a record sig; degenerate and non-canonical keys as a record's key.
  recordCase(cases, 'F7', 'a-address-sig-s-plus-l', recordBytes({ ...addr, sig: plusL(addr.sig as string) }))
  for (const [label, pub] of [...SMALL_ORDER, ...NON_CANONICAL]) {
    const line = (SMALL_ORDER as readonly (readonly [string, string])[]).some((s) => s[1] === pub) ? 'b' : 'c'
    for (const grind of [false, true]) {
      let found: J | undefined
      for (let iat = NOW; iat > NOW - 4096 && found === undefined; iat--) {
        const r: J = { ...addr, key: `ed25519:${pub}`, iat, sig: DEGENERATE_SIG }
        const digest = fromHex(sha256hex(canonical(recordPreimage(r as unknown as AcRecord))), 32)
        if (!grind || ground(pub, digest)) found = r
      }
      if (found === undefined) throw new Error('gen-adversarial: no ground iat found')
      recordCase(cases, 'F7', `${line}-address-key-${label}${grind ? '-ground' : ''}`, recordBytes(found))
    }
  }

  // D1: rotations.
  {
    const prevKey = at(cast.signers, 11)
    const rotationKey = at(cast.signers, 12)
    const nextKey = at(cast.signers, 13)
    const unrelated = at(cast.signers, 14)
    const prev = addressRecord(cast, prevKey, { rotation_key: rotationKey.address })
    const next = addressRecord(cast, nextKey, { rotated_from: prevKey.address, iat: T0 + 1 })
    const countersigned = (k: SigningKey, r: J): J => ({
      ...r,
      rotation_sig: signPreimage(k, recordPreimage(r as unknown as AcRecord)),
    })
    const rot = (label: string, n: J): void => {
      const pb = recordBytes(prev)
      const nb = recordBytes(n)
      cases.add(
        'D1',
        'rotation',
        label,
        { prev_bytes_hex: toHex(pb), next_bytes_hex: toHex(nb) },
        rotationVerdict(pb, nb),
      )
    }
    const byPrev = countersigned(prevKey, next)
    controlOk('D1 rotation by the previous key', rotationVerdict(recordBytes(prev), recordBytes(byPrev)))
    rot('countersigned-by-previous-key', byPrev)
    rot('countersigned-by-rotation-key', countersigned(rotationKey, next))
    rot('rotation-sig-null', next)
    rot('rotation-sig-by-unrelated-key', countersigned(unrelated, next))
    rot('rotation-sig-s-plus-l', { ...byPrev, rotation_sig: plusL(byPrev.rotation_sig as string) })
    rot('rotated-from-other-key', countersigned(prevKey, { ...next, rotated_from: unrelated.address }))
    rot('rotation-sig-by-new-key-itself', countersigned(nextKey, next))
  }

  return {
    file: fileOf(
      'Record mutations (spec/SPEC.md §7). D1: rotations without a valid countersignature. D3: the validity window. D4: caps and bounds. D5: hostile relay URLs, the form only. D6: duplicate members. P2: number spellings of iat, ttl and exp. F7: S + L on a record signature, and the small-order and non-canonical Ed25519 encodings as a record key with R the identity and S = 0, over an arbitrary and a ground digest.',
      cases,
    ),
    preimages,
  }
}

// ---- open-cases.json (P4, F2, F8, D6) ---------------------------------------------------------------------------

/** The eight small-order X25519 u-coordinates (each gives an all-zero shared secret). */
export const X25519_SMALL_ORDER = [
  ['zero', '00'.repeat(32)],
  ['one', `01${'00'.repeat(31)}`],
  ['order-8-a', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'],
  ['order-8-b', '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'],
  ['p-minus-1', `ec${FF30}7f`],
  ['p', `ed${FF30}7f`],
  ['p-plus-1', `ee${FF30}7f`],
  ['zero-high-bit', `${'00'.repeat(31)}80`],
] as const

/** Seals a plaintext by hand: wrap i is sealed to `to[i]`'s key with the AAD of `aadOf(i)`. */
function sealManual(
  to: readonly Party[],
  from: string,
  plaintext: Uint8Array,
  aadOf: (i: number) => string,
): Sealed {
  const contentKey = rng(32)
  const nonce = rng(12)
  return {
    wraps: to.map((p, i) => {
      const { enc, ct } = hpkeSeal(p.seal.publicKey, utf8('ac/seal/1'), utf8(aadOf(i)), contentKey, rng(32))
      return { to: p.address, enc: toHex(enc), ct: toHex(ct) }
    }),
    nonce: toHex(nonce),
    ct: toHex(
      aeadSeal(
        contentKey,
        nonce,
        contentAad(
          to.map((p) => p.address),
          from,
        ),
        plaintext,
      ),
    ),
  }
}

function openFile(cast: Cast): J {
  const cases = new Cases()
  const add = (line: string, label: string, i: OpenInput): void => {
    cases.add(line, 'open', label, { ...i }, openVerdict(i))
  }
  const input = (e: { to: readonly string[]; from: string; sealed: Sealed }, p: Party): OpenInput => ({
    v: 1,
    to: [...e.to],
    from: e.from,
    sealed: JSON.parse(JSON.stringify(e.sealed)) as Sealed,
    address: p.address,
    seal_seed: toHex(p.seal.exportSeed()),
  })
  const b = envelope(cast, 2, 0)
  const [A, B] = [at(b.to, 0), at(b.to, 1)]
  const base = input(b.envelope, A)
  controlOk('P4 open', openVerdict(base))
  add('P4', 'genuine-open-by-first', base)
  add('P4', 'genuine-open-by-second', input(b.envelope, B))
  const outsider = cast.parties.find((p) => !b.envelope.to.includes(p.address)) as Party
  add('P4', 'outsider-not-recipient', input(b.envelope, outsider))
  // (a) the content opened with the AAD of a different to list or from.
  add('P4', 'a-to-reordered', {
    ...base,
    to: [B.address, A.address],
    sealed: { ...base.sealed, wraps: [at(base.sealed.wraps, 1), at(base.sealed.wraps, 0)] },
  })
  add('P4', 'a-to-extra-recipient', { ...base, to: [...base.to, outsider.address] })
  add('P4', 'a-from-changed', { ...base, from: cast.attacker.address })
  // (b) a wrap sealed to the recipient's key with the other recipient's address as AAD (also F8(c)).
  {
    const plaintext = encodeContent(content())
    const sealed = sealManual([A, B], b.envelope.from, plaintext, (i) => (i === 0 ? B.address : A.address))
    add('P4', 'b-wrap-aad-of-other-recipient', { ...base, sealed })
    add('F8', 'c-wrap-aad-of-other-recipient-second', { ...input(b.envelope, B), sealed })
  }
  // (c) enc replaced by each small-order X25519 point.
  for (const [label, u] of X25519_SMALL_ORDER) {
    const wraps = base.sealed.wraps.map((w, i) => (i === 0 ? { ...w, enc: u } : w))
    add('P4', `c-enc-small-order-${label}`, { ...base, sealed: { ...base.sealed, wraps } })
  }
  // (d) the wrap ct's last byte changed; (e) the content tag changed.
  {
    const w0 = at(base.sealed.wraps, 0)
    const ct = w0.ct.slice(0, -2) + (w0.ct.endsWith('00') ? '01' : '00')
    differs('P4d', ct, w0.ct)
    add('P4', 'd-wrap-ct-last-byte', {
      ...base,
      sealed: { ...base.sealed, wraps: [{ ...w0, ct }, at(base.sealed.wraps, 1)] },
    })
    const c = base.sealed.ct
    const tagged = c.slice(0, -2) + (c.endsWith('00') ? '01' : '00')
    add('P4', 'e-content-tag-last-byte', { ...base, sealed: { ...base.sealed, ct: tagged } })
    add('P4', 'e-content-ct-first-byte', {
      ...base,
      sealed: { ...base.sealed, ct: (c.startsWith('00') ? '01' : '00') + c.slice(2) },
    })
  }
  // F2: the sealed part under another from (the attacker re-signed it).
  add('F2', 'resigned-from-attacker-open-by-first', { ...base, from: cast.attacker.address })
  // F8(b): wraps swapped, id and sig recomputed by the sender: each recipient's open.
  {
    const [w0, w1] = [at(base.sealed.wraps, 0), at(base.sealed.wraps, 1)]
    const sealed = {
      ...base.sealed,
      wraps: [
        { to: w0.to, enc: w1.enc, ct: w1.ct },
        { to: w1.to, enc: w0.enc, ct: w0.ct },
      ],
    }
    add('F8', 'b-wraps-swapped-open-by-first', { ...base, sealed })
    add('F8', 'b-wraps-swapped-open-by-second', { ...input(b.envelope, B), sealed })
  }
  // D6: a sealed content with two type members, and other malformed plaintexts.
  {
    const thread = newThread(rng)
    const plain = (s: string): Sealed =>
      sealManual([A, B], b.envelope.from, utf8(s), (i) => at([A, B], i).address)
    const th = JSON.stringify(thread)
    for (const [label, s] of [
      ['two-type-valid-last', `{"type":"","type":"coding.task.v1","thread":${th},"body":null}`],
      ['two-type-valid-first', `{"type":"coding.task.v1","type":"","thread":${th},"body":null}`],
      ['content-not-json', 'not json'],
      ['content-extra-member', `{"type":"t","thread":${th},"body":null,"x":1}`],
      ['content-bad-thread', '{"type":"t","thread":{"id":"00","prev":[]},"body":null}'],
      ['content-bom', `﻿{"type":"t","thread":${th},"body":null}`],
    ] as const) {
      add(label.startsWith('two') ? 'D6' : 'P4', label, { ...base, sealed: plain(s) })
    }
  }
  return fileOf(
    'Open cases (spec/SPEC.md §4.4): the recipient opens with its own sealing key (seal_seed, test data). P4: (a) the content under the AAD of a different to or from; (b) a wrap sealed with the other recipient as AAD; (c) enc replaced by each small-order X25519 point; (d) a wrap ct byte changed; (e) the content tag changed. F2: the sealed part under the attacker as from. F8: wraps swapped. D6: a sealed content with two type members.',
    cases,
  )
}

// ---- round 2: pre-registered verdicts ------------------------------------------------------------------

/**
 * In the round2-*.json files `expected` is the verdict pre-registered for the line (the codes of spec/SPEC.md
 * Appendix A), not the TypeScript core's: the generator computes the core's verdict beside it,
 * and when the two differ it writes the pre-registered one and names the case in its summary, so that the TypeScript
 * reader fails on it as the other readers would. The round-2 cases draw from the same seeded stream after the first
 * five files' last draw, so those five files regenerate byte for byte (G2).
 */
let round2Differs: string[] = []

function pre(
  cases: Cases,
  line: string,
  kind: string,
  label: string,
  input: J,
  expected: string,
  ts: string,
): void {
  cases.add(line, kind, label, input, expected)
  if (ts !== expected) {
    const name = (cases.list.at(-1) as J).name as string
    round2Differs.push(`${name}: pre-registered ${expected}, TypeScript ${ts}`)
  }
}

function fileOf2(description: string, cases: Cases): J {
  return fileOf(
    `${description} Round 2: each case's expected verdict is the one pre-registered for its line, not the TypeScript core's (spec/adversarial/README.md, "Round 2").`,
    cases,
  )
}

/** The `rotation-claim` kind: the JSON reader, §7.5 at now and skew, then the claim of §7.3 (verifyRotationClaim). */
export function rotationClaimVerdict(bytes: Uint8Array, now = NOW, skew = SKEW): string {
  return outcome(() => verifyRotationClaim(verifyRecord(parseRecord(bytes), now, skew) as AddressRecord))
}

function recordCase2(
  cases: Cases,
  line: string,
  label: string,
  r: J | Uint8Array,
  expected: string,
  now = NOW,
): void {
  const bytes = r instanceof Uint8Array ? r : recordBytes(r)
  pre(
    cases,
    line,
    'record',
    label,
    { bytes_hex: toHex(bytes), now, skew: SKEW },
    expected,
    recordVerdict(bytes, now),
  )
}

function claimCase(
  cases: Cases,
  line: string,
  label: string,
  r: J | Uint8Array,
  expected: string,
  now = NOW,
): void {
  const bytes = r instanceof Uint8Array ? r : recordBytes(r)
  pre(
    cases,
    line,
    'rotation-claim',
    label,
    { bytes_hex: toHex(bytes), now, skew: SKEW },
    expected,
    rotationClaimVerdict(bytes, now),
  )
}

function rotationCase2(cases: Cases, line: string, label: string, prev: J, next: J, expected: string): void {
  const pb = recordBytes(prev)
  const nb = recordBytes(next)
  pre(
    cases,
    line,
    'rotation',
    label,
    { prev_bytes_hex: toHex(pb), next_bytes_hex: toHex(nb) },
    expected,
    rotationVerdict(pb, nb),
  )
}

function acceptFrom(owner: SigningKey, roots: readonly string[], over: J = {}): J {
  return signLoose(owner, {
    kind: 'accept-from',
    owner: owner.address,
    roots,
    max_bytes: 65_536,
    ttl: TTL,
    iat: T0,
    ...over,
  })
}

/** A host of exactly n characters: labels of 63 joined by dots, the last one shortened. */
function hostOf(n: number): string {
  const labels: string[] = []
  let left = n
  while (left > 0) {
    const take = Math.min(63, left)
    labels.push('a'.repeat(take))
    left -= take + 1
  }
  const host = labels.join('.')
  if (host.length !== n) throw new Error(`gen-adversarial: a host of ${host.length} characters, not ${n}`)
  return host
}

// ---- round2-domains.json (W7) -------------------------------------------------------------------------------------

function domainsFile(cast: Cast): J {
  const cases = new Cases()
  const owner = generateSigningKey(rng)
  const other = pick(cast.signers).address
  controlOk('W7 base', recordVerdict(recordBytes(acceptFrom(owner, ['domain:example.com']))))
  // W7's six named shapes first, then further malformed hosts the same rule refuses (W7: bad-record).
  const refused: [string, string | string[]][] = [
    ['ip-literal', 'domain:127.0.0.1'],
    ['trailing-dot', 'domain:example.com.'],
    ['uppercase-label', 'domain:Example.com'],
    ['single-label', 'domain:localhost'],
    ['length-254', `domain:${hostOf(254)}`],
    ['empty-host', 'domain:'],
    ['ip-literal-short', 'domain:127.1'],
    ['ip-literal-ipv4-trailing-dot', 'domain:127.0.0.1.'],
    ['ip-literal-last-label-digits', 'domain:example.123'],
    ['ip-literal-last-label-hex', 'domain:example.0x7f'],
    ['ip-literal-last-label-bare-0x', 'domain:example.0x'],
    ['ipv6-bracketed', 'domain:[::1]'],
    ['ipv6-bare', 'domain:::1'],
    ['uppercase-all', 'domain:EXAMPLE.COM'],
    ['with-port', 'domain:example.com:443'],
    ['with-userinfo', 'domain:user@example.com'],
    ['with-scheme', 'domain:https://example.com'],
    ['with-path', 'domain:example.com/x'],
    ['leading-space', 'domain: example.com'],
    ['trailing-space', 'domain:example.com '],
    ['label-leading-hyphen', 'domain:-example.com'],
    ['label-trailing-hyphen', 'domain:example-.com'],
    ['empty-label', 'domain:example..com'],
    ['leading-dot', 'domain:.example.com'],
    ['label-64', `domain:${'a'.repeat(64)}.com`],
    ['underscore', 'domain:exa_mple.com'],
    ['wildcard-label', 'domain:*.example.com'],
    ['non-ascii', 'domain:b\u00fccher.example'],
    ['cyrillic-lookalike', 'domain:ex\u0430mple.com'],
    ['nul-in-host', 'domain:example.com\u0000'],
    ['prefix-uppercase', 'DOMAIN:example.com'],
    ['prefix-without-colon', 'domainexample.com'],
    ['beside-wildcard', ['*', 'domain:example.com']],
    ['listed-twice', ['domain:example.com', 'domain:example.com']],
    ['beside-address-one-malformed', [other, 'domain:Example.com']],
  ]
  for (const [label, roots] of refused) {
    const list = typeof roots === 'string' ? [roots] : roots
    recordCase2(cases, 'W7', label, acceptFrom(owner, list), 'bad-record')
  }
  // V1 positive controls: the lawful neighbours of the refused shapes.
  const accepted: [string, string | string[]][] = [
    ['control-two-labels', 'domain:example.com'],
    ['control-length-253', `domain:${hostOf(253)}`],
    ['control-label-63', `domain:${'a'.repeat(63)}.com`],
    ['control-digits-not-last', 'domain:1.2.3.example'],
    ['control-punycode', 'domain:xn--bcher-kva.example'],
    ['control-hyphen-inside', 'domain:ex-ample.com'],
    ['control-beside-address', [other, 'domain:example.com']],
    ['control-two-domains', ['domain:a.example', 'domain:b.example']],
  ]
  for (const [label, roots] of accepted) {
    const list = typeof roots === 'string' ? [roots] : roots
    recordCase2(cases, 'W7', label, acceptFrom(owner, list), 'ok')
  }
  return fileOf2(
    'W7: accept-from records whose domain: roots are malformed (an IP literal, a trailing dot, an uppercase label, a single label, 254 characters, an empty host, and further shapes the same rule refuses), each bad-record, beside lawful controls (two labels, 253 characters, a 63-character label), each ok; every record signed by its owner.',
    cases,
  )
}

// ---- round2-records.json (T1, T2, T3) -----------------------------------------------------------------------------

function recordsFile(cast: Cast): J {
  const cases = new Cases()
  const countersigned = (k: SigningKey, r: J): J => ({
    ...r,
    rotation_sig: signPreimage(k, recordPreimage(r as unknown as AcRecord)),
  })

  // T1: a rotation to a reader that holds no record of rotated_from.
  {
    const prevKey = generateSigningKey(rng)
    const rotationKey = generateSigningKey(rng)
    const nextKey = generateSigningKey(rng)
    const unrelated = generateSigningKey(rng)
    const prev = addressRecord(cast, prevKey, { rotation_key: rotationKey.address })
    const next = addressRecord(cast, nextKey, { rotated_from: prevKey.address, iat: T0 + 1 })
    controlOk('T1 next record', recordVerdict(recordBytes(next)))
    const byPrev = countersigned(prevKey, next)
    claimCase(cases, 'T1', 'rotation-sig-null', next, 'bad-rotation')
    claimCase(cases, 'T1', 'rotation-sig-by-unrelated-key', countersigned(unrelated, next), 'bad-rotation')
    claimCase(cases, 'T1', 'rotation-sig-by-own-key', countersigned(nextKey, next), 'bad-rotation')
    claimCase(
      cases,
      'T1',
      'rotation-sig-by-previous-rotation-key',
      countersigned(rotationKey, next),
      'bad-rotation',
    )
    claimCase(
      cases,
      'T1',
      'rotation-sig-s-plus-l',
      { ...byPrev, rotation_sig: plusL(byPrev.rotation_sig as string) },
      'bad-rotation',
    )
    const elsewhere = addressRecord(cast, nextKey, {
      rotated_from: prevKey.address,
      iat: T0 + 1,
      relays: ['https://other.example'],
    })
    differs('T1 other record', recordBytes(elsewhere), recordBytes(next))
    claimCase(
      cases,
      'T1',
      'rotation-sig-moved-from-another-record',
      { ...elsewhere, rotation_sig: byPrev.rotation_sig },
      'bad-rotation',
    )
    claimCase(cases, 'T1', 'control-rotation-sig-by-rotated-from', byPrev, 'ok')
    claimCase(cases, 'T1', 'control-no-rotation-claimed', addressRecord(cast, nextKey, { iat: T0 + 1 }), 'ok')
    // The rotation-key path, taken only by a reader that holds the previous record (the `rotation` kind).
    rotationCase2(cases, 'T1', 'held-previous-control-by-rotated-from', prev, byPrev, 'ok')
    rotationCase2(
      cases,
      'T1',
      'held-previous-control-by-rotation-key',
      prev,
      countersigned(rotationKey, next),
      'ok',
    )
    rotationCase2(cases, 'T1', 'held-previous-by-own-key', prev, countersigned(nextKey, next), 'bad-rotation')
    rotationCase2(cases, 'T1', 'held-previous-rotation-sig-null', prev, next, 'bad-rotation')
  }

  // T2: the claim's key comes from rotated_from, never from key or rotation_key, members the submitter controls.
  {
    const victim = generateSigningKey(rng)
    const attacker = generateSigningKey(rng)
    const attacker2 = generateSigningKey(rng)
    const victimRecord = addressRecord(cast, victim)
    const claim = (over: J): J =>
      addressRecord(cast, attacker, { rotated_from: victim.address, iat: T0 + 1, ...over })
    controlOk('T2 claim record', recordVerdict(recordBytes(claim({}))))
    claimCase(cases, 'T2', 'self-countersigned-by-key', countersigned(attacker, claim({})), 'bad-rotation')
    claimCase(
      cases,
      'T2',
      'self-countersigned-by-own-rotation-key',
      countersigned(attacker2, claim({ rotation_key: attacker2.address })),
      'bad-rotation',
    )
    claimCase(
      cases,
      'T2',
      'self-countersigned-rotation-key-equal-to-key',
      countersigned(attacker, claim({ rotation_key: attacker.address })),
      'bad-rotation',
    )
    claimCase(
      cases,
      'T2',
      'victim-named-as-rotation-key-signed-by-key',
      countersigned(attacker, claim({ rotation_key: victim.address })),
      'bad-rotation',
    )
    claimCase(cases, 'T2', 'control-countersigned-by-rotated-from', countersigned(victim, claim({})), 'ok')
    rotationCase2(
      cases,
      'T2',
      'held-previous-self-countersigned-by-key',
      victimRecord,
      countersigned(attacker, claim({})),
      'bad-rotation',
    )
    rotationCase2(
      cases,
      'T2',
      'held-previous-self-countersigned-by-own-rotation-key',
      victimRecord,
      countersigned(attacker2, claim({ rotation_key: attacker2.address })),
      'bad-rotation',
    )
    rotationCase2(
      cases,
      'T2',
      'held-previous-control-by-rotated-from',
      victimRecord,
      countersigned(victim, claim({})),
      'ok',
    )
  }

  // T3: the caps of roots (1,024) and of a key record's lifetime (86,400 s).
  {
    const owner = generateSigningKey(rng)
    const addresses = Array.from(
      { length: 1025 },
      (_, i) => `ed25519:${sha256hex(`adversarial T3 root ${i}`)}`,
    )
    const domains = Array.from({ length: 1025 }, (_, i) => `domain:r${i}.example`)
    recordCase2(cases, 'T3', 'roots-1025', acceptFrom(owner, addresses), 'bad-record')
    recordCase2(cases, 'T3', 'control-roots-1024', acceptFrom(owner, addresses.slice(0, 1024)), 'ok')
    recordCase2(
      cases,
      'T3',
      'roots-1025-with-domains',
      acceptFrom(owner, [...addresses.slice(0, 513), ...domains.slice(0, 512)]),
      'bad-record',
    )
    recordCase2(
      cases,
      'T3',
      'control-roots-1024-with-domains',
      acceptFrom(owner, [...addresses.slice(0, 512), ...domains.slice(0, 512)]),
      'ok',
    )
    recordCase2(cases, 'T3', 'roots-0', acceptFrom(owner, []), 'bad-record')
    const keyRec = (iat: number, exp: number): J =>
      signLoose(owner, {
        kind: 'key',
        key: owner.address,
        sealing_key: toHex(pick(cast.parties).seal.publicKey),
        iat,
        exp,
      })
    recordCase2(cases, 'T3', 'key-exp-iat-plus-86401', keyRec(T0, T0 + DAY + 1), 'bad-record')
    recordCase2(cases, 'T3', 'control-key-exp-iat-plus-86400', keyRec(T0, T0 + DAY), 'ok')
    recordCase2(cases, 'T3', 'key-exp-iat-minus-1', keyRec(T0, T0 - 1), 'bad-record', T0)
    recordCase2(cases, 'T3', 'control-key-exp-equal-to-iat', keyRec(T0, T0), 'ok', T0)
    recordCase2(cases, 'T3', 'key-exp-max-iat-0', keyRec(0, MAX), 'bad-record', 0)
  }

  return fileOf2(
    "T1: a rotation claim judged by a reader that holds no record of rotated_from (the rotation-claim kind: rotation_sig null, by an unrelated key, by the record key, by the previous record's rotation key, S + L, moved from another record: each bad-rotation; countersigned by rotated_from: ok), and the rotation-key path, taken only with the previous record held (the rotation kind). T2: self-countersigned claims, the countersigning key the record's key or rotation_key, each bad-rotation. T3: 1,025 roots and 1,024, a key record living 86,401 s and 86,400 s, exp before iat.",
    cases,
  )
}

// ---- round2-keys.json (T4) ----------------------------------------------------------------------------------------

/** The two encodings with x = 0 and the sign bit set: of the identity and of the point of order 2 (RFC 8032 §5.1.3). */
export const SIGN_BIT_ALIASES = [
  ['identity-sign-bit', `01${'00'.repeat(30)}80`],
  ['order-2-sign-bit', `ec${FF30}ff`],
] as const
/** T4's 14 degenerate keys: 8 small-order, 2 sign-bit aliases, 4 non-canonical (y + p). */
export const DEGENERATE_KEYS: readonly (readonly [string, string])[] = [
  ...SMALL_ORDER,
  ...SIGN_BIT_ALIASES,
  ...NON_CANONICAL,
]

const P25519 = 2n ** 255n - 19n

function modP(a: bigint, m = P25519): bigint {
  const r = a % m
  return r < 0n ? r + m : r
}

function powMod(b: bigint, e: bigint, m = P25519): bigint {
  let r = 1n
  let x = modP(b, m)
  for (let k = e; k > 0n; k >>= 1n) {
    if (k & 1n) r = (r * x) % m
    x = (x * x) % m
  }
  return r
}

const invP = (a: bigint): bigint => powMod(a, P25519 - 2n)
const CURVE_D = modP(-121_665n * invP(121_666n))
const SQRT_M1 = powMod(2n, (P25519 - 1n) / 4n)

/** A point of edwards25519 in extended coordinates (X, Y, Z, T), RFC 8032 §6. */
type Point = readonly [bigint, bigint, bigint, bigint]

function pointAdd(p: Point, q: Point): Point {
  const a = modP((p[1] - p[0]) * (q[1] - q[0]))
  const b = modP((p[1] + p[0]) * (q[1] + q[0]))
  const c = modP(2n * p[3] * q[3] * CURVE_D)
  const d = modP(2n * p[2] * q[2])
  const [e, f, g, h] = [b - a, d - c, d + c, b + a]
  return [modP(e * f), modP(g * h), modP(f * g), modP(e * h)]
}

function pointMul(s: bigint, p: Point): Point {
  let q: Point = [0n, 1n, 1n, 0n]
  let x = p
  for (let k = s; k > 0n; k >>= 1n) {
    if (k & 1n) q = pointAdd(q, x)
    x = pointAdd(x, x)
  }
  return q
}

function recoverX(y: bigint, sign: bigint): bigint {
  const x2 = modP((y * y - 1n) * invP(CURVE_D * y * y + 1n))
  if (x2 === 0n) return 0n
  let x = powMod(x2, (P25519 + 3n) / 8n)
  if (modP(x * x - x2) !== 0n) x = modP(x * SQRT_M1)
  if (modP(x * x - x2) !== 0n) throw new Error('gen-adversarial: not a point')
  return (x & 1n) === sign ? x : P25519 - x
}

function pointDecode(hex: string): Point {
  const n = leInt(fromHex(hex, 32))
  const y = n & ((1n << 255n) - 1n)
  const x = recoverX(y, n >> 255n)
  return [x, y, 1n, modP(x * y)]
}

function pointEncode(p: Point): string {
  const zi = invP(p[2])
  const x = modP(p[0] * zi)
  const y = modP(p[1] * zi)
  return toHex(leBytes(y | ((x & 1n) << 255n), 32))
}

const BASE_Y = modP(4n * invP(5n))
const BASE: Point = [recoverX(BASE_Y, 0n), BASE_Y, 1n, modP(recoverX(BASE_Y, 0n) * BASE_Y)]

/** A key of mixed order: [a]B plus a point of order 8, with its scalar a (test data from the seeded stream). */
export interface MixedKey {
  readonly a: bigint
  readonly address: string
}

/** The mixed-order key [a]B + T for a torsion point T given by its encoding. */
export function mixedKey(a: bigint, torsionHex: string): MixedKey {
  return { a, address: `ed25519:${pointEncode(pointAdd(pointMul(a, BASE), pointDecode(torsionHex)))}` }
}

/**
 * Signs `message` under a mixed-order key with the nonce scalar r: R = [r]B, k = SHA-512(R || A || M) mod L,
 * S = r + k a mod L. The cofactorless check [S]B = R + [k]A holds exactly when [k] sends the torsion part to the
 * identity: k = 0 mod 8 for a point of order 8 (spec/SPEC.md §2.3). Returns the signature and k mod 8.
 */
export function mixedSign(key: MixedKey, r: bigint, message: Uint8Array): { sig: string; k8: number } {
  const rHex = pointEncode(pointMul(r, BASE))
  const k = challenge(rHex, key.address.slice(8), message)
  return { sig: rHex + toHex(leBytes((r + k * key.a) % L, 32)), k8: Number(k % 8n) }
}

function scalar(): bigint {
  const s = leInt(rng(64)) % L
  return s === 0n ? 1n : s
}

const ORDER_8 = SMALL_ORDER.filter(([label]) => label.startsWith('order-8'))

function keysFile(cast: Cast): J {
  const cases = new Cases()
  const recordBase = addressRecord(cast, generateSigningKey(rng))
  const digestOf = (pre: CanonicalValue): Uint8Array => fromHex(sha256hex(canonical(pre)), 32)
  const sub = pick(cast.parties).key.address
  const to = shuffled(cast.parties).slice(0, 2)

  /** An address record under `key`, iat ground down from NOW until `accept(digest)`, signed by `sign`. */
  const record = (key: string, accept: (d: Uint8Array) => boolean, sign: (d: Uint8Array) => string): J => {
    for (let iat = NOW; iat > NOW - 4096; iat--) {
      const r: J = { ...recordBase, key, iat }
      const d = digestOf(recordPreimage(r as unknown as AcRecord))
      if (accept(d)) return { ...r, sig: sign(d) }
    }
    throw new Error('gen-adversarial: no ground iat found (T4)')
  }
  /** A one-hop chain from `iss` to `sub`, exp ground up from T0 + DAY until `accept(digest)`. */
  const hop = (iss: string, accept: (d: Uint8Array) => boolean, sign: (d: Uint8Array) => string): J[] => {
    for (let exp = T0 + DAY; exp < T0 + DAY + 4096; exp++) {
      const h = { iss, sub, caveats: ['type=coding.*'], exp }
      const d = digestOf(hopPreimage(h))
      if (accept(d)) return [{ ...h, sig: sign(d) }]
    }
    throw new Error('gen-adversarial: no ground exp found (T4)')
  }
  /** An envelope from `from`, ts ground down from T0 until `accept(id)`, signed by `sign` over the id. */
  const env = (
    from: string,
    accept: (d: Uint8Array) => boolean,
    sign: (d: Uint8Array) => string,
  ): Uint8Array => {
    const sealed = sealTo(
      to.map((p) => ({ address: p.address, sealingKey: p.seal.publicKey })),
      from,
      content(),
      rng,
    )
    for (let ts = T0; ts > T0 - 4096; ts--) {
      const unsigned = { v: 1, to: to.map((p) => p.address), from, auth: [], suite: 1, ts, sealed } as const
      const id = envelopeId(unsigned)
      if (accept(fromHex(id, 32))) return serializeEnvelope({ ...unsigned, id, sig: sign(fromHex(id, 32)) })
    }
    throw new Error('gen-adversarial: no ground ts found (T4)')
  }
  const places = (
    label: string,
    key: string,
    accept: (d: Uint8Array) => boolean,
    sign: (d: Uint8Array) => string,
    expected: { record: string; chain: string; outer: string },
  ): void => {
    const r = record(key, accept, sign)
    recordCase2(cases, 'T4', `record-key-${label}`, r, expected.record)
    const auth = hop(key, accept, sign)
    pre(
      cases,
      'T4',
      'chain',
      `hop-iss-${label}`,
      { auth, from: sub, ts: T0 },
      expected.chain,
      chainVerdict(auth, sub, T0),
    )
    const bytes = env(key, accept, sign)
    pre(
      cases,
      'T4',
      'outer',
      `envelope-from-${label}`,
      { bytes_hex: toHex(bytes), now: NOW, ttl: TTL, skew: SKEW },
      expected.outer,
      outerVerdict(bytes),
    )
  }
  const refused = { record: 'bad-record-sig', chain: 'bad-hop-sig', outer: 'bad-sig' }
  const accepted = { record: 'ok', chain: 'ok', outer: 'ok' }

  // V1: a genuine key in each place.
  const genuine = generateSigningKey(rng)
  places(
    'control-genuine-key',
    genuine.address,
    () => true,
    (d) => toHex(genuine.sign(d)),
    accepted,
  )
  // The 14 degenerate keys with R the identity and S = 0, over an arbitrary digest and one ground to k = 0 mod 8.
  for (const [label, pub] of DEGENERATE_KEYS) {
    for (const grind of [false, true]) {
      places(
        `${label}${grind ? '-ground' : ''}`,
        `ed25519:${pub}`,
        (d) => !grind || ground(pub, d),
        () => DEGENERATE_SIG,
        refused,
      )
    }
  }
  // Mixed-order keys, [a]B plus each point of order 8: ok when k = 0 mod 8, bad-*-sig otherwise (§2.3, decided).
  for (const [label, torsion] of ORDER_8) {
    const key = mixedKey(scalar(), torsion)
    for (const zero of [true, false]) {
      const r = scalar()
      places(
        `mixed-${label}-${zero ? 'k-0-mod-8' : 'k-not-0-mod-8'}`,
        key.address,
        (d) => (mixedSign(key, r, d).k8 === 0) === zero,
        (d) => mixedSign(key, r, d).sig,
        zero ? accepted : refused,
      )
    }
  }
  return fileOf2(
    "T4: the 14 degenerate Ed25519 keys (8 small-order, 2 sign-bit aliases of x = 0, 4 non-canonical y + p) as an address record's key, a hop's iss and an envelope's from, with R the identity and S = 0 over an arbitrary digest and one ground so that k = 0 mod 8: bad-record-sig, bad-hop-sig, bad-sig. Keys of mixed order ([a]B plus each point of order 8) signing with a: ok when k = 0 mod 8, bad-*-sig otherwise (spec/SPEC.md §2.3). A genuine key in each place as the control.",
    cases,
  )
}

// ---- round2-duplicates.json (T5, T6) ------------------------------------------------------------------------------

function duplicatesFile(cast: Cast): J {
  const cases = new Cases()

  // T5, envelopes: a member named twice at the top, in a hop, in sealed, in a wrap (parse and outer).
  {
    const b = envelope(cast, 2, 2)
    controlOk('T5 envelope', outerVerdict(b.bytes))
    const t = text(b.bytes)
    const e = b.envelope
    const h0 = at(e.auth, 0)
    const w0 = at(e.sealed.wraps, 0)
    const both = (label: string, bytes: Uint8Array, expected: string): void => {
      pre(
        cases,
        'T5',
        'parse',
        `envelope-${label}`,
        { bytes_hex: toHex(bytes) },
        expected,
        parseVerdict(bytes),
      )
      pre(
        cases,
        'T5',
        'outer',
        `envelope-${label}`,
        { bytes_hex: toHex(bytes), now: NOW, ttl: TTL, skew: SKEW },
        expected,
        outerVerdict(bytes),
      )
    }
    both('control-unchanged', b.bytes, 'ok')
    for (const [label, from, to] of [
      ['two-v-same-value', '{"v":1,', '{"v":1,"v":1,'],
      ['two-from-same-value', `"from":"${e.from}"`, `"from":"${e.from}","from":"${e.from}"`],
      ['two-ts-same-value', `"ts":${e.ts},`, `"ts":${e.ts},"ts":${e.ts},`],
      ['two-ts-escaped-name', `"ts":${e.ts},`, `"ts":${e.ts},"\\u0074s":${e.ts},`],
      ['two-sig-same-value', `"sig":"${e.sig}"`, `"sig":"${e.sig}","sig":"${e.sig}"`],
      ['hop-two-iss-same-value', `"iss":"${h0.iss}"`, `"iss":"${h0.iss}","iss":"${h0.iss}"`],
      ['hop-two-exp-same-value', `"exp":${h0.exp},`, `"exp":${h0.exp},"exp":${h0.exp},`],
      [
        'sealed-two-nonce',
        `"nonce":"${e.sealed.nonce}"`,
        `"nonce":"${e.sealed.nonce}","nonce":"${e.sealed.nonce}"`,
      ],
      ['wrap-two-enc', `"enc":"${w0.enc}"`, `"enc":"${w0.enc}","enc":"${w0.enc}"`],
    ] as const) {
      const m = utf8(replaceOnce(t, from, to))
      differs(`T5 ${label}`, m, b.bytes)
      both(label, m, 'bad-json')
    }
  }

  // T5, records: a member named twice in each kind of record, and in a rotation claim.
  {
    const owner = generateSigningKey(rng)
    const prevKey = generateSigningKey(rng)
    const addr = addressRecord(cast, owner)
    const accept = acceptFrom(owner, [pick(cast.signers).address])
    const keyRec = signLoose(owner, {
      kind: 'key',
      key: owner.address,
      sealing_key: toHex(pick(cast.parties).seal.publicKey),
      iat: T0,
      exp: T0 + DAY,
    })
    const unsignedClaim = addressRecord(cast, owner, { rotated_from: prevKey.address, iat: T0 + 1 })
    const claim = {
      ...unsignedClaim,
      rotation_sig: signPreimage(prevKey, recordPreimage(unsignedClaim as unknown as AcRecord)),
    }
    const at2 = (r: J, from: string, to: string): Uint8Array => {
      const m = utf8(replaceOnce(text(recordBytes(r)), from, to))
      differs(`T5 record ${from}`, m, recordBytes(r))
      return m
    }
    recordCase2(cases, 'T5', 'record-control-address', addr, 'ok')
    recordCase2(cases, 'T5', 'record-control-accept-from', accept, 'ok')
    recordCase2(cases, 'T5', 'record-control-key', keyRec, 'ok')
    recordCase2(
      cases,
      'T5',
      'address-two-key-same-value',
      at2(addr, `"key":"${owner.address}"`, `"key":"${owner.address}","key":"${owner.address}"`),
      'bad-json',
    )
    recordCase2(
      cases,
      'T5',
      'address-two-kind-escaped-name',
      at2(addr, '"kind":"address"', '"kind":"address","\\u006bind":"address"'),
      'bad-json',
    )
    recordCase2(
      cases,
      'T5',
      'accept-from-two-roots',
      at2(accept, '"max_bytes":', `"roots":["*"],"max_bytes":`),
      'bad-json',
    )
    recordCase2(
      cases,
      'T5',
      'key-two-exp-same-value',
      at2(keyRec, `"exp":${T0 + DAY}`, `"exp":${T0 + DAY},"exp":${T0 + DAY}`),
      'bad-json',
    )
    claimCase(cases, 'T5', 'claim-control', claim, 'ok')
    const sig = claim.rotation_sig
    claimCase(
      cases,
      'T5',
      'claim-two-rotation-sig-null-first',
      at2(claim, `"rotation_sig":"${sig}"`, `"rotation_sig":null,"rotation_sig":"${sig}"`),
      'bad-json',
    )
    claimCase(
      cases,
      'T5',
      'claim-two-rotation-sig-null-last',
      at2(claim, `"rotation_sig":"${sig}"`, `"rotation_sig":"${sig}","rotation_sig":null`),
      'bad-json',
    )
    claimCase(
      cases,
      'T5',
      'claim-two-rotated-from',
      at2(
        claim,
        `"rotated_from":"${prevKey.address}"`,
        `"rotated_from":"${prevKey.address}","rotated_from":"${owner.address}"`,
      ),
      'bad-json',
    )
  }

  // T5, a relay frame and an audit line: the JSON reader alone (the json kind).
  {
    const signer = pick(cast.signers).address
    const mailbox = pick(cast.parties).address
    const auth = `{"t":"auth","mailbox":"${mailbox}","signer":"${signer}","auth":[],"cursor":null,"sig":"${'ab'.repeat(64)}"}`
    const ack = '{"t":"ack","cursor":7}'
    const line = `{"seq":3,"prev":"${'0'.repeat(64)}","ts":${T0},"event":"verify","decision":"accept","reason":"ok","id":null,"from":null,"root":null,"detail":null,"hash":"${'1'.repeat(64)}"}`
    const json = (label: string, s: string, expected: string): void => {
      const bytes = utf8(s)
      pre(cases, 'T5', 'json', label, { bytes_hex: toHex(bytes) }, expected, jsonVerdict(bytes))
    }
    json('frame-control-auth', auth, 'ok')
    json('frame-control-ack', ack, 'ok')
    json('audit-control-line', line, 'ok')
    json('frame-auth-two-t', replaceOnce(auth, '"t":"auth",', '"t":"auth","t":"ack",'), 'bad-json')
    json(
      'frame-auth-two-signer',
      replaceOnce(auth, `"signer":"${signer}",`, `"signer":"${signer}","signer":"${mailbox}",`),
      'bad-json',
    )
    json('frame-ack-two-cursor', replaceOnce(ack, '"cursor":7', '"cursor":7,"cursor":9'), 'bad-json')
    json(
      'frame-ack-two-t-escaped-name',
      replaceOnce(ack, '"t":"ack",', '"t":"ack","\\u0074":"ack",'),
      'bad-json',
    )
    json(
      'audit-two-reason',
      replaceOnce(line, '"reason":"ok",', '"reason":"ok","reason":"bad-sig",'),
      'bad-json',
    )
    json(
      'audit-two-hash-same-value',
      replaceOnce(
        line,
        `"hash":"${'1'.repeat(64)}"`,
        `"hash":"${'1'.repeat(64)}","hash":"${'1'.repeat(64)}"`,
      ),
      'bad-json',
    )
    json(
      'audit-detail-object-two-members',
      replaceOnce(line, '"detail":null', '"detail":{"cause":"a","cause":"b"}'),
      'bad-json',
    )
    json('control-same-name-in-sibling-objects', '{"a":{"k":1},"b":{"k":1}}', 'ok')
    json('control-precomposed-and-decomposed-names', '{"\u00e9":1,"e\u0301":2}', 'ok')
    json('two-names-solidus-escaped', '{"a/b":1,"a\\/b":2}', 'bad-json')
    json('two-names-non-ascii-escaped', '{"\u00e9":1,"\\u00e9":2}', 'bad-json')
  }

  // T5 and T6, the sealed content: duplicates are bad-content wherever they are, a non-I-JSON body is carried.
  {
    const b = envelope(cast, 2, 0)
    const [A, B] = [at(b.to, 0), at(b.to, 1)]
    const thread = JSON.stringify(newThread(rng))
    const tid = (JSON.parse(thread) as { id: string }).id
    const openCase = (line: string, label: string, plaintext: string, expected: string): void => {
      const sealed = sealManual([A, B], b.envelope.from, utf8(plaintext), (i) => at([A, B], i).address)
      const i: OpenInput = {
        v: 1,
        to: [...b.envelope.to],
        from: b.envelope.from,
        sealed,
        address: A.address,
        seal_seed: toHex(A.seal.exportSeed()),
      }
      pre(cases, line, 'open', label, { ...i }, expected, openVerdict(i))
      // The same plaintext through the JSON reader alone, which the Rust core (no HPKE, §1) also reads.
      const bytes = utf8(plaintext)
      const jsonExpected = expected === 'bad-content' ? 'bad-json' : 'ok'
      pre(
        cases,
        line,
        'json',
        `${label}-plaintext`,
        { bytes_hex: toHex(bytes) },
        jsonExpected,
        jsonVerdict(bytes),
      )
    }
    const c = (body: string, type = '"type":"coding.task.v1"', th = `"thread":${thread}`): string =>
      `{${type},${th},"body":${body}}`
    openCase('T5', 'content-control', c('{"repo":"acme/api"}'), 'ok')
    openCase('T5', 'content-two-type-same-value', c('null', '"type":"t","type":"t"'), 'bad-content')
    openCase('T5', 'content-two-type-escaped-name', c('null', '"type":"t","\\u0074ype":"t"'), 'bad-content')
    openCase(
      'T5',
      'content-two-thread',
      c('null', '"type":"t"', `"thread":${thread},"thread":${thread}`),
      'bad-content',
    )
    openCase('T5', 'content-two-body', `{"type":"t","thread":${thread},"body":1,"body":1}`, 'bad-content')
    openCase(
      'T5',
      'thread-two-id',
      c('null', '"type":"t"', `"thread":{"id":"${tid}","id":"${tid}","prev":[]}`),
      'bad-content',
    )
    openCase(
      'T5',
      'thread-two-prev',
      c('null', '"type":"t"', `"thread":{"id":"${tid}","prev":[],"prev":[]}`),
      'bad-content',
    )
    // T6: the body's I-JSON freedom (§4.2) carries a lawful non-I-JSON value and never a duplicate member.
    for (const [label, body] of [
      ['fraction', '1.5'],
      ['one-point-zero', '1.0'],
      ['minus-zero', '-0'],
      ['exponent', '1e0'],
      ['exponent-plus-16', '1e+16'],
      ['negative', '-1'],
      ['past-2-53', '9007199254740993'],
      ['underflow', '1e-400'],
      ['booleans', '[true,false]'],
      ['nested-fractions', '{"x":[1.5,-2,{"y":1e3}]}'],
    ] as const)
      openCase('T6', `body-carried-${label}`, c(body), 'ok')
    for (const [label, body] of [
      ['top', '{"a":1,"a":2}'],
      ['same-value', '{"a":1.5,"a":1.5}'],
      ['in-list', '[{"a":1,"a":1}]'],
      ['escaped-name', '{"a":1,"\\u0061":1}'],
      ['deep', '{"x":{"y":[{"z":{"q":0.5,"q":-0}}]}}'],
      ['beside-fraction', '{"n":1.5,"m":-0,"n":2}'],
    ] as const)
      openCase('T6', `body-duplicate-${label}`, c(body), 'bad-content')
    openCase('T6', 'body-control-same-name-in-sibling-objects', c('{"a":{"k":1.5},"b":{"k":1.5}}'), 'ok')
    openCase('T6', 'type-twice-body-non-ijson', c('1.5', '"type":"t","type":"u"'), 'bad-content')
    openCase(
      'T6',
      'thread-twice-body-non-ijson',
      c('-0', '"type":"t"', `"thread":${thread},"thread":${thread}`),
      'bad-content',
    )
  }

  return fileOf2(
    'T5: a member named twice in an envelope (top, hop, sealed, wrap; parse and outer kinds), in each kind of record and in a rotation claim, in a relay frame and an audit line (the json kind), and inside the sealed content (the open kind, with the plaintext also through the json kind): bad-json, and bad-content for the sealed content. T6: a sealed body that is lawful JSON outside I-JSON (fractions, -0, exponents, 2^53 + 1) is carried, ok; a duplicate member inside the body, or a content naming type or thread twice, is bad-content.',
    cases,
  )
}

// ---- round2-numbers.json (T7, T8) ---------------------------------------------------------------------------------

/**
 * Spellings of a number past the range of a double (§2.5), each read by JSON.parse as Infinity or -Infinity: `bad-json`
 * wherever a reader reads it, and `bad-content` inside the seal, whose body is exempt from the integer rule only (§4.2;
 * seal). `1.7976931348623158e308`, which rounds to the largest double, is no such spelling: T8 pins it as finite
 * (fixed by serde_json's float_roundtrip in the Rust readers).
 */
const PAST_RANGE: readonly (readonly [string, string])[] = [
  ['1e400', '1e400'],
  ['minus-1e400', '-1e400'],
  ['capital-e-400', '1E400'],
  ['1e309', '1e309'],
  ['above-largest-double', '1.7976931348623159e308'],
  ['integer-of-401-digits', `1${'0'.repeat(400)}`],
  ['negative-integer-of-401-digits', `-1${'0'.repeat(400)}`],
]

function numbersFile(cast: Cast): J {
  const cases = new Cases()

  // T7 and T8, inside the seal: a body number past a double's range is bad-content; a finite one, however written,
  // is carried.
  const sealedTo = envelope(cast, 2, 0)
  const [A, B] = [at(sealedTo.to, 0), at(sealedTo.to, 1)]
  const thread = JSON.stringify(newThread(rng))
  const openCase = (
    line: string,
    label: string,
    body: string,
    expected: string,
    type = '"coding.task.v1"',
  ): void => {
    const plaintext = `{"type":${type},"thread":${thread},"body":${body}}`
    const sealed = sealManual([A, B], sealedTo.envelope.from, utf8(plaintext), (i) => at([A, B], i).address)
    const i: OpenInput = {
      v: 1,
      to: [...sealedTo.envelope.to],
      from: sealedTo.envelope.from,
      sealed,
      address: A.address,
      seal_seed: toHex(A.seal.exportSeed()),
    }
    pre(cases, line, 'open', label, { ...i }, expected, openVerdict(i))
    // The same plaintext through the JSON reader alone (the Rust core has no HPKE, §1): bad-json outside the seal.
    const bytes = utf8(plaintext)
    const jsonExpected = expected === 'bad-content' ? 'bad-json' : 'ok'
    pre(
      cases,
      line,
      'json',
      `${label}-plaintext`,
      { bytes_hex: toHex(bytes) },
      jsonExpected,
      jsonVerdict(bytes),
    )
  }
  for (const [label, n] of [
    ['underflow-1e-400', '1e-400'],
    ['1e308', '1e308'],
    ['fraction', '1.5'],
    ['largest-double', '1.7976931348623157e308'],
  ] as const)
    openCase('T7', `body-control-${label}`, n, 'ok')
  for (const [label, n] of PAST_RANGE) openCase('T7', `body-past-range-${label}`, n, 'bad-content')
  openCase('T7', 'body-past-range-nested', '{"x":[1.5,{"y":1e400}]}', 'bad-content')
  openCase('T7', 'body-past-range-beside-finite', '[1e308,-1e400,1.5]', 'bad-content')
  openCase('T7', 'type-past-range-1e400', 'null', 'bad-content', '1e400')

  // T7, outside the seal: the same spellings as an envelope's ts and a hop's exp (parse), and as a record's iat and
  // ttl (record), are bad-json.
  {
    const b = envelope(cast, 2, 2)
    controlOk('T7 envelope', parseVerdict(b.bytes))
    const t = text(b.bytes)
    const e = b.envelope
    const h0 = at(e.auth, 0)
    const parse = (label: string, bytes: Uint8Array, expected: string): void =>
      pre(cases, 'T7', 'parse', label, { bytes_hex: toHex(bytes) }, expected, parseVerdict(bytes))
    parse('envelope-control-unchanged', b.bytes, 'ok')
    for (const [label, n] of PAST_RANGE) {
      for (const [where, from] of [
        ['ts', `"ts":${e.ts},`],
        ['hop-exp', `"exp":${h0.exp},`],
      ] as const) {
        const m = utf8(replaceOnce(t, from, `${from.slice(0, from.indexOf(':') + 1)}${n},`))
        differs(`T7 ${where} ${label}`, m, b.bytes)
        parse(`envelope-${where}-${label}`, m, 'bad-json')
      }
    }

    const owner = generateSigningKey(rng)
    const addr = addressRecord(cast, owner)
    recordCase2(cases, 'T7', 'record-control-address', addr, 'ok')
    for (const [label, n] of PAST_RANGE) {
      for (const [where, from] of [
        ['iat', `"iat":${T0},`],
        ['ttl', `"ttl":${DAY},`],
      ] as const) {
        const m = utf8(
          replaceOnce(text(recordBytes(addr)), from, `${from.slice(0, from.indexOf(':') + 1)}${n},`),
        )
        differs(`T7 record ${where} ${label}`, m, recordBytes(addr))
        recordCase2(cases, 'T7', `address-${where}-${label}`, m, 'bad-json')
      }
    }
  }

  // T8, drawn after T7 so T7's cases keep their bytes: the largest finite double,
  // `1.7976931348623158e308` (which rounds to DBL_MAX) and `1.7976931348623157e308` (DBL_MAX), is carried in the
  // body, alone and nested, and its plaintext is ok through the json kind, which Rust judges with serde_json's
  // float_roundtrip.
  openCase('T8', 't8-body-rounds-to-largest-double', '1.7976931348623158e308', 'ok')
  openCase('T8', 't8-body-nested-rounds-to-largest-double', '{"x":[1.5,{"y":1.7976931348623158e308}]}', 'ok')
  openCase('T8', 't8-body-largest-double', '1.7976931348623157e308', 'ok')

  return fileOf2(
    "T7: a number past the range of a double (1e400, -1e400, 1E400, 1e309, 1.7976931348623159e308, integers of 401 digits) inside the sealed body, alone, nested or beside finite numbers, or as the content's type, is bad-content (the open kind; its plaintext through the json kind is bad-json), since the body is exempt from §2.5's integer rule only (§4.2); a finite body number however written (1e-400, which underflows to 0, 1e308, 1.5, the largest double) is carried, ok. The same spellings as an envelope's ts and a hop's exp (parse) and as an address record's iat and ttl (record) are bad-json. T8: 1.7976931348623158e308, which rounds to the largest double, and 1.7976931348623157e308, the largest double, are carried in the body, alone and nested, ok, and their plaintext is ok through the json kind.",
    cases,
  )
}

// ---- writing and checking ---------------------------------------------------------------------------------------

export interface Built5 {
  readonly files: Record<FileName, J>
  readonly f1: F1Summary
  /** Round-2 cases whose pre-registered verdict is not the TypeScript core's. */
  readonly round2Differs: readonly string[]
}

export function build(): Built5 {
  rng = xorshiftRng(SEED)
  const cast = makeCast()
  const env = envelopeFile(cast)
  const chains = chainFile(cast)
  const records = recordFile(cast)
  const open = openFile(cast)
  const canon = canonicalFile([...chains.preimages, ...records.preimages])
  // Round 2 draws after the first five files' last draw, so those files are unchanged (G2).
  round2Differs = []
  const domains = domainsFile(cast)
  const records2 = recordsFile(cast)
  const keys = keysFile(cast)
  const duplicates = duplicatesFile(cast)
  // T7 draws after T5 and T6, so the four earlier round-2 files are unchanged too.
  const numbers = numbersFile(cast)
  return {
    files: {
      'canonical-fuzz.json': canon,
      'envelope-mutations.json': env.file,
      'chain-mutations.json': chains.file,
      'record-mutations.json': records.file,
      'open-cases.json': open,
      'round2-domains.json': domains,
      'round2-records.json': records2,
      'round2-keys.json': keys,
      'round2-duplicates.json': duplicates,
      'round2-numbers.json': numbers,
    },
    f1: env.f1,
    round2Differs,
  }
}

/** The file as written, in process: two-space JSON and a newline (the content is the contract; G2 pins the bytes). */
function formatted(value: J): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

function writeAll(dir: string): Built5 {
  const built = build()
  for (const name of FILES) writeFileSync(join(dir, name), formatted(built.files[name]))
  return built
}

function summarize(built: Built5): void {
  let total = 0
  for (const name of FILES) {
    const cases = list(built.files[name].cases).map(obj)
    total += cases.length
    const byLine = new Map<string, number>()
    for (const c of cases) byLine.set(c.line as string, (byLine.get(c.line as string) ?? 0) + 1)
    console.log(
      `gen-adversarial: ${name}: ${cases.length} cases (${[...byLine].map(([l, n]) => `${l} ${n}`).join(', ')})`,
    )
  }
  const v = Object.entries(built.f1.verdicts)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k} ${n}`)
    .join(', ')
  console.log(
    `gen-adversarial: F1 swept ${built.f1.mutations} mutations of ${built.f1.envelopes} envelopes, kept ${built.f1.kept}; verdicts: ${v}`,
  )
  console.log(`gen-adversarial: ${total} cases in ${FILES.length} files`)
  console.log(
    `gen-adversarial: round 2: ${built.round2Differs.length} case(s) whose pre-registered verdict is not the TypeScript core's${built.round2Differs.length === 0 ? '' : ':'}`,
  )
  for (const d of built.round2Differs) console.log(`gen-adversarial:   ${d}`)
}

function check(): number {
  const root = process.env.AC_TEST_TMP || tmpdir()
  const dir = mkdtempSync(join(root, 'bag-adversarial-'))
  let problems = 0
  try {
    const built = writeAll(dir)
    for (const name of FILES) {
      const committedPath = join(ADVERSARIAL_DIR, name)
      if (!existsSync(committedPath)) {
        console.error(`adversarial:check: spec/adversarial/${name} is missing`)
        problems++
        continue
      }
      const same = readFileSync(committedPath).equals(readFileSync(join(dir, name)))
      if (same) console.log(`adversarial:check: ${name} byte-identical`)
      else {
        console.error(`adversarial:check: ${name} differs from the regenerated file`)
        problems++
      }
    }
    const known = [...FILES, ...HAND_WRITTEN] as string[]
    for (const extra of readdirSync(ADVERSARIAL_DIR).filter((f) => !known.includes(f))) {
      console.error(`adversarial:check: spec/adversarial/${extra} is not written by the generator`)
      problems++
    }
    summarize(built)
    console.log(
      problems === 0
        ? `adversarial:check: OK, ${FILES.length} of ${FILES.length} files byte-identical`
        : `adversarial:check: FAIL, ${problems} problem(s)`,
    )
  } finally {
    if (process.env.AC_KEEP_TMP === '1') console.log(`adversarial:check: kept ${dir}`)
    else rmSync(dir, { recursive: true, force: true })
  }
  return problems === 0 ? 0 : 1
}

function main(argv: readonly string[]): number {
  if (argv.includes('--check')) return check()
  const built = writeAll(ADVERSARIAL_DIR)
  summarize(built)
  return 0
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = main(process.argv.slice(2))
}
