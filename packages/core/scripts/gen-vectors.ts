/**
 * Writes the test vectors, spec/vectors/*.json (spec/SPEC.md §11), from fixed seeds, fixed timestamps, a seeded
 * xorshift128+ rng and injected ephemeral keys. Every seed and key in them is test data by construction.
 *
 *   node packages/core/scripts/gen-vectors.ts                    rewrite spec/vectors
 *   node packages/core/scripts/gen-vectors.ts --check            regenerate into a temporary directory and fail unless
 *                                                                every file is byte-identical to spec/vectors
 *   node packages/core/scripts/gen-vectors.ts --upstream <file>  filter the CFRG test-vectors.json (its sha256 must
 *                                                                match) into hpke-rfc9180-subset.json
 *
 * Without --upstream, hpke-rfc9180-subset.json is rebuilt from the committed subset's inputs alone (info, ikmR, ikmE,
 * each pt and aad, each export's context and length), and this package's HPKE recomputes every other field: the check
 * fails if the implementation stops reproducing RFC 9180, as well as if a file was edited by hand.
 *
 * Each case states the result it must have, and the generator fails when the implementation disagrees, so a bug in
 * the core cannot be written into a vector unnoticed. Temporary files go under AC_TEST_TMP (default the system
 * temporary directory) and are removed unless AC_KEEP_TMP=1.
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { aeadSeal } from '../src/hpke.ts'
import {
  AC_ERROR_CODES,
  type AcRecord,
  type AddressRecord,
  AUDIT_GENESIS,
  type AuditFields,
  auditHash,
  auditPreimage,
  buildEnvelope,
  type CanonicalValue,
  canonical,
  checkDiscovered,
  checkHandleRecord,
  checkRecord,
  codingEvaluator,
  contentAad,
  countersignRotation,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  discover,
  type Envelope,
  encodeContent,
  envelopeId,
  envelopeIdPreimage,
  evaluateCaveats,
  FETCH_TAG,
  fetchAuthPreimage,
  fromHex,
  type HandleRecord,
  type Hop,
  handlePath,
  handleRecordPreimage,
  hopPreimage,
  hpkeOpen,
  hpkeSeal,
  isAcError,
  isAddress,
  isHex,
  newThread,
  openSealed,
  parseEnvelope,
  parseHandle,
  parseHandleRecord,
  parseRecord,
  parseTxtPresentation,
  preimageDigest,
  recordPreimage,
  recordSigner,
  replyThread,
  SEAL_INFO,
  type Sealed,
  type SealedContent,
  SUITE,
  sealedHash,
  sealedHashPreimage,
  sealTo,
  serializeEnvelope,
  serializeHandleRecord,
  serializeRecord,
  sha256hex,
  signFetchAuth,
  signHandleRecord,
  signHop,
  signPreimage,
  signRecord,
  signSubscribe,
  subscribePreimage,
  type Thread,
  toHex,
  txtName,
  type UnsignedAddressRecord,
  utf8,
  verifyChain,
  verifyFetchAuth,
  verifyHandleRecord,
  verifyOuter,
  verifyPreimage,
  verifyRecord,
  verifyRotation,
  verifyRotationClaim,
} from '../src/index.ts'
import { SMALL_ORDER_POINTS } from '../src/keys.ts'
import {
  add,
  bytesOf,
  challenge,
  decodeLoose,
  encode,
  FIELD_P,
  le,
  ORDER_L,
  type Point,
  signAs,
  signWithR,
} from '../test/support/ed25519.ts'
import { DAY, HOUR, opener, P, type Party, recipient, SIXTEEN, T0 } from '../test/support/fixtures.ts'
import { type RfcCase, rebuildRfcCase } from '../test/support/rfc9180.ts'
import { recordingRng, replayRng, xorshiftRng } from '../test/support/rng.ts'

const VECTORS_DIR = fileURLToPath(new URL('../../../spec/vectors/', import.meta.url))
const SUBSET = 'hpke-rfc9180-subset.json'
const FILES = [
  'canonical.json',
  'envelope.json',
  'sealed-multi.json',
  'chain-valid.json',
  'chain-invalid.json',
  'records.json',
  SUBSET,
  'discovery.json',
] as const
type FileName = (typeof FILES)[number]

const UPSTREAM = {
  url: 'https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json',
  sha256: '61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6',
  downloaded: '2026-10-24 17:30 UTC',
} as const

type J = Record<string, unknown>
const obj = (v: unknown): J => v as J
const list = (v: unknown): unknown[] => v as unknown[]
const text = (b: Uint8Array): string => new TextDecoder().decode(b)

function header(description: string, notes: readonly string[] = []): J {
  return {
    description,
    generated_by: 'packages/core/scripts/gen-vectors.ts',
    suite: SUITE,
    suite_parameters:
      'Ed25519 signatures; sealing with RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) (kem 0x0020), HKDF-SHA256 (kdf 0x0001), AES-256-GCM (aead 0x0002)',
    test_data:
      'Every seed, private key, content key and nonce in this file is test data, fixed by construction: seeds are one byte repeated 32 times, and the rest comes from a seeded xorshift128+. They are public; never let them protect anything real.',
    notes,
  }
}

/** Runs fn: 'ok', or the code of the AcError it throws. */
function outcome(fn: () => unknown): string {
  try {
    fn()
    return 'ok'
  } catch (e) {
    if (isAcError(e)) return e.code
    throw e
  }
}

function expectResult(name: string, got: string, want: string): string {
  if (got !== want) throw new Error(`gen-vectors: "${name}": the core says ${got}; the case says ${want}`)
  return got
}

function sealingOf(p: Party): { readonly seed: Uint8Array; readonly publicKey: Uint8Array } {
  if (p.sealing === undefined || p.sealingSeed === undefined)
    throw new Error(`gen-vectors: ${p.name} cannot receive`)
  return { seed: p.sealingSeed, publicKey: p.sealing.publicKey }
}

function hopVector(h: Hop): J {
  const preimage = hopPreimage(h)
  return { canonical: canonical(preimage), digest: toHex(preimageDigest(preimage)) }
}

// ---- envelopes -------------------------------------------------------------------------------------------------

interface EnvelopeSpec {
  readonly name: string
  readonly from: Party
  readonly to: readonly Party[]
  readonly auth?: readonly Hop[]
  readonly type: string
  readonly thread: Thread
  readonly body: unknown
  readonly ts: number
  readonly rngSeed: number
}

interface EnvelopeCase {
  readonly envelope: Envelope
  readonly bytes: Uint8Array
  readonly vector: J
}

function envelopeCase(s: EnvelopeSpec): EnvelopeCase {
  const rec = recordingRng(xorshiftRng(s.rngSeed))
  const content: SealedContent = { type: s.type, thread: s.thread, body: s.body }
  const { envelope, bytes } = buildEnvelope({
    from: s.from.key,
    to: s.to.map(recipient),
    auth: s.auth ?? [],
    ...content,
    ts: s.ts,
    rng: rec.rng,
  })
  const [contentKey, nonce, ...ephemeral] = rec.drawn
  if (contentKey === undefined || nonce === undefined || ephemeral.length !== s.to.length) {
    throw new Error(`gen-vectors: "${s.name}": unexpected rng draws`)
  }
  verifyOuter(envelope, s.ts)
  const chain = verifyChain(envelope.auth, envelope.from, envelope.ts)
  for (const p of s.to) {
    if (JSON.stringify(openSealed(envelope, opener(p))) !== JSON.stringify(content)) {
      throw new Error(`gen-vectors: "${s.name}": ${p.name} opened other content`)
    }
  }
  const coding = evaluateCaveats(chain.caveats, [codingEvaluator], {
    from: envelope.from,
    to: envelope.to,
    ts: envelope.ts,
    root: chain.root,
    sealed: content,
  })
  return {
    envelope,
    bytes,
    vector: {
      name: s.name,
      inputs: {
        from: s.from.address,
        from_seed: toHex(s.from.signingSeed),
        to: s.to.map((p) => ({
          address: p.address,
          sealing_key: toHex(sealingOf(p).publicKey),
          sealing_seed: toHex(sealingOf(p).seed),
        })),
        auth: envelope.auth,
        content,
        ts: s.ts,
        content_key: toHex(contentKey),
        nonce: toHex(nonce),
        ephemeral_seeds: ephemeral.map(toHex),
      },
      expected: {
        plaintext: text(encodeContent(content)),
        content_aad: text(contentAad(envelope.to, envelope.from)),
        hops: envelope.auth.map(hopVector),
        sealed_hash_canonical: canonical(sealedHashPreimage(envelope.sealed)),
        sealed_hash: sealedHash(envelope.sealed),
        id_canonical: canonical(envelopeIdPreimage(envelope)),
        id: envelope.id,
        sig: envelope.sig,
        chain,
        coding_profile: coding,
        envelope,
        bytes: text(bytes),
        size: bytes.length,
      },
    },
  }
}

const hopOrgJane = signHop(P.org.key, P.jane.address, ['type=coding.*'], T0 + 30 * DAY)
const hopJaneSession = signHop(P.jane.key, P.session.address, ['repo=acme/api'], T0 + 8 * HOUR)

const THREAD_1 = newThread(xorshiftRng(101))
const E1 = envelopeCase({
  name: 'self-rooted, one recipient',
  from: P.jane,
  to: [P.bob],
  type: 'coding.task.v1',
  thread: THREAD_1,
  body: { repo: 'acme/api', task: 'run the tests', note: 'naïve ✓ 日本語' },
  ts: T0,
  rngSeed: 1,
})
const E2 = envelopeCase({
  name: 'org to principal to session, with two coding caveats',
  from: P.session,
  to: [P.bob],
  auth: [hopOrgJane, hopJaneSession],
  type: 'coding.task.v1',
  thread: newThread(xorshiftRng(102)),
  body: { repo: 'acme/api', task: 'fix the flaky test' },
  ts: T0 + 60,
  rngSeed: 2,
})
const E3 = envelopeCase({
  name: 'a second root message, with a string body',
  from: P.carol,
  to: [P.bob],
  type: 'coding.result.v1',
  thread: newThread(xorshiftRng(103)),
  body: 'done',
  ts: T0 + 120,
  rngSeed: 3,
})
const E4 = envelopeCase({
  name: 'a fan-in reply naming three parents, to two recipients',
  from: P.bob,
  to: [P.jane, P.carol],
  type: 'coding.result.v1',
  thread: replyThread(THREAD_1, [E1.envelope.id, E2.envelope.id, E3.envelope.id]),
  body: { repo: 'acme/api', status: 'green', passed: 412, ratio: 0.5, flaky: false, note: null },
  ts: T0 + 180,
  rngSeed: 4,
})

function mutated(c: EnvelopeCase, f: (e: J) => void): string {
  const e = obj(JSON.parse(text(c.bytes)))
  f(e)
  return JSON.stringify(e)
}

/** The envelope's JSON text with members replaced (a member set to undefined is dropped by JSON.stringify). */
function withMembers(c: EnvelopeCase, members: J): string {
  return JSON.stringify({ ...obj(JSON.parse(text(c.bytes))), ...members })
}

/** The envelope's JSON text without one member. */
function without(c: EnvelopeCase, member: string): string {
  return withMembers(c, { [member]: undefined })
}

const ADDRESSES_17 = Array.from({ length: 17 }, (_, i) => `ed25519:${sha256hex(`recipient ${i}`)}`)

function parseCase(name: string, want: string, bytes: string, pad = 0): J {
  const full = bytes + ' '.repeat(pad)
  const result = expectResult(
    name,
    outcome(() => parseEnvelope(full)),
    want,
  )
  return pad > 0 ? { name, bytes, pad_with_spaces: pad, result } : { name, bytes, result }
}

function parseCaseHex(name: string, want: string, hex: string): J {
  const result = expectResult(
    name,
    outcome(() => parseEnvelope(Buffer.from(hex, 'hex'))),
    want,
  )
  return { name, bytes_hex: hex, result }
}

function verifyCase(name: string, want: string, bytes: string, now: number): J {
  const result = expectResult(
    name,
    outcome(() => verifyOuter(parseEnvelope(bytes), now)),
    want,
  )
  return { name, bytes, now, ttl: DEFAULT_TTL, skew: DEFAULT_SKEW, result }
}

function envelopeFile(): J {
  const b1 = text(E1.bytes)
  const b2 = text(E2.bytes)
  const parse = [
    parseCase('a valid envelope', 'ok', b1),
    parseCase('padded with spaces to exactly 65,536 bytes', 'ok', b1, 65_536 - E1.bytes.length),
    parseCase(
      'padded with spaces to 65,537 bytes, one over the cap',
      'envelope-too-large',
      b1,
      65_537 - E1.bytes.length,
    ),
    parseCase('not JSON', 'bad-json', 'not json'),
    parseCaseHex('not UTF-8', 'bad-json', '7bff7d'),
    parseCaseHex('a byte-order mark before the object', 'bad-json', `efbbbf${toHex(E1.bytes)}`),
    parseCase('a lone surrogate escaped in a caveat', 'bad-json', b2.replace('"repo=acme/api"', '"\\ud800"')),
    parseCase('a JSON list', 'bad-shape', '[]'),
    parseCase('v is 2', 'bad-version', withMembers(E1, { v: 2 })),
    parseCase('v is a string', 'bad-shape', withMembers(E1, { v: '1' })),
    parseCase('v is missing', 'bad-shape', without(E1, 'v')),
    parseCase('suite is 2', 'bad-suite', withMembers(E1, { suite: 2 })),
    parseCase('an extra member', 'bad-shape', withMembers(E1, { note: 'x' })),
    parseCase('sig is missing', 'bad-shape', without(E1, 'sig')),
    parseCase('id in upper-case hex', 'bad-hex', withMembers(E1, { id: E1.envelope.id.toUpperCase() })),
    parseCase('id is a number', 'bad-shape', withMembers(E1, { id: 1 })),
    parseCase('no recipients', 'bad-shape', withMembers(E1, { to: [] })),
    parseCase('seventeen recipients', 'too-many-recipients', withMembers(E1, { to: ADDRESSES_17 })),
    parseCase(
      'a recipient listed twice',
      'bad-shape',
      withMembers(E1, { to: [P.bob.address, P.bob.address] }),
    ),
    parseCase(
      'a recipient that is not an address',
      'bad-address',
      withMembers(E1, { to: [P.bob.address.toUpperCase()] }),
    ),
    parseCase(
      'from with another prefix',
      'bad-address',
      withMembers(E1, { from: E1.envelope.from.replace('ed25519:', 'x25519:') }),
    ),
    parseCase('nine hops', 'too-many-hops', withMembers(E2, { auth: Array(9).fill(hopOrgJane) })),
    parseCase(
      'a hop without sig',
      'bad-hop',
      mutated(E2, (e) => {
        delete obj(list(e.auth)[1]).sig
      }),
    ),
    parseCase(
      'thirty-three caveats in a hop',
      'too-many-caveats',
      mutated(E2, (e) => {
        obj(list(e.auth)[1]).caveats = Array.from({ length: 33 }, (_, i) => `c${i}`)
      }),
    ),
    parseCase(
      'a caveat of 257 bytes',
      'caveat-too-long',
      mutated(E2, (e) => {
        obj(list(e.auth)[1]).caveats = ['x'.repeat(257)]
      }),
    ),
    parseCase('auth is not a list', 'bad-shape', withMembers(E1, { auth: {} })),
    parseCase('ts is a fraction', 'bad-shape', withMembers(E1, { ts: T0 + 0.5 })),
    parseCase('ts is negative', 'bad-shape', withMembers(E1, { ts: -1 })),
    parseCase(
      'a wrap addressed to another recipient',
      'bad-shape',
      mutated(E1, (e) => {
        obj(list(obj(e.sealed).wraps)[0]).to = P.carol.address
      }),
    ),
    parseCase(
      'one wrap too many',
      'bad-shape',
      mutated(E1, (e) => {
        list(obj(e.sealed).wraps).push(list(obj(e.sealed).wraps)[0])
      }),
    ),
    parseCase(
      'a wrap with an extra member',
      'bad-shape',
      mutated(E1, (e) => {
        obj(list(obj(e.sealed).wraps)[0]).aad = ''
      }),
    ),
    parseCase(
      'a wrap ct of 47 bytes',
      'bad-hex',
      mutated(E1, (e) => {
        const w = obj(list(obj(e.sealed).wraps)[0])
        w.ct = String(w.ct).slice(2)
      }),
    ),
    parseCase(
      'a nonce of 11 bytes',
      'bad-hex',
      mutated(E1, (e) => {
        obj(e.sealed).nonce = String(obj(e.sealed).nonce).slice(2)
      }),
    ),
    parseCase(
      'a ct shorter than its tag',
      'bad-hex',
      mutated(E1, (e) => {
        obj(e.sealed).ct = '00'.repeat(15)
      }),
    ),
    parseCase('sig of 63 bytes', 'bad-hex', withMembers(E1, { sig: E1.envelope.sig.slice(2) })),
    parseCase(
      'order: v is checked before the members, so a v2 envelope is bad-version',
      'bad-version',
      mutated(E1, (e) => {
        e.v = 2
        e.extra = true
      }),
    ),
    parseCase(
      'order: to is checked before sealed',
      'too-many-recipients',
      mutated(E1, (e) => {
        e.to = ADDRESSES_17
        obj(e.sealed).nonce = 'zz'
      }),
    ),
    ...strictParseCases(b1, b2),
    parseCase(
      'order: wrap[0] is checked fully before wrap[1], so a bad-hex wrap[0] beats a bad-shape wrap[1] (SPEC §5.4 step 12)',
      'bad-hex',
      mutated(E4, (e) => {
        const wraps = list(obj(e.sealed).wraps)
        obj(wraps[0]).enc = 'zz'
        wraps[1] = { to: String(obj(wraps[1]).to), enc: String(obj(wraps[1]).enc) }
      }),
    ),
  ]
  const verify = [
    verifyCase('in the window', 'ok', b1, T0),
    verifyCase('at the stale edge: now = ts + ttl + skew', 'ok', b1, T0 + DEFAULT_TTL + DEFAULT_SKEW),
    verifyCase('one second past the stale edge', 'stale-ts', b1, T0 + DEFAULT_TTL + DEFAULT_SKEW + 1),
    verifyCase('at the future edge: now = ts - skew', 'ok', b1, T0 - DEFAULT_SKEW),
    verifyCase('one second past the future edge', 'future-ts', b1, T0 - DEFAULT_SKEW - 1),
    verifyCase(
      'a recipient added after signing',
      'bad-id',
      mutated(E1, (e) => {
        list(e.to).push(P.carol.address)
        const w = obj(list(obj(e.sealed).wraps)[0])
        list(obj(e.sealed).wraps).push({ to: P.carol.address, enc: w.enc, ct: w.ct })
      }),
      T0,
    ),
    verifyCase('ts moved after signing', 'bad-id', withMembers(E1, { ts: T0 + 1 }), T0),
    verifyCase(
      'a caveat stripped from the chain after signing',
      'bad-id',
      mutated(E2, (e) => {
        obj(list(e.auth)[1]).caveats = []
      }),
      T0 + 60,
    ),
    verifyCase(
      'the sealed ciphertext changed after signing',
      'bad-id',
      mutated(E1, (e) => {
        obj(e.sealed).ct = `00${String(obj(e.sealed).ct).slice(2)}`
      }),
      T0,
    ),
    verifyCase(
      "another key's signature over the same id",
      'bad-sig',
      withMembers(E1, { sig: toHex(P.mallory.key.sign(Buffer.from(E1.envelope.id, 'hex'))) }),
      T0,
    ),
    verifyCase(
      'from replaced and the id recomputed: the signature no longer matches',
      'bad-sig',
      mutated(E1, (e) => {
        e.from = P.mallory.address
        e.id = envelopeId(parseEnvelope(JSON.stringify(e)))
      }),
      T0,
    ),
    ...strictVerifyCases(),
  ]
  return {
    ...header(
      'Envelopes (spec/SPEC.md §5): each case lists its inputs (keys as seeds, the content, the injected content key, nonce and ephemeral keys) and every intermediate value: the plaintext, the content AAD, the canonical strings of the hops, the sealed hash and the id, the signature, the verified chain, the coding-profile evaluation, the envelope and its exact bytes. "parse" holds bytes and the result of parsing them (spec/SPEC.md §5, in check order); "verify" holds bytes that parse and the result of the outer checks at "now"; "open" holds a sealed part, the recipient that opens it with its sealing seed, and the result of opening and reading the content (§4.4, §5.2), with the content when it opens; "seal" holds a seal to a recipient key that is malformed or of small order, and its result (§4.1, §4.3); "key_record_seal" and "stolen_key" hold the forward-secrecy cases (§7.4), described in the notes below.',
      [
        'A parse case with bytes_hex gives its bytes in hex; with pad_with_spaces, its bytes are followed by that many ASCII spaces (0x20).',
        'result is "ok" or an error code from spec/SPEC.md, Appendix A.',
        'The rng draws, in order: the content key (32 bytes), the nonce (12), then one ephemeral X25519 private key (32) per recipient.',
        'Forward secrecy (spec/SPEC.md §7.4): "key_record_seal" seals a content key to the recipient\'s key-record sealing key and opens it with that key (ok); each case gives { address, key_record, now, epoch_seed, content_key, ephemeral_seed, wrap: { enc, ct }, result }. "stolen_key" seals a content key to an epoch key, then opens it after stolen_at with the recipient\'s long-term key and with the current (different) epoch key, both of which fail (open-failed), so only the deleted epoch key could have opened past mail; each case gives { address, long_term_seed, epoch: { key_record, seed }, current: { key_record, seed }, sealed_at, stolen_at, content_key, ephemeral_seed, wrap, result }.',
        'The cases added on 2026-10-25 (spec/SPEC.md §2.3 and §2.5) follow the earlier ones in each list. "verify": the 14 degenerate keys (the eight points of small order, two x = 0 encodings with the sign bit set, four y + p encodings) as from, with R the identity and S = 0 and ts ground until k = SHA-512(R || A || M) mod L is 0 mod 8, so that OpenSSL alone accepts each; S + L, S = L and S = 2^256 - 1; R as each small-order point and sign alias and each of the 38 y + p encodings, with S = k·a from the sender\'s own key, so that a verifier comparing points rather than R\'s 32 bytes accepts the ones that decode to the identity; a mixed-order key (an honest key plus a point of order 8) with k not 0 mod 8, and a mixed-order R, which a cofactored check accepts. "parse": duplicate member names and numbers that are not plain decimal integers.',
      ],
    ),
    cases: [E1.vector, E2.vector, E3.vector, E4.vector],
    parse,
    verify,
    open: openCases(),
    seal: sealCases(),
    key_record_seal: keyRecordSealCases(),
    stolen_key: stolenKeyCases(),
  }
}

function sealedMultiFile(): J {
  const cases = [
    envelopeCase({
      name: 'two recipients, with a chain',
      from: P.session,
      to: [P.bob, P.carol],
      auth: [hopOrgJane, hopJaneSession],
      type: 'coding.task.v1',
      thread: newThread(xorshiftRng(111)),
      body: { repo: 'acme/api', task: 'review the patch' },
      ts: T0 + 300,
      rngSeed: 11,
    }),
    envelopeCase({
      name: 'three recipients',
      from: P.jane,
      to: [P.bob, P.carol, P.dave],
      type: 'coding.question.v1',
      thread: newThread(xorshiftRng(112)),
      body: { question: 'who owns the release?' },
      ts: T0 + 360,
      rngSeed: 12,
    }),
    envelopeCase({
      name: 'sixteen recipients, the cap',
      from: P.jane,
      to: SIXTEEN,
      type: 'coding.announce.v1',
      thread: newThread(xorshiftRng(113)),
      body: { text: 'the build is green' },
      ts: T0 + 420,
      rngSeed: 13,
    }),
  ]
  for (const c of cases) {
    const keys = new Set(c.envelope.sealed.wraps.map((w) => w.enc))
    if (keys.size !== c.envelope.to.length) throw new Error('gen-vectors: two wraps share an ephemeral key')
  }
  return {
    ...header(
      'One envelope sealed to several recipients: one id, one content ciphertext, and one wrap per recipient, each holding the same content key. Every recipient opens its own wrap. Same layout as envelope.json "cases".',
      [
        'The rng draws, in order: the content key (32 bytes), the nonce (12), then one ephemeral X25519 private key (32) per recipient.',
      ],
    ),
    cases: cases.map((c) => c.vector),
  }
}

// ---- chains ----------------------------------------------------------------------------------------------------

function chainValid(name: string, from: string, ts: number, auth: readonly Hop[]): J {
  const chain = verifyChain(auth, from, ts)
  return { name, from, ts, auth, hops: auth.map(hopVector), result: 'ok', chain }
}

function chainInvalid(
  name: string,
  rule: number,
  want: string,
  from: string,
  ts: number,
  auth: readonly unknown[],
): J {
  const result = expectResult(
    name,
    outcome(() => verifyChain(auth as readonly Hop[], from, ts)),
    want,
  )
  return { name, rule, from, ts, auth, result }
}

/** A chain of `n` hops through SIXTEEN[0] .. SIXTEEN[n], each adding one caveat, expiries non-increasing. */
function longChain(n: number): Hop[] {
  return Array.from({ length: n }, (_, i) => {
    const iss = SIXTEEN[i] as Party
    const sub = SIXTEEN[i + 1] as Party
    return signHop(iss.key, sub.address, [`type=coding.level${i}.*`], T0 + (30 - i) * DAY)
  })
}

/** A copy of a hop with members replaced; a member set to undefined is dropped. */
function hopWith(h: Hop, members: J): J {
  return obj(JSON.parse(JSON.stringify({ ...h, ...members })))
}

const hopSessionWorker = signHop(P.session.key, P.worker.address, ['type=coding.task.*'], T0 + HOUR)

function chainValidFile(): J {
  const eight = longChain(8)
  const thirtyTwo = Array.from({ length: 31 }, (_, i) => `c${i}`).concat(['é'.repeat(128)])
  return {
    ...header(
      'Authority chains that verify (spec/SPEC.md §6): each case gives the sender (from), the time the hops are judged at (ts), the hops, each hop preimage canonical string and digest, and what the chain establishes: its root, its principal (the last hop\'s iss, or from) and the effective caveats in chain order. "caveats" (added 2026-10-25) holds effective caveats, a sealed content, and the coding profile\'s verdict on them (§6.3, §6.4): "ok", or the code and the caveat that decided.',
    ),
    cases: [
      chainValid('the empty chain: self-rooted', P.jane.address, T0, []),
      chainValid('one hop: jane to her session', P.session.address, T0, [
        signHop(P.jane.key, P.session.address, [], T0 + 8 * HOUR),
      ]),
      chainValid('two hops: org to jane to session, with coding caveats', P.session.address, T0, [
        hopOrgJane,
        hopJaneSession,
      ]),
      chainValid('three hops: down to a sub-agent', P.worker.address, T0, [
        hopOrgJane,
        hopJaneSession,
        hopSessionWorker,
      ]),
      chainValid('eight hops, the cap', (SIXTEEN[8] as Party).address, T0, eight),
      chainValid('equal expiries are allowed', P.session.address, T0, [
        signHop(P.org.key, P.jane.address, [], T0 + DAY),
        signHop(P.jane.key, P.session.address, [], T0 + DAY),
      ]),
      chainValid("ts equal to the last hop's exp", P.session.address, T0 + 8 * HOUR, [
        hopOrgJane,
        hopJaneSession,
      ]),
      chainValid('thirty-two caveats, one of exactly 256 UTF-8 bytes', P.session.address, T0, [
        signHop(P.jane.key, P.session.address, thirtyTwo, T0 + HOUR),
      ]),
      chainValid('a caveat of exactly 256 ASCII bytes', P.session.address, T0, [
        signHop(P.jane.key, P.session.address, ['x'.repeat(256)], T0 + HOUR),
      ]),
      chainValid('non-ASCII caveats', P.session.address, T0, [
        signHop(P.jane.key, P.session.address, ['repo=équipe/日本', 'type=coding.*'], T0 + HOUR),
      ]),
      chainValid('a middle hop that adds no caveat', P.worker.address, T0, [
        hopOrgJane,
        signHop(P.jane.key, P.session.address, [], T0 + 8 * HOUR),
        hopSessionWorker,
      ]),
      mixedChainValid(),
    ],
    caveats: caveatCases(),
  }
}

function chainInvalidFile(): J {
  const s = P.session.address
  const strip = signHop(P.jane.key, P.session.address, ['repo=acme/api', 'type=coding.task.*'], T0 + 8 * HOUR)
  return {
    ...header(
      'Authority chains that fail (spec/SPEC.md §6): each case names the rule it breaks and the result. The rules run in order, each over every hop before the next, so a chain that breaks several rules fails with the first; the cases named "order" pin that.',
      [
        'rule: 1 hops <= 8; 2 each hop well-formed; 3 caveats <= 32 per hop; 4 each caveat <= 256 UTF-8 bytes; 5 hop[i].sub == hop[i+1].iss; 6 the last sub is from; 7 hop[i+1].exp <= hop[i].exp; 8 ts <= exp for every hop; 9 every hop sig verifies under its iss.',
      ],
    ),
    cases: [
      chainInvalid('nine hops', 1, 'too-many-hops', (SIXTEEN[9] as Party).address, T0, longChain(9)),
      chainInvalid('a hop without sig', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { sig: undefined }),
      ]),
      chainInvalid('a hop with an extra member', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { iat: T0 }),
      ]),
      chainInvalid('iss in upper-case hex', 2, 'bad-hop', s, T0, [
        hopWith(hopOrgJane, { iss: hopOrgJane.iss.toUpperCase() }),
        hopJaneSession,
      ]),
      chainInvalid('sub with another prefix', 2, 'bad-hop', s, T0, [
        hopWith(hopOrgJane, { sub: hopOrgJane.sub.replace('ed25519:', 'x25519:') }),
        hopJaneSession,
      ]),
      chainInvalid('exp is a fraction', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { exp: T0 + 0.5 }),
      ]),
      chainInvalid('exp is negative', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { exp: -1 }),
      ]),
      chainInvalid('exp is a string', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { exp: String(T0) }),
      ]),
      chainInvalid('exp is 2^53, past the largest integer', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { exp: 2 ** 53 }),
      ]),
      chainInvalid('caveats is not a list', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: 'repo=acme/api' }),
      ]),
      chainInvalid('a caveat that is a number', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: [7] }),
      ]),
      chainInvalid('an empty caveat', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: [''] }),
      ]),
      chainInvalid('sig of 63 bytes', 2, 'bad-hop', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { sig: hopJaneSession.sig.slice(2) }),
      ]),
      chainInvalid('a hop that is a list', 2, 'bad-hop', s, T0, [hopOrgJane, Object.values(hopJaneSession)]),
      chainInvalid('a hop that is null', 2, 'bad-hop', s, T0, [hopOrgJane, null]),
      chainInvalid('thirty-three caveats', 3, 'too-many-caveats', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: Array.from({ length: 33 }, (_, i) => `c${i}`) }),
      ]),
      chainInvalid('a caveat of 257 ASCII bytes', 4, 'caveat-too-long', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: ['x'.repeat(257)] }),
      ]),
      chainInvalid('a caveat of 258 UTF-8 bytes in 129 characters', 4, 'caveat-too-long', s, T0, [
        hopOrgJane,
        hopWith(hopJaneSession, { caveats: ['é'.repeat(129)] }),
      ]),
      chainInvalid("a broken link: hop 0's sub is not hop 1's iss", 5, 'chain-broken', s, T0, [
        signHop(P.org.key, P.carol.address, ['type=coding.*'], T0 + 30 * DAY),
        hopJaneSession,
      ]),
      chainInvalid('the last sub is not the sender', 6, 'chain-not-to-sender', P.worker.address, T0, [
        hopOrgJane,
        hopJaneSession,
      ]),
      chainInvalid('a child hop that outlives its parent', 7, 'exp-not-monotone', s, T0, [
        hopOrgJane,
        signHop(P.jane.key, P.session.address, ['repo=acme/api'], T0 + 31 * DAY),
      ]),
      chainInvalid('the last hop expired one second before ts', 8, 'hop-expired', s, T0 + 8 * HOUR + 1, [
        hopOrgJane,
        hopJaneSession,
      ]),
      chainInvalid('the root hop expired', 8, 'hop-expired', s, T0 + 2 * DAY, [
        signHop(P.org.key, P.jane.address, [], T0 + DAY),
        signHop(P.jane.key, P.session.address, [], T0 + DAY),
      ]),
      chainInvalid('a hop signed by a key that is not its iss', 9, 'bad-hop-sig', s, T0, [
        { ...hopOrgJane, sig: signPreimage(P.mallory.key, hopPreimage(hopOrgJane)) },
        hopJaneSession,
      ]),
      chainInvalid('a caveat stripped from a signed hop', 9, 'bad-hop-sig', s, T0, [
        hopOrgJane,
        { ...strip, caveats: ['repo=acme/api'] },
      ]),
      chainInvalid('a caveat appended to a signed hop', 9, 'bad-hop-sig', s, T0, [
        hopOrgJane,
        { ...hopJaneSession, caveats: [...hopJaneSession.caveats, 'type=coding.task.*'] },
      ]),
      chainInvalid('an exp extended after signing', 9, 'bad-hop-sig', s, T0, [
        hopOrgJane,
        { ...hopJaneSession, exp: hopJaneSession.exp + 1 },
      ]),
      chainInvalid('order: rule 1 before rule 2 (nine hops, one malformed)', 1, 'too-many-hops', s, T0, [
        ...Array(8).fill(hopOrgJane),
        null,
      ]),
      chainInvalid('order: rule 2 before rule 3 (33 caveats, then a malformed hop)', 2, 'bad-hop', s, T0, [
        hopWith(hopOrgJane, { caveats: Array.from({ length: 33 }, (_, i) => `c${i}`) }),
        hopWith(hopJaneSession, { sig: undefined }),
      ]),
      chainInvalid('order: rule 5 before rule 8 (broken and expired)', 5, 'chain-broken', s, T0 + 40 * DAY, [
        signHop(P.org.key, P.carol.address, [], T0 + 30 * DAY),
        hopJaneSession,
      ]),
      chainInvalid(
        'order: rule 7 before rule 9 (outlives its parent and a bad signature)',
        7,
        'exp-not-monotone',
        s,
        T0,
        [hopOrgJane, { ...hopJaneSession, exp: T0 + 31 * DAY }],
      ),
      chainInvalid(
        'order: rule 8 before rule 9 (expired and a bad signature)',
        8,
        'hop-expired',
        s,
        T0 + 9 * HOUR,
        [hopOrgJane, { ...hopJaneSession, caveats: [] }],
      ),
      ...strictChainCases(),
    ],
  }
}

// ---- records ---------------------------------------------------------------------------------------------------

const ACME_RELAY = 'https://relay.acme.example'
const orgRecord = signRecord(P.org.key, {
  kind: 'address',
  key: P.org.address,
  sealing_key: null,
  relays: [ACME_RELAY],
  rotation_key: P.rotation.address,
  revoked: [P.mallory.address],
  ttl: DAY,
  iat: T0,
  rotated_from: null,
})
const janeRecord = signRecord(P.jane.key, {
  kind: 'address',
  key: P.jane.address,
  sealing_key: toHex(sealingOf(P.jane).publicKey),
  relays: [ACME_RELAY, 'http://127.0.0.1:7700'],
  rotation_key: null,
  revoked: [],
  ttl: HOUR,
  iat: T0,
  rotated_from: null,
})
const bobAccept = signRecord(P.bob.key, {
  kind: 'accept-from',
  owner: P.bob.address,
  roots: [P.org.address, P.carol.address, P.jane.address],
  max_bytes: 65_536,
  ttl: 7 * DAY,
  iat: T0,
})
const carolAccept = signRecord(P.carol.key, {
  kind: 'accept-from',
  owner: P.carol.address,
  roots: ['*'],
  max_bytes: 32_768,
  ttl: DAY,
  iat: T0,
})
// Changed 2026-10-25: a key record lives a day at most, so this one's exp moved from T0 + 30 days to
// T0 + 1 day; the case below and canonical.json's key record preimage changed with it.
const janeKeyRecord = signRecord(P.jane.key, {
  kind: 'key',
  key: P.jane.address,
  sealing_key: toHex(sealingOf(P.jane).publicKey),
  iat: T0,
  exp: T0 + DAY,
})
const nextUnsigned: UnsignedAddressRecord = {
  kind: 'address',
  key: P.orgNext.address,
  sealing_key: null,
  relays: [ACME_RELAY],
  rotation_key: P.rotation.address,
  revoked: [],
  ttl: DAY,
  iat: T0 + DAY,
  rotated_from: P.org.address,
}
const nextBare = signRecord(P.orgNext.key, nextUnsigned)
const nextByPrev = countersignRotation(P.org.key, nextBare)
// Domain roots: accept-from records that name domains, appended after every earlier
// case so that those stay byte-identical.
const daveAcceptDomains = signRecord(P.dave.key, {
  kind: 'accept-from',
  owner: P.dave.address,
  roots: ['domain:acme.example', P.org.address, 'domain:relay-acme.usuals.now'],
  max_bytes: 65_536,
  ttl: 7 * DAY,
  iat: T0,
})
const bobAcceptDomain = signRecord(P.bob.key, {
  kind: 'accept-from',
  owner: P.bob.address,
  roots: ['domain:acme.example'],
  max_bytes: 65_536,
  ttl: DAY,
  iat: T0 + HOUR,
})
const LONG_HOST = [...Array(3).fill('a'.repeat(63)), 'a'.repeat(62)].join('.')
// An address record whose one relay holds a U+2028 line separator: RELAY_URL (§7.1) bans only space and Cc, so the
// separator is accepted. Appended after the earlier records so their vectors stay byte-identical.
const u2028RelayRecord = signRecord(P.jane.key, {
  kind: 'address',
  key: P.jane.address,
  sealing_key: toHex(sealingOf(P.jane).publicKey),
  relays: [`https://relay${String.fromCharCode(0x2028)}.acme.example`],
  rotation_key: null,
  revoked: [],
  ttl: HOUR,
  iat: T0,
  rotated_from: null,
})

function recordCase(name: string, record: AcRecord, checks: readonly (readonly [number, string])[]): J {
  const preimage = recordPreimage(record)
  return {
    name,
    record,
    canonical: canonical(preimage),
    digest: toHex(preimageDigest(preimage)),
    signer: recordSigner(record),
    checks: checks.map(([now, want]) => ({
      now,
      skew: DEFAULT_SKEW,
      result: expectResult(
        `${name} at ${now}`,
        outcome(() => verifyRecord(record, now)),
        want,
      ),
    })),
  }
}

function invalidRecord(name: string, want: string, base: AcRecord, members: J): J {
  const r = obj(JSON.parse(JSON.stringify({ ...base, ...members })))
  return {
    name,
    record: r,
    result: expectResult(
      name,
      outcome(() => checkRecord(r)),
      want,
    ),
  }
}

function rotation(name: string, want: string, prev: AddressRecord, next: AddressRecord): J {
  return {
    name,
    prev,
    next,
    result: expectResult(
      name,
      outcome(() => verifyRotation(prev, next)),
      want,
    ),
  }
}

function recordsFile(): J {
  const forged = { ...orgRecord, sig: signPreimage(P.mallory.key, recordPreimage(orgRecord)) }
  const revoked1025 = Array.from({ length: 1025 }, (_, i) => `ed25519:${sha256hex(`revoked ${i}`)}`)
  return {
    ...header(
      'Records (spec/SPEC.md §7): each case gives a signed record, its preimage canonical string and digest, its signer, and the result of verifying it at several times. "invalid" holds records that fail the form and cap checks, which run before the signature. "rotations" holds pairs (prev, next) and the result of the rotation check. "parse" holds bytes (or bytes_hex) and the result of reading them as a record (§2.5, §7.1). "rotation_claims" holds a record and the result of checking the rotation it claims by a reader that holds no record of its rotated_from (§7.3).',
      [
        'A record is valid from iat - skew; an address record until iat + ttl, a key record until exp, at most iat + 86,400; an accept-from record does not expire, and its roots hold at most 1,024 entries.',
        'The cases added on 2026-10-25 follow the earlier ones in each list: the 14 degenerate keys as a record key with R the identity and S = 0 and iat ground until k is 0 mod 8, R the identity with S = k·a under the org key, the roots cap, the key record of a day, "parse" and "rotation_claims". The key record case changed: its exp was iat + 30 days.',
      ],
    ),
    cases: [
      recordCase('an org address record with a rotation key and a revoked key', orgRecord, [
        [T0, 'ok'],
        [T0 + DAY, 'ok'],
        [T0 + DAY + 1, 'record-expired'],
        [T0 - DEFAULT_SKEW, 'ok'],
        [T0 - DEFAULT_SKEW - 1, 'future-iat'],
      ]),
      recordCase("an individual's address record with a sealing key and two relays", janeRecord, [
        [T0 + HOUR, 'ok'],
        [T0 + HOUR + 1, 'record-expired'],
      ]),
      recordCase('an accept-from record with listed roots', bobAccept, [
        [T0, 'ok'],
        [T0 + 365 * DAY, 'ok'],
        [T0 - DEFAULT_SKEW - 1, 'future-iat'],
      ]),
      recordCase('an accept-from record with the wildcard root', carolAccept, [[T0, 'ok']]),
      recordCase('a key record', janeKeyRecord, [
        [T0 + DAY, 'ok'],
        [T0 + DAY + 1, 'record-expired'],
      ]),
      recordCase('a rotated address record, countersigned by the previous key', nextByPrev, [
        [T0 + DAY, 'ok'],
      ]),
      recordCase("a record signed by a key that is not the record's", forged, [[T0, 'bad-record-sig']]),
      recordCase('a record changed after signing', { ...orgRecord, ttl: HOUR }, [[T0, 'bad-record-sig']]),
      recordCase('an accept-from record with domain roots beside an address', daveAcceptDomains, [
        [T0, 'ok'],
        [T0 + 365 * DAY, 'ok'],
      ]),
      recordCase('an accept-from record with one domain root', bobAcceptDomain, [
        [T0 + HOUR, 'ok'],
        [T0 + HOUR - DEFAULT_SKEW - 1, 'future-iat'],
      ]),
      recordCase('an accept-from record with 1,024 roots, the cap', bobAcceptFull, [[T0 + 2 * HOUR, 'ok']]),
      ...strictRecordCases(),
      recordCase(
        'a relay URL with a U+2028 line separator is accepted (§7.1): RELAY_URL bans space and Cc only',
        u2028RelayRecord,
        [[T0 + HOUR, 'ok']],
      ),
    ],
    invalid: [
      invalidRecord('an unknown kind', 'bad-record', orgRecord, { kind: 'org' }),
      invalidRecord('a missing member', 'bad-record', orgRecord, { revoked: undefined }),
      invalidRecord('an extra member', 'bad-record', orgRecord, { domain: 'acme.example' }),
      invalidRecord('sixty-five relays', 'too-many-relays', orgRecord, {
        relays: Array.from({ length: 65 }, (_, i) => `https://relay${i}.acme.example`),
      }),
      invalidRecord('a relay that is not http or https', 'bad-record', orgRecord, {
        relays: ['ftp://relay.acme.example'],
      }),
      invalidRecord('a relay with a space', 'bad-record', orgRecord, {
        relays: ['https://relay .acme.example'],
      }),
      invalidRecord('a relay with no host', 'bad-record', orgRecord, { relays: ['https:///v0'] }),
      invalidRecord('a relay listed twice', 'bad-record', orgRecord, { relays: [ACME_RELAY, ACME_RELAY] }),
      invalidRecord('1,025 revoked keys', 'too-many-revoked', orgRecord, { revoked: revoked1025 }),
      invalidRecord('a revoked entry that is not an address', 'bad-record', orgRecord, {
        revoked: ['mallory'],
      }),
      invalidRecord('ttl over 24 hours', 'bad-record', orgRecord, { ttl: DAY + 1 }),
      invalidRecord('ttl of zero', 'bad-record', orgRecord, { ttl: 0 }),
      invalidRecord('a rotation_sig without rotated_from', 'bad-record', orgRecord, {
        rotation_sig: orgRecord.sig,
      }),
      invalidRecord('a sealing_key of 31 bytes', 'bad-record', janeRecord, { sealing_key: '00'.repeat(31) }),
      invalidRecord('no roots', 'bad-record', bobAccept, { roots: [] }),
      invalidRecord('the wildcard beside an address', 'bad-record', bobAccept, {
        roots: ['*', P.org.address],
      }),
      invalidRecord('max_bytes of zero', 'bad-record', bobAccept, { max_bytes: 0 }),
      invalidRecord('exp before iat', 'bad-record', janeKeyRecord, { exp: T0 - 1 }),
      invalidRecord('a domain root in upper case', 'bad-record', daveAcceptDomains, {
        roots: ['domain:ACME.example'],
      }),
      invalidRecord('a domain root that is an IP literal', 'bad-record', daveAcceptDomains, {
        roots: ['domain:192.0.2.1'],
      }),
      invalidRecord('a domain root with a trailing dot', 'bad-record', daveAcceptDomains, {
        roots: ['domain:acme.example.'],
      }),
      invalidRecord('a domain root with no dot', 'bad-record', daveAcceptDomains, {
        roots: ['domain:localhost'],
      }),
      invalidRecord('a domain root over 253 characters', 'bad-record', daveAcceptDomains, {
        roots: [`domain:${LONG_HOST}`],
      }),
      invalidRecord('a domain root with a label over 63 characters', 'bad-record', daveAcceptDomains, {
        roots: [`domain:${'a'.repeat(64)}.example`],
      }),
      invalidRecord('a domain root with a hyphen at the edge of a label', 'bad-record', daveAcceptDomains, {
        roots: ['domain:-acme.example'],
      }),
      invalidRecord('a domain root with a port', 'bad-record', daveAcceptDomains, {
        roots: ['domain:acme.example:443'],
      }),
      invalidRecord('the wildcard beside a domain root', 'bad-record', daveAcceptDomains, {
        roots: ['*', 'domain:acme.example'],
      }),
      invalidRecord('a domain root listed twice', 'bad-record', daveAcceptDomains, {
        roots: ['domain:acme.example', 'domain:acme.example'],
      }),
      invalidRecord('a host without the domain: prefix', 'bad-record', daveAcceptDomains, {
        roots: ['acme.example'],
      }),
      invalidRecord('1,025 roots, one over the cap', 'bad-record', bobAccept, {
        roots: [...ROOTS_1024, `ed25519:${sha256hex('root 1024')}`],
      }),
      invalidRecord('a key record that lives one second over a day', 'bad-record', janeKeyRecord, {
        exp: T0 + DAY + 1,
      }),
      // The relay-URL class (§7.1, records.ts RELAY_URL = /^https?:\/\/[^\p{Cc} /?#]+[^\p{Cc} ]*$/u): a space is
      // already pinned above ("a relay with a space"); a Unicode Cc control character is banned too, while U+2028 is
      // accepted (the "cases" list pins that), since the class bans only space and Cc.
      invalidRecord('a relay URL with a control character (Cc)', 'bad-record', orgRecord, {
        relays: [`https://relay${String.fromCharCode(1)}.acme.example`],
      }),
    ],
    rotations: [
      rotation('countersigned by the previous key', 'ok', orgRecord, nextByPrev),
      rotation(
        'countersigned by the rotation key',
        'ok',
        orgRecord,
        countersignRotation(P.rotation.key, nextBare),
      ),
      rotation('a bare rotation: no rotation_sig', 'bad-rotation', orgRecord, nextBare),
      rotation(
        'countersigned by a key with no standing',
        'bad-rotation',
        orgRecord,
        countersignRotation(P.mallory.key, nextBare),
      ),
      rotation(
        'rotated_from names another key',
        'bad-rotation',
        orgRecord,
        countersignRotation(
          P.org.key,
          signRecord(P.orgNext.key, { ...nextUnsigned, rotated_from: P.jane.address }),
        ),
      ),
      rotation('a record that does not name the previous key', 'bad-rotation', orgRecord, janeRecord),
    ],
    parse: recordParseCases(),
    rotation_claims: rotationClaims(),
  }
}

// ---- canonical form and the position tables ----------------------------------------------------------------------

const CONTROL = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i))
  .filter((c) => !'\b\f\n\r\t'.includes(c))
  .join('')

const CANONICAL_VALID: readonly (readonly [string, CanonicalValue])[] = [
  ['null', null],
  ['zero', 0],
  ['the largest integer, 2^53 - 1', 9_007_199_254_740_991],
  ['the empty list', []],
  ['the empty string', ''],
  ['plain ASCII', 'bag'],
  ['a quotation mark and a backslash, escaped', 'say "hi" \\ bye'],
  ['the five short escapes', '\b\f\n\r\t'],
  ['every other control character, as lowercase \\u00xx', CONTROL],
  ['DEL, U+2028 and U+2029, not escaped', '\u007f  '],
  ['the solidus, not escaped', 'a/b'],
  ['non-ASCII, not escaped and not normalized (precomposed and decomposed é)', 'café café 日本語'],
  ['a character outside the Basic Multilingual Plane', '😀'],
  ['integers', [0, 1, 9, 10, 255, 1_800_000_000]],
  ['nested lists', [[], [[]], ['a', [1, null]]]],
  ['a hop-shaped list', ['ac/hop/1', P.org.address, P.jane.address, ['type=coding.*'], T0]],
]

const CANONICAL_INVALID: readonly (readonly [string, unknown])[] = [
  ['a fraction', 1.5],
  ['a negative integer', -1],
  ['2^53, one past the largest integer', 2 ** 53],
  ['true', true],
  ['false', false],
  ['an object', { a: 1 }],
  ['an empty object', {}],
  ['an object inside a list', ['a', {}]],
  ['a boolean deep in a list', [[[false]]]],
]

const CANONICAL_UTF16: readonly (readonly [string, string])[] = [
  ['a lone high surrogate', 'd800'],
  ['a lone low surrogate', 'dc00'],
  ['a low surrogate before a high one', 'dc00d800'],
]

function fromUtf16Hex(hex: string): string {
  return String.fromCharCode(...(hex.match(/.{4}/g) ?? []).map((u) => Number.parseInt(u, 16)))
}

function preimageVector(table: string, preimage: CanonicalValue, signer?: string, sig?: string): J {
  const c = canonical(preimage)
  if (signer !== undefined && sig !== undefined && !verifyPreimage(signer, preimage, sig)) {
    throw new Error(`gen-vectors: the ${table} example's signature does not verify`)
  }
  return {
    table,
    preimage,
    canonical: c,
    sha256: sha256hex(c),
    ...(signer === undefined ? {} : { signer, sig }),
  }
}

// ---- fetch proofs (spec/SPEC.md §8.3) --------------------------------------------------------------------------

type FetchHeaders = Readonly<Record<'ac-signer' | 'ac-ts' | 'ac-sig', string>> & {
  readonly 'ac-auth'?: string
}

/**
 * A relay's verdict on a fetch proof for a held envelope, in the relay's order (crates/ac-relay/src/auth.rs): the id,
 * the headers, the signature for one of the accepted bases, the skew, then the party of the chain's root.
 */
function fetchVerdict(
  accepted: readonly string[],
  id: string,
  h: FetchHeaders,
  parties: readonly string[],
  now: number,
): string {
  if (!isHex(id, 32)) return 'bad-hex'
  const signer = h['ac-signer']
  const tsText = h['ac-ts']
  const sig = h['ac-sig']
  if (!isAddress(signer) || !/^[0-9]+$/.test(tsText) || !isHex(sig, 64)) return 'bad-auth'
  const ts = Number(tsText)
  if (ts > Number.MAX_SAFE_INTEGER) return 'bad-auth'
  let hops: Hop[]
  try {
    hops =
      h['ac-auth'] === undefined ? [] : JSON.parse(Buffer.from(h['ac-auth'], 'base64url').toString('utf8'))
  } catch {
    return 'bad-auth'
  }
  if (!accepted.some((base) => verifyFetchAuth(signer, id, ts, base, sig))) return 'bad-auth'
  if (ts < now - DEFAULT_SKEW) return 'stale-ts'
  if (ts > now + DEFAULT_SKEW) return 'future-ts'
  let root: string
  try {
    root = verifyChain(hops, signer, ts).root
  } catch (e) {
    if (isAcError(e)) return 'not-authorized'
    throw e
  }
  return parties.includes(root) ? 'ok' : 'not-authorized'
}

/**
 * The fetch-proof cases (the Q-8 ruling's vectors): bob, jane's recipient, fetches E1 at ACME_RELAY. Each case
 * changes what the caller signed, the headers or the relay's accepted bases, and states its verdict. A relays entry is
 * scheme and authority only, and the relay compares the audience byte for byte with its accepted set, so a trailing
 * slash, a path, :443 or an upper-case host is a refusal.
 */
function fetchProofCases(): J[] {
  const id = E1.envelope.id
  const parties = [E1.envelope.from, ...E1.envelope.to]
  const now = T0 + 90
  const other = 'https://relay.globex.example'
  const nonce = toHex(xorshiftRng(0xfe7)(32))
  const upper = (address: string): string => `${address.slice(0, 8)}${address.slice(8).toUpperCase()}`
  const fetchCase = (
    name: string,
    want: string,
    o: {
      readonly accepted?: readonly string[]
      readonly id?: string
      readonly party?: Party
      readonly signer?: string
      readonly ts?: number
      readonly audience?: string
      readonly signed?: CanonicalValue
      readonly auth?: readonly Hop[]
    } = {},
  ): J => {
    const party = o.party ?? P.bob
    const signer = o.signer ?? party.address
    const ts = o.ts ?? now
    const pathId = o.id ?? id
    const signed = o.signed ?? fetchAuthPreimage(signer, pathId, ts, o.audience ?? ACME_RELAY)
    const accepted = o.accepted ?? [ACME_RELAY]
    const headers: FetchHeaders = {
      'ac-signer': signer,
      'ac-ts': String(ts),
      'ac-sig': signPreimage(party.key, signed),
      ...(o.auth === undefined
        ? {}
        : { 'ac-auth': Buffer.from(JSON.stringify(o.auth), 'utf8').toString('base64url') }),
    }
    const result = expectResult(name, fetchVerdict(accepted, pathId, headers, parties, now), want)
    return { name, accepted, now, id: pathId, headers, parties, signed, result }
  }
  return [
    fetchCase("a proof for the relay's base verifies", 'ok'),
    fetchCase("a proof for another relay's base is refused here: the cross-relay replay", 'bad-auth', {
      audience: other,
    }),
    fetchCase('the old four-field preimage is refused at a new relay', 'bad-auth', {
      signed: [FETCH_TAG, P.bob.address, id, now],
    }),
    fetchCase('an audience with a trailing slash is not the relays entry', 'bad-auth', {
      audience: `${ACME_RELAY}/`,
    }),
    fetchCase('an audience with a path is not the relays entry', 'bad-auth', {
      audience: `${ACME_RELAY}/v0`,
    }),
    fetchCase('an audience with an explicit :443 is not the relays entry', 'bad-auth', {
      audience: 'https://relay.acme.example:443',
    }),
    fetchCase('an audience with an uppercase host is not the relays entry', 'bad-auth', {
      audience: 'https://RELAY.ACME.EXAMPLE',
    }),
    fetchCase('a relay under two names accepts a proof for either', 'ok', {
      accepted: [ACME_RELAY, 'https://relay2.acme.example'],
      audience: 'https://relay2.acme.example',
    }),
    fetchCase('ts 301 s before the relay clock, with the right audience', 'stale-ts', { ts: now - 301 }),
    fetchCase('ts 301 s after the relay clock, with the right audience', 'future-ts', { ts: now + 301 }),
    fetchCase('ts 300 s before the relay clock is within the skew', 'ok', { ts: now - 300 }),
    fetchCase('a proof for another relay outside the skew: the signature is checked first', 'bad-auth', {
      ts: now - 301,
      audience: other,
    }),
    fetchCase('a session with a chain from a party (AC-Auth), with the audience', 'ok', {
      party: P.session,
      auth: [hopJaneSession],
    }),
    fetchCase('a signer that is not a party and has no chain', 'not-authorized', { party: P.carol }),
    fetchCase('a subscribe response presented as a fetch proof', 'bad-auth', {
      signed: subscribePreimage(nonce, P.bob.address, P.bob.address, null),
    }),
    fetchCase('a five-element array under another tag presented as a fetch proof', 'bad-auth', {
      signed: ['ac/fetch/2', P.bob.address, id, now, ACME_RELAY],
    }),
    fetchCase('an uppercase id in the path is refused, not canonicalized', 'bad-hex', {
      id: id.toUpperCase(),
    }),
    fetchCase('an id padded to 33 bytes is refused', 'bad-hex', { id: `00${id}` }),
    fetchCase('a signer in uppercase hex is not the canonical address', 'bad-auth', {
      signer: upper(P.bob.address),
    }),
  ]
}

function canonicalFile(): J {
  const nonce = toHex(xorshiftRng(0x5ab)(32))
  const audit1: AuditFields = {
    seq: 1,
    prev: AUDIT_GENESIS,
    ts: T0 + 61,
    event: 'verify',
    decision: 'accept',
    reason: 'ok',
    id: E2.envelope.id,
    from: E2.envelope.from,
    root: P.org.address,
    detail: JSON.stringify({ bytes: E2.bytes.length }),
  }
  const audit2: AuditFields = {
    seq: 2,
    prev: auditHash(audit1),
    ts: T0 + 62,
    event: 'policy',
    decision: 'reject',
    reason: 'untrusted-root',
    id: E3.envelope.id,
    from: E3.envelope.from,
    root: E3.envelope.from,
    detail: null,
  }
  const subCursor = 41
  return {
    ...header(
      'The canonical form (spec/SPEC.md §2): "cases" pairs values with their canonical strings and SHA-256; "invalid" holds values the form rejects (bad-canonical); "preimages" holds one worked example of every position table, with its canonical string, SHA-256 and, where the table is signed, the signer and signature over that SHA-256; "fetch_proofs" holds a relay\'s verdicts on fetch proofs (§8.3).',
      [
        'A case with utf16_hex describes a string by its UTF-16 code units, four hex digits each, because a lone surrogate cannot be written portably in JSON (RFC 8259 §8.2).',
        "Python's json.dumps(value, separators=(',', ':'), ensure_ascii=False) gives every canonical string here byte for byte.",
        'A fetch_proofs case is a GET /v0/fetch/{id} at a relay whose advertised base URLs are "accepted", at "now", with the skew of 300 s: "id" is the path segment and "headers" the request\'s AC-Signer, AC-Ts, AC-Sig and, with a chain, AC-Auth (the hops as JSON in base64url without padding). The relay rebuilds ["ac/fetch/1", signer, id, ts, audience] from AC-Signer, the id, AC-Ts and each accepted base, never from a Host or forwarded header, and the proof holds when its signature verifies for one of them. "signed" is the array the caller signed, for reading only: no verdict uses it. The envelope is held, and "parties" are its from, each to and its principal.',
        "The verdicts follow the relay's order: bad-hex for an id that is not 64 lowercase hex; bad-auth for a malformed header or a signature that verifies for no accepted base; stale-ts or future-ts outside the skew, so a proof for another relay outside the skew is bad-auth; not-authorized unless the root of the chain (the signer itself without one) is a party; else ok.",
      ],
    ),
    cases: CANONICAL_VALID.map(([name, value]) => ({
      name,
      value,
      canonical: canonical(value),
      sha256: sha256hex(canonical(value)),
    })),
    invalid: [
      ...CANONICAL_INVALID.map(([name, value]) => ({
        name,
        value,
        result: expectResult(
          name,
          outcome(() => canonical(value as CanonicalValue)),
          'bad-canonical',
        ),
      })),
      ...CANONICAL_UTF16.map(([name, hex]) => ({
        name,
        utf16_hex: hex,
        result: expectResult(
          name,
          outcome(() => canonical(fromUtf16Hex(hex))),
          'bad-canonical',
        ),
      })),
    ],
    preimages: [
      preimageVector('envelope id', envelopeIdPreimage(E2.envelope), E2.envelope.from, E2.envelope.sig),
      preimageVector('hop', hopPreimage(hopOrgJane), hopOrgJane.iss, hopOrgJane.sig),
      preimageVector('sealed hash', sealedHashPreimage(E2.envelope.sealed)),
      preimageVector('address record', recordPreimage(orgRecord), orgRecord.key, orgRecord.sig),
      preimageVector('accept-from', recordPreimage(bobAccept), bobAccept.owner, bobAccept.sig),
      preimageVector('key record', recordPreimage(janeKeyRecord), janeKeyRecord.key, janeKeyRecord.sig),
      preimageVector(
        'subscribe response',
        subscribePreimage(nonce, P.session.address, P.jane.address, subCursor),
        P.session.address,
        signSubscribe(P.session.key, nonce, P.jane.address, subCursor),
      ),
      preimageVector(
        'subscribe response, resuming from the stored ack',
        subscribePreimage(nonce, P.jane.address, P.jane.address, null),
        P.jane.address,
        signSubscribe(P.jane.key, nonce, P.jane.address, null),
      ),
      preimageVector(
        'fetch auth',
        fetchAuthPreimage(P.bob.address, E1.envelope.id, T0 + 90, ACME_RELAY),
        P.bob.address,
        signFetchAuth(P.bob.key, E1.envelope.id, T0 + 90, ACME_RELAY),
      ),
      preimageVector('audit line', auditPreimage(audit1)),
      preimageVector('audit line, chained to the first', auditPreimage(audit2)),
    ],
    fetch_proofs: fetchProofCases(),
  }
}

// ---- the RFC 9180 subset --------------------------------------------------------------------------------------

const matchesSuite = (c: RfcCase): boolean =>
  c.mode === 0 && c.kem_id === 0x20 && c.kdf_id === 1 && c.aead_id === 2

function subsetFile(upstream: string | undefined): J {
  let cases: readonly RfcCase[]
  let upstreamCases: number
  if (upstream !== undefined) {
    const raw = readFileSync(upstream)
    const sha = createHash('sha256').update(raw).digest('hex')
    if (sha !== UPSTREAM.sha256)
      throw new Error(`gen-vectors: ${upstream} has sha256 ${sha}, not ${UPSTREAM.sha256}`)
    const all = JSON.parse(raw.toString('utf8')) as RfcCase[]
    upstreamCases = all.length
    cases = all.filter(matchesSuite)
  } else {
    const committed = obj(JSON.parse(readFileSync(join(VECTORS_DIR, SUBSET), 'utf8')))
    upstreamCases = Number(obj(committed.source).upstream_cases)
    cases = (committed.cases as RfcCase[]).filter(matchesSuite).map(rebuildRfcCase)
  }
  return {
    ...header(
      "The RFC 9180 test vectors for suite 1's HPKE parameters, filtered from the CFRG file: mode base (0), DHKEM(X25519, HKDF-SHA256) (kem 0x0020), HKDF-SHA256 (kdf 0x0001), AES-256-GCM (aead 0x0002). Every field of each kept case is as upstream; an encryption's sequence number is its index.",
      [
        'RFC 9180 Appendix A prints no vector for this suite (A.1 is AES-128-GCM); the CFRG file holds one.',
        'This file is upstream data, kept unchanged apart from the filter; it is never executed.',
      ],
    ),
    source: {
      url: UPSTREAM.url,
      sha256: UPSTREAM.sha256,
      downloaded: UPSTREAM.downloaded,
      filter: { mode: 0, kem_id: 0x20, kdf_id: 1, aead_id: 2 },
      upstream_cases: upstreamCases,
      kept_cases: cases.length,
    },
    cases,
  }
}

// ---- the strict rule of spec/SPEC.md §2.3, the opening and the caveats -----------------------
// Appended after every earlier case of each list, so that those stay byte-identical (the key record of records.json
// excepted: B5). Each degenerate signature is built so that a verifier that skips a strict check accepts it: OpenSSL
// alone takes R = the identity and S = 0 under a small-order key whenever k = SHA-512(R || A || M) mod L is 0 mod 8,
// so the message (the id, through ts; a hop's exp; a record's iat) is ground until it is.

const FF30 = 'ff'.repeat(30)
const IDENTITY_POINT = toHex(SMALL_ORDER_POINTS[0] as Uint8Array)
/** R = the identity and S = 0. */
const DEGENERATE_SIG = `${IDENTITY_POINT}${'00'.repeat(32)}`
const SMALL_ORDER_NAMES = [
  'the identity',
  'the point of order 2',
  'a point of order 4',
  'the other point of order 4',
  'a point of order 8',
  'a second point of order 8',
  'a third point of order 8',
  'a fourth point of order 8',
]
/** The 14 degenerate keys: the eight points of small order, and six aliases that a lax decoder reads as one of them. */
const DEGENERATE: readonly (readonly [string, string])[] = [
  ...SMALL_ORDER_POINTS.map((b, i) => [SMALL_ORDER_NAMES[i] as string, toHex(b)] as const),
  ['the identity with the sign bit set (x = 0)', `01${'00'.repeat(30)}80`],
  ['the point of order 2 with the sign bit set (x = 0)', `ec${'ff'.repeat(31)}`],
  ['the identity written y + p', `ee${FF30}7f`],
  ['the identity written y + p, the sign bit set', `ee${'ff'.repeat(31)}`],
  ['a point of order 4 written y + p', `ed${FF30}7f`],
  ['the other point of order 4 written y + p', `ed${'ff'.repeat(31)}`],
]
/** The 38 encodings with y >= p: y + p for each y from 0 to 18, each sign. */
const PLUS_P: readonly (readonly [string, string])[] = Array.from({ length: 38 }, (_, i) => {
  const y = BigInt(i >> 1)
  const sign = i % 2 === 1
  const n = (FIELD_P + y) | (sign ? 1n << 255n : 0n)
  return [`y = ${y} written y + p${sign ? ', the sign bit set' : ''}`, toHex(bytesOf(n))] as const
})
/** A point of order 8: the torsion part of the mixed-order key and of the mixed-order R. */
const TORSION_8 = decodeLoose(SMALL_ORDER_POINTS[4] as Uint8Array) as Point
/** The eight small-order X25519 u-coordinates (each gives an all-zero shared secret), as adversarial line P4 lists them. */
const X25519_SMALL_ORDER: readonly (readonly [string, string])[] = [
  ['u = 0', '00'.repeat(32)],
  ['u = 1', `01${'00'.repeat(31)}`],
  ['a point of order 8', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'],
  ['the other point of order 8', '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'],
  ['u = p - 1', `ec${FF30}7f`],
  ['u = p', `ed${FF30}7f`],
  ['u = p + 1', `ee${FF30}7f`],
  ['u = 0 with the top bit set', `${'00'.repeat(31)}80`],
]

/** k mod 8, for the signature's R, the key A and the message M. */
function kMod8(r: string, a: string, message: Uint8Array): bigint {
  return challenge(fromHex(r, 32), fromHex(a, 32), message) % 8n
}

/** The party's key plus the point of order 8: a mixed-order key, whose holder knows the scalar of its prime part. */
function mixedKey(p: Party): string {
  return toHex(encode(add(decodeLoose(p.key.publicKey) as Point, TORSION_8)))
}

/** S + L in place of a signature's S. */
function plusL(sig: string): string {
  const b = fromHex(sig, 64)
  return toHex(b.subarray(0, 32)) + toHex(bytesOf(le(b.subarray(32)) + ORDER_L))
}

/** The first t at or after `from` for which `ok(t)` holds. */
function firstAt(from: number, ok: (t: number) => boolean): number {
  for (let t = from; t < from + 4096; t++) if (ok(t)) return t
  throw new Error('gen-vectors: nothing ground within 4,096 steps')
}

/** The text with `from` replaced once by `to`, which must change it. */
function respellText(t: string, from: string, to: string): string {
  if (!t.includes(from)) throw new Error(`gen-vectors: ${from} is not in the text`)
  return t.replace(from, to)
}

/** Envelope "parse" cases: member names given twice (B4), and numbers that are not plain decimal integers (§2.5). */
function strictParseCases(b1: string, b2: string): J[] {
  const e1 = E1.envelope
  const other = sha256hex('another id')
  const exp = `"exp":${hopOrgJane.exp}`
  const w = e1.sealed.wraps[0] as Sealed['wraps'][number]
  const ts = `"ts":${T0}`
  return [
    parseCase(
      'two id members, the valid one first (B4)',
      'bad-json',
      respellText(b1, `"id":"${e1.id}"`, `"id":"${e1.id}","id":"${other}"`),
    ),
    parseCase(
      'two id members, the valid one last (B4)',
      'bad-json',
      respellText(b1, `"id":"${e1.id}"`, `"id":"${other}","id":"${e1.id}"`),
    ),
    parseCase('two ts members (B4)', 'bad-json', respellText(b1, ts, `"ts":${T0 + 1},${ts}`)),
    parseCase(
      'a member name given twice, once through an escape (B4)',
      'bad-json',
      respellText(b1, ts, `"\\u0074s":${T0},${ts}`),
    ),
    parseCase(
      'a hop with two exp members (B4)',
      'bad-json',
      respellText(b2, exp, `"exp":${hopOrgJane.exp - 1},${exp}`),
    ),
    parseCase(
      'a wrap with two enc members (B4)',
      'bad-json',
      respellText(b1, `"enc":"${w.enc}"`, `"enc":"${w.enc}","enc":"${w.enc}"`),
    ),
    parseCase('v written 1.0 (§2.5)', 'bad-version', respellText(b1, '"v":1', '"v":1.0')),
    parseCase('v written 1e0 (§2.5)', 'bad-version', respellText(b1, '"v":1', '"v":1e0')),
    parseCase('suite written 1.0 (§2.5)', 'bad-suite', respellText(b1, '"suite":1', '"suite":1.0')),
    parseCase('ts written with a fraction of zero (§2.5)', 'bad-shape', respellText(b1, ts, `"ts":${T0}.0`)),
    parseCase('ts written with an exponent (§2.5)', 'bad-shape', respellText(b1, ts, '"ts":18e8')),
    parseCase('ts written -0 (§2.5)', 'bad-shape', respellText(b1, ts, '"ts":-0')),
    parseCase(
      'ts written 1e-400, which a double rounds to 0 (§2.5)',
      'bad-shape',
      respellText(b1, ts, '"ts":1e-400'),
    ),
    parseCase(
      'ts written 9007199254740990.9, which a double rounds to 2^53 - 1 (§2.5)',
      'bad-shape',
      respellText(b1, ts, '"ts":9007199254740990.9'),
    ),
    parseCase(
      'ts of 2^53, past the largest canonical integer (§2.5)',
      'bad-shape',
      respellText(b1, ts, '"ts":9007199254740992'),
    ),
    parseCase(
      "ts written 1e400, past a double's range (§2.5)",
      'bad-json',
      respellText(b1, ts, '"ts":1e400'),
    ),
    parseCase('ts with a leading zero: not JSON (§2.5)', 'bad-json', respellText(b1, ts, `"ts":0${T0}`)),
    parseCase(
      "a hop's exp written with an exponent (§2.5)",
      'bad-hop',
      respellText(b2, exp, `"exp":${hopOrgJane.exp / 1000}e3`),
    ),
  ]
}

/** Envelope "verify" cases: E1, to its recipient (examples/python-join opens every verify case as that one). */
function strictVerifyCases(): J[] {
  const e1 = E1.envelope
  const jane = P.jane
  const janeKey = toHex(jane.key.publicKey)
  /** E1 from `key` at `ts`, the id recomputed, signed by `sign`. */
  const from = (key: string, ts: number, sign: (id: Uint8Array) => string): string => {
    const unsigned = { ...e1, from: `ed25519:${key}`, ts }
    const id = envelopeId(unsigned)
    return text(serializeEnvelope({ ...unsigned, id, sig: sign(fromHex(id, 32)) }))
  }
  const idAt = (key: string, ts: number): Uint8Array =>
    fromHex(envelopeId({ ...e1, from: `ed25519:${key}`, ts }), 32)
  const out: J[] = []
  for (const [label, key] of DEGENERATE) {
    const ts = firstAt(T0, (t) => kMod8(IDENTITY_POINT, key, idAt(key, t)) === 0n)
    out.push(
      verifyCase(
        `from is ${label}, R the identity and S = 0, k = 0 mod 8: OpenSSL alone accepts it`,
        'bad-sig',
        from(key, ts, () => DEGENERATE_SIG),
        ts,
      ),
    )
  }
  const s1 = le(fromHex(e1.sig, 64).subarray(32))
  const r1 = e1.sig.slice(0, 64)
  for (const [label, s] of [
    ['S + L', s1 + ORDER_L],
    ['S = L', ORDER_L],
    ['S = 2^256 - 1', (1n << 256n) - 1n],
  ] as const) {
    out.push(
      verifyCase(
        `${label} in place of the signature's S`,
        'bad-sig',
        text(serializeEnvelope({ ...e1, sig: r1 + toHex(bytesOf(s)) })),
        T0,
      ),
    )
  }
  const id1 = fromHex(e1.id, 32)
  for (const [label, r] of [...DEGENERATE.slice(0, 10), ...PLUS_P]) {
    const sig = toHex(signWithR(jane.signingSeed, jane.key.publicKey, id1, fromHex(r, 32)))
    out.push(
      verifyCase(
        `R is ${label}, S = k·a under the sender's own key`,
        'bad-sig',
        text(serializeEnvelope({ ...e1, sig })),
        T0,
      ),
    )
  }
  const mixed = mixedKey(jane)
  const signMixed = (id: Uint8Array): string => toHex(signAs(jane.signingSeed, fromHex(mixed, 32), id))
  const ts = firstAt(T0, (t) => kMod8(signMixed(idAt(mixed, t)).slice(0, 64), mixed, idAt(mixed, t)) !== 0n)
  out.push(
    verifyCase(
      "from is a mixed-order key (the sender's key plus a point of order 8), k not 0 mod 8: the cofactorless equation fails, a cofactored one holds",
      'bad-sig',
      from(mixed, ts, signMixed),
      ts,
    ),
  )
  out.push(
    verifyCase(
      "R is a mixed-order point (R plus a point of order 8), S from the sender's own key: the cofactorless equation fails, a cofactored one holds",
      'bad-sig',
      text(
        serializeEnvelope({
          ...e1,
          sig: toHex(signAs(jane.signingSeed, jane.key.publicKey, id1, TORSION_8)),
        }),
      ),
      T0,
    ),
  )
  if (janeKey !== e1.from.slice(8)) throw new Error('gen-vectors: E1 is not from jane')
  return out
}

/** One hop to the session under `iss`, its exp ground by `ok`, signed by `sign`. */
function groundHop(
  iss: string,
  ok: (h: J, digest: Uint8Array) => boolean,
  sign: (d: Uint8Array) => string,
): J {
  const s = P.session.address
  const unsigned = (exp: number) => ({ iss, sub: s, caveats: [] as string[], exp })
  const digestAt = (exp: number): Uint8Array => preimageDigest(hopPreimage(unsigned(exp)))
  const exp = firstAt(T0 + DAY, (e) => ok(unsigned(e), digestAt(e)))
  return { ...unsigned(exp), sig: sign(digestAt(exp)) }
}

/** chain-invalid.json cases: the degenerate keys, S + L, R the identity and a mixed-order key, as a hop's iss. */
function strictChainCases(): J[] {
  const s = P.session.address
  const out: J[] = []
  for (const [label, key] of DEGENERATE) {
    const hop = groundHop(
      `ed25519:${key}`,
      (_, d) => kMod8(IDENTITY_POINT, key, d) === 0n,
      () => DEGENERATE_SIG,
    )
    out.push(
      chainInvalid(`the iss is ${label}, R the identity and S = 0, k = 0 mod 8`, 9, 'bad-hop-sig', s, T0, [
        hop,
      ]),
    )
  }
  const honest = signHop(P.org.key, s, ['type=coding.*'], T0 + DAY)
  out.push(
    chainInvalid('S + L in place of the hop signature S', 9, 'bad-hop-sig', s, T0, [
      { ...honest, sig: plusL(honest.sig) },
    ]),
  )
  const r = signWithR(
    P.org.signingSeed,
    P.org.key.publicKey,
    preimageDigest(hopPreimage(honest)),
    fromHex(IDENTITY_POINT, 32),
  )
  out.push(
    chainInvalid("R the identity and S = k·a under the iss's own key", 9, 'bad-hop-sig', s, T0, [
      { ...honest, sig: toHex(r) },
    ]),
  )
  const mixed = mixedKey(P.org)
  const signMixed = (d: Uint8Array): string => toHex(signAs(P.org.signingSeed, fromHex(mixed, 32), d))
  out.push(
    chainInvalid(
      "the iss is a mixed-order key (the org's key plus a point of order 8), k not 0 mod 8: the cofactorless equation fails",
      9,
      'bad-hop-sig',
      s,
      T0,
      [groundHop(`ed25519:${mixed}`, (_, d) => kMod8(signMixed(d).slice(0, 64), mixed, d) !== 0n, signMixed)],
    ),
  )
  return out
}

/** The chain-valid.json case of a mixed-order iss whose k is 0 mod 8: the cofactorless equation holds. */
function mixedChainValid(): J {
  const mixed = mixedKey(P.org)
  const signMixed = (d: Uint8Array): string => toHex(signAs(P.org.signingSeed, fromHex(mixed, 32), d))
  const hop = groundHop(
    `ed25519:${mixed}`,
    (_, d) => kMod8(signMixed(d).slice(0, 64), mixed, d) === 0n,
    signMixed,
  )
  return chainValid(
    'the iss is a mixed-order key and k is 0 mod 8: the cofactorless equation holds, and no reader refuses the key for its order',
    P.session.address,
    T0,
    [hop as unknown as Hop],
  )
}

/** records.json cases: the degenerate keys, and R the identity, as a record's signer. */
function strictRecordCases(): J[] {
  const out: J[] = []
  for (const [label, key] of DEGENERATE) {
    const at = (iat: number): AddressRecord => ({
      kind: 'address',
      key: `ed25519:${key}`,
      sealing_key: null,
      relays: [ACME_RELAY],
      rotation_key: null,
      revoked: [],
      ttl: HOUR,
      iat,
      rotated_from: null,
      rotation_sig: null,
      sig: DEGENERATE_SIG,
    })
    const iat = firstAt(T0, (t) => kMod8(IDENTITY_POINT, key, preimageDigest(recordPreimage(at(t)))) === 0n)
    out.push(
      recordCase(`an address record whose key is ${label}, R the identity and S = 0, k = 0 mod 8`, at(iat), [
        [iat, 'bad-record-sig'],
      ]),
    )
  }
  const r = signWithR(
    P.org.signingSeed,
    P.org.key.publicKey,
    preimageDigest(recordPreimage(orgRecord)),
    fromHex(IDENTITY_POINT, 32),
  )
  out.push(
    recordCase(
      "the org's address record with R the identity and S = k·a under its own key",
      {
        ...orgRecord,
        sig: toHex(r),
      },
      [[T0, 'bad-record-sig']],
    ),
  )
  return out
}

/** The fields opening reads, as a case lists them. */
interface Opened {
  readonly to: readonly string[]
  readonly from: string
  readonly sealed: Sealed
}

/** An "open" case: `p` opens the sealed part with its own sealing key (§4.4), then reads the content (§5.2). */
function openCase(name: string, want: string, e: Opened, p: Party): J {
  let content: SealedContent | undefined
  const result = expectResult(
    name,
    outcome(() => {
      content = openSealed(e, opener(p))
    }),
    want,
  )
  return {
    name,
    to: [...e.to],
    from: e.from,
    sealed: obj(JSON.parse(JSON.stringify(e.sealed))),
    address: p.address,
    sealing_seed: toHex(sealingOf(p).seed),
    result,
    ...(content === undefined ? {} : { content }),
  }
}

/**
 * A sealed part whose plaintext is exactly `plaintext`, to `to` under the AAD of `from`, for contents no writer makes;
 * `keyLength` below 32 wraps a content key of that many bytes.
 */
function sealRaw(
  to: readonly Party[],
  from: string,
  plaintext: Uint8Array,
  rngSeed: number,
  keyLength = 32,
): Sealed {
  const rng = xorshiftRng(rngSeed)
  const contentKey = rng(32)
  const nonce = rng(12)
  const wrapped = contentKey.subarray(0, keyLength)
  return {
    wraps: to.map((p) => {
      const { enc, ct } = hpkeSeal(sealingOf(p).publicKey, utf8(SEAL_INFO), utf8(p.address), wrapped, rng(32))
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

/** The hex with its first character moved to the next hex digit. */
function nudge(hex: string): string {
  return ((Number.parseInt(hex.slice(0, 1), 16) + 1) % 16).toString(16) + hex.slice(1)
}

/** The hex with its last character moved to the next hex digit. */
function nudgeLast(hex: string): string {
  return hex.slice(0, -1) + ((Number.parseInt(hex.slice(-1), 16) + 1) % 16).toString(16)
}

function openCases(): J[] {
  const e1 = E1.envelope
  const e4 = E4.envelope
  const [w0, w1] = e4.sealed.wraps as [Sealed['wraps'][number], Sealed['wraps'][number]]
  const wrap1 = (f: (w: Sealed['wraps'][number]) => Sealed['wraps'][number]): Opened => ({
    ...e1,
    sealed: { ...e1.sealed, wraps: e1.sealed.wraps.map(f) },
  })
  const toBob = (plaintext: string | Uint8Array, rngSeed: number, keyLength = 32): Opened => ({
    to: [P.bob.address],
    from: P.jane.address,
    sealed: sealRaw(
      [P.bob],
      P.jane.address,
      typeof plaintext === 'string' ? utf8(plaintext) : plaintext,
      rngSeed,
      keyLength,
    ),
  })
  const th = JSON.stringify(THREAD_1)
  const id = THREAD_1.id
  const parents = (n: number): string[] => Array.from({ length: n }, (_, i) => sha256hex(`parent ${i}`))
  const withPrev = (prev: readonly string[]): string =>
    `{"type":"coding.result.v1","thread":${JSON.stringify({ id, prev })},"body":null}`
  return [
    openCase('the recipient opens it', 'ok', e1, P.bob),
    openCase('the second of two recipients opens the same content', 'ok', e4, P.carol),
    openCase('no wrap names this address', 'not-recipient', e1, P.carol),
    openCase(
      "a moved wrap: the two recipients' wraps swapped",
      'open-failed',
      {
        ...e4,
        sealed: {
          ...e4.sealed,
          wraps: [
            { ...w0, enc: w1.enc, ct: w1.ct },
            { ...w1, enc: w0.enc, ct: w0.ct },
          ],
        },
      },
      P.jane,
    ),
    openCase(
      'a changed AAD: the content under another from',
      'open-failed',
      { ...e1, from: P.mallory.address },
      P.bob,
    ),
    openCase(
      'a changed AAD: the content under another to',
      'open-failed',
      { ...e1, to: [P.bob.address, P.carol.address] },
      P.bob,
    ),
    ...X25519_SMALL_ORDER.map(([label, u]) =>
      openCase(
        `enc replaced by the small-order X25519 point ${label}`,
        'open-failed',
        wrap1((w) => ({ ...w, enc: u })),
        P.bob,
      ),
    ),
    openCase(
      'enc of 31 bytes',
      'open-failed',
      wrap1((w) => ({ ...w, enc: w.enc.slice(2) })),
      P.bob,
    ),
    openCase(
      'a byte of the wrap ct changed',
      'open-failed',
      wrap1((w) => ({ ...w, ct: nudge(w.ct) })),
      P.bob,
    ),
    openCase(
      'the content tag changed',
      'open-failed',
      { ...e1, sealed: { ...e1.sealed, ct: nudgeLast(e1.sealed.ct) } },
      P.bob,
    ),
    openCase(
      'the nonce changed',
      'open-failed',
      { ...e1, sealed: { ...e1.sealed, nonce: nudge(e1.sealed.nonce) } },
      P.bob,
    ),
    openCase(
      'a wrapped content key of 31 bytes',
      'open-failed',
      toBob(text(encodeContent({ type: 'coding.result.v1', thread: THREAD_1, body: null })), 221, 31),
      P.bob,
    ),
    openCase('a plaintext that is not JSON', 'bad-content', toBob('not json', 222), P.bob),
    openCase(
      'a plaintext that is not UTF-8',
      'bad-content',
      toBob(Uint8Array.of(0x7b, 0xff, 0x7d), 223),
      P.bob,
    ),
    openCase(
      'a byte-order mark before the object',
      'bad-content',
      toBob(`﻿{"type":"t","thread":${th},"body":null}`, 224),
      P.bob,
    ),
    openCase('a JSON list', 'bad-content', toBob('[]', 225), P.bob),
    openCase(
      'an extra member',
      'bad-content',
      toBob(`{"type":"t","thread":${th},"body":null,"x":1}`, 226),
      P.bob,
    ),
    openCase('an empty type', 'bad-content', toBob(`{"type":"","thread":${th},"body":null}`, 227), P.bob),
    // The content control-character rule (SPEC §5.2, added 2026-10-27): the escape is six characters in the JSON, so
    // the plaintext parses to a control character in `type`; a raw C0 would already be bad-content at parse. A C1
    // (U+009B) is legal raw JSON, so the rule is what refuses it.
    openCase(
      'an escaped C0 control in type',
      'bad-content',
      toBob(`{"type":"a\\u0001b","thread":${th},"body":null}`, 236),
      P.bob,
    ),
    openCase(
      'a C1 control in type (U+009B)',
      'bad-content',
      toBob(`{"type":"a\\u009bb","thread":${th},"body":null}`, 237),
      P.bob,
    ),
    openCase(
      'a line separator in type (U+2028)',
      'bad-content',
      toBob(`{"type":"a\\u2028b","thread":${th},"body":null}`, 238),
      P.bob,
    ),
    openCase(
      'DEL in type (U+007F)',
      'bad-content',
      toBob(`{"type":"a\\u007fb","thread":${th},"body":null}`, 239),
      P.bob,
    ),
    openCase(
      'a paragraph separator in type (U+2029)',
      'bad-content',
      toBob(`{"type":"a\\u2029b","thread":${th},"body":null}`, 240),
      P.bob,
    ),
    openCase(
      'two type members, the valid one last (B4)',
      'bad-content',
      toBob(`{"type":"","type":"t","thread":${th},"body":null}`, 228),
      P.bob,
    ),
    openCase(
      'two members of one name in the body (B4)',
      'bad-content',
      toBob(`{"type":"t","thread":${th},"body":{"repo":"acme/web","repo":"acme/api"}}`, 229),
      P.bob,
    ),
    openCase(
      'two id members in the thread (B4)',
      'bad-content',
      toBob(`{"type":"t","thread":{"id":"${'00'.repeat(32)}","id":"${id}","prev":[]},"body":null}`, 230),
      P.bob,
    ),
    openCase(
      'a thread id of 31 bytes',
      'bad-thread',
      toBob(`{"type":"t","thread":{"id":"${'00'.repeat(31)}","prev":[]},"body":null}`, 231),
      P.bob,
    ),
    openCase(
      'a thread with an extra member',
      'bad-thread',
      toBob(`{"type":"t","thread":{"id":"${id}","prev":[],"x":1},"body":null}`, 232),
      P.bob,
    ),
    openCase(
      'a parent listed twice',
      'bad-thread',
      toBob(withPrev([...parents(1), ...parents(1)]), 233),
      P.bob,
    ),
    openCase('sixty-five parents', 'too-many-prev', toBob(withPrev(parents(65)), 234), P.bob),
    openCase('sixty-four parents, the cap', 'ok', toBob(withPrev(parents(64)), 235), P.bob),
  ]
}

/** "seal" cases: a sender seals to a recipient key that is malformed or of small order (§4.1): bad-key. */
function sealCases(): J[] {
  const content: SealedContent = { type: 'coding.task.v1', thread: THREAD_1, body: { repo: 'acme/api' } }
  const keys: readonly (readonly [string, string])[] = [
    ...X25519_SMALL_ORDER.map(
      ([label, u]) => [`the recipient's sealing key is the small-order point ${label}`, u] as const,
    ),
    ['a sealing key of 31 bytes', toHex(sealingOf(P.bob).publicKey).slice(2)],
  ]
  return keys.map(([name, key], i) => {
    const rng = xorshiftRng(301 + i)
    const draws = [rng(32), rng(12), rng(32)]
    const result = expectResult(
      name,
      outcome(() =>
        sealTo(
          [{ address: P.bob.address, sealingKey: fromHex(key) }],
          P.jane.address,
          content,
          replayRng(draws),
        ),
      ),
      'bad-key',
    )
    const [contentKey, nonce, ephemeral] = draws.map(toHex)
    return {
      name,
      from: P.jane.address,
      to: [{ address: P.bob.address, sealing_key: key }],
      content,
      content_key: contentKey,
      nonce,
      ephemeral_seeds: [ephemeral],
      result,
    }
  })
}

// ---- forward secrecy (spec/SPEC.md §7.4) ------------------------------------------------------------------

// A content key is HPKE-sealed to the recipient's current key-record sealing key (ac/key/1), never the address
// record's sealing key, which an individual publishes as null (KEEP-NULL; the resolver enforces it, not the shared
// validator, so group records that carry a generation key stay valid). Forward secrecy comes from the recipient
// deleting each epoch's private key after its horizon; that deletion is the edge's lifecycle, not core's. Core proves
// the crypto: a wrap sealed to an epoch key opens with that key and with no other, so once the epoch key is gone its
// past mail cannot be opened by the long-term key or by the next epoch's key.

/** A key record signed by `signer` for `address`, publishing `sealingPub` as its sealing key, from `iat` for a day. */
function signedKeyRecord(signer: Party, address: string, sealingPub: Uint8Array, iat: number): AcRecord {
  return signRecord(signer.key, {
    kind: 'key',
    key: address,
    sealing_key: toHex(sealingPub),
    iat,
    exp: iat + DAY,
  })
}

/**
 * "key_record_seal" cases: a content key HPKE-sealed to the recipient's key-record sealing key, opened with that key
 * (result ok). The seal target is the `sealing_key` of the recipient's ac/key/1 record (spec/SPEC.md §7.4).
 */
function keyRecordSealCases(): J[] {
  const address = P.jane.address
  const epoch = sealingOf(P.jane)
  const record = signedKeyRecord(P.jane, address, epoch.publicKey, T0)
  const rng = xorshiftRng(401)
  const contentKey = rng(32)
  const ephemeralSeed = rng(32)
  const { enc, ct } = hpkeSeal(epoch.publicKey, utf8(SEAL_INFO), utf8(address), contentKey, ephemeralSeed)
  const name = "a content key sealed to the recipient's key-record sealing key opens"
  const result = expectResult(
    name,
    outcome(() => {
      const got = opener(P.jane).key.open(enc, utf8(SEAL_INFO), utf8(address), ct)
      if (toHex(got) !== toHex(contentKey)) {
        throw new Error(`gen-vectors: "${name}": the key record's key recovered a different content key`)
      }
    }),
    'ok',
  )
  return [
    {
      name,
      address,
      key_record: record,
      now: T0 + HOUR,
      epoch_seed: toHex(epoch.seed),
      content_key: toHex(contentKey),
      ephemeral_seed: toHex(ephemeralSeed),
      wrap: { enc: toHex(enc), ct: toHex(ct) },
      result,
    },
  ]
}

/**
 * "stolen_key" cases: a content key sealed to an epoch key, which the recipient deletes after its horizon. Opening the
 * wrap after stolen_at with the recipient's long-term key or with the current (different) epoch key both fail
 * (open-failed); only the deleted epoch key could have opened it, which is forward secrecy.
 */
function stolenKeyCases(): J[] {
  const address = P.jane.address
  const epoch = sealingOf(P.carol) // the epoch key E the recipient deletes after its horizon
  const current = sealingOf(P.dave) // the recipient's next epoch key, valid at the theft, different from E
  const epochRecord = signedKeyRecord(P.jane, address, epoch.publicKey, T0)
  const sealedAt = T0 + HOUR // within E's validity window (iat T0, exp T0 + DAY)
  // E's deletion horizon: its key record's exp plus the forward-secrecy retention TTL (7 days) and the skew. The theft
  // is past the horizon, so the recipient has already deleted E's private key by then (spec/SPEC.md §7.4).
  const stolenAt = T0 + DAY + 7 * DAY + DEFAULT_SKEW + HOUR
  // The current epoch key record is valid at the theft: it started an hour before and lives a day.
  const currentRecord = signedKeyRecord(P.jane, address, current.publicKey, stolenAt - HOUR)
  const rng = xorshiftRng(402)
  const contentKey = rng(32)
  const ephemeralSeed = rng(32)
  const { enc, ct } = hpkeSeal(epoch.publicKey, utf8(SEAL_INFO), utf8(address), contentKey, ephemeralSeed)
  const name =
    'a content key sealed to a deleted epoch key: the long-term and the current epoch key both fail'
  const recovered = opener(P.carol).key.open(enc, utf8(SEAL_INFO), utf8(address), ct)
  if (toHex(recovered) !== toHex(contentKey)) {
    throw new Error(`gen-vectors: "${name}": the epoch key did not open its own wrap`)
  }
  // The long-term key is the recipient's own signing seed read as an X25519 private key (the raw-seed derivation); it
  // is the signing key of the case address and cannot open content sealed to the epoch key.
  const byLongTerm = expectResult(
    `${name} (long-term key)`,
    outcome(() => hpkeOpen(P.jane.signingSeed, enc, utf8(SEAL_INFO), utf8(address), ct)),
    'open-failed',
  )
  expectResult(
    `${name} (current epoch key)`,
    outcome(() => opener(P.dave).key.open(enc, utf8(SEAL_INFO), utf8(address), ct)),
    'open-failed',
  )
  return [
    {
      name,
      address,
      long_term_seed: toHex(P.jane.signingSeed),
      epoch: { key_record: epochRecord, seed: toHex(epoch.seed) },
      current: { key_record: currentRecord, seed: toHex(current.seed) },
      sealed_at: sealedAt,
      stolen_at: stolenAt,
      content_key: toHex(contentKey),
      ephemeral_seed: toHex(ephemeralSeed),
      wrap: { enc: toHex(enc), ct: toHex(ct) },
      result: byLongTerm,
    },
  ]
}

/** A "caveats" case: the coding profile's verdict on the effective caveats against a sealed content (§6.3, §6.4). */
function caveatCase(name: string, want: string, caveats: readonly string[], content: SealedContent): J {
  const r = evaluateCaveats(caveats, [codingEvaluator], {
    from: P.session.address,
    to: [P.bob.address],
    ts: T0,
    root: P.org.address,
    sealed: content,
  })
  const result = expectResult(name, r.ok ? 'ok' : r.code, want)
  return { name, caveats, content, result, ...(r.ok ? {} : { caveat: r.caveat }) }
}

function caveatCases(): J[] {
  const task: SealedContent = {
    type: 'coding.task.v1',
    thread: THREAD_1,
    body: { repo: 'acme/api', task: 'run the tests' },
  }
  const note: SealedContent = { type: 'coding.note.v1', thread: THREAD_1, body: 'a string body' }
  return [
    caveatCase('a type pattern that holds', 'ok', ['type=coding.*'], task),
    caveatCase('an exact type and a repo that hold', 'ok', ['type=coding.task.v1', 'repo=acme/api'], task),
    caveatCase('no caveat at all', 'ok', [], task),
    caveatCase('a caveat of no profile: unknown, so it fails closed', 'unknown-caveat', ['color=blue'], task),
    caveatCase(
      'a type pattern with a star inside: malformed, so unknown',
      'unknown-caveat',
      ['type=coding.*.v1'],
      task,
    ),
    caveatCase('an empty repo name: malformed, so unknown', 'unknown-caveat', ['repo='], task),
    caveatCase('another exact type', 'caveat-failed', ['type=chat.v1'], task),
    caveatCase(
      'a type pattern needs its dot: coding.* against the type coding',
      'caveat-failed',
      ['type=coding.*'],
      {
        ...task,
        type: 'coding',
      },
    ),
    caveatCase('another repo', 'caveat-failed', ['repo=acme/web'], task),
    caveatCase('a repo caveat against a string body', 'caveat-failed', ['repo=acme/api'], note),
    caveatCase(
      'order: an unknown caveat before a failing one decides',
      'unknown-caveat',
      ['color=blue', 'type=chat.v1'],
      task,
    ),
    caveatCase(
      'order: a failing caveat before an unknown one decides',
      'caveat-failed',
      ['type=chat.v1', 'color=blue'],
      task,
    ),
  ]
}

/** 1,024 distinct root addresses, the cap of an accept-from record's roots (B6), each the hash of its index. */
const ROOTS_1024 = Array.from({ length: 1024 }, (_, i) => `ed25519:${sha256hex(`root ${i}`)}`)
const bobAcceptFull = signRecord(P.bob.key, {
  kind: 'accept-from',
  owner: P.bob.address,
  roots: ROOTS_1024,
  max_bytes: 65_536,
  ttl: DAY,
  iat: T0 + 2 * HOUR,
})

/** A record "parse" case: bytes, and the result of reading them as a record (§2.5, §7.1). */
function recordParseCase(name: string, want: string, bytes: string): J {
  return {
    name,
    bytes,
    result: expectResult(
      name,
      outcome(() => parseRecord(bytes)),
      want,
    ),
  }
}

function recordParseCaseHex(name: string, want: string, hex: string): J {
  const result = expectResult(
    name,
    outcome(() => parseRecord(Buffer.from(hex, 'hex'))),
    want,
  )
  return { name, bytes_hex: hex, result }
}

/** The record's JSON text with its first `from` replaced by `to`. */
function respelled(r: AcRecord, from: string, to: string): string {
  const t = text(serializeRecord(r))
  if (!t.includes(from)) throw new Error(`gen-vectors: ${from} is not in the record`)
  return t.replace(from, to)
}

function recordParseCases(): J[] {
  const org = text(serializeRecord(orgRecord))
  return [
    recordParseCase('the address record as written', 'ok', org),
    recordParseCase(
      'two ttl members, the valid one last (B4)',
      'bad-json',
      respelled(orgRecord, `"ttl":${DAY}`, `"ttl":1,"ttl":${DAY}`),
    ),
    recordParseCase(
      'two ttl members, the valid one first (B4)',
      'bad-json',
      respelled(orgRecord, `"ttl":${DAY}`, `"ttl":${DAY},"ttl":1`),
    ),
    recordParseCase(
      'two kind members (B4)',
      'bad-json',
      respelled(orgRecord, '"kind":"address"', '"kind":"key","kind":"address"'),
    ),
    recordParseCase(
      'a member name given twice, once through an escape (B4)',
      'bad-json',
      respelled(orgRecord, `"ttl":${DAY}`, `"\\u0074tl":1,"ttl":${DAY}`),
    ),
    recordParseCase(
      'an accept-from record with two roots members (B4)',
      'bad-json',
      respelled(bobAccept, '"roots":', `"roots":["*"],"roots":`),
    ),
    recordParseCase(
      'a key record with two exp members (B4)',
      'bad-json',
      respelled(
        janeKeyRecord,
        `"exp":${janeKeyRecord.exp}`,
        `"exp":${T0 + 30 * DAY},"exp":${janeKeyRecord.exp}`,
      ),
    ),
    recordParseCase(
      'ttl written 86400.0 (§2.5)',
      'bad-record',
      respelled(orgRecord, `"ttl":${DAY}`, `"ttl":${DAY}.0`),
    ),
    recordParseCase(
      'iat written 1.8e9 (§2.5)',
      'bad-record',
      respelled(orgRecord, `"iat":${T0}`, '"iat":1.8e9'),
    ),
    recordParseCase(
      'max_bytes written -0 (§2.5)',
      'bad-record',
      respelled(bobAccept, '"max_bytes":65536', '"max_bytes":-0'),
    ),
    recordParseCase(
      "a key record's exp written 1e400, past a double's range (§2.5)",
      'bad-json',
      respelled(janeKeyRecord, `"exp":${janeKeyRecord.exp}`, '"exp":1e400'),
    ),
    recordParseCase(
      'iat written with a leading zero: not JSON',
      'bad-json',
      respelled(orgRecord, `"iat":${T0}`, `"iat":0${T0}`),
    ),
    recordParseCaseHex('a byte-order mark before the record', 'bad-json', `efbbbf${toHex(utf8(org))}`),
  ]
}

/** A "rotation_claims" case: what a reader that holds no record of rotated_from checks (§7.3). */
function rotationClaim(name: string, want: string, next: AddressRecord): J {
  return {
    name,
    next,
    result: expectResult(
      name,
      outcome(() => verifyRotationClaim(next)),
      want,
    ),
  }
}

function rotationClaims(): J[] {
  return [
    rotationClaim('countersigned by rotated_from, the previous key', 'ok', nextByPrev),
    rotationClaim('a bare rotation: no rotation_sig', 'bad-rotation', nextBare),
    rotationClaim(
      'countersigned by a key with no standing',
      'bad-rotation',
      countersignRotation(P.mallory.key, nextBare),
    ),
    rotationClaim(
      "countersigned by the previous record's rotation key: only a reader that holds that record can check it",
      'bad-rotation',
      countersignRotation(P.rotation.key, nextBare),
    ),
    rotationClaim('a record that claims no rotation', 'ok', orgRecord),
  ]
}

// ---- discovery by DNS and handles (spec/SPEC.md §12, L2; 2026-10-26) -------------
// A file of its own, discovery.json, so that the seven files before it stay byte-identical.

const ACME_DOMAIN = 'acme.example'
const ORG_KEY = P.org.address

/** A binary string (one character per byte, as parseTxtPresentation returns) as hex. */
function binaryHex(s: string): string {
  return toHex(Uint8Array.from(s, (c) => c.charCodeAt(0)))
}

/** A "presentation" case: a TXT record in its text form (§12.2 item 7) and its strings, as hex, or the refusal. */
function presentationCase(name: string, want: string, text: string): J {
  const result = expectResult(
    name,
    outcome(() => parseTxtPresentation(text)),
    want,
  )
  return result === 'ok'
    ? { name, text, result, strings_hex: parseTxtPresentation(text).map(binaryHex) }
    : { name, text, result }
}

/** A "txt" case: a domain's TXT records, each a list of strings, and where they lead (§12.2 items 1 to 4). */
function txtCase(
  name: string,
  want: string,
  records: readonly (readonly string[])[],
  domain = ACME_DOMAIN,
): J {
  const result = expectResult(
    name,
    outcome(() => discover(records, domain)),
    want,
  )
  const base = { name, domain, txt_name: txtName(domain), records }
  if (result !== 'ok') return { ...base, result }
  const d = discover(records, domain)
  return { ...base, result, key: d.key, url: d.url, origin: d.origin }
}

/** A "handles" case: a string read as a handle (§12.3 item 1), with its parts and record path, or bad-address. */
function handleCase(name: string, want: string, value: string): J {
  const result = expectResult(
    name,
    outcome(() => parseHandle(value)),
    want,
  )
  if (result !== 'ok') return { name, handle: value, result }
  const h = parseHandle(value)
  return { name, handle: value, result, local: h.local, domain: h.domain, path: handlePath(value) }
}

type HandleCheck = readonly [
  now: number,
  org: string,
  handle: string,
  revoked: readonly string[],
  want: string,
]

/** A handle record "cases" case: its canonical string, digest and signer, and its verdict for a reader (§12.4 item 3). */
function handleRecordCase(name: string, record: HandleRecord, checks: readonly HandleCheck[]): J {
  const preimage = handleRecordPreimage(record)
  return {
    name,
    record,
    canonical: canonical(preimage),
    digest: toHex(preimageDigest(preimage)),
    signer: record.org,
    checks: checks.map(([now, org, handle, revoked, want]) => ({
      now,
      skew: DEFAULT_SKEW,
      org,
      handle,
      revoked,
      result: expectResult(
        `${name} at ${now}`,
        outcome(() => verifyHandleRecord(record, { org, handle, revoked }, now)),
        want,
      ),
    })),
  }
}

function invalidHandleRecord(name: string, want: string, base: HandleRecord, members: J): J {
  const r = obj(JSON.parse(JSON.stringify({ ...base, ...members })))
  return {
    name,
    record: r,
    result: expectResult(
      name,
      outcome(() => checkHandleRecord(r)),
      want,
    ),
  }
}

function handleParseCase(name: string, want: string, bytes: string): J {
  return {
    name,
    bytes,
    result: expectResult(
      name,
      outcome(() => parseHandleRecord(bytes)),
      want,
    ),
  }
}

function handleRecord(org: Party, handle: string, address: string, iat: number, ttl: number): HandleRecord {
  return signHandleRecord(org.key, { kind: 'handle', org: org.address, handle, address, iat, ttl })
}

function presentationCases(): J[] {
  const hex = ORG_KEY.slice('ed25519:'.length)
  return [
    presentationCase('one quoted string', 'ok', `"v=ac1; key=${ORG_KEY}"`),
    presentationCase('two quoted strings', 'ok', `"v=ac1; key=ed25519:" "${hex}"`),
    presentationCase('a bare string', 'ok', `v=ac1;key=${ORG_KEY}`),
    presentationCase('spaces and tabs around and between strings', 'ok', '\t"a"  "b"\tc '),
    presentationCase('an escaped quote and an escaped backslash', 'ok', '"a\\"b\\\\c"'),
    presentationCase('an escaped character in a bare string', 'ok', 'd\\;e'),
    presentationCase('a decimal escape', 'ok', '"a\\059b"'),
    presentationCase('a decimal escape of a byte past ASCII', 'ok', '"\\233"'),
    presentationCase('an empty string', 'ok', '""'),
    presentationCase('a string of 255 bytes, the cap', 'ok', `"${'x'.repeat(255)}"`),
    presentationCase('a string of 256 bytes', 'resolve-failed', `"${'x'.repeat(256)}"`),
    presentationCase('256 bytes through decimal escapes', 'resolve-failed', `"${'\\120'.repeat(256)}"`),
    presentationCase('no string', 'resolve-failed', ''),
    presentationCase('spaces only', 'resolve-failed', '   '),
    presentationCase('a quoted string not closed', 'resolve-failed', '"abc'),
    presentationCase('text right after a closing quote', 'resolve-failed', '"ab"cd'),
    presentationCase('a quote inside a bare string', 'resolve-failed', 'ab"c'),
    presentationCase('a decimal escape over 255', 'resolve-failed', '"a\\256"'),
    presentationCase('a decimal escape of two digits', 'resolve-failed', '"a\\05x"'),
    presentationCase('a backslash at the end', 'resolve-failed', '"abc\\'),
    presentationCase('a character past ASCII', 'resolve-failed', '"jané"'),
    presentationCase('a line feed', 'resolve-failed', '"a\nb"'),
    // §12.2 item 7: a bare word carries no parenthesis, but a quoted string may.
    presentationCase('a parenthesis in a quoted string', 'ok', '"a(b)c"'),
    presentationCase('an open parenthesis in a bare string', 'resolve-failed', 'a(b'),
    presentationCase('a close parenthesis in a bare string', 'resolve-failed', 'a)b'),
  ]
}

function txtCases(): J[] {
  const k = `key=${ORG_KEY}`
  const labels = ['a', 'b', 'c'].map((c) => c.repeat(63)).join('.')
  const longDomain = `${labels}.${'d'.repeat(57)}`
  const edgeDomain = `${labels}.${'d'.repeat(56)}`
  const exact = `v=ac1; ${k}; x=`
  const bagTxt = `v=ac1; ${k}; host=bag`
  return [
    txtCase('a key and host=bag: the origin bag.<domain>', 'ok', [[bagTxt]]),
    txtCase('a key and no host: the origin at the domain', 'ok', [[`v=ac1; ${k}`]]),
    txtCase('strings split at a field', 'ok', [[`v=ac1; ${k}`, '; host=bag']]),
    txtCase('strings split inside a name, joined with nothing between', 'ok', [
      ['v=ac1; ke', `y=${ORG_KEY}`],
    ]),
    txtCase('an empty string among them', 'ok', [['v=ac1; ', '', k]]),
    txtCase('spaces and tabs around fields, names and values, and empty fields', 'ok', [
      [` v = ac1 ;;\t${k} ; `],
    ]),
    txtCase('unknown fields are ignored', 'ok', [[`v=ac1; ${k}; note=hello; X-Future_1=a=b; host=bag`]]),
    txtCase('no record: the origin at the domain and no key', 'ok', []),
    txtCase('only records that are not ours', 'ok', [['v=spf1 -all'], ['google-site-verification=abc']]),
    txtCase('a later version is not ours', 'ok', [[`v=ac2; ${k}`]]),
    txtCase('the version field is case-sensitive', 'ok', [[`V=ac1; ${k}`]]),
    txtCase('the version field must come first', 'ok', [[`${k}; v=ac1`]]),
    txtCase('ours beside records that are not', 'ok', [['v=spf1 -all'], [`v=ac1; ${k}`], ['hello world']]),
    txtCase('a domain whose TXT name would be over 253 characters is not asked', 'ok', [], longDomain),
    txtCase('records handed in for a domain that is not asked are not read', 'ok', [[bagTxt]], longDomain),
    txtCase('host=bag on a domain whose TXT name is 253 characters', 'ok', [[bagTxt]], edgeDomain),
    txtCase('a domain under a special-use name is not asked', 'ok', [], 'acme.local'),
    txtCase('records handed in for a special-use domain are not read', 'ok', [[bagTxt]], 'acme.onion'),
    txtCase('a special-use name that is not the last label is asked', 'ok', [[bagTxt]], 'acme.local.example'),
    txtCase('exactly 1,024 bytes', 'ok', [[`${exact}${'y'.repeat(1024 - exact.length)}`]]),
    txtCase('two bag records', 'resolve-failed', [[`v=ac1; ${k}`], [`v=ac1; key=${P.orgNext.address}`]]),
    txtCase('two bag records of one key, as in a rotation done with two', 'resolve-failed', [
      [`v=ac1; ${k}`],
      [bagTxt],
    ]),
    txtCase('the key given twice', 'resolve-failed', [[`v=ac1; ${k}; ${k}`]]),
    txtCase('an unknown field given twice', 'resolve-failed', [[`v=ac1; ${k}; x=1; x=2`]]),
    txtCase('the version given twice', 'resolve-failed', [[`v=ac1; ${k}; v=ac1`]]),
    txtCase('host given twice', 'resolve-failed', [[`${bagTxt}; host=bag`]]),
    txtCase('no key', 'resolve-failed', [['v=ac1; host=bag']]),
    txtCase('a key that is not an address', 'resolve-failed', [[`v=ac1; key=${ORG_KEY.toUpperCase()}`]]),
    txtCase('a rec field: DNS names no URL', 'resolve-failed', [
      [`v=ac1; ${k}; rec=https://agents.acme.example/org.json`],
    ]),
    txtCase('a rec field that names the well-known URL itself', 'resolve-failed', [
      [`v=ac1; ${k}; rec=https://acme.example/.well-known/bag/address.json`],
    ]),
    txtCase('a rec field beside host=bag', 'resolve-failed', [
      [`${bagTxt}; rec=https://bag.acme.example/.well-known/bag/address.json`],
    ]),
    txtCase('a host other than bag', 'resolve-failed', [[`v=ac1; ${k}; host=agents`]]),
    txtCase('a host in upper case', 'resolve-failed', [[`v=ac1; ${k}; host=Bag`]]),
    txtCase('a host that names a whole host name', 'resolve-failed', [
      [`v=ac1; ${k}; host=bag.acme.example`],
    ]),
    txtCase('a field with no =', 'resolve-failed', [[`v=ac1; ${k}; nothing`]]),
    txtCase('an empty value', 'resolve-failed', [[`v=ac1; ${k}; note=`]]),
    txtCase('a value with a space inside', 'resolve-failed', [[`v=ac1; ${k}; note=a b`]]),
    txtCase('a name that starts with a digit', 'resolve-failed', [[`v=ac1; ${k}; 1x=2`]]),
    txtCase('a name of 33 characters', 'resolve-failed', [[`v=ac1; ${k}; ${'n'.repeat(33)}=1`]]),
    txtCase('a character past ASCII', 'resolve-failed', [[`v=ac1; ${k}; note=café`]]),
    txtCase('1,025 bytes', 'resolve-failed', [[`${exact}${'y'.repeat(1025 - exact.length)}`]]),
  ]
}

/** The key a reader holds pinned after reading `record` that agreed with its TXT (§7.3): a first contact pins the
 * record's key, the pinned key's own record keeps it, and another key moves the pin only by a rotation that verifies
 * against the pinned record. */
function pinAfter(pinned: AddressRecord | null, record: AddressRecord): string {
  if (pinned === null || pinned.key === record.key) return record.key
  return outcome(() => verifyRotation(pinned, record)) === 'ok' ? record.key : pinned.key
}

/**
 * An "agreement" case (§12.2 item 5): the key a domain's TXT names (null for no TXT), an org record
 * that verifies on its own, the record a reader had pinned (null at first contact), the verdict of the agreement, and
 * the key pinned after the reading: the earlier pin's, or none, when the record does not agree.
 */
function agreementCase(
  name: string,
  want: string,
  txtKey: string | null,
  record: AddressRecord,
  pinned: AddressRecord | null,
  wantPin: string | null,
): J {
  const found = discover(txtKey === null ? [] : [[`v=ac1; key=${txtKey}`]], ACME_DOMAIN)
  const result = expectResult(
    name,
    outcome(() => checkDiscovered(record, found)),
    want,
  )
  const pin = result === 'ok' ? pinAfter(pinned, record) : (pinned?.key ?? null)
  if (pin !== wantPin) throw new Error(`${name}: the pin after is ${pin}, not ${wantPin}`)
  return { name, txt_key: txtKey, record, pinned, result, pin }
}

function agreementCases(): J[] {
  const k10 = P.org.address
  const k11 = P.orgNext.address
  const byOther = countersignRotation(P.mallory.key, nextBare)
  const byRotationKey = countersignRotation(P.rotation.key, nextBare)
  const plain = signRecord(P.orgNext.key, { ...nextUnsigned, rotated_from: null })
  const twoSteps = countersignRotation(
    P.orgNext.key,
    signRecord(P.worker.key, { ...nextUnsigned, key: P.worker.address, rotated_from: k11 }),
  )
  return [
    agreementCase("a record of the TXT's key, at first contact", 'ok', k10, orgRecord, null, k10),
    agreementCase("a record of the TXT's key, its key pinned", 'ok', k10, orgRecord, orgRecord, k10),
    agreementCase('no TXT: a record of any key, at first contact', 'ok', null, plain, null, k11),
    agreementCase(
      "k11 countersigned by the TXT's key k10, at first contact: k11 is pinned",
      'ok',
      k10,
      nextByPrev,
      null,
      k11,
    ),
    agreementCase(
      "k11 countersigned by the TXT's key k10, k10 pinned: the pin moves to k11",
      'ok',
      k10,
      nextByPrev,
      orgRecord,
      k11,
    ),
    agreementCase('k11 naming k10, countersigned by another key', 'resolve-failed', k10, byOther, null, null),
    agreementCase(
      'k11 naming k10, countersigned by another key, k10 pinned: the pin stays',
      'resolve-failed',
      k10,
      byOther,
      orgRecord,
      k10,
    ),
    agreementCase('k11 naming k10 with no rotation_sig', 'resolve-failed', k10, nextBare, null, null),
    agreementCase('k11 naming no rotated_from, k10 pinned', 'resolve-failed', k10, plain, orgRecord, k10),
    agreementCase(
      "k11 countersigned by k10's rotation key: only a reader that holds k10's record can check it",
      'resolve-failed',
      k10,
      byRotationKey,
      orgRecord,
      k10,
    ),
    agreementCase(
      'k12 countersigned by k11: two steps from the TXT key k10',
      'resolve-failed',
      k10,
      twoSteps,
      null,
      null,
    ),
    agreementCase(
      'the TXT moved to k11, k10 pinned, k11 countersigned by k10: the pin moves',
      'ok',
      k11,
      nextByPrev,
      orgRecord,
      k11,
    ),
    agreementCase(
      "the TXT moved to k11, k10 pinned, k11 countersigned by k10's rotation key: the pin moves by §7.3",
      'ok',
      k11,
      byRotationKey,
      orgRecord,
      k11,
    ),
    agreementCase(
      'the TXT names k11, k10 pinned, a k11 that no rotation links: DNS moves no pin',
      'ok',
      k11,
      plain,
      orgRecord,
      k10,
    ),
  ]
}

function handleCases(): J[] {
  return [
    handleCase('a handle', 'ok', 'jane@acme.example'),
    handleCase('every character a local part may hold', 'ok', 'j.doe-2_x@acme.example'),
    handleCase('a local part of 64 characters, the cap', 'ok', `${'a'.repeat(64)}@acme.example`),
    handleCase('a local part of 65 characters', 'bad-address', `${'a'.repeat(65)}@acme.example`),
    handleCase('an upper-case letter in the local part', 'bad-address', 'Jane@acme.example'),
    handleCase('an upper-case letter in the domain', 'bad-address', 'jane@ACME.example'),
    handleCase('a domain of one label', 'bad-address', 'jane@acme'),
    handleCase('an IP literal', 'bad-address', 'jane@192.0.2.1'),
    handleCase('no local part', 'bad-address', '@acme.example'),
    handleCase('no domain', 'bad-address', 'jane@'),
    handleCase('two @', 'bad-address', 'jane@@acme.example'),
    handleCase('a space', 'bad-address', 'ja ne@acme.example'),
    handleCase('a trailing dot on the domain', 'bad-address', 'jane@acme.example.'),
    handleCase('a local part that starts with a dot', 'bad-address', '.jane@acme.example'),
    handleCase('a local part that ends with a dot', 'bad-address', 'jane.@acme.example'),
    handleCase('a local part that starts with a hyphen', 'bad-address', '-jane@acme.example'),
    handleCase('a plus sign', 'bad-address', 'jane+tag@acme.example'),
    handleCase('a character past ASCII', 'bad-address', 'jané@acme.example'),
    handleCase('no @', 'bad-address', 'jane'),
    handleCase('an address', 'bad-address', P.jane.address),
    // Added 2026-10-26: ports, IP literals and the special-use
    // top-level names that name no org on the public DNS.
    handleCase('a port', 'bad-address', 'jane@acme.example:443'),
    handleCase('an IPv6 literal', 'bad-address', 'jane@[2001:db8::1]'),
    handleCase('a last label in hex, an IP literal by the WHATWG rule', 'bad-address', 'jane@acme.0x1f'),
    handleCase('under .local', 'bad-address', 'jane@acme.local'),
    handleCase('under .localhost', 'bad-address', 'jane@acme.localhost'),
    handleCase('under .internal', 'bad-address', 'jane@acme.internal'),
    handleCase('under .onion', 'bad-address', 'jane@acme.onion'),
    handleCase('under .alt', 'bad-address', 'jane@acme.alt'),
    handleCase('under .arpa', 'bad-address', 'jane@acme.arpa'),
    handleCase('under .invalid', 'bad-address', 'jane@acme.invalid'),
    handleCase('a special-use name that is not the last label', 'ok', 'jane@acme.local.example'),
    handleCase('.test is not refused', 'ok', 'jane@acme.e2e.test'),
  ]
}

function handleRecordCases(): J[] {
  const jane = 'jane@acme.example'
  const janeRecord = handleRecord(P.org, jane, P.jane.address, T0, DAY)
  const forged = { ...janeRecord, sig: signPreimage(P.mallory.key, handleRecordPreimage(janeRecord)) }
  const none: readonly string[] = []
  return [
    handleRecordCase('a handle record signed by the org key', janeRecord, [
      [T0, ORG_KEY, jane, none, 'ok'],
      [T0 + DAY, ORG_KEY, jane, none, 'ok'],
      [T0 + DAY + 1, ORG_KEY, jane, none, 'record-expired'],
      [T0 - DEFAULT_SKEW, ORG_KEY, jane, none, 'ok'],
      [T0 - DEFAULT_SKEW - 1, ORG_KEY, jane, none, 'future-iat'],
      [T0, P.orgNext.address, jane, none, 'resolve-failed'],
      [T0, ORG_KEY, 'bob@acme.example', none, 'resolve-failed'],
      [T0, ORG_KEY, 'jane@globex.example', none, 'resolve-failed'],
      [T0, ORG_KEY, jane, [P.mallory.address, P.jane.address], 'revoked'],
    ]),
    handleRecordCase(
      'a handle of every local-part character',
      handleRecord(P.org, 'j.doe-2_x@acme.example', P.bob.address, T0, HOUR),
      [[T0, ORG_KEY, 'j.doe-2_x@acme.example', none, 'ok']],
    ),
    handleRecordCase('a record that names the org key and is signed by another', forged, [
      [T0, ORG_KEY, jane, none, 'bad-record-sig'],
    ]),
    handleRecordCase('a record changed after signing', { ...janeRecord, address: P.mallory.address }, [
      [T0, ORG_KEY, jane, none, 'bad-record-sig'],
    ]),
    handleRecordCase(
      'a record of another key, valid alone',
      handleRecord(P.mallory, jane, P.mallory.address, T0, DAY),
      [
        [T0, ORG_KEY, jane, none, 'resolve-failed'],
        [T0, P.mallory.address, jane, none, 'ok'],
      ],
    ),
    handleRecordCase(
      'a record of the org key for a handle of another domain',
      handleRecord(P.org, 'jane@globex.example', P.jane.address, T0, DAY),
      [[T0, ORG_KEY, jane, none, 'resolve-failed']],
    ),
    handleRecordCase('a record of one second', handleRecord(P.org, jane, P.jane.address, T0, 1), [
      [T0 + 1, ORG_KEY, jane, none, 'ok'],
      [T0 + 2, ORG_KEY, jane, none, 'record-expired'],
    ]),
  ]
}

function invalidHandleRecords(): J[] {
  const r = handleRecord(P.org, 'jane@acme.example', P.jane.address, T0, DAY)
  return [
    invalidHandleRecord('another kind', 'bad-record', r, { kind: 'address' }),
    invalidHandleRecord('a missing member', 'bad-record', r, { sig: undefined }),
    invalidHandleRecord('an extra member', 'bad-record', r, { relays: [] }),
    invalidHandleRecord('an org that is not an address', 'bad-record', r, { org: 'acme.example' }),
    invalidHandleRecord('a handle with an upper-case letter', 'bad-record', r, {
      handle: 'Jane@acme.example',
    }),
    invalidHandleRecord('a handle with no @', 'bad-record', r, { handle: 'jane' }),
    invalidHandleRecord('a handle whose local part is over 64', 'bad-record', r, {
      handle: `${'a'.repeat(65)}@acme.example`,
    }),
    invalidHandleRecord('a handle at an IP literal', 'bad-record', r, { handle: 'jane@192.0.2.1' }),
    invalidHandleRecord('an address where the handle goes', 'bad-record', r, { handle: P.jane.address }),
    invalidHandleRecord('a handle that is a number', 'bad-record', r, { handle: 7 }),
    invalidHandleRecord('an address that is not an address', 'bad-record', r, {
      address: 'jane@acme.example',
    }),
    invalidHandleRecord('a negative iat', 'bad-record', r, { iat: -1 }),
    invalidHandleRecord('a fractional iat', 'bad-record', r, { iat: T0 + 0.5 }),
    invalidHandleRecord('a ttl of zero', 'bad-record', r, { ttl: 0 }),
    invalidHandleRecord('a ttl over a day', 'bad-record', r, { ttl: DAY + 1 }),
    invalidHandleRecord('a sig of 63 bytes', 'bad-record', r, { sig: r.sig.slice(2) }),
    invalidHandleRecord('a handle under a special-use name', 'bad-record', r, { handle: 'jane@acme.local' }),
  ]
}

function handleParseCases(): J[] {
  const r = text(serializeHandleRecord(handleRecord(P.org, 'jane@acme.example', P.jane.address, T0, DAY)))
  return [
    handleParseCase('the bytes of a handle record', 'ok', r),
    handleParseCase(
      'a member named twice',
      'bad-json',
      r.replace('{"kind":"handle",', '{"kind":"handle","kind":"handle",'),
    ),
    handleParseCase('a ttl written 86400.0', 'bad-record', r.replace('"ttl":86400', '"ttl":86400.0')),
    handleParseCase('not JSON', 'bad-json', r.slice(0, -1)),
    handleParseCase('a list', 'bad-record', `[${r}]`),
    handleParseCase("an address record's bytes", 'bad-record', text(serializeRecord(orgRecord))),
  ]
}

function discoveryFile(): J {
  return {
    ...header(
      'Discovery by DNS and handles (spec/SPEC.md §12, L2; added 2026-10-26). "presentation" holds TXT records written as text (§12.2 item 7) and their character-strings, as strings_hex, or resolve-failed. "txt" holds the TXT records a lookup of txt_name gave (null: none is asked), each a list of strings, and where they lead: the key the record must agree with (null without a bag record), the org\'s address record URL and its origin, or resolve-failed (§12.2 items 1 to 4). "agreement" holds the key a TXT names, an org record, the record a reader had pinned, the verdict of the record\'s agreement with the TXT (§12.2 item 5) and the key pinned after the reading (§7.3). "handles" holds strings read as handles (§12.3 item 1), with their local part, domain and record path, or bad-address. "cases" holds signed handle records with their canonical strings, digests and signers, and their verdict for a reader that expects an org key and a handle and holds the org\'s revoked list, at several times (§12.4 item 3). "invalid" holds handle records that break their form, and "parse" bytes read as a handle record.',
      [
        'A TXT record is a bag record when its first field is v=ac1; a reader joins its strings with nothing between them, ignores spaces and tabs around fields and empty fields, ignores unknown fields and refuses one given twice; key is required, host is exactly bag or absent, and a rec field is refused: DNS names no URL. Two bag records, or a malformed one, are resolve-failed with no fallback to the well-known URL. The origin is https://bag.<domain> with host=bag, else https://<domain>; no TXT is asked for a name over 253 characters or under a special-use name.',
        'A record agrees with its TXT when its key is the TXT key, or when its rotated_from is the TXT key and its rotation_sig verifies under it (one countersigned step); anything else is resolve-failed before any pin is read. The pin then moves only by §7.3: DNS never moves a pin.',
        'A handle record is checked in this order: its form, its signature under its org, iat <= now + skew, now <= iat + ttl, its org and handle against the expected ones (resolve-failed), its address against the revoked list (revoked). Relays store no handle record. A handle finds an address and admits no one.',
      ],
    ),
    presentation: presentationCases(),
    txt: txtCases(),
    agreement: agreementCases(),
    handles: handleCases(),
    cases: handleRecordCases(),
    invalid: invalidHandleRecords(),
    parse: handleParseCases(),
  }
}

// ---- writing and checking ---------------------------------------------------------------------------------------

function build(upstream: string | undefined): Record<FileName, J> {
  return {
    'canonical.json': canonicalFile(),
    'envelope.json': envelopeFile(),
    'sealed-multi.json': sealedMultiFile(),
    'chain-valid.json': chainValidFile(),
    'chain-invalid.json': chainInvalidFile(),
    'records.json': recordsFile(),
    'hpke-rfc9180-subset.json': subsetFile(upstream),
    'discovery.json': discoveryFile(),
  }
}

/** The case lists of the vector files. */
const CASE_LISTS = [
  'cases',
  'parse',
  'verify',
  'invalid',
  'rotations',
  'preimages',
  'fetch_proofs',
  'open',
  'seal',
  'caveats',
  'rotation_claims',
  'presentation',
  'txt',
  'agreement',
  'handles',
] as const

/** The number of cases in a file: the entries of its case lists. */
function caseCount(file: J): number {
  return CASE_LISTS.map((k) => (Array.isArray(file[k]) ? (file[k] as unknown[]).length : 0)).reduce(
    (a, b) => a + b,
    0,
  )
}

/** Every `result` member's value in a vector file, in any list, a record's `checks` included. */
function verdictsIn(v: unknown, into: Set<string>): Set<string> {
  if (Array.isArray(v)) for (const x of v) verdictsIn(x, into)
  else if (typeof v === 'object' && v !== null) {
    const r = (v as J).result
    if (typeof r === 'string') into.add(r)
    for (const x of Object.values(v)) verdictsIn(x, into)
  }
  return into
}

/**
 * The codes of the closed set (spec/SPEC.md Appendix A, which test/errors.test.ts pins to AC_ERROR_CODES) that some
 * vector gives as its verdict: the unit of the vector claim.
 */
function codesWithAVerdict(files: Record<FileName, J>): string {
  const found = new Set<string>()
  for (const name of FILES) verdictsIn(files[name], found)
  const codes = AC_ERROR_CODES.filter((c) => found.has(c))
  return `codes of Appendix A with a vector verdict: ${codes.length} of ${AC_ERROR_CODES.length}`
}

function writeAll(dir: string, upstream: string | undefined): Record<FileName, J> {
  const files = build(upstream)
  for (const name of FILES) writeFileSync(join(dir, name), `${JSON.stringify(files[name], null, 2)}\n`)
  return files
}

function firstDifference(a: Buffer, b: Buffer): string {
  const la = a.toString('utf8').split('\n')
  const lb = b.toString('utf8').split('\n')
  const i = la.findIndex((line, n) => line !== lb[n])
  return `line ${(i === -1 ? la.length : i) + 1}`
}

function check(): number {
  const root = process.env.AC_TEST_TMP || tmpdir()
  const dir = mkdtempSync(join(root, 'bag-vectors-'))
  let problems = 0
  try {
    const files = writeAll(dir, undefined)
    for (const name of FILES) {
      const committedPath = join(VECTORS_DIR, name)
      if (!existsSync(committedPath)) {
        console.error(`vectors:check: spec/vectors/${name} is missing`)
        problems++
        continue
      }
      const committed = readFileSync(committedPath)
      const fresh = readFileSync(join(dir, name))
      if (committed.equals(fresh)) {
        console.log(
          `vectors:check: ${name} byte-identical (${caseCount(files[name])} cases, ${fresh.length} bytes)`,
        )
      } else {
        console.error(
          `vectors:check: ${name} differs from the regenerated file, first at ${firstDifference(committed, fresh)}`,
        )
        problems++
      }
    }
    // pair-code.json is hand-maintained (core cannot import edge's codec); verify_vectors.py and the edge tests check it.
    const handMaintained: readonly string[] = ['pair-code.json']
    for (const extra of readdirSync(VECTORS_DIR).filter(
      (f) => !(FILES as readonly string[]).includes(f) && !handMaintained.includes(f),
    )) {
      console.error(`vectors:check: spec/vectors/${extra} is not written by the generator`)
      problems++
    }
    const total = FILES.reduce((n, name) => n + caseCount(files[name]), 0)
    console.log(`vectors:check: ${codesWithAVerdict(files)}`)
    console.log(
      problems === 0
        ? `vectors:check: OK, ${FILES.length} of ${FILES.length} files byte-identical, ${total} cases`
        : `vectors:check: FAIL, ${problems} problem(s)`,
    )
  } finally {
    if (process.env.AC_KEEP_TMP === '1') console.log(`vectors:check: kept ${dir}`)
    else rmSync(dir, { recursive: true, force: true })
  }
  return problems === 0 ? 0 : 1
}

function main(argv: readonly string[]): number {
  const upstreamAt = argv.indexOf('--upstream')
  const upstream = upstreamAt === -1 ? undefined : argv[upstreamAt + 1]
  if (upstreamAt !== -1 && upstream === undefined) {
    console.error('gen-vectors: --upstream needs the path of the CFRG test-vectors.json')
    return 2
  }
  if (argv.includes('--check')) return check()
  const files = writeAll(VECTORS_DIR, upstream)
  for (const name of FILES)
    console.log(`gen-vectors: wrote spec/vectors/${name} (${caseCount(files[name])} cases)`)
  console.log(`gen-vectors: ${codesWithAVerdict(files)}`)
  return 0
}

process.exitCode = main(process.argv.slice(2))
