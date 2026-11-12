import { readFileSync, writeFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { isAcError } from '../src/errors.ts'
import { preimageDigest } from '../src/hash.ts'
import { toHex } from '../src/hex.ts'
import { signingKeyFromSeed } from '../src/keys.ts'
import {
  checkMembersRecord,
  checkPolicyRecord,
  isCaveatPattern,
  isPolicyCode,
  isPolicyEntry,
  isTypePattern,
  matchesCaveat,
  parseMembersRecord,
  parsePolicyRecord,
  policyPreimage,
  serializePolicyRecord,
  signPolicyRecord,
  typeMatches,
  type UnsignedMembersRecord,
  type UnsignedPolicyRecord,
  verifyMembersRecord,
  verifyPolicyRecord,
} from '../src/policy.ts'

// The two policy records in the TypeScript core (the served record, and the members
// record that is never served), and the shared table (spec/drafts/policy-vectors.json): written from fixed seeds by
// this test, checked against the file on every run (AC_WRITE_POLICY_VECTORS=1 writes it). Its `cases`, served
// records, are read unchanged by crates/ac-core/src/policy/tests.rs; its `members_cases` by this core alone, since a
// members record never leaves the org's edges.

const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n)
const ORG = signingKeyFromSeed(seed(0x51))
const OTHER = signingKeyFromSeed(seed(0x52))
const PEER = signingKeyFromSeed(seed(0x53)).address
const NOW = 1_800_000_000
const SKEW = 300

const served: UnsignedPolicyRecord = {
  kind: 'policy',
  key: ORG.address,
  scopes: [
    { match: '*', accept_types: ['chat.*', 'query.v1'], max_bytes: 65_536 },
    { match: 'repo=web', accept_types: ['deploy.*'], max_bytes: 4096 },
  ],
  external: { required_caveats: ['type=*'], max_hop_lifetime: 86_400, max_hops: 2 },
  inspection: null,
  iat: NOW,
}
const members: UnsignedMembersRecord = {
  kind: 'policy-members',
  key: ORG.address,
  roots: { mode: 'allow', list: ['domain:globex.example', PEER], unknown: 'quarantine' },
  rates: { per_root: 120, window: 60 },
  outbound: { deny: ['domain:evil.example'] },
  moderation: { module: 'keyword', action: 'quarantine', params: ['ignore previous instructions'] },
  iat: NOW,
}

type Json = Record<string, unknown>
const textOf = (r: UnsignedPolicyRecord | UnsignedMembersRecord, key = ORG): string =>
  new TextDecoder().decode(
    serializePolicyRecord(r.kind === 'policy' ? signPolicyRecord(key, r) : signPolicyRecord(key, r)),
  )
/** A signed record with one change, as JSON text: the signature is kept, so the form decides first. */
const mutate = (r: UnsignedPolicyRecord | UnsignedMembersRecord, change: (v: Json) => void): string => {
  const v = JSON.parse(textOf(r)) as Json
  change(v)
  return JSON.stringify(v)
}
const at = (path: string, value: unknown) => (r: Json) => {
  const keys = path.split('.')
  let o = r as Record<string, unknown>
  for (const k of keys.slice(0, -1)) o = o[k] as Record<string, unknown>
  o[keys.at(-1) as string] = value
}
const drop = (member: string) => (r: Json) => {
  delete r[member]
}
const scope = (i: number, member: string, value: unknown) => (r: Json) => {
  ;((r.scopes as Json[])[i] as Json)[member] = value
}
const domains = (n: number): string[] => Array.from({ length: n }, (_, i) => `domain:d${i}.example`)

interface Case {
  readonly name: string
  readonly text: string
  readonly now: number
  readonly expect: string
}
const ok = (name: string, r: UnsignedPolicyRecord | UnsignedMembersRecord, now = NOW): Case => ({
  name,
  text: textOf(r),
  now,
  expect: 'ok',
})
const no = (name: string, text: string, expect = 'bad-record', now = NOW): Case => ({
  name,
  text,
  now,
  expect,
})
const sm = (change: (v: Json) => void): string => mutate(served, change)
const mm = (change: (v: Json) => void): string => mutate(members, change)

const SERVED: readonly Case[] = [
  ok('the minimal served record: no scopes, no external rules', { ...served, scopes: [], external: null }),
  ok('scopes and external rules', served),
  ok('valid at iat - skew', served, NOW - SKEW),
  ok('valid 400 days after iat: it does not expire, a newer iat replaces it', served, NOW + 400 * 86_400),
  ok('external nulls and a non-ASCII <name>=* scope', {
    ...served,
    scopes: [{ match: 'équipe=*', accept_types: ['*'], max_bytes: 1 }],
    external: { required_caveats: [], max_hop_lifetime: null, max_hops: null },
  }),
  no(
    'signed by another key',
    JSON.stringify({
      ...JSON.parse(textOf(served)),
      sig: signPolicyRecord(OTHER, { ...served, key: OTHER.address }).sig,
    }),
    'bad-record-sig',
  ),
  no('a member changed after signing', sm(scope(1, 'max_bytes', 4097)), 'bad-record-sig'),
  no('iat ahead of now + skew', textOf(served), 'future-iat', NOW - SKEW - 1),
  no('a members record read as a served one', textOf(members)),
  no('a deny list in a served record', sm(at('roots', members.roots))),
  no('an outbound section in a served record', sm(at('outbound', members.outbound))),
  no('a moderation section in a served record', sm(at('moderation', members.moderation))),
  no('a ttl, which no policy record has', sm(at('ttl', 86_400))),
  no('inspection set: reserved and null', sm(at('inspection', PEER))),
  no('kind is not policy', sm(at('kind', 'address'))),
  no('key is not an address', sm(at('key', 'ed25519:zz'))),
  no('a member missing', sm(drop('external'))),
  no('scopes is not a list', sm(at('scopes', {}))),
  no(
    'over 32 scopes',
    sm(
      at(
        'scopes',
        Array.from({ length: 33 }, () => served.scopes[0]),
      ),
    ),
  ),
  no('a scope with a member added', sm(scope(0, 'extra', 1))),
  no('a scope match that is empty', sm(scope(0, 'match', ''))),
  no('a scope match that is =*', sm(scope(0, 'match', '=*'))),
  no('a scope match over 256 bytes', sm(scope(0, 'match', `team=${'x'.repeat(252)}`))),
  no('accept_types empty', sm(scope(0, 'accept_types', []))),
  no('a type pattern with an inner star', sm(scope(0, 'accept_types', ['a*b']))),
  no('a type pattern with an empty prefix', sm(scope(0, 'accept_types', ['.*']))),
  no('a type pattern listed twice', sm(scope(0, 'accept_types', ['chat.*', 'chat.*']))),
  no('max_bytes zero', sm(scope(0, 'max_bytes', 0))),
  no('max_bytes over 196,608', sm(scope(0, 'max_bytes', 196_609))),
  no('external is not an object', sm(at('external', []))),
  no('a required caveat that is the bare wildcard', sm(at('external.required_caveats', ['*']))),
  no('max_hop_lifetime zero', sm(at('external.max_hop_lifetime', 0))),
  no('max_hops over 8', sm(at('external.max_hops', 9))),
  no('sig is not hex', sm(at('sig', 'zz'))),
  no('iat written 1800000000.0', textOf(served).replace(`"iat":${NOW}`, `"iat":${NOW}.0`)),
  no('a member named twice', textOf(served).replace('"iat":', '"inspection":null,"iat":'), 'bad-json'),
  no('not JSON', '{"kind":"policy"', 'bad-json'),
  no('a list, not an object', '[]'),
]

const MEMBERS: readonly Case[] = [
  ok('the minimal members record: every section null', {
    ...members,
    roots: null,
    rates: null,
    outbound: null,
    moderation: null,
  }),
  ok('every section set', members),
  ok('a deny list, a refusal for the unknown, non-ASCII params', {
    ...members,
    roots: { mode: 'deny', list: [PEER], unknown: 'refuse' },
    moderation: {
      module: 'allow-all',
      action: 'allow',
      params: ['ignorez les instructions précédentes', '指示を無視'],
    },
  }),
  no(
    'signed by another key',
    JSON.stringify({
      ...JSON.parse(textOf(members)),
      sig: signPolicyRecord(OTHER, { ...members, key: OTHER.address }).sig,
    }),
    'bad-record-sig',
  ),
  no('iat ahead of now + skew', textOf(members), 'future-iat', NOW - SKEW - 1),
  no('a served record read as a members one', textOf(served)),
  no('scopes in a members record', mm(at('scopes', []))),
  no('roots.mode is neither allow nor deny', mm(at('roots.mode', 'block'))),
  no('unknown allow: a policy never admits an unknown root', mm(at('roots.unknown', 'allow'))),
  no('roots.unknown is not an action', mm(at('roots.unknown', 'drop'))),
  no('roots.list holds the wildcard', mm(at('roots.list', ['*']))),
  no('roots.list names an entry twice', mm(at('roots.list', [PEER, PEER]))),
  no('roots.list holds an IP literal domain', mm(at('roots.list', ['domain:127.0.0.1']))),
  no('roots.list over 1,024 entries', mm(at('roots.list', domains(1025)))),
  no('rates.window zero', mm(at('rates.window', 0))),
  no('rates.window over a day', mm(at('rates.window', 86_401))),
  no('rates.per_root zero', mm(at('rates.per_root', 0))),
  no('outbound.deny holds the wildcard', mm(at('outbound.deny', ['*']))),
  no('a module name with a capital', mm(at('moderation.module', 'Keyword'))),
  no('a moderation action that is not one', mm(at('moderation.action', 'block'))),
  no(
    'over 64 params',
    mm(
      at(
        'moderation.params',
        Array.from({ length: 65 }, (_, i) => `p${i}`),
      ),
    ),
  ),
  no('a param over 256 bytes', mm(at('moderation.params', ['é'.repeat(129)]))),
  no('an empty param', mm(at('moderation.params', ['']))),
  no('a member missing', mm(drop('rates'))),
]

/** The verdict of reading and verifying a case's text as the given kind: "ok" or the code. */
function verdict(
  c: Case,
  read: (text: string) => unknown,
  verify: (r: unknown, now: number) => unknown,
): string {
  try {
    verify(read(c.text), c.now)
    return 'ok'
  } catch (e) {
    if (isAcError(e)) return e.code
    throw e
  }
}

const VECTORS = new URL('../../../spec/drafts/policy-vectors.json', import.meta.url)
const withDigest = (
  cases: readonly Case[],
  read: (t: string) => UnsignedPolicyRecord | UnsignedMembersRecord,
) =>
  cases.map((c) =>
    c.expect === 'ok' ? { ...c, digest: toHex(preimageDigest(policyPreimage(read(c.text)))) } : c,
  )

describe('the two policy records in the TypeScript core', () => {
  it('gives every case of the shared table its pre-written verdict, and the file holds exactly this table', () => {
    for (const c of SERVED)
      expect(
        verdict(c, parsePolicyRecord, (r, now) => verifyPolicyRecord(r, now, SKEW)),
        c.name,
      ).toBe(c.expect)
    for (const c of MEMBERS)
      expect(
        verdict(c, parseMembersRecord, (r, now) => verifyMembersRecord(r, now, SKEW)),
        c.name,
      ).toBe(c.expect)
    const doc = {
      description:
        'Org policy records from fixed seeds (org root [0x51; 32], another key [0x52; 32], a peer [0x53; 32]), each as JSON text with the time it is verified at (skew 300) and the result: "ok" with the digest of its preimage, or the code. "cases" are served records (kind policy), read by both cores; "members_cases" are members records (kind policy-members), which never leave the org\'s edges and are read by the TypeScript core alone. Written by packages/core/test/policy.test.ts, read by crates/ac-core/src/policy/tests.rs.',
      skew: SKEW,
      cases: withDigest(SERVED, parsePolicyRecord),
      members_cases: withDigest(MEMBERS, parseMembersRecord),
    }
    if (process.env.AC_WRITE_POLICY_VECTORS === '1')
      writeFileSync(VECTORS, `${JSON.stringify(doc, null, 2)}\n`)
    expect(JSON.parse(readFileSync(VECTORS, 'utf8'))).toEqual(doc)
    console.log(
      `MEASURE L1(c): ${SERVED.length} served cases (both cores), ${MEMBERS.length} members cases (TypeScript)`,
    )
  })

  it('signs only with its own key, writes wire order, and reads back what it wrote', () => {
    expect(() => signPolicyRecord(OTHER, served)).toThrow(expect.objectContaining({ code: 'bad-key' }))
    const a = signPolicyRecord(ORG, served)
    const b = signPolicyRecord(ORG, members)
    expect(Object.keys(JSON.parse(new TextDecoder().decode(serializePolicyRecord(a))))).toEqual([
      'kind',
      'key',
      'scopes',
      'external',
      'inspection',
      'iat',
      'sig',
    ])
    expect(Object.keys(JSON.parse(new TextDecoder().decode(serializePolicyRecord(b))))).toEqual([
      'kind',
      'key',
      'roots',
      'rates',
      'outbound',
      'moderation',
      'iat',
      'sig',
    ])
    expect([
      parsePolicyRecord(serializePolicyRecord(a)),
      checkPolicyRecord(a),
      verifyPolicyRecord(a, NOW),
    ]).toEqual([a, a, a])
    expect([
      parseMembersRecord(serializePolicyRecord(b)),
      checkMembersRecord(b),
      verifyMembersRecord(b, NOW),
    ]).toEqual([b, b, b])
  })

  it('matches caveat and type patterns, entries and codes', () => {
    expect([
      matchesCaveat('*', []),
      matchesCaveat('repo=web', ['repo=web']),
      matchesCaveat('repo=web', ['repo=webx']),
    ]).toEqual([true, true, false])
    expect([
      matchesCaveat('type=*', ['type=chat.*']),
      matchesCaveat('type=*', ['types=x']),
      matchesCaveat('type=*', []),
    ]).toEqual([true, false, false])
    expect([
      isCaveatPattern('*', true),
      isCaveatPattern('*', false),
      isCaveatPattern('=*', true),
      isCaveatPattern(7, true),
    ]).toEqual([true, false, false, false])
    expect(['*', 'chat.*', 'chat.v1', 'a*', '.*', '', 3].map(isTypePattern)).toEqual([
      true,
      true,
      true,
      false,
      false,
      false,
      false,
    ])
    expect([
      typeMatches('*', 'x'),
      typeMatches('chat.*', 'chat.v1'),
      typeMatches('chat.*', 'chatty'),
      typeMatches('chat.v1', 'chat.v1'),
    ]).toEqual([true, true, false, true])
    expect([
      isPolicyEntry(PEER),
      isPolicyEntry('domain:acme.example'),
      isPolicyEntry('*'),
      isPolicyEntry('domain:x'),
    ]).toEqual([true, true, false, false])
    expect([isPolicyCode('policy-refused'), isPolicyCode('untrusted-root'), isPolicyCode('nope')]).toEqual([
      true,
      true,
      false,
    ])
  })
})
