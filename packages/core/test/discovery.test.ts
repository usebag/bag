import { describe, expect, it } from 'vitest'
import {
  BAG_HOST,
  checkDiscovered,
  DISCOVERY_PREFIX,
  discover,
  MAX_TXT_BYTES,
  parseDiscoveryTxt,
  parseTxtPresentation,
  TXT_VERSION_FIELD,
  txtName,
  WELL_KNOWN_RECORD_PATH,
} from '../src/discovery.ts'
import { type AddressRecord, countersignRotation, signRecord } from '../src/records.ts'
import { expectAcError, outcome } from './support/assert.ts'
import { DAY, P, type Party, T0 } from './support/fixtures.ts'

// Discovery by DNS (spec/SPEC.md §12.2): the text form, the TXT fields, the outcome of a
// lookup and a record's agreement with its TXT. The shared vectors (spec/vectors/discovery.json) are read by
// vectors.test.ts; these pin the edges each rule has.

const ACME = 'acme.example'
const KEY = P.org.address
const OTHER = P.orgNext.address
const txt = (text: string) => parseDiscoveryTxt(text, ACME)

function orgRecord(key = P.org, from: Party | null = null, by: Party | null = from): AddressRecord {
  const r = signRecord(key.key, {
    kind: 'address',
    key: key.address,
    sealing_key: null,
    relays: [],
    rotation_key: null,
    revoked: [],
    ttl: DAY,
    iat: T0,
    rotated_from: from?.address ?? null,
  })
  return by === null ? r : countersignRotation(by.key, r)
}

describe('the TXT name', () => {
  it('is the prefix and the domain, and none past 253 characters or under a special-use name', () => {
    expect(txtName(ACME)).toBe('_bag.acme.example')
    expect(DISCOVERY_PREFIX).toBe('_bag.')
    const host = (last: number) => `${['a', 'a', 'a'].map((c) => c.repeat(63)).join('.')}.${'b'.repeat(last)}`
    expect(host(56)).toHaveLength(248)
    expect(txtName(host(56))).toHaveLength(253)
    expect(txtName(host(57))).toBeNull()
    for (const special of ['acme.local', 'acme.onion', 'printer.internal'])
      expect(txtName(special)).toBeNull()
    expect(txtName('acme.local.example')).toBe('_bag.acme.local.example')
    expectAcError(() => txtName('ACME.example'), 'resolve-failed')
  })
})

describe('a bag TXT record', () => {
  it('gives its key and its host', () => {
    expect(txt(`v=ac1; key=${KEY}; host=bag`)).toEqual({ key: KEY, host: BAG_HOST })
    expect(txt(` v = ac1 ;\tkey= ${KEY} ;; `)).toEqual({ key: KEY, host: null })
    expect(TXT_VERSION_FIELD).toBe('v=ac1')
  })

  it('is none when its first field is not v=ac1', () => {
    for (const text of [
      '',
      ';;',
      'v=spf1 -all',
      'v=ac2; key=x',
      'V=ac1',
      `key=${KEY}; v=ac1`,
      'v=ac1x',
      'v',
      '=ac1',
    ])
      expect(txt(text), text).toBeNull()
  })

  it('ignores unknown fields', () => {
    expect(txt(`v=ac1; key=${KEY}; note=hello; X-Future_1=a=b; host=bag`)).toEqual({
      key: KEY,
      host: BAG_HOST,
    })
  })

  it('is refused when malformed', () => {
    const k = `key=${KEY}`
    const cases = [
      `v=ac1; ${k}; ${k}`,
      `v=ac1; ${k}; x=1; x=2`,
      'v=ac1',
      'v=ac1; key=ed25519:ABC',
      'v=ac1; host=bag',
      `v=ac1; ${k}; rec=https://agents.acme.example/org.json`,
      `v=ac1; ${k}; rec=https://acme.example${WELL_KNOWN_RECORD_PATH}`,
      `v=ac1; ${k}; rec=x`,
      `v=ac1; ${k}; host=agents`,
      `v=ac1; ${k}; host=Bag`,
      `v=ac1; ${k}; host=bag.acme.example`,
      `v=ac1; ${k}; host=bag; host=bag`,
      `v=ac1; ${k}; nothing`,
      `v=ac1; ${k}; note=a b`,
      `v=ac1; ${k}; note=`,
      `v=ac1; ${k}; 1x=2`,
      `v=ac1; ${k}; né=1`,
      `v=ac1; ${k}; x=${'y'.repeat(MAX_TXT_BYTES)}`,
      `v=ac1; ${k}; ${'n'.repeat(33)}=1`,
    ]
    for (const text of cases)
      expect(
        outcome(() => txt(text)),
        text,
      ).toBe('resolve-failed')
    const exact = `v=ac1; ${k}; x=`
    const pad = 'y'.repeat(MAX_TXT_BYTES - exact.length)
    expect(txt(`${exact}${pad}`)).not.toBeNull()
    expectAcError(() => txt(`${exact}${pad}y`), 'resolve-failed')
    expectAcError(() => parseDiscoveryTxt(`v=ac1; ${k}`, 'acme'), 'resolve-failed')
  })
})

describe('the text form of a TXT record', () => {
  it('reads quoted and bare strings with escapes', () => {
    expect(parseTxtPresentation('"v=ac1; key=x"')).toEqual(['v=ac1; key=x'])
    expect(parseTxtPresentation('\t"a"  "b" c ')).toEqual(['a', 'b', 'c'])
    expect(parseTxtPresentation('"a\\"b\\\\c" d;e')).toEqual(['a"b\\c', 'd;e'])
    expect(parseTxtPresentation('"a\\059b" "\\233"')).toEqual(['a;b', 'é'])
    expect(parseTxtPresentation('""')).toEqual([''])
    expect(parseTxtPresentation('x'.repeat(255))).toEqual(['x'.repeat(255)])
    // A parenthesis is legal inside a quoted string (§12.2 item 7 forbids it only in a bare word).
    expect(parseTxtPresentation('"a(b)c"')).toEqual(['a(b)c'])
  })

  it('refuses anything else', () => {
    for (const text of [
      '',
      '  ',
      '"abc',
      '"ab"cd',
      'ab"c',
      '"a\\256"',
      '"a\\05x"',
      '"a\\',
      'a\\',
      'é',
      'a\nb',
      'a(b',
      'a)b',
    ]) {
      expect(
        outcome(() => parseTxtPresentation(text)),
        JSON.stringify(text),
      ).toBe('resolve-failed')
    }
    expectAcError(() => parseTxtPresentation('x'.repeat(256)), 'resolve-failed')
    expectAcError(() => parseTxtPresentation(`"${'\\120'.repeat(256)}"`), 'resolve-failed')
  })
})

describe('a lookup', () => {
  it('gives the origin at the domain, the origin at bag.<domain>, or a refusal', () => {
    const wellKnown = {
      key: null,
      url: `https://acme.example${WELL_KNOWN_RECORD_PATH}`,
      origin: 'https://acme.example',
    }
    expect(discover([], ACME)).toEqual(wellKnown)
    expect(discover([['v=spf1 -all'], ['google-site-verification=x']], ACME)).toEqual(wellKnown)
    expect(discover([['v=spf1 -all'], ['v=ac1; key=', KEY, '; host=bag']], ACME)).toEqual({
      key: KEY,
      url: `https://bag.acme.example${WELL_KNOWN_RECORD_PATH}`,
      origin: 'https://bag.acme.example',
    })
    expect(discover([[`v=ac1;key=${KEY}`]], ACME)).toEqual({ ...wellKnown, key: KEY })
    expectAcError(() => discover([[`v=ac1; key=${KEY}`], [`v=ac1; key=${OTHER}`]], ACME), 'resolve-failed')
    expectAcError(() => discover([[`v=ac1; key=${KEY}; key=${KEY}`]], ACME), 'resolve-failed')
    expectAcError(() => discover([[`v=ac1; key=${KEY}; rec=https://acme.example/o`]], ACME), 'resolve-failed')
    expectAcError(() => discover([], 'acme'), 'resolve-failed')
  })

  it('reads no record for a domain it does not ask', () => {
    const records = [[`v=ac1; key=${KEY}; host=bag`]]
    expect(discover(records, 'acme.local')).toEqual({
      key: null,
      url: `https://acme.local${WELL_KNOWN_RECORD_PATH}`,
      origin: 'https://acme.local',
    })
    const long = `${['a', 'a', 'a'].map((c) => c.repeat(63)).join('.')}.${'b'.repeat(57)}`
    expect(discover(records, long).key).toBeNull()
  })
})

describe("a record's agreement with its TXT", () => {
  const named = discover([[`v=ac1; key=${KEY}`]], ACME)
  const verdict = (record: AddressRecord, d = named) => outcome(() => checkDiscovered(record, d))

  it("holds for the TXT's key, and for any key without a TXT", () => {
    expect(verdict(orgRecord())).toBe('ok')
    expect(verdict(orgRecord(P.orgNext), discover([], ACME))).toBe('ok')
  })

  it('holds for one rotation the TXT key countersigned, and nothing else', () => {
    expect(verdict(orgRecord(P.orgNext, P.org))).toBe('ok')
    expect(verdict(orgRecord(P.orgNext))).toBe('resolve-failed')
    expect(verdict(orgRecord(P.orgNext, P.org, P.mallory))).toBe('resolve-failed')
    expect(verdict(orgRecord(P.orgNext, P.org, null))).toBe('resolve-failed')
    expect(verdict(orgRecord(P.orgNext, P.mallory))).toBe('resolve-failed')
    expect(verdict(orgRecord(P.rotation, P.orgNext))).toBe('resolve-failed')
    expectAcError(() => checkDiscovered(orgRecord(P.orgNext), named), 'resolve-failed')
  })
})
