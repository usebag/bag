import {
  countersignRotation,
  type HandleRecord,
  serializeHandleRecord,
  serializeRecord,
  signHandleRecord,
  signRecord,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { createRecordSource } from '../src/adapters/well-known.ts'
import { Audit } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import { RelayGuard } from '../src/net.ts'
import type { RecordSource } from '../src/ports.ts'
import { Resolver } from '../src/resolver.ts'
import {
  addressRecord,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { members } from './support/org.ts'
import { MemoryRelay } from './support/relays.ts'

// DNS discovery and handles at the edge (spec/SPEC.md §12.2 and §12.4 item 4): the TXT record at
// _bag.<domain> names the org key and its one origin; the org record there must agree with that key; a handle
// record at the origin binds a handle to an address under the domain's pinned key, cached no longer than its iat + ttl,
// checked against the org's revoked list at every send; a handle is shown for a sender only from a binding this edge
// holds. Every DNS answer and every fetch is injected: no test asks a real resolver or opens a socket.

const DOMAIN = 'acme.test'
const ORIGIN = `bag.${DOMAIN}`
const TXT_NAME = `_bag.${DOMAIN}`
const ORG_RELAY = 'http://relay-acme.test'
const OWN = 'http://relay-own.test'
const JANE = `jane@${DOMAIN}`

const txt = (key: string, host = true): string[] => [`v=ac1; key=${key}`, host ? '; host=bag' : '']
const wellKnown = (host: string): string => `https://${host}/.well-known/bag/address.json`
const handleUrl = (local: string, host = ORIGIN): string =>
  `https://${host}/.well-known/bag/handles/${local}.json`

function handleRecord(o: Partial<HandleRecord> & { signer?: Party } = {}): Uint8Array {
  const signer = o.signer ?? P.org
  return serializeHandleRecord(
    signHandleRecord(signer.signing, {
      kind: 'handle',
      org: signer.address,
      handle: o.handle ?? JANE,
      address: o.address ?? P.jane.address,
      iat: o.iat ?? T0,
      ttl: o.ttl ?? 3600,
    }),
  )
}

/** An org's DNS and origin, served through the real record source with an injected Dns and GET. */
class Org {
  readonly txts = new Map<string, string[][] | Error>()
  readonly files = new Map<string, Uint8Array>()
  readonly asked: string[] = []
  readonly gets: [string, string | null][] = []
  readonly relay = new MemoryRelay()

  constructor() {
    this.txts.set(TXT_NAME, [txt(P.org.address)])
    this.files.set(wellKnown(ORIGIN), serializeRecord(addressRecord(P.org, { relays: [ORG_RELAY] })))
    this.files.set(handleUrl('jane'), handleRecord())
  }

  org(o: Parameters<typeof addressRecord>[1] = {}, host = ORIGIN): void {
    this.files.set(wellKnown(host), serializeRecord(addressRecord(P.org, { relays: [ORG_RELAY], ...o })))
  }

  /** Jane's address record at the org relay, as her edge publishes it there. */
  async home(): Promise<void> {
    await this.relay.publish(
      ORG_RELAY,
      serializeRecord(addressRecord(P.jane, { relays: [ORG_RELAY], ttl: 86_400 })),
    )
  }

  source(): RecordSource {
    return createRecordSource(this.relay, {
      dns: {
        txt: async (name) => {
          this.asked.push(name)
          const v = this.txts.get(name) ?? []
          if (v instanceof Error) throw v
          return v
        },
      },
      get: async (url, connect) => {
        this.gets.push([url, connect])
        const body = this.files.get(url)
        return body === undefined ? { status: 404, body: null } : { status: 200, body }
      },
    })
  }
}

function setup(org = new Org(), source: RecordSource = org.source(), lookup = PUBLIC_LOOKUP) {
  const store = new SqliteStore(':memory:')
  const sink = new MemoryAuditSink()
  const clock = new FakeClock()
  const audit = new Audit(sink, clock)
  const guard = new RelayGuard({ own: [OWN], lookup })
  const resolver = new Resolver({ store, source, clock, audit, relays: [OWN], guard })
  return { resolver, store, sink, clock, org }
}

const lines = (sink: MemoryAuditSink) =>
  sink.lines.map((l) => {
    const v = JSON.parse(l) as { event: string; decision: string; reason: string; detail: string }
    return { ...v, detail: JSON.parse(v.detail) as Record<string, unknown> }
  })

describe('discovery at the edge: the TXT at _bag.<domain>, then the org record at its origin (§12.2)', () => {
  it('with no bag TXT record the origin is the domain; with one, its host; the fetch connects to the checked address', async () => {
    const none = new Org()
    none.txts.set(TXT_NAME, [['v=spf1 -all'], ['google-site-verification=x']])
    none.org({}, DOMAIN)
    const a = setup(none)
    expect((await a.resolver.domain(DOMAIN)).key).toBe(P.org.address)
    expect(none.gets).toEqual([[wellKnown(DOMAIN), '1.1.1.1']])
    expect(none.asked).toEqual([TXT_NAME])

    const plain = new Org()
    plain.txts.set(TXT_NAME, [txt(P.org.address, false)])
    plain.org({}, DOMAIN)
    await setup(plain).resolver.domain(DOMAIN)
    expect(plain.gets.map(([u]) => u)).toEqual([wellKnown(DOMAIN)])

    const hosted = new Org()
    const b = setup(hosted)
    expect((await b.resolver.domain(DOMAIN)).relays).toEqual([ORG_RELAY])
    expect(hosted.gets).toEqual([[wellKnown(ORIGIN), '1.1.1.1']])
    expect(b.store.pinGet(`domain:${DOMAIN}`)?.key).toBe(P.org.address)
    expect(b.sink.steps()).toEqual(['pin accept ok', 'resolve accept ok'])
  })

  it('two bag records, a malformed one or a failed lookup: resolve-failed from dns, no fetch and no pin', async () => {
    const cases: [string, string[][] | Error, string][] = [
      ['two', [txt(P.org.address), txt(P.other.address)], '2 bag TXT records; a domain has one at most'],
      ['rec', [[`v=ac1; key=${P.org.address}; rec=https://x.test/r.json`]], 'the TXT names a rec'],
      ['no key', [['v=ac1; host=bag']], 'a bag TXT record names no key'],
      ['servfail', new Error('ESERVFAIL'), 'error'],
    ]
    for (const [label, answer, why] of cases) {
      const org = new Org()
      org.txts.set(TXT_NAME, answer)
      const { resolver, store, sink } = setup(org)
      const e = (await resolver.domain(DOMAIN).catch((x: unknown) => x)) as Error
      expect(e, label).toMatchObject({ code: 'resolve-failed' })
      expect(e.message, label).toContain(`resolve-failed: domain:${DOMAIN} from dns: `)
      expect(e.message, label).toContain(why)
      expect(org.gets, label).toEqual([])
      expect(store.pinGet(`domain:${DOMAIN}`), label).toBeNull()
      expect(
        lines(sink).map((l) => [l.reason, l.detail.source]),
        label,
      ).toEqual([['resolve-failed', 'dns']])
    }
  })

  it("refuses a record that is neither the TXT's key nor a rotation it countersigned, before any pin", async () => {
    const org = new Org()
    org.txts.set(TXT_NAME, [txt(P.other.address)])
    const { resolver, store } = setup(org)
    await expect(resolver.domain(DOMAIN)).rejects.toThrow(
      `resolve-failed: domain:${DOMAIN} from well-known: the record's key ${P.org.address} is neither the TXT's key ${P.other.address} nor one rotation countersigned by it`,
    )
    expect(store.pinGet(`domain:${DOMAIN}`)).toBeNull()
  })

  it('accepts a rotation countersigned by the key the TXT still names, and pins the new key', async () => {
    const org = new Org()
    const next = signRecord(P.orgNext.signing, {
      kind: 'address',
      key: P.orgNext.address,
      sealing_key: null,
      relays: [ORG_RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 3600,
      iat: T0,
      rotated_from: P.org.address,
    })
    org.files.set(wellKnown(ORIGIN), serializeRecord(countersignRotation(P.org.signing, next)))
    const { resolver, store } = setup(org)
    expect((await resolver.domain(DOMAIN)).key).toBe(P.orgNext.address)
    expect(store.pinGet(`domain:${DOMAIN}`)?.key).toBe(P.orgNext.address)
    // A rotation countersigned by another key than the TXT's does not agree with it.
    org.files.set(wellKnown(ORIGIN), serializeRecord(countersignRotation(P.mallory.signing, next)))
    await expect(setup(org).resolver.domain(DOMAIN)).rejects.toThrow(/neither the TXT's key/)
  })

  it('refuses a special-use domain before any lookup, and asks no TXT for a host DNS cannot name', async () => {
    const org = new Org()
    const { resolver } = setup(org)
    await expect(resolver.domain('printer.local')).rejects.toThrow(
      'resolve-failed: domain:printer.local from dns: printer.local is under a special-use name',
    )
    org.files.set(wellKnown('93.184.216.34:8443'), serializeRecord(addressRecord(P.org)))
    expect((await resolver.domain('93.184.216.34:8443')).key).toBe(P.org.address)
    const long = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(61)}.test`
    org.files.set(wellKnown(long), serializeRecord(addressRecord(P.org)))
    expect((await resolver.domain(long)).key).toBe(P.org.address)
    expect(org.asked).toEqual([])
  })

  it('runs the origin through the guard: a name on the LAN is refused before any request', async () => {
    const org = new Org()
    const { resolver } = setup(org, org.source(), async () => ['192.168.1.20'])
    await expect(resolver.domain(DOMAIN)).rejects.toThrow(
      `resolve-failed: domain:${DOMAIN} from well-known: ${wellKnown(ORIGIN)}: ${ORIGIN} resolves to a non-public address (private) among 1 answer`,
    )
    expect(org.gets).toEqual([])
  })
})

describe('handles at the edge (§12.4 item 4): the org record, the handle record, the address record', () => {
  it('resolves jane@acme.test end to end, audits the handle and the address, and sends to it', async () => {
    const org = new Org()
    await org.home()
    const { resolver, sink, store } = setup(org)
    const binding = await resolver.handle(JANE)
    expect(binding).toEqual({
      handle: JANE,
      domain: DOMAIN,
      address: P.jane.address,
      org: P.org.address,
      relays: [ORG_RELAY],
      valid_until: T0 + 3600,
    })
    expect(org.gets.map(([u, c]) => [u, c])).toEqual([
      [wellKnown(ORIGIN), '1.1.1.1'],
      [handleUrl('jane'), '1.1.1.1'],
    ])
    expect(lines(sink).at(-1)).toMatchObject({
      event: 'resolve',
      decision: 'accept',
      detail: {
        subject: `handle:${JANE}`,
        kind: 'handle',
        source: ORIGIN,
        handle: JANE,
        address: P.jane.address,
        org: P.org.address,
        expires_at: T0 + 3600,
      },
    })
    const r = await resolver.recipient(JANE, ['http://hint.test'])
    expect(r.address).toBe(P.jane.address)
    expect(r.relays).toEqual([ORG_RELAY])
    expect(org.relay.recordFetches).toContain(`${ORG_RELAY} ${P.jane.address} address`)
    expect(await resolver.addresses([JANE, P.bob.address])).toEqual({
      to: [P.jane.address, P.bob.address],
      relays: [ORG_RELAY],
    })
    expect(store.cacheGet(`handle:${JANE}`, 'handle', T0)).not.toBeNull()

    // Through the Edge: the Sender takes the handle in `to`, and the envelope goes to jane's relay.
    const edge = new Edge({
      keys: P.bob.keys,
      store: new SqliteStore(':memory:'),
      relays: { client: org.relay, urls: [OWN] },
      records: org.source(),
      policy: { roots: [], types: ['*'] },
      clock: new FakeClock(),
      rng: seededRng('handles'),
      audit: new MemoryAuditSink(),
      lookup: PUBLIC_LOOKUP,
      leaveRecords: false,
    })
    const sent = await edge.send({ to: [JANE], type: 'chat.v1', body: { hi: 1 } })
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([[ORG_RELAY, 'published']])
    expect(org.relay.box(ORG_RELAY, P.jane.address)).toHaveLength(1)
  })

  it('a missing handle, a source without handle records, and records that do not verify resolve nothing', async () => {
    const org = new Org()
    org.files.set(
      handleUrl('eve'),
      handleRecord({ handle: `eve@${DOMAIN}`, address: P.mallory.address, signer: P.mallory }),
    )
    org.files.set(handleUrl('carl'), handleRecord())
    org.files.set(handleUrl('old'), handleRecord({ handle: `old@${DOMAIN}`, iat: T0 - 7200 }))
    org.files.set(handleUrl('junk'), new TextEncoder().encode('{"kind":"handle"}'))
    const { resolver, sink } = setup(org)
    const failed = async (h: string) => resolver.handle(h).catch((e: Error) => e.message)
    expect(await failed(`nobody@${DOMAIN}`)).toBe(
      `resolve-failed: handle:nobody@${DOMAIN} from handle: no such handle at ${ORIGIN}`,
    )
    expect(await failed(`eve@${DOMAIN}`)).toBe(
      `resolve-failed: handle:eve@${DOMAIN} from handle: the handle record is not signed by the domain's key`,
    )
    expect(await failed(`carl@${DOMAIN}`)).toBe(
      `resolve-failed: handle:carl@${DOMAIN} from handle: the handle record names another handle`,
    )
    expect(await failed(`old@${DOMAIN}`)).toBe(
      `resolve-failed: handle:old@${DOMAIN} from handle: record-expired: the handle record is past its ttl`,
    )
    expect(await failed(`junk@${DOMAIN}`)).toMatch(/from handle: bad-record: /)
    expect(
      lines(sink)
        .filter((l) => l.decision === 'reject')
        .map((l) => l.detail.cause),
    ).toEqual(['resolve-failed', 'resolve-failed', 'resolve-failed', 'record-expired', 'bad-record'])
    const bare = org.source()
    org.org({}, DOMAIN)
    const { resolver: r2 } = setup(org, { wellKnown: bare.wellKnown, relayRecord: bare.relayRecord })
    await expect(r2.handle(JANE)).rejects.toThrow(
      `resolve-failed: handle:${JANE} from handle: this record source reads no handle record`,
    )
    const broken = new Org()
    broken.txts.set(TXT_NAME, [txt(P.org.address), txt(P.org.address)])
    await expect(setup(broken).resolver.handle(JANE)).rejects.toThrow(
      `resolve-failed: handle:${JANE} from dns: 2 bag TXT records`,
    )
    await expect(resolver.handle('Jane@acme.test')).rejects.toMatchObject({ code: 'bad-address' })
  })

  it('caches the binding no longer than the handle record’s iat + ttl, from now when its iat is ahead', async () => {
    const org = new Org()
    org.org({ ttl: 86_400 })
    org.files.set(handleUrl('jane'), handleRecord({ ttl: 600 }))
    const { resolver, clock, store } = setup(org)
    await resolver.handle(JANE)
    clock.t = T0 + 599
    await resolver.handle(JANE)
    expect(org.gets.filter(([u]) => u === handleUrl('jane'))).toHaveLength(1)
    clock.t = T0 + 600
    org.files.set(handleUrl('jane'), handleRecord({ ttl: 600, iat: T0 + 600 }))
    await resolver.handle(JANE)
    expect(org.gets.filter(([u]) => u === handleUrl('jane'))).toHaveLength(2)

    const ahead = new Org()
    ahead.files.set(handleUrl('jane'), handleRecord({ iat: T0 + 100, ttl: 60 }))
    const s = setup(ahead)
    await s.resolver.handle(JANE)
    expect(s.store.cacheGet(`handle:${JANE}`, 'handle', T0 + 59)).not.toBeNull()
    expect(s.store.cacheGet(`handle:${JANE}`, 'handle', T0 + 60)).toBeNull()
    expect(store.cacheGet(`handle-of:${P.jane.address}`, 'handle', T0 + 600)).not.toBeNull()
  })

  it("checks the address against the freshest org record's revoked list at every send, a cached binding included", async () => {
    const org = new Org()
    org.org({ ttl: 60 })
    await org.home()
    const { resolver, clock, sink } = setup(org)
    await resolver.recipient(JANE)
    clock.t = T0 + 60
    org.org({ ttl: 60, iat: T0 + 60, revoked: [P.jane.address] })
    await expect(resolver.recipient(JANE)).rejects.toMatchObject({
      code: 'revoked',
      message: `revoked: handle:${JANE} from handle: revoked: ${P.jane.address} is revoked by its org`,
    })
    expect(lines(sink).at(-1)).toMatchObject({
      reason: 'revoked',
      detail: { subject: `handle:${JANE}`, source: 'handle' },
    })
    // Resolved afresh under that org record, the handle record is refused revoked too.
    const fresh = setup(org)
    fresh.clock.t = T0 + 60
    org.files.set(handleUrl('jane'), handleRecord({ iat: T0 + 60 }))
    await expect(fresh.resolver.handle(JANE)).rejects.toMatchObject({ code: 'revoked' })
  })

  it('a binding that moves to another address is shown, not followed, until the cached one expires', async () => {
    const org = new Org()
    org.org({ ttl: 86_400 })
    const { resolver, clock } = setup(org)
    await resolver.handle(JANE)
    expect(resolver.handleOf(P.jane.address, P.org.address)).toEqual({
      handle: JANE,
      domain: DOMAIN,
      verified: true,
    })
    org.files.set(handleUrl('jane'), handleRecord({ address: P.bob.address, iat: T0 + 10 }))
    clock.t = T0 + 10
    expect((await resolver.handle(JANE)).address).toBe(P.jane.address)
    expect(resolver.handleOf(P.bob.address, P.org.address)).toBeNull()
    clock.t = T0 + 3600
    expect((await resolver.handle(JANE)).address).toBe(P.bob.address)
    expect(resolver.handleOf(P.bob.address, P.org.address)).toEqual({
      handle: JANE,
      domain: DOMAIN,
      verified: true,
    })
    // jane's reverse entry still names the handle, but the binding names bob now: no handle for jane.
    expect(resolver.handleOf(P.jane.address, P.org.address)).toBeNull()
  })

  it('shows a handle only under the chain root and the key the domain is pinned to now', async () => {
    const org = new Org()
    org.org({ ttl: 86_400 })
    const { resolver, store, clock } = setup(org)
    expect(resolver.handleOf(P.jane.address, P.org.address)).toBeNull()
    await resolver.handle(JANE)
    expect(resolver.handleOf(P.jane.address, P.mallory.address)).toBeNull()
    store.pinPut({
      subject: `domain:${DOMAIN}`,
      key: P.orgNext.address,
      record: null,
      pinnedAt: T0,
      updatedAt: T0,
    })
    expect(resolver.handleOf(P.jane.address, P.org.address)).toBeNull()
    // The same cache under a store with no pin at all shows nothing.
    const bare = new SqliteStore(':memory:')
    for (const s of [`handle:${JANE}`, `handle-of:${P.jane.address}`])
      bare.cachePut(s, 'handle', store.cacheGet(s, 'handle', T0) as Uint8Array, T0 + 3600)
    const audit = new Audit(new MemoryAuditSink(), clock)
    const r = new Resolver({ store: bare, source: org.source(), clock, audit, relays: [OWN] })
    expect(r.handleOf(P.jane.address, P.org.address)).toBeNull()
  })

  it('resolves a cached binding again when a countersigned rotation moved the domain’s pin', async () => {
    const org = new Org()
    org.org({ ttl: 60 })
    const { resolver, clock, store } = setup(org)
    await resolver.handle(JANE)
    clock.t = T0 + 60
    const next = signRecord(P.orgNext.signing, {
      kind: 'address',
      key: P.orgNext.address,
      sealing_key: null,
      relays: [ORG_RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 3600,
      iat: T0 + 60,
      rotated_from: P.org.address,
    })
    org.files.set(wellKnown(ORIGIN), serializeRecord(countersignRotation(P.org.signing, next)))
    org.files.set(handleUrl('jane'), handleRecord({ signer: P.orgNext, iat: T0 + 60 }))
    const b = await resolver.handle(JANE)
    expect(b.org).toBe(P.orgNext.address)
    expect(store.pinGet(`domain:${DOMAIN}`)?.key).toBe(P.orgNext.address)
    expect(resolver.handleOf(P.jane.address, P.orgNext.address)).toMatchObject({ handle: JANE })
  })
})

describe('lookup of a handle and of a domain: each step and its outcome, writing nothing', () => {
  it('reports the TXT, the org record, the handle record and the address records', async () => {
    const org = new Org()
    await org.home()
    const { resolver, sink } = setup(org)
    const report = await resolver.lookup(JANE, ['http://hint.test'])
    expect(report.subject).toBe(`handle:${JANE}`)
    expect(report.cached).toBeNull()
    expect(report.results.map((r) => [r.relay, r.kind, r.outcome, r.key ?? null, r.detail ?? null])).toEqual([
      [TXT_NAME, 'txt', 'found', P.org.address, `origin https://${ORIGIN}`],
      [wellKnown(ORIGIN), 'address', 'found', P.org.address, null],
      [handleUrl('jane'), 'handle', 'found', P.org.address, `address ${P.jane.address}`],
      [ORG_RELAY, 'address', 'found', P.jane.address, null],
      ['http://hint.test', 'address', 'none', null, null],
      [OWN, 'address', 'none', null, null],
      [ORG_RELAY, 'key', 'none', null, null],
      ['http://hint.test', 'key', 'none', null, null],
      [OWN, 'key', 'none', null, null],
    ])
    expect(report.results[2]).toMatchObject({ iat: T0, valid_until: T0 + 3600 })
    expect(sink.lines).toEqual([])
    await resolver.handle(JANE)
    expect((await resolver.lookup(JANE)).cached).toEqual({
      kind: 'handle',
      iat: T0,
      valid_until: T0 + 3600,
      source: ORIGIN,
    })
  })

  it('stops at the step that fails: the TXT, the org record, or the handle record', async () => {
    const two = new Org()
    two.txts.set(TXT_NAME, [txt(P.org.address), txt(P.org.address)])
    expect((await setup(two).resolver.lookup(JANE)).results).toEqual([
      {
        relay: TXT_NAME,
        kind: 'txt',
        outcome: 'error',
        detail: 'resolve-failed: 2 bag TXT records; a domain has one at most',
      },
    ])
    const noOrg = new Org()
    noOrg.files.delete(wellKnown(ORIGIN))
    expect((await setup(noOrg).resolver.lookup(JANE)).results.map((r) => [r.kind, r.outcome])).toEqual([
      ['txt', 'found'],
      ['address', 'error'],
    ])
    const lan = new Org()
    const refused = await setup(lan, lan.source(), async () => ['10.9.9.9']).resolver.lookup(JANE)
    expect(refused.results.map((r) => [r.kind, r.outcome])).toEqual([
      ['txt', 'found'],
      ['address', 'refused'],
    ])
    const missing = await setup().resolver.lookup(`nobody@${DOMAIN}`)
    expect(missing.results.map((r) => [r.kind, r.outcome])).toEqual([
      ['txt', 'found'],
      ['address', 'found'],
      ['handle', 'none'],
    ])
    const plain = new Org()
    const bare = plain.source()
    const noHandles = await setup(plain, {
      wellKnown: bare.wellKnown,
      relayRecord: bare.relayRecord,
      txt: bare.txt as RecordSource['txt'],
    } as RecordSource).resolver.lookup(JANE)
    expect(noHandles.results.at(-1)).toMatchObject({
      kind: 'handle',
      outcome: 'error',
      detail: 'resolve-failed: this record source reads no handle record',
    })
  })

  it('reports the TXT step of a domain lookup, none for a domain without a bag record', async () => {
    const org = new Org()
    org.txts.set(TXT_NAME, [])
    org.org({}, DOMAIN)
    const report = await setup(org).resolver.lookup(`domain:${DOMAIN}`)
    expect(report.results.map((r) => [r.relay, r.kind, r.outcome, r.detail ?? null])).toEqual([
      [TXT_NAME, 'txt', 'none', `origin https://${DOMAIN}`],
      [wellKnown(DOMAIN), 'address', 'found', null],
    ])
  })
})

describe("the Edge's gate judges a handle by its domain and by the address it binds (edge/handles' correction 2)", () => {
  function gated(org: Org, deny: string[]) {
    const audit = new MemoryAuditSink()
    const edge = new Edge({
      keys: P.bob.keys,
      store: new SqliteStore(':memory:'),
      relays: { client: org.relay, urls: [OWN] },
      records: org.source(),
      policy: { roots: [], types: ['*'], members: members({ outbound: { deny } }) },
      clock: new FakeClock(),
      rng: seededRng('handles-gate'),
      audit,
      lookup: PUBLIC_LOOKUP,
      leaveRecords: false,
    })
    const refused = () => lines(audit).filter((l) => l.event === 'policy')
    return { edge, refused }
  }
  const chat = { type: 'chat.v1', body: { hi: 1 } }

  it('refuses a handle whose address the deny list names, the line naming both', async () => {
    const org = new Org()
    await org.home()
    const g = gated(org, [P.jane.address])
    await expect(g.edge.send({ ...chat, to: [JANE] })).rejects.toMatchObject({ rule: 'outbound.deny[0]' })
    expect(g.refused().map((l) => l.detail)).toEqual([
      { to: P.jane.address, handle: JANE, rule: 'outbound.deny[0]' },
    ])
    expect(org.relay.box(ORG_RELAY, P.jane.address)).toHaveLength(0)
  })

  it("refuses a handle under a denied domain before any lookup of the domain's records", async () => {
    const org = new Org()
    const g = gated(org, [P.carol.address, `domain:${DOMAIN}`])
    await expect(g.edge.send({ ...chat, to: [JANE] })).rejects.toMatchObject({ rule: 'outbound.deny[1]' })
    expect([org.asked, org.gets]).toEqual([[], []])
    expect(g.refused().map((l) => l.detail)).toEqual([{ to: JANE, handle: JANE, rule: 'outbound.deny[1]' }])
  })

  it("passes a handle no entry names, sent to the address it binds at the org record's relays", async () => {
    const org = new Org()
    await org.home()
    const g = gated(org, ['domain:other.test'])
    const sent = await g.edge.send({ ...chat, to: [JANE] })
    const hinted = await g.edge.send({ ...chat, to: [JANE], relays: ['http://hint.test'] })
    expect([sent, hinted].map((s) => s.targets.map((t) => [t.relay, t.state]))).toEqual([
      [[ORG_RELAY, 'published']],
      [[ORG_RELAY, 'published']],
    ])
    expect(g.refused()).toEqual([])
  })
})
