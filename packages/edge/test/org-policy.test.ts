import { signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { P, T0 } from './support/fixtures.ts'
import {
  ACME,
  acmeChain,
  bob,
  envelope,
  HOME,
  heldHaveNoContent,
  members,
  orgPolicy,
  records,
  ruled,
} from './support/org.ts'

// The org policy and the rate: the org's two records at bob's edge, before dedup, unsealing and routing.

const allow = (list: string[], unknown: 'refuse' | 'quarantine') =>
  members({ roots: { mode: 'allow', list, unknown } })
const deny = (list: string[]) => members({ roots: { mode: 'deny', list, unknown: 'refuse' } })

describe('roots allowed, denied or unknown, before routing', () => {
  it('(a) an allow list refuses a root the edge trusts but the list does not name, rule roots.unknown, before dedup', async () => {
    const b = bob({ members: allow([`domain:${ACME}`], 'refuse') })
    const row = await b.edge.receive(HOME, 1, envelope().bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
    expect(ruled(b.audit)).toEqual(['verify accept ok', 'policy reject untrusted-root roots.unknown'])
    expect(b.got).toEqual([])
  })

  it('(b) unknown quarantine holds it: quarantined, content null, never routed, one policy queue line', async () => {
    const b = bob({ members: allow([], 'quarantine') })
    const e = envelope()
    const row = await b.edge.receive(HOME, 1, e.bytes)
    expect([row.state, row.reason, row.content, row.id]).toEqual([
      'quarantined',
      'untrusted-root',
      null,
      e.id,
    ])
    expect(ruled(b.audit)).toEqual(['verify accept ok', 'policy queue untrusted-root roots.unknown'])
    expect(b.edge.receiver.ack(row).state).toBe('quarantined')
    expect([b.got.length, heldHaveNoContent(b.store)]).toEqual([0, 1])
    expect(b.edge.receiver.quarantined().map((q) => [q.row.seq, q.hold.rule, q.hold.code])).toEqual([
      [row.seq, 'roots.unknown', 'untrusted-root'],
    ])
  })

  it('(c) a deny list refuses a root it names though the edge trusts it, and routes a trusted root it does not name', async () => {
    const b = bob({ members: deny([P.carol.address]) })
    const refused = await b.edge.receive(HOME, 1, envelope().bytes)
    expect([refused.state, refused.reason]).toEqual(['rejected', 'untrusted-root'])
    const routed = await b.edge.receive(HOME, 2, envelope({ from: P.session, auth: acmeChain() }).bytes)
    expect(routed.state).toBe('routed')
    expect(ruled(b.audit).slice(0, 2)).toEqual([
      'verify accept ok',
      'policy reject untrusted-root roots.deny',
    ])
    expect(b.got.map((m) => m.root)).toEqual([P.org.address])
  })

  it('(c2) a deny list names a domain by its current key, and a domain it never resolved matches nothing', async () => {
    const b = bob({ members: deny(['domain:dead.test', `domain:${ACME}`]) })
    const row = await b.edge.receive(HOME, 1, envelope({ from: P.session, auth: acmeChain() }).bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
    const other = bob({ members: deny(['domain:dead.test']) })
    expect((await other.edge.receive(HOME, 1, envelope().bytes)).state).toBe('routed')
  })

  it('(c3) a denied domain that has gone dark still matches the key it is pinned to here', async () => {
    const r = records()
    const b = bob({ members: deny([`domain:${ACME}`]), records: r })
    expect(
      (await b.edge.receive(HOME, 1, envelope({ from: P.session, auth: acmeChain() }).bytes)).reason,
    ).toBe('untrusted-root')
    r.domains.set(ACME, new Error('the well-known host is down'))
    b.clock.advance(86_401)
    const later = envelope({
      from: P.session,
      auth: acmeChain([], [T0 + 200_000, T0 + 200_000]),
      ts: T0 + 86_401,
    })
    const dark = await b.edge.receive(HOME, 2, later.bytes)
    expect([dark.state, dark.reason]).toEqual(['rejected', 'untrusted-root'])
    expect(ruled(b.audit).at(-1)).toBe('policy reject untrusted-root roots.deny')
  })

  it('(d) a release admits a held unknown root, reading its revoked list from its own record when it has hops', async () => {
    const b = bob({ members: allow([], 'quarantine'), roots: [] })
    const chain = [signHop(P.carol.signing, P.mallory.address, [], T0 + 3600)]
    const held = await b.edge.receive(HOME, 1, envelope({ from: P.mallory, auth: chain }).bytes)
    expect((await b.edge.receiver.release(held.seq)).state).toBe('acked')
    const lone = [signHop(P.other.signing, P.mallory.address, [], T0 + 3600)]
    const orphan = await b.edge.receive(HOME, 2, envelope({ from: P.mallory, auth: lone }).bytes)
    const waiting = await b.edge.receiver.release(orphan.seq)
    expect([waiting.state, waiting.reason, b.got.length]).toEqual(['received', 'resolve-failed', 1])
  })

  it("(e) an allow list admits the root that is its listed domain's current key", async () => {
    const b = bob({ members: allow([`domain:${ACME}`], 'refuse') })
    expect(
      (await b.edge.receive(HOME, 1, envelope({ from: P.session, auth: acmeChain() }).bytes)).state,
    ).toBe('routed')
  })

  it('(e2) an allow list whose domain does not resolve waits, resolve-failed, when nothing else matched', async () => {
    const r = records()
    r.domains.delete(ACME)
    const b = bob({
      members: allow([`domain:${ACME}`], 'refuse'),
      records: r,
      roots: [{ address: P.carol.address }],
    })
    const row = await b.edge.receive(HOME, 1, envelope().bytes)
    expect([row.state, row.reason]).toEqual(['received', 'resolve-failed'])
  })

  it('under an org record a trusted domain that does not resolve still waits, resolve-failed, as without one', async () => {
    const b = bob({ members: allow([], 'refuse'), roots: [{ domain: 'dead.test' }] })
    const row = await b.edge.receive(HOME, 1, envelope().bytes)
    expect([row.state, row.reason]).toEqual(['received', 'resolve-failed'])
  })

  it('(f) without a roots section, the edge trusts as it did, and refuses an untrusted root plainly', async () => {
    const b = bob({ org: orgPolicy(), members: members() })
    const row = await b.edge.receive(HOME, 1, envelope({ from: P.mallory }).bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
    expect([ruled(b.audit)[1], b.store.policyCounts()]).toEqual(['policy reject untrusted-root', []])
  })

  it('refuses two records signed by different roots', () => {
    const other = { ...orgPolicy(), key: P.other.address }
    expect(() => bob({ org: other, members: members() })).toThrow('policy: the served and members records')
  })
})

describe('types and sizes per scope', () => {
  const scopes = [
    { match: '*', accept_types: ['chat.*', 'deploy.*'], max_bytes: 65_536 },
    { match: 'repo=web', accept_types: ['deploy.*'], max_bytes: 4096 },
  ]

  it('(a) a deploy message where the only scope takes chat is type-not-accepted, rule scopes[0].accept_types', async () => {
    const b = bob({
      org: orgPolicy({ scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }] }),
    })
    const refused = await b.edge.receive(HOME, 1, envelope({ type: 'deploy.run' }).bytes)
    expect([refused.state, refused.reason]).toEqual(['rejected', 'type-not-accepted'])
    expect(ruled(b.audit).at(-1)).toBe('policy reject type-not-accepted scopes[0].accept_types')
    expect((await b.edge.receive(HOME, 2, envelope().bytes)).state).toBe('routed')
  })

  it('(b) under repo=web every matching scope applies: size by scopes[1], type by scopes[1]', async () => {
    const b = bob({ org: orgPolicy({ scopes }) })
    const auth = acmeChain(['repo=web'])
    const big = envelope({
      from: P.session,
      auth,
      type: 'deploy.run',
      body: { repo: 'web', pad: 'x'.repeat(4096) },
    })
    const small = envelope({ from: P.session, auth, type: 'deploy.run', body: { repo: 'web' } })
    const chat = envelope({ from: P.session, auth, type: 'chat.v1', body: { repo: 'web' } })
    expect(big.bytes.length).toBeGreaterThan(4096)
    const rows = [await b.edge.receive(HOME, 1, big.bytes), await b.edge.receive(HOME, 2, small.bytes)]
    rows.push(await b.edge.receive(HOME, 3, chat.bytes))
    expect(rows.map((r) => [r.state, r.reason])).toEqual([
      ['rejected', 'policy-refused'],
      ['routed', null],
      ['rejected', 'type-not-accepted'],
    ])
    expect(ruled(b.audit).filter((l) => l.includes('scopes'))).toEqual([
      'policy reject policy-refused scopes[1].max_bytes',
      'policy reject type-not-accepted scopes[1].accept_types',
    ])
  })

  it('(c) a message no scope matches is not restricted by scopes', async () => {
    const b = bob({ org: orgPolicy({ scopes: [scopes[1] as (typeof scopes)[number]] }) })
    const e = envelope({ type: 'chat.v1', body: { pad: 'x'.repeat(5000) } })
    expect((await b.edge.receive(HOME, 1, e.bytes)).state).toBe('routed')
  })
})

describe('external chains', () => {
  const external = { required_caveats: ['type=*'], max_hop_lifetime: 86_400, max_hops: 2 }
  // The served record's key is P.org; carol's chains are rooted at carol, so they are external.
  const carolChain = (caveats: readonly string[], exp = T0 + 3600) => [
    signHop(P.carol.signing, P.mallory.address, caveats, exp),
  ]

  it('(a, b, c) refuses an external chain without a type= caveat, with a hop living two days, or of three hops', async () => {
    const b = bob({ org: orgPolicy({ external }) })
    const missing = await b.edge.receive(HOME, 1, envelope({ from: P.mallory, auth: carolChain([]) }).bytes)
    const long = carolChain(['type=chat.*'], T0 + 172_800)
    const lived = await b.edge.receive(HOME, 2, envelope({ from: P.mallory, auth: long }).bytes)
    const three = [
      signHop(P.carol.signing, P.other.address, ['type=chat.*'], T0 + 3600),
      signHop(P.other.signing, P.jane.address, [], T0 + 3600),
      signHop(P.jane.signing, P.mallory.address, [], T0 + 3600),
    ]
    const hops = await b.edge.receive(HOME, 3, envelope({ from: P.mallory, auth: three }).bytes)
    expect([missing, lived, hops].map((r) => r.reason)).toEqual([
      'policy-refused',
      'policy-refused',
      'policy-refused',
    ])
    expect(ruled(b.audit).filter((l) => l.includes('external'))).toEqual([
      'policy reject policy-refused external.required_caveats[0]',
      'policy reject policy-refused external.max_hop_lifetime',
      'policy reject policy-refused external.max_hops',
    ])
  })

  it('(d, e) routes a compliant external chain, and a chain rooted at the org key without the caveat', async () => {
    const b = bob({ org: orgPolicy({ external }) })
    const ok = await b.edge.receive(
      HOME,
      1,
      envelope({ from: P.mallory, auth: carolChain(['type=chat.*']) }).bytes,
    )
    const internal = await b.edge.receive(HOME, 2, envelope({ from: P.session, auth: acmeChain() }).bytes)
    expect([ok.state, internal.state]).toEqual(['routed', 'routed'])
  })

  it('applies only the limits a record sets', async () => {
    const b = bob({
      org: orgPolicy({ external: { required_caveats: [], max_hop_lifetime: null, max_hops: null } }),
    })
    const auth = carolChain([], T0 + 172_800)
    expect((await b.edge.receive(HOME, 1, envelope({ from: P.mallory, auth }).bytes)).state).toBe('routed')
  })
})

describe('the rate per root', () => {
  it('holds the message one over per_root in its window, passes again in the next window, and releases the held one', async () => {
    const b = bob({ members: members({ rates: { per_root: 2, window: 60 } }) })
    const rows = []
    for (let i = 1; i <= 3; i++) rows.push(await b.edge.receive(HOME, i, envelope().bytes))
    expect(rows.map((r) => r.state)).toEqual(['routed', 'routed', 'quarantined'])
    expect(ruled(b.audit).filter((l) => l.includes('rates'))).toEqual([
      'policy queue policy-refused rates.per_root',
    ])
    b.clock.advance(60)
    expect((await b.edge.receive(HOME, 4, envelope().bytes)).state).toBe('routed')
    expect((await b.edge.receiver.release((rows[2] as { seq: number }).seq)).state).toBe('acked')
    expect(b.got.length).toBe(4)
  })

  it('bounds the quarantine: a hold past the cap is refused, rule quarantine.full', async () => {
    const b = bob({ members: allow([], 'quarantine'), maxQuarantined: 2 })
    const rows = []
    for (let i = 1; i <= 3; i++) rows.push(await b.edge.receive(HOME, i, envelope().bytes))
    expect(rows.map((r) => [r.state, r.reason])).toEqual([
      ['quarantined', 'untrusted-root'],
      ['quarantined', 'untrusted-root'],
      ['rejected', 'policy-refused'],
    ])
    expect(ruled(b.audit).at(-1)).toBe('policy reject policy-refused quarantine.full')
  })
})
