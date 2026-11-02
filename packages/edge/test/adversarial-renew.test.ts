import { type Hop, parseEnvelope, serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { EdgeError } from '../src/ports.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// Edge.renewChain (packages/edge/src/edge.ts lines 224 to 268) under attack, on the fake clock
// (the edge's clock injection, EdgeOptions.clock). S1: a chain of another root, another principal, with no hop from the
// mailbox key, or a shorter one, and a self-rooted edge: chain-mismatch (lines 228, 234, 241) or chain-not-later
// (line 247), and a refusal changes nothing: the chain the next send carries, and the audit log, are as before. S2: the
// equal-exp chain is chain-not-later (`exp <= before`, line 245); a chain that does not verify at the edge's clock
// (verifyChain, line 231) is refused before its exp is compared, so a hop already expired cannot renew, however much
// later its exp is than the current chain's. Each case is a positive control first (V1): the lawful renewal succeeds.

const HOME = 'http://home.test'

const hop = (from: Party, to: Party, exp: number, caveats: readonly string[] = []): Hop =>
  signHop(from.signing, to.address, caveats, exp)

/** The session's edge: it signs as `signer` (the session), receives at jane's mailbox, under `auth`. */
async function sessionEdge(
  auth: readonly Hop[],
  o: { mailbox?: string; signer?: Party; clock?: FakeClock } = {},
) {
  const clock = o.clock ?? new FakeClock()
  const audit = new MemoryAuditSink()
  const relay = new MemoryRelay()
  await relay.publish(HOME, serializeRecord(addressRecord(P.bob, { relays: [HOME], ttl: DAY })))
  const signer = o.signer ?? P.session
  const edge = new Edge({
    keys: { signing: signer.signing, sealing: P.jane.sealing },
    auth,
    mailbox: o.mailbox ?? P.jane.address,
    store: new SqliteStore(':memory:'),
    relays: { client: relay, urls: [HOME] },
    policy: { roots: [], types: [] },
    clock,
    rng: seededRng('adversarial-renew'),
    audit,
    lookup: PUBLIC_LOOKUP,
  })
  return { edge, clock, audit, relay }
}

/** [code, an EdgeError?] of what renewChain throws, or ['renewed', false]. */
function attempt(edge: Edge, auth: readonly Hop[]): [string, boolean] {
  try {
    edge.renewChain(auth)
    return ['renewed', false]
  } catch (e) {
    return [(e as { code: string }).code, e instanceof EdgeError]
  }
}

/** The chain the next envelope carries: a send to bob, read back from the relay. */
async function carried(edge: Edge, relay: MemoryRelay): Promise<readonly Hop[]> {
  const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { probe: true } })
  const row = relay.box(HOME, P.bob.address).find((r) => parseEnvelope(r.bytes).id === sent.id)
  return parseEnvelope(row?.bytes as Uint8Array).auth
}

describe('S1: renewChain refuses a chain that does not continue the current one, and changes nothing', () => {
  const current = (): Hop[] => [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3600)]

  it('V1: the lawful renewal (same root and principal, a later exp) is taken, with one audit line', async () => {
    const { edge, audit, relay } = await sessionEdge(current())
    const next = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)]
    expect(edge.renewChain(next)).toMatchObject({
      root: P.org.address,
      principal: P.jane.address,
      exp: T0 + 7200,
    })
    expect(await carried(edge, relay)).toEqual(next)
    expect(audit.steps().filter((s) => s.startsWith('rotate'))).toEqual(['rotate accept ok'])
  })

  it('refuses another root, another principal, an attacker spliced in, no hop from the mailbox key, a shorter chain and a self-rooted edge', async () => {
    const { edge, audit, clock, relay } = await sessionEdge(current())
    clock.t = T0 + 100
    const before = [...audit.lines]
    const cases: [string, readonly Hop[], string][] = [
      [
        'another root (mallory -> jane)',
        [hop(P.mallory, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)],
        'chain-mismatch',
      ],
      [
        'another principal (org -> other)',
        [hop(P.org, P.other, T0 + DAY), hop(P.other, P.session, T0 + 7200)],
        'chain-mismatch',
      ],
      [
        'an attacker spliced in as principal (org -> jane -> mallory -> session)',
        [
          hop(P.org, P.jane, T0 + DAY),
          hop(P.jane, P.mallory, T0 + DAY),
          hop(P.mallory, P.session, T0 + 7200),
        ],
        'chain-mismatch',
      ],
      ['a self-rooted chain from jane (no org hop)', [hop(P.jane, P.session, T0 + 7200)], 'chain-mismatch'],
      [
        'shorter: an earlier exp',
        [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 1800)],
        'chain-not-later',
      ],
    ]
    const results: string[] = []
    for (const [what, auth, code] of cases) {
      expect(attempt(edge, auth), what).toEqual([code, true])
      expect(edge.auth, what).toEqual(current())
      results.push(`${what}: ${code}`)
    }
    // No hop from the mailbox key: an edge whose mailbox is `other`, between org and jane, renewed with a chain that
    // skips other (it would verify, same root and principal, later exp).
    const deep = [
      hop(P.org, P.other, T0 + DAY),
      hop(P.other, P.jane, T0 + DAY),
      hop(P.jane, P.session, T0 + 3600),
    ]
    const viaOther = await sessionEdge(deep, { mailbox: P.other.address })
    const skipping = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)]
    expect(attempt(viaOther.edge, skipping)).toEqual(['chain-mismatch', true])
    expect(viaOther.edge.auth).toEqual(deep)
    expect(viaOther.audit.lines).toEqual([])
    results.push('no hop from the mailbox key: chain-mismatch')
    // A self-rooted edge has no chain to renew, whatever it is offered.
    const self = await sessionEdge([], { mailbox: P.session.address })
    expect(attempt(self.edge, [hop(P.jane, P.session, T0 + 7200)])).toEqual(['chain-mismatch', true])
    expect(self.edge.auth).toEqual([])
    expect(self.audit.lines).toEqual([])
    results.push('a self-rooted edge: chain-mismatch')
    // Nothing changed: no audit line was written, and the next envelope carries the current chain.
    expect(audit.lines).toEqual(before)
    expect(await carried(edge, relay)).toEqual(current())
    console.log(
      `MEASURE S1: ${results.length} refusals, 0 renewals, 0 audit lines\n  ${results.join('\n  ')}`,
    )
  })
})

describe('S2: chain-not-later against the clock', () => {
  it('the equal-exp chain is chain-not-later, re-signed or the same bytes, at any clock before it', async () => {
    const chain = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3600)]
    const { edge, clock, audit } = await sessionEdge(chain)
    // V1: a later exp renews; then the attacks run against the renewed chain.
    expect(attempt(edge, [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3601)])).toEqual([
      'renewed',
      false,
    ])
    const now = edge.auth
    for (const t of [T0, T0 + 3000, T0 + 3601]) {
      clock.t = t
      // The very same hops presented again, and the same exp re-signed with other caveats.
      expect(attempt(edge, now), `same bytes at ts + ${t - T0}`).toEqual(['chain-not-later', true])
      expect(
        attempt(edge, [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3601, ['type=chat.*'])]),
        `same exp re-signed at ts + ${t - T0}`,
      ).toEqual(['chain-not-later', true])
    }
    expect(edge.auth).toEqual(now)
    expect(audit.steps().filter((s) => s.startsWith('rotate'))).toEqual(['rotate accept ok'])
  })

  it('a hop already expired at the edge clock cannot renew, though its exp is later than the current chain; the edge clock decides', async () => {
    const chain = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3600)]
    const { edge, clock, audit } = await sessionEdge(chain)
    // The current chain has expired (the edge clock at ts + 5,000); the offered one expires at ts + 4,000: later than
    // the current (ts + 3,600), already past at the edge clock. Refused by verifyChain at the clock, before exp.
    clock.t = T0 + 5000
    const backdated = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 4000)]
    expect(attempt(edge, backdated)).toEqual(['hop-expired', false])
    // The same refusal when only the first hop is past (org -> jane until ts + 4,500).
    expect(attempt(edge, [hop(P.org, P.jane, T0 + 4500), hop(P.jane, P.session, T0 + 4500)])).toEqual([
      'hop-expired',
      false,
    ])
    expect(edge.auth).toEqual(chain)
    // The edge's clock is the judge: at exactly the hop's exp it verifies (rule 8, ts <= exp) and renews; one second
    // later it does not. A clock running behind takes what the true time would refuse; ahead, it refuses a good one.
    const late = await sessionEdge(chain)
    late.clock.t = T0 + 4000
    expect(attempt(late.edge, backdated)).toEqual(['renewed', false])
    const behind = await sessionEdge(chain)
    behind.clock.t = T0 + 3900 // true time ts + 5,000, the edge 1,100 s behind
    expect(attempt(behind.edge, backdated)).toEqual(['renewed', false])
    const ahead = await sessionEdge(chain)
    ahead.clock.t = T0 + 9000 // true time ts + 3,000, the edge 6,000 s ahead
    expect(attempt(ahead.edge, [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)])).toEqual([
      'hop-expired',
      false,
    ])
    expect(audit.lines).toEqual([])
    console.log(
      'MEASURE S2: exp later than the current but past at the edge clock -> hop-expired before the exp compare; at clock = exp renewed; ' +
        'an edge clock 1,100 s behind renews it, one 6,000 s ahead refuses a good chain hop-expired (the edge clock decides)',
    )
  })
})
