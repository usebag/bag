import {
  type BuiltEnvelope,
  buildEnvelope,
  countersignRotation,
  newThread,
  serializeRecord,
  signHop,
} from '@usebag/core'
import { coreRng, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  type Party,
  party,
  rawPublish,
  relayEvents,
  wellKnownFirst,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 31 (conditions (3b) and (3c)): through
// the release binary and the harness's well-known stubs (--well-known-insecure-http, --well-known-resolve), with the
// default cache ceiling, so that a pinned record answers from the cache for an hour. (a) A chain under acme's new key,
// countersigned by the cached one, refreshes the record once and is delivered; (b) the rotated-away key is refused
// from then on, and so is a key the host does not serve, with no further GET inside the minute and the pin kept; (c) a
// publish to a mailbox that waits on a domain with no record and one that takes any root is 200, delivered 1, and
// holds the first in a pending row; the same bytes again are a duplicate, held once. The pending row's late delivery,
// a minute after the failure at the earliest, is crates/ac-relay/tests/network_front.rs's L8, on a manual clock.

const ACME = 'acme.e2e.test'
const GLOBEX = 'globex.e2e.test'

/** An envelope from `sender` to `to` under a one-hop chain from `root`, `n` seconds back. */
function under(root: Party, sender: Party, to: readonly Party[], n = 0): BuiltEnvelope {
  const rng = coreRng(systemRng)
  return buildEnvelope({
    from: sender.signing,
    to: to.map((p) => ({ address: p.address, sealingKey: p.sealing.publicKey })),
    type: 'chat.v1',
    thread: newThread(rng),
    body: { n },
    ts: now() - n,
    rng,
    auth: [signHop(root.signing, sender.address, [], now() + 3600)],
  })
}

describe('e2e scenario 31: a rotation followed at once, and a recipient held pending', () => {
  it('(31) a chain under the new key refreshes the record once and is delivered; the old key and an unknown one are refused with no GET inside the minute; a recipient waiting on a domain is held pending once, the other delivered', async () => {
    const acme = await wellKnownFirst()
    const globex = await wellKnownFirst()
    const w = await withSpawnedRelays(() =>
      world('s31', {
        relayArgs: [
          '--well-known-insecure-http',
          '--well-known-resolve',
          `${ACME}=${acme.domain}`,
          '--well-known-resolve',
          `${GLOBEX}=${globex.domain}`,
        ],
      }),
    )
    const [k1, k2, k3, alice, bob, carol, dave] = ['k1', 'k2', 'k3', 'alice', 'bob', 'carol', 'dave'].map(
      (n) => party(n),
    ) as [Party, Party, Party, Party, Party, Party, Party]
    const org = (p: Party, rotatedFrom: string | null = null) =>
      addressRecord(p, { relays: [w.url], sealing: false, ttl: 3600, rotatedFrom })
    for (const r of [addressRecord(bob, { relays: [w.url] }), acceptFrom(bob, [`domain:${ACME}`])]) {
      expect((await rawPublish(w.url, serializeRecord(r))).status).toBe(200)
    }
    acme.serve(() => serializeRecord(org(k1)))
    const delivered = { status: 200, body: { ok: true, duplicate: false, delivered: 1 } }
    expect(await rawPublish(w.url, under(k1, alice, [bob]).bytes)).toMatchObject(delivered)
    expect(acme.requests()).toBe(1)

    // (a) The rotation, countersigned by the cached k1: one refresh, delivered.
    acme.serve(() => serializeRecord(countersignRotation(k1.signing, org(k2, k1.address))))
    expect(await rawPublish(w.url, under(k2, alice, [bob], 1).bytes)).toMatchObject(delivered)
    expect(acme.requests()).toBe(2)
    const wellKnown = () =>
      relayEvents(w.relay)
        .filter((e) => e.event === 'well-known' && e.domain === ACME)
        .map((e) => [e.outcome, e.key])
    expect(wellKnown()).toEqual([
      ['pinned', k1.address],
      ['rotated', k2.address],
    ])

    // (b) The rotated-away key, then a key the host does not serve: refused, no GET inside the minute, the pin kept.
    const notAccepted = { status: 403, body: { error: 'root-not-accepted' }, retryAfter: null }
    expect(await rawPublish(w.url, under(k1, alice, [bob], 2).bytes)).toEqual(notAccepted)
    expect(await rawPublish(w.url, under(k3, alice, [bob], 3).bytes)).toEqual(notAccepted)
    expect(acme.requests()).toBe(2)
    expect(await rawPublish(w.url, under(k2, alice, [bob], 4).bytes)).toMatchObject(delivered)
    expect(wellKnown()).toEqual([
      ['pinned', k1.address],
      ['rotated', k2.address],
    ])
    console.log(`(31) measure: acme asked ${acme.requests()} times: the pin, then one refresh`)

    // (c) carol waits on globex, which serves nothing; dave takes any root.
    for (const r of [
      addressRecord(carol, { relays: [w.url] }),
      acceptFrom(carol, [`domain:${GLOBEX}`]),
      addressRecord(dave, { relays: [w.url] }),
      acceptFrom(dave, ['*']),
    ]) {
      expect((await rawPublish(w.url, serializeRecord(r))).status).toBe(200)
    }
    const both = under(k2, alice, [carol, dave], 5)
    expect(await rawPublish(w.url, both.bytes)).toMatchObject(delivered)
    expect(await rawPublish(w.url, both.bytes)).toMatchObject({
      status: 200,
      body: { ok: true, duplicate: true, delivered: 0 },
    })
    const pending = relayEvents(w.relay).filter((e) => e.event === 'pending')
    console.log(`(31) measure: pending lines ${JSON.stringify(pending)}`)
    expect(pending.map((e) => [e.id, e.mailbox])).toEqual([[both.envelope.id, carol.address]])
    expect(typeof pending[0]?.until).toBe('number')
    expect(
      relayEvents(w.relay).filter((e) => e.event === 'well-known-refused' && e.domain === GLOBEX),
    ).toHaveLength(1)
  })
})
