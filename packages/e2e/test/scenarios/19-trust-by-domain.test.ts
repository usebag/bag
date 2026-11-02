import { countersignRotation, serializeRecord, signHop, utf8 } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  extraRelay,
  type Node,
  nodeAt,
  now,
  type Party,
  party,
  rawPublish,
  relayEvents,
  until,
  untilSecond,
  wellKnownFirst,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// The relay reaches the harness's well-known stub, a node:http server on 127.0.0.1:<port>, through its test-only
// flags: --well-known-insecure-http (http, and a host whose address is not public) and --well-known-resolve (the
// host's address, as curl's --resolve), since a domain root names a host with no port. The edges reach the same stub
// as the domain 127.0.0.1:<port>, as in scenarios 2 and 14. The relay caches acme's record for a second at most
// (--well-known-cache-max 1), so each step after the first reads it again. acme's first records live a second, so bob's
// edge reads the rotation of (b); the rotated record lives an hour, so it is still valid at (c), where the pin it
// carries must stay current through a bare rotation.
const ACME = 'acme.e2e.test'
const PRIVATE = 'private.e2e.test'

describe('e2e scenario 19: trust at the relay by domain', () => {
  it("(19) bob's accept-from names only domain:acme.e2e.test: (a) a session under acme's first key k1 is delivered and bob accepts it; (a2) once acme's record revokes alice, the relay refuses 403 revoked; (b) after a rotation to k2 countersigned by k1 a session under k2 is delivered with no republish of bob's accept-from, and the relay logs the rotation; (c) after a bare rotation to k3 the relay logs pin-mismatch and keeps k2: a session under k2 is still delivered, and one under k3 is refused 403 root-not-accepted; (d) a domain root that is an IP literal is 400 bad-record; (e) a relay without the test-only http flag refuses the loopback host before connecting, 503 resolve-failed, logging non-public-address", async () => {
    const site = await wellKnownFirst()
    const relayArgs = [
      '--bind',
      '127.0.0.1',
      '--well-known-insecure-http',
      '--well-known-cache-max',
      '1',
      '--well-known-resolve',
      `${ACME}=${site.domain}`,
    ]
    const w = await withSpawnedRelays(() => world('s19', { relayArgs }))
    const k1 = party('acme-1')
    const k2 = party('acme-2')
    const k3 = party('acme-3')
    const alice = party('alice')
    const bob = party('bob')
    const t = now()
    const b = w.node('bob', { keys: bob.keys, roots: [{ domain: site.domain }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    const accept = acceptFrom(bob, [`domain:${ACME}`])
    await b.edge.publishRecord(accept)
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    // Each session is a new key in a state directory of its own: the edge's writer lock refuses a second edge on
    // a directory an open edge holds, and five of these sessions share a root.
    let sessions = 0
    const sessionUnder = (root: Party, at = w.url): Node => {
      const s = party(`session-of-${root.name}-${++sessions}`)
      const auth = [
        signHop(root.signing, alice.address, [], t + 3600),
        signHop(alice.signing, s.address, [], t + 3600),
      ]
      return at === w.url
        ? w.node(s.name, { keys: s.keys, auth })
        : nodeAt(w, s.name, at, { keys: s.keys, auth })
    }
    const org = (p: Party, revoked: string[] = [], rotatedFrom: string | null = null, ttl = 1) =>
      addressRecord(p, { relays: [w.url], sealing: false, ttl, revoked, rotatedFrom })
    const afterCaches = (): Promise<void> => untilSecond(now() + 2)
    const outcome = async (s: Node, n: number) => {
      const sent = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { n } })
      return sent.targets.map((x) => [x.state, x.reason])
    }

    // (a) First contact: the relay resolves acme, pins k1 and delivers; bob's edge accepts under k1.
    site.serve(() => serializeRecord(org(k1)))
    expect(await outcome(sessionUnder(k1), 1)).toEqual([['published', null]])
    await until('the first message at bob', () => b.received.length === 1)

    // (a2) acme's record now revokes alice, the principal of the chain: the relay refuses it.
    await afterCaches()
    site.serve(() => serializeRecord(org(k1, [alice.address])))
    expect(await outcome(sessionUnder(k1), 2)).toEqual([['failed', 'revoked']])

    // (b) A rotation countersigned by k1, valid for an hour: delivered under k2, bob's accept-from untouched.
    await afterCaches()
    site.serve(() => serializeRecord(countersignRotation(k1.signing, org(k2, [], k1.address, 3600))))
    expect(await outcome(sessionUnder(k2), 3)).toEqual([['published', null]])
    await until('the rotated message at bob', () => b.received.length === 2)
    expect(b.received.map((m) => [m.root, m.body])).toEqual([
      [k1.address, { n: 1 }],
      [k2.address, { n: 3 }],
    ])
    const held = await fetch(`${w.url}/v0/fetch/record/${bob.address}/accept-from`)
    expect(new Uint8Array(await held.arrayBuffer())).toEqual(serializeRecord(accept))

    // (c) A bare rotation to k3: the pin stays at k2, whose record is still valid; k3 is refused, k2 still delivered.
    await afterCaches()
    site.serve(() => serializeRecord(org(k3, [], k2.address)))
    expect(await outcome(sessionUnder(k3), 4)).toEqual([['failed', 'root-not-accepted']])
    expect(await outcome(sessionUnder(k2), 5)).toEqual([['published', null]])
    await until('the message under the kept key at bob', () => b.received.length === 3)
    expect(b.received.map((m) => [m.root, m.body])[2]).toEqual([k2.address, { n: 5 }])

    // (d) An IP literal is no domain root: the relay refuses the record's form.
    const literal = {
      ...(JSON.parse(new TextDecoder().decode(serializeRecord(accept))) as object),
      roots: ['domain:127.0.0.1'],
    }
    expect(await rawPublish(w.url, utf8(JSON.stringify(literal)))).toMatchObject({
      status: 400,
      body: { error: 'bad-record' },
    })

    // (e) Without --well-known-insecure-http the guard refuses the host: its only address is loopback.
    const guarded = await extraRelay(w, 'guarded', [
      '--bind',
      '127.0.0.1',
      '--well-known-resolve',
      `${PRIVATE}=${site.domain}`,
    ])
    const carol = party('carol')
    expect(
      (await rawPublish(guarded.url, serializeRecord(addressRecord(carol, { relays: [guarded.url] }))))
        .status,
    ).toBe(200)
    expect(
      (await rawPublish(guarded.url, serializeRecord(acceptFrom(carol, [`domain:${PRIVATE}`])))).status,
    ).toBe(200)
    const asked = site.requests()
    const toCarol = await sessionUnder(k2, guarded.url).edge.send({
      to: [carol.address],
      type: 'chat.v1',
      body: {},
    })
    expect(toCarol.targets.map((x) => [x.state, x.reason])).toEqual([['retry', 'resolve-failed']])
    expect(site.requests()).toBe(asked)

    const events = relayEvents(w.relay)
    const resolved = events.filter((e) => e.event === 'well-known').map((e) => [e.domain, e.outcome, e.key])
    expect(resolved).toEqual([
      [ACME, 'pinned', k1.address],
      [ACME, 'refreshed', k1.address],
      [ACME, 'rotated', k2.address],
    ])
    expect(events.find((e) => e.outcome === 'rotated')?.from).toBe(k1.address)
    const refused = events.filter((e) => e.event === 'well-known-refused')
    expect(refused).toMatchObject([
      {
        domain: ACME,
        reason: 'pin-mismatch',
        pinned: k2.address,
        offered: k3.address,
        check: 'bad-rotation',
        kept: k2.address,
      },
    ])
    expect(typeof refused[0]?.valid_until).toBe('number')
    expect(events.filter((e) => e.event === 'publish-record' && e.kind === 'accept-from')).toHaveLength(1)
    expect(events.find((e) => e.event === 'well-known-insecure-http')).toBeDefined()
    const guard = relayEvents(guarded).filter((e) => e.event === 'well-known-refused')
    expect(guard).toMatchObject([
      { domain: PRIVATE, reason: 'non-public-address', address: '127.0.0.1', category: 'loopback' },
    ])
    expect(guard[0]?.kept).toBeUndefined()
    expect(b.errors).toEqual([])
  })
})
