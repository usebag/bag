import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  type BuiltEnvelope,
  buildEnvelope,
  countersignRotation,
  newThread,
  serializeRecord,
  signHop,
} from '@usebag/core'
import { coreRng, systemRng } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  type Party,
  party,
  rawPublish,
  relayEvents,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 32 (spec/SPEC.md §12.2, §8.8 item 1): the
// release relay's domain-root resolution through an org's _bag TXT record. The TXT records are the test-only --dns-resolve's (no DNS server is asked), the record hosts reach a
// node:http server of this scenario on 127.0.0.1 through --well-known-resolve and --well-known-insecure-http, so
// nothing leaves the Mac. (a) acme's TXT names k1 and host=bag: the relay reads the record at the origin
// bag.acme, pins k1 and delivers; (b) umbrella's TXT names k2 while k3's record is served: 503 resolve-failed,
// txt-key-mismatch, nothing pinned; (c) globex has no TXT: the well-known URL, as before; (d) initech's TXT gives a
// field twice: 503 resolve-failed, txt-malformed, nothing fetched; (e) hooli's TXT still names h10 and the record is
// h11, countersigned by h10: h11 pinned at first contact and delivered; then h11's record countersigned by
// another key is refused txt-key-mismatch at the refresh a chain under h10 asks for, and the pin stays h11.

const DOMAINS = ['acme', 'umbrella', 'globex', 'initech', 'hooli'].map((d) => `${d}.e2e.test`)
const [ACME, UMBRELLA, GLOBEX, INITECH, HOOLI] = DOMAINS as [string, string, string, string, string]
const BAG = `bag.${ACME}`
const WELL_KNOWN = '/.well-known/bag/address.json'

/** A node:http server that answers each `host path` it was given, and 404 otherwise, and counts each request. */
async function recordHost(): Promise<{
  readonly at: string
  serve(host: string, path: string, bytes: Uint8Array): void
  asked(): readonly string[]
}> {
  const served = new Map<string, Uint8Array>()
  const asked: string[] = []
  const server = createServer((req, res) => {
    const key = `${String(req.headers.host)} ${req.url}`
    asked.push(key)
    const body = served.get(key)
    if (body === undefined) res.writeHead(404).end()
    else res.writeHead(200, { 'content-type': 'application/json' }).end(body)
  })
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  onTestFinished(
    () =>
      new Promise<void>((done) => {
        server.closeAllConnections()
        server.close(() => done())
      }),
  )
  return {
    at: `127.0.0.1:${(server.address() as AddressInfo).port}`,
    serve: (host, path, bytes) => served.set(`${host} ${path}`, bytes),
    asked: () => asked,
  }
}

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

describe('e2e scenario 32: discovery by DNS TXT at the relay', () => {
  it("(32) acme's TXT names host=bag and k1 is pinned from that origin and delivered; umbrella's TXT key differs from the served record: 503 txt-key-mismatch, nothing pinned; globex has no TXT: the well-known URL; initech's TXT names a field twice: 503 txt-malformed, nothing fetched; hooli's TXT names h10 and h11 countersigned by h10 is pinned and delivered, and h11 countersigned by another key is refused with the pin kept", async () => {
    const site = await recordHost()
    const [k1, k2, k3, g1, i1, h10, h11, alice] = ['k1', 'k2', 'k3', 'g1', 'i1', 'h10', 'h11', 'alice'].map(
      (n) => party(n),
    ) as [Party, Party, Party, Party, Party, Party, Party, Party]
    const txt = (domain: string, text: string) => ['--dns-resolve', `_bag.${domain}=${text}`]
    const relayArgs = [
      '--bind',
      '127.0.0.1',
      '--well-known-insecure-http',
      ...[...DOMAINS, BAG].flatMap((h) => ['--well-known-resolve', `${h}=${site.at}`]),
      ...txt(ACME, `"v=ac1; key=${k1.address};" " host=bag"`),
      ...txt(UMBRELLA, `"v=ac1; key=${k2.address}"`),
      ...txt(INITECH, `"v=ac1; key=${i1.address}; key=${i1.address}"`),
      ...txt(GLOBEX, '"v=spf1 -all"'),
      ...txt(HOOLI, `"v=ac1; key=${h10.address}"`),
    ]
    const w = await withSpawnedRelays(() => world('s32', { relayArgs }))
    const org = (p: Party) => serializeRecord(addressRecord(p, { relays: [w.url], sealing: false }))
    /** p's record naming `from` in rotated_from, countersigned by `by`. */
    const rotated = (p: Party, from: Party, by: Party) =>
      serializeRecord(
        countersignRotation(
          by.signing,
          addressRecord(p, { relays: [w.url], sealing: false, rotatedFrom: from.address }),
        ),
      )
    site.serve(BAG, WELL_KNOWN, org(k1))
    site.serve(UMBRELLA, WELL_KNOWN, org(k3))
    site.serve(GLOBEX, WELL_KNOWN, org(g1))
    site.serve(INITECH, WELL_KNOWN, org(i1))
    site.serve(HOOLI, WELL_KNOWN, rotated(h11, h10, h10))
    // One mailbox per domain, each trusting only that domain.
    const mailboxes = DOMAINS.map((d) => [d, party(`at-${d}`)] as const)
    for (const [d, p] of mailboxes) {
      for (const r of [addressRecord(p, { relays: [w.url] }), acceptFrom(p, [`domain:${d}`])])
        expect((await rawPublish(w.url, serializeRecord(r))).status).toBe(200)
    }
    const box = (d: string): Party => (mailboxes.find(([x]) => x === d) as readonly [string, Party])[1]
    const delivered = { status: 200, body: { ok: true, duplicate: false, delivered: 1 } }
    const refused = { status: 503, body: { error: 'resolve-failed' }, retryAfter: '60' }
    const events = () => relayEvents(w.relay)
    const lines = (event: string, domain: string) =>
      events().filter((e) => e.event === event && e.domain === domain)

    // (a) acme: the origin bag.acme that the TXT names, k1 pinned, delivered; the apex never asked.
    expect(await rawPublish(w.url, under(k1, alice, [box(ACME)]).bytes)).toMatchObject(delivered)
    expect(lines('txt', ACME).map((e) => [e.source, e.records, e.ok])).toEqual([['fixed', 1, true]])
    expect(lines('well-known', ACME).map((e) => [e.outcome, e.key, e.source, e.url])).toEqual([
      ['pinned', k1.address, 'txt', `https://${BAG}${WELL_KNOWN}`],
    ])
    expect(site.asked().filter((a) => a.includes(ACME))).toEqual([`${BAG} ${WELL_KNOWN}`])

    // (b) umbrella: the TXT names k2, k3's record is served: refused before any pin.
    expect(await rawPublish(w.url, under(k3, alice, [box(UMBRELLA)]).bytes)).toEqual(refused)
    expect(lines('well-known-refused', UMBRELLA).map((e) => [e.reason, e.txt, e.offered])).toEqual([
      ['txt-key-mismatch', k2.address, k3.address],
    ])
    expect(lines('well-known', UMBRELLA)).toEqual([])

    // (c) globex: only a TXT record that is not ours, so the well-known URL, as before.
    expect(await rawPublish(w.url, under(g1, alice, [box(GLOBEX)]).bytes)).toMatchObject(delivered)
    expect(lines('well-known', GLOBEX).map((e) => [e.outcome, e.source, e.url])).toEqual([
      ['pinned', 'well-known', `https://${GLOBEX}${WELL_KNOWN}`],
    ])

    // (d) initech: a field given twice: refused, and the record host never asked.
    expect(await rawPublish(w.url, under(i1, alice, [box(INITECH)]).bytes)).toEqual(refused)
    expect(lines('well-known-refused', INITECH).map((e) => e.reason)).toEqual(['txt-malformed'])
    expect(site.asked().filter((a) => a.includes(INITECH))).toEqual([])

    // (e) hooli: the TXT still names h10 and h11's record is countersigned by h10: h11 pinned, delivered.
    expect(await rawPublish(w.url, under(h11, alice, [box(HOOLI)]).bytes)).toMatchObject(delivered)
    expect(lines('well-known', HOOLI).map((e) => [e.outcome, e.key, e.source])).toEqual([
      ['pinned', h11.address, 'txt'],
    ])
    // Then h11's record countersigned by another key: a chain under h10 makes the relay read it again, the
    // record is refused before the pin is read, the pin stays h11, and h10 is not admitted.
    site.serve(HOOLI, WELL_KNOWN, rotated(h11, h10, k3))
    expect(await rawPublish(w.url, under(h10, alice, [box(HOOLI)]).bytes)).toMatchObject({
      status: 403,
      body: { error: 'root-not-accepted' },
    })
    expect(lines('well-known-refused', HOOLI).map((e) => [e.reason, e.txt, e.offered, e.kept])).toEqual([
      ['txt-key-mismatch', h10.address, h11.address, h11.address],
    ])
    expect(lines('well-known', HOOLI)).toHaveLength(1)
    const listening = events().find((e) => e.event === 'listening')
    expect(listening?.txt).toBe('fixed')
    console.log(`(32) measure: the record host was asked ${JSON.stringify(site.asked())}`)
  })
})
