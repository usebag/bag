import { countersignRotation, serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  type Party,
  party,
  type RelayHandle,
  wellKnownFirst,
} from '../harness.ts'
import { envelope, events, httpStub, post, publishRecords, spawnRelay } from './support.ts'

const WELL_KNOWN = '/.well-known/bag/address.json'

/** A loopback well-known stub that answers 404 and counts every GET (unlike wellKnownFirst, which counts only 200s). */
async function deadHost(): Promise<{ readonly origin: string; requests(path?: string): number }> {
  return httpStub((_req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not-found"}')
  })
}

// R1, R2, R3: the relay's first-contact fetch fan-out and its per-domain refresh limiter,
// through the release ac-relay on 127.0.0.1 (AC_RELAY_CMD). Every `domain:` root is a loopback stub reached only
// through the loopback-gated --well-known-insecure-http (resolver.rs:167, any_address = insecure_http, which skips
// the non-public guard at resolver.rs:184); nothing opens a connection off this Mac. The mechanisms:
//  - a single publish resolves EVERY uncached `domain:` root its recipients name, each once, serially, with no
//    per-publish cap (policy.rs:75-87 publish_resolving loops pending.domains(), policy.rs:131-134, the uncached path
//    ungated at resolver.rs:348-353; an accept-from may name up to MAX_ROOTS = 1024 roots, records.rs:35);
//  - a failed fetch is remembered FAILURE_TTL = 60 s (resolver.rs:40, resolver.rs:394), so a burst re-fetches once;
//  - a cached-but-mismatched domain re-fetches once per REFRESH_EVERY = 60 s PER DOMAIN, with no global budget
//    (resolver.rs:44, refresh_due resolver.rs:272-281).

/** An org's address record: no sealing key, valid an hour. */
const org = (p: Party, url: string, o: { rotatedFrom?: string | null } = {}) =>
  addressRecord(p, { relays: [url], sealing: false, ttl: 3600, rotatedFrom: o.rotatedFrom ?? null })

/** An envelope from `sender` to `to` under a one-hop chain rooted at `root`. */
const under = (root: Party, sender: Party, to: readonly Party[]) =>
  envelope(sender, to, { auth: [signHop(root.signing, sender.address, [], now() + 3600)] })

/** A mailbox at the relay whose accept-from names `roots`. */
async function mailbox(relay: RelayHandle, name: string, roots: readonly string[]): Promise<Party> {
  const p = party(name)
  expect(
    await publishRecords(relay.url, [addressRecord(p, { relays: [relay.url] }), acceptFrom(p, roots)]),
  ).toEqual([200, 200])
  return p
}

/** A raw POST to /v0/publish with a generous timeout: the single R2 publish does N serial GETs. */
async function publishLong(
  url: string,
  bytes: Uint8Array,
  ms: number,
): Promise<{ readonly status: number; readonly body: unknown; readonly retryAfter: string | null }> {
  const res = await fetch(`${url}/v0/publish`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: bytes,
    signal: AbortSignal.timeout(ms),
  })
  const text = await res.text()
  let body: unknown = text
  try {
    body = JSON.parse(text)
  } catch {
    // not JSON: kept as text
  }
  return { status: res.status, body, retryAfter: res.headers.get('retry-after') }
}

const wellKnownEvents = (relay: RelayHandle, domain: string) =>
  events(relay).filter((e) => e.event === 'well-known' && e.domain === domain)

describe('R1: a burst under unknown roots contacts a dead well-known host once (failure remembered 60 s)', () => {
  it('R1 [--well-known-insecure-http] V1: a live first contact resolves, pins and delivers in one GET; then 50 publishes under an unknown root to a mailbox naming one dead host: 50x503 resolve-failed, the dead host contacted once', async () => {
    const live = await wellKnownFirst()
    const dead = await deadHost()
    const relay = await spawnRelay('r1', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '2',
      '--well-known-resolve',
      `live.e2e.test=${live.domain}`,
      '--well-known-resolve',
      `dead.e2e.test=${dead.origin}`,
    ])
    const alice = party('alice')

    // V1 control: a legitimate first contact resolves and pins; the count goes up by exactly 1 and it delivers.
    const kLive = party('k-live')
    const bobLive = await mailbox(relay, 'bob-live', ['domain:live.e2e.test'])
    live.serve(() => serializeRecord(org(kLive, relay.url)))
    expect(await post(relay.url, under(kLive, alice, [bobLive]).bytes)).toMatchObject({
      status: 200,
      body: { ok: true, duplicate: false, delivered: 1 },
    })
    expect(live.requests(), 'one GET pins the live host').toBe(1)
    expect(wellKnownEvents(relay, 'live.e2e.test')).toMatchObject([{ outcome: 'pinned', key: kLive.address }])
    // A second publish under the pinned key is served from the cache: still one GET.
    expect(await post(relay.url, under(kLive, alice, [bobLive]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(live.requests(), 'the pin answers from cache, no second GET').toBe(1)

    // R1 attack: a dead host (404) and 50 publishes under an unknown root; the failure is remembered 60 s.
    const unknown = party('r1-unknown')
    const bobDead = await mailbox(relay, 'bob-dead', ['domain:dead.e2e.test'])
    const burst = Array.from({ length: 50 }, () => under(unknown, alice, [bobDead]).bytes)
    const t = performance.now()
    const answers = await Promise.all(burst.map((b) => post(relay.url, b)))
    const ms = Math.round(performance.now() - t)
    for (const a of answers) {
      expect(a).toEqual({ status: 503, body: { error: 'resolve-failed' }, retryAfter: '60' })
    }
    console.log(`R1 measure: 50 publishes under an unknown root -> ${dead.requests()} GET(s) in ${ms} ms`)
    expect(dead.requests(), 'the dead host is contacted once; the failure is then remembered').toBe(1)
  })
})

describe('R2 (fixed): one publish resolves at most the per-publish cap, not every uncached domain:root', () => {
  // THE CANDIDATE, now FIXED. One publish, to a recipient whose accept-from lists N distinct uncached
  // `domain:` roots under a chain rooted at an unknown key. publish_resolving (policy.rs) iterates pending.domains();
  // before the fix it resolved EACH serially with no bound (up to N = 1024 outbound GETs from one publish, the
  // amplifier, measured 1024 on 2026-10-26). The fix (merged 2026-10-26)
  // caps per-publish network resolutions at CAP, so one publish now resolves at most CAP
  // uncached domains and leaves the rest unresolved. All N domains point at ONE loopback stub, so no external
  // connection is opened and the stub counts the fan-out. Measured against the fix: CAP outbound GETs, answer 503.
  it('R2 [--well-known-insecure-http] one publish to a recipient whose accept-from names 1024 distinct dead domains resolves at most the per-publish cap of 8 (fixed), then 503 resolve-failed', async () => {
    const N = 1024 // MAX_ROOTS (records.rs:35): the most an accept-from may name; the cap must hold even at this many
    const CAP = 8 // the per-publish resolution cap: at most CAP resolutions per publish
    const stub = await deadHost() // every domain is a 404; the stub counts every GET, which is the fan-out
    const resolves = Array.from({ length: N }, (_, i) => [
      '--well-known-resolve',
      `d${i}.e2e.test=${stub.origin}`,
    ]).flat()
    const relay = await spawnRelay('r2', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '2',
      ...resolves,
    ])
    const alice = party('alice')
    const unknown = party('r2-unknown') // a root no domain pins, so every domain must be resolved
    const roots = Array.from({ length: N }, (_, i) => `domain:d${i}.e2e.test`)
    const victim = await mailbox(relay, 'victim', roots)

    const t = performance.now()
    const answer = await publishLong(relay.url, under(unknown, alice, [victim]).bytes, 120_000)
    const ms = Math.round(performance.now() - t)
    const fanout = stub.requests(WELL_KNOWN)
    console.log(
      `R2 measure (fixed, cap ${CAP}): one publish, ${N} distinct domain roots -> ${fanout} outbound GET(s) in ${ms} ms; answer ${answer.status} ${JSON.stringify(answer.body)}`,
    )
    // The fix: one request in, at most CAP outbound GETs out, even though the accept-from names N = 1024 domains.
    expect(fanout, 'the per-publish resolution cap holds the fan-out').toBe(CAP)
    // The whole envelope is unresolvable (every root is a dead domain, no co-delivered recipient): 503.
    expect(answer).toEqual({ status: 503, body: { error: 'resolve-failed' }, retryAfter: '60' })
  })
})

describe('R3 (measure): two distinct cached-but-mismatched domains both refresh within one minute', () => {
  // The refresh limiter is keyed per domain only (refresh_due, resolver.rs:272-281): N domains cost N GET/min, with
  // no global budget. Two domains, each pinned, each sent a chain under a key that mismatches the pin while a
  // legitimate rotation is served: each refreshes once in the same minute, so both rotations take effect at once.
  it('R3 [--well-known-insecure-http] two pinned domains each take a countersigned rotation in the same minute (one refresh GET each, no global budget), each delivered', async () => {
    const a = await wellKnownFirst()
    const b = await wellKnownFirst()
    const relay = await spawnRelay('r3', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '2',
      '--well-known-resolve',
      `a.e2e.test=${a.domain}`,
      '--well-known-resolve',
      `b.e2e.test=${b.domain}`,
    ])
    const alice = party('alice')
    const [a1, a2, b1, b2] = ['a1', 'a2', 'b1', 'b2'].map((n) => party(n)) as [Party, Party, Party, Party]
    const bobA = await mailbox(relay, 'bob-a', ['domain:a.e2e.test'])
    const bobB = await mailbox(relay, 'bob-b', ['domain:b.e2e.test'])
    const delivered = { status: 200, body: { ok: true, duplicate: false, delivered: 1 } }

    // First contact pins each domain's first key (one GET each).
    a.serve(() => serializeRecord(org(a1, relay.url)))
    b.serve(() => serializeRecord(org(b1, relay.url)))
    expect(await post(relay.url, under(a1, alice, [bobA]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(b1, alice, [bobB]).bytes)).toMatchObject(delivered)
    expect([a.requests(), b.requests()]).toEqual([1, 1])

    // Both domains now serve a rotation countersigned by their pinned key.
    a.serve(() =>
      serializeRecord(countersignRotation(a1.signing, org(a2, relay.url, { rotatedFrom: a1.address }))),
    )
    b.serve(() =>
      serializeRecord(countersignRotation(b1.signing, org(b2, relay.url, { rotatedFrom: b1.address }))),
    )

    // A chain under each new key mismatches its pin: each domain refreshes once, in the same minute, and delivers.
    expect(await post(relay.url, under(a2, alice, [bobA]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(b2, alice, [bobB]).bytes)).toMatchObject(delivered)
    console.log(
      `R3 measure: a asked ${a.requests()} times, b asked ${b.requests()} times (pin + one refresh each)`,
    )
    expect([a.requests(), b.requests()], 'both refreshed in one minute, no global budget').toEqual([2, 2])
    expect(wellKnownEvents(relay, 'a.e2e.test').map((e) => [e.outcome, e.key])).toEqual([
      ['pinned', a1.address],
      ['rotated', a2.address],
    ])
    expect(wellKnownEvents(relay, 'b.e2e.test').map((e) => [e.outcome, e.key])).toEqual([
      ['pinned', b1.address],
      ['rotated', b2.address],
    ])
  })
})
