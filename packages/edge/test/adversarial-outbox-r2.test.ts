import { parseEnvelope } from '@usebag/core'
import { describe, expect, it, onTestFinished } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { UNREACHABLE } from '../src/outbox.ts'
import type { OutboxTarget } from '../src/ports.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { closedPort, json, startHttp } from './support/http.ts'

// The outbox's `unreachable` through the real HTTP adapter (createRelayClient) on
// 127.0.0.1 only: closed ports that refuse every connection, and a loopback stub that answers 403. With the CLI's
// unreachableReason on, each unanswered try is `retry` with reason `unreachable` (sender.ts line 199), retried to the
// horizon ts + TTL, where the target fails `publish-failed` (outbox.ts line 88); a 403 keeps its code at once
// (sender.ts lines 194 and 197; outbox.ts line 87); and every audit line of an unanswered try keeps `publish-failed` as
// its reason with `cause: unreachable` in its detail (sender.ts lines 211 and 217). Both relays are the edge's own, so
// the private-address guard allows them (net.ts line 136); the clock is the fake one, so the week-long horizon passes
// in a loop of flushes.

const WEEK = 604_800

/** Carol's edge, whose own relays are `urls`, where bob's record (at the first) names them all. */
function carol(urls: readonly string[]) {
  const records = new FakeRecords()
  records.put(urls[0] as string, addressRecord(P.bob, { relays: urls }))
  const clock = new FakeClock()
  const audit = new MemoryAuditSink()
  const store = new SqliteStore(':memory:')
  onTestFinished(() => store.close())
  const edge = new Edge({
    keys: P.carol.keys,
    store,
    relays: { client: createRelayClient({ maxReconnects: 0 }), urls },
    records,
    policy: { roots: [], types: [] },
    clock,
    rng: seededRng('adversarial-outbox-r2'),
    audit,
    lookup: PUBLIC_LOOKUP,
    unreachableReason: true,
  })
  return { edge, clock, audit }
}

/** The publish and rate-limit audit lines of one relay: "event decision reason" and the parsed detail. */
function publishLines(audit: MemoryAuditSink, relay: string): [string, Record<string, unknown>][] {
  return audit.lines
    .map((l) => JSON.parse(l) as Record<string, string>)
    .filter((v) => v.event === 'publish' || v.event === 'rate-limit')
    .map(
      (v) =>
        [`${v.event} ${v.decision} ${v.reason}`, JSON.parse(v.detail as string)] as [
          string,
          Record<string, unknown>,
        ],
    )
    .filter(([, d]) => d.relay === relay)
}

describe('a send no relay answers, a 403, and the audit line of an unreachable try', () => {
  it('V1: the lawful send to a relay that answers is published at once', async () => {
    const stub = await startHttp()
    onTestFinished(() => stub.close())
    stub.handle = (req, res) =>
      json(res, 200, { ok: true, id: parseEnvelope(req.body).id, duplicate: false, delivered: 1 })
    const { edge } = carol([stub.url])
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 0 } })
    expect(sent.targets.map((t) => [t.state, t.tries, t.reason])).toEqual([['published', 1, null]])
  })

  it('every target relay a closed port: each try retry unreachable, publish-failed at the horizon; retry lines unreachable, the give-up publish-failed, cause unreachable throughout', async () => {
    const urls = [`http://127.0.0.1:${await closedPort()}`, `http://127.0.0.1:${await closedPort()}`]
    expect(urls[0]).not.toBe(urls[1])
    const { edge, clock, audit } = carol(urls)
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 1 } })
    // The edge returns a send's targets ordered by relay URL (the store's ORDER BY relay, sqlite-store.ts line 182;
    // sender.ts line 205 keeps that order), not in the order the relays were given: closedPort() hands out random
    // ports, so the call order of the two URLs is not their sorted order. Both sides are therefore sorted by URL, every
    // field of every entry kept, and the edge's order is its own claim, asserted beside.
    const byUrl = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)
    const sortedUrls = [...urls].sort(byUrl)
    expect(sent.targets.map((t) => t.relay)).toEqual(sortedUrls)
    expect(
      [...sent.targets]
        .sort((a, b) => byUrl(a.relay, b.relay))
        .map((t) => [t.relay, t.state, t.tries, t.reason, t.nextAt]),
    ).toEqual(sortedUrls.map((u) => [u, 'retry', 1, UNREACHABLE, T0 + 1]))
    const reasons = new Set<string | null>()
    let flushes = 0
    for (;;) {
      const live = edge.status(sent.id).filter((t) => t.state === 'retry')
      if (live.length === 0) break
      for (const t of live) reasons.add(t.reason)
      clock.t = Math.min(...live.map((t) => t.nextAt as number))
      await edge.flush()
      flushes++
    }
    const final = edge.status(sent.id)
    expect([...reasons]).toEqual([UNREACHABLE])
    expect(final.map((t) => [t.state, t.reason, t.nextAt, t.updatedAt])).toEqual(
      urls.map(() => ['failed', 'publish-failed', null, T0 + WEEK]),
    )
    const tries = final.map((t) => t.tries)
    for (const url of urls) {
      const lines = publishLines(audit, url)
      const t = final.find((x) => x.relay === url) as OutboxTarget
      expect(lines).toHaveLength(t.tries)
      // Every retry line of an unanswered try: reason unreachable (a code of Appendix A), status 0, cause unreachable;
      // the horizon give-up line keeps publish-failed.
      expect(new Set(lines.map(([s]) => s))).toEqual(
        new Set(['publish retry unreachable', 'publish reject publish-failed']), // retries read unreachable; the horizon give-up keeps publish-failed
      )
      expect(lines.at(-1)?.[0]).toBe('publish reject publish-failed')
      expect(lines.every(([, d]) => d.status === 0 && d.cause === UNREACHABLE)).toBe(true)
    }
    console.log(
      `MEASURE E4 (no answer): 2 closed ports -> retry unreachable at ts + 1; ${tries.join(' and ')} tries in ${flushes} flushes; both failed publish-failed at ts + ${WEEK}; retry lines unreachable and the give-up publish-failed, status 0, cause unreachable`,
    )
  })

  it('a relay that answers 403 keeps its code at once, beside an unanswered one that retries unreachable', async () => {
    const stub = await startHttp()
    onTestFinished(() => stub.close())
    stub.handle = (_req, res) => json(res, 403, { error: 'root-not-accepted' })
    const down = `http://127.0.0.1:${await closedPort()}`
    const { edge, audit } = carol([stub.url, down])
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 2 } })
    const byRelay = new Map(sent.targets.map((t) => [t.relay, t]))
    expect(byRelay.get(stub.url)).toMatchObject({
      state: 'failed',
      tries: 1,
      reason: 'root-not-accepted',
      nextAt: null,
    })
    expect(byRelay.get(down)).toMatchObject({ state: 'retry', tries: 1, reason: UNREACHABLE, nextAt: T0 + 1 })
    expect(stub.seen.filter((s) => s.method === 'POST' && s.url === '/v0/publish')).toHaveLength(1)
    expect(publishLines(audit, stub.url)).toEqual([
      ['publish reject root-not-accepted', { relay: stub.url, tries: 1, status: 403, next_at: null }],
    ])
    expect(publishLines(audit, down)).toEqual([
      [
        'publish retry unreachable',
        { relay: down, tries: 1, status: 0, next_at: T0 + 1, cause: UNREACHABLE },
      ],
    ])
    console.log(
      'MEASURE E4 (403): 403 root-not-accepted -> failed at once, 1 try, its code kept; the closed port beside it -> retry unreachable',
    )
  })
})
