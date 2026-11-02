import { type AcceptFromRecord, serializeRecord, signRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, now, type Party, party, until } from '../harness.ts'
import { envelope, events, httpStub, post, publishRecords, spawnRelay } from './support.ts'

// P1-P3: per-recipient pending rows under a flood (policy.rs:226-246, 422,
// store/sqlite.rs:79-81, 287, 377, 398-400). The release ac-relay on 127.0.0.1 from AC_RELAY_CMD. A "dead" domain is
// a loopback httpStub that answers 404, reached only through --well-known-insecure-http --well-known-resolve, so no
// resolution ever leaves this Mac. A recipient whose accept-from names that domain cannot resolve, so an
// envelope co-delivered to a live mailbox leaves it one pending row.

/** A dead `domain:` root: a loopback stub that answers 404 at the well-known path, and the relay flags to reach it. */
async function deadDomain(): Promise<{ readonly host: string; readonly args: string[]; requests(): number }> {
  const stub = await httpStub((_req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not-found"}')
  })
  const host = 'dead.test'
  return {
    host,
    args: ['--well-known-insecure-http', '--well-known-resolve', `${host}=${stub.origin}`],
    requests: stub.requests,
  }
}

/** An accept-from record signed at an explicit `iat`, so a newer one can replace it (P3). */
function acceptFromAt(p: Party, roots: readonly string[], iat: number): AcceptFromRecord {
  return signRecord(p.signing, {
    kind: 'accept-from',
    owner: p.address,
    roots,
    max_bytes: 65_536,
    ttl: 86_400,
    iat,
  })
}

describe('P: pending rows under a flood (policy.rs:226-246, 422)', () => {
  it('P1 (measure) a flood of envelopes each to one deliverable recipient and one at an unresolvable domain leaves one pending row apiece, with no per-client or per-mailbox count cap', async () => {
    const dead = await deadDomain()
    const relay = await spawnRelay('p1', dead.args)
    const alice = party('alice')
    const bob = party('bob')
    const dom = party('dom')
    expect(
      await publishRecords(relay.url, [acceptFrom(bob, ['*']), acceptFrom(dom, [`domain:${dead.host}`])]),
    ).toEqual([200, 200])
    const N = 25
    let delivered = 0
    for (let i = 0; i < N; i++) {
      const r = await post(relay.url, envelope(alice, [bob, dom]).bytes)
      expect(r.status, JSON.stringify(r.body)).toBe(200)
      delivered += (r.body as { delivered?: number }).delivered ?? 0
    }
    await until(
      `${N} pending rows`,
      () => events(relay).filter((e) => e.event === 'pending').length === N,
      20_000,
    )
    const pend = events(relay).filter((e) => e.event === 'pending')
    const ttl = (pend[0]?.until as number) - now()
    console.log(
      `P1 measure: ${N} envelopes -> ${pend.length} pending rows (one each), ${delivered} live deliveries; ` +
        `row TTL ~${ttl}s (~7 days); ${dead.requests()} outbound GET(s) (a remembered failure gates the rest); ` +
        'nothing but the rate limit caps live pending rows (store/sqlite.rs:287,377).',
    )
    expect(pend.length).toBe(N) // V1: each envelope delivered to bob and left dom pending; no count cap fired.
    expect(delivered).toBe(N)
  })

  it('P2 an all-unresolvable envelope (no co-delivered recipient) is 503 resolve-failed with Retry-After 60 and stores nothing (policy.rs:237-238)', async () => {
    const dead = await deadDomain()
    const relay = await spawnRelay('p2', dead.args)
    const alice = party('alice')
    const bob = party('bob')
    const dom = party('dom')
    expect(
      await publishRecords(relay.url, [acceptFrom(bob, ['*']), acceptFrom(dom, [`domain:${dead.host}`])]),
    ).toEqual([200, 200])
    // V1: a lawful delivery to the live mailbox is accepted.
    const ok = await post(relay.url, envelope(alice, [bob]).bytes)
    expect(ok.status).toBe(200)
    expect((ok.body as { delivered?: number }).delivered).toBe(1)
    // The attack: the only recipient's root is the dead domain.
    const r = await post(relay.url, envelope(alice, [dom]).bytes)
    console.log(
      `P2 measure: all-unresolvable -> ${r.status} ${JSON.stringify(r.body)} retry-after=${r.retryAfter}`,
    )
    expect(r.status).toBe(503)
    expect(r.body).toEqual({ error: 'resolve-failed' })
    expect(r.retryAfter).toBe('60')
    // Nothing was stored: no pending row for dom.
    expect(events(relay).filter((e) => e.event === 'pending' && e.mailbox === dom.address)).toHaveLength(0)
  })

  it('P3 with 257 pending rows that become resolvable at once, a sweep retries 256 and the 257th waits for the next sweep (policy.rs:422, store/sqlite.rs:398-400); a delay, not a loss', async () => {
    const dead = await deadDomain()
    const relay = await spawnRelay('p3', [
      ...dead.args,
      '--rate-per-from',
      '2000',
      '--rate-per-root',
      '4000',
      '--rate-per-ip',
      '2000',
      '--sweep-interval',
      '2',
    ])
    const alice = party('alice')
    const bob = party('bob')
    const dom = party('dom')
    const base = now()
    // dom starts behind the dead domain (every envelope pends); bob is always deliverable.
    expect(
      await publishRecords(relay.url, [
        acceptFrom(bob, ['*']),
        acceptFromAt(dom, [`domain:${dead.host}`], base),
      ]),
    ).toEqual([200, 200])
    const N = 257
    for (let i = 0; i < N; i++) {
      const r = await post(relay.url, envelope(alice, [bob, dom]).bytes)
      expect(r.status, JSON.stringify(r.body)).toBe(200)
    }
    await until(
      `${N} pending rows`,
      () => events(relay).filter((e) => e.event === 'pending').length === N,
      30_000,
    )
    // Nothing is swept-delivered yet: the domain is still dead.
    expect(events(relay).filter((e) => e.event === 'pending-delivered')).toHaveLength(0)
    // Make all 257 resolvable at once: dom's accept-from now admits every root (a newer iat wins), so the sweep
    // delivers them without touching the network.
    const update = await post(relay.url, serializeRecord(acceptFromAt(dom, ['*'], base + 10)))
    expect(update.status, JSON.stringify(update.body)).toBe(200)
    const deliveredEvents = () => events(relay).filter((e) => e.event === 'pending-delivered')
    const delivered = (): number => deliveredEvents().length
    // Wait for all 257, then read when the relay delivered each. A pass retries its rows one after another within
    // milliseconds; the next pass starts a sweep interval (2 s) after the first began, so the gap between the passes is
    // about 2000 ms less the first pass's duration. The widest gap between two deliveries is where the passes part,
    // and it must fall after the 256th: no count is read at a chosen instant, so a late pass cannot move the 257th.
    await until('all 257 retried', () => delivered() === N, 30_000)
    const ats = deliveredEvents().map((e) => e.at)
    const gaps = ats.slice(1).map((t, i) => t - (ats[i] as number))
    const widest = Math.max(...gaps)
    const parted = gaps.indexOf(widest) + 1
    console.log(
      `P3 measure: the relay retried ${parted} then ${N - parted} in successive passes (cap 256), ${widest} ms between the two passes`,
    )
    expect(parted, 'the widest gap is after the 256th delivery').toBe(256)
    expect(widest, 'and it is a sweep apart, not a pass apart').toBeGreaterThanOrEqual(500)
    expect(delivered()).toBe(N)
  })
})
