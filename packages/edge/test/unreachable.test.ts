import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { UNREACHABLE } from '../src/outbox.ts'
import type { OutboxTarget, RelayClient } from '../src/ports.ts'
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
import { closedPort, json, startHttp, type TestServer } from './support/http.ts'
import { ScriptedRelay } from './support/relays.ts'

// The outbox reason `unreachable` (the edge half): a try that got no answer
// from its relay, a closed port on 127.0.0.1 through the real HTTP adapter here, is `unreachable` in its target's
// reason and in its audit line's unless the edge turns that off (on by default; the line's reason is in
// spec/SPEC.md §9 item 8 and Appendix A), and is retried to the horizon, where
// the target and its last line fail publish-failed; a relay's code is kept, an answer without one is publish-failed,
// and the line names the cause in its detail either way. Each test prints its measurement as a MEASURE line.

const WEEK = 604_800
let server: TestServer
beforeAll(async () => {
  server = await startHttp()
})
afterAll(() => server.close())

/** Carol's edge, whose own relay is `url`, where bob's record names `url` too; the private-address guard allows it. */
function carol(url: string, client: RelayClient, unreachableReason?: boolean) {
  const records = new FakeRecords()
  records.put(url, addressRecord(P.bob, { relays: [url] }))
  const clock = new FakeClock()
  const audit = new MemoryAuditSink()
  const edge = new Edge({
    keys: P.carol.keys,
    store: new SqliteStore(':memory:'),
    relays: { client, urls: [url] },
    records,
    policy: { roots: [], types: [] },
    clock,
    rng: seededRng('unreachable'),
    audit,
    lookup: PUBLIC_LOOKUP,
    ...(unreachableReason === undefined ? {} : { unreachableReason }),
  })
  return { edge, clock, audit }
}

/** The last audit line's event, decision and reason, and its detail. */
function lastLine(audit: MemoryAuditSink): [string, Record<string, unknown>] {
  const v = JSON.parse(audit.lines.at(-1) as string) as Record<string, string>
  return [`${v.event} ${v.decision} ${v.reason}`, JSON.parse(v.detail as string) as Record<string, unknown>]
}

describe('the outbox reason unreachable: a try with no answer from its relay', () => {
  it('(L4 a) a closed port is unreachable with a retry at ts + 1, retried to the horizon, where the target fails publish-failed', async () => {
    const url = `http://127.0.0.1:${await closedPort()}`
    const { edge, clock, audit } = carol(url, createRelayClient(), true)
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 1 } })
    expect(sent.targets).toEqual([
      {
        id: sent.id,
        relay: url,
        state: 'retry',
        tries: 1,
        nextAt: T0 + 1,
        reason: UNREACHABLE,
        updatedAt: T0,
      },
    ])
    expect(lastLine(audit)).toEqual([
      'publish retry unreachable',
      { relay: url, tries: 1, status: 0, next_at: T0 + 1, cause: 'unreachable' },
    ])
    let t = sent.targets[0] as OutboxTarget
    const reasons = new Set<string | null>()
    while (t.state === 'retry') {
      reasons.add(t.reason)
      clock.t = t.nextAt as number
      t = (await edge.flush())[0] as OutboxTarget
    }
    expect([...reasons]).toEqual(['unreachable'])
    expect(t).toMatchObject({ state: 'failed', reason: 'publish-failed', nextAt: null, updatedAt: T0 + WEEK })
    // Every unanswered try's line reads unreachable; only the give-up at the horizon reads publish-failed.
    const steps = audit.steps().filter((s) => s.startsWith('publish'))
    expect(steps).toHaveLength(t.tries)
    expect(new Set(steps.slice(0, -1))).toEqual(new Set(['publish retry unreachable']))
    expect(steps.at(-1)).toBe('publish reject publish-failed')
    expect(edge.status(sent.id)).toEqual([t])
    console.log(
      `MEASURE L4(a): closed port -> retry reason ${sent.targets[0]?.reason} next_at ts + 1; ${t.tries} tries, then ${t.state} ${t.reason} at ts + ${t.updatedAt - T0}`,
    )
  })

  it('(L4 b) the option is on by default; false keeps publish-failed in the target and its audit line, which names the cause either way', async () => {
    const url = `http://127.0.0.1:${await closedPort()}`
    const reasons: (string | null | undefined)[] = []
    const lines: string[] = []
    for (const option of [undefined, false]) {
      const { edge, audit } = carol(url, createRelayClient(), option)
      const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 2 } })
      expect(sent.targets[0]).toMatchObject({ state: 'retry', tries: 1, nextAt: T0 + 1 })
      reasons.push(sent.targets[0]?.reason)
      const [step, detail] = lastLine(audit)
      lines.push(step)
      expect(detail).toEqual({ relay: url, tries: 1, status: 0, next_at: T0 + 1, cause: 'unreachable' })
    }
    expect(reasons).toEqual(['unreachable', 'publish-failed'])
    expect(lines).toEqual(['publish retry unreachable', 'publish retry publish-failed'])
    console.log(
      `MEASURE L4(b): option absent -> retry reason ${reasons[0]}, line ${lines[0]}; false -> ${reasons[1]}, line ${lines[1]}`,
    )
  })

  it("(L4 c) a relay's 403 keeps its code at once; an answer without a code, a 503 from a proxy, is a retry with publish-failed", async () => {
    server.handle = (_req, res) => json(res, 403, { error: 'root-not-accepted' })
    const refused = carol(server.url, createRelayClient(), true)
    const sent = await refused.edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 3 } })
    expect(sent.targets[0]).toMatchObject({
      state: 'failed',
      tries: 1,
      reason: 'root-not-accepted',
      nextAt: null,
    })
    expect(lastLine(refused.audit)).toEqual([
      'publish reject root-not-accepted',
      { relay: server.url, tries: 1, status: 403, next_at: null },
    ])
    server.handle = (_req, res) => {
      res.writeHead(503, { 'content-type': 'text/html' }).end('<html>bad gateway</html>')
    }
    const proxied = carol(server.url, createRelayClient(), true)
    const later = await proxied.edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 4 } })
    expect(later.targets[0]).toMatchObject({
      state: 'retry',
      tries: 1,
      reason: 'publish-failed',
      nextAt: T0 + 1,
    })
    expect(lastLine(proxied.audit)).toEqual([
      'publish retry publish-failed',
      { relay: server.url, tries: 1, status: 503, next_at: T0 + 1 },
    ])
    console.log(
      `MEASURE L4(c): 403 -> ${sent.targets[0]?.state} ${sent.targets[0]?.reason}; 503 without a code -> ${later.targets[0]?.state} ${later.targets[0]?.reason}`,
    )
  })

  it("(L4 a') a client that throws something other than a RelayError is no answer too; the guard's refusal stays resolve-failed", async () => {
    const relay = new ScriptedRelay()
    relay.script.push(new TypeError('fetch failed'))
    const thrown = carol('http://relay.test', relay, true)
    const sent = await thrown.edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 5 } })
    expect(sent.targets[0]).toMatchObject({ state: 'retry', reason: 'unreachable' })
    // Bob's record names a private relay that is not carol's own: refused before any request, as before.
    const records = new FakeRecords()
    records.put('http://relay.test', addressRecord(P.bob, { relays: ['http://10.1.2.3:7777'] }))
    const guarded = new Edge({
      keys: P.carol.keys,
      store: new SqliteStore(':memory:'),
      relays: { client: relay, urls: ['http://relay.test'] },
      records,
      policy: { roots: [], types: [] },
      clock: new FakeClock(),
      rng: seededRng('guarded'),
      audit: new MemoryAuditSink(),
      lookup: PUBLIC_LOOKUP,
      unreachableReason: true,
    })
    const refused = await guarded.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 6 } })
    expect(refused.targets[0]).toMatchObject({ state: 'failed', reason: 'resolve-failed' })
    expect(relay.published).toHaveLength(1)
  })
})
