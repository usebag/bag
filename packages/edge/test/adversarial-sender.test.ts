import { parseEnvelope, parseRecord, serializeRecord } from '@usebag/core'
import { describe, expect, it, onTestFinished } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { addressRecord, FakeClock, FakeRecords, MemoryAuditSink, P, seededRng } from './support/fixtures.ts'
import { json, startHttp } from './support/http.ts'

// A recipient whose address record names `http://127.0.0.1:<port>/` as its relay, where the test listens with
// node:http. Does the sender's edge POST the envelope there? Without a private-address guard it would: the
// spec's relay-URL form admits loopback, link-local and private addresses. The hostile URL forms through the
// record checks are in the core tests.

const HOME = 'http://home.test'

describe('a relay URL on a local address in a recipient record', () => {
  it('measures whether the edge POSTs the envelope to the local listener the record names', async () => {
    const listener = await startHttp()
    onTestFinished(() => listener.close())
    listener.handle = (req, res) => {
      const id = req.url === '/v0/publish' ? parseEnvelope(req.body).id : ''
      json(res, 200, { ok: true, id, duplicate: false, delivered: 1 })
    }
    const local = `${listener.url}/`
    // The record that names it passes the record checks (the form the spec gives a relay URL).
    const record = addressRecord(P.bob, { relays: [local] })
    expect(parseRecord(serializeRecord(record)).kind).toBe('address')
    const records = new FakeRecords()
    records.put(HOME, record)
    const store = new SqliteStore(':memory:')
    onTestFinished(() => store.close())
    const edge = new Edge({
      keys: P.carol.keys,
      store,
      relays: { client: createRelayClient({ maxReconnects: 0 }), urls: [HOME] },
      records,
      policy: { roots: [], types: ['*'] },
      clock: new FakeClock(),
      rng: seededRng('adversarial-sender'),
      audit: new MemoryAuditSink(),
    })
    const sent = await edge.send({
      to: [P.bob.address],
      type: 'chat.v1',
      body: { text: 'to a local listener' },
    })
    const posts = listener.seen.filter((s) => s.method === 'POST' && s.url === '/v0/publish')
    const exact = posts.filter(
      (s) => Buffer.compare(s.body, Buffer.from(store.outboxGet(sent.id)?.bytes ?? [])) === 0,
    )
    console.log(
      `MEASURE D5: record relay ${local.replace(/:\d+\/$/, ':<port>/')} -> ${posts.length} POST /v0/publish to the local ` +
        `listener, ${exact.length} with the exact envelope bytes; target state ${sent.targets[0]?.state}`,
    )
    // Before the private-address guard existed, the POST arrived with the envelope's exact bytes and the target was
    // published. Now the guard refuses the loopback URL, which is not one of the edge's own relays, before any
    // request: no POST, and the target fails at once with resolve-failed.
    expect(posts).toHaveLength(0)
    expect(exact).toHaveLength(0)
    expect(sent.targets.map((t) => [t.relay, t.state, t.reason])).toEqual([
      [local, 'failed', 'resolve-failed'],
    ])
  })
})
