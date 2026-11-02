import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { RelayError } from '../src/ports.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
} from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// Post-hoc, beside the guard tests: an audit line records a relay URL that carries a user name or password as
// its scheme and host only, the port kept, in every publish branch (refused, failed, published); any other URL as it
// is. The outbox row keeps the URL as written, since it is the target's key (the outbox_targets primary key is
// id and relay, and the send result's targets[].relay matches it).

const HOME = 'http://home.test'

function setup(relays: string[], o: { urls?: string[]; allowPrivateRelays?: boolean } = {}) {
  const store = new SqliteStore(':memory:')
  const audit = new MemoryAuditSink()
  const clock = new FakeClock()
  const relay = new ScriptedRelay()
  const records = new FakeRecords()
  records.put(HOME, addressRecord(P.carol, { relays }))
  const edge = new Edge({
    keys: P.session.keys,
    auth: [],
    store,
    relays: { client: relay, urls: o.urls ?? [HOME] },
    records,
    policy: { roots: [], types: ['*'] },
    clock,
    rng: seededRng('sender-userinfo'),
    audit,
    lookup: PUBLIC_LOOKUP,
    ...(o.allowPrivateRelays === undefined ? {} : { allowPrivateRelays: o.allowPrivateRelays }),
  })
  return { edge, store, audit, clock, relay }
}

/** The publish and rate-limit audit lines, raw and with their detail parsed. */
function publishLines(
  audit: MemoryAuditSink,
): { raw: string; reason: string; detail: Record<string, unknown> }[] {
  return audit.lines
    .filter((l) => /"event":"(publish|rate-limit)"/.test(l))
    .map((raw) => {
      const v = JSON.parse(raw) as { reason: string; detail: string }
      return { raw, reason: v.reason, detail: JSON.parse(v.detail) as Record<string, unknown> }
    })
}

describe('Sender: a relay URL with userinfo is recorded as its scheme and host only', () => {
  it('refuses the two repro URLs (and a password alone) resolve-failed with 0 requests, and the audit line holds no user name or password', async () => {
    for (const url of ['https://user:pw@1.1.1.1/', 'https://user@1.1.1.1/', 'https://:pw@1.1.1.1/']) {
      const { edge, store, audit, relay } = setup([url])
      const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
      expect(
        sent.targets.map((t) => [t.relay, t.state, t.reason, t.tries]),
        url,
      ).toEqual([[url, 'failed', 'resolve-failed', 1]])
      expect(relay.published, url).toEqual([])
      const lines = publishLines(audit)
      expect(
        lines.map((l) => [l.reason, l.detail]),
        url,
      ).toEqual([['resolve-failed', { relay: 'https://1.1.1.1', tries: 1, refused: 'userinfo' }]])
      // The range's own name, userinfo, is the one place "user" may appear.
      const rest = (lines[0]?.raw ?? '').replaceAll('userinfo', '')
      expect([rest.includes('user'), rest.includes('pw')], url).toEqual([false, false])
      // The outbox row keeps the URL: it is the target's key.
      expect(
        store.outboxTargets(sent.id).map((t) => t.relay),
        url,
      ).toEqual([url])
      store.close()
    }
  })

  it('keeps the port of a userinfo URL, and records a URL without userinfo unchanged', async () => {
    const cred = 'https://alice-name:s3cret-word@1.1.1.1:8443/x/'
    const { edge, store, audit, relay } = setup([cred, 'http://10.0.0.1:7777/', 'https://1.1.1.1:8443/x/'])
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(relay.published.map((p) => p.url)).toEqual(['https://1.1.1.1:8443/x/'])
    // Targets come in the store's order (by relay), audit lines in the order the tries end: both compared sorted.
    expect(sent.targets.map((t) => `${t.relay} ${t.state}`).sort()).toEqual([
      'http://10.0.0.1:7777/ failed',
      'https://1.1.1.1:8443/x/ published',
      `${cred} failed`,
    ])
    const lines = publishLines(audit)
    expect(lines.map((l) => `${l.detail.relay} ${l.detail.refused ?? '-'}`).sort()).toEqual([
      'http://10.0.0.1:7777/ private',
      'https://1.1.1.1:8443 userinfo',
      'https://1.1.1.1:8443/x/ -',
    ])
    for (const l of lines)
      expect([l.raw.includes('alice-name'), l.raw.includes('s3cret')]).toEqual([false, false])
    store.close()
  })

  it('records a called userinfo relay (own, or with allowPrivateRelays) as its scheme and host when it fails and when it publishes', async () => {
    const cred = 'http://user:pw@127.0.0.1:7777/'
    for (const o of [{ urls: [HOME, cred] }, { allowPrivateRelays: true }]) {
      const { edge, store, audit, clock, relay } = setup([cred], o)
      relay.script.push(
        new RelayError(null, 0, null, 'connection refused'),
        new RelayError(null, 503, null, 'down'),
      )
      const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
      clock.advance(1)
      await edge.flush()
      clock.advance(2)
      await edge.flush()
      expect(relay.published.map((p) => p.url)).toEqual([cred, cred, cred])
      expect(store.outboxTargets(sent.id).map((t) => [t.relay, t.state])).toEqual([[cred, 'published']])
      const lines = publishLines(audit)
      expect(lines.map((l) => [l.reason, l.detail.relay, l.detail.cause ?? null])).toEqual([
        ['unreachable', 'http://127.0.0.1:7777', 'unreachable'],
        ['publish-failed', 'http://127.0.0.1:7777', null],
        ['ok', 'http://127.0.0.1:7777', null],
      ])
      for (const l of lines) expect([l.raw.includes('user'), l.raw.includes('pw')]).toEqual([false, false])
      store.close()
    }
  })
})
