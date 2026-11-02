import {
  codingEvaluator,
  type Hop,
  serializeRecord,
  signHop,
  signRecord,
  toHex,
  verifyFetchAuth,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge, type EdgeOptions, generateEdgeKeys, hopsFrom } from '../src/edge.ts'
import {
  type EdgeKeys,
  type FetchProof,
  type InboundMessage,
  type RecordSource,
  type RelayClient,
  RelayError,
  type Subscription,
} from '../src/ports.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay, ScriptedRelay } from './support/relays.ts'

const HOME = 'http://home.test'

interface Node {
  readonly edge: Edge
  readonly audit: MemoryAuditSink
  readonly store: SqliteStore
}

function node(
  keys: EdgeKeys,
  relay: RelayClient,
  o: Partial<EdgeOptions> & { roots: EdgeOptions['policy']['roots'] },
  records?: RecordSource,
): Node {
  const audit = new MemoryAuditSink()
  const store = new SqliteStore(':memory:')
  const edge = new Edge({
    keys,
    store,
    relays: { client: relay, urls: [HOME] },
    ...(records === undefined ? {} : { records }),
    policy: { roots: o.roots, types: ['chat.*', 'coding.*'], evaluators: [codingEvaluator] },
    clock: o.clock ?? new FakeClock(),
    rng: seededRng(keys.signing.address),
    audit,
    flushEveryMs: 5,
    lookup: PUBLIC_LOOKUP,
    resubscribeDelayMs: () => 0,
    ...o,
  })
  return { edge, audit, store }
}

function inbox(session: string, into: InboundMessage[], then?: (m: InboundMessage) => Promise<unknown>) {
  return {
    session,
    deliver: async (m: InboundMessage) => {
      into.push(m)
      await then?.(m)
    },
  }
}

async function until(test: () => boolean): Promise<void> {
  for (let i = 0; i < 2000 && !test(); i++) await new Promise((r) => setTimeout(r, 1))
  expect(test()).toBe(true)
}

function noSecrets(lines: readonly string[], parties: readonly Party[]): void {
  const all = lines.join('\n')
  for (const p of parties) for (const s of p.secrets) expect(all).not.toContain(s)
}

describe('Edge: sender, receiver, resolver, policy, router and audit composed (spec/SPEC.md §9)', () => {
  it('runs a round trip carol -> bob -> carol through a relay, routing the reply to the session that opened the thread', async () => {
    const relay = new MemoryRelay()
    const carol = node(P.carol.keys, relay, { roots: [{ address: P.bob.address }] })
    const bob = node(P.bob.keys, relay, { roots: [{ address: P.carol.address }] })
    await carol.edge.publishRecord(addressRecord(P.carol, { relays: [HOME] }))
    await bob.edge.publishRecord(addressRecord(P.bob, { relays: [HOME] }))
    const atBob: InboundMessage[] = []
    const atCarol: InboundMessage[] = []
    bob.edge.setDefault(
      inbox('bob-inbox', atBob, (m) => bob.edge.reply(m, { type: 'chat.reply', body: { ok: true } })),
    )
    carol.edge.attach(inbox('chat-1', atCarol))
    await bob.edge.start()
    await carol.edge.start()
    const sent = await carol.edge.send({
      to: [P.bob.address],
      type: 'chat.v1',
      body: { q: 'ping' },
      session: 'chat-1',
    })
    await until(() => atCarol.length === 1)
    await bob.edge.stop()
    await carol.edge.stop()
    expect(atBob[0]).toMatchObject({
      id: sent.id,
      from: P.carol.address,
      principal: P.carol.address,
      body: { q: 'ping' },
    })
    expect(atCarol[0]).toMatchObject({
      from: P.bob.address,
      type: 'chat.reply',
      thread: { id: sent.thread.id, prev: [sent.id] },
    })
    expect(carol.edge.status(sent.id).map((t) => t.state)).toEqual(['published'])
    await until(() => bob.edge.inbox(['acked']).length === 1)
    expect(bob.edge.inbox().map((r) => [r.state, r.session])).toEqual([['acked', 'bob-inbox']])
    expect(relay.acks.get(`${HOME} ${P.bob.address} ${P.bob.address}`)).toBe(1)
    for (const n of [carol, bob]) expect(verifyAuditLog(n.audit.lines)).toMatchObject({ ok: true })
    noSecrets([...carol.audit.lines, ...bob.audit.lines], [P.carol, P.bob])
  })

  it('carries a cross-org chain both ways: org -> jane -> session to bob, and bob replies to the principal', async () => {
    const relay = new MemoryRelay()
    const wellKnown = new FakeRecords()
    wellKnown.domain('acme.test', addressRecord(P.org, { relays: [HOME], ttl: 86_400 }))
    const records: RecordSource = {
      wellKnown: (d) => wellKnown.wellKnown(d),
      relayRecord: (u, a, k) => relay.fetchRecord(u, a, k),
    }
    const auth: Hop[] = [
      signHop(P.org.signing, P.jane.address, ['type=coding.*'], T0 + 86_400),
      signHop(P.jane.signing, P.session.address, ['repo=bag'], T0 + 3600),
    ]
    const session = node(
      { signing: P.session.signing, sealing: P.jane.sealing },
      relay,
      { roots: [{ address: P.bob.address }], auth, mailbox: P.jane.address },
      records,
    )
    const bob = node(P.bob.keys, relay, { roots: [{ domain: 'acme.test' }] }, records)
    await relay.publish(HOME, serializeRecord(addressRecord(P.jane, { relays: [HOME] })))
    await bob.edge.publishRecord(addressRecord(P.bob))
    const atBob: InboundMessage[] = []
    const atSession: InboundMessage[] = []
    bob.edge.setDefault(
      inbox('bob', atBob, (m) => bob.edge.reply(m, { type: 'coding.result.v1', body: { repo: 'bag' } })),
    )
    session.edge.attach(inbox('coder', atSession))
    expect([session.edge.address, session.edge.mailbox]).toEqual([P.session.address, P.jane.address])
    await bob.edge.start()
    await session.edge.start()
    const sent = await session.edge.send({
      to: [P.bob.address],
      type: 'coding.task.v1',
      body: { repo: 'bag', task: 'review' },
      session: 'coder',
    })
    await until(() => atSession.length === 1)
    await bob.edge.stop()
    await session.edge.stop()
    expect(atBob[0]).toMatchObject({
      from: P.session.address,
      principal: P.jane.address,
      root: P.org.address,
    })
    expect(atSession[0]).toMatchObject({
      to: [P.jane.address],
      from: P.bob.address,
      thread: { prev: [sent.id] },
    })
    expect(bob.store.pinGet('domain:acme.test')?.key).toBe(P.org.address)
    const fetched = await session.edge.fetch(HOME, sent.id)
    expect(toHex(fetched)).toBe(toHex(relay.ids.get(`${HOME} ${sent.id}`) as Uint8Array))
    await expect(bob.edge.fetch(HOME, 'ab'.repeat(32))).rejects.toMatchObject({ code: 'not-found' })
    noSecrets([...session.audit.lines, ...bob.audit.lines], [P.session, P.jane, P.bob])
  })

  it('signs each fetch proof for the relay URL it is given, byte for byte, under a chain too (spec/SPEC.md §8.3)', async () => {
    const asked: { readonly url: string; readonly proof: FetchProof }[] = []
    const client: RelayClient = {
      publish: async () => ({ id: '', duplicate: false, delivered: 0 }),
      fetch: async (url, _id, proof) => {
        asked.push({ url, proof })
        return new Uint8Array()
      },
      fetchRecord: async () => null,
      subscribe: () => {
        throw new Error('no subscription in this test')
      },
    }
    const auth = [signHop(P.jane.signing, P.session.address, [], T0 + 3600)]
    const keys = { signing: P.session.signing, sealing: P.jane.sealing }
    const bob = node(P.bob.keys, client, { roots: [] })
    const session = node(keys, client, { roots: [], auth, mailbox: P.jane.address })
    // Nothing is added or stripped: a path stays, and a trailing slash is neither added nor removed.
    const urls = [HOME, 'https://relay.example', 'https://relay.example/', 'https://relay.example/bag']
    const id = 'ab'.repeat(32)
    for (const url of urls) {
      await bob.edge.fetch(url, id)
      await session.edge.fetch(url, id)
    }
    const want = urls.flatMap((url) => [
      [url, P.bob.address, T0, []],
      [url, P.session.address, T0, auth],
    ])
    expect(asked.map((a) => [a.url, a.proof.signer, a.proof.ts, a.proof.auth])).toEqual(want)
    for (const { url, proof } of asked) {
      const { signer, ts, sig } = proof
      expect(urls.filter((u) => verifyFetchAuth(signer, id, ts, u, sig))).toEqual([url])
      expect(verifyFetchAuth(signer, id, ts + 1, url, sig)).toBe(false)
    }
  })

  it('publishes records to given relays, and keeps no key material in its audit lines', async () => {
    const relay = new MemoryRelay()
    const n = node(P.bob.keys, relay, { roots: [] })
    const accept = signRecord(P.bob.signing, {
      kind: 'accept-from',
      owner: P.bob.address,
      roots: ['*'],
      max_bytes: 1000,
      ttl: 60,
      iat: T0,
    })
    const answer = { kind: 'accept-from', signer: P.bob.address, iat: T0, valid_until: null }
    expect(await n.edge.publishRecord(accept, ['http://a', 'http://b'])).toEqual([answer, answer])
    expect([...relay.records.keys()]).toEqual([
      `http://a ${P.bob.address} accept-from`,
      `http://b ${P.bob.address} accept-from`,
    ])
  })

  it('answers null for a relay that names no record answer, as an older relay does', async () => {
    const relay = new ScriptedRelay()
    relay.fallback = { id: '', duplicate: false, delivered: 0 }
    const n = node(P.bob.keys, relay, { roots: [] })
    const accept = signRecord(P.bob.signing, {
      kind: 'accept-from',
      owner: P.bob.address,
      roots: ['*'],
      max_bytes: 1000,
      ttl: 60,
      iat: T0,
    })
    expect(await n.edge.publishRecord(accept, ['http://a'])).toEqual([null])
    expect(relay.published.map((p) => p.url)).toEqual(['http://a'])
  })

  it('starts once, stops once, and does not subscribe when stopped while recovering', async () => {
    const relay = new MemoryRelay()
    const n = node(P.bob.keys, relay, { roots: [] })
    const plain = new Edge({
      keys: P.carol.keys,
      store: new SqliteStore(':memory:'),
      relays: { client: relay, urls: [] },
      policy: { roots: [], types: [] },
      clock: new FakeClock(),
      rng: seededRng('plain'),
      audit: new MemoryAuditSink(),
    })
    await plain.start()
    await plain.stop()
    await n.edge.start()
    await n.edge.start()
    expect(relay.subs.size).toBe(1)
    await n.edge.stop()
    await n.edge.stop()
    expect(relay.subs.size).toBe(0)
    const starting = n.edge.start()
    await n.edge.stop()
    await starting
    expect(relay.subs.size).toBe(0)
  })

  it('publishes due outbox targets on its timer, and reports a subscription that fails', async () => {
    const relay = new MemoryRelay()
    const clock = new FakeClock()
    const carol = node(P.carol.keys, relay, { roots: [], clock })
    await carol.edge.publishRecord(addressRecord(P.bob, { relays: [HOME] }))
    relay.failing.set(HOME, new RelayError(null, 503, null, 'busy'))
    const sent = await carol.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect(carol.edge.status(sent.id)[0]?.state).toBe('retry')
    relay.failing.clear()
    clock.advance(1)
    await carol.edge.start()
    await until(() => carol.edge.status(sent.id)[0]?.state === 'published')
    await carol.edge.stop()

    const errors: unknown[] = []
    const failing: RelayClient = {
      ...relay,
      publish: relay.publish.bind(relay),
      fetch: relay.fetch.bind(relay),
      fetchRecord: relay.fetchRecord.bind(relay),
      subscribe: (): Subscription => ({
        ack: () => {},
        close: () => {},
        [Symbol.asyncIterator]: () => ({
          next: () => Promise.reject(new RelayError('bad-auth', 0, null, 'no')),
        }),
      }),
    }
    const loud = node(P.bob.keys, failing, { roots: [], onError: (e) => errors.push(e) })
    await loud.edge.start()
    await until(() => errors.length === 1)
    await loud.edge.stop()
    expect(errors[0]).toMatchObject({ code: 'bad-auth' })
    const quiet = node(P.bob.keys, failing, { roots: [] })
    await quiet.edge.start()
    await quiet.edge.stop()
  })

  it('reports a store fault on its timer, and stops again when recovery fails at start', async () => {
    const relay = new MemoryRelay()
    const store = new SqliteStore(':memory:')
    let broken = 'seenPrune'
    const faulty = new Proxy(store, {
      get(target, key) {
        if (key === broken) {
          return () => {
            throw new Error(`${String(key)} failed`)
          }
        }
        const value = Reflect.get(target, key) as unknown
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const errors: unknown[] = []
    const n = node(P.bob.keys, relay, { roots: [], store: faulty, onError: (e) => errors.push(e) })
    await n.edge.start()
    await until(() => errors.length > 0)
    await n.edge.stop()
    expect(String(errors[0])).toContain('seenPrune failed')
    broken = 'inboxList'
    await expect(n.edge.start()).rejects.toThrow('inboxList failed')
    expect(relay.subs.size).toBe(0)
    broken = ''
    await n.edge.start()
    expect(relay.subs.size).toBe(1)
    await n.edge.stop()
  })

  it('prunes at the tick of its start the thread bindings unused for 2 x TTL + skew, keeping those used within it', async () => {
    const clock = new FakeClock()
    const n = node(P.bob.keys, new MemoryRelay(), { roots: [], clock, window: { ttl: 100, skew: 10 } })
    n.store.threadSet('old', 'chat-1', T0)
    n.store.threadSet('edge-of-horizon', 'chat-1', T0 + 1)
    n.store.threadSet('conversation', 'chat-1', T0)
    clock.advance(210)
    // The conversation goes on: a send on its thread is a use.
    n.edge.router.bind('conversation', 'chat-1')
    clock.advance(1)
    await n.edge.start()
    await n.edge.stop()
    const left = ['old', 'edge-of-horizon', 'conversation'].map((t) => n.store.threadGet(t))
    expect(left).toEqual([null, 'chat-1', 'chat-1'])
  })

  it('makes a signing key and a separate sealing key, and finds the chain from the mailbox to the signer', () => {
    const keys = generateEdgeKeys(seededRng('keys'))
    expect(keys.signing.address).toMatch(/^ed25519:[0-9a-f]{64}$/)
    expect(toHex(keys.sealing.publicKey)).not.toBe(keys.signing.address.slice(8))
    const auth = [
      signHop(P.org.signing, P.jane.address, [], T0 + 60),
      signHop(P.jane.signing, P.session.address, [], T0 + 60),
    ]
    expect(hopsFrom(auth, P.jane.address, P.session.address)).toEqual(auth.slice(1))
    expect(hopsFrom(auth, P.org.address, P.session.address)).toEqual(auth)
    expect(hopsFrom(auth, P.session.address, P.session.address)).toEqual([])
    expect(hopsFrom(auth, P.bob.address, P.session.address)).toEqual([])
  })
})
