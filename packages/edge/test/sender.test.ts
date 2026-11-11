import {
  type Hop,
  newThread,
  openSealed,
  parseEnvelope,
  replyThread,
  signHop,
  toHex,
  verifyChain,
  verifyOuter,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { startTry } from '../src/outbox.ts'
import { type EdgeKeys, type PublishResult, type RelayClient, RelayError } from '../src/ports.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  keyRecord,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

const R1 = 'http://relay-1.test'
const R2 = 'http://relay-2.test'
const HOME = 'http://home.test'

function setup(
  o: {
    relay?: RelayClient
    records?: FakeRecords
    urls?: string[]
    auth?: Hop[]
    keys?: EdgeKeys
    lookup?: (host: string) => Promise<readonly string[]>
    allowPrivateRelays?: boolean
  } = {},
) {
  const store = new SqliteStore(':memory:')
  const audit = new MemoryAuditSink()
  const clock = new FakeClock()
  const relay = o.relay ?? new ScriptedRelay()
  const records = o.records ?? new FakeRecords()
  const edge = new Edge({
    keys: o.keys ?? P.session.keys,
    auth: o.auth ?? [],
    store,
    relays: { client: relay, urls: o.urls ?? [HOME] },
    records,
    policy: { roots: [], types: ['*'] },
    clock,
    rng: seededRng('sender'),
    audit,
    lookup: o.lookup ?? PUBLIC_LOOKUP,
    ...(o.allowPrivateRelays === undefined ? {} : { allowPrivateRelays: o.allowPrivateRelays }),
  })
  return { edge, store, audit, clock, relay, records }
}

/** Records for bob (relays R1 and R2) and carol (relay R2), at the home relay. */
function directory(): FakeRecords {
  const records = new FakeRecords()
  records.put(HOME, addressRecord(P.bob, { relays: [R1, R2] }))
  records.put(HOME, addressRecord(P.carol, { relays: [R2] }))
  return records
}

const ok: PublishResult = { id: 'x', duplicate: false, delivered: 1 }

/** A relay that refuses not-hosted at the URLs in `refuse` and takes every other publish. */
class ByUrl extends ScriptedRelay {
  readonly refuse = new Set<string>()
  override async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.published.push({ url, bytes })
    if (this.refuse.has(url)) throw new RelayError('not-hosted', 403, null, 'no accept-from')
    return ok
  }
}
const down = (): RelayError => new RelayError(null, 0, null, 'connection refused')

describe('Sender: resolve, build, persist, publish (spec/SPEC.md §9.1)', () => {
  it('publishes the exact persisted bytes to every relay of every recipient, once per relay', async () => {
    const relay = new ScriptedRelay()
    const { edge, store, audit } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.bob.address, P.carol.address], type: 'chat.v1', body: { hi: 1 } })
    expect(sent.targets.map((t) => [t.relay, t.state, t.tries])).toEqual([
      [R1, 'published', 1],
      [R2, 'published', 1],
    ])
    const entry = store.outboxGet(sent.id)
    expect(entry).toMatchObject({ id: sent.id, thread: sent.thread.id, session: null, createdAt: T0 })
    expect(relay.published.map((p) => p.url).sort()).toEqual([R1, R2])
    for (const p of relay.published) expect(p.bytes).toEqual(entry?.bytes)
    const env = parseEnvelope(relay.published[0]?.bytes as Uint8Array)
    verifyOuter(env, T0)
    expect(env).toMatchObject({
      id: sent.id,
      to: [P.bob.address, P.carol.address],
      from: P.session.address,
      ts: T0,
    })
    expect(openSealed(env, { address: P.carol.address, key: P.carol.sealing })).toEqual({
      type: 'chat.v1',
      thread: sent.thread,
      body: { hi: 1 },
    })
    expect(audit.steps().filter((s) => s.startsWith('publish'))).toEqual([
      'publish accept ok',
      'publish accept ok',
    ])
    expect(edge.status(sent.id)).toEqual(sent.targets)
  })

  it('sends in a given thread, and names the chain root in its audit lines', async () => {
    const hop = signHop(P.jane.signing, P.session.address, ['type=chat.*'], T0 + 3600)
    const { edge, audit } = setup({ records: directory(), auth: [hop] })
    const thread = replyThread(
      newThread(() => new Uint8Array(32).fill(7)),
      ['cd'.repeat(32)],
    )
    const sent = await edge.send({ to: [P.carol.address], type: 'chat.v1', body: null, thread })
    expect(sent.thread).toEqual(thread)
    const line = JSON.parse(audit.lines.at(-1) as string)
    expect(line).toMatchObject({
      event: 'publish',
      id: sent.id,
      from: P.session.address,
      root: P.jane.address,
    })
  })

  it('retries a failed try after 1 s, doubling, with the same bytes, then publishes', async () => {
    const relay = new ScriptedRelay()
    relay.script.push(down(), down())
    const { edge, clock, audit } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    // No answer is `unreachable` by default, in the target and in its audit line.
    expect(sent.targets[0]).toMatchObject({
      state: 'retry',
      tries: 1,
      nextAt: T0 + 1,
      reason: 'unreachable',
    })
    expect(await edge.flush()).toEqual([])
    clock.advance(1)
    expect((await edge.flush())[0]).toMatchObject({ state: 'retry', tries: 2, nextAt: T0 + 1 + 2 })
    clock.advance(1)
    expect(await edge.flush()).toEqual([])
    clock.advance(1)
    expect((await edge.flush())[0]).toMatchObject({
      state: 'published',
      tries: 3,
      nextAt: null,
      reason: null,
    })
    expect(new Set(relay.published.map((p) => toHex(p.bytes))).size).toBe(1)
    expect(audit.steps().filter((s) => s.startsWith('publish'))).toEqual([
      'publish retry unreachable',
      'publish retry unreachable',
      'publish accept ok',
    ])
  })

  it('retries a target until ts + TTL, each try with the same bytes, then fails it, and resend publishes those bytes again', async () => {
    const relay = new ScriptedRelay()
    relay.fallback = down()
    const { edge, clock, audit } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    const waits: number[] = []
    let t = sent.targets[0]
    while (t?.state === 'retry') {
      waits.push((t.nextAt as number) - clock.now())
      clock.t = t.nextAt as number
      t = (await edge.flush())[0]
    }
    // Earlier versions failed the target after 20 tries (29,295 s); the horizon is now the relay TTL, 604,800 s after ts.
    expect(t).toMatchObject({ state: 'failed', reason: 'publish-failed', updatedAt: T0 + 604_800 })
    expect(clock.now()).toBe(T0 + 604_800)
    for (const [n, w] of waits.slice(0, -1).entries()) {
      const base = Math.min(2 ** n, 3600)
      expect(w, `wait ${n}`).toBeGreaterThanOrEqual(base - Math.floor(base / 10))
      expect(w, `wait ${n}`).toBeLessThanOrEqual(base)
    }
    // The jitter spreads the capped waits below the hour.
    expect(new Set(waits.slice(12, -1)).size).toBeGreaterThan(10)
    expect(relay.published).toHaveLength(t?.tries as number)
    expect(t?.tries).toBeGreaterThanOrEqual(180)
    expect(t?.tries).toBeLessThanOrEqual(202)
    expect(
      audit
        .steps()
        .filter((s) => s.startsWith('publish'))
        .at(-1),
    ).toBe('publish reject publish-failed')
    clock.advance(10 * 3600)
    expect(await edge.flush()).toEqual([])
    relay.fallback = ok
    const again = await edge.resend(sent.id)
    expect(again[0]).toMatchObject({ state: 'published', tries: 1 })
    expect(new Set(relay.published.map((p) => toHex(p.bytes))).size).toBe(1)
  })

  it('fails a target whose try fails past its horizon at once, and a resend of it too', async () => {
    const relay = new ScriptedRelay()
    relay.fallback = down()
    const { edge, clock } = setup({ relay, records: directory() })
    const late = await edge.send({ to: [P.carol.address], type: 't', body: 2 })
    expect(late.targets[0]).toMatchObject({ state: 'retry', tries: 1 })
    clock.advance(604_801)
    expect((await edge.flush())[0]).toMatchObject({ state: 'failed', tries: 2, reason: 'publish-failed' })
    expect((await edge.resend(late.id))[0]).toMatchObject({
      state: 'failed',
      tries: 1,
      reason: 'publish-failed',
    })
    expect(relay.published).toHaveLength(3)
  })

  it('a send every relay refuses not-hosted re-reads the recipient once: a move from relay X to Y goes out via Y', async () => {
    const X = 'http://relay-x.test'
    const Y = 'http://relay-y.test'
    const relay = new ByUrl()
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.carol, { relays: [X], ttl: 86_400 }))
    const { edge, store } = setup({ relay, records })
    expect((await edge.send({ to: [P.carol.address], type: 't', body: 0 })).targets[0]?.state).toBe(
      'published',
    )
    records.put(HOME, addressRecord(P.carol, { relays: [Y], ttl: 86_400, iat: T0 + 1 }))
    relay.refuse.add(X)
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([[Y, 'published']])
    expect(relay.published.map((p) => p.url)).toEqual([X, X, Y])
    const stale = parseEnvelope((relay.published[1] as { bytes: Uint8Array }).bytes).id
    expect(store.outboxTargets(stale).map((t) => [t.state, t.reason])).toEqual([['failed', 'not-hosted']])
    // The first envelope stays in the outbox as history (bag deletes no outbox row) but is never due again: no flush,
    // at any time, publishes it beside the re-sent one.
    expect(store.outboxDue(T0 + 10 * 86_400).filter((d) => d.target.id === stale)).toEqual([])
    expect(store.outboxGet(stale)).not.toBeNull()
  })

  it('does not re-send to a recipient whose fresh record names the same relays: one publish, failed not-hosted', async () => {
    const X = 'http://relay-x.test'
    const relay = new ByUrl()
    relay.refuse.add(X)
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.carol, { relays: [X], ttl: 86_400 }))
    const { edge } = setup({ relay, records })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets.map((t) => [t.relay, t.state, t.reason])).toEqual([[X, 'failed', 'not-hosted']])
    expect(relay.published.map((p) => p.url)).toEqual([X])
  })

  it('does not re-send when reading the recipient again fails: the send keeps its own failure', async () => {
    const X = 'http://relay-x.test'
    const relay = new ByUrl()
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.carol, { relays: [X], ttl: 86_400 }))
    const { edge } = setup({ relay, records })
    await edge.send({ to: [P.carol.address], type: 't', body: 0 })
    relay.refuse.add(X)
    records.relays.set(`${HOME} ${P.carol.address} address`, new Error('down'))
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets.map((t) => [t.relay, t.state, t.reason])).toEqual([[X, 'failed', 'not-hosted']])
    expect(relay.published.map((p) => p.url)).toEqual([X, X])
  })

  it('re-sends at most once per send: a moved recipient whose new relay refuses too is one re-send, then failed', async () => {
    const X = 'http://relay-x.test'
    const Y = 'http://relay-y.test'
    const relay = new ByUrl()
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.carol, { relays: [X], ttl: 86_400 }))
    const { edge } = setup({ relay, records })
    await edge.send({ to: [P.carol.address], type: 't', body: 0 })
    records.put(HOME, addressRecord(P.carol, { relays: [Y], ttl: 86_400, iat: T0 + 1 }))
    relay.refuse.add(X)
    relay.refuse.add(Y)
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets.map((t) => [t.relay, t.state, t.reason])).toEqual([[Y, 'failed', 'not-hosted']])
    expect(relay.published.map((p) => p.url)).toEqual([X, X, Y])
  })

  it("fails at once on a refusal the same bytes would meet again, keeping the relay's code", async () => {
    const relay = new ScriptedRelay()
    relay.script.push(new RelayError('root-not-accepted', 403, null, 'refused'))
    const { edge, audit } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets[0]).toMatchObject({ state: 'failed', tries: 1, reason: 'root-not-accepted' })
    expect(audit.steps().at(-1)).toBe('publish reject root-not-accepted')
    relay.script.push(new RelayError(null, 400, null, 'bad request'))
    expect((await edge.resend(sent.id))[0]).toMatchObject({ state: 'failed', reason: 'publish-failed' })
  })

  it('retries a 429 after its Retry-After, audited as rate-limit, and retries 408 and 5xx', async () => {
    const relay = new ScriptedRelay()
    relay.script.push(
      new RelayError('rate-limited', 429, 60, 'slow down'),
      new RelayError(null, 408, null, 'timeout'),
    )
    relay.script.push(new RelayError(null, 503, null, 'unavailable'))
    const { edge, clock, audit } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets[0]).toMatchObject({ state: 'retry', nextAt: T0 + 60, reason: 'rate-limited' })
    expect(audit.steps().at(-1)).toBe('rate-limit retry rate-limited')
    clock.advance(60)
    expect((await edge.flush())[0]).toMatchObject({ state: 'retry', tries: 2, reason: 'publish-failed' })
    clock.advance(2)
    expect((await edge.flush())[0]).toMatchObject({ state: 'retry', tries: 3 })
    clock.advance(4)
    expect((await edge.flush())[0]).toMatchObject({ state: 'published', tries: 4 })
  })

  it('treats a client that throws something other than a RelayError as no response', async () => {
    const relay = new ScriptedRelay()
    relay.script.push(new TypeError('fetch failed'))
    const { edge } = setup({ relay, records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets[0]).toMatchObject({ state: 'retry', reason: 'unreachable' })
  })

  it('publishes a target that a crash left publishing, and never one already in flight', async () => {
    let release: (r: PublishResult) => void = () => {}
    let reached: () => void = () => {}
    const publishing = new Promise<void>((r) => {
      reached = r
    })
    const relay = new ScriptedRelay()
    const slow: RelayClient = {
      ...relay,
      publish: (url, bytes) => {
        relay.published.push({ url, bytes })
        reached()
        return new Promise((resolve) => {
          release = resolve
        })
      },
      fetch: relay.fetch,
      fetchRecord: relay.fetchRecord,
      subscribe: relay.subscribe,
    }
    const { edge, store } = setup({ relay: slow, records: directory() })
    const sending = edge.send({ to: [P.carol.address], type: 't', body: 1 })
    // The target is in flight only once send has reached publish; wait for that call, not for a guessed delay.
    await publishing
    expect(await edge.flush()).toEqual([])
    release(ok)
    const sent = await sending
    expect(relay.published).toHaveLength(1)
    const [target] = store.outboxTargets(sent.id)
    store.outboxPut(startTry({ ...(target as NonNullable<typeof target>), state: 'retry' }, T0))
    const flushing = edge.flush()
    // The guard looks the relay's name up first (it is not one of the edge's own relays), so the publish starts later.
    while (relay.published.length < 2) await new Promise((r) => setTimeout(r, 1))
    release(ok)
    expect((await flushing)[0]).toMatchObject({ state: 'published', tries: 2 })
  })

  it('reads a sealing key from a key record when the address record has none, and falls back for relays', async () => {
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { sealing_key: null }))
    records.put(HOME, keyRecord(P.bob))
    records.put(R1, keyRecord(P.carol))
    const relay = new ScriptedRelay()
    const { edge } = setup({ relay, records })
    const toBob = await edge.send({ to: [P.bob.address], type: 't', body: 1 })
    expect(toBob.targets.map((t) => t.relay)).toEqual([HOME])
    const toCarol = await edge.send({ to: [P.carol.address], type: 't', body: 1, relays: [R1] })
    expect(toCarol.targets.map((t) => t.relay)).toEqual([R1])
    const env = parseEnvelope(relay.published[1]?.bytes as Uint8Array)
    expect(openSealed(env, { address: P.carol.address, key: P.carol.sealing }).body).toBe(1)
  })

  it('refuses with resolve-failed when a recipient has no sealing key, or there is no relay, persisting nothing', async () => {
    const { edge, store, audit } = setup({ records: directory() })
    await expect(edge.send({ to: [P.mallory.address], type: 't', body: 1 })).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    expect(audit.steps().at(-1)).toBe('resolve reject resolve-failed')
    const none = setup({ records: new FakeRecords(), urls: [] })
    await expect(none.edge.send({ to: [P.bob.address], type: 't', body: 1 })).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    const lonely = new FakeRecords()
    lonely.put('http://only.test', keyRecord(P.bob))
    const noRelay = setup({ records: lonely, urls: [] })
    await expect(
      noRelay.edge.send({ to: [P.bob.address], type: 't', body: 1, relays: ['http://only.test'] }),
    ).resolves.toMatchObject({ targets: [{ relay: 'http://only.test' }] })
    await expect(noRelay.edge.send({ to: [P.bob.address], type: 't', body: 1 })).rejects.toMatchObject({
      code: 'resolve-failed',
      message: 'resolve-failed: no relay to publish to',
    })
    expect(store.outboxDue(T0 + 10 ** 6)).toEqual([])
  })

  it('refuses to resend an envelope it never sent, and resends nothing that has not failed', async () => {
    const relay = new ScriptedRelay()
    const { edge } = setup({ relay, records: directory() })
    await expect(edge.resend('ef'.repeat(32))).rejects.toThrow('outbox: no envelope')
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(await edge.resend(sent.id)).toEqual([])
    expect(relay.published).toHaveLength(1)
  })

  it('does not count a fault after a publish as a failed publish: the target stays publishing for flush', async () => {
    const relay = new ScriptedRelay()
    const sink = new MemoryAuditSink()
    const store = new SqliteStore(':memory:')
    const failing = {
      append: (line: string) => {
        if (line.includes('"event":"publish"')) throw new Error('disk full')
        sink.append(line)
      },
      last: () => sink.last(),
    }
    const edge = new Edge({
      keys: P.session.keys,
      store,
      relays: { client: relay, urls: [HOME] },
      records: directory(),
      policy: { roots: [], types: ['*'] },
      clock: new FakeClock(),
      rng: seededRng('fault'),
      audit: failing,
    })
    await expect(edge.send({ to: [P.carol.address], type: 't', body: 1 })).rejects.toThrow('disk full')
    expect(relay.published).toHaveLength(1)
    const [entry] = store.outboxDue(T0)
    expect(entry?.target).toMatchObject({ state: 'publishing', tries: 0 })
  })

  it('binds a new thread to the sending session', async () => {
    const { edge, store } = setup({ records: directory() })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1, session: 'coder-1' })
    expect(store.threadGet(sent.thread.id)).toBe('coder-1')
    expect(store.outboxGet(sent.id)?.session).toBe('coder-1')
  })

  it('refuses a target on a private address at once, with no request, unless it is an own relay or private relays are allowed', async () => {
    const records = new FakeRecords()
    const local = 'http://127.0.0.1:6379/'
    records.put(HOME, addressRecord(P.carol, { relays: [local, R2] }))
    const relay = new ScriptedRelay()
    const { edge, audit } = setup({ relay, records })
    const sent = await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    expect(sent.targets.map((t) => [t.relay, t.state, t.tries, t.reason])).toEqual([
      [local, 'failed', 1, 'resolve-failed'],
      [R2, 'published', 1, null],
    ])
    expect(relay.published.map((p) => p.url)).toEqual([R2])
    const refused = audit.lines.map((l) => JSON.parse(l)).find((l) => l.reason === 'resolve-failed')
    expect([refused.event, refused.decision, JSON.parse(refused.detail)]).toEqual([
      'publish',
      'reject',
      { relay: local, tries: 1, refused: 'loopback' },
    ])
    // A name that resolves only to private addresses is refused as well, and so is one with any private address among
    // public ones (as the core's judgeAddresses).
    const lan = setup({ relay, records, lookup: async () => ['192.168.1.20', 'fd00::5'] })
    expect((await lan.edge.send({ to: [P.carol.address], type: 't', body: 2 })).targets[1]).toMatchObject({
      relay: R2,
      state: 'failed',
      reason: 'resolve-failed',
    })
    const mixed = setup({ relay, records, lookup: async () => ['10.0.0.1', '1.1.1.1'] })
    expect((await mixed.edge.send({ to: [P.carol.address], type: 't', body: 3 })).targets[1]).toMatchObject({
      relay: R2,
      state: 'failed',
      reason: 'resolve-failed',
    })
    // The edge's own relay on a loopback address, and anything with allowPrivateRelays, are called.
    const own = setup({ relay, records, urls: [HOME, local] })
    expect((await own.edge.send({ to: [P.carol.address], type: 't', body: 4 })).targets[0]).toMatchObject({
      relay: local,
      state: 'published',
    })
    const open = setup({ relay, records, allowPrivateRelays: true })
    expect((await open.edge.send({ to: [P.carol.address], type: 't', body: 5 })).targets[0]).toMatchObject({
      relay: local,
      state: 'published',
    })
  })

  it('signs as the session, with the chain from the principal', async () => {
    const hop = signHop(P.jane.signing, P.session.address, [], T0 + 60)
    const relay = new ScriptedRelay()
    const { edge } = setup({ relay, records: directory(), auth: [hop] })
    await edge.send({ to: [P.carol.address], type: 't', body: 1 })
    const env = parseEnvelope(relay.published[0]?.bytes as Uint8Array)
    expect(verifyChain(env.auth, env.from, env.ts)).toEqual({
      root: P.jane.address,
      principal: P.jane.address,
      caveats: [],
    })
  })
})
