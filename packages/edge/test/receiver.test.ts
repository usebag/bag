import {
  buildEnvelope,
  type CaveatEvaluator,
  codingEvaluator,
  type Hop,
  type MembersRecord,
  newThread,
  replyThread,
  signHop,
  type Thread,
  type TimeWindow,
  utf8,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import type { TrustedRoot } from '../src/policy.ts'
import type { EdgeStore, InboundMessage, InboxRow, SessionHandler, SpawnHook } from '../src/ports.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  seededRng,
  T0,
  text,
} from './support/fixtures.ts'
import { members } from './support/org.ts'
import { MemoryRelay, ScriptedRelay } from './support/relays.ts'

const HOME = 'http://home.test'
const ACME = 'acme.test'
const rng = coreRng(seededRng('receiver'))

interface Built {
  readonly id: string
  readonly bytes: Uint8Array
  readonly thread: Thread
}

function envelope(
  o: {
    from?: Party
    to?: readonly Party[]
    auth?: readonly Hop[]
    type?: string
    body?: unknown
    thread?: Thread
    ts?: number
    sealWith?: Party
  } = {},
): Built {
  const thread = o.thread ?? newThread(rng)
  const to = (o.to ?? [P.bob]).map((p) => ({
    address: p.address,
    sealingKey: (o.sealWith ?? p).sealing.publicKey,
  }))
  const built = buildEnvelope({
    from: (o.from ?? P.carol).signing,
    to,
    auth: o.auth ?? [],
    type: o.type ?? 'chat.v1',
    thread,
    body: o.body ?? { text: 'hello' },
    ts: o.ts ?? T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes, thread }
}

/** Bob's edge: it trusts carol by key and acme.test by domain, honors the coding evaluator, accepts chat and coding. */
function bob(
  o: {
    roots?: TrustedRoot[]
    types?: string[]
    evaluators?: CaveatEvaluator[]
    records?: FakeRecords
    window?: TimeWindow
    spawn?: SpawnHook
    store?: EdgeStore
    audit?: MemoryAuditSink
    doorbell?: () => void
    accepted?: (row: InboxRow) => void
    onError?: (error: unknown) => void
    members?: MembersRecord
  } = {},
) {
  const audit = o.audit ?? new MemoryAuditSink()
  const clock = new FakeClock()
  const store = o.store ?? new SqliteStore(':memory:')
  const records = o.records ?? acme()
  const edge = new Edge({
    keys: P.bob.keys,
    store,
    relays: { client: new ScriptedRelay(), urls: [HOME] },
    records,
    policy: {
      roots: o.roots ?? [{ address: P.carol.address }, { domain: ACME }],
      types: o.types ?? ['chat.*', 'coding.*'],
      evaluators: o.evaluators ?? [codingEvaluator],
      ...(o.members === undefined ? {} : { members: o.members }),
    },
    clock,
    rng: seededRng('bob'),
    audit,
    ...(o.window === undefined ? {} : { window: o.window }),
    ...(o.spawn === undefined ? {} : { spawn: o.spawn }),
    ...(o.doorbell === undefined ? {} : { doorbell: o.doorbell }),
    ...(o.accepted === undefined ? {} : { accepted: o.accepted }),
    ...(o.onError === undefined ? {} : { onError: o.onError }),
  })
  return { edge, store, audit, clock, records }
}

/** acme.test's well-known record (the org key), revoking mallory, and carol's address record at the home relay. */
function acme(revoked: readonly string[] = [P.mallory.address]): FakeRecords {
  const records = new FakeRecords()
  records.domain(ACME, addressRecord(P.org, { relays: [HOME], revoked, ttl: 86_400 }))
  records.put(HOME, addressRecord(P.carol))
  return records
}

/** The chain org -> jane -> session, with the caveats each hop adds. */
function chain(orgCaveats: readonly string[] = [], janeCaveats: readonly string[] = []): Hop[] {
  return [
    signHop(P.org.signing, P.jane.address, orgCaveats, T0 + 86_400),
    signHop(P.jane.signing, P.session.address, janeCaveats, T0 + 3600),
  ]
}

function handler(session: string, into: InboundMessage[]): SessionHandler {
  return { session, deliver: (m) => void into.push(m) }
}

function tamper(bytes: Uint8Array, edit: (v: Record<string, unknown>) => void): Uint8Array {
  const v = JSON.parse(text(bytes)) as Record<string, unknown>
  edit(v)
  return utf8(JSON.stringify(v))
}

describe('Receiver: verify -> policy -> dedup -> unseal -> caveats -> route (spec/SPEC.md §9.2, §9.3)', () => {
  it('accepts a self-rooted sender trusted by key, queues it with no handler, and audits every step', async () => {
    const { edge, audit } = bob()
    const e = envelope()
    const row = await edge.receive(HOME, 1, e.bytes)
    expect(row).toMatchObject({
      state: 'queued',
      id: e.id,
      reason: null,
      session: null,
      relay: HOME,
      cursor: 1,
    })
    expect(JSON.parse(row.content as string)).toEqual({
      type: 'chat.v1',
      thread: e.thread,
      body: { text: 'hello' },
    })
    expect(audit.steps()).toEqual([
      'verify accept ok',
      'policy accept ok',
      'dedup accept ok',
      'unseal accept ok',
      'policy accept ok',
      'route queue ok',
    ])
    expect(verifyAuditLog(audit.lines)).toEqual({ ok: true, lines: 6 })
  })

  it('accepts a cross-org chain org -> principal -> session with coding caveats, and pins the root', async () => {
    const { edge, store, audit } = bob()
    const got: InboundMessage[] = []
    edge.setDefault(handler('inbox', got))
    const auth = chain(['type=coding.*'], ['repo=bag'])
    const e = envelope({
      from: P.session,
      auth,
      type: 'coding.task.v1',
      body: { repo: 'bag', task: 'x' },
    })
    const row = await edge.receive(HOME, 1, e.bytes)
    expect(row).toMatchObject({ state: 'routed', session: 'inbox' })
    expect(got[0]).toMatchObject({
      id: e.id,
      from: P.session.address,
      principal: P.jane.address,
      root: P.org.address,
      to: [P.bob.address],
      type: 'coding.task.v1',
      caveats: ['type=coding.*', 'repo=bag'],
      relay: HOME,
    })
    expect(store.pinGet(`domain:${ACME}`)?.key).toBe(P.org.address)
    expect(audit.steps()).toContain('pin accept ok')
    expect(store.threadGet(e.thread.id)).toBe('inbox')
  })

  it('rejects bytes that do not parse, and a member of the wrong shape', async () => {
    const { edge } = bob()
    expect(await edge.receive(HOME, 1, utf8('not json'))).toMatchObject({
      state: 'rejected',
      reason: 'bad-json',
      id: null,
    })
    const bad = tamper(envelope().bytes, (v) => {
      v.ts = 'soon'
    })
    expect(await edge.receive(HOME, 2, bad)).toMatchObject({ state: 'rejected', reason: 'bad-shape' })
  })

  it('rejects a stale ts and a future ts, with the window of TTL + skew', async () => {
    const { edge, audit } = bob()
    const stale = envelope({ ts: T0 - (604_800 + 300) - 1 })
    expect(await edge.receive(HOME, 1, stale.bytes)).toMatchObject({
      state: 'rejected',
      reason: 'stale-ts',
      id: stale.id,
    })
    // future-ts is transient: the row waits for a retry (below).
    expect(await edge.receive(HOME, 2, envelope({ ts: T0 + 301 }).bytes)).toMatchObject({
      state: 'received',
      reason: 'future-ts',
      tries: 1,
    })
    expect(await edge.receive(HOME, 3, envelope({ ts: T0 - 604_800 - 300 }).bytes)).toMatchObject({
      state: 'queued',
    })
    expect(await edge.receive(HOME, 4, envelope({ ts: T0 + 300 }).bytes)).toMatchObject({ state: 'queued' })
    const line = JSON.parse(audit.lines[0] as string)
    expect(line).toMatchObject({
      event: 'verify',
      decision: 'reject',
      reason: 'stale-ts',
      id: stale.id,
      from: P.carol.address,
    })
  })

  it('rejects a bad signature and an id that does not recompute', async () => {
    const { edge } = bob()
    const e = envelope()
    const badSig = tamper(e.bytes, (v) => {
      const sig = v.sig as string
      v.sig = `${sig.slice(0, 10)}${sig[10] === '0' ? '1' : '0'}${sig.slice(11)}`
    })
    expect(await edge.receive(HOME, 1, badSig)).toMatchObject({ state: 'rejected', reason: 'bad-sig' })
    const badId = tamper(e.bytes, (v) => {
      v.ts = T0 + 1
    })
    expect(await edge.receive(HOME, 2, badId)).toMatchObject({ state: 'rejected', reason: 'bad-id' })
  })

  it('rejects an envelope for another mailbox: not a recipient', async () => {
    const { edge } = bob()
    expect(await edge.receive(HOME, 1, envelope({ to: [P.jane] }).bytes)).toMatchObject({
      state: 'rejected',
      reason: 'not-recipient',
    })
  })

  it('rejects an untrusted root, and a chain that fails its rules', async () => {
    const { edge, audit } = bob()
    expect(await edge.receive(HOME, 1, envelope({ from: P.mallory }).bytes)).toMatchObject({
      state: 'rejected',
      reason: 'untrusted-root',
    })
    expect(JSON.parse(audit.lines.at(-1) as string)).toMatchObject({
      event: 'policy',
      root: P.mallory.address,
    })
    const expired = [
      signHop(P.org.signing, P.jane.address, [], T0 - 1),
      signHop(P.jane.signing, P.session.address, [], T0 - 1),
    ]
    expect(await edge.receive(HOME, 2, envelope({ from: P.session, auth: expired }).bytes)).toMatchObject({
      reason: 'hop-expired',
    })
    expect(JSON.parse(audit.lines.at(-1) as string)).toMatchObject({ event: 'policy', root: null })
  })

  it("rejects a chain whose hop names a key the root's current record revokes", async () => {
    const { edge } = bob({ records: acme([P.jane.address]) })
    expect(await edge.receive(HOME, 1, envelope({ from: P.session, auth: chain() }).bytes)).toMatchObject({
      state: 'rejected',
      reason: 'revoked',
    })
    const viaSession = bob({ records: acme([P.session.address]) })
    expect(
      await viaSession.edge.receive(HOME, 1, envelope({ from: P.session, auth: chain() }).bytes),
    ).toMatchObject({
      reason: 'revoked',
    })
  })

  it('rejects a root whose domain now shows another key without a valid rotation: pin mismatch', async () => {
    const records = acme()
    const { edge, clock } = bob({ records })
    expect(await edge.receive(HOME, 1, envelope({ from: P.session, auth: chain() }).bytes)).toMatchObject({
      state: 'queued',
    })
    records.domain(ACME, addressRecord(P.orgNext, { iat: T0 + 2 * 86_400, rotated_from: P.org.address }))
    clock.advance(2 * 86_400)
    const next = [
      signHop(P.orgNext.signing, P.jane.address, [], T0 + 3 * 86_400),
      signHop(P.jane.signing, P.session.address, [], T0 + 3 * 86_400),
    ]
    expect(
      await edge.receive(HOME, 2, envelope({ from: P.session, auth: next, ts: T0 + 2 * 86_400 }).bytes),
    ).toMatchObject({ state: 'rejected', reason: 'pin-mismatch' })
  })

  it('holds with resolve-failed, for a retry, when the root has hops but no record to read revocations from', async () => {
    const { edge } = bob({ roots: [{ address: P.jane.address }] })
    const hop = signHop(P.jane.signing, P.session.address, [], T0 + 60)
    expect(await edge.receive(HOME, 1, envelope({ from: P.session, auth: [hop] }).bytes)).toMatchObject({
      state: 'received',
      reason: 'resolve-failed',
      tries: 1,
      nextAt: T0 + 1,
    })
    const down = new FakeRecords()
    down.domain(ACME, new Error('unreachable'))
    const org = bob({ records: down })
    expect(await org.edge.receive(HOME, 1, envelope({ from: P.session, auth: chain() }).bytes)).toMatchObject(
      {
        state: 'received',
        reason: 'resolve-failed',
      },
    )
  })

  it('leaves a row received when a local fault, not a verdict, stops the policy step', async () => {
    const store = new SqliteStore(':memory:')
    const { edge } = bob({ store })
    const failing = new Proxy(store, {
      get(target, key) {
        if (key === 'cacheGet') {
          return () => {
            throw new Error('disk I/O error')
          }
        }
        const value = Reflect.get(target, key) as unknown
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const broken = bob({ store: failing })
    const e = envelope({ from: P.session, auth: chain() })
    await expect(broken.edge.receive(HOME, 1, e.bytes)).rejects.toThrow('disk I/O error')
    expect(store.inboxFind(HOME, P.bob.address, 1)?.state).toBe('received')
    expect((await edge.receiver.recover()).map((r) => r.state)).toEqual(['queued'])
  })

  it('reads the revoked list of a root trusted by key from its address record', async () => {
    const records = acme()
    records.put(HOME, addressRecord(P.jane, { revoked: [P.session.address] }))
    const { edge } = bob({ roots: [{ address: P.jane.address }], records })
    const hop = signHop(P.jane.signing, P.session.address, [], T0 + 60)
    expect(await edge.receive(HOME, 1, envelope({ from: P.session, auth: [hop] }).bytes)).toMatchObject({
      reason: 'revoked',
    })
    const clean = acme()
    clean.put(HOME, addressRecord(P.jane))
    const ok = bob({ roots: [{ address: P.jane.address }], records: clean })
    expect(await ok.edge.receive(HOME, 1, envelope({ from: P.session, auth: [hop] }).bytes)).toMatchObject({
      state: 'queued',
    })
  })

  it('takes another id at a used cursor as a new envelope: stored, checked and delivered, the old row untouched', async () => {
    const { edge, store, audit } = bob()
    const [first, second] = [envelope(), envelope()]
    const held = await edge.receive(HOME, 5, first.bytes)
    expect(held).toMatchObject({ id: first.id, state: 'queued' })
    edge.receiver.ack(held)

    // A relay restored from an older copy issues cursor 5 again, to another envelope (spec/SPEC.md §9 item 2).
    const fresh = await edge.receive(HOME, 5, second.bytes)
    expect(fresh).toMatchObject({ id: second.id, state: 'queued', cursor: 5 })
    expect(fresh.seq).not.toBe(held.seq)
    expect(store.inboxAt(HOME, P.bob.address, 5).map((r) => [r.id, r.state])).toEqual([
      [first.id, 'acked'],
      [second.id, 'queued'],
    ])
    expect(store.inboxFind(HOME, P.bob.address, 5)?.id).toBe(second.id)
    expect(audit.steps().filter((s) => s === 'dedup reject duplicate')).toEqual([])
    expect(edge.receiver.ack(fresh).state).toBe('acked')
  })

  it('keeps the same id at one cursor as one row, whichever of two rows there it is, and dedups it at another', async () => {
    const { edge, store, audit } = bob()
    const [first, second] = [envelope(), envelope()]
    edge.receiver.ack(await edge.receive(HOME, 5, first.bytes))
    edge.receiver.ack(await edge.receive(HOME, 5, second.bytes))
    audit.lines.length = 0
    expect(await edge.receive(HOME, 5, first.bytes)).toMatchObject({ id: first.id, state: 'acked' })
    expect(await edge.receive(HOME, 5, second.bytes)).toMatchObject({ id: second.id, state: 'acked' })
    expect(store.inboxAt(HOME, P.bob.address, 5)).toHaveLength(2)
    expect(audit.steps()).toEqual([])
    expect(await edge.receive(HOME, 6, first.bytes)).toMatchObject({ state: 'rejected', reason: 'duplicate' })
    expect(store.inboxList()).toHaveLength(3)
  })

  it('takes one id in other bytes at a used cursor as the same envelope', async () => {
    const { edge, store } = bob()
    const e = envelope()
    const spaced = utf8(`${new TextDecoder().decode(e.bytes)}\n`)
    expect(spaced).not.toEqual(e.bytes)
    edge.receiver.ack(await edge.receive(HOME, 5, e.bytes))
    expect(await edge.receive(HOME, 5, spaced)).toMatchObject({ id: e.id, state: 'acked' })
    expect(store.inboxAt(HOME, P.bob.address, 5)).toHaveLength(1)
  })

  it('gives bytes that do not parse a row of their own at a used cursor, refused there, in either order', async () => {
    const { edge, store } = bob()
    const e = envelope()
    edge.receiver.ack(await edge.receive(HOME, 5, e.bytes))
    expect(await edge.receive(HOME, 5, utf8('not an envelope'))).toMatchObject({
      state: 'rejected',
      id: null,
    })
    expect(store.inboxFind(HOME, P.bob.address, 5)).toMatchObject({ state: 'rejected', reason: 'bad-json' })
    expect(await edge.receive(HOME, 5, utf8('not an envelope'))).toMatchObject({ state: 'rejected' })
    const later = envelope()
    expect(await edge.receive(HOME, 5, later.bytes)).toMatchObject({ id: later.id, state: 'queued' })
    expect(store.inboxAt(HOME, P.bob.address, 5).map((r) => r.state)).toEqual(['acked', 'rejected', 'queued'])
  })

  it('finishes the right row of two at one cursor after a crash', async () => {
    const store = new SqliteStore(':memory:')
    const audit = new MemoryAuditSink()
    const [first, second] = [envelope(), envelope()]
    const before = bob({ store, audit })
    before.edge.receiver.ack(await before.edge.receive(HOME, 5, first.bytes))
    store.inboxAdd(HOME, P.bob.address, 5, second.bytes, T0)
    const done = await bob({ store, audit }).edge.receiver.recover()
    expect(done.map((r) => [r.id, r.state])).toEqual([[second.id, 'queued']])
    expect(store.inboxAt(HOME, P.bob.address, 5).map((r) => [r.id, r.state])).toEqual([
      [first.id, 'acked'],
      [second.id, 'acked'],
    ])
  })

  it('rejects a duplicate by id, through any relay and cursor, until the dedup window ends', async () => {
    const window = { ttl: 100, skew: 10 }
    const { edge, clock, store, audit } = bob({ window })
    const e = envelope()
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'queued' })
    expect(await edge.receive('http://other.test', 1, e.bytes)).toMatchObject({
      state: 'rejected',
      reason: 'duplicate',
    })
    expect(audit.steps().at(-1)).toBe('dedup reject duplicate')
    clock.t = T0 + 110
    expect(await edge.receive(HOME, 2, e.bytes)).toMatchObject({ reason: 'duplicate' })
    expect(store.seenPrune(T0 + 110)).toBe(0)
    clock.t = T0 + 111
    expect(await edge.receive(HOME, 3, e.bytes)).toMatchObject({ reason: 'stale-ts' })
    expect(store.seenPrune(T0 + 111)).toBe(1)
  })

  it('keeps an id seen past a ts ahead of its first sight, so the window covers every ts it accepts', async () => {
    const { edge, clock } = bob({ window: { ttl: 100, skew: 10 } })
    const e = envelope({ ts: T0 + 10 })
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'queued' })
    clock.t = T0 + 120
    expect(await edge.receive(HOME, 2, e.bytes)).toMatchObject({ reason: 'duplicate' })
    clock.t = T0 + 121
    expect(await edge.receive(HOME, 3, e.bytes)).toMatchObject({ reason: 'stale-ts' })
  })

  it('rejects what does not open: a wrap sealed to another key', async () => {
    const { edge, store } = bob()
    const e = envelope({ sealWith: P.jane })
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'rejected', reason: 'open-failed' })
    expect(store.seenHas(e.id, T0)).toBe(true)
  })

  it('rejects an unknown caveat (fail closed) and a caveat that fails, after unsealing', async () => {
    const { edge, audit } = bob()
    const unknown = envelope({ from: P.session, auth: chain(['budget=5']), type: 'coding.task.v1' })
    expect(await edge.receive(HOME, 1, unknown.bytes)).toMatchObject({
      state: 'rejected',
      reason: 'unknown-caveat',
    })
    expect(JSON.parse(JSON.parse(audit.lines.at(-1) as string).detail)).toMatchObject({ caveat: 'budget=5' })
    const failed = envelope({ from: P.session, auth: chain(['type=coding.*']), type: 'chat.v1' })
    expect(await edge.receive(HOME, 2, failed.bytes)).toMatchObject({ reason: 'caveat-failed' })
    const none = bob({ evaluators: [] })
    expect(
      await none.edge.receive(HOME, 1, envelope({ from: P.session, auth: chain(['type=chat.*']) }).bytes),
    ).toMatchObject({
      reason: 'unknown-caveat',
    })
  })

  it('rejects a type it does not accept', async () => {
    const { edge, audit } = bob({ types: ['coding.*'] })
    expect(await edge.receive(HOME, 1, envelope({ type: 'chat.v1' }).bytes)).toMatchObject({
      state: 'rejected',
      reason: 'type-not-accepted',
    })
    expect(JSON.parse(JSON.parse(audit.lines.at(-1) as string).detail)).toMatchObject({ type: 'chat.v1' })
    const any = bob({ types: ['*'] })
    expect(await any.edge.receive(HOME, 1, envelope({ type: 'anything' }).bytes)).toMatchObject({
      state: 'queued',
    })
  })

  it('routes a reply to the handler registered for its thread, and a root to the default handler', async () => {
    const { edge, store } = bob()
    const mine: InboundMessage[] = []
    const fallback: InboundMessage[] = []
    const thread = newThread(rng)
    edge.register(thread.id, handler('coder-1', mine))
    edge.setDefault(handler('inbox', fallback))
    const first = envelope({ thread })
    expect(await edge.receive(HOME, 1, first.bytes)).toMatchObject({ state: 'routed', session: 'coder-1' })
    const reply = envelope({ thread: replyThread(thread, [first.id]) })
    expect(await edge.receive(HOME, 2, reply.bytes)).toMatchObject({ state: 'routed', session: 'coder-1' })
    expect(await edge.receive(HOME, 3, envelope().bytes)).toMatchObject({ state: 'routed', session: 'inbox' })
    expect(mine.map((m) => m.thread.prev)).toEqual([[], [first.id]])
    expect(fallback).toHaveLength(1)
    expect(store.threadGet(thread.id)).toBe('coder-1')
  })

  it('asks the spawn hook for a root on an unknown thread when there is no default handler', async () => {
    const got: InboundMessage[] = []
    const asked: string[] = []
    const spawn: SpawnHook = {
      onUnroutedThread: async (ctx) => {
        asked.push(ctx.message.type)
        return ctx.message.type === 'chat.spawn' ? handler('worker-1', got) : null
      },
    }
    const { edge, store } = bob({ spawn })
    const e = envelope({ type: 'chat.spawn' })
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'routed', session: 'worker-1' })
    expect(store.threadGet(e.thread.id)).toBe('worker-1')
    expect(await edge.receive(HOME, 2, envelope({ type: 'chat.v1' }).bytes)).toMatchObject({
      state: 'queued',
    })
    expect(asked).toEqual(['chat.spawn', 'chat.v1'])
    const throwing = bob({ spawn: { onUnroutedThread: async () => Promise.reject(new Error('no')) } })
    expect(await throwing.edge.receive(HOME, 1, envelope().bytes)).toMatchObject({ state: 'queued' })
  })

  it('queues a reply on an unknown thread, a thread whose session is not live, and what a handler throws on', async () => {
    const { edge, audit } = bob()
    edge.setDefault(handler('inbox', []))
    const stray = envelope({ thread: replyThread(newThread(rng), ['ab'.repeat(32)]) })
    expect(await edge.receive(HOME, 1, stray.bytes)).toMatchObject({ state: 'queued' })
    const thread = newThread(rng)
    edge.register(thread.id, handler('gone', []))
    edge.router.detach('gone')
    expect(await edge.receive(HOME, 2, envelope({ thread }).bytes)).toMatchObject({ state: 'queued' })
    const angry = newThread(rng)
    edge.register(angry.id, {
      session: 'angry',
      deliver: () => {
        throw new Error('handler bug')
      },
    })
    expect(await edge.receive(HOME, 3, envelope({ thread: angry }).bytes)).toMatchObject({
      state: 'queued',
      session: null,
    })
    expect(JSON.parse(JSON.parse(audit.lines.at(-1) as string).detail)).toMatchObject({
      error: 'the handler threw',
    })
  })

  it('returns the row of a redelivered frame without handling it again', async () => {
    const { edge, audit } = bob()
    const got: InboundMessage[] = []
    edge.setDefault(handler('inbox', got))
    const e = envelope()
    const first = await edge.receive(HOME, 1, e.bytes)
    const lines = audit.lines.length
    const acked = edge.receiver.ack(first)
    expect(acked.state).toBe('acked')
    expect(edge.receiver.ack(acked)).toEqual(acked)
    expect(await edge.receive(HOME, 1, e.bytes)).toEqual(acked)
    expect(got).toHaveLength(1)
    expect(audit.lines.length).toBe(lines)
  })

  it('rings the doorbell, then calls accepted, once per accepted row when the store acks it; never for a refusal, a wait or a second ack', async () => {
    // The doorbell and accepted fire in ack, at the routed-or-queued to acked transition.
    const events: string[] = []
    const seam = {
      doorbell: () => void events.push('ring'),
      accepted: (r: InboxRow) => void events.push(`accepted ${r.seq} ${r.state}`),
    }
    const { edge, store } = bob(seam)
    const first = envelope()
    const routed = await edge.receive(HOME, 1, first.bytes)
    // Routed is not yet delivered: nothing fires before the ack.
    expect([routed.state, events]).toEqual(['queued', []])
    expect(edge.receiver.ack(routed).state).toBe('acked')
    expect(events).toEqual(['ring', `accepted ${routed.seq} queued`])
    // A second ack of the stale copy, the same frame again and its ack, a duplicate at another cursor, an untrusted
    // root and a type not accepted, each acked: nothing more fires.
    expect(edge.receiver.ack(routed)).toEqual(store.inboxGet(routed.seq))
    edge.receiver.ack(await edge.receive(HOME, 1, first.bytes))
    for (const [cursor, e] of [
      [2, first],
      [3, envelope({ from: P.mallory })],
      [4, envelope({ type: 'other.v1' })],
    ] as const) {
      const row = await edge.receive(HOME, cursor, e.bytes)
      expect(row.state).toBe('rejected')
      expect(edge.receiver.ack(row).state).toBe('acked')
    }
    expect(events).toHaveLength(2)
    // A second accepted row fires again, once.
    const fifth = await edge.receive(HOME, 5, envelope().bytes)
    edge.receiver.ack(fifth)
    expect(events.slice(2)).toEqual(['ring', `accepted ${fifth.seq} queued`])
    // A row that waits for a retry (resolve-failed) fires nothing when acked; made due again, recover() accepts it,
    // acks it and fires once, returning it as it was before the ack.
    const quiet: string[] = []
    const waits = bob({
      roots: [{ address: P.jane.address }],
      doorbell: () => void quiet.push('ring'),
      accepted: (r) => void quiet.push(`accepted ${r.state}`),
    })
    const hop = signHop(P.jane.signing, P.session.address, [], T0 + 60)
    const row = await waits.edge.receive(HOME, 1, envelope({ from: P.session, auth: [hop] }).bytes)
    expect([row.state, row.reason, waits.edge.receiver.ack(row).state, quiet]).toEqual([
      'received',
      'resolve-failed',
      'received',
      [],
    ])
    waits.records.put(HOME, addressRecord(P.jane))
    waits.clock.t = T0 + 1
    expect((await waits.edge.receiver.recover()).map((r) => r.state)).toEqual(['queued'])
    expect([quiet, waits.store.inboxGet(row.seq)?.state]).toEqual([['ring', 'accepted queued'], 'acked'])
  })

  it('a release and the rows recover() finishes ring and fire accepted once; a hold and a drop fire nothing', async () => {
    const events: string[] = []
    const seam = {
      doorbell: () => void events.push('ring'),
      accepted: (r: InboxRow) => void events.push(`accepted ${r.id}`),
    }
    const unknownHeld = members({ roots: { mode: 'allow', list: [P.carol.address], unknown: 'quarantine' } })
    const roots = [{ address: P.carol.address }, { address: P.mallory.address }]
    const { edge } = bob({ members: unknownHeld, roots, ...seam })
    const kept = envelope({ from: P.mallory })
    const held = await edge.receive(HOME, 1, kept.bytes)
    const dropped = await edge.receive(HOME, 2, envelope({ from: P.mallory }).bytes)
    expect([held.state, edge.receiver.ack(held).state, events]).toEqual(['quarantined', 'quarantined', []])
    expect(edge.receiver.drop(dropped.seq).state).toBe('acked')
    expect(events).toEqual([])
    expect((await edge.receiver.release(held.seq)).state).toBe('acked')
    expect(events).toEqual(['ring', `accepted ${kept.id}`])
    // Rows a crash left verified, and routed but not acked: recover() finishes and acks both, each firing once, and
    // returns them as they were before the ack; a second recover() finds nothing.
    const store = new SqliteStore(':memory:')
    const audit = new MemoryAuditSink()
    const [verified, routed] = [envelope(), envelope()]
    const before = bob({ store, audit })
    await before.edge.receive(HOME, 1, verified.bytes)
    const one = store.inboxFind(HOME, P.bob.address, 1)
    store.inboxPut(one as NonNullable<typeof one>, { state: 'verified' }, T0)
    expect((await before.edge.receive(HOME, 2, routed.bytes)).state).toBe('queued')
    events.length = 0
    const again = bob({ store, audit, ...seam })
    const done = await again.edge.receiver.recover()
    expect(done.map((r) => [r.id, r.state])).toEqual([
      [verified.id, 'queued'],
      [routed.id, 'queued'],
    ])
    expect(events).toEqual(['ring', `accepted ${verified.id}`, 'ring', `accepted ${routed.id}`])
    expect(store.inboxList().map((r) => r.state)).toEqual(['acked', 'acked'])
    // Another mailbox's row in the same store (a group's, CLI inbox --group) is its own receiver's: left as it is.
    store.inboxAdd(HOME, P.other.address, 7, envelope().bytes, T0)
    expect(await again.edge.receiver.recover()).toEqual([])
    expect(store.inboxList().map((r) => [r.mailbox, r.state])).toEqual([
      [P.bob.address, 'acked'],
      [P.bob.address, 'acked'],
      [P.other.address, 'received'],
    ])
    // A caller that acks a returned row again (the CLI's recover loop did) fires nothing.
    for (const r of done) again.edge.receiver.ack(r)
    expect(events).toHaveLength(4)
  })

  it('a doorbell or accepted callback that throws goes to onError, loses its own call, and leaves the row acked', async () => {
    const ringDown = (): void => {
      throw new Error('ring failed')
    }
    const acceptedDown = (): void => {
      throw new Error('accepted failed')
    }
    // A doorbell that throws: accepted is still called, once, and the error reaches onError.
    const events: string[] = []
    const errors: unknown[] = []
    const a = bob({
      doorbell: ringDown,
      accepted: (r: InboxRow) => void events.push(`accepted ${r.seq}`),
      onError: (e: unknown) => void errors.push(e),
    })
    const routed = await a.edge.receive(HOME, 1, envelope().bytes)
    expect(a.edge.receiver.ack(routed).state).toBe('acked')
    expect([events, errors.map(String), a.store.inboxGet(routed.seq)?.state]).toEqual([
      [`accepted ${routed.seq}`],
      ['Error: ring failed'],
      'acked',
    ])
    // An accepted that throws: the doorbell rang first, the error reaches onError, the row stays acked, and a second
    // ack fires and reports nothing more.
    const rung: string[] = []
    const problems: unknown[] = []
    const b = bob({
      doorbell: () => void rung.push('ring'),
      accepted: acceptedDown,
      onError: (e: unknown) => void problems.push(e),
    })
    const second = await b.edge.receive(HOME, 1, envelope().bytes)
    expect(b.edge.receiver.ack(second).state).toBe('acked')
    expect(b.edge.receiver.ack(second).state).toBe('acked')
    expect([rung, problems.map(String), b.store.inboxGet(second.seq)?.state]).toEqual([
      ['ring'],
      ['Error: accepted failed'],
      'acked',
    ])
    // With no onError set, a throwing callback still does not throw out of ack.
    const c = bob({ doorbell: ringDown, accepted: acceptedDown })
    expect(c.edge.receiver.ack(await c.edge.receive(HOME, 1, envelope().bytes)).state).toBe('acked')
  })

  it('throws for the ack of a row whose seq the store does not hold', async () => {
    const { edge } = bob()
    const routed = await edge.receive(HOME, 1, envelope().bytes)
    const { edge: empty } = bob()
    expect(() => empty.receiver.ack(routed)).toThrow('is not in the store')
  })

  it('finishes rows a crash left received or verified', async () => {
    const store = new SqliteStore(':memory:')
    // One audit log across the restart, as on disk: a new edge refuses a log that is shorter than its anchor.
    const audit = new MemoryAuditSink()
    const a = envelope()
    const b = envelope()
    store.inboxAdd(HOME, P.bob.address, 1, a.bytes, T0)
    const first = bob({ store, audit })
    await first.edge.receive(HOME, 2, b.bytes)
    const row = store.inboxFind(HOME, P.bob.address, 2)
    store.inboxPut(row as NonNullable<typeof row>, { state: 'verified' }, T0)
    const got: InboundMessage[] = []
    const again = bob({ store, audit })
    again.edge.setDefault(handler('inbox', got))
    const done = await again.edge.receiver.recover()
    expect(done.map((r) => [r.cursor, r.state])).toEqual([
      [1, 'routed'],
      [2, 'routed'],
    ])
    expect(got.map((m) => m.id)).toEqual([a.id, b.id])
  })

  it('runs a subscription: each frame is handled, then acked, and it resumes after the last ack', async () => {
    const relay = new MemoryRelay()
    const store = new SqliteStore(':memory:')
    const audit = new MemoryAuditSink()
    const edge = new Edge({
      keys: P.bob.keys,
      store,
      relays: { client: relay, urls: [HOME] },
      records: acme(),
      policy: { roots: [{ address: P.carol.address }], types: ['*'] },
      clock: new FakeClock(),
      rng: seededRng('run'),
      audit,
    })
    const got: InboundMessage[] = []
    edge.setDefault(handler('inbox', got))
    for (let i = 0; i < 3; i++) await relay.publish(HOME, envelope().bytes)
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    while (got.length < 3) await new Promise((r) => setTimeout(r, 1))
    // The loop finishes the frame it is on (handle, then ack) before it sees the abort, so once `running` settles the
    // third frame is acked; no sleep stands in for that.
    abort.abort()
    await running
    expect(store.inboxLastAcked(HOME, P.bob.address)).toBe(3)
    expect(relay.acks.get(`${HOME} ${P.bob.address} ${P.bob.address}`)).toBe(3)
    await relay.publish(HOME, envelope().bytes)
    const sub = relay.subscribe(
      HOME,
      P.bob.address,
      P.bob.signing,
      [],
      store.inboxLastAcked(HOME, P.bob.address),
    )
    expect(sub.start).toBe(3)
    sub.close()
    const second = edge.receiver.run(HOME)
    while (got.length < 4) await new Promise((r) => setTimeout(r, 1))
    for (const s of relay.subs) s.close()
    await second
    expect(store.inboxList(['acked']).map((r) => r.cursor)).toEqual([1, 2, 3, 4])
  })
})
