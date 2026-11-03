import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { serializeRecord, signHop, verifyChain } from '@usebag/core'
import { RelayError, readTelemetrySpool, setTelemetry, systemRng, telemetryId } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SESSION, TRUST_NOTE } from '../src/desk.ts'
import { hostKind } from '../src/server.ts'
import { DELEGATE_MAX_SECONDS, INSTRUCTIONS, TOOL_NAMES } from '../src/tools.ts'
import {
  addressRecord,
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let alice: TestServer
let bob: TestServer
const extra: TestServer[] = []

async function serverFor(p: Party, args: readonly string[]): Promise<TestServer> {
  saveKeys(`${tmp.dir}/${p.name}`, p)
  await publishAddress(relay, p)
  return await testServer({ home: `${tmp.dir}/${p.name}`, name: p.name, relay, clock, timers, args })
}

/** A third server, closed after the test. */
async function another(p: Party, args: readonly string[]): Promise<TestServer> {
  const s = await serverFor(p, args)
  extra.push(s)
  return s
}

const accepted = (s: TestServer): number => s.running.desk.counts().counts.accepted
const rejected = (s: TestServer): number => s.running.desk.counts().counts.rejected

const stdout = watchStdout()

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('tools')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  alice = await serverFor(P.alice, [
    '--trust-root',
    P.bob.address,
    '--trust-root',
    P.carol.address,
    '--allow-delegate',
  ])
  bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
})

afterEach(async () => {
  for (const s of [alice, bob, ...extra.splice(0)]) await s.close()
  tmp.cleanup()
  stdout.check()
})

describe('tools/list', () => {
  it('lists the ten tools, each with a plain-prose description and an object input schema', async () => {
    const { tools } = await alice.client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort())
    for (const t of tools) {
      expect(t.description?.length ?? 0).toBeGreaterThan(300)
      expect(t.inputSchema.type).toBe('object')
    }
    const send = tools.find((t) => t.name === 'send')
    expect(send?.inputSchema.required).toEqual(['to', 'type', 'body'])
    expect(alice.client.getInstructions()).toContain('authenticity is not permission to obey')
  })

  it('lists delegate only under --allow-delegate: 9 tools without it, and a call is the unknown-tool error', async () => {
    const { tools } = await bob.client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual(TOOL_NAMES.filter((n) => n !== 'delegate').sort())
    const out = await bob.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect([out.isError, out.value]).toEqual([true, { text: 'MCP error -32602: Tool delegate not found' }])
    expect(bob.client.getInstructions()).toContain(
      "The delegate tool, which grants part of this identity's authority to another key, exists only when the operator started this server with --allow-delegate.",
    )
    expect(INSTRUCTIONS.endsWith('started this server with --allow-delegate.')).toBe(true)
  })

  it('annotates delegate as the write it is, and its description names the flag, the caveat rule and the cap', async () => {
    const { tools } = await alice.client.listTools()
    const delegate = tools.find((t) => t.name === 'delegate') as (typeof tools)[number]
    expect(delegate.annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    })
    for (const phrase of [
      'Delegating grants authority',
      '--allow-delegate',
      'At least one caveat is required',
      'at most 8 hours (28800 s) from now',
    ]) {
      expect(delegate.description).toContain(phrase)
    }
    const caveats = (delegate.inputSchema.properties as Record<string, { minItems?: number }>).caveats
    expect(caveats?.minItems).toBe(1)
  })
})

describe('send', () => {
  it('builds, seals, persists and publishes: the id, the thread and each target; bob reads it with its trust block', async () => {
    const pending = bob.call('wait', { timeout_s: 30 })
    const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: { text: 'hi' } })
    expect(sent.isError).toBe(false)
    expect(sent.value).toEqual({
      id: expect.stringMatching(/^[0-9a-f]{64}$/),
      thread: { id: expect.stringMatching(/^[0-9a-f]{64}$/), prev: [] },
      targets: [{ relay: RELAY, status: 'published', tries: 1, reason: null, next_at: null }],
      retrying: false,
      reason: null,
    })
    expect(sent.result.structuredContent).toEqual(sent.value)
    const id = sent.value.id as string
    const thread = sent.value.thread as { id: string }
    const got = await pending
    expect(got.value).toEqual({
      message: {
        cursor: 1,
        id,
        from: P.alice.address,
        principal: P.alice.address,
        root: P.alice.address,
        handle: null,
        type: 'chat.v1',
        body: { text: 'hi' },
        thread: { id: thread.id, prev: [] },
        received_at: new Date(T0 * 1000).toISOString(),
        relay: RELAY,
        trust: { root: P.alice.address, chain_hops: 0, caveats: [], verified: true },
        handed_off_to: null,
        reply: { to: [P.alice.address], thread: { id: thread.id, prev: [id] } },
        from_name: null,
        principal_name: null,
        warning: null,
      },
      note: TRUST_NOTE,
    })
    expect(alice.running.opened.store.threadGet(thread.id)).toBe(SESSION)
  })

  it("answers in the thread with the received message's reply field, and the answer is routed to the opener", async () => {
    const opened = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    await until('bob has it', () => accepted(bob) === 1)
    const inbox = await bob.call('inbox')
    const [m] = inbox.value.messages as { reply: Record<string, unknown> }[]
    const answer = await bob.call('send', { ...m?.reply, type: 'chat.v1', body: 2 })
    expect(answer.value.thread).toEqual({
      id: (opened.value.thread as { id: string }).id,
      prev: [opened.value.id],
    })
    await until('alice has it', () => accepted(alice) === 1)
    expect(alice.running.desk.counts().counts).toMatchObject({ accepted: 1, routed: 1, queued: 0 })
    expect(bob.running.desk.counts().counts).toMatchObject({ accepted: 1, routed: 0, queued: 1 })
  })

  it("refuses a bad address (bad-address), a bad thread (bad-thread) and an input that breaks the schema (the SDK's error)", async () => {
    const bad = await alice.call('send', { to: ['Bob!'], type: 'chat.v1', body: {} })
    expect([bad.isError, bad.value]).toEqual([
      true,
      { error: 'bad-address', detail: 'to "Bob!" is neither an address, a handle nor a name' },
    ])
    const thread = await alice.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: {},
      thread: { id: 'a'.repeat(64), prev: ['x'] },
    })
    expect(thread.value).toEqual({ error: 'bad-thread', detail: 'each parent is an envelope id (64 hex)' })
    const schema = await alice.call('send', { to: [P.bob.address], body: {} })
    expect(schema.isError).toBe(true)
    expect(schema.value.text).toMatch(/Input validation error/)
  })

  it('keeps a send to a recipient with no record waiting, naming the relays tried, also when the relay cannot be reached for one', async () => {
    const none = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    const until = T0 + 604_800
    expect([none.isError, none.value]).toEqual([
      false,
      {
        waiting: true,
        thread: { id: expect.stringMatching(/^[0-9a-f]{64}$/), prev: [] },
        to: [P.carol.address],
        tried: [RELAY],
        reason: `address:${P.carol.address} from relay; tried ${RELAY} (none)`,
        next_at: T0 + 1,
        until,
        hint: `the recipient's address record was not found at the relays tried; it is retried until ${new Date(until * 1000).toISOString()}; lookup shows where records live`,
      },
    ])
    relay.failRecords = new RelayError(null, 0, null, 'connection refused')
    const down = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect(down.value).toMatchObject({
      waiting: true,
      reason: `address:${P.carol.address} from relay; tried ${RELAY} (unreachable)`,
      hint: expect.stringMatching(
        /^the relay refused the connection or could not be reached, so the recipient's record could not be read; it is retried until /,
      ),
    })
  })

  it("fails with the relay's code when the relay refuses for good, and reports retry when it cannot be reached", async () => {
    relay.failPublish.set(RELAY, new RelayError('root-not-accepted', 403, null, 'refused'))
    const refused = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: {} })
    expect(refused.isError).toBe(true)
    expect(refused.value).toEqual({
      error: 'root-not-accepted',
      detail: expect.stringMatching(
        /^http:\/\/relay\.test did not take envelope [0-9a-f]{64}; its bytes stay/,
      ),
    })
    // A 403 root-not-accepted names the next step, with this identity's root.
    expect(refused.value.detail).toMatch(
      new RegExp(
        `; the recipient has not paired with this identity, and its relays take mail only from peers it paired with: your user and the recipient's person pair first \\(pair_invite or pair_accept\\), then send again\\. In an org, the recipient adds ${P.alice.address} or the org's domain root to its accept-from record instead, or you send under a chain from a root it accepts \\(send --auth / delegate\\)`,
      ),
    )
    relay.failPublish.set(RELAY, new RelayError(null, 0, null, 'connection refused'))
    const later = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: {} })
    expect([later.isError, later.value.retrying, later.value.targets]).toEqual([
      false,
      true,
      [
        {
          relay: RELAY,
          status: 'retry',
          tries: 1,
          reason: 'unreachable',
          next_at: T0 + 1,
        },
      ],
    ])
    expect([later.value.reason, later.value.detail]).toEqual(['unreachable', undefined])
  })

  it('returns the targets when one relay refuses and another publishes', async () => {
    const two = 'http://second.test'
    await relay.publish(RELAY, serializeRecord(addressRecord(P.carol, [RELAY, two])))
    relay.failPublish.set(two, new RelayError('not-hosted', 403, null, 'no mailbox'))
    const sent = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect([sent.isError, sent.value.targets]).toEqual([
      false,
      [
        { relay: RELAY, status: 'published', tries: 1, reason: null, next_at: null },
        { relay: two, status: 'failed', tries: 1, reason: 'not-hosted', next_at: null },
      ],
    ])
    expect([sent.value.reason, 'detail' in sent.value]).toEqual([null, false])
  })
})

describe('inbox', () => {
  async function three(): Promise<string[]> {
    const ids: string[] = []
    for (const n of [1, 2, 3]) {
      const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: { n } })
      ids.push(sent.value.id as string)
      clock.t += 100
    }
    await until('three at bob', () => accepted(bob) === 3)
    return ids
  }

  it('pages oldest first with limit, more and next_cursor, and lists nothing new after the last cursor', async () => {
    const ids = await three()
    const first = await bob.call('inbox', { limit: 2 })
    expect(first.value).toMatchObject({ more: true, next_cursor: 2, note: TRUST_NOTE })
    expect((first.value.messages as { id: string }[]).map((m) => m.id)).toEqual(ids.slice(0, 2))
    const rest = await bob.call('inbox', { since: first.value.next_cursor })
    expect(rest.value).toMatchObject({ more: false, next_cursor: 3 })
    expect((rest.value.messages as { id: string }[]).map((m) => m.id)).toEqual([ids[2]])
    expect((await bob.call('inbox', { since: 3 })).value).toMatchObject({
      messages: [],
      next_cursor: 3,
      more: false,
    })
  })

  it('reads from an ISO time and by thread, and refuses a since that is neither a cursor nor a time', async () => {
    const ids = await three()
    const later = await bob.call('inbox', { since: new Date((T0 + 150) * 1000).toISOString() })
    expect((later.value.messages as { id: string }[]).map((m) => m.id)).toEqual([ids[2]])
    const all = (await bob.call('inbox')).value.messages as { thread: { id: string } }[]
    const one = await bob.call('inbox', { thread: all[1]?.thread.id })
    expect((one.value.messages as { id: string }[]).map((m) => m.id)).toEqual([ids[1]])
    expect((await bob.call('inbox', { since: 'yesterday' })).value).toEqual({
      error: 'usage',
      detail: 'since is a cursor or an ISO time, not "yesterday"',
    })
    expect((await bob.call('inbox', { thread: 'abc' })).value).toMatchObject({ error: 'bad-thread' })
  })

  it('never lists a rejected message: status counts it by code', async () => {
    const carol = await another(P.carol, ['--trust-root', P.bob.address])
    const refused = await carol.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: { from: 'carol' },
    })
    expect(refused.isError).toBe(false)
    await until('the rejection at bob', () => rejected(bob) === 1)
    expect((await bob.call('inbox')).value).toMatchObject({ messages: [], next_cursor: 1 })
    expect((await bob.call('status')).value).toMatchObject({
      counts: { accepted: 0, rejected: 1, unread: 0 },
      rejected_by_code: { 'untrusted-root': 1 },
    })
  })
})

describe('wait', () => {
  it('returns a message that arrived before the call at once, unless inbox returned it first', async () => {
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'early' })
    await until('bob has it', () => accepted(bob) === 1)
    expect(bob.running.desk.counts().counts.unread).toBe(1)
    const early = await bob.call('wait', { timeout_s: 30 })
    expect((early.value.message as { body: unknown }).body).toBe('early')
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'read' })
    await until('bob has the second', () => accepted(bob) === 2)
    await bob.call('inbox', { since: 1 })
    const none = bob.call('wait', { timeout_s: 5 })
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([5000])
    timers.fire()
    expect((await none).value).toEqual({
      timed_out: true,
      pending: false,
      resume: `r1.2.${T0 + 5}.any`,
    })
  })

  it('waits on one thread: other messages stay unread, and the thread is bound to the server first', async () => {
    const thread = 'c'.repeat(64)
    const waiting = bob.call('wait', { thread, timeout_s: 30 })
    await until('the wait is pending', () => timers.live().length === 1)
    expect(bob.running.opened.store.threadGet(thread)).toBe(SESSION)
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'other' })
    await until('the other is unread', () => bob.running.desk.counts().counts.unread === 1)
    await alice.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: 'on it',
      thread: { id: thread, prev: [] },
    })
    const got = await waiting
    expect(got.value.message).toMatchObject({ body: 'on it', thread: { id: thread } })
    const other = await bob.call('wait', { timeout_s: 0 })
    expect((other.value.message as { body: unknown }).body).toBe('other')
  })

  it('settles when the client cancels the request, and refuses a bad thread', async () => {
    const abort = new AbortController()
    const cancelled = bob.call('wait', { timeout_s: 300 }, abort.signal)
    await until('the wait is pending', () => timers.live().length === 1)
    abort.abort()
    await expect(cancelled).rejects.toThrow()
    await until('the server let go of it', () => timers.live().length === 0)
    expect((await bob.call('wait', { thread: 'nope', timeout_s: 1 })).value).toMatchObject({
      error: 'bad-thread',
    })
    expect((await bob.call('wait', { timeout_s: 301 })).isError).toBe(true)
  })
})

describe('ask', () => {
  it('sends question.v1 on a new thread and returns the first message on it: the answer bob sends', async () => {
    const question = bob.call('wait', { timeout_s: 30 })
    const asked = alice.call('ask', { to: P.bob.address, body: { q: 'ready?' }, timeout_s: 30 })
    const q = (await question).value.message as {
      id: string
      thread: { id: string }
      reply: { thread: unknown }
    }
    expect(q).toMatchObject({ type: 'question.v1', body: { q: 'ready?' }, thread: { prev: [] } })
    await bob.call('send', {
      to: [P.alice.address],
      thread: q.reply.thread,
      type: 'answer.v1',
      body: { a: 'yes' },
    })
    const a = await asked
    expect(a.value).toEqual({
      answer: expect.objectContaining({
        type: 'answer.v1',
        body: { a: 'yes' },
        from: P.bob.address,
        thread: { id: q.thread.id, prev: [q.id] },
        trust: { root: P.bob.address, chain_hops: 0, caveats: [], verified: true },
      }),
      question: {
        id: q.id,
        thread: { id: q.thread.id, prev: [] },
        targets: [{ relay: RELAY, status: 'published', tries: 1, reason: null, next_at: null }],
        retrying: false,
        reason: null,
      },
      note: TRUST_NOTE,
    })
  })

  it('times out with the question, and the late answer is still read with wait on its thread', async () => {
    const asked = alice.call('ask', { to: P.bob.address, body: 'q', timeout_s: 2 })
    await until('the ask waits', () => timers.live().length === 1)
    timers.fire()
    const out = await asked
    expect(out.value).toMatchObject({ timed_out: true, pending: false, question: { thread: { prev: [] } } })
    const { id, thread } = out.value.question as { id: string; thread: { id: string } }
    await until('bob has the question', () => accepted(bob) === 1)
    await bob.call('send', {
      to: [P.alice.address],
      thread: { id: thread.id, prev: [id] },
      type: 'answer.v1',
      body: 'a',
    })
    const late = await alice.call('wait', { thread: thread.id, timeout_s: 30 })
    expect(late.value.message).toMatchObject({ body: 'a', thread: { id: thread.id, prev: [id] } })
  })

  it('refuses a bad address, and fails without waiting when the relay refuses the question', async () => {
    expect((await alice.call('ask', { to: 'X', body: 1, timeout_s: 1 })).value).toMatchObject({
      error: 'bad-address',
    })
    relay.failPublish.set(RELAY, new RelayError('too-large-for-mailbox', 403, null, 'big'))
    const refused = await alice.call('ask', { to: P.bob.address, body: 1, timeout_s: 30 })
    expect([refused.isError, refused.value.error, timers.live()]).toEqual([true, 'too-large-for-mailbox', []])
  })
})

describe('handoff', () => {
  it('sends handoff.v1 with the threads and the note, and later messages on them queue with handed_off_to', async () => {
    const carol = await another(P.carol, ['--trust-root', P.alice.address])
    const opened = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'start' })
    const thread = (opened.value.thread as { id: string }).id
    const handed = await alice.call('handoff', {
      to: P.carol.address,
      threads: [thread, thread],
      note: 'yours now',
    })
    expect(handed.value).toMatchObject({ handed_off: [thread], targets: [{ status: 'published' }] })
    expect(alice.running.opened.store.threadGet(thread)).toBe(`handoff:${P.carol.address}`)
    const got = await carol.call('wait', { timeout_s: 30 })
    expect(got.value.message).toMatchObject({
      type: 'handoff.v1',
      body: { threads: [thread], note: 'yours now' },
      from: P.alice.address,
    })
    await bob.call('send', {
      to: [P.alice.address],
      type: 'chat.v1',
      body: 'more',
      thread: { id: thread, prev: [opened.value.id] },
    })
    await until('alice has it', () => accepted(alice) === 1)
    expect(alice.running.desk.counts().counts).toMatchObject({ accepted: 1, routed: 0, queued: 1 })
    const inbox = await alice.call('inbox')
    expect(inbox.value.messages).toEqual([
      expect.objectContaining({ body: 'more', handed_off_to: P.carol.address }),
    ])
  })

  it('sends a handoff without a note, refuses a bad thread id, and marks nothing when the send fails', async () => {
    const thread = 'd'.repeat(64)
    const plain = await alice.call('handoff', { to: P.bob.address, threads: [thread] })
    expect(plain.isError).toBe(false)
    const got = await bob.call('wait', { timeout_s: 30 })
    expect((got.value.message as { body: unknown }).body).toEqual({ threads: [thread] })
    expect((await alice.call('handoff', { to: P.bob.address, threads: ['x'] })).value).toMatchObject({
      error: 'bad-thread',
    })
    const other = 'e'.repeat(64)
    const failed = await alice.call('handoff', { to: P.carol.address, threads: [other] })
    expect([failed.value.error, alice.running.opened.store.threadGet(other)]).toEqual([
      'resolve-failed',
      null,
    ])
  })
})

describe('delegate', () => {
  it('signs one hop from a self-rooted identity, with its caveats and an expiry in seconds or +N', async () => {
    const out = await alice.call('delegate', { to: P.carol.address, caveats: ['type=chat.*'], exp: T0 + 600 })
    expect(out.value).toEqual({
      chain: [expect.objectContaining({ iss: P.alice.address, sub: P.carol.address, exp: T0 + 600 })],
      root: P.alice.address,
      principal: P.alice.address,
      hops: 1,
      exp: T0 + 600,
      caveats: ['type=chat.*'],
      reply_to: P.alice.address,
    })
    expect(verifyChain(out.value.chain as never, P.carol.address, T0).root).toBe(P.alice.address)
    const relative = await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect(relative.value.exp).toBe(T0 + 60)
  })

  it('extends a chain whose last subject is this identity, and surfaces the core codes otherwise', async () => {
    const granted = [signHop(P.org.keys.signing, P.alice.address, ['repo=a'], T0 + 3600)]
    const out = await alice.call('delegate', {
      to: P.carol.address,
      caveats: ['type=x'],
      exp: '+60',
      chain: granted,
    })
    expect(out.value).toMatchObject({
      root: P.org.address,
      principal: P.alice.address,
      hops: 2,
      caveats: ['repo=a', 'type=x'],
    })
    const toBob = [signHop(P.org.keys.signing, P.bob.address, [], T0 + 3600)]
    const codes = [
      await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60', chain: toBob }),
      await alice.call('delegate', {
        to: P.carol.address,
        caveats: ['repo=x'],
        exp: T0 + 7200,
        chain: granted,
      }),
      await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: T0 - 1 }),
      await alice.call('delegate', { to: P.carol.address, caveats: [''], exp: '+60' }),
      await alice.call('delegate', {
        to: P.carol.address,
        caveats: ['repo=x'],
        exp: '+60',
        chain: [{ iss: 1 }],
      }),
      await alice.call('delegate', { to: 'carol', caveats: ['repo=x'], exp: '+60' }),
      await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: 'tomorrow' }),
    ]
    expect(codes.map((c) => c.value.error)).toEqual([
      'chain-broken',
      'exp-not-monotone',
      'hop-expired',
      'bad-hop',
      'bad-hop',
      'bad-address',
      'usage',
    ])
  })

  it('refuses an empty caveat list by its schema, naming the rule, and signs nothing', async () => {
    const out = await alice.call('delegate', { to: P.carol.address, caveats: [], exp: '+60' })
    expect(out.isError).toBe(true)
    expect(out.value.chain).toBeUndefined()
    expect(String(out.value.text)).toMatch(
      /^MCP error -32602: Input validation error: Invalid arguments for tool delegate: /,
    )
    expect(String(out.value.text)).toContain('delegate needs at least one caveat; [] is refused')
    const one = await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect(one.value).toMatchObject({ hops: 1, caveats: ['repo=x'] })
  })

  it('caps the expiry at 8 hours from now, before any signature, on a hop and on a chain extension', async () => {
    expect(DELEGATE_MAX_SECONDS).toBe(28_800)
    const call = (exp: number | string, chain?: unknown[]) =>
      alice.call('delegate', {
        to: P.carol.address,
        caveats: ['repo=x'],
        exp,
        ...(chain === undefined ? {} : { chain }),
      })
    const cap = (exp: number, now = T0) => ({
      error: 'usage',
      detail:
        `exp ${exp} is ${exp - now} s from now, past the cap of 28800 s (8 hours) on a hop the delegate tool signs` +
        ': pass an expiry at most 8 hours from now',
    })
    // One second past the cap, as Unix seconds and as +N: usage naming it; the cap itself passes.
    expect((await call(T0 + 28_801)).value).toEqual(cap(T0 + 28_801))
    expect((await call('+28801')).value).toEqual(cap(T0 + 28_801))
    expect((await call(T0 + 28_800)).value).toMatchObject({ hops: 1, exp: T0 + 28_800 })
    expect((await call('+28800')).value).toMatchObject({ hops: 1, exp: T0 + 28_800 })
    // An expiry that is no safe integer is past the cap too, before signHop's shape check could see it.
    expect((await call('+9999999999999999999')).value).toMatchObject({ error: 'usage' })
    // The cap is from the clock: an hour later, the same Unix expiry passes and one 8 hours past the new now does not.
    clock.t = T0 + 3600
    expect((await call(T0 + 28_801)).value).toMatchObject({ hops: 1, exp: T0 + 28_801 })
    expect((await call(T0 + 3600 + 28_801)).value).toEqual(cap(T0 + 3600 + 28_801, T0 + 3600))
    clock.t = T0
    // A chain that allows a day: the new hop is still capped at 8 hours from now.
    const day = [signHop(P.org.keys.signing, P.alice.address, ['repo=a'], T0 + 86_400)]
    expect((await call(T0 + 28_801, day)).value).toEqual(cap(T0 + 28_801))
    expect((await call('+28800', day)).value).toMatchObject({ hops: 2, exp: T0 + 28_800 })
    // A chain that ends within the hour: past its earliest exp is the core's chain rule 7, exp-not-monotone.
    const hour = [signHop(P.org.keys.signing, P.alice.address, ['repo=a'], T0 + 3600)]
    expect((await call(T0 + 3601, hour)).value).toMatchObject({ error: 'exp-not-monotone' })
  })
})

describe('status', () => {
  it('names the identity, its relays, roots and policy; counts the mailbox; reads the audit seq; and the uptime', async () => {
    const fresh = await alice.call('status')
    expect(fresh.value).toEqual({
      address: P.alice.address,
      mailbox: P.alice.address,
      principal: P.alice.address,
      root: P.alice.address,
      chain_hops: 0,
      relays: [RELAY],
      trust_roots: [P.bob.address, P.carol.address],
      honor: [],
      accept_types: ['*'],
      default_handler: 'queue',
      max_tool_seconds: 25,
      progress_seconds: 15,
      names: [],
      trust_file: 0,
      counts: { accepted: 0, routed: 0, queued: 0, rejected: 0, quarantined: 0, in_flight: 0, unread: 0 },
      rejected_by_code: {},
      last_audit_seq: 0,
      edge_errors: 0,
      last_edge_error: null,
      subscriptions: [{ relay: RELAY, state: 'subscribed', refusals: 0, last_code: null, last_at: null }],
      chain: null,
      keep_alive: null,
      receipts_to: [],
      started_at: new Date(T0 * 1000).toISOString(),
      uptime_s: 0,
      waiting: [],
      peers: [],
      policy: { counts: [], quarantined: 0, pending: 0 },
      doorbell_path: join(tmp.dir, 'alice', 'state', 'alice', 'doorbell'),
      telemetry: { on: false, reason: 'no-file', choice: null },
      telemetry_counts: null,
      network: { https: null, http: null, no_proxy: null, active: false },
    })
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 1 })
    await until('alice has it', () => accepted(alice) === 1)
    clock.t += 90
    const later = await alice.call('status')
    expect(later.value).toMatchObject({
      counts: { accepted: 1, routed: 0, queued: 1, unread: 1 },
      uptime_s: 90,
    })
    expect(later.value.last_audit_seq).toBeGreaterThan(0)
  })

  it('counts an edge error: a subscription the relay refuses ends, and status says so', async () => {
    relay.failSubscribe = new RelayError('not-authorized', 0, null, 'refused')
    relay.wakeAll()
    await until('the edge error', () => alice.log.lines.some((l) => l.event === 'edge-error'))
    expect((await alice.call('status')).value).toMatchObject({
      edge_errors: 1,
      last_edge_error: { code: 'not-authorized', at: new Date(T0 * 1000).toISOString() },
    })
    relay.failSubscribe = null
  })

  it("reads the machine's telemetry switch (HOME/.bag) at each call, not its home's; never shows the install id or makes the notice's mark; the environment only turns it off", async () => {
    const HOME = join(tmp.dir, 'machine')
    const dir = join(HOME, '.bag')
    const server = async (p: Party, env: Record<string, string>): Promise<TestServer> => {
      saveKeys(join(tmp.dir, p.name), p)
      const s = await testServer({ home: join(tmp.dir, p.name), name: p.name, relay, clock, timers, env })
      extra.push(s)
      return s
    }
    const state = async (s: TestServer) => (await s.call('status')).value.telemetry
    const carol = await server(P.carol, { HOME })
    expect(await state(carol)).toEqual({ on: false, reason: 'no-file', choice: null })
    setTelemetry(dir, 'on', systemRng)
    const on = (await carol.call('status')).value
    expect(on.telemetry).toEqual({ on: true, reason: 'file', choice: 'on' })
    expect(JSON.stringify(on)).not.toContain(telemetryId(dir) as string)
    // A choice in the identity's own home is not read.
    setTelemetry(join(tmp.dir, 'carol'), 'off', systemRng)
    expect(await state(carol)).toEqual({ on: true, reason: 'file', choice: 'on' })
    // A person's yes under DO_NOT_TRACK stays off.
    const jane = await server(P.jane, { HOME, DO_NOT_TRACK: '1' })
    expect(await state(jane)).toEqual({ on: false, reason: 'DO_NOT_TRACK', choice: 'on' })
    setTelemetry(dir, 'off', systemRng)
    expect(await state(carol)).toEqual({ on: false, reason: 'file', choice: 'off' })
    expect(existsSync(join(dir, 'telemetry-noticed-2'))).toBe(false)
  })

  it("counts tool calls by tool and code with a duration bucket each, and its session by host kind, into the machine's store while telemetry is on; status shows today's raw, never the id; close writes what it holds", async () => {
    const HOME = join(tmp.dir, 'machine')
    const dir = join(HOME, '.bag')
    setTelemetry(dir, 'on', systemRng)
    const home = join(tmp.dir, 'carol')
    saveKeys(home, P.carol)
    const s = await testServer({ home, name: 'carol', relay, clock, timers, env: { HOME } })
    try {
      await s.call('status')
      const sent = await s.call('send', { to: ['nobody'], type: 'chat.v1', body: 1 })
      expect(sent.value.error).toBe('name-unknown')
      const shown = (await s.call('status')).value
      expect(JSON.stringify(shown)).not.toContain(telemetryId(dir) as string)
      const counts = shown.telemetry_counts as Record<string, number>
      // The SDK client here is named mcp-test: neither Claude Code nor Codex.
      expect(counts).toMatchObject({ 'sessions other': 1, 'mcp status ok': 1, 'mcp send name-unknown': 1 })
      const names = ['claude-code', 'Claude Desktop', 'codex-mcp-client', 'mcp-test', undefined]
      expect(names.map((n) => hostKind(n))).toEqual(['claude-code', 'other', 'codex', 'other', 'other'])
      const sum = (tool: string) =>
        Object.entries(counts).reduce((a, [k, n]) => a + (k.startsWith(`mcp_durations ${tool} `) ? n : 0), 0)
      expect([sum('status'), sum('send'), Object.keys(counts).length]).toEqual([1, 1, 5])
    } finally {
      await s.close()
    }
    // The close wrote what the process held: the last status call.
    const day = new Date(T0 * 1000).toISOString().slice(0, 10)
    expect(readTelemetrySpool(dir).get(day)?.get('mcp status ok')).toBe(2)
  })
})

describe('send: unreachable, a try with no answer from its relay (the edge with unreachableReason)', () => {
  it('names only the targets whose relay gave no answer unreachable, and the result when every target is so; an answer without a code stays publish-failed', async () => {
    const two = 'http://second.test'
    await relay.publish(RELAY, serializeRecord(addressRecord(P.carol, [RELAY, two])))
    relay.failPublish.set(two, new RelayError(null, 0, null, 'connection refused'))
    const one = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect(one.value).toMatchObject({
      targets: [
        { relay: RELAY, status: 'published', reason: null },
        { relay: two, status: 'retry', tries: 1, reason: 'unreachable', next_at: T0 + 1 },
      ],
      retrying: true,
      reason: null,
    })
    relay.failPublish.set(RELAY, new RelayError(null, 0, null, 'timed out'))
    const none = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect([none.isError, none.value.reason, none.value.retrying]).toEqual([false, 'unreachable', true])
    // A relay that answered, even with a failure that is not a refusal (503 without a code), is publish-failed.
    relay.failPublish.set(RELAY, new RelayError(null, 503, null, 'unavailable'))
    const answered = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect(answered.value).toMatchObject({
      targets: [
        { relay: RELAY, status: 'retry', reason: 'publish-failed' },
        { relay: two, status: 'retry', reason: 'unreachable' },
      ],
      reason: null,
    })
    // A client that throws something other than a RelayError gave no answer either.
    relay.failPublish.set(RELAY, new Error('a fault in the client') as RelayError)
    const thrown = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: {} })
    expect(thrown.value).toMatchObject({ reason: 'unreachable' })
    // A try with no answer has the reason unreachable in its audit line too, with the cause in its detail; the 503
    // that answered keeps publish-failed (spec/SPEC.md §9 item 8: a code from Appendix A, which names unreachable;
    // Appendix B item 35).
    const lines = readFileSync(join(alice.running.opened.stateDir, 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { event: string; decision: string; reason: string; detail: string | null })
    const retries = lines.filter((l) => l.event === 'publish' && l.decision === 'retry')
    const reasons = retries.map((l) => [l.reason, JSON.parse(l.detail as string).cause ?? null])
    expect(reasons).toContainEqual(['unreachable', 'unreachable'])
    expect(reasons).toContainEqual(['publish-failed', null])
    expect(reasons.filter(([, cause]) => cause === 'unreachable').every(([r]) => r === 'unreachable')).toBe(
      true,
    )
  })
})

describe("--allow-private-relays: the guard on a peer's relay at a private address that is not one of --relay", () => {
  it('refuses the send resolve-failed without the flag, and publishes at that relay with it', async () => {
    const lan = 'http://10.1.2.3:7777'
    await relay.publish(RELAY, serializeRecord(addressRecord(P.carol, [lan])))
    const refused = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'over the lan' })
    expect(refused.isError).toBe(true)
    expect(refused.value).toEqual({
      error: 'resolve-failed',
      detail: expect.stringMatching(
        /^http:\/\/10\.1\.2\.3:7777 did not take envelope [0-9a-f]{64}; its bytes stay/,
      ),
    })
    expect(relay.published).not.toContain(lan)
    const org = await another(P.org, ['--allow-private-relays'])
    const sent = await org.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'over the lan' })
    expect([sent.isError, sent.value.targets]).toEqual([
      false,
      [{ relay: lan, status: 'published', tries: 1, reason: null, next_at: null }],
    ])
    expect(relay.published).toContain(lan)
  })
})

describe('inbox: the handed_off filter', () => {
  it('lists all messages, those on threads not handed off, or only those on threads handed off', async () => {
    await another(P.carol, ['--trust-root', P.alice.address])
    const opened = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'start' })
    const thread = (opened.value.thread as { id: string }).id
    await alice.call('handoff', { to: P.carol.address, threads: [thread] })
    await bob.call('send', {
      to: [P.alice.address],
      type: 'chat.v1',
      body: 'on the handed-off thread',
      thread: { id: thread, prev: [opened.value.id] },
    })
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'elsewhere' })
    await until('alice has both', () => accepted(alice) === 2)
    const bodies = async (handed_off?: string): Promise<unknown[]> => {
      const page = await alice.call('inbox', handed_off === undefined ? {} : { handed_off })
      return (page.value.messages as { body: unknown }[]).map((m) => m.body)
    }
    expect(await bodies()).toEqual(['on the handed-off thread', 'elsewhere'])
    expect(await bodies('include')).toEqual(['on the handed-off thread', 'elsewhere'])
    expect(await bodies('exclude')).toEqual(['elsewhere'])
    expect(await bodies('only')).toEqual(['on the handed-off thread'])
    expect((await alice.call('inbox', { handed_off: 'some' })).isError).toBe(true)
  })
})

describe('names: the local name book in send, ask, inbox, wait and status', () => {
  /** Writes a home's names.json as the CLI's name command does. */
  const book = (who: string, names: Record<string, unknown>): void =>
    writeFileSync(join(tmp.dir, who, 'names.json'), JSON.stringify({ version: 1, names }))
  const ref = (name: string) => ({ name, former: false, warning: null })

  it('sends and asks by name, lists the names in status, and names a known sender in wait, inbox and the answer', async () => {
    book('alice', {
      bob: { address: P.bob.address, added_at: T0 },
      carl: { address: P.carol.address, added_at: T0 },
    })
    book('bob', { alice: { address: P.alice.address, added_at: T0 } })
    expect((await alice.call('status')).value.names).toEqual([
      { name: 'bob', address: P.bob.address },
      { name: 'carl', address: P.carol.address },
    ])
    const sent = await alice.call('send', { to: ['bob'], type: 'chat.v1', body: 'by name' })
    expect(sent.value).toMatchObject({ targets: [{ status: 'published' }] })
    const got = (await bob.call('wait', { timeout_s: 30 })).value.message as Record<string, unknown>
    expect(got).toMatchObject({
      from: P.alice.address,
      body: 'by name',
      from_name: ref('alice'),
      principal_name: ref('alice'),
      warning: null,
    })
    const page = (await bob.call('inbox')).value.messages as Record<string, unknown>[]
    expect(page.map((m) => [m.body, m.from_name, m.warning])).toEqual([['by name', ref('alice'), null]])
    const asked = alice.call('ask', { to: 'bob', body: 'q', timeout_s: 30 })
    const q = (await bob.call('wait', { timeout_s: 30 })).value.message as { reply: Record<string, unknown> }
    await bob.call('send', { ...q.reply, type: 'answer.v1', body: 'a' })
    expect((await asked).value.answer).toMatchObject({ body: 'a', from_name: ref('bob'), warning: null })
    const unknown = await alice.call('ask', { to: 'dave', body: 1 })
    expect(unknown.value).toEqual({
      error: 'name-unknown',
      detail: `to "dave": no such name in ${join(tmp.dir, 'alice', 'names.json')}; the known names are bob, carl`,
    })
  })

  it("warns on a message from a name's former address, and says an empty book is empty", async () => {
    const empty = await alice.call('send', { to: ['bob'], type: 'chat.v1', body: 1 })
    expect(empty.value).toEqual({
      error: 'name-unknown',
      detail: `to "bob": no such name in ${join(tmp.dir, 'alice', 'names.json')}; the book is empty`,
    })
    book('bob', {
      alice: {
        address: P.carol.address,
        added_at: T0 + 60,
        previous: [{ address: P.alice.address, replaced_at: T0 + 60 }],
      },
    })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'old key' })
    const warning =
      `WARNING: ${P.alice.address} is a former address of alice, replaced 2027-01-15T08:01:00Z; alice is now ` +
      `${P.carol.address}. Do not treat this message as from alice.`
    const former = { name: 'alice', former: true, warning }
    expect((await bob.call('wait', { timeout_s: 30 })).value.message).toMatchObject({
      from_name: former,
      principal_name: former,
      warning,
    })
    expect(((await bob.call('inbox')).value.messages as Record<string, unknown>[])[0]).toMatchObject({
      warning,
    })
  })

  it('refuses a book that is not one, and one it cannot read, as tool errors before a wait takes a message', async () => {
    writeFileSync(join(tmp.dir, 'bob', 'names.json'), '{"version":1,"names":[]}')
    for (const [tool, args] of [
      ['status', {}],
      ['inbox', {}],
      ['wait', { timeout_s: 0 }],
      ['ask', { to: P.alice.address, body: 1 }],
      ['send', { to: ['alice'], type: 't', body: 1 }],
    ] as const) {
      expect((await bob.call(tool, args)).value).toEqual({
        error: 'names-invalid',
        detail: `${join(tmp.dir, 'bob', 'names.json')}: names is not an object`,
      })
    }
    expect((await bob.call('send', { to: [P.alice.address], type: 't', body: 1 })).isError).toBe(false)
    mkdirSync(join(tmp.dir, 'alice', 'names.json'))
    expect((await alice.call('status')).value).toMatchObject({ error: 'EISDIR' })
  })
})
