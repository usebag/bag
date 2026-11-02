import type { CallToolResult, Progress } from '@modelcontextprotocol/sdk/types.js'
import type { AcErrorCode } from '@usebag/core'
import { createWsSubscriber, RelayError, resubscribeDelay, type SocketFactory } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { HINTS, Subscriptions, type SubscriptionView } from '../src/subscriptions.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
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
import { gatedRelay, MemoryRelay } from './support/relay.ts'

// The MCP half: status lists the server's subscriptions, one per relay, kept from what the edge tells the server,
// and wait and inbox say `refused: <code>` once every subscription has ended for good (the edge's three refusals in a
// row), a wait at once rather than at the end of its window. The in-memory relay's `refuse` throws a fresh
// RelayError per read, as the real client does (pinned below on ws-relay's own subscriptions); testServer gives the
// edge no resubscription wait unless a test asks for one, and the server's timers are fired by hand, so no test waits
// on a clock, but for one that runs the edge's own 250 ms backoff. The hints are pinned as text. Every test here is on
// the in-memory relay: e2e scenario 20 has a refusal by the real relay at the edge; the MCP server's report of it is
// not an e2e scenario yet. A connection the relay has not admitted is on gatedRelay, the real client over a fake socket,
// since a close with no frame is the real client's own affair: on the memory relay it cannot happen.

const TWO = 'http://second.test'
const at = new Date(T0 * 1000).toISOString()
const NA: AcErrorCode = 'not-authorized'
const HINT = {
  refused:
    "the relay refused this mailbox's subscription three times in a row, so nothing new arrives here: status lists the subscriptions; a session's is made again once its chain is renewed, a principal's only when its server is restarted",
  ended:
    'the subscription failed in a way the edge does not retry, so nothing new arrives here: status lists the subscriptions; it is made again only when the server is restarted',
  stopped:
    "the edge did not start again after this session's chain was renewed, so nothing new arrives here: the server's log has the resubscribe error; the next renewal tries again, or restart the server",
}
const refused = (relay: string) => ({ mailbox: 'refused: not-authorized', relay, at, hint: HINT.refused })

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
const servers: TestServer[] = []

async function serverFor(
  p: Party,
  args: readonly string[] = [],
  resubscribeDelayMs?: (attempt: number) => number,
  client: MemoryRelay = relay,
): Promise<TestServer> {
  saveKeys(`${tmp.dir}/${p.name}`, p)
  await publishAddress(relay, p)
  const home = `${tmp.dir}/${p.name}`
  const delay = resubscribeDelayMs === undefined ? {} : { resubscribeDelayMs }
  const s = await testServer({ home, name: p.name, relay: client, clock, timers, args, ...delay })
  servers.push(s)
  return s
}

/** The subscription lines of a server's log (of one relay, when given) after its first admission, as `<state> <refusals>`. */
function lines(s: TestServer, url?: string): string[] {
  const all = s.log.lines
    .filter((l) => l.event === 'subscription' && (url === undefined || l.fields.relay === url))
    .map((l) => `${l.fields.state} ${l.fields.refusals}`)
  return all[0] === 'subscribed 0' ? all.slice(1) : all
}

/** Three refusals in a row at each relay for alice's mailbox, and the wait for their ends. */
async function refuseAll(s: TestServer, relays: readonly string[] = [RELAY]): Promise<void> {
  for (const url of relays) relay.refuse(url, P.alice.address, NA, NA, NA)
  await until('the end', () => lines(s).filter((l) => l.startsWith('ended')).length === relays.length)
}

const stdout = watchStdout()

beforeEach(() => {
  stdout.start()
  tmp = tempDir('subscriptions')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

describe('status: subscriptions', () => {
  it('lists the relay subscribed, then retrying after each refusal and ended at the third, with its code and when', async () => {
    const alice = await serverFor(P.alice)
    expect((await alice.call('status')).value.subscriptions).toEqual([
      { relay: RELAY, state: 'subscribed', refusals: 0, last_code: null, last_at: null },
    ])
    await refuseAll(alice)
    // A real relay's refusal comes before its ok, so a refused resubscribe never reads subscribed.
    expect(lines(alice)).toEqual(['retrying 1', 'retrying 2', 'ended 3'])
    expect((await alice.call('status')).value).toMatchObject({
      edge_errors: 1,
      last_edge_error: { code: 'not-authorized', at },
      subscriptions: [
        { relay: RELAY, state: 'ended', refusals: 3, last_code: 'not-authorized', last_at: at },
      ],
    })
  })

  it('shows a subscription that recovers after a refusal as subscribed again; a frame resets its refusals', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address])
    const bob = await serverFor(P.bob)
    relay.refuse(RELAY, P.alice.address, NA)
    await until('subscribed again', () => lines(alice).length === 2)
    expect(lines(alice)).toEqual(['retrying 1', 'subscribed 1'])
    expect((await alice.call('status')).value).toMatchObject({
      edge_errors: 0,
      subscriptions: [
        { relay: RELAY, state: 'subscribed', refusals: 1, last_code: 'not-authorized', last_at: at },
      ],
    })
    const waiting = alice.call('wait', { timeout_s: 10 })
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'after the refusal' })
    expect((await waiting).value.message).toMatchObject({ body: 'after the refusal' })
    expect((await alice.call('status')).value.subscriptions).toEqual([
      { relay: RELAY, state: 'subscribed', refusals: 0, last_code: 'not-authorized', last_at: at },
    ])
  })

  it('counts a code outside the refusals as none in a row, as the edge does, and keeps it as the last code', async () => {
    const alice = await serverFor(P.alice)
    relay.refuse(RELAY, P.alice.address, NA, 'rate-limited', NA)
    await until('subscribed again', () => lines(alice).length === 4)
    expect(lines(alice)).toEqual(['retrying 1', 'retrying 0', 'retrying 1', 'subscribed 1'])
    expect((await alice.call('status')).value.subscriptions).toMatchObject([
      { state: 'subscribed', refusals: 1 },
    ])
  })

  it('says refused only once every relay has ended, naming one of them; each relay its own lines', async () => {
    const alice = await serverFor(P.alice, ['--relay', TWO])
    await refuseAll(alice, [RELAY, TWO])
    for (const url of [RELAY, TWO]) {
      expect(lines(alice, url)).toEqual(['retrying 1', 'retrying 2', 'ended 3'])
    }
    expect((await alice.call('status')).value.subscriptions).toMatchObject([
      { relay: RELAY, state: 'ended', refusals: 3 },
      { relay: TWO, state: 'ended', refusals: 3 },
    ])
    const out = await alice.call('inbox')
    expect([RELAY, TWO]).toContain(out.value.relay)
    expect(out.value).toMatchObject({ mailbox: 'refused: not-authorized', at, hint: HINT.refused })
  })

  it('with one relay of two ended: status shows both, inbox has no mailbox field and a wait still blocks', async () => {
    const alice = await serverFor(P.alice, ['--relay', TWO])
    await refuseAll(alice, [TWO])
    expect((await alice.call('status')).value.subscriptions).toEqual([
      { relay: RELAY, state: 'subscribed', refusals: 0, last_code: null, last_at: null },
      { relay: TWO, state: 'ended', refusals: 3, last_code: 'not-authorized', last_at: at },
    ])
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
    const waiting = alice.call('wait', { timeout_s: 60 })
    await until('the wait blocks', () => timers.live().includes(25_000))
    timers.fire((ms) => ms === 25_000)
    expect((await waiting).value).toEqual({
      timed_out: false,
      pending: true,
      resume: expect.any(String),
      remaining_s: 60,
    })
  })
})

describe('wait and inbox while the edge retries', () => {
  it("holds a wait through a transient refusal and the edge's real 250 ms backoff, and the wait gets the next message", async () => {
    // The edge's own resubscription wait (250 ms, then doubling), on real timers: about a quarter second of real time.
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], resubscribeDelay)
    const bob = await serverFor(P.bob)
    let settled = false
    const waiting = alice.call('wait', { timeout_s: 60 }).finally(() => {
      settled = true
    })
    await until('the wait blocks', () => timers.live().includes(25_000))
    relay.refuse(RELAY, P.alice.address, NA)
    await until('subscribed again', () => lines(alice).length === 2)
    expect(lines(alice)).toEqual(['retrying 1', 'subscribed 1'])
    expect(settled).toBe(false)
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'after the backoff' })
    const out = await waiting
    expect(out.value).not.toHaveProperty('mailbox')
    expect(out.value.message).toMatchObject({ body: 'after the backoff' })
  })

  it('says nothing in wait or inbox after exactly two refusals, one short of the end', async () => {
    const alice = await serverFor(P.alice)
    relay.refuse(RELAY, P.alice.address, NA, NA)
    await until('subscribed again', () => lines(alice).length === 3)
    expect(lines(alice)).toEqual(['retrying 1', 'retrying 2', 'subscribed 2'])
    expect((await alice.call('status')).value).toMatchObject({
      edge_errors: 0,
      subscriptions: [{ relay: RELAY, state: 'subscribed', refusals: 2, last_code: 'not-authorized' }],
    })
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
    const waiting = alice.call('wait', { timeout_s: 60 })
    await until('the wait blocks', () => timers.live().includes(25_000))
    timers.fire((ms) => ms === 25_000)
    expect((await waiting).value).toEqual({
      timed_out: false,
      pending: true,
      resume: expect.any(String),
      remaining_s: 60,
    })
  })
})

describe('wait and inbox on a mailbox whose subscription has ended', () => {
  it('ends a wait in progress at once with refused, its window not run out, and a later wait the same', async () => {
    const alice = await serverFor(P.alice)
    const waiting = alice.call('wait', { timeout_s: 60 })
    await until('the wait blocks', () => timers.live().includes(25_000))
    await refuseAll(alice)
    const out = await waiting
    expect(out.isError).toBe(false)
    expect(out.value).toEqual({
      timed_out: false,
      pending: false,
      resume: expect.any(String),
      ...refused(RELAY),
    })
    expect(out.result.structuredContent).toEqual(out.value)
    expect(timers.live()).not.toContain(25_000)
    expect(clock.t).toBe(T0)
    const again = await alice.call('wait', { resume: out.value.resume as string })
    expect(again.value).toMatchObject({ pending: false, ...refused(RELAY) })
  })

  it('sends no progress tick for a wait under a progressToken that ends refused', async () => {
    const alice = await serverFor(P.alice)
    const got: Progress[] = []
    const call = alice.client.callTool({ name: 'wait', arguments: { timeout_s: 60 } }, undefined, {
      onprogress: (p) => got.push(p),
    })
    await until('the wait blocks', () => timers.live().includes(15_000) && timers.live().includes(25_000))
    await refuseAll(alice)
    const result = (await call) as CallToolResult
    expect(JSON.parse((result.content[0] as { text: string }).text)).toMatchObject(refused(RELAY))
    // Both the window's timer and the progress tick were cancelled: no tick can be sent.
    expect(timers.live()).toEqual([])
  })

  it('still returns a message that arrived before the end, and inbox lists it with refused', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address])
    const bob = await serverFor(P.bob)
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'before the end' })
    await until('alice has it', () => alice.running.desk.counts().counts.accepted === 1)
    await refuseAll(alice)
    expect((await alice.call('wait')).value.message).toMatchObject({ body: 'before the end' })
    const page = await alice.call('inbox')
    expect(page.value).toMatchObject({ messages: [{ body: 'before the end' }], ...refused(RELAY) })
    expect(page.result.structuredContent).toEqual(page.value)
    expect((await alice.call('wait')).value).toMatchObject(refused(RELAY))
  })

  it('leaves wait and inbox as they were while the mailbox is subscribed', async () => {
    const alice = await serverFor(P.alice)
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
    const waiting = alice.call('wait', { timeout_s: 60 })
    await until('the wait blocks', () => timers.live().includes(25_000))
    timers.fire((ms) => ms === 25_000)
    expect((await waiting).value).toEqual({
      timed_out: false,
      pending: true,
      resume: expect.any(String),
      remaining_s: 60,
    })
  })
})

describe('status: a connection the relay has not admitted', () => {
  const seen = async (s: TestServer): Promise<SubscriptionView> =>
    ((await s.call('status')).value.subscriptions as SubscriptionView[])[0] as SubscriptionView

  it('is not subscribed before the relay answers, with no error yet', async () => {
    const quiet = gatedRelay(relay, 'hold')
    const alice = await serverFor(P.alice, [], undefined, quiet.client)
    await until('the connection', () => quiet.dials() === 1)
    expect(await seen(alice)).toEqual({
      relay: RELAY,
      state: 'connecting',
      refusals: 0,
      last_code: null,
      last_at: null,
    })
  })

  it('is not subscribed while each connection closes with no frame, with the last error and when; the edge goes on', async () => {
    const full = gatedRelay(relay, 'close')
    const alice = await serverFor(P.alice, [], undefined, full.client)
    await until('the closes', () => full.dials() >= 3)
    expect(await seen(alice)).toEqual({
      relay: RELAY,
      state: 'retrying',
      refusals: 0,
      last_code: 'unreachable',
      last_at: at,
    })
    expect((await alice.call('status')).value).toMatchObject({ edge_errors: 0, last_edge_error: null })
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
  })

  it('is subscribed once the relay admits it, the last error kept', async () => {
    const full = gatedRelay(relay, 'close')
    const alice = await serverFor(P.alice, [], undefined, full.client)
    await until('the closes', () => full.dials() >= 2)
    expect(await seen(alice)).toMatchObject({ state: 'retrying', last_code: 'unreachable' })
    full.gate = 'admit'
    await until('the admission', () => full.admitted() === 1)
    expect(await seen(alice)).toMatchObject({ state: 'subscribed', last_code: 'unreachable', last_at: at })
  })

  it('counts a refusal by error frame once, though the client reports it twice, and ends at the third', async () => {
    const refusing = gatedRelay(relay, NA)
    const alice = await serverFor(P.alice, [], undefined, refusing.client)
    await until('the end', () => lines(alice).some((l) => l.startsWith('ended')))
    expect(lines(alice)).toEqual(['retrying 1', 'retrying 2', 'ended 3'])
    expect(refusing.dials()).toBe(3)
  })

  it('names a capacity refusal, which counts toward no end: rate-limited, and the edge goes on', async () => {
    const reserve = gatedRelay(relay, 'rate-limited')
    const alice = await serverFor(P.alice, [], undefined, reserve.client)
    await until('the refusals', () => reserve.dials() >= 3)
    expect(await seen(alice)).toEqual({
      relay: RELAY,
      state: 'retrying',
      refusals: 0,
      last_code: 'rate-limited',
      last_at: at,
    })
    expect((await alice.call('inbox')).value).not.toHaveProperty('mailbox')
  })

  it('stops being subscribed when an admitted connection drops, and is subscribed again when it is back', async () => {
    const flaky = gatedRelay(relay, 'admit')
    const alice = await serverFor(P.alice, [], undefined, flaky.client)
    await until('the admission', () => flaky.admitted() === 1)
    expect(await seen(alice)).toMatchObject({ state: 'subscribed', last_code: null })
    flaky.gate = 'close'
    flaky.drop()
    const dials = flaky.dials()
    await until('the closes', () => flaky.dials() > dials)
    expect(await seen(alice)).toMatchObject({ state: 'retrying', last_code: 'unreachable', last_at: at })
    flaky.gate = 'admit'
    await until('the second admission', () => flaky.admitted() === 2)
    expect((await seen(alice)).state).toBe('subscribed')
  })
})

describe('Subscriptions: the record alone', () => {
  const OTHER = 'http://other.test'

  it('has the hints as written here', () => {
    expect(HINTS).toEqual(HINT)
  })

  it("rests on the real client's subscriptions each throwing their own error object, the same one again on each read", async () => {
    // subscriptions.ts reads an end by the identity of the error Receiver.run rejects with; the Subscription port does
    // not promise a fresh object per subscription, ws-relay's does, and this pins it.
    const deliver: ((event: { readonly data: unknown }) => void)[] = []
    const factory: SocketFactory = () => ({
      addEventListener: (
        type: 'message' | 'close',
        listener: (event: { readonly data: unknown }) => void,
      ) => {
        if (type === 'message') deliver.push(listener)
      },
      send: () => {},
      close: () => {},
    })
    const client = createWsSubscriber({ socketFactory: factory })
    const subs = [RELAY, OTHER].map((url) =>
      client.subscribe(url, P.alice.address, P.alice.keys.signing, [], null),
    )
    for (const d of deliver) d({ data: JSON.stringify({ t: 'error', error: 'not-authorized' }) })
    const read = (i: number): Promise<unknown> =>
      (subs[i] as (typeof subs)[number])
        [Symbol.asyncIterator]()
        .next()
        .catch((e: unknown) => e)
    const [first, second] = [await read(0), await read(1)]
    expect([(first as RelayError).code, (second as RelayError).code]).toEqual([NA, NA])
    expect(first).not.toBe(second)
    expect(await read(0)).toBe(first)
  })

  it('ignores a relay outside --relay, and an onError no subscription threw', () => {
    const log = new MemoryLog()
    const s = new Subscriptions([RELAY], new FakeClock(), log)
    const before = s.list()
    s.admitted(OTHER)
    s.lost(OTHER, 'unreachable')
    s.arrived(OTHER)
    s.failed(OTHER, new RelayError(NA, 0, null, 'refused'), NA)
    s.ended(new Error('a flush that failed'))
    expect([s.list(), s.refused(), s.dead.aborted, log.lines]).toEqual([before, null, false, []])
  })

  it('is retrying after a refusal the edge retries, with its code and time, and not dead', () => {
    const s = new Subscriptions([RELAY], new FakeClock(), new MemoryLog())
    s.failed(RELAY, new RelayError(NA, 0, null, 'refused'), NA)
    expect([s.list(), s.refused(), s.dead.aborted]).toEqual([
      [{ relay: RELAY, state: 'retrying', refusals: 1, last_code: 'not-authorized', last_at: at }],
      null,
      false,
    ])
  })

  it('ends without retrying on an error the edge does not retry: "ended: <code>" with its hint', () => {
    const log = new MemoryLog()
    const s = new Subscriptions([RELAY], new FakeClock(), log)
    const fault = new RelayError(null, 0, null, 'no socket could be made')
    s.failed(RELAY, fault, 'unreachable')
    expect(s.list()).toMatchObject([{ state: 'connecting', refusals: 0, last_code: 'unreachable' }])
    s.ended(fault)
    s.ended(fault)
    expect(s.refused()).toEqual({ mailbox: 'ended: unreachable', relay: RELAY, at, hint: HINT.ended })
    expect(s.dead.aborted).toBe(true)
    // An end already recorded is not ended again, by the same error or a failed restart; a reset starts afresh, logged.
    s.halt('internal')
    expect([s.refused()?.mailbox, s.list()[0]?.last_code]).toEqual(['ended: unreachable', 'unreachable'])
    s.reset()
    expect([s.list(), s.refused(), s.dead.aborted]).toEqual([
      [{ relay: RELAY, state: 'connecting', refusals: 0, last_code: null, last_at: null }],
      null,
      false,
    ])
    expect(log.lines.map((l) => `${l.event} ${l.fields.state}`)).toEqual([
      'subscription ended',
      'subscription connecting',
    ])
  })

  it('logs a lost connection once, moves its time on, keeps the refusals, and leaves an end alone', () => {
    const log = new MemoryLog()
    const s = new Subscriptions([RELAY], clock, log)
    s.failed(RELAY, new RelayError(NA, 0, null, 'refused'), NA)
    s.lost(RELAY, 'unreachable')
    clock.t += 5
    s.lost(RELAY, 'unreachable')
    expect(s.list()).toEqual([
      {
        relay: RELAY,
        state: 'retrying',
        refusals: 1,
        last_code: 'unreachable',
        last_at: new Date((T0 + 5) * 1000).toISOString(),
      },
    ])
    s.admitted(RELAY)
    s.admitted(RELAY)
    s.lost(RELAY, 'unreachable')
    expect(log.lines.map((l) => `${l.fields.state} ${l.fields.refusals}`)).toEqual([
      'retrying 1',
      'subscribed 1',
      'retrying 1',
    ])
    s.halt('internal')
    s.lost(RELAY, 'unreachable')
    s.admitted(RELAY)
    expect(s.list()).toMatchObject([{ state: 'ended', last_code: 'internal' }])
  })

  it('a failed restart stops every subscription: "stopped: <code>" with its hint', () => {
    const s = new Subscriptions([RELAY, OTHER], new FakeClock(), new MemoryLog())
    s.halt('bad-shape')
    expect(s.list()).toMatchObject([{ state: 'ended' }, { state: 'ended' }])
    expect(s.refused()).toEqual({ mailbox: 'stopped: bad-shape', relay: OTHER, at, hint: HINT.stopped })
  })
})
