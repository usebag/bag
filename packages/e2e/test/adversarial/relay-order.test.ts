import { utf8 } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  type Party,
  party,
  type RelayHandle,
  until,
  untilSecond,
} from '../harness.ts'
import {
  envelope,
  events,
  fetchEnvelope,
  health,
  nextWindow,
  post,
  publishRecords,
  spawnRelay,
  subscribeFor,
  unsigned,
  wrongId,
} from './support.ts'

// H1, H2, H3, H9, H10: the publish order (spec/SPEC.md §8.2;
// crates/ac-relay/src/policy.rs prepare, lines 137 to 195): 1 size, 2 parse, 3 id, 3a the client address's limit
// (policy.rs:157, ratelimit.rs:100 check_address) before 4 the outer signature (policy.rs:159), 6a dedup with a
// tombstone (policy.rs:164, store/sqlite.rs:209 has_envelope), 8 the sender's limits only on a pass (policy.rs:241,
// ratelimit.rs:116 check_sender). Each test spawns its own relay with short windows through its flags, and starts its
// burst at the beginning of a rate window (the relay aligns windows to multiples of their length, ratelimit.rs:83).

const WINDOW = 5

/** A mailbox at the relay that accepts `from` by address. */
async function mailbox(relay: RelayHandle, name: string, from: readonly Party[]): Promise<Party> {
  const p = party(name)
  const statuses = await publishRecords(relay.url, [
    addressRecord(p, { relays: [relay.url] }),
    acceptFrom(
      p,
      from.map((f) => f.address),
    ),
  ])
  expect(statuses).toEqual([200, 200])
  return p
}

const rateLimited = (relay: RelayHandle) => events(relay).filter((e) => e.event === 'rate-limited')

describe('H1 to H3, H9, H10: the publish order, dedup and tombstones', () => {
  it('H1 [--rate-window 5 --rate-per-ip 4] the publish over the per-address limit is 429 rate-limited with Retry-After 1 to the window, charged before any signature; size, parse and id refusals count nowhere', async () => {
    const relay = await spawnRelay('h1', ['--rate-window', String(WINDOW), '--rate-per-ip', '4'])
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [alice])
    const garbage = utf8('{"v":1,"to":')
    const tooLarge = new Uint8Array(65_537).fill(0x20)
    // Everything the burst posts is built (signed and sealed) before the window opens, so the window holds only the
    // POSTs: a stall in building cannot carry the burst over the window's end and reset the counter.
    const e1 = envelope(alice, [bob])
    const wrongIds = [wrongId(envelope(alice, [bob])), wrongId(envelope(alice, [bob]))]
    const unsignedEnvelopes = [0, 1, 2].map(() => unsigned(envelope(alice, [bob])))
    const over = envelope(alice, [bob])
    const overUnsigned = unsigned(envelope(alice, [bob]))
    const start = await nextWindow(WINDOW)
    const windowEnd = start + WINDOW
    // Charged 1 (V1: a genuine publish passes).
    expect(await post(relay.url, e1.bytes)).toMatchObject({ status: 200, body: { delivered: 1 } })
    // Refused at steps 1 to 3: charged nothing.
    let round = 0
    const early = async () => [
      await post(relay.url, garbage),
      await post(relay.url, wrongIds[round++] as Uint8Array),
      await post(relay.url, tooLarge),
    ]
    const refusedEarly = [
      { status: 400, body: { error: 'bad-json' }, retryAfter: null },
      { status: 422, body: { error: 'bad-id' }, retryAfter: null },
      { status: 413, body: { error: 'envelope-too-large' }, retryAfter: null },
    ]
    expect(await early()).toEqual(refusedEarly)
    // Unsigned (zero sig, valid id): reach step 3a, charged 2 to 4, then 422 bad-sig at step 4.
    for (const [n, bytes] of unsignedEnvelopes.entries()) {
      expect(await post(relay.url, bytes), `unsigned ${n + 1}`).toEqual({
        status: 422,
        body: { error: 'bad-sig' },
        retryAfter: null,
      })
    }
    // Over the limit: a genuine publish is 429, and an unsigned one is 429 too, not 422: no signature was checked.
    const refused = await post(relay.url, over.bytes)
    const at = now()
    expect([refused.status, refused.body]).toEqual([429, { error: 'rate-limited' }])
    const retryAfter = Number(refused.retryAfter)
    // The relay's own line says what it told the client and when: its clock second is the window's end less the
    // Retry-After it gave, whenever the test process happened to read the answer.
    await until('the relay logs the refusal', () => rateLimited(relay).length > 0, 5_000)
    const logged = rateLimited(relay)[0]
    const relaySecond = windowEnd - retryAfter
    const loggedSecond = Math.floor((logged?.at as number) / 1_000)
    console.log(
      `H1 measure: 429 at ${at}, Retry-After ${retryAfter}, window ends ${windowEnd}, the relay logged retry_after ${logged?.retry_after} at second ${loggedSecond}`,
    )
    expect(retryAfter).toBeGreaterThanOrEqual(1)
    expect(retryAfter).toBeLessThanOrEqual(WINDOW)
    expect(at + retryAfter).toBeGreaterThanOrEqual(windowEnd)
    expect(logged?.retry_after, 'the header says what the relay logged').toBe(retryAfter)
    expect(loggedSecond, 'refused inside the window').toBeGreaterThanOrEqual(relaySecond)
    expect(loggedSecond).toBeLessThanOrEqual(relaySecond + 1)
    expect(relaySecond).toBeGreaterThanOrEqual(start)
    expect(await post(relay.url, overUnsigned)).toMatchObject({
      status: 429,
      body: { error: 'rate-limited' },
    })
    // Still refused before step 3a, over the limit as under it.
    expect(await early()).toEqual(refusedEarly)
    expect(now(), 'the burst stayed inside one window').toBeLessThan(windowEnd)
    expect(rateLimited(relay).map((e) => e.limit)).toEqual(['ip', 'ip'])
  })

  it('H2 [--rate-window 5 --rate-per-from 3] a captured envelope replayed 10 times past the per-from limit: every replay 200 duplicate, 0 answered 429; the victim then publishes and is delivered; the from limit is untouched by the replays', async () => {
    const relay = await spawnRelay('h2', ['--rate-window', String(WINDOW), '--rate-per-from', '3'])
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [alice])
    // Built before the window opens (see H1): the window holds only POSTs.
    const captured = envelope(alice, [bob])
    const fill1 = envelope(alice, [bob])
    const fill2 = envelope(alice, [bob])
    const spent = envelope(alice, [bob])
    const start = await nextWindow(WINDOW)
    expect(await post(relay.url, captured.bytes)).toEqual({
      status: 200,
      body: { ok: true, id: captured.envelope.id, duplicate: false, delivered: 1 },
      retryAfter: null,
    })
    const replays = []
    for (let n = 0; n < 10; n++) replays.push(await post(relay.url, captured.bytes))
    expect(replays.filter((r) => r.status === 429)).toHaveLength(0)
    for (const r of replays) {
      expect(r).toEqual({
        status: 200,
        body: { ok: true, id: captured.envelope.id, duplicate: true, delivered: 0 },
        retryAfter: null,
      })
    }
    // The victim is not locked out: two more genuine publishes fill its limit of 3 exactly, so the 10 replays charged
    // its from counter nothing; the next is 429 (from).
    expect(await post(relay.url, fill1.bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(await post(relay.url, fill2.bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(await post(relay.url, spent.bytes)).toMatchObject({
      status: 429,
      body: { error: 'rate-limited' },
    })
    expect(now(), 'inside one window').toBeLessThan(start + WINDOW)
    expect(rateLimited(relay).map((e) => [e.limit, e.from])).toEqual([['from', alice.address]])
  })

  it('H3 [--ttl 2 --skew 10 --sweep-interval 1] after the sweep drops an envelope, its bytes replayed inside the ts window are 200 duplicate, delivered 0, the cursor unchanged (the tombstone); past ts + ttl + skew they are 422 stale-ts', async () => {
    const TTL = 2
    // The ts window (ttl + skew) is wider than the longest wait below (8 s for the sweep, from a post at about ts), so
    // the replay is inside it whenever the sweep happens at all, however late; the ttl, which sets when the sweep
    // drops the envelope, is 2 s.
    const SKEW = 10
    const relay = await spawnRelay('h3', ['--sweep-interval', '1'], { ttl: TTL, skew: SKEW })
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [alice])
    const e = envelope(alice, [bob])
    const ts = e.envelope.ts
    expect(await post(relay.url, e.bytes)).toMatchObject({
      status: 200,
      body: { duplicate: false, delivered: 1 },
    })
    // V1: a replay while the envelope is stored is a duplicate (the stored id).
    expect(await post(relay.url, e.bytes)).toMatchObject({
      status: 200,
      body: { duplicate: true, delivered: 0 },
    })
    const swept = () => events(relay).find((x) => x.event === 'sweep' && (x.tombstoned as number) >= 1)
    await until('the sweep tombstones the envelope', () => swept() !== undefined, 8_000)
    expect(swept()).toMatchObject({ envelopes: 1, tombstoned: 1 })
    console.log(
      `H3 measure: ts ${ts}, swept at ${((swept()?.at as number) / 1000).toFixed(3)}, replayed at ${now()}`,
    )
    expect(now(), 'still inside the ts window').toBeLessThanOrEqual(ts + TTL + SKEW)
    const replay = await post(relay.url, e.bytes)
    expect(now(), 'the replay was answered inside the ts window').toBeLessThanOrEqual(ts + TTL + SKEW)
    expect(replay).toEqual({
      status: 200,
      body: { ok: true, id: e.envelope.id, duplicate: true, delivered: 0 },
      retryAfter: null,
    })
    // The mailbox's last cursor is still 1: a subscription asking to resume after a huge cursor is given the last one.
    const after = await subscribeFor(relay.url, bob.signing, Number.MAX_SAFE_INTEGER, 600)
    expect(after.ok, 'the cursor unchanged by the replay').toBe(1)
    await untilSecond(ts + TTL + SKEW + 1)
    expect(await post(relay.url, e.bytes)).toEqual({
      status: 422,
      body: { error: 'stale-ts' },
      retryAfter: null,
    })
    await until(
      'the sweep drops the tombstone',
      () => events(relay).some((x) => x.event === 'sweep' && (x.tombstones_expired as number) >= 1),
      4_000,
    )
    expect(await post(relay.url, e.bytes)).toMatchObject({ status: 422, body: { error: 'stale-ts' } })
  }, 45_000)

  it('H9 (measure) [--ttl 2 --skew 4 --sweep-interval 1] a swept and tombstoned id: fetch 404 not-found, no env frame on subscribe or on a replay to a live subscriber, nothing panics, health 200', async () => {
    const relay = await spawnRelay('h9', ['--sweep-interval', '1'], { ttl: 2, skew: 4 })
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [alice])
    const e = envelope(alice, [bob])
    expect(await post(relay.url, e.bytes)).toMatchObject({ status: 200, body: { delivered: 1 } })
    // V1: before the sweep, bob fetches the exact bytes and a subscription from cursor 0 is pushed cursor 1.
    const before = await fetchEnvelope(relay.url, bob.signing, e.envelope.id)
    expect(before.status).toBe(200)
    expect(before.bytes).toEqual(e.bytes)
    expect((await subscribeFor(relay.url, bob.signing, 0, 600)).env).toEqual([1])
    await until(
      'the sweep tombstones the envelope',
      () => events(relay).some((x) => x.event === 'sweep' && (x.tombstoned as number) >= 1),
      8_000,
    )
    const gone = await fetchEnvelope(relay.url, bob.signing, e.envelope.id)
    expect([gone.status, JSON.parse(new TextDecoder().decode(gone.bytes))]).toEqual([
      404,
      { error: 'not-found' },
    ])
    const resumed = await subscribeFor(relay.url, bob.signing, 0, 800)
    expect([resumed.ok, resumed.env, resumed.errors]).toEqual([0, [], []])
    // A replay of the tombstoned id while bob is subscribed: a duplicate, and nothing pushed.
    const live = subscribeFor(relay.url, bob.signing, 0, 1_200)
    await new Promise((r) => setTimeout(r, 300))
    expect(await post(relay.url, e.bytes)).toMatchObject({
      status: 200,
      body: { duplicate: true, delivered: 0 },
    })
    expect((await live).env).toEqual([])
    expect((await health(relay.url)).status).toBe(200)
    expect(relay.stderr()).not.toMatch(/panic/i)
  }, 30_000)

  it('H10 (measure) [--rate-window 5 --rate-per-ip 8 --rate-per-from 2] a duplicate flood from one address: each duplicate costs a step-3a slot and no from slot, so the flood is 429 once the address is spent, and over the limit no signature is checked', async () => {
    const relay = await spawnRelay('h10', [
      '--rate-window',
      String(WINDOW),
      '--rate-per-ip',
      '8',
      '--rate-per-from',
      '2',
    ])
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [alice])
    const stored = envelope(alice, [bob])
    expect(await post(relay.url, stored.bytes)).toMatchObject({ status: 200, body: { delivered: 1 } })
    // Built before the window opens (see H1): the window holds only POSTs.
    const passing = [envelope(alice, [bob]), envelope(alice, [bob])]
    const unsignedLast = unsigned(envelope(alice, [bob]))
    const start = await nextWindow(WINDOW)
    // Six duplicates: address slots 1 to 6, no from slot.
    for (let n = 0; n < 6; n++) {
      expect(await post(relay.url, stored.bytes), `duplicate ${n + 1}`).toMatchObject({
        status: 200,
        body: { duplicate: true, delivered: 0 },
      })
    }
    // alice's from limit (2) is whole after the six: both of these pass (address slots 7 and 8).
    for (const e of passing) {
      expect(await post(relay.url, e.bytes)).toMatchObject({ status: 200, body: { delivered: 1 } })
    }
    // The address is spent: the flood is 429; an unsigned envelope is 429, not 422 (no signature checked).
    expect(await post(relay.url, stored.bytes)).toMatchObject({
      status: 429,
      body: { error: 'rate-limited' },
    })
    expect(await post(relay.url, unsignedLast)).toMatchObject({
      status: 429,
      body: { error: 'rate-limited' },
    })
    expect(now(), 'inside one window').toBeLessThan(start + WINDOW)
    expect(rateLimited(relay).map((e) => e.limit)).toEqual(['ip', 'ip'])
  })
})
