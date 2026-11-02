import { type AddressRecord, DEFAULT_SKEW, DEFAULT_TTL, serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import type { InboxRow } from '../src/ports.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// B2, on the fake clock: a root revokes a session a day before
// the session's hop expires; an envelope the session sent in that day waits at an offline recipient's relay; the
// recipient verifies it after the hop's exp, at the envelope's ts, against the root's record of that day.
// Under the earlier drop ("entries drop out at the cert's exp") the record no longer lists the session and the recipient accepts
// mail its root revoked: the attack, shown first. Under B2 the entry stays until the hop's exp + TTL + skew, the last
// second any envelope under the hop passes the stale-ts check, and the recipient refuses it `revoked`. The edge
// itself drops nothing: it checks the root's record as published (policy.ts), so the rule is the writer's.

const HOME = 'http://home.test'
/** The session's one hop, from jane, expires here. */
const EXP = T0 + 2 * DAY
/** Jane revokes the session a day before that. */
const REVOKED_AT = EXP - DAY

/** A writer of jane's address record: whether it still lists a key whose hop expires at `exp`, at `now`. */
type Writer = (exp: number, now: number) => boolean
/** The earlier writer: an entry drops out at its hop's exp. */
const R2_5: Writer = (exp, now) => now < exp
/** B2: an entry stays through exp + TTL + skew. */
const B2: Writer = (exp, now) => now <= exp + DEFAULT_TTL + DEFAULT_SKEW
/** A writer one second short of B2, to show that its bound is the last second that matters. */
const SHORT: Writer = (exp, now) => now <= exp + DEFAULT_TTL + DEFAULT_SKEW - 1

/** Jane's record as her writer signs it at `now`, re-signed daily: the session listed while the writer keeps it. */
function janeRecord(writer: Writer, now: number): AddressRecord {
  const revoked = now >= REVOKED_AT && writer(EXP, now) ? [P.session.address] : []
  return addressRecord(P.jane, { relays: [HOME], revoked, ttl: DAY, iat: now })
}

/**
 * The session sends to bob at `sentAt`, with jane's record of that time at the relay; bob, offline until `readAt`,
 * then receives the waiting frame against jane's record of `readAt`, on a fresh edge (nothing cached).
 */
async function readLater(writer: Writer, sentAt: number, readAt: number): Promise<InboxRow> {
  const relay = new MemoryRelay()
  const clock = new FakeClock(sentAt)
  const publish = (r: AddressRecord) => relay.publish(HOME, serializeRecord(r))
  await publish(addressRecord(P.bob, { relays: [HOME], ttl: DAY, iat: sentAt }))
  await publish(janeRecord(writer, sentAt))
  const session = new Edge({
    keys: P.session.keys,
    auth: [signHop(P.jane.signing, P.session.address, [], EXP)],
    store: new SqliteStore(':memory:'),
    relays: { client: relay, urls: [HOME] },
    policy: { roots: [], types: [] },
    clock,
    rng: seededRng('session'),
    audit: new MemoryAuditSink(),
    lookup: PUBLIC_LOOKUP,
  })
  const sent = await session.send({ to: [P.bob.address], type: 'chat.v1', body: { sent_at: sentAt } })
  expect(sent.targets.map((t) => t.state)).toEqual(['published'])
  const [frame] = relay.box(HOME, P.bob.address)
  clock.t = readAt
  await publish(janeRecord(writer, readAt))
  const bob = new Edge({
    keys: P.bob.keys,
    store: new SqliteStore(':memory:'),
    relays: { client: relay, urls: [HOME] },
    policy: { roots: [{ address: P.jane.address }], types: ['*'] },
    clock,
    rng: seededRng('bob'),
    audit: new MemoryAuditSink(),
    lookup: PUBLIC_LOOKUP,
  })
  bob.setDefault({ session: 'bob', deliver: () => {} })
  // The relay received the envelope when the session sent it; the receiver judges live delivery at that
  // stamp as well as at ts, so the frame carries it, as the relay's env frame does.
  return bob.receiver.receive(HOME, frame?.cursor as number, frame?.bytes as Uint8Array, sentAt)
}

const outcome = (row: InboxRow): string =>
  row.state === 'rejected' ? `reject ${row.reason}` : `accept (${row.state})`

describe('B2: a revoked entry outlives its hop by TTL + skew', () => {
  it('(L2 a, b) the attack: an offline recipient verifying after exp accepts a revoked session under the earlier drop, and refuses it revoked under retention', async () => {
    const sentAt = REVOKED_AT + 3600
    const readAt = EXP + DAY
    // Both writers list the session when it sends; only their copies of a day after exp differ.
    expect([janeRecord(R2_5, sentAt).revoked, janeRecord(B2, sentAt).revoked]).toEqual([
      [P.session.address],
      [P.session.address],
    ])
    expect([janeRecord(R2_5, readAt).revoked, janeRecord(B2, readAt).revoked]).toEqual([
      [],
      [P.session.address],
    ])
    const attack = await readLater(R2_5, sentAt, readAt)
    expect(outcome(attack)).toBe('accept (routed)')
    const kept = await readLater(B2, sentAt, readAt)
    expect([kept.state, kept.reason]).toEqual(['rejected', 'revoked'])
    console.log(
      `MEASURE L2(a): earlier writer, sent at exp - 82,800 s, read at exp + 86,400 s: ${outcome(attack)}`,
    )
    console.log(`MEASURE L2(b): B2 writer, the same envelope and time: ${outcome(kept)}`)
  })

  it('(L2 c, d) the bound is tight: at exp + TTL + skew an envelope with ts = exp still verifies, so the entry must be there; one second later the envelope is stale', async () => {
    const last = EXP + DEFAULT_TTL + DEFAULT_SKEW
    const atLast = await readLater(B2, EXP, last)
    const shortAtLast = await readLater(SHORT, EXP, last)
    expect([atLast.state, atLast.reason]).toEqual(['rejected', 'revoked'])
    expect(outcome(shortAtLast)).toBe('accept (routed)')
    const after = await Promise.all([B2, SHORT, R2_5].map((w) => readLater(w, EXP, last + 1)))
    expect(after.map((r) => [r.state, r.reason])).toEqual([
      ['rejected', 'stale-ts'],
      ['rejected', 'stale-ts'],
      ['rejected', 'stale-ts'],
    ])
    console.log(
      `MEASURE L2(c): ts = exp, read at exp + 604,800 + 300: B2 ${outcome(atLast)}, one second short ${outcome(shortAtLast)}`,
    )
    console.log(
      `MEASURE L2(d): read one second later: ${after.map(outcome).join(', ')} (B2, short, earlier drop)`,
    )
  })
})
