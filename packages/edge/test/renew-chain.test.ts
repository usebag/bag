import { type Hop, parseEnvelope, type SigningKey, serializeRecord, signHop, verifyChain } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import {
  EdgeError,
  type FetchProof,
  type Frame,
  type PublishResult,
  type RelayClient,
  RelayError,
  type Subscription,
} from '../src/ports.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// Edge.renewChain (the edge's call), on the fake clock: a chain
// that continues the current one (same root and principal, a later earliest exp) is swapped in for every later send,
// subscription and fetch, with one audit line; anything else is refused and changes nothing. An open subscription
// keeps its hops; the next one, the resubscription after an error frame included, presents the new ones.

const HOME = 'http://home.test'

/** A subscription that waits until `end(error)` throws it from next(), as a relay's error frame does, or close. */
class EndsWithError implements Subscription {
  #settle: (e: Error | null) => void = () => {}
  readonly #settled = new Promise<Error | null>((resolve) => {
    this.#settle = resolve
  })

  end(e: Error): void {
    this.#settle(e)
  }

  ack(): void {}

  close(): void {
    this.#settle(null)
  }

  [Symbol.asyncIterator](): AsyncIterator<Frame> {
    return {
      next: async (): Promise<IteratorResult<Frame>> => {
        const e = await this.#settled
        if (e !== null) throw e
        return { value: undefined, done: true }
      },
    }
  }
}

/** The memory relay, recording the hops each subscribe and fetch presents; its first subscription can be ended. */
class Recording implements RelayClient {
  readonly inner = new MemoryRelay()
  readonly subscribed: (readonly Hop[])[] = []
  readonly fetched: (readonly Hop[])[] = []
  first: EndsWithError | null = null

  publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    return this.inner.publish(url, bytes)
  }

  fetch(url: string, id: string, proof: FetchProof): Promise<Uint8Array> {
    this.fetched.push(proof.auth)
    return this.inner.fetch(url, id, proof)
  }

  fetchRecord(
    url: string,
    address: string,
    kind: 'address' | 'accept-from' | 'key',
  ): Promise<Uint8Array | null> {
    return this.inner.fetchRecord(url, address, kind)
  }

  subscribe(
    url: string,
    mailbox: string,
    signer: SigningKey,
    hops: readonly Hop[],
    cursor: number | null,
  ): Subscription {
    this.subscribed.push(hops)
    if (this.subscribed.length === 1 && this.first !== null) return this.first
    return this.inner.subscribe(url, mailbox, signer, hops, cursor)
  }
}

/** The session's edge: it signs as the session, receives at `mailbox` (jane's by default), under `auth`. */
function sessionEdge(auth: readonly Hop[], o: { mailbox?: string; relay?: Recording; signer?: Party } = {}) {
  const clock = new FakeClock()
  const audit = new MemoryAuditSink()
  const relay = o.relay ?? new Recording()
  const signer = o.signer ?? P.session
  const edge = new Edge({
    keys: { signing: signer.signing, sealing: P.jane.sealing },
    auth,
    mailbox: o.mailbox ?? P.jane.address,
    store: new SqliteStore(':memory:'),
    relays: { client: relay, urls: [HOME] },
    policy: { roots: [], types: [] },
    clock,
    rng: seededRng('renew'),
    audit,
    lookup: PUBLIC_LOOKUP,
    resubscribeDelayMs: () => 0,
  })
  return { edge, clock, audit, relay }
}

const hop = (from: Party, to: Party, exp: number, caveats: readonly string[] = []): Hop =>
  signHop(from.signing, to.address, caveats, exp)

async function until(test: () => boolean): Promise<void> {
  for (let i = 0; i < 500 && !test(); i++) await new Promise((r) => setTimeout(r, 2))
  expect(test()).toBe(true)
}

/** The code of what `f` throws, and whether it is an EdgeError. */
function refusal(f: () => unknown): [string, boolean] {
  try {
    f()
  } catch (e) {
    return [(e as { code: string }).code, e instanceof EdgeError]
  }
  return ['none', false]
}

describe('Edge.renewChain: a renewed chain for every later send, subscribe and fetch', () => {
  it('(L6 a, d) swaps a chain with a later exp: the next send carries it after the old one expired, the next subscription and fetch present it, one audit line', async () => {
    const old = [hop(P.jane, P.session, T0 + 3600, ['type=chat.*'])]
    const { edge, clock, audit, relay } = sessionEdge(old)
    await relay.publish(HOME, serializeRecord(addressRecord(P.bob, { relays: [HOME], ttl: DAY })))
    clock.t = T0 + 3000
    const next = [hop(P.jane, P.session, T0 + 7200, ['type=chat.*'])]
    expect(edge.renewChain(next)).toEqual({
      root: P.jane.address,
      principal: P.jane.address,
      caveats: ['type=chat.*'],
      exp: T0 + 7200,
    })
    // (d) The edge keeps its own copy: a change to the caller's array afterwards changes nothing.
    next.push(hop(P.session, P.bob, T0 + 60))
    expect(edge.auth).toEqual([next[0]])
    clock.t = T0 + 4000
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { renewed: true } })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    const env = parseEnvelope(relay.inner.box(HOME, P.bob.address)[0]?.bytes as Uint8Array)
    expect(env.auth).toEqual([next[0]])
    expect(verifyChain(env.auth, P.session.address, env.ts)).toMatchObject({ root: P.jane.address })
    expect(() => verifyChain(old, P.session.address, env.ts)).toThrow(/^hop-expired: /)
    await edge.start()
    await until(() => relay.subscribed.length === 1)
    await edge.stop()
    expect(relay.subscribed).toEqual([[next[0]]])
    expect(await edge.fetch(HOME, sent.id)).toEqual(relay.inner.box(HOME, P.bob.address)[0]?.bytes)
    expect(relay.fetched).toEqual([[next[0]]])
    const rotations = audit.lines.map((l) => JSON.parse(l)).filter((l) => l.event === 'rotate')
    expect(rotations.map((l) => [l.decision, l.reason, l.from, l.root, JSON.parse(l.detail)])).toEqual([
      [
        'accept',
        'ok',
        P.session.address,
        P.jane.address,
        {
          subject: `chain:${P.session.address}`,
          principal: P.jane.address,
          hops: 1,
          caveats: ['type=chat.*'],
          exp_before: T0 + 3600,
          exp_after: T0 + 7200,
        },
      ],
    ])
    const all = audit.lines.join('\n')
    for (const p of Object.values(P)) for (const s of p.secrets) expect(all.includes(s)).toBe(false)
    console.log(
      `MEASURE L6(a,d): renewed at ts + 3,000 to exp ts + 7,200; send at ts + 4,000 carries it (old chain hop-expired); subscribe and fetch present it; ${rotations.length} audit line; caller's later change ignored`,
    )
  })

  it('(L6 b) refuses a chain that does not continue the current one, and changes nothing', () => {
    const current = [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3600)]
    const { edge, clock, audit } = sessionEdge(current)
    clock.t = T0 + 100
    const before = audit.lines.length
    const cases: [string, readonly Hop[], string, boolean][] = [
      [
        'another root',
        [hop(P.mallory, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)],
        'chain-mismatch',
        true,
      ],
      [
        'another principal',
        [hop(P.org, P.other, T0 + DAY), hop(P.other, P.session, T0 + 7200)],
        'chain-mismatch',
        true,
      ],
      [
        'the same exp',
        [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 3600)],
        'chain-not-later',
        true,
      ],
      [
        'an earlier exp',
        [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 1800)],
        'chain-not-later',
        true,
      ],
      [
        'to another key',
        [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.bob, T0 + 7200)],
        'chain-not-to-sender',
        false,
      ],
      [
        'already expired',
        [hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 50)],
        'hop-expired',
        false,
      ],
      [
        'a bad hop signature',
        [hop(P.org, P.jane, T0 + DAY), { ...hop(P.jane, P.session, T0 + 7200), sig: 'ab'.repeat(64) }],
        'bad-hop-sig',
        false,
      ],
      ['not a chain', [{ iss: 'x' } as unknown as Hop], 'bad-hop', false],
    ]
    for (const [what, auth, code, edgeError] of cases) {
      expect(
        refusal(() => edge.renewChain(auth)),
        what,
      ).toEqual([code, edgeError])
      expect(edge.auth, what).toEqual(current)
    }
    expect(audit.lines.length).toBe(before)
    const self = sessionEdge([], { mailbox: P.session.address })
    expect(refusal(() => self.edge.renewChain([hop(P.jane, P.session, T0 + 7200)]))).toEqual([
      'chain-mismatch',
      true,
    ])
    // A mailbox between the root and the principal: a renewal that skips its key could not subscribe there.
    const deep = [
      hop(P.org, P.other, T0 + DAY),
      hop(P.other, P.jane, T0 + DAY),
      hop(P.jane, P.session, T0 + 3600),
    ]
    const viaOther = sessionEdge(deep, { mailbox: P.other.address })
    expect(
      refusal(() =>
        viaOther.edge.renewChain([hop(P.org, P.jane, T0 + DAY), hop(P.jane, P.session, T0 + 7200)]),
      ),
    ).toEqual(['chain-mismatch', true])
    expect(viaOther.edge.auth).toEqual(deep)
    expect(() =>
      viaOther.edge.renewChain([...deep.slice(0, 2), hop(P.jane, P.session, T0 + 7200)]),
    ).not.toThrow()
    console.log(
      `MEASURE L6(b): ${cases.length + 2} refusals (${[...cases.map((c) => c[2]), 'chain-mismatch', 'chain-mismatch'].join(', ')}), the chain and the audit log unchanged after each`,
    )
  })

  it('(L6 c) a subscription the relay ends with a hop-expired error frame after a renewal is made again by the recovery, with the new hops', async () => {
    const relay = new Recording()
    relay.first = new EndsWithError()
    const old = [hop(P.jane, P.session, T0 + 3600)]
    const { edge, clock, audit } = sessionEdge(old, { relay })
    await edge.start()
    await until(() => relay.subscribed.length === 1)
    clock.t = T0 + 3000
    const next = [hop(P.jane, P.session, T0 + 7200)]
    edge.renewChain(next)
    clock.t = T0 + 3601
    relay.first.end(
      new RelayError('hop-expired', 0, null, 'the relay ended the subscription at its chain exp'),
    )
    await until(() => relay.subscribed.length === 2)
    await edge.stop()
    expect(relay.subscribed).toEqual([old, next])
    const steps = audit.steps()
    expect(steps.filter((s) => s.startsWith('subscribe') || s.startsWith('rotate'))).toEqual([
      'rotate accept ok',
      'subscribe retry hop-expired',
    ])
    console.log(
      `MEASURE L6(c): subscriptions presented ${relay.subscribed.map((h) => (h[0]?.exp ?? 0) - T0).join(' then ')} (exp - ts), through ${steps.filter((s) => s.startsWith('subscribe')).join(', ')}`,
    )
  })
})
