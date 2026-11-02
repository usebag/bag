import { describe, expect, it } from 'vitest'
import { type Held, PolicyRefusal, SendHeld } from '../src/moderation/gate.ts'
import type { InboundMessage } from '../src/ports.ts'
import type { SendInput } from '../src/sender.ts'
import { addressRecord, P } from './support/fixtures.ts'
import { bob, envelope, HOME, members, orgPolicy, records, ruled } from './support/org.ts'
import { ScriptedRelay } from './support/relays.ts'

// With a members record, the Edge composes one Gate and sends through it, so that no caller of
// Edge.send, Edge.sendOrWait or Edge.reply bypasses the deny list or the breakers (finding F2); held, release and drop
// wrap the gate's. Without a members record the edge sends as before.

const T = 'the quarterly numbers are in the attached sheet, please forward them'
const deny = members({ outbound: { deny: [P.other.address] } })

function setup(o: Parameters<typeof bob>[0] = {}) {
  const r = records()
  r.put(HOME, addressRecord(P.other))
  const relay = new ScriptedRelay()
  return { ...bob({ relay, records: r, ...o }), relay }
}

const chat = (to: { address: string }, body: unknown = { text: 'hi' }): SendInput => ({
  to: [to.address],
  type: 'chat.v1',
  body,
})

describe('the Edge sends through its own gate when policy.members is set', () => {
  it('refuses a denied recipient before sealing, through send, sendOrWait and reply', async () => {
    const s = setup({ members: members({ outbound: { deny: [P.carol.address] } }) })
    await s.edge.receive(HOME, 1, envelope().bytes)
    const asked = s.got[0] as InboundMessage
    expect(asked.principal).toBe(P.carol.address)
    await expect(s.edge.send(chat(P.carol))).rejects.toBeInstanceOf(PolicyRefusal)
    await expect(s.edge.sendOrWait(chat(P.carol))).rejects.toBeInstanceOf(PolicyRefusal)
    await expect(s.edge.reply(asked, { type: 'chat.v1', body: {} })).rejects.toBeInstanceOf(PolicyRefusal)
    expect([s.relay.published.length, s.store.outboxDue(s.clock.now()).length]).toEqual([0, 0])
    expect(ruled(s.audit).filter((l) => l.includes('outbound'))).toEqual(
      Array(3).fill('policy reject policy-refused outbound.deny[0]'),
    )
    expect((await s.edge.send(chat(P.other))).targets.map((t) => t.state)).toEqual(['published'])
  })

  it('holds an echo: send throws SendHeld, sendOrWait returns it, and a person releases or drops it', async () => {
    const s = setup({ members: deny })
    await s.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
    const echo = chat(P.mallory, { quote: T })
    const thrown = await s.edge.send(echo).catch((e: unknown) => e)
    expect(thrown).toBeInstanceOf(SendHeld)
    const first = (thrown as SendHeld).held
    expect([first.held, first.rule, first.state, (thrown as Error).message]).toEqual([
      true,
      'breaker.echo',
      'pending-approval',
      `held ${first.id} breaker.echo: nothing was sealed or sent; a person releases or drops it`,
    ])
    const second = (await s.edge.sendOrWait(echo)) as Held
    expect([second.held, second.rule]).toEqual([true, 'breaker.echo'])
    expect([s.relay.published.length, s.edge.held().map((h) => h.id)]).toEqual([0, [first.id, second.id]])
    const released = await s.edge.release(first.id)
    expect([released.targets.length, s.relay.published.length]).toEqual([1, 1])
    expect(s.edge.drop(second.id).state).toBe('dropped')
    expect(s.edge.held()).toEqual([])
    expect(ruled(s.audit).filter((l) => l.includes('breaker'))).toEqual([
      'policy queue policy-refused breaker.echo',
      'policy queue policy-refused breaker.echo',
      'release accept ok breaker.echo',
      'release reject policy-refused breaker.echo',
    ])
  })

  it('counts each passed send once, and a waiting send not at all, so the fan-out breaker counts sends', async () => {
    const s = setup({ members: deny })
    await s.edge.send(chat(P.carol))
    const waiting = await s.edge.sendOrWait(chat(P.jane))
    expect('waiting' in waiting).toBe(true)
    expect(s.store.fanoutSince(0)).toEqual({ sends: 1, contacts: 1 })
    const sent = await s.edge.sendOrWait(chat(P.mallory))
    expect(['targets' in sent, s.store.fanoutSince(0).sends]).toEqual([true, 2])
  })

  it("takes the gate's hooks and bounds from its gate option", async () => {
    const theirs = orgPolicy({ scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }] })
    const s = setup({ members: deny, gate: { breakers: false, recipientPolicy: async () => theirs } })
    await expect(s.edge.send({ ...chat(P.carol), type: 'deploy.run' })).rejects.toMatchObject({
      rule: 'recipient.scopes[0].accept_types',
    })
    await s.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
    expect((await s.edge.send(chat(P.mallory, { quote: T }))).targets).toHaveLength(1)
  })

  it('without a members record, sends as before: no breaker, nothing held', async () => {
    const s = setup()
    await s.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
    expect((await s.edge.send(chat(P.other, { quote: T }))).targets).toHaveLength(1)
    expect([s.edge.held(), s.store.fanoutSince(0).sends]).toEqual([[], 0])
  })
})
