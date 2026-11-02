import { openSealed, parseEnvelope } from '@usebag/core'
import { RECEIPT_ACK, RECEIPT_HINT, RECEIPT_TYPE } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type NodeOptions,
  party,
  sleep,
  until,
  type World,
  world,
} from '../harness.ts'

// e2e scenario 53 (spec/SPEC.md §10 Read receipts): a sender
// learns a message reached its reader, on the release relay, and nothing else happens: a reader who has not named the
// peer stays silent, and a receipt never earns a receipt. SETTLE_MS is several of the nodes' 200 ms ticks: long enough for
// a receipt that was going to go out to have reached the sender.

const SETTLE_MS = 1200

/** A started node of `p`, its records at the relay, trusting and accepting `peers`. */
async function started(
  w: World,
  p: ReturnType<typeof party>,
  peers: readonly ReturnType<typeof party>[],
  o: Partial<NodeOptions> = {},
) {
  const addresses = peers.map((peer) => peer.address)
  const n = w.node(p.name, { keys: p.keys, roots: addresses.map((address) => ({ address })), ...o })
  await n.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
  await n.edge.publishRecord(acceptFrom(p, addresses))
  n.edge.setDefault(n.handler(p.name))
  await n.edge.start()
  return n
}

describe('e2e scenario 53: read receipts', () => {
  it('(53a) a reader who named the peer answers: sealed, the id alone; the sender learns it, and no session of its hears', async () => {
    const w = await world('s53a')
    const [alice, bob] = [party('alice'), party('bob')]
    const a = await started(w, alice, [bob])
    const b = await started(w, bob, [alice], { receiptsTo: () => [alice.address] })
    const body = { text: 'did this reach you?' }
    const sent = await a.edge.send({ to: [bob.address], type: 'chat.v1', body, receipt: true })
    await until('the receipt at alice', () => a.edge.receipts(sent.id).length === 1)
    expect(a.edge.receipts(sent.id)[0]?.reader).toBe(bob.address)
    expect(b.received[0]?.body).toEqual({ ...body, [RECEIPT_HINT]: true })

    const [row] = a.store.inboxList()
    expect(row?.state).toBe('consumed')
    const env = parseEnvelope(row?.bytes as Uint8Array)
    const content = openSealed(env, { address: alice.address, key: alice.keys.sealing })
    expect(content.type).toBe(RECEIPT_TYPE)
    expect(content.body).toEqual({ [RECEIPT_ACK]: sent.id })
    expect(a.received).toEqual([])
    expect(a.errors).toEqual([])
    expect(b.errors).toEqual([])
  })

  it('(53b) off by default: a reader with receipts off, one who named someone else and one who never read all look the same', async () => {
    const w = await world('s53b')
    const [alice, off, other, unread] = [party('alice'), party('off'), party('other'), party('unread')]
    // Alice trusts and accepts all three, so a receipt any of them wrongly sent would land and be seen.
    const a = await started(w, alice, [off, other, unread])
    const nodes = [
      await started(w, off, [alice]),
      await started(w, other, [alice], { receiptsTo: () => [unread.address] }),
    ]
    // Never started, so it never reads: its records are all it has done.
    const asleep = w.node(unread.name, { keys: unread.keys, roots: [{ address: alice.address }] })
    await asleep.edge.publishRecord(addressRecord(unread, { relays: [w.url] }))
    await asleep.edge.publishRecord(acceptFrom(unread, [alice.address]))

    const ids = []
    for (const p of [off, other, unread]) {
      const input = { to: [p.address], type: 'chat.v1', body: { text: 'hello' }, receipt: true }
      ids.push((await a.edge.send(input)).id)
    }
    for (const n of nodes) await until(`the message at ${n.name}`, () => n.received.length === 1)
    await sleep(SETTLE_MS)
    expect(ids.map((id) => a.edge.receipts(id))).toEqual([[], [], []])
    expect(a.store.inboxList()).toEqual([])
    for (const n of nodes) expect(n.errors).toEqual([])
  })

  it('(53c) no receipt for a receipt: with each naming the other, one receipt goes one way and nothing comes back', async () => {
    const w = await world('s53c')
    const [alice, bob] = [party('alice'), party('bob')]
    const a = await started(w, alice, [bob], { receiptsTo: () => [bob.address] })
    const b = await started(w, bob, [alice], { receiptsTo: () => [alice.address] })
    const input = { to: [bob.address], type: 'chat.v1', body: { text: 'hello' }, receipt: true }
    const sent = await a.edge.send(input)
    await until('the receipt at alice', () => a.edge.receipts(sent.id).length === 1)
    await sleep(SETTLE_MS)
    expect(b.store.inboxList().map((r) => r.id)).toEqual([sent.id])
    expect(a.store.inboxList()).toHaveLength(1)
    expect(a.edge.receipts(sent.id)).toHaveLength(1)
  })
})
