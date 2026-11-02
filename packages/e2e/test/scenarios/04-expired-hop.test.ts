import { signHop } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, party, rawPublish, world } from '../harness.ts'

async function refusal(p: Promise<unknown>): Promise<RelayError> {
  const e = await p.then(
    () => null,
    (x: unknown) => x,
  )
  expect(e).toBeInstanceOf(RelayError)
  return e as RelayError
}

describe('e2e scenario 4: a hop that expired before the envelope was built', () => {
  it("(4) a chain whose hop expired before ts: the relay refuses the publish with 422 hop-expired and stores nothing, so bob's fetch of the id is 404; bob's edge, handed the same bytes as a relay that skipped the check would deliver them, rejects them with hop-expired; and a session whose delegation expired cannot fetch with it (403 not-authorized) while a live delegation can", async () => {
    const w = await world('s04')
    const org = party('org')
    const late = party('late-session')
    const bob = party('bob')
    const alice = party('alice')
    const t = now()
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: org.address }, { address: alice.address }] })
    const s = w.node('late', { keys: late.keys, auth: [signHop(org.signing, late.address, [], t - 60)] })
    await b.edge.publishRecord(addressRecord(org, { relays: [w.url], sealing: false }))
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, ['*']))

    const sent = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { late: true } })
    expect(sent.targets.map((x) => [x.state, x.tries, x.reason])).toEqual([['failed', 1, 'hop-expired']])
    const line = s.audit().find((l) => l.event === 'publish')
    expect([line?.reason, JSON.parse(line?.detail as string).status]).toEqual(['hop-expired', 422])
    const bytes = s.store.outboxGet(sent.id)?.bytes as Uint8Array
    expect(await rawPublish(w.url, bytes)).toEqual({
      status: 422,
      body: { error: 'hop-expired' },
      retryAfter: null,
    })
    const missing = await refusal(b.edge.fetch(w.url, sent.id))
    expect([missing.status, missing.code]).toEqual([404, 'not-found'])

    const row = await b.edge.receive('direct:a-relay-that-skipped-the-check', 1, bytes)
    expect([row.state, row.reason, row.id]).toEqual(['rejected', 'hop-expired', sent.id])
    expect(b.steps(sent.id)).toEqual(['verify accept ok', 'policy reject hop-expired'])

    // The relay judges a fetch's chain at AC-Ts: an expired delegation from bob proves nothing, a live one does.
    const a = w.node('alice', { keys: alice.keys })
    const stored = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { live: true } })
    expect(stored.targets.map((x) => x.state)).toEqual(['published'])
    const expired = party('expired-delegate')
    const live = party('live-delegate')
    const delegate = (p: typeof expired, exp: number) =>
      w.node(p.name, {
        keys: { signing: p.signing, sealing: bob.sealing },
        mailbox: bob.address,
        auth: [signHop(bob.signing, p.address, [], exp)],
      })
    const old = await refusal(delegate(expired, t - 1).edge.fetch(w.url, stored.id))
    expect([old.status, old.code]).toEqual([403, 'not-authorized'])
    const fetched = await delegate(live, t + 3600).edge.fetch(w.url, stored.id)
    expect(fetched).toEqual(a.store.outboxGet(stored.id)?.bytes)
  })
})
