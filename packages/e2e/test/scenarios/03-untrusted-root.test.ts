import { serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, until, world } from '../harness.ts'

describe('e2e scenario 3: a root the recipient does not trust', () => {
  it("(3) a message whose root bob does not trust (neither his trusted key nor his trusted domain's key) is delivered by the relay, which judges no trust, and rejected by bob's edge in its policy step with untrusted-root: the row is acked with that reason, no handler sees it, and a message from the trusted root still arrives", async () => {
    const w = await world('s03')
    const stranger = party('stranger')
    const trusted = party('trusted')
    const org = party('org')
    const bob = party('bob')
    const site = await w.wellKnown()
    site.serve(() => serializeRecord(addressRecord(org, { relays: [w.url], sealing: false })))
    const b = w.node('bob', {
      keys: bob.keys,
      roots: [{ domain: site.domain }, { address: trusted.address }],
    })
    const s = w.node('stranger', { keys: stranger.keys })
    const t = w.node('trusted', { keys: trusted.keys })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, ['*']))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    const refused = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { hello: 'bob' } })
    const publish = s.audit().find((l) => l.event === 'publish')
    expect(JSON.parse(publish?.detail as string)).toEqual({
      relay: w.url,
      tries: 1,
      duplicate: false,
      delivered: 1,
    })
    const fence = await t.edge.send({ to: [bob.address], type: 'chat.v1', body: { hello: 'again' } })
    await until('the trusted message at bob', () => b.received.length === 1)
    await until('both rows acked', () => b.store.inboxList(['acked']).length === 2)

    expect(b.received.map((m) => [m.id, m.root])).toEqual([[fence.id, trusted.address]])
    expect(b.store.inboxList().map((r) => [r.cursor, r.id, r.state, r.reason, r.session])).toEqual([
      [1, refused.id, 'acked', 'untrusted-root', null],
      [2, fence.id, 'acked', null, 'bob'],
    ])
    expect(b.steps(refused.id)).toEqual(['verify accept ok', 'policy reject untrusted-root'])
    expect(b.store.pinGet(`domain:${site.domain}`)?.key).toBe(org.address)
    expect(b.errors).toEqual([])
  })
})
