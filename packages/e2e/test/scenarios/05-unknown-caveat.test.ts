import { signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, party, until, world } from '../harness.ts'

describe('e2e scenario 5: a caveat no profile knows', () => {
  it("(5) a chain carrying the caveat foo=bar is accepted and delivered by the relay, which never evaluates caveats, and rejected by bob's edge after unsealing with unknown-caveat naming foo=bar; a known caveat that does not hold (type=chat.v1 on chat.v2) is caveat-failed, and one that holds is routed", async () => {
    const w = await world('s05')
    const org = party('org')
    const unknown = party('unknown-session')
    const known = party('known-session')
    const bob = party('bob')
    const t = now()
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: org.address }] })
    const u = w.node('unknown', {
      keys: unknown.keys,
      auth: [signHop(org.signing, unknown.address, ['foo=bar'], t + 3600)],
    })
    const k = w.node('known', {
      keys: known.keys,
      auth: [signHop(org.signing, known.address, ['type=chat.v1'], t + 3600)],
    })
    await b.edge.publishRecord(addressRecord(org, { relays: [w.url], sealing: false }))
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [org.address]))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    const foo = await u.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 1 } })
    const wrongType = await k.edge.send({ to: [bob.address], type: 'chat.v2', body: { n: 2 } })
    const holds = await k.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 3 } })
    for (const sent of [foo, wrongType, holds]) {
      expect(sent.targets.map((x) => [x.state, x.reason])).toEqual([['published', null]])
    }
    await until('three rows acked', () => b.store.inboxList(['acked']).length === 3)

    expect(b.store.inboxList().map((r) => [r.id, r.reason])).toEqual([
      [foo.id, 'unknown-caveat'],
      [wrongType.id, 'caveat-failed'],
      [holds.id, null],
    ])
    const before = ['verify accept ok', 'policy accept ok', 'dedup accept ok', 'unseal accept ok']
    expect(b.steps(foo.id)).toEqual([...before, 'policy reject unknown-caveat'])
    expect(b.steps(wrongType.id)).toEqual([...before, 'policy reject caveat-failed'])
    expect(b.steps(holds.id)).toEqual([...before, 'policy accept ok', 'route route ok'])
    const rejects = b.audit().filter((l) => l.decision === 'reject')
    expect(rejects.map((l) => JSON.parse(l.detail as string).caveat)).toEqual(['foo=bar', 'type=chat.v1'])
    expect(b.received.map((m) => [m.id, m.caveats])).toEqual([[holds.id, ['type=chat.v1']]])
    expect(b.errors).toEqual([])
  })
})
