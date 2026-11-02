import { serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, party, until, world } from '../harness.ts'

describe('e2e scenario 2: a cross-org chain, org -> principal -> session, with coding caveats', () => {
  it("(2) org acme's chain acme -> jane (type=coding.task) -> session (repo=bag) reaches bob of another org: the relay delivers it under bob's accept-from of acme's root; bob's edge resolves acme's well-known record, pins acme's key under its domain, accepts the message with root acme, principal jane and the caveats in chain order; bob's reply to the principal reaches the session's thread", async () => {
    const w = await world('s02')
    const acme = party('acme')
    const jane = party('jane')
    const session = party('session')
    const bob = party('bob')
    const site = await w.wellKnown()
    site.serve(() => serializeRecord(addressRecord(acme, { relays: [w.url], sealing: false })))
    const t = now()
    const auth = [
      signHop(acme.signing, jane.address, ['type=coding.task'], t + 86_400),
      signHop(jane.signing, session.address, ['repo=bag'], t + 3600),
    ]
    const s = w.node('session', {
      keys: { signing: session.signing, sealing: jane.sealing },
      auth,
      mailbox: jane.address,
      roots: [{ address: bob.address }],
      types: ['coding.*'],
    })
    const b = w.node('bob', { keys: bob.keys, roots: [{ domain: site.domain }], types: ['coding.*'] })
    await s.edge.publishRecord(addressRecord(jane, { relays: [w.url] }))
    await s.edge.publishRecord(acceptFrom(jane, [bob.address]))
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [acme.address]))
    b.edge.setDefault(
      b.handler('bob', (m) => b.edge.reply(m, { type: 'coding.result', body: { repo: 'bag', ok: true } })),
    )
    s.edge.attach(s.handler('coder'))
    await b.edge.start()
    await s.edge.start()

    const body = { repo: 'bag', task: 'review the patch' }
    const sent = await s.edge.send({ to: [bob.address], type: 'coding.task', body, session: 'coder' })
    expect(sent.targets.map((x) => x.state)).toEqual(['published'])
    await until('the reply at the session', () => s.received.length === 1)
    // bob's route line is written after his handler, which awaits its reply, returns: wait for his ack first.
    await until("bob's row acked", () => b.store.inboxList()[0]?.state === 'acked')

    expect(b.received).toEqual([
      {
        id: sent.id,
        from: session.address,
        principal: jane.address,
        root: acme.address,
        to: [bob.address],
        ts: expect.any(Number),
        type: 'coding.task',
        thread: sent.thread,
        body,
        caveats: ['type=coding.task', 'repo=bag'],
        relay: w.url,
      },
    ])
    expect(b.store.pinGet(`domain:${site.domain}`)?.key).toBe(acme.address)
    const pins = b.audit().filter((l) => l.event === 'pin')
    expect(pins.map((l) => [l.decision, JSON.parse(l.detail as string)])).toEqual([
      ['accept', { subject: `domain:${site.domain}`, key: acme.address }],
      // the reply resolves the principal's record at the relay, and pins that key under its address
      ['accept', { subject: `address:${jane.address}`, key: jane.address }],
    ])
    const resolved = b.audit().filter((l) => l.event === 'resolve' && l.detail?.includes('well-known'))
    expect(resolved.map((l) => l.decision)).toEqual(['accept'])
    expect(b.steps(sent.id)).toEqual([
      'verify accept ok',
      'policy accept ok',
      'dedup accept ok',
      'unseal accept ok',
      'policy accept ok',
      'route route ok',
    ])
    const policy = b.audit().find((l) => l.id === sent.id && l.event === 'policy')
    expect([policy?.root, JSON.parse(policy?.detail as string)]).toEqual([
      acme.address,
      { principal: jane.address },
    ])
    const publish = s.audit().find((l) => l.id === sent.id && l.event === 'publish')
    expect([publish?.root, JSON.parse(publish?.detail as string)]).toEqual([
      acme.address,
      { relay: w.url, tries: 1, duplicate: false, delivered: 1 },
    ])
    expect(s.received[0]).toMatchObject({
      from: bob.address,
      principal: bob.address,
      to: [jane.address],
      type: 'coding.result',
      thread: { id: sent.thread.id, prev: [sent.id] },
    })
    await until("the session's row acked", () => s.store.inboxList()[0]?.state === 'acked')
    expect(s.store.inboxList().map((r) => [r.mailbox, r.session])).toEqual([[jane.address, 'coder']])
    expect([s.errors, b.errors]).toEqual([[], []])
  })
})
