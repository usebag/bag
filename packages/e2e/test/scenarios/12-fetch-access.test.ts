import { signFetchAuth, signHop } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, type Node, now, type Party, party, world } from '../harness.ts'

async function fetched(n: Node, url: string, id: string): Promise<Uint8Array | RelayError> {
  return n.edge.fetch(url, id).then(
    (b) => b,
    (e: unknown) => {
      expect(e).toBeInstanceOf(RelayError)
      return e as RelayError
    },
  )
}

describe('e2e scenario 12: who may fetch an envelope by id', () => {
  it("(12) fetch by id returns the exact stored bytes to the sender, the recipient and a key the recipient delegated to; a third party and a third party's delegate get 403 not-authorized, a bad signature 401 bad-auth, an unknown id 404 not-found; and the principal of a sending session, in neither from nor to, gets the exact bytes too (the fetch party rule of spec/SPEC.md §8.3)", async () => {
    const w = await world('s12')
    const alice = party('alice')
    const bob = party('bob')
    const carol = party('carol')
    const jane = party('jane')
    const session = party('session')
    const t = now()
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys })
    const c = w.node('carol', { keys: carol.keys })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, ['*']))
    const sent = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { secret: 'for bob' } })
    const bytes = a.store.outboxGet(sent.id)?.bytes as Uint8Array

    const delegate = (p: Party, of: Party): Node =>
      w.node(`${p.name}-of-${of.name}`, {
        keys: { signing: p.signing, sealing: of.sealing },
        mailbox: of.address,
        auth: [signHop(of.signing, p.address, [], t + 3600)],
      })
    expect(await fetched(a, w.url, sent.id)).toEqual(bytes)
    expect(await fetched(b, w.url, sent.id)).toEqual(bytes)
    expect(await fetched(delegate(party('bob-session'), bob), w.url, sent.id)).toEqual(bytes)
    for (const n of [c, delegate(party('carol-session'), carol)]) {
      const e = (await fetched(n, w.url, sent.id)) as RelayError
      expect([e.status, e.code]).toEqual([403, 'not-authorized'])
    }
    const res = await fetch(`${w.url}/v0/fetch/${sent.id}`, {
      headers: {
        'AC-Signer': alice.address,
        'AC-Ts': String(t),
        'AC-Sig': signFetchAuth(carol.signing, sent.id, t, w.url),
      },
    })
    expect([res.status, await res.json()]).toEqual([401, { error: 'bad-auth' }])
    const unknown = (await fetched(a, w.url, 'ab'.repeat(32))) as RelayError
    expect([unknown.status, unknown.code]).toEqual([404, 'not-found'])

    const s = w.node('session', {
      keys: session.keys,
      auth: [signHop(jane.signing, session.address, [], t + 3600)],
    })
    const viaSession = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: {} })
    expect(viaSession.targets.map((x) => x.state)).toEqual(['published'])
    expect(await fetched(s, w.url, viaSession.id)).toEqual(s.store.outboxGet(viaSession.id)?.bytes)
    const principal = await fetched(w.node('jane', { keys: jane.keys }), w.url, viaSession.id)
    expect(principal).toEqual(s.store.outboxGet(viaSession.id)?.bytes)
  })
})
