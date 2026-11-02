import { signFetchAuth, signHop } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, type Node, now, type Party, party, world } from '../harness.ts'

// e2e scenario 27 (spec/SPEC.md §8.3): fetch by id
// through the release relay for an envelope that a session sent under the two-hop chain org -> principal -> session.
// The parties are its `from`, each `to` and its principal, the last hop's `iss`, and a key with a chain from any of
// them; so the session, the recipient, the principal and the principal's own session get the exact bytes, with
// AC-Received-At, and the org root, the first hop's `iss`, a third party and the org root's delegate get 403
// not-authorized.

async function outcome(n: Node, url: string, id: string, bytes: Uint8Array): Promise<string> {
  return n.edge.fetch(url, id).then(
    (b) => (Buffer.from(b).equals(Buffer.from(bytes)) ? '200 exact' : '200 other bytes'),
    (e: unknown) => (e instanceof RelayError ? `${e.status} ${e.code}` : String(e)),
  )
}

describe('e2e scenario 27: the principal fetches what its session sent', () => {
  it("(27) under org -> principal -> session, the session, the recipient, the principal and the principal's own session fetch the exact bytes with AC-Received-At; the org root, a third party and the org root's delegate get 403 not-authorized", async () => {
    const w = await world('s27')
    const org = party('org')
    const principal = party('principal')
    const session = party('session')
    const own = party('principal-own-session')
    const bob = party('bob')
    const stranger = party('stranger')
    const orgDelegate = party('org-delegate')
    const t = now()
    const chain = [
      signHop(org.signing, principal.address, [], t + 3600),
      signHop(principal.signing, session.address, [], t + 3600),
    ]
    const s = w.node('session', { keys: session.keys, auth: chain })
    const b = w.node('bob', { keys: bob.keys })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, ['*']))
    const sent = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { for: 'bob' } })
    expect(sent.targets.map((x) => x.state)).toEqual(['published'])
    const bytes = s.store.outboxGet(sent.id)?.bytes as Uint8Array

    const delegate = (who: Party, of: Party): Node =>
      w.node(who.name, {
        keys: { signing: who.signing, sealing: of.sealing },
        mailbox: of.address,
        auth: [signHop(of.signing, who.address, [], t + 3600)],
      })
    const cases: [string, Node][] = [
      ['from, the session', s],
      ['to, the recipient', b],
      ['the principal', w.node('principal', { keys: principal.keys })],
      ["the principal's own session", delegate(own, principal)],
      ['the org root', w.node('org', { keys: org.keys })],
      ['a third party', w.node('stranger', { keys: stranger.keys })],
      ["the org root's delegate", delegate(orgDelegate, org)],
    ]
    const got: string[] = []
    for (const [, n] of cases) got.push(await outcome(n, w.url, sent.id, bytes))
    expect(got).toEqual([
      '200 exact',
      '200 exact',
      '200 exact',
      '200 exact',
      '403 not-authorized',
      '403 not-authorized',
      '403 not-authorized',
    ])
    const ts = now()
    const res = await fetch(`${w.url}/v0/fetch/${sent.id}`, {
      headers: {
        'AC-Signer': principal.address,
        'AC-Ts': String(ts),
        'AC-Sig': signFetchAuth(principal.signing, sent.id, ts, w.url),
      },
    })
    const stamp = Number(res.headers.get('ac-received-at'))
    expect([res.status, stamp >= t && stamp <= now()]).toEqual([200, true])
    console.log(
      `MEASURE L3 27: ${cases.map(([label], i) => `${label} ${got[i]}`).join('; ')}; the principal's answer AC-Received-At t+${stamp - t}`,
    )
  })
})
