import { countersignRotation, serializeRecord, signHop } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Node,
  now,
  type Party,
  party,
  until,
  untilSecond,
  world,
} from '../harness.ts'

// The org's record lives a second, so bob's edge reads the well-known URL again for each message after a pause.
const TTL = 1

describe('e2e scenario 14: rotating a pinned org root', () => {
  it("(14) bob pins acme's first key at first contact; a rotation countersigned by that key is accepted and the pin moves to the new key; a bare rotation (rotated_from set, no countersignature) is refused with pin-mismatch, the pin stays, and the rotated key still works after it; the relay refuses the bare and a self-signed rotation record with 422 bad-rotation", async () => {
    const w = await world('s14')
    const site = await w.wellKnown()
    const k1 = party('acme-key-1')
    const k2 = party('acme-key-2')
    const forger = party('forger')
    const bob = party('bob')
    const t = now()
    const b = w.node('bob', { keys: bob.keys, roots: [{ domain: site.domain }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, ['*']))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    const sessionOf = (root: Party): Node => {
      const p = party(`session-of-${root.name}`)
      return w.node(p.name, { keys: p.keys, auth: [signHop(root.signing, p.address, [], t + 3600)] })
    }
    const s1 = sessionOf(k1)
    const s2 = sessionOf(k2)
    const s3 = sessionOf(forger)
    const record = (p: Party, rotatedFrom: string | null) =>
      addressRecord(p, { relays: [w.url], sealing: false, ttl: TTL, rotatedFrom })
    const pin = (): string | undefined => b.store.pinGet(`domain:${site.domain}`)?.key
    let handled = 0
    const deliver = async (s: Node, n: number): Promise<string> => {
      const sent = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { n } })
      expect(sent.targets.map((x) => x.state)).toEqual(['published'])
      handled++
      await until(`message ${n} handled`, () => b.store.inboxList(['acked']).length === handled)
      return sent.id
    }
    const afterCache = (): Promise<void> => untilSecond(now() + TTL + 1)

    site.serve(() => serializeRecord(record(k1, null)))
    const m1 = await deliver(s1, 1)
    expect(pin()).toBe(k1.address)
    await afterCache()
    site.serve(() => serializeRecord(countersignRotation(k1.signing, record(k2, k1.address))))
    const m2 = await deliver(s2, 2)
    expect(pin()).toBe(k2.address)
    await afterCache()
    site.serve(() => serializeRecord(record(forger, k2.address)))
    const m3 = await deliver(s3, 3)
    expect(pin()).toBe(k2.address)
    await afterCache()
    site.serve(() => serializeRecord(countersignRotation(k1.signing, record(k2, k1.address))))
    const m4 = await deliver(s2, 4)

    expect(b.store.inboxList().map((r) => [r.id, r.reason])).toEqual([
      [m1, null],
      [m2, null],
      [m3, 'pin-mismatch'],
      [m4, null],
    ])
    expect(b.received.map((m) => [m.id, m.root])).toEqual([
      [m1, k1.address],
      [m2, k2.address],
      [m4, k2.address],
    ])
    expect(b.steps(m3)).toEqual(['verify accept ok', 'policy reject pin-mismatch'])
    const subject = `domain:${site.domain}`
    const trail = b.audit().filter((l) => l.event === 'pin' || l.event === 'rotate')
    expect(trail.map((l) => [l.event, l.decision, l.reason, JSON.parse(l.detail as string)])).toEqual([
      ['pin', 'accept', 'ok', { subject, key: k1.address }],
      ['rotate', 'accept', 'ok', { subject, from: k1.address, to: k2.address }],
      [
        'rotate',
        'reject',
        'pin-mismatch',
        { subject, pinned: k2.address, offered: forger.address, check: 'bad-rotation' },
      ],
    ])

    // The relay's half: it checks a rotation against the address record it holds for rotated_from.
    await b.edge.publishRecord(addressRecord(k1, { relays: [w.url], sealing: false }))
    await b.edge.publishRecord(
      countersignRotation(k1.signing, addressRecord(k2, { relays: [w.url], rotatedFrom: k1.address })),
    )
    const bare = addressRecord(forger, { relays: [w.url], rotatedFrom: k2.address })
    const selfSigned = countersignRotation(forger.signing, bare)
    for (const r of [bare, selfSigned]) {
      const e = await b.edge.publishRecord(r).then(
        () => null,
        (x: unknown) => x,
      )
      expect(e).toBeInstanceOf(RelayError)
      expect([(e as RelayError).status, (e as RelayError).code]).toEqual([422, 'bad-rotation'])
    }
    expect(b.errors).toEqual([])
  })
})
