import { buildEnvelope, newThread, type SigningKey, signFetchAuth, signSubscribe, utf8 } from '@usebag/core'
import { coreRng, subscribeUrl, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, party, rawPublish, until, world } from '../harness.ts'

// e2e scenario 26: the env frame carries the envelope as a JSON string of the exact bytes the
// relay stored (spec/SPEC.md §8.5 step 4), and the shipped edge verifies those bytes. An envelope the edge
// sent and the same kind of envelope published by hand with two-space indentation and newlines both reach a raw
// subscriber as strings equal to the published bytes, fetch by id answers those bytes with AC-Received-At, and the
// edge accepts both, its inbox rows holding exactly the published bytes.

/** Subscribes as the mailbox key over a raw WebSocket, keeps the text of `count` env frames, and closes, acking none. */
async function rawEnvFrames(url: string, key: SigningKey, count: number): Promise<string[]> {
  const ws = new WebSocket(subscribeUrl(url))
  return await new Promise<string[]>((resolve, reject) => {
    const frames: string[] = []
    const timer = setTimeout(() => {
      ws.close()
      reject(new Error(`${frames.length} of ${count} env frames within 10 s`))
    }, 10_000)
    ws.addEventListener('message', (event) => {
      const text = String(event.data)
      const f = JSON.parse(text) as { t: string; nonce?: string; error?: string }
      if (f.t === 'challenge') {
        const sig = signSubscribe(key, f.nonce as string, key.address, null)
        ws.send(
          JSON.stringify({
            t: 'auth',
            mailbox: key.address,
            signer: key.address,
            auth: [],
            cursor: null,
            sig,
          }),
        )
      } else if (f.t === 'env' || f.t === 'error') {
        if (f.t === 'env') frames.push(text)
        if (frames.length === count || f.t === 'error') {
          clearTimeout(timer)
          ws.close()
          if (f.t === 'error') reject(new Error(`the relay refused: ${f.error}`))
          else resolve(frames)
        }
      }
    })
  })
}

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

describe('e2e scenario 26: the env frame carries the exact stored bytes', () => {
  it('(26) an envelope the edge sent and one published by hand pretty-printed reach a raw subscriber as strings equal to the published bytes, fetch answers those bytes with AC-Received-At, and the edge accepts both with those bytes in its inbox', async () => {
    const w = await world('s26')
    const [alice, bob] = [party('alice'), party('bob')]
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    const t0 = now()

    const sent = await a.edge.send({
      to: [bob.address],
      type: 'chat.v1',
      body: { text: 'héllo 🚀 "quoted"' },
    })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    const built = buildEnvelope({
      from: alice.signing,
      to: [{ address: bob.address, sealingKey: bob.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread(coreRng(systemRng)),
      body: { text: 'pretty' },
      ts: now(),
      rng: coreRng(systemRng),
    })
    const pretty = utf8(JSON.stringify(JSON.parse(text(built.bytes)), null, 2))
    expect(text(pretty)).toContain('\n  "id": ')
    expect((await rawPublish(w.url, pretty)).status).toBe(200)
    const published = [a.store.outboxGet(sent.id)?.bytes as Uint8Array, pretty]

    const frames = (await rawEnvFrames(w.url, bob.signing, 2)).map(
      (f) => JSON.parse(f) as { cursor: number; received_at: number; envelope: unknown },
    )
    expect(frames.map((f) => [f.cursor, typeof f.envelope])).toEqual([
      [1, 'string'],
      [2, 'string'],
    ])
    expect(frames.map((f) => utf8(f.envelope as string))).toEqual(published)

    const stamps: (string | null)[] = []
    for (const [i, id] of [sent.id, built.envelope.id].entries()) {
      const ts = now()
      const res = await fetch(`${w.url}/v0/fetch/${id}`, {
        headers: {
          'AC-Signer': bob.address,
          'AC-Ts': String(ts),
          'AC-Sig': signFetchAuth(bob.signing, id, ts, w.url),
        },
      })
      expect(res.status).toBe(200)
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(published[i])
      stamps.push(res.headers.get('ac-received-at'))
    }
    expect(stamps).toEqual(frames.map((f) => String(f.received_at)))
    expect(frames.every((f) => f.received_at >= t0 && f.received_at <= now())).toBe(true)

    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    await until('both at bob', () => b.received.length === 2)
    const rows = [sent.id, built.envelope.id].map((id) => b.rows(id)[0])
    expect(rows.map((r) => r?.bytes)).toEqual(published)
    expect(rows.map((r) => r?.receivedAt)).toEqual(frames.map((f) => f.received_at))
    expect(b.received.map((m) => m.body)).toEqual([{ text: 'héllo 🚀 "quoted"' }, { text: 'pretty' }])
    console.log(
      `MEASURE L2(b) 26: 2 of 2 frames carry strings equal to the published bytes (${published.map((p) => p.length).join(' and ')} bytes, the second pretty-printed); fetch 2 of 2 with AC-Received-At ${stamps.join(', ')}; the edge accepted 2 of 2 with those bytes`,
    )
  })
})
