import { type SigningKey, signSubscribe, utf8 } from '@usebag/core'
import { subscribeUrl } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, sleep, storedAck, until, world } from '../harness.ts'

// e2e scenario 28 (spec/SPEC.md §8.5): delivery is at least once. A subscriber that reads a
// frame and closes without acking leaves the relay's stored ack where it was, so the next subscription that resumes
// from it gets the same frame again, cursor and bytes; the shipped edge, subscribing then, routes the message once
// and acks it, which moves the stored ack; and the same envelope handed in from another relay is a duplicate.

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

describe('e2e scenario 28: delivery is at least once', () => {
  it('(28) a frame read and not acked comes again, the same cursor and bytes, to the next subscription; the edge routes it once and acks it, and the same envelope from another relay is a duplicate', async () => {
    const w = await world('s28')
    const [alice, bob] = [party('alice'), party('bob')]
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    const sent = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 1 } })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])

    const [first] = await rawEnvFrames(w.url, bob.signing, 1)
    const [again] = await rawEnvFrames(w.url, bob.signing, 1)
    expect(again).toBe(first)
    expect(await storedAck(w.url, bob.signing)).toBe(0)
    const frame = JSON.parse(first as string) as { cursor: number; envelope: string }

    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    await until('the message at bob', () => b.received.some((m) => m.id === sent.id))
    await until('the row acked', () => b.rows(sent.id).some((r) => r.state === 'acked'))
    await b.edge.stop()
    const rows = b.rows(sent.id)
    expect(rows.map((r) => [r.cursor, r.state])).toEqual([[frame.cursor, 'acked']])
    expect(rows[0]?.bytes).toEqual(utf8(frame.envelope))
    let acked = await storedAck(w.url, bob.signing)
    for (let i = 0; i < 50 && acked !== frame.cursor; i++) {
      await sleep(100)
      acked = await storedAck(w.url, bob.signing)
    }
    expect(acked).toBe(frame.cursor)

    const other = await b.edge.receive('http://other-relay.test', 9, utf8(frame.envelope))
    expect([other.state, other.reason]).toEqual(['rejected', 'duplicate'])
    expect(b.received.map((m) => m.id)).toEqual([sent.id])
    expect(b.steps(sent.id).filter((s) => s.startsWith('route'))).toEqual(['route route ok'])
    console.log(
      `MEASURE L4(c) 28: a frame not acked came again to the next raw subscriber identical: ${again === first}; stored ack before the edge 0, after ${frame.cursor}; routed once; the same id from another relay: ${other.state} ${other.reason}`,
    )
  })
})
