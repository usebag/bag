import { signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  party,
  rawPublish,
  sleep,
  until,
  untilSecond,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 22: the relay's hardening through the shipped edge and the release binary. (a) A
// subscriber that only answers the relay's pings is not closed as idle (the relay once closed it at
// exactly its idle timeout about half the time); (b) a session's subscription ends at its chain's
// earliest exp with hop-expired, and the edge's receiver, refused three times in a row, ends it for good (through
// the binary); (c) a record body over 131,072 bytes is 413 body-too-large and is not stored. Each part spawns its
// own relay, even under AC_RELAY_URL, since its flags are its point.

interface LogLine {
  readonly timestamp: string
  readonly fields: Record<string, unknown>
}

/** The relay's JSON log lines so far. */
function log(stderr: string): LogLine[] {
  return stderr
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as LogLine)
}

describe('e2e scenario 22: relay hardening through the edge', () => {
  it('(22a) with --ping-interval 1 --idle-timeout 2, an edge that sends nothing but pongs keeps one subscription for 6 s, three times the idle timeout, and receives a message sent at about 5 s', async () => {
    const w = await withSpawnedRelays(() =>
      world('s22a', { relayArgs: ['--ping-interval', '1', '--idle-timeout', '2'] }),
    )
    const alice = party('alice')
    const bob = party('bob')
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    await until('bob subscribed', () =>
      log(w.relay.stderr()).some((l) => l.fields.event === 'subscribe' && l.fields.mailbox === bob.address),
    )
    const subscribed = Date.now()
    await sleep(5_000)
    const sent = await a.edge.send({
      to: [bob.address],
      type: 'chat.v1',
      body: { text: 'after five quiet seconds' },
    })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    await until('the message at bob', () => b.received.some((m) => m.id === sent.id))
    await sleep(Math.max(0, subscribed + 6_000 - Date.now()))
    const mine = log(w.relay.stderr()).filter((l) => l.fields.mailbox === bob.address)
    const events = mine.map((l) => String(l.fields.event))
    expect(
      events.filter((e) => e === 'subscribe'),
      'one subscription, never closed',
    ).toHaveLength(1)
    expect(events.filter((e) => e === 'subscribe-closed')).toEqual([])
    expect(b.errors).toEqual([])
  }, 30_000)

  it("(22b) a session subscribed under a chain that expires is sent mail before its exp and none after: the relay ends the subscription with hop-expired within two seconds of exp (close 4001 is the Rust tests' to see), and, refused at its next two handshakes, the receiver ends it after three refusals", async () => {
    const w = await withSpawnedRelays(() => world('s22b'))
    const alice = party('alice')
    const bob = party('bob')
    const session = party('bob-session')
    const a = w.node('alice', { keys: alice.keys })
    const owner = w.node('bob', { keys: bob.keys })
    await owner.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await owner.edge.publishRecord(acceptFrom(bob, [alice.address]))
    // The chain's exp is a whole second, 4 s ahead: valid through it, refused from the next second on.
    await untilSecond(now() + 1)
    const exp = now() + 4
    const s = w.node('bob-session', {
      keys: { signing: session.signing, sealing: bob.sealing },
      mailbox: bob.address,
      auth: [signHop(bob.signing, session.address, [], exp)],
      roots: [{ address: alice.address }],
    })
    s.edge.setDefault(s.handler('bob-session'))
    await s.edge.start()
    // The precondition, measured on the relay's own log: its first handshake for the session was accepted at or
    // before exp. Mail "before exp" is then sent against that order, not against how long this process took to
    // get here; a handshake the relay refused hop-expired (the clock passed exp first) names itself here.
    const subscribedLine = (): LogLine | undefined =>
      log(w.relay.stderr()).find((l) => l.fields.event === 'subscribe' && l.fields.signer === session.address)
    await until(
      'the session subscribed before its chain expired (a first handshake refused hop-expired shows as none)',
      () => subscribedLine() !== undefined,
      10_000,
    )
    const subscribedAt = Date.parse(subscribedLine()?.timestamp as string) / 1000
    expect(Math.floor(subscribedAt), 'subscribed through exp').toBeLessThanOrEqual(exp)
    const before = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 1 } })
    await until('the message before exp', () => s.received.some((m) => m.id === before.id))
    const closed = (): LogLine | undefined =>
      log(w.relay.stderr()).find(
        (l) => l.fields.event === 'subscribe-closed' && l.fields.signer === session.address,
      )
    await until('the relay ends the subscription', () => closed() !== undefined, 10_000)
    const at = Date.parse(closed()?.timestamp as string) / 1000
    expect(closed()?.fields.reason).toBe('hop-expired')
    expect(at, 'after its exp').toBeGreaterThan(exp)
    expect(at, 'within two seconds of it').toBeLessThanOrEqual(exp + 2)
    const after = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 2 } })
    expect(after.targets.map((t) => t.state)).toEqual(['published'])
    await until('three refusals end it', () => s.steps().includes('subscribe reject hop-expired'), 15_000)
    expect(s.steps().filter((x) => x.startsWith('subscribe '))).toEqual([
      'subscribe retry hop-expired',
      'subscribe retry hop-expired',
      'subscribe reject hop-expired',
    ])
    await sleep(300)
    expect(
      s.received.map((m) => m.id),
      'nothing after exp',
    ).toEqual([before.id])
    const refused = log(w.relay.stderr()).filter(
      (l) => l.fields.event === 'subscribe-refused' && l.fields.code === 'hop-expired',
    )
    expect(refused.length).toBe(2)
  }, 40_000)

  it('(22c) a record body of 131,073 bytes is 413 body-too-large and not stored; one of 131,072 bytes is stored', async () => {
    const w = await withSpawnedRelays(() => world('s22c'))
    const bob = party('bob')
    const record = new TextEncoder().encode(JSON.stringify(addressRecord(bob, { relays: [w.url] })))
    const padded = (size: number): Uint8Array => {
      const out = new Uint8Array(size).fill(0x20)
      out[0] = record[0] as number
      out.set(record.subarray(1), size - record.length + 1)
      return out
    }
    expect(await rawPublish(w.url, padded(131_073))).toEqual({
      status: 413,
      body: { error: 'body-too-large' },
      retryAfter: null,
    })
    const fetch404 = await fetch(`${w.url}/v0/fetch/record/${bob.address}/address`)
    expect(fetch404.status).toBe(404)
    await fetch404.arrayBuffer()
    expect((await rawPublish(w.url, padded(131_072))).status).toBe(200)
    const stored = await fetch(`${w.url}/v0/fetch/record/${bob.address}/address`)
    expect([stored.status, (await stored.arrayBuffer()).byteLength]).toEqual([200, 131_072])
  })
})
