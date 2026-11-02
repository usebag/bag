import { execFile } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  DEFAULT_RELAY_CMD,
  party,
  rawPublish,
  relayEvents,
  until,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 30: through the release binary, (a) `ac-relay probe <url> --key <file>`
// exits 0 printing `probe ok <id>`, publishes the probe's accept-from record on its first run only, stores one envelope
// a run in its own mailbox, and never prints its seed; against no relay it exits 1 naming the step; (b) a record
// publish answers its kind, signer, iat and valid_until, and the shipped edge, which reads `ok`, still publishes
// records and delivers; (c) health answers the URL the relay announced.

/** `ac-relay probe <args>`: its exit code, stdout and stderr. */
function probe(args: readonly string[]): Promise<{ code: number; out: string; err: string }> {
  const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
  return new Promise((resolve) => {
    execFile(cmd, ['probe', ...args], { timeout: 30_000 }, (error, out, err) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
      resolve({ code, out, err })
    })
  })
}

describe('e2e scenario 30: the probe, the record answer and health', () => {
  it('(30) the probe exits 0 twice, its record published once and one envelope a run; 1 against no relay; a record publish answers what it stored and the edge still delivers; health names the announced URL', async () => {
    const w = await withSpawnedRelays(() => world('s30'))
    const key = join(w.dir, 'probe.key')
    const first = await probe([w.url, '--key', key])
    const second = await probe([`${w.url}/`, '--key', key])
    const seed = readFileSync(key, 'utf8').trim()
    console.log(
      `(30) measure: probe ${first.code} ${first.out.trim()}; again ${second.code} ${second.out.trim()}`,
    )
    expect([first.code, second.code]).toEqual([0, 0])
    expect(first.out).toMatch(/^probe ok [0-9a-f]{64}\n$/)
    expect(second.out).toMatch(/^probe ok [0-9a-f]{64}\n$/)
    expect(first.out).not.toEqual(second.out)
    expect([first.err, second.err]).toEqual(['', ''])
    expect(first.out.includes(seed) || second.out.includes(seed)).toBe(false)
    const lines = relayEvents(w.relay)
    expect(lines.filter((e) => e.event === 'publish-record').map((e) => e.kind)).toEqual(['accept-from'])
    const probed = lines.filter((e) => e.event === 'publish')
    expect(probed.map((e) => [e.delivered, e.duplicate])).toEqual([
      [1, false],
      [1, false],
    ])
    expect(new Set(probed.map((e) => e.from)).size).toBe(1)

    // (b) The record answer, and the edge reading it.
    const bob = party('bob')
    const alice = party('alice')
    const address = addressRecord(bob, { relays: [w.url] })
    expect(await rawPublish(w.url, serializeRecord(address))).toEqual({
      status: 200,
      body: {
        ok: true,
        kind: 'address',
        signer: bob.address,
        iat: address.iat,
        valid_until: address.iat + address.ttl,
      },
      retryAfter: null,
    })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }], types: ['chat.v1'] })
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()
    const a = w.node('alice', { keys: alice.keys })
    await a.edge.publishRecord(addressRecord(alice, { relays: [w.url] }))
    const sent = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { via: 'probe' } })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    await until('the message at bob', () => b.received.length === 1)
    expect([a.errors, b.errors]).toEqual([[], []])

    // (c) Health names the URL the relay announced on its first line.
    const health = await fetch(`${w.url}/v0/health`)
    expect(((await health.json()) as { url: string }).url).toBe(w.url)

    await w.relay.stop()
    const dead = await probe([w.url, '--key', key])
    console.log(`(30) measure: against a stopped relay: ${dead.code} ${dead.err.trim()}`)
    expect(dead.code).toBe(1)
    expect(dead.err).toMatch(/^probe: health: /)
    expect(dead.out).toBe('')
  })
})
