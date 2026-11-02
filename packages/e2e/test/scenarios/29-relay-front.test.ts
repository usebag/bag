import { type BuiltEnvelope, buildEnvelope, newThread, serializeRecord } from '@usebag/core'
import { coreRng, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, now, type Party, party, relayEvents, withSpawnedRelays, world } from '../harness.ts'

// e2e scenario 29: the relay's network front through the release binary. Every
// request here comes from 127.0.0.1; a relay that trusts 127.0.0.0/8 as a proxy counts and logs each request as the
// client its cf-connecting-ip header names, a relay that does not trusts no header, and a malformed value counts as
// the peer. The harness spawns relays with --log-ip full; the last part passes --log-ip prefix, the default.

/** A new chat envelope from `from` to `to`, a second earlier for each `n`, so each is a new id. */
function envelope(from: Party, to: Party, n: number): BuiltEnvelope {
  const rng = coreRng(systemRng)
  return buildEnvelope({
    from: from.signing,
    to: [{ address: to.address, sealingKey: to.sealing.publicKey }],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { n },
    ts: now() - n,
    rng,
  })
}

/** A raw POST to /v0/publish with `headers`: the status. */
async function post(url: string, bytes: Uint8Array, headers: Record<string, string> = {}): Promise<number> {
  const res = await fetch(`${url}/v0/publish`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: bytes,
  })
  await res.arrayBuffer()
  return res.status
}

const A = { 'cf-connecting-ip': '203.0.113.7' }
const B = { 'cf-connecting-ip': '198.51.100.9' }

/** The `ip` of every publish and rate-limited line, in order. */
function addresses(relay: Parameters<typeof relayEvents>[0]): [string, unknown][] {
  return relayEvents(relay)
    .filter((e) => e.event === 'publish' || e.event === 'rate-limited')
    .map((e) => [e.event as string, e.ip])
}

describe('e2e scenario 29: the relay behind a trusted proxy', () => {
  it('(29) trusting 127.0.0.0/8, three clients get three buckets of --rate-per-ip 3 and the lines name each; a malformed header counts as the proxy; a relay that trusts another network reads no header; the default log names a /24', async () => {
    const alice = party('alice')
    const bob = party('bob')
    const flags = ['--rate-window', '3600', '--rate-per-ip', '3']
    const trusted = await withSpawnedRelays(() =>
      world('s29-trusted', { relayArgs: [...flags, '--trust-proxy', '127.0.0.0/8'] }),
    )
    expect(await post(trusted.url, serializeRecord(acceptFrom(bob, ['*'])))).toBe(200)
    const statuses: number[] = []
    for (const n of [1, 2, 3, 4]) statuses.push(await post(trusted.url, envelope(alice, bob, n).bytes, A))
    statuses.push(await post(trusted.url, envelope(alice, bob, 5).bytes, B))
    statuses.push(await post(trusted.url, envelope(alice, bob, 6).bytes))
    // The proxy's bucket holds the record and the envelope with no header; a malformed value is the proxy's too.
    statuses.push(await post(trusted.url, envelope(alice, bob, 7).bytes, { 'cf-connecting-ip': 'not-an-ip' }))
    statuses.push(
      await post(trusted.url, envelope(alice, bob, 8).bytes, { 'cf-connecting-ip': '203.0.113.7:80' }),
    )
    console.log(`(29) measure: trusted, A x4, B, none, two malformed -> ${JSON.stringify(statuses)}`)
    expect(statuses).toEqual([200, 200, 200, 429, 200, 200, 200, 429])
    expect(addresses(trusted.relay)).toEqual([
      ['publish', '203.0.113.7'],
      ['publish', '203.0.113.7'],
      ['publish', '203.0.113.7'],
      ['rate-limited', '203.0.113.7'],
      ['publish', '198.51.100.9'],
      ['publish', '127.0.0.1'],
      ['publish', '127.0.0.1'],
      ['rate-limited', '127.0.0.1'],
    ])

    const other = await withSpawnedRelays(() =>
      world('s29-untrusted', { relayArgs: [...flags, '--trust-proxy', '10.0.0.0/8'] }),
    )
    expect(await post(other.url, serializeRecord(acceptFrom(bob, ['*'])))).toBe(200)
    const ignored: number[] = []
    for (const n of [1, 2, 3]) ignored.push(await post(other.url, envelope(alice, bob, n).bytes, A))
    ignored.push(await post(other.url, envelope(alice, bob, 4).bytes, B))
    console.log(`(29) measure: untrusted, A x3, B -> ${JSON.stringify(ignored)}`)
    expect(ignored).toEqual([200, 200, 429, 429])
    expect(addresses(other.relay).every(([, ip]) => ip === '127.0.0.1')).toBe(true)

    const prefixed = await withSpawnedRelays(() =>
      world('s29-prefix', { relayArgs: ['--trust-proxy', '127.0.0.0/8', '--log-ip', 'prefix'] }),
    )
    expect(await post(prefixed.url, serializeRecord(acceptFrom(bob, ['*'])), A)).toBe(200)
    expect(
      await post(prefixed.url, envelope(alice, bob, 1).bytes, { 'cf-connecting-ip': '2001:db8:5:6::7' }),
    ).toBe(200)
    const lines = relayEvents(prefixed.relay)
    expect(lines[0]).toMatchObject({ event: 'listening', log_ip: 'prefix', trust_proxy: '127.0.0.0/8' })
    expect(
      lines.filter((e) => e.event === 'publish-record' || e.event === 'publish').map((e) => e.ip),
    ).toEqual(['203.0.113.0/24', '2001:db8:5::/48'])
  })
})
