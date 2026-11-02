import { describe, expect, it } from 'vitest'
import { acceptFrom, now, party, until, untilSecond } from '../harness.ts'
import {
  DEADLINE,
  envelope,
  events,
  parseResponse,
  portOf,
  publishRecords,
  rawConn,
  spawnRelay,
} from './support.ts'

// Cases F1-F5 and B1-B2: the trusted-proxy front and the per-client buckets
// (crates/ac-relay/src/net.rs Front::client :197-210, bucket :110-113). The release ac-relay on 127.0.0.1 from
// AC_RELAY_CMD, --log-ip full (the harness sets it), so each publish line names the whole client the relay keyed; a
// raw-socket POST (below) injects client-IP headers byte for byte, the one thing support.ts's fetch-based post()
// cannot do (a raw non-ASCII byte for F2, several header lines for F3). Nothing leaves this Mac: the peer is always
// 127.0.0.1 and every address in a header is a label the relay only logs or buckets, never connects to.

type PublishBody = {
  readonly ok?: boolean
  readonly id?: string
  readonly delivered?: number
  readonly duplicate?: boolean
  readonly error?: string
}

/**
 * A raw HTTP/1.1 POST of `bytes` to /v0/publish with `headerLines` injected verbatim and Connection: close (so the
 * relay closes once it answers): the status, the JSON answer and the headers. Full byte control, so a header value
 * can carry a raw 0x80 byte (F2) or repeat across lines (F3), which Node's fetch normalises or refuses.
 */
async function rawPost(
  url: string,
  bytes: Uint8Array,
  headerLines: readonly string[] = [],
): Promise<{
  readonly status: number
  readonly body: PublishBody
  readonly headers: Record<string, string>
}> {
  const conn = await rawConn(portOf(url))
  const head = `${[
    'POST /v0/publish HTTP/1.1',
    'Host: 127.0.0.1',
    'Content-Type: application/json',
    `Content-Length: ${bytes.length}`,
    'Connection: close',
    ...headerLines,
  ].join('\r\n')}\r\n\r\n`
  conn.socket.write(Buffer.concat([Buffer.from(head, 'latin1'), Buffer.from(bytes)]))
  await conn.closed(DEADLINE)
  const res = parseResponse(conn.received())
  if (res === null) {
    throw new Error(`no HTTP response (${conn.received().length} bytes)`)
  }
  let body: PublishBody = {}
  try {
    body = JSON.parse(res.body) as PublishBody
  } catch {
    body = { error: res.body }
  }
  return { status: res.status, body, headers: res.headers }
}

/** A sender and a mailbox whose accept-from admits every root (["*"]), so a lawful publish from `alice` delivers. */
async function deliverable(
  url: string,
): Promise<{ alice: ReturnType<typeof party>; bob: ReturnType<typeof party> }> {
  const alice = party('alice')
  const bob = party('bob')
  const [status] = await publishRecords(url, [acceptFrom(bob, ['*'])])
  expect(status, 'bob accept-from stored').toBe(200)
  return { alice, bob }
}

/** The whole client address the relay logged for the publish of `id` (--log-ip full), or undefined. */
function loggedClient(relay: Parameters<typeof events>[0], id: string): string | undefined {
  const line = events(relay).find((e) => e.event === 'publish' && e.id === id)
  return line?.ip as string | undefined
}

describe('F: the trusted-proxy front keys the right client (net.rs:197-210)', () => {
  it('F1 [no --trust-proxy] an untrusted peer that sets cf-connecting-ip: 9.9.9.9 is keyed as its peer 127.0.0.1, not the header (net.rs:201); V1 the publish still delivers', async () => {
    const relay = await spawnRelay('f1')
    const { alice, bob } = await deliverable(relay.url)
    const r = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 9.9.9.9'])
    expect(r.status).toBe(200)
    expect(r.body.ok, JSON.stringify(r.body)).toBe(true)
    expect(r.body.delivered, 'V1: the lawful publish delivered').toBeGreaterThanOrEqual(1)
    await until('the publish is logged', () => loggedClient(relay, r.body.id as string) !== undefined)
    const client = loggedClient(relay, r.body.id as string)
    console.log(`F1 measure: untrusted peer, header 9.9.9.9 ignored, keyed client=${client}`)
    expect(client).toBe('127.0.0.1')
  })

  it('F2 [--trust-proxy 127.0.0.0/8 --client-ip-header cf-connecting-ip] a header value with a raw 0x80 byte voids the whole header; the client falls back to the peer 127.0.0.1 and nothing panics (net.rs:200)', async () => {
    const relay = await spawnRelay('f2', [
      '--trust-proxy',
      '127.0.0.0/8',
      '--client-ip-header',
      'cf-connecting-ip',
    ])
    const { alice, bob } = await deliverable(relay.url)
    // A raw 0x80 (latin1) is obs-text on the wire: hyper accepts it, but http's to_str() errs, voiding the header.
    const bad = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: \u0080'])
    expect(bad.status, JSON.stringify(bad.body)).toBe(200)
    expect(bad.body.ok).toBe(true)
    await until(
      'the bad-header publish is logged',
      () => loggedClient(relay, bad.body.id as string) !== undefined,
    )
    const client = loggedClient(relay, bad.body.id as string)
    console.log(`F2 measure: non-ASCII header voided, keyed client=${client}`)
    expect(client).toBe('127.0.0.1')
    // Nothing panicked: the next lawful request is still answered.
    const after = await rawPost(relay.url, envelope(alice, [bob]).bytes)
    expect(after.status, 'V1: a clean request after the bad header').toBe(200)
    expect(after.body.ok).toBe(true)
  })

  it('F3 [--trust-proxy 127.0.0.0/8] the header is walked right-to-left: the first address outside the trusted CIDR is the client, in one comma list and across lines; an all-trusted chain yields the peer (net.rs:202-208)', async () => {
    const relay = await spawnRelay('f3', ['--trust-proxy', '127.0.0.0/8'])
    const { alice, bob } = await deliverable(relay.url)
    // One line, comma list: right-most 127.0.0.9 is trusted and skipped, 198.51.100.7 is the client.
    const comma = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: 198.51.100.7, 127.0.0.9',
    ])
    // Two header lines: get_all joins them, 127.0.0.10 (right-most) is skipped, 198.51.100.8 is the client.
    const lines = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: 198.51.100.8',
      'cf-connecting-ip: 127.0.0.10',
    ])
    // An all-trusted chain: no untrusted address, so the request is the proxy's (the peer 127.0.0.1).
    const allTrusted = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: 127.0.0.5, 127.0.0.6',
    ])
    for (const r of [comma, lines, allTrusted]) {
      expect(r.status, JSON.stringify(r.body)).toBe(200)
      expect(r.body.ok).toBe(true)
    }
    await until('all three publishes logged', () =>
      [comma, lines, allTrusted].every((r) => loggedClient(relay, r.body.id as string) !== undefined),
    )
    const got = {
      comma: loggedClient(relay, comma.body.id as string),
      lines: loggedClient(relay, lines.body.id as string),
      allTrusted: loggedClient(relay, allTrusted.body.id as string),
    }
    console.log(`F3 measure: keyed clients ${JSON.stringify(got)}`)
    expect(got.comma).toBe('198.51.100.7')
    expect(got.lines).toBe('198.51.100.8')
    expect(got.allTrusted).toBe('127.0.0.1')
  })

  it('F4 [--trust-proxy 127.0.0.0/8] a port suffix and brackets fail IpAddr::from_str and fall back to the peer; a bare IPv6 parses and is the client, logged whole (net.rs:206, :110-113)', async () => {
    const relay = await spawnRelay('f4', ['--trust-proxy', '127.0.0.0/8'])
    const { alice, bob } = await deliverable(relay.url)
    const port = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 203.0.113.7:443'])
    const brackets = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: [2001:db8::1]',
    ])
    const bareV6 = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 2001:db8::1'])
    for (const r of [port, brackets, bareV6]) {
      expect(r.status, JSON.stringify(r.body)).toBe(200)
      expect(r.body.ok).toBe(true)
    }
    await until('all three publishes logged', () =>
      [port, brackets, bareV6].every((r) => loggedClient(relay, r.body.id as string) !== undefined),
    )
    const got = {
      port: loggedClient(relay, port.body.id as string),
      brackets: loggedClient(relay, brackets.body.id as string),
      bareV6: loggedClient(relay, bareV6.body.id as string),
    }
    console.log(`F4 measure: keyed clients ${JSON.stringify(got)}`)
    expect(got.port).toBe('127.0.0.1')
    expect(got.brackets).toBe('127.0.0.1')
    expect(got.bareV6).toBe('2001:db8::1')
  })

  it('F5 (measure) [--trust-proxy 0.0.0.0/0] a relay that trusts every proxy honours any client-supplied address (config hazard, recorded)', async () => {
    const relay = await spawnRelay('f5', ['--trust-proxy', '0.0.0.0/0'])
    const { alice, bob } = await deliverable(relay.url)
    // 0.0.0.0/0 is an IPv4 network: a forged IPv6 value is cross-family (untrusted) and is honoured as the client,
    // while a forged IPv4 value is itself a "trusted proxy" and collapses to the peer. Either way the forged address
    // can move the rate/cap key off the peer: a configuration that disables the per-client front. Measure only.
    const v6 = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 2001:db8::99'])
    const v4 = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 198.51.100.50'])
    expect(v6.status).toBe(200)
    expect(v4.status).toBe(200)
    await until('both publishes logged', () =>
      [v6, v4].every((r) => loggedClient(relay, r.body.id as string) !== undefined),
    )
    const got = {
      forgedV6: loggedClient(relay, v6.body.id as string),
      forgedV4: loggedClient(relay, v4.body.id as string),
    }
    console.log(
      `F5 measure (config hazard): keyed clients under --trust-proxy 0.0.0.0/0 = ${JSON.stringify(got)}`,
    )
  })
})

describe('B: per-client buckets behind a proxy (net.rs:110-113)', () => {
  it('B1 (measure) [--trust-proxy 127.0.0.0/8] one honest proxy that sets the header keys N distinct real clients distinctly', async () => {
    const relay = await spawnRelay('b1', ['--trust-proxy', '127.0.0.0/8'])
    const { alice, bob } = await deliverable(relay.url)
    const clients = ['198.51.100.1', '198.51.100.2', '198.51.100.3']
    const ids: string[] = []
    for (const c of clients) {
      const r = await rawPost(relay.url, envelope(alice, [bob]).bytes, [`cf-connecting-ip: ${c}`])
      expect(r.status).toBe(200)
      ids.push(r.body.id as string)
    }
    await until('three publishes logged', () => ids.every((id) => loggedClient(relay, id) !== undefined))
    const keyed = ids.map((id) => loggedClient(relay, id))
    console.log(
      `B1 measure: three real clients keyed ${JSON.stringify(keyed)} (an untrusted peer cannot move it, F1)`,
    )
    expect(keyed).toEqual(clients)
  })

  it('B2 [--trust-proxy 127.0.0.0/8 --rate-per-ip 1 --rate-window 3600] two IPv6 clients in one /56 share a bucket; a third in a neighbouring /56 is separate (net.rs, rate_bucket)', async () => {
    const relay = await spawnRelay('b2', [
      '--trust-proxy',
      '127.0.0.0/8',
      '--rate-per-ip',
      '1',
      '--rate-window',
      '3600',
    ])
    const { alice, bob } = await deliverable(relay.url)
    // Keep the whole burst inside one aligned 3600 s window, so the per-IP counters do not reset mid-test.
    const win = 3600
    if (win - (now() % win) < 10) await untilSecond(now() - (now() % win) + win + 1)
    // Same /56 (2001:db8:0:0::/56), another /64: the first spends the one slot, the second is refused.
    const first = await rawPost(relay.url, envelope(alice, [bob]).bytes, ['cf-connecting-ip: 2001:db8::1'])
    const same56 = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: 2001:db8:0:1::1',
    ])
    // Neighbouring /56 (2001:db8:0:100::/56): a bucket of its own, so it is served.
    const other56 = await rawPost(relay.url, envelope(alice, [bob]).bytes, [
      'cf-connecting-ip: 2001:db8:0:100::1',
    ])
    const report = `first=${first.status} same/56=${same56.status}(${same56.body.error}) other/56=${other56.status}`
    console.log(`B2 measure: ${report}`)
    expect(first.status, report).toBe(200)
    expect(same56.status, report).toBe(429)
    expect(same56.body.error, report).toBe('rate-limited')
    expect(same56.headers['retry-after'], report).toBeDefined()
    expect(other56.status, report).toBe(200)
    // The refusal was keyed to the forged /56, not the loopback peer.
    const limited = events(relay).filter((e) => e.event === 'rate-limited' && e.limit === 'ip')
    expect(limited.map((e) => e.ip)).toContain('2001:db8:0:1::1')
  })
})
