import { Socket } from 'node:net'
import { classifyIp, judgeAddresses, parseRecord, serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { hostOf, type Lookup } from '../src/net.ts'
import type { OutboxTarget } from '../src/ports.ts'
import { noSockets } from './support/adversarial.ts'
import { addressRecord, FakeClock, FakeRecords, MemoryAuditSink, P, seededRng } from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// The edge's private-address guard (packages/edge/src/net.ts) against relay URLs that a
// recipient's address record names. Strictly in process (V8): the relay client is ScriptedRelay, which records the URL
// it is asked to POST to and opens no socket; the guard's `lookup` is injected, so no name reaches a real resolver; and
// noSockets() refuses (and counts) every net.Socket connect and global fetch while each test runs. Nothing here can
// open a connection toward 100.64.0.0/10, 240.0.0.0/4 or any other range below, even if a line were red.
//
// E1 (measure): the guard keeps six address classes (classify4, net.ts line 56; classify6, line
// 65) where the core has twelve (NET_CATEGORIES, packages/core/src/net.ts line 23). The line records, per range, whether
// the sender's edge asks its relay client to POST (sender.ts lines 168 to 170) or refuses the target resolve-failed
// before any request (sender.ts lines 177 to 192). No demand: the gap is the decided design.
//
// E2 (fixed): credentials (userinfo, net.ts line 151), the six classes as literals (line 156), the loopback
// names (line 161) and a name resolving only to such addresses (lines 164 to 176) are refused resolve-failed with no
// request; the edge's own relays are allowed (line 136); allowPrivateRelays turns the guard off.

const HOME = 'http://home.test'

type Verdict = 'POST attempted' | 'refused resolve-failed'

/** The answers the injected lookup gives, by host; it records every host it is asked about. */
function lookupOf(answers: Readonly<Record<string, readonly string[]>>): { lookup: Lookup; asked: string[] } {
  const asked: string[] = []
  return {
    asked,
    lookup: async (host) => {
      asked.push(host)
      const a = answers[host]
      if (a === undefined) throw new Error(`ENOTFOUND ${host}`)
      return a
    },
  }
}

/** Records that also note every relay a record is asked of. */
class NotingRecords extends FakeRecords {
  readonly asked: string[] = []

  override async relayRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    this.asked.push(url)
    return super.relayRecord(url, address, kind)
  }
}

/**
 * Carol's edge, whose own relay is HOME (a name, allowed outright, never looked up), where bob's address record names
 * `relays`; the relay client records every POST and opens nothing.
 */
function carol(
  relays: readonly string[],
  o: { lookup?: Lookup; own?: readonly string[]; allowPrivate?: boolean } = {},
) {
  const records = new NotingRecords()
  const record = addressRecord(P.bob, { relays })
  // The record passes the core's record checks: the edge, not the record grammar, is what decides.
  expect(parseRecord(serializeRecord(record)).kind).toBe('address')
  records.put(HOME, record)
  const relay = new ScriptedRelay()
  const store = new SqliteStore(':memory:')
  const audit = new MemoryAuditSink()
  const edge = new Edge({
    keys: P.carol.keys,
    store,
    relays: { client: relay, urls: [HOME, ...(o.own ?? [])] },
    records,
    policy: { roots: [], types: [] },
    clock: new FakeClock(),
    rng: seededRng('adversarial-guard-r2'),
    audit,
    ...(o.lookup === undefined ? {} : { lookup: o.lookup }),
    ...(o.allowPrivate === undefined ? {} : { allowPrivateRelays: o.allowPrivate }),
  })
  return { edge, relay, records, store, audit }
}

/** Sends one message from carol to bob, whose record names `url`: what the edge did with the target. */
async function verdictFor(
  url: string,
  o: { lookup?: Lookup; own?: readonly string[]; allowPrivate?: boolean } = {},
): Promise<{ verdict: Verdict; posts: number; target: OutboxTarget }> {
  const { edge, relay, store } = carol([url], o)
  try {
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { probe: url } })
    const target = sent.targets[0] as OutboxTarget
    expect(sent.targets).toHaveLength(1)
    const posts = relay.published.filter((p) => p.url === url).length
    expect(relay.published.length).toBe(posts)
    if (posts === 1) {
      expect(target).toMatchObject({ relay: url, state: 'published', tries: 1 })
      return { verdict: 'POST attempted', posts, target }
    }
    expect(posts).toBe(0)
    expect(target).toMatchObject({ relay: url, state: 'failed', reason: 'resolve-failed', tries: 1 })
    return { verdict: 'refused resolve-failed', posts, target }
  } finally {
    store.close()
  }
}

/** The core's twelve-class verdict on a URL's host literal (packages/core/src/net.ts classifyIp). */
const coreOf = (url: string): string => classifyIp(hostOf(url)) ?? 'not-an-address'

describe('measure: what the six-class guard admits, strictly in process', () => {
  it("the no-socket guard's own control (V4): a connect and a fetch are refused before any packet, and counted", async () => {
    const sockets = noSockets()
    // Loopback port 1 even so: were the guard broken, the attempt would stay on this host.
    expect(() => new Socket().connect(1, '127.0.0.1')).toThrow(
      'no-socket guard: a socket connect was attempted',
    )
    await expect(fetch('http://127.0.0.1:1/')).rejects.toThrow('no-socket guard: a fetch was attempted')
    expect(sockets.attempts()).toBe(2)
  })

  it('records, per special range, whether the sender asks its relay client to POST; no socket, no real lookup', async () => {
    const sockets = noSockets()
    const names = lookupOf({ 'tailnet-peer.test': ['100.101.102.103'] })
    // [range, url, the expected verdict for the edge] (the expectation: a POST for 100.64.0.0/10 and the reserved
    // ranges; the documentation, benchmarking and IETF ranges are in the same row).
    const rows: [string, string, Verdict][] = [
      ['shared 100.64.0.0/10 (Tailscale CGNAT), first', 'http://100.64.0.1:7777/', 'POST attempted'],
      ['shared 100.64.0.0/10, last', 'http://100.127.255.254:7777/', 'POST attempted'],
      [
        'shared 100.64.0.0/10, by a name the lookup answers',
        'http://tailnet-peer.test:7777/',
        'POST attempted',
      ],
      ['reserved 240.0.0.0/4', 'http://240.0.0.1:7777/', 'POST attempted'],
      ['reserved 240.0.0.0/4, limited broadcast', 'http://255.255.255.255:7777/', 'POST attempted'],
      ['reserved 192.88.99.0/24 (6to4 relay anycast)', 'http://192.88.99.1:7777/', 'POST attempted'],
      ['reserved IPv6 outside 2000::/3', 'http://[4000::1]:7777/', 'POST attempted'],
      ['reserved IPv6 fec0::/10 (site-local, deprecated)', 'http://[fec0::1]:7777/', 'POST attempted'],
      ['reserved IPv6 100::/64 (discard-only)', 'http://[100::1]:7777/', 'POST attempted'],
      ['documentation 192.0.2.0/24 (TEST-NET-1)', 'http://192.0.2.1:7777/', 'POST attempted'],
      ['documentation 198.51.100.0/24 (TEST-NET-2)', 'http://198.51.100.1:7777/', 'POST attempted'],
      ['documentation 203.0.113.0/24 (TEST-NET-3)', 'http://203.0.113.1:7777/', 'POST attempted'],
      ['documentation 2001:db8::/32', 'http://[2001:db8::1]:7777/', 'POST attempted'],
      ['documentation 3fff::/20', 'http://[3fff::1]:7777/', 'POST attempted'],
      ['benchmarking 198.18.0.0/15, first', 'http://198.18.0.1:7777/', 'POST attempted'],
      ['benchmarking 198.18.0.0/15, last', 'http://198.19.255.254:7777/', 'POST attempted'],
      ['IETF protocol assignments 192.0.0.0/24', 'http://192.0.0.1:7777/', 'POST attempted'],
      ['IETF protocol assignments 2001::/23 (TEREDO)', 'http://[2001::1]:7777/', 'POST attempted'],
      ['special 2002::/16 (6to4)', 'http://[2002::1]:7777/', 'POST attempted'],
    ]
    // Post-hoc, beside the line (not in E1's row): NAT64 (64:ff9b::/96, RFC 6052) addresses that carry a loopback or
    // an RFC 1918 IPv4 address. The core reads them as the IPv4 they carry (packages/core/src/net.ts line 158); the
    // edge's classify6 read only ::ffff:0:0/96 and ::/96 that way (net.ts line 70). Measured, not predicted: both were
    // POSTed to. Flipped to the fix: the edge now reads 64:ff9b::/96 as the IPv4 it carries, so both rows are
    // refused.
    const nat64: [string, string, Verdict][] = [
      ['NAT64 64:ff9b::/96 carrying 127.0.0.1', 'http://[64:ff9b::7f00:1]:7777/', 'refused resolve-failed'],
      ['NAT64 64:ff9b::/96 carrying 10.0.0.1', 'http://[64:ff9b::a00:1]:7777/', 'refused resolve-failed'],
    ]
    // V1: the positive control (a public literal is POSTed to) and the negative control (an RFC 1918 literal, one of
    // the six classes, is refused): the guard is on in this harness, and the harness can see both outcomes.
    const controls: [string, string, Verdict][] = [
      ['control: public 1.1.1.1', 'http://1.1.1.1:7777/', 'POST attempted'],
      ['control: public 2606:4700:4700::1111', 'http://[2606:4700:4700::1111]:7777/', 'POST attempted'],
      [
        'control: private 10.0.0.1 (one of the six classes)',
        'http://10.0.0.1:7777/',
        'refused resolve-failed',
      ],
    ]
    const table: string[] = []
    const measured: [string, Verdict][] = []
    for (const [range, url, predicted] of [...controls, ...rows, ...nat64]) {
      const { verdict } = await verdictFor(url, { lookup: names.lookup })
      const core = url.includes('tailnet-peer.test')
        ? `${judgeAddresses(['100.101.102.103']).verdicts[0]?.category} (lookup answer 100.101.102.103)`
        : coreOf(url)
      measured.push([range, verdict])
      table.push(`  ${range} | ${url} | core: ${core} | edge: ${verdict} | predicted: ${predicted}`)
      expect(verdict, `${range} (${url})`).toBe(predicted)
    }
    console.log(`MEASURE E1: the edge guard per range (no socket, injected lookup)\n${table.join('\n')}`)
    // The core refuses every one of the E1 rows and both NAT64 rows: the gap is exactly the six-against-twelve design.
    for (const [, url] of [...rows, ...nat64]) {
      if (!url.includes('tailnet-peer.test')) expect(coreOf(url), url).not.toBe('public')
    }
    expect(judgeAddresses(['100.101.102.103']).allPublic).toBe(false)
    expect(measured.filter(([, v]) => v === 'POST attempted')).toHaveLength(rows.length + 2)
    // The name was looked up once through the injected lookup; no literal was looked up; nothing opened a socket.
    expect(names.asked).toEqual(['tailnet-peer.test'])
    expect(sockets.attempts()).toBe(0)
  })
})

describe('refused before any request; own relays and allowPrivateRelays allowed', () => {
  it('refuses userinfo, the six classes as literals and names, and the loopback names, with 0 POSTs', async () => {
    const sockets = noSockets()
    const names = lookupOf({
      'inside.test': ['10.0.0.5', 'fd00::5'],
      'meta.test': ['169.254.169.254'],
      'mixed.test': ['10.0.0.5', '1.1.1.1'],
    })
    // [case, url, the refusal's range as the guard names it in the audit line]
    const refused: [string, string, string][] = [
      // The password made distinctive, so a search for it cannot match another word.
      ['userinfo with a password', 'https://u:hunter2xyz@1.1.1.1/', 'userinfo'],
      ['userinfo, a user name alone', 'https://user@1.1.1.1/', 'userinfo'],
      ['loopback 127.0.0.2', 'http://127.0.0.2:7777/', 'loopback'],
      ['loopback ::1', 'http://[::1]:7777/', 'loopback'],
      [
        'loopback 2130706433 (decimal, the URL parser reads 127.0.0.1)',
        'http://2130706433:7777/',
        'loopback',
      ],
      ['loopback 0x7f.1 (hex shorthand)', 'http://0x7f.1:7777/', 'loopback'],
      ['loopback ::ffff:127.0.0.1 (IPv4-mapped)', 'http://[::ffff:127.0.0.1]:7777/', 'loopback'],
      ['loopback name localhost', 'http://localhost:7777/', 'loopback'],
      ['loopback name relay.localhost. (final dot)', 'http://relay.localhost./', 'loopback'],
      ['link-local 169.254.169.254 (cloud metadata)', 'http://169.254.169.254/', 'link-local'],
      ['link-local fe80::1', 'http://[fe80::1]:7777/', 'link-local'],
      ['RFC 1918 10.0.0.1', 'http://10.0.0.1:7777/', 'private'],
      ['RFC 1918 172.16.0.1', 'http://172.16.0.1:7777/', 'private'],
      ['RFC 1918 192.168.1.1', 'http://192.168.1.1:7777/', 'private'],
      ['ULA fd00::1', 'http://[fd00::1]:7777/', 'ula'],
      ['multicast 224.0.0.1', 'http://224.0.0.1:7777/', 'multicast'],
      ['multicast ff02::1', 'http://[ff02::1]:7777/', 'multicast'],
      ['unspecified 0.0.0.0', 'http://0.0.0.0:7777/', 'unspecified'],
      ['unspecified ::', 'http://[::]:7777/', 'unspecified'],
      ['a name resolving only to 10.0.0.5 and fd00::5', 'http://inside.test:7777/', 'private'],
      ['a name resolving only to 169.254.169.254', 'http://meta.test/', 'link-local'],
    ]
    const lines: string[] = []
    let credentialLines = 0
    let userWordLines = 0
    let passwordHits = 0
    for (const [what, url, range] of refused) {
      const { edge, relay, store, audit } = carol([url], { lookup: names.lookup })
      try {
        const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { probe: what } })
        expect(
          sent.targets.map((t) => [t.relay, t.state, t.reason, t.tries]),
          what,
        ).toEqual([[url, 'failed', 'resolve-failed', 1]])
        expect(relay.published, what).toEqual([])
        // The audit line names the range as its detail's `refused` (sender.ts line 191).
        const publishes = audit.lines.filter((l) => l.includes('"event":"publish"'))
        expect(publishes, what).toHaveLength(1)
        const line = JSON.parse(publishes[0] as string) as { reason: string; detail: string }
        // Post-hoc observation, not part of E2's row: the detail's `relay` was the target URL as the record wrote it,
        // so the user name and password of a userinfo URL reached the audit line verbatim, though the guard's own
        // refusal text leaves them out (net.ts line 152). The URL came from a public record. Flipped to the fix:
        // the audit line records scheme and host only; the outbox row keeps the full URL, because (id, relay) is the
        // target's key.
        if (range === 'userinfo') {
          const recorded = JSON.parse(line.detail).relay as string
          expect(recorded, `${what} (fixed)`).toBe('https://1.1.1.1')
          const u = URL.parse(recorded)
          credentialLines += recorded.includes('@') || u?.username || u?.password ? 1 : 0
          // The pre-fix count, a whole-line search for 'user': it still matches the range name "refused":"userinfo".
          userWordLines += (publishes[0] as string).includes('user') ? 1 : 0
          passwordHits += audit.lines.filter((l) => l.includes('hunter2xyz')).length
          expect(
            store.outboxTargets(sent.id).map((t) => t.relay),
            `${what} (fixed)`,
          ).toEqual([url])
        }
        expect(line.reason, what).toBe('resolve-failed')
        expect(JSON.parse(line.detail).refused, what).toBe(range)
        lines.push(`  ${what}: refused ${range}, 0 POST`)
      } finally {
        store.close()
      }
    }
    // Allowed: the positive control (public), the edge's own relay on loopback, and any URL with allowPrivateRelays.
    expect((await verdictFor('https://1.1.1.1/', { lookup: names.lookup })).verdict).toBe('POST attempted')
    expect(
      (await verdictFor('http://127.0.0.1:7777/', { lookup: names.lookup, own: ['http://127.0.0.1:7777'] }))
        .verdict,
    ).toBe('POST attempted')
    expect((await verdictFor('http://10.0.0.1:7777/', { allowPrivate: true })).verdict).toBe('POST attempted')
    // Post-hoc, beside the line: a name with one non-public and one public answer was allowed (net.ts line 172: refused
    // only when every answer was non-public), where the core's judgeAddresses refuses when any answer is not public.
    // Measured, not predicted. Flipped to the fix: the edge now refuses the name on any non-public answer,
    // with 0 POSTs.
    const mixed = await verdictFor('http://mixed.test:7777/', { lookup: names.lookup })
    expect(judgeAddresses(['10.0.0.5', '1.1.1.1']).allPublic).toBe(false)
    console.log(
      `MEASURE E2: ${refused.length} of ${refused.length} refused resolve-failed with 0 POST\n${lines.join('\n')}\n` +
        '  allowed: public 1.1.1.1, own relay 127.0.0.1:7777, 10.0.0.1 with allowPrivateRelays\n' +
        `  post-hoc (fixed): ${credentialLines} of 2 userinfo refusals carry a user name or password in the audit line's detail.relay; ${passwordHits} audit lines hold the password; ${userWordLines} of 2 lines contain 'user' (the range name userinfo); the outbox rows keep the full URL\n` +
        `  post-hoc: a name answering 10.0.0.5 and 1.1.1.1 -> edge ${mixed.verdict}; core judgeAddresses allPublic false`,
    )
    expect(mixed.verdict).toBe('refused resolve-failed')
    // Fixed: no credentials reach the audit line.
    expect(credentialLines).toBe(0)
    expect(passwordHits).toBe(0)
    expect(userWordLines).toBe(2)
    expect(sockets.attempts()).toBe(0)
  })

  it('refuses a private hint relay at the record lookup, and a private URL at fetch and at publishRecord, with no call', async () => {
    const sockets = noSockets()
    const { edge, relay, records, store } = carol(['https://1.1.1.1/'], { lookup: lookupOf({}).lookup })
    try {
      // V1: the lawful send through the hint-free path reaches the public relay.
      const ok = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 1 } })
      expect(ok.targets.map((t) => t.state)).toEqual(['published'])
      // A hint relay on the cloud metadata address: skipped as a failed relay before any record call (resolver.ts
      // line 102), so the record still comes from HOME.
      const hinted = await edge.send({
        to: [P.bob.address],
        type: 'chat.v1',
        body: { n: 2 },
        relays: ['http://169.254.169.254/'],
      })
      expect(hinted.targets.map((t) => t.state)).toEqual(['published'])
      expect(records.asked).not.toContain('http://169.254.169.254/')
      await expect(edge.fetch('http://10.0.0.1:7777', ok.id)).rejects.toMatchObject({
        code: 'resolve-failed',
      })
      await expect(
        edge.publishRecord(addressRecord(P.carol), ['http://[fd00::1]:7777/']),
      ).rejects.toMatchObject({ code: 'resolve-failed' })
      expect(relay.published.map((p) => p.url)).toEqual(['https://1.1.1.1/', 'https://1.1.1.1/'])
      console.log(
        `MEASURE E2 (paths): hint 169.254.169.254 asked ${records.asked.filter((u) => u.includes('169.254')).length} times; fetch 10.0.0.1 and publishRecord fd00::1 resolve-failed with 0 calls`,
      )
      expect(sockets.attempts()).toBe(0)
    } finally {
      store.close()
    }
  })
})
