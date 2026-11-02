import { countersignRotation, judgeAddresses, type NetCategory, serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  type Party,
  party,
  type RelayHandle,
  untilSecond,
  wellKnownFirst,
} from '../harness.ts'
import {
  countingListener,
  envelope,
  events,
  httpStub,
  ownAddress,
  post,
  publishRecords,
  spawnRelay,
} from './support.ts'

// W1 to W6: the relay's resolution of `domain:` roots (crates/ac-relay/src/resolver.rs)
// attacked through the release binary on 127.0.0.1. W1 runs WITHOUT --well-known-insecure-http (that flag turns the
// guard off, resolver.rs:163), so the guard (resolver.rs:180-185, ac_core::net::first_non_public) is what refuses;
// every W1 target stays on this Mac. W2 to W6 need a well-known host on loopback, which only
// --well-known-insecure-http lets the relay reach, so they pass it, and each test says so in its name.

const WELL_KNOWN = '/.well-known/bag/address.json'

/** An org's address record: no sealing key, valid `ttl` seconds (an hour by default). */
const org = (p: Party, url: string, o: { ttl?: number; rotatedFrom?: string | null } = {}) =>
  addressRecord(p, { relays: [url], sealing: false, ttl: o.ttl ?? 3600, rotatedFrom: o.rotatedFrom ?? null })

/** An envelope from `sender` to `to` under a one-hop chain from `root` (so its root is `root`). */
const under = (root: Party, sender: Party, to: readonly Party[]) =>
  envelope(sender, to, { auth: [signHop(root.signing, sender.address, [], now() + 3600)] })

/** A mailbox at the relay whose accept-from names `roots`. */
async function mailbox(relay: RelayHandle, name: string, roots: readonly string[]): Promise<Party> {
  const p = party(name)
  expect(
    await publishRecords(relay.url, [addressRecord(p, { relays: [relay.url] }), acceptFrom(p, roots)]),
  ).toEqual([200, 200])
  return p
}

/** The relay's well-known-refused log lines for `domain`. */
const refusals = (relay: RelayHandle, domain: string) =>
  events(relay).filter((e) => e.event === 'well-known-refused' && e.domain === domain)

/** The relay's well-known log lines (pinned, refreshed, rotated) for `domain`. */
const wellKnown = (relay: RelayHandle, domain: string) =>
  events(relay).filter((e) => e.event === 'well-known' && e.domain === domain)

// --- W1: the guard, seven non-public categories ------------------------------------------------------------------

interface W1Case {
  readonly category: NetCategory
  readonly range: string
  /** The target over a socket, and whether a counting listener can stand on it; null for the classifier path. */
  readonly socket: { readonly ip: string; readonly listen: string | null; readonly where: string } | null
  /** The address the core classifier judges in process when there is no socket target. */
  readonly inProcess: string
}

// Read at module load, so the test names say which path each category took (V3; G3: no category skips).
const shared = ownAddress('shared', 'IPv4')
const linkLocal = ownAddress('link-local', 'IPv4')
const private1918 = ownAddress('private', 'IPv4')
const ula = ownAddress('ula', 'IPv6')

const W1: readonly W1Case[] = [
  {
    category: 'shared',
    range: '100.64.0.0/10',
    socket: shared && {
      ip: shared.address,
      listen: shared.address,
      where: `this Mac's own address on ${shared.iface}`,
    },
    inProcess: '100.64.0.1',
  },
  {
    category: 'loopback',
    range: '127.0.0.0/8',
    // macOS holds only 127.0.0.1 on lo0, so nothing can listen on 127.0.0.2 (bind: EADDRNOTAVAIL); the route is lo0.
    socket: { ip: '127.0.0.2', listen: null, where: '127.0.0.2 (route lo0, no listener possible)' },
    inProcess: '127.0.0.2',
  },
  {
    category: 'link-local',
    range: '169.254.0.0/16',
    socket: linkLocal && {
      ip: linkLocal.address,
      listen: linkLocal.address,
      where: `this Mac's own address on ${linkLocal.iface}`,
    },
    inProcess: '169.254.0.1',
  },
  {
    category: 'multicast',
    range: '224.0.0.0/4',
    // TCP to a multicast group is refused by the kernel before any packet: nothing can listen there.
    socket: { ip: '224.0.0.1', listen: null, where: '224.0.0.1 (no listener possible)' },
    inProcess: '224.0.0.1',
  },
  {
    category: 'unspecified',
    range: '0.0.0.0/8',
    // A connect to 0.0.0.0 reaches a listener on 127.0.0.1 on macOS (checked before this file was written).
    socket: {
      ip: '0.0.0.0',
      listen: '127.0.0.1',
      where: '0.0.0.0 (a listener on 127.0.0.1 counts a connect)',
    },
    inProcess: '0.0.0.0',
  },
  {
    category: 'ula',
    range: 'fc00::/7',
    // fd00::1 routes to this Mac's default IPv6 gateway on en0 (route -n get -inet6 fd00::1), so a red case would leave
    // the Mac: the target is a ULA this Mac holds, else the classifier.
    socket: ula && { ip: ula.address, listen: ula.address, where: `this Mac's own address on ${ula.iface}` },
    inProcess: 'fd00::1',
  },
  {
    category: 'private',
    range: 'RFC 1918',
    socket: private1918 && {
      ip: private1918.address,
      listen: private1918.address,
      where: `this Mac's own address on ${private1918.iface}`,
    },
    inProcess: '10.0.0.1',
  },
]

const hostPort = (ip: string, port: number) => (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`)

describe('W1: the well-known guard refuses every non-public category before connecting (no --well-known-insecure-http)', () => {
  for (const c of W1) {
    const path = c.socket === null ? `classifier on ${c.inProcess}` : `socket to ${c.socket.where}`
    const outcome =
      c.socket === null
        ? `no address of this category on this Mac, so no socket: judgeAddresses refuses it as ${c.category}`
        : '503 resolve-failed, Retry-After 60, 0 connections'
    it(`W1 ${c.category} (${c.range}) [path: ${path}]: ${outcome}`, async () => {
      if (c.socket === null) {
        // No address of this category on any interface of this Mac: the core classifier's verdict, in process.
        const verdict = judgeAddresses([c.inProcess])
        expect(verdict, `classifier path for ${c.category}`).toEqual({
          allPublic: false,
          verdicts: [{ address: c.inProcess, category: c.category }],
        })
        // V1: the classifier passes a public address (so a refusal above is not a classifier that refuses all).
        expect(judgeAddresses(['1.1.1.1']).allPublic).toBe(true)
        return
      }
      const listener = c.socket.listen === null ? null : await countingListener(c.socket.listen)
      const port = listener?.port ?? 443
      const host = `w1-${c.category}.e2e.test`
      const relay = await spawnRelay(`w1-${c.category}`, [
        '--bind',
        '127.0.0.1',
        '--well-known-timeout',
        '1',
        '--well-known-resolve',
        `${host}=${hostPort(c.socket.ip, port)}`,
      ])
      expect(relay.stderr()).not.toContain('well-known-insecure-http')
      const root = party('w1-root')
      const alice = party('alice')
      const bob = await mailbox(relay, 'bob', [`domain:${host}`])
      const carol = await mailbox(relay, 'carol', [root.address])
      // V1: the same chain to a mailbox that names the root's address is delivered.
      expect(await post(relay.url, under(root, alice, [carol]).bytes)).toMatchObject({
        status: 200,
        body: { ok: true, duplicate: false, delivered: 1 },
      })
      const answer = await post(relay.url, under(root, alice, [bob]).bytes)
      expect(answer).toEqual({ status: 503, body: { error: 'resolve-failed' }, retryAfter: '60' })
      if (listener !== null) {
        expect(listener.count(), `connections to ${c.socket.where}: ${listener.peers.join(' ')}`).toBe(0)
      }
      // Corroboration, not the decision (row W1): the refusal came from the guard, before any connection.
      expect(refusals(relay, host)).toMatchObject([{ reason: 'non-public-address', category: c.category }])
    })
  }

  it('W1 loopback supplement [path: socket to 127.0.0.1 with a counting listener]: 503 resolve-failed, 0 connections', async () => {
    const listener = await countingListener('127.0.0.1')
    const host = 'w1-loopback-counted.e2e.test'
    const relay = await spawnRelay('w1-loop', [
      '--well-known-timeout',
      '1',
      '--well-known-resolve',
      `${host}=127.0.0.1:${listener.port}`,
    ])
    const root = party('w1-root')
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', [`domain:${host}`])
    expect(await post(relay.url, under(root, alice, [bob]).bytes)).toEqual({
      status: 503,
      body: { error: 'resolve-failed' },
      retryAfter: '60',
    })
    expect(listener.count()).toBe(0)
    expect(refusals(relay, host)).toMatchObject([{ reason: 'non-public-address', category: 'loopback' }])
  })
})

// --- W2 to W6: the loopback well-known stub, behind --well-known-insecure-http ------------------------------------

/** Record bytes padded with spaces after the opening brace to exactly `size` bytes (still one valid record). */
function padded(record: Uint8Array, size: number): Uint8Array {
  const out = new Uint8Array(size).fill(0x20)
  out[0] = record[0] as number
  out.set(record.subarray(1), size - record.length + 1)
  return out
}

describe('W2 to W6: the resolver behind the loopback stub (--well-known-insecure-http, needed to reach 127.0.0.1)', () => {
  // The relay has the edge's cap, 262,144 bytes, so both boundaries moved with it, and the 65,537-byte
  // body, too large before, is a control that now resolves.
  it('W2 [--well-known-insecure-http] a well-known body of 262,144 bytes is read and pins its key (delivered); one of 262,145 is too-large: 503 resolve-failed, nothing pinned; one of 65,537 resolves', async () => {
    const exact = await wellKnownFirst()
    const big = await wellKnownFirst()
    const control = await wellKnownFirst()
    const relay = await spawnRelay('w2', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '2',
      '--well-known-resolve',
      `exact.e2e.test=${exact.domain}`,
      '--well-known-resolve',
      `big.e2e.test=${big.domain}`,
      '--well-known-resolve',
      `control.e2e.test=${control.domain}`,
    ])
    const kExact = party('k-exact')
    const kBig = party('k-big')
    const kControl = party('k-control')
    const alice = party('alice')
    const bobExact = await mailbox(relay, 'bob-exact', ['domain:exact.e2e.test'])
    const bobBig = await mailbox(relay, 'bob-big', ['domain:big.e2e.test'])
    const bobControl = await mailbox(relay, 'bob-control', ['domain:control.e2e.test'])
    const exactBytes = padded(serializeRecord(org(kExact, relay.url)), 262_144)
    const bigBytes = padded(serializeRecord(org(kBig, relay.url)), 262_145)
    const controlBytes = padded(serializeRecord(org(kControl, relay.url)), 65_537)
    expect([exactBytes.length, bigBytes.length, controlBytes.length]).toEqual([262_144, 262_145, 65_537])
    exact.serve(() => exactBytes)
    big.serve(() => bigBytes)
    control.serve(() => controlBytes)
    expect(await post(relay.url, under(kControl, alice, [bobControl]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(wellKnown(relay, 'control.e2e.test')).toMatchObject([{ outcome: 'pinned', key: kControl.address }])
    // V1: exactly the cap is read, and the record earns its pin.
    expect(await post(relay.url, under(kExact, alice, [bobExact]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(wellKnown(relay, 'exact.e2e.test')).toMatchObject([{ outcome: 'pinned', key: kExact.address }])
    expect(await post(relay.url, under(kBig, alice, [bobBig]).bytes)).toEqual({
      status: 503,
      body: { error: 'resolve-failed' },
      retryAfter: '60',
    })
    expect(big.requests(), 'the 262,145-byte host was asked once').toBe(1)
    expect(wellKnown(relay, 'big.e2e.test'), 'nothing pinned for the 262,145-byte record').toEqual([])
    expect(refusals(relay, 'big.e2e.test')).toMatchObject([{ reason: 'too-large' }])
    // Remembered: a second publish inside the minute is 503 again with no new request.
    expect((await post(relay.url, under(kBig, alice, [bobBig]).bytes)).status).toBe(503)
    expect(big.requests()).toBe(1)
  })

  it('W3 [--well-known-insecure-http] a 301 to an internal URL is not followed (Status(301), 0 internal requests) and a 500 is Status(500), each 503 resolve-failed; [no insecure flag] a plain-http host is refused, 0 requests', async () => {
    const kInternal = party('k-internal')
    const kOk = party('k-ok')
    let relayUrl = ''
    // The internal URL a redirect points at: it would serve a valid record, so a followed redirect would deliver.
    const internal = await httpStub((_req, res) => {
      res
        .writeHead(200, { 'content-type': 'application/json' })
        .end(serializeRecord(org(kInternal, relayUrl)))
    })
    const redirect = await httpStub((_req, res) => {
      res.writeHead(301, { location: `http://${internal.origin}${WELL_KNOWN}` }).end()
    })
    const failing = await httpStub((_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' }).end('{"error":"internal"}')
    })
    const fine = await httpStub((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }).end(serializeRecord(org(kOk, relayUrl)))
    })
    const relay = await spawnRelay('w3', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '2',
      '--well-known-resolve',
      `redirect.e2e.test=${redirect.origin}`,
      '--well-known-resolve',
      `failing.e2e.test=${failing.origin}`,
      '--well-known-resolve',
      `fine.e2e.test=${fine.origin}`,
    ])
    relayUrl = relay.url
    const alice = party('alice')
    const bobRedirect = await mailbox(relay, 'bob-redirect', ['domain:redirect.e2e.test'])
    const bobFailing = await mailbox(relay, 'bob-failing', ['domain:failing.e2e.test'])
    const bobFine = await mailbox(relay, 'bob-fine', ['domain:fine.e2e.test'])
    // V1: a 200 with a valid record on this relay is delivered.
    expect(await post(relay.url, under(kOk, alice, [bobFine]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    const refused = { status: 503, body: { error: 'resolve-failed' }, retryAfter: '60' }
    expect(await post(relay.url, under(kInternal, alice, [bobRedirect]).bytes)).toEqual(refused)
    expect(
      [redirect.requests(WELL_KNOWN), internal.requests()],
      'one GET, the redirect not followed',
    ).toEqual([1, 0])
    expect(refusals(relay, 'redirect.e2e.test')).toMatchObject([{ reason: 'http-status', status: 301 }])
    expect(await post(relay.url, under(kOk, alice, [bobFailing]).bytes)).toEqual(refused)
    expect(failing.requests(WELL_KNOWN)).toBe(1)
    expect(refusals(relay, 'failing.e2e.test')).toMatchObject([{ reason: 'http-status', status: 500 }])

    // Plain http:// without the flag. The relay builds https:// URLs unless --well-known-insecure-http is set
    // (resolver.rs:172), and the same flag is the only way past the guard to a loopback host (resolver.rs:163), so
    // https_only (resolver.rs:187) cannot be reached from outside: the guard refuses first. Outcome asserted; the
    // mechanism is reported (partial).
    const plain = await httpStub((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' }).end(serializeRecord(org(kOk, relayUrl)))
    })
    const strict = await spawnRelay('w3-strict', [
      '--well-known-timeout',
      '2',
      '--well-known-resolve',
      `plain.e2e.test=${plain.origin}`,
    ])
    const bobPlain = await mailbox(strict, 'bob-plain', ['domain:plain.e2e.test'])
    expect(await post(strict.url, under(kOk, alice, [bobPlain]).bytes)).toEqual(refused)
    expect(plain.requests(), 'no request to the plain-http host').toBe(0)
    expect(refusals(strict, 'plain.e2e.test')).toMatchObject([{ reason: 'non-public-address' }])
  })

  it('W4 [--well-known-insecure-http, --well-known-cache-max 1] after a pin, a bare substitution is pin-mismatch: the offered root 403 root-not-accepted, the pinned key still delivered; a rotation countersigned by the pinned key moves the pin and delivers', async () => {
    const bare = await wellKnownFirst()
    const unsignedRotation = await wellKnownFirst()
    const rotation = await wellKnownFirst()
    const relay = await spawnRelay('w4', [
      '--well-known-insecure-http',
      '--well-known-cache-max',
      '1',
      '--well-known-resolve',
      `bare.e2e.test=${bare.domain}`,
      '--well-known-resolve',
      `named.e2e.test=${unsignedRotation.domain}`,
      '--well-known-resolve',
      `rotation.e2e.test=${rotation.domain}`,
    ])
    const alice = party('alice')
    const [a1, a3, n1, n3, r1, r2] = ['a1', 'a3', 'n1', 'n3', 'r1', 'r2'].map((n) => party(n)) as [
      Party,
      Party,
      Party,
      Party,
      Party,
      Party,
    ]
    const bobBare = await mailbox(relay, 'bob-bare', ['domain:bare.e2e.test'])
    const bobNamed = await mailbox(relay, 'bob-named', ['domain:named.e2e.test'])
    const bobRotation = await mailbox(relay, 'bob-rotation', ['domain:rotation.e2e.test'])
    const delivered = { status: 200, body: { ok: true, duplicate: false, delivered: 1 } }
    // V1: first contact pins each domain's first key and delivers.
    bare.serve(() => serializeRecord(org(a1, relay.url)))
    unsignedRotation.serve(() => serializeRecord(org(n1, relay.url)))
    rotation.serve(() => serializeRecord(org(r1, relay.url)))
    expect(await post(relay.url, under(a1, alice, [bobBare]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(n1, alice, [bobNamed]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(r1, alice, [bobRotation]).bytes)).toMatchObject(delivered)
    // Past the one-second cache: each publish below reads the well-known record again.
    await untilSecond(now() + 2)
    bare.serve(() => serializeRecord(org(a3, relay.url)))
    // A record of another key that names rotated_from but carries no countersignature.
    unsignedRotation.serve(() => serializeRecord(org(n3, relay.url, { rotatedFrom: n1.address })))
    rotation.serve(() =>
      serializeRecord(countersignRotation(r1.signing, org(r2, relay.url, { rotatedFrom: r1.address }))),
    )
    const notAccepted = { status: 403, body: { error: 'root-not-accepted' }, retryAfter: null }
    expect(await post(relay.url, under(a3, alice, [bobBare]).bytes)).toEqual(notAccepted)
    expect(await post(relay.url, under(a1, alice, [bobBare]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(n3, alice, [bobNamed]).bytes)).toEqual(notAccepted)
    expect(await post(relay.url, under(n1, alice, [bobNamed]).bytes)).toMatchObject(delivered)
    expect(await post(relay.url, under(r2, alice, [bobRotation]).bytes)).toMatchObject(delivered)
    expect(refusals(relay, 'bare.e2e.test')).toMatchObject([
      { reason: 'pin-mismatch', pinned: a1.address, offered: a3.address, kept: a1.address },
    ])
    expect(refusals(relay, 'named.e2e.test')).toMatchObject([
      { reason: 'pin-mismatch', pinned: n1.address, offered: n3.address, kept: n1.address },
    ])
    expect(wellKnown(relay, 'rotation.e2e.test').map((e) => [e.outcome, e.key])).toEqual([
      ['pinned', r1.address],
      ['rotated', r2.address],
    ])
  })

  it('W5 [--well-known-insecure-http] a burst of 50 publishes against a domain whose host answers nothing: 50 x 503 resolve-failed Retry-After 60, the host contacted once', async () => {
    // "Does not resolve" is emulated by a host that accepts and drops every connection (fetch-failed): a real DNS
    // failure would send a query off this Mac. The listener counts every contact.
    const dead = await countingListener('127.0.0.1')
    const relay = await spawnRelay('w5', [
      '--well-known-insecure-http',
      '--well-known-timeout',
      '1',
      '--well-known-resolve',
      `dead.e2e.test=127.0.0.1:${dead.port}`,
    ])
    const root = party('w5-root')
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', ['domain:dead.e2e.test'])
    const carol = await mailbox(relay, 'carol', [root.address])
    expect(await post(relay.url, under(root, alice, [carol]).bytes)).toMatchObject({ status: 200 })
    const burst = Array.from({ length: 50 }, () => under(root, alice, [bob]).bytes)
    const t = performance.now()
    const answers = await Promise.all(burst.map((b) => post(relay.url, b)))
    const ms = Math.round(performance.now() - t)
    const tally = new Map<string, number>()
    for (const a of answers) {
      const k = `${a.status} ${JSON.stringify(a.body)} ${a.retryAfter}`
      tally.set(k, (tally.get(k) ?? 0) + 1)
    }
    console.log(`W5 measure: ${JSON.stringify([...tally])} in ${ms} ms, ${dead.count()} contact(s)`)
    expect([...tally], `50 answers in ${ms} ms`).toEqual([['503 {"error":"resolve-failed"} 60', 50]])
    expect(dead.count(), `contacts: ${dead.peers.join(' ')}`).toBe(1)
    expect(refusals(relay, 'dead.e2e.test')).toHaveLength(1)
  })

  it('W6 (measure) [--well-known-insecure-http, --well-known-cache-max 3] a countersigned rotation published while the old key is cached: a chain under the new key refreshes the record at once, and the old key is admitted no longer, never longer than cache_max', async () => {
    const CACHE_MAX = 3
    const site = await wellKnownFirst()
    const relay = await spawnRelay('w6', [
      '--well-known-insecure-http',
      '--well-known-cache-max',
      String(CACHE_MAX),
      '--well-known-resolve',
      `acme.e2e.test=${site.domain}`,
    ])
    const k1 = party('k1')
    const k2 = party('k2')
    const alice = party('alice')
    const bob = await mailbox(relay, 'bob', ['domain:acme.e2e.test'])
    site.serve(() => serializeRecord(org(k1, relay.url)))
    expect(await post(relay.url, under(k1, alice, [bob]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    const [pinned] = wellKnown(relay, 'acme.e2e.test')
    expect(pinned).toMatchObject({ outcome: 'pinned', key: k1.address })
    const pinnedAt = (pinned?.at as number) / 1000
    const expiresAt = pinned?.expires_at as number
    // The legitimate rotation is now what the domain serves.
    site.serve(() =>
      serializeRecord(countersignRotation(k1.signing, org(k2, relay.url, { rotatedFrom: k1.address }))),
    )
    const rotatedAt = Date.now() / 1000
    const statuses: [number, number][] = []
    let k2Early: number | null = null
    let refusedAt: number | null = null
    // k2's chain while k1 is cached refreshes the record once, so the rotation takes effect at once.
    const asked = site.requests()
    let askedAfterK2 = asked
    const end = Date.now() + 10_000
    while (refusedAt === null && Date.now() < end) {
      const a = await post(relay.url, under(k1, alice, [bob]).bytes)
      statuses.push([Math.round((Date.now() / 1000 - rotatedAt) * 1000), a.status])
      if (k2Early === null) {
        k2Early = (await post(relay.url, under(k2, alice, [bob]).bytes)).status
        askedAfterK2 = site.requests()
        expect(wellKnown(relay, 'acme.e2e.test').map((e) => [e.outcome, e.key])).toEqual([
          ['pinned', k1.address],
          ['rotated', k2.address],
        ])
      }
      if (a.status !== 200) {
        refusedAt = Date.now() / 1000
        expect(a).toEqual({ status: 403, body: { error: 'root-not-accepted' }, retryAfter: null })
      } else await new Promise((r) => setTimeout(r, 200))
    }
    const admitted = statuses.filter(([, s]) => s === 200)
    const lastAdmitted = admitted.length === 0 ? null : (admitted[admitted.length - 1]?.[0] as number) / 1000
    const report = `pinned at ${pinnedAt.toFixed(3)}, cache expires_at ${expiresAt}, rotation served at ${rotatedAt.toFixed(3)}, k1 admitted ${admitted.length} times up to ${lastAdmitted} s after the rotation, refused at ${refusedAt === null ? 'never' : (refusedAt - rotatedAt).toFixed(3)} s; k2 inside the cache: ${k2Early}`
    expect(admitted.length, report).toBeGreaterThan(0)
    expect(k2Early, report).toBe(200)
    expect(askedAfterK2, 'the refresh: one more GET at the host').toBe(asked + 1)
    expect(refusedAt, report).not.toBeNull()
    // The design bound: the stale key is admitted no longer than cache_max after the pin (+1 s: whole seconds).
    expect((refusedAt as number) - pinnedAt, report).toBeLessThanOrEqual(CACHE_MAX + 1)
    expect(expiresAt - Math.floor(pinnedAt), report).toBeLessThanOrEqual(CACHE_MAX)
    expect(await post(relay.url, under(k2, alice, [bob]).bytes)).toMatchObject({
      status: 200,
      body: { delivered: 1 },
    })
    expect(wellKnown(relay, 'acme.e2e.test').map((e) => [e.outcome, e.key])).toEqual([
      ['pinned', k1.address],
      ['rotated', k2.address],
    ])
    console.log(`W6 measure: ${report}`)
  })
})
