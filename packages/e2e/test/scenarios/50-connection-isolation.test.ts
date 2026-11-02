import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, renameSync } from 'node:fs'
import { connect, createServer as createTcpServer, type Server, type Socket } from 'node:net'
import { homedir, tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { createServer as createTlsServer, type TLSSocket } from 'node:tls'
import { serializeRecord } from '@usebag/core'
import { createRelayClient, type RelayClient } from '@usebag/edge'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { addressRecord, type Party, party, sleep, until, type World, world } from '../harness.ts'

// e2e scenario 50: the connection-isolation measurement for several identities in one process.
// Two identities, A and B, each with its own relay client made by createRelayClient in
// this one Node process, talk to one release relay through a counting proxy that this file runs: plain TCP for the
// http:// questions, and a local TLS terminator (a throwaway self-signed certificate made with the openssl command) for
// the https:// and wss:// ones. The proxy records, per TCP connection, every byte the client sent and, behind TLS,
// whether the handshake resumed an earlier session. A connection is A's or B's by the address its requests name (a
// record fetch's path, a record publish's body); a WebSocket upgrade is told apart by its request line.
//
//   50a  global fetch, keep-alive: does one TCP connection carry requests of both identities? (calls spaced 100 ms;
//        back to back is recorded as 50a-burst and not pinned, since which connection the pool hands out is timing)
//   50b  a fetch that sends `connection: close`: does every request get its own connection?
//   50c  a WebSocket upgrade after HTTP calls: does it ride a connection an HTTP call used, of either identity?
//   50d  TLS, global fetch: shared connections and resumed handshakes
//   50e  TLS, `connection: close`: does B's first handshake resume a session A's connections made?
//   50f  wss:// after A's HTTP calls: does B's WebSocket handshake resume A's session?
//   50g  the claim: each identity's subscription is its own WebSocket on its own TCP connection, per relay
//
// 50a to 50f are informational (ruling of 2026-10-30: connection and TLS sharing at a shared
// relay is a documented residual, not a fix): each prints one `FACT 50x {...}` line and asserts only that the harness
// saw what it sent, never the pooling or the resumption, which are Node's to change. Only 50g asserts, since it is the
// one thing claimed. Measured on Node 24.4.1 on 2026-10-30: 50a one connection for both,
// 50b one per request, 50c the upgrade on the pooled connection both had used, 50d one connection, 50e and 50f B
// resumed A's session.
// Predictions, written before the first run: 50a shared,
// 50b one connection per request and none shared, 50c a fresh connection, 50d shared, 50e resumed, 50f resumed.

/**
 * The throwaway certificate of the TLS terminator, made with the openssl command in its own temporary directory, which
 * is moved to ~/.Trash/ when the file ends (never deleted). Without openssl, or when it fails, the TLS sub-scenarios
 * are skipped and say why: a missing tool is not a red.
 */
function certificate(): { key: Buffer; cert: Buffer; dir: string } | string {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-e2e-50-tls-'))
  const [key, cert] = [join(dir, 'tls.key'), join(dir, 'tls.crt')]
  const args = [
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-days',
    '1',
  ]
  try {
    execFileSync('openssl', [...args, '-subj', '/CN=127.0.0.1', '-keyout', key, '-out', cert], {
      stdio: 'ignore',
    })
    return { key: readFileSync(key), cert: readFileSync(cert), dir }
  } catch (e) {
    toTrash(dir)
    return `no certificate from the openssl command (${e instanceof Error ? e.message.split('\n')[0] : String(e)})`
  }
}

/** Moves `dir` into ~/.Trash/; left in place, and said so, when the move fails. */
function toTrash(dir: string): void {
  const trash = join(homedir(), '.Trash')
  try {
    mkdirSync(trash, { recursive: true })
    renameSync(dir, join(trash, `${basename(dir)}-${Date.now()}`))
  } catch (e) {
    console.log(`scenario 50: ${dir} left in place, not moved to ${trash}: ${String(e)}`)
  }
}

const made = certificate()
const tls = typeof made === 'string' ? null : made
const skipTls = typeof made === 'string' ? made : ''

/** One TCP connection the proxy accepted: what the client sent, and behind TLS whether its handshake resumed. */
interface Conn {
  readonly id: number
  sent: string
  resumed: boolean | null
}

interface Proxy {
  readonly url: string
  readonly conns: Conn[]
  close(): Promise<void>
}

/** A proxy in front of `target` (http://host:port) on 127.0.0.1, plain TCP or TLS with `tls`. */
async function proxy(target: string, tls?: { key: Buffer; cert: Buffer }): Promise<Proxy> {
  const { hostname, port } = new URL(target)
  const conns: Conn[] = []
  const sockets = new Set<Socket>()
  const pipe = (client: Socket, conn: Conn): void => {
    const upstream = connect(Number(port), hostname)
    for (const s of [client, upstream]) {
      sockets.add(s)
      s.on('error', () => {})
      s.on('close', () => sockets.delete(s))
    }
    client.on('data', (d: Buffer) => {
      conn.sent += d.toString('latin1')
      upstream.write(d)
    })
    upstream.pipe(client)
    client.on('end', () => upstream.end())
    upstream.on('close', () => client.destroy())
    client.on('close', () => upstream.destroy())
  }
  const server: Server = tls
    ? createTlsServer({ key: tls.key, cert: tls.cert }, (s: TLSSocket) => {
        const conn: Conn = { id: conns.length, sent: '', resumed: s.isSessionReused() }
        conns.push(conn)
        pipe(s, conn)
      })
    : createTcpServer((s) => {
        const conn: Conn = { id: conns.length, sent: '', resumed: null }
        conns.push(conn)
        pipe(s, conn)
      })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('the proxy has no port')
  return {
    url: `${tls ? 'https' : 'http'}://127.0.0.1:${address.port}`,
    conns,
    close: () =>
      new Promise((r) => {
        for (const s of sockets) s.destroy()
        server.close(() => r())
      }),
  }
}

/** Whose requests a connection carried: A, B, both or none, and whether it carried a WebSocket upgrade. */
function owner(
  c: Conn,
  a: Party,
  b: Party,
): { readonly who: string; readonly upgrade: boolean; readonly http: number } {
  const hasA = c.sent.includes(a.address)
  const hasB = c.sent.includes(b.address)
  const http = (c.sent.match(/^(GET|POST) \/v0\/(fetch|publish)/gm) ?? []).length
  const upgrade = /^upgrade: websocket\r$/im.test(c.sent)
  return { who: hasA && hasB ? 'both' : hasA ? 'A' : hasB ? 'B' : 'none', upgrade, http }
}

/** The global fetch with `connection: close` on every request. */
const closing: typeof fetch = (input, init) => {
  const headers = new Headers(init?.headers)
  headers.set('connection', 'close')
  return fetch(input, { ...init, headers })
}

/**
 * A record fetch of each identity's own address record, `rounds` times, A before B, each awaited, then `gapMs` of
 * quiet. Back to back (no gap) the next call can start before the pool has taken the last connection back, so the
 * pool opens another: that split is timing, not isolation. Real calls are seconds apart, which a gap stands for.
 */
async function interleave(
  url: string,
  a: [RelayClient, Party],
  b: [RelayClient, Party],
  rounds = 3,
  gapMs = 100,
): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    for (const [client, p] of [a, b]) {
      expect(await client.fetchRecord(url, p.address, 'address')).not.toBeNull()
      if (gapMs > 0) await sleep(gapMs)
    }
  }
}

function fact(name: string, value: unknown): void {
  console.log(`FACT ${name} ${JSON.stringify(value)}`)
}

/** Lets the proxy see the last bytes and the client close what it closes. */
const settle = (): Promise<void> => sleep(200)

describe('50 connection isolation between two identities in one process (measurement)', () => {
  const a = party('a')
  const b = party('b')
  const unsafe = process.env.NODE_TLS_REJECT_UNAUTHORIZED

  /** The relays that hold both records. Under AC_RELAY_URL every world is one relay, and a second publish is 409. */
  const holding = new Set<string>()

  /** This sub-scenario's world, a relay that holds each identity's address record, so that each record fetch is a 200. */
  async function relay(): Promise<World> {
    const w = await world('50-isolation')
    if (holding.has(w.url)) return w
    holding.add(w.url)
    const direct = createRelayClient({})
    for (const p of [a, b]) {
      const r = await direct.publish(w.url, serializeRecord(addressRecord(p, { relays: [w.url] })))
      expect(r.record).toBeDefined()
    }
    return w
  }

  afterAll(() => {
    if (tls !== null) toTrash(tls.dir)
    if (unsafe === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = unsafe
  })

  it('50a global fetch, keep-alive: one connection carries both identities', async () => {
    const w = await relay()
    for (const gapMs of [0, 100]) {
      const p = await proxy(w.url)
      await interleave(p.url, [createRelayClient({}), a], [createRelayClient({}), b], 3, gapMs)
      await settle()
      const seen = p.conns.map((c) => owner(c, a, b))
      const shape = {
        connections: seen.length,
        owners: seen.map((s) => s.who),
        requests: seen.map((s) => s.http),
      }
      fact(gapMs === 0 ? '50a-burst' : '50a', shape)
      expect(seen.reduce((n, s) => n + s.http, 0)).toBe(6)
      await p.close()
    }
  })

  it('50b `connection: close`: one connection per request, none shared', async () => {
    const w = await relay()
    const p = await proxy(w.url)
    await interleave(
      p.url,
      [createRelayClient({ fetch: closing }), a],
      [createRelayClient({ fetch: closing }), b],
    )
    await settle()
    const seen = p.conns.map((c) => owner(c, a, b))
    fact('50b', {
      connections: seen.length,
      owners: seen.map((s) => s.who),
      requests: seen.map((s) => s.http),
    })
    expect(seen.reduce((n, s) => n + s.http, 0)).toBe(6)
    await p.close()
  })

  it('50c where a WebSocket upgrade after HTTP calls goes', async () => {
    const w = await relay()
    const p = await proxy(w.url)
    const [ca, cb] = [createRelayClient({}), createRelayClient({})]
    await interleave(p.url, [ca, a], [cb, b], 1)
    const sub = cb.subscribe(p.url, b.address, b.signing, [], null)
    await until('the upgrade at the proxy', () => p.conns.some((c) => owner(c, a, b).upgrade))
    sub.close()
    await settle()
    const seen = p.conns.map((c) => owner(c, a, b))
    const upgrades = seen.filter((s) => s.upgrade)
    fact('50c', {
      connections: seen.length,
      owners: seen.map((s) => s.who),
      upgrades: upgrades.map((s) => s.http),
    })
    expect(upgrades).toHaveLength(1)
    await p.close()
  })

  it('50g each identity subscribes on its own WebSocket, on its own TCP connection, at one relay', async () => {
    const w = await relay()
    const p = await proxy(w.url)
    const [ca, cb] = [createRelayClient({}), createRelayClient({})]
    // Both identities' HTTP calls first, so that a pooled connection is there to be ridden.
    await interleave(p.url, [ca, a], [cb, b], 1)
    const subs = [
      ca.subscribe(p.url, a.address, a.signing, [], null),
      cb.subscribe(p.url, b.address, b.signing, [], null),
    ]
    const upgradesOn = (c: Conn): number => (c.sent.match(/^upgrade: websocket\r$/gim) ?? []).length
    await until('both upgrades at the proxy', () => p.conns.filter((c) => upgradesOn(c) > 0).length >= 2)
    for (const sub of subs) sub.close()
    await settle()
    const sockets = p.conns.filter((c) => upgradesOn(c) > 0)
    fact('50g', { connections: p.conns.length, upgradesPerConnection: sockets.map(upgradesOn) })
    expect(sockets.map(upgradesOn)).toEqual([1, 1])
    await p.close()
  })

  // The clients cannot be told about a test certificate without a product option, so this process stops checking
  // certificates for the TLS sub-scenarios only (restored in afterAll).
  describe.skipIf(tls === null)(`behind TLS${skipTls ? `: skipped, ${skipTls}` : ''}`, () => {
    beforeAll(() => {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    })

    it('50d global fetch: shared connections, and which handshakes resumed', async () => {
      const w = await relay()
      const p = await proxy(w.url, tls ?? undefined)
      await interleave(p.url, [createRelayClient({}), a], [createRelayClient({}), b])
      await settle()
      const seen = p.conns.map((c) => ({ ...owner(c, a, b), resumed: c.resumed }))
      fact('50d', seen)
      expect(seen.reduce((n, s) => n + s.http, 0)).toBe(6)
      await p.close()
    })

    it('50e `connection: close`: whether B resumes a session from A', async () => {
      const w = await relay()
      const p = await proxy(w.url, tls ?? undefined)
      await interleave(
        p.url,
        [createRelayClient({ fetch: closing }), a],
        [createRelayClient({ fetch: closing }), b],
      )
      await settle()
      const seen = p.conns.map((c) => ({ ...owner(c, a, b), resumed: c.resumed }))
      fact('50e', seen)
      // B's first connection comes after A's first only, so a resumed handshake there can only hold A's session.
      expect(seen.slice(0, 2).map((s) => s.who)).toEqual(['A', 'B'])
      fact('50e-cross', { bFirstResumedFromA: seen[1]?.resumed })
      await p.close()
    })

    it("50f wss:// after A's HTTP calls: whether B's WebSocket handshake resumes A's session", async () => {
      const w = await relay()
      const p = await proxy(w.url, tls ?? undefined)
      const [ca, cb] = [createRelayClient({ fetch: closing }), createRelayClient({})]
      for (let i = 0; i < 2; i++) expect(await ca.fetchRecord(p.url, a.address, 'address')).not.toBeNull()
      await settle()
      const sub = cb.subscribe(p.url, b.address, b.signing, [], null)
      await until('the upgrade at the proxy', () => p.conns.some((c) => owner(c, a, b).upgrade))
      sub.close()
      await settle()
      const seen = p.conns.map((c) => ({ ...owner(c, a, b), resumed: c.resumed }))
      fact('50f', seen)
      expect(seen.filter((s) => s.upgrade)).toHaveLength(1)
      fact('50f-cross', { bWebSocketResumedFromA: seen.find((s) => s.upgrade)?.resumed })
      await p.close()
    })
  })
})
