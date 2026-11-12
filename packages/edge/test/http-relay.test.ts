import { MAX_ENVELOPE_BYTES, signFetchAuth, signHop, utf8, verifyFetchAuth } from '@usebag/core'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import {
  BASE_TIMEOUT_MS,
  createHttpRelay,
  createRelayClient,
  MAX_RESPONSE_BYTES,
  MAX_TIMEOUT_MS,
  timeoutFor,
} from '../src/adapters/http-relay.ts'
import { RelayError } from '../src/ports.ts'
import { P, T0 } from './support/fixtures.ts'
import { closedPort, json, startHttp, type TestServer } from './support/http.ts'

let server: TestServer
beforeAll(async () => {
  server = await startHttp()
})
afterAll(() => server.close())

const relay = createHttpRelay() as Required<ReturnType<typeof createHttpRelay>>
const ID = 'ab'.repeat(32)
const BYTES = utf8('{"v":1}')

async function failure(p: Promise<unknown>): Promise<RelayError> {
  const e = await p.then(
    () => null,
    (x: unknown) => x,
  )
  expect(e).toBeInstanceOf(RelayError)
  return e as RelayError
}

describe('http-relay: the relay API of spec/SPEC.md §8 on the global fetch', () => {
  it('publishes the exact bytes as JSON and reads {ok, id, duplicate, delivered}', async () => {
    server.handle = (_req, res) => json(res, 200, { ok: true, id: ID, duplicate: true, delivered: 2 })
    expect(await relay.publish(`${server.url}/`, BYTES)).toEqual({ id: ID, duplicate: true, delivered: 2 })
    const req = server.seen.at(-1)
    expect(req).toMatchObject({ method: 'POST', url: '/v0/publish' })
    expect(req?.headers['content-type']).toBe('application/json')
    expect(new Uint8Array(req?.body as Buffer)).toEqual(BYTES)
  })

  it('refuses a 200 that is not a publish result', async () => {
    for (const body of [{ ok: true }, { ok: false, id: ID, duplicate: false, delivered: 1 }, [1], 'text']) {
      server.handle = (_req, res) => json(res, 200, body)
      const e = await failure(relay.publish(server.url, BYTES))
      expect([e.code, e.status]).toEqual(['bad-shape', 200])
    }
  })

  it("publishes a record and reads the relay's record answer, which names no id and fills no mailbox", async () => {
    const record = utf8('{"kind":"address"}')
    const answer = { kind: 'address', signer: P.bob.address, iat: T0, valid_until: T0 + 3600 }
    server.handle = (_req, res) => json(res, 200, { ok: true, ...answer })
    expect(await relay.publish(server.url, record)).toEqual({
      id: '',
      duplicate: false,
      delivered: 0,
      record: answer,
    })
    expect(new Uint8Array(server.seen.at(-1)?.body as Buffer)).toEqual(record)
  })

  it("reads an accept-from record's answer with a null valid_until", async () => {
    const answer = { kind: 'accept-from', signer: P.bob.address, iat: T0, valid_until: null }
    server.handle = (_req, res) => json(res, 200, { ok: true, ...answer })
    const r = await relay.publish(server.url, utf8('{"kind":"accept-from"}'))
    expect(r).toEqual({ id: '', duplicate: false, delivered: 0, record: answer })
  })

  it('reads the {"ok": true} of an older relay as a record result with no answer', async () => {
    const record = utf8('{"kind":"accept-from"}')
    server.handle = (_req, res) => json(res, 200, { ok: true })
    const r = await relay.publish(server.url, record)
    expect(r).toEqual({ id: '', duplicate: false, delivered: 0 })
    expect(Object.hasOwn(r, 'record')).toBe(false)
  })

  it('refuses a record answer that names a kind without its signer, iat and valid_until', async () => {
    const good = { ok: true, kind: 'key', signer: P.bob.address, iat: T0, valid_until: T0 + 1 }
    for (const bad of [
      { kind: 1 },
      { signer: null },
      { iat: '1' },
      { iat: 1.5 },
      { valid_until: '1' },
      { valid_until: undefined },
    ]) {
      server.handle = (_req, res) => json(res, 200, { ...good, ...bad })
      const e = await failure(relay.publish(server.url, utf8('{"kind":"key"}')))
      expect([e.code, e.status, e.message], JSON.stringify(bad)).toEqual([
        'bad-shape',
        200,
        'bad-shape: a record publish answered 200 without {kind, signer, iat, valid_until}',
      ])
    }
  })

  it('refuses a record publish answered 200 without {ok: true}', async () => {
    for (const body of [{ ok: false }, {}, [1]]) {
      server.handle = (_req, res) => json(res, 200, body)
      const e = await failure(relay.publish(server.url, utf8('{"kind":null}')))
      expect([e.code, e.status, e.message]).toEqual([
        'bad-shape',
        200,
        'bad-shape: publish answered 200 without {ok: true}',
      ])
    }
  })

  it("reads a refusal's code, status and Retry-After", async () => {
    server.handle = (_req, res) => json(res, 429, { error: 'rate-limited' }, { 'retry-after': '7' })
    let e = await failure(relay.publish(server.url, BYTES))
    expect([e.code, e.status, e.retryAfter]).toEqual(['rate-limited', 429, 7])
    expect(e.message).toContain('rate-limited: ')
    server.handle = (_req, res) =>
      json(res, 403, { error: 'root-not-accepted' }, { 'retry-after': 'Wed, 21 Oct 2026 07:28:00 GMT' })
    e = await failure(relay.publish(server.url, BYTES))
    expect([e.code, e.status, e.retryAfter]).toEqual(['root-not-accepted', 403, null])
    for (const body of ['{"error":"made-up"}', 'not json', '[1]', 'null', '"x"']) {
      server.handle = (_req, res) => {
        res.writeHead(500, { 'retry-after': '-1' }).end(body)
      }
      e = await failure(relay.publish(server.url, BYTES))
      expect([e.code, e.status, e.retryAfter], body).toEqual([null, 500, null])
      expect(e.message).toContain('status 500')
    }
  })

  it('fetches by id with AC-Signer, AC-Ts and AC-Sig, adding AC-Auth only for a chain', async () => {
    server.handle = (_req, res) => {
      res.writeHead(200).end(BYTES)
    }
    const sig = signFetchAuth(P.bob.signing, ID, T0, server.url)
    expect(await relay.fetch(server.url, ID, { signer: P.bob.address, ts: T0, sig, auth: [] })).toEqual(BYTES)
    let h = server.seen.at(-1)?.headers ?? {}
    expect(server.seen.at(-1)?.url).toBe(`/v0/fetch/${ID}`)
    expect([h['ac-signer'], h['ac-ts'], h['ac-auth']]).toEqual([P.bob.address, String(T0), undefined])
    expect(verifyFetchAuth(P.bob.address, ID, T0, server.url, h['ac-sig'] as string)).toBe(true)
    const hop = signHop(P.jane.signing, P.session.address, ['type=chat.*'], T0 + 60)
    const sessionSig = signFetchAuth(P.session.signing, ID, T0, server.url)
    await relay.fetch(server.url, ID, { signer: P.session.address, ts: T0, sig: sessionSig, auth: [hop] })
    h = server.seen.at(-1)?.headers ?? {}
    expect(JSON.parse(Buffer.from(h['ac-auth'] as string, 'base64url').toString('utf8'))).toEqual([hop])
    expect(h['ac-auth']).not.toMatch(/[=+/]/)
    // The proof beside a chain names its relay too: good at this URL, not at another spelling of it.
    expect(verifyFetchAuth(P.session.address, ID, T0, server.url, h['ac-sig'] as string)).toBe(true)
    expect(verifyFetchAuth(P.session.address, ID, T0, `${server.url}/`, h['ac-sig'] as string)).toBe(false)
    server.handle = (_req, res) => json(res, 401, { error: 'bad-auth' })
    const e = await failure(relay.fetch(server.url, ID, { signer: P.bob.address, ts: T0, sig, auth: [] }))
    expect([e.code, e.status]).toEqual(['bad-auth', 401])
  })

  it('fetches a record by address and kind, null on 404', async () => {
    server.handle = (req, res) => {
      if (req.url.endsWith('/address')) res.writeHead(200).end(BYTES)
      else if (req.url.endsWith('/key')) json(res, 404, { error: 'not-found' })
      else json(res, 500, {})
    }
    expect(await relay.fetchRecord(server.url, P.bob.address, 'address')).toEqual(BYTES)
    expect(server.seen.at(-1)?.url).toBe(`/v0/fetch/record/${P.bob.address}/address`)
    expect(await relay.fetchRecord(server.url, P.bob.address, 'key')).toBeNull()
    expect((await failure(relay.fetchRecord(server.url, P.bob.address, 'accept-from'))).status).toBe(500)
  })

  it('opens a pair rendezvous: posts the reach as JSON and reads the nameplate; null on 404 or 405 (no pair call)', async () => {
    const reach = { inviter: P.carol.address, invitation: P.bob.address, relays: ['http://r1.test'] }
    const open = { ...reach, ttl: 600, sig: 'ab'.repeat(64) }
    server.handle = (_req, res) => json(res, 200, { nameplate: '472' })
    expect(await relay.pairOpen(server.url, open)).toBe('472')
    const req = server.seen.at(-1)
    expect(req).toMatchObject({ method: 'POST', url: '/v0/pair/open' })
    expect(req?.headers['content-type']).toBe('application/json')
    expect(JSON.parse(String(req?.body))).toEqual(open)
    for (const status of [404, 405]) {
      server.handle = (_req, res) => json(res, status, { error: 'not-found' })
      expect(await relay.pairOpen(server.url, open)).toBeNull()
    }
    for (const nameplate of [472, '0472', '', 'abc', '1234567890']) {
      server.handle = (_req, res) => json(res, 200, { nameplate })
      expect((await failure(relay.pairOpen(server.url, open))).code).toBe('bad-shape')
    }
    server.handle = (_req, res) => json(res, 429, { error: 'rate-limited' })
    expect((await failure(relay.pairOpen(server.url, open))).status).toBe(429)
  })

  it('claims a nameplate: the reach it holds, null on 404, bad-shape for anything else', async () => {
    const reach = { inviter: P.carol.address, invitation: P.bob.address, relays: ['http://r1.test'], exp: T0 }
    server.handle = (_req, res) => json(res, 200, reach)
    expect(await relay.pairClaim(server.url, '472')).toEqual(reach)
    expect(server.seen.at(-1)).toMatchObject({ method: 'GET', url: '/v0/pair/claim/472' })
    server.handle = (_req, res) => json(res, 404, { error: 'no-nameplate' })
    expect(await relay.pairClaim(server.url, '473')).toBeNull()
    for (const bad of [
      { ...reach, inviter: 1 },
      { ...reach, invitation: null },
      { ...reach, relays: 'http://r1.test' },
      { ...reach, relays: [1] },
      { ...reach, exp: 1.5 },
    ]) {
      server.handle = (_req, res) => json(res, 200, bad)
      expect((await failure(relay.pairClaim(server.url, '472'))).code).toBe('bad-shape')
    }
  })

  it('probes health', async () => {
    server.handle = (_req, res) => json(res, 200, { ok: true })
    expect(await relay.health(server.url)).toBe(true)
    expect(server.seen.at(-1)?.url).toBe('/v0/health')
    server.handle = (_req, res) => json(res, 503, {})
    expect(await relay.health(server.url)).toBe(false)
  })

  it('refuses a response over 256 KiB and a relay that does not answer in time, and takes a redirect as an answer it never follows', async () => {
    server.handle = (_req, res) => {
      res.writeHead(200).end(Buffer.alloc(MAX_RESPONSE_BYTES + 1, 0x20))
    }
    expect((await failure(relay.fetchRecord(server.url, P.bob.address, 'key'))).message).toContain(
      'over 262144 bytes',
    )
    // A 3xx is the relay's answer, a failed try with its status, not "no response".
    server.handle = (_req, res) => {
      res.writeHead(302, { location: 'http://127.0.0.1:1/' }).end()
    }
    const before = server.seen.length
    expect((await failure(relay.fetchRecord(server.url, P.bob.address, 'key'))).status).toBe(302)
    const redirected = await failure(relay.publish(server.url, BYTES))
    expect([redirected.code, redirected.status]).toEqual([null, 302])
    expect(server.seen.length - before).toBe(2)
    server.handle = () => {}
    const slow = createHttpRelay({ timeoutMs: 50 })
    expect((await failure(slow.health(server.url))).status).toBe(0)
  })

  it('answers status 0 when nothing listens, and uses an injected fetch', async () => {
    const port = await closedPort()
    const e = await failure(relay.publish(`http://127.0.0.1:${port}`, BYTES))
    expect([e.code, e.status]).toEqual([null, 0])
    expect(e.message).toContain('no response')
    const urls: string[] = []
    const fake = createHttpRelay({
      fetch: async (url) => {
        urls.push(String(url))
        return new Response(null, { status: 200 })
      },
    })
    expect(await fake.health('http://relay.example')).toBe(true)
    expect(urls).toEqual(['http://relay.example/v0/health'])
    const empty = createHttpRelay({ fetch: async () => new Response(null, { status: 200 }) })
    expect(await empty.fetchRecord('http://x', P.bob.address, 'key')).toEqual(new Uint8Array(0))
    const throwing = createHttpRelay({ fetch: () => Promise.reject('plain') })
    expect((await failure(throwing.health('http://x'))).message).toContain('plain')
  })

  it('composes the HTTP calls and subscribe into one client', () => {
    const client = createRelayClient()
    const keys = ['fetch', 'fetchRecord', 'health', 'pairClaim', 'pairOpen', 'publish', 'subscribe']
    expect(Object.keys(client).sort()).toEqual(keys)
  })

  it("gives a fetched envelope's bytes the relay's AC-Received-At as their receivedAt: absent, none; anything but Unix seconds, bad-shape", async () => {
    const sig = signFetchAuth(P.bob.signing, ID, T0, server.url)
    const proof = { signer: P.bob.address, ts: T0, sig, auth: [] }
    let stamp: string | null = String(T0 + 7)
    server.handle = (_req, res) => {
      res.writeHead(200, stamp === null ? {} : { 'ac-received-at': stamp }).end(BYTES)
    }
    const stamped = await relay.fetch(server.url, ID, proof)
    expect([stamped, stamped.receivedAt, Object.keys(stamped).includes('receivedAt')]).toEqual([
      BYTES,
      T0 + 7,
      false,
    ])
    stamp = null
    const plain = await relay.fetch(server.url, ID, proof)
    expect([plain, plain.receivedAt]).toEqual([BYTES, undefined])
    for (const bad of ['1.5', '-1', '01', '9007199254740992', 'soon', '']) {
      stamp = bad
      const e = await failure(relay.fetch(server.url, ID, proof))
      expect([e.code, e.status], bad).toEqual(['bad-shape', 200])
    }
  })

  it('publishes 1 KiB, 8 KiB, 64 KiB and a full envelope at the cap whole, and a relay that never answers one ends the try in time', async () => {
    server.handle = (_req, res) => json(res, 200, { ok: true, id: ID, duplicate: false, delivered: 1 })
    for (const size of new Set([1024, 8192, 65_536, MAX_ENVELOPE_BYTES])) {
      const bytes = utf8(`{"v":1,"pad":"${'p'.repeat(size - 16)}"}`)
      expect(bytes.length).toBe(size)
      expect(await relay.publish(server.url, bytes)).toEqual({ id: ID, duplicate: false, delivered: 1 })
      expect(new Uint8Array(server.seen.at(-1)?.body as Buffer)).toEqual(bytes)
    }
    // A relay that takes the whole body and never answers: the try fails with no answer (status 0) by its timeout.
    server.handle = () => {}
    const slow = createHttpRelay({ timeoutMs: 100 })
    const started = Date.now()
    const e = await failure(slow.publish(server.url, utf8(`{"v":1,"pad":"${'p'.repeat(65_520)}"}`)))
    expect(e.status).toBe(0)
    expect(Date.now() - started).toBeLessThan(5000)
  })
})

describe('http-relay: the time a request is given (W9)', () => {
  it('is 10 s plus 1 s per whole 16 KiB of body, at most 29 s, under the relay 30 s body timeout', () => {
    expect([BASE_TIMEOUT_MS, MAX_TIMEOUT_MS]).toEqual([10_000, 29_000])
    const sizes = [0, 16_383, 16_384, 65_536, 131_072, 196_608, 262_144, 311_296, 1_048_576]
    expect(sizes.map(timeoutFor)).toEqual([
      10_000, 10_000, 11_000, 14_000, 18_000, 22_000, 26_000, 29_000, 29_000,
    ])
  })

  it('gives a publish the time of its body and a fetch by id the time of a full envelope; a timeoutMs is fixed', async () => {
    server.handle = (_req, res) => json(res, 200, { ok: true, id: ID, duplicate: false, delivered: 1 })
    const spy = vi.spyOn(AbortSignal, 'timeout')
    try {
      const big = utf8(`{"v":1,"pad":"${'p'.repeat(65_536 - 16)}"}`)
      await createHttpRelay().publish(server.url, big)
      await createHttpRelay().publish(server.url, BYTES)
      server.handle = (_req, res) => res.writeHead(200).end(BYTES)
      const proof = { signer: P.bob.address, ts: T0, sig: 'ab', auth: [] }
      await createHttpRelay().fetch(server.url, ID, proof)
      server.handle = (_req, res) => json(res, 200, { ok: true, id: ID, duplicate: false, delivered: 1 })
      await createHttpRelay({ timeoutMs: 1234 }).publish(server.url, big)
      expect(spy.mock.calls.map(([ms]) => ms)).toEqual([14_000, 10_000, timeoutFor(MAX_ENVELOPE_BYTES), 1234])
    } finally {
      spy.mockRestore()
    }
  })
})
