import { createServer as createHttpServer } from 'node:http'
import { createServer as createTcpServer, type Server } from 'node:net'
import { signHop, utf8, verifySubscribe } from '@usebag/core'
import { describe, expect, it, onTestFinished, vi } from 'vitest'
import {
  createWsSubscriber,
  jsonObject,
  type SocketFactory,
  type SocketLike,
  subscribeUrl,
  webSocketFactory,
} from '../src/adapters/ws-relay.ts'
import { type Frame, RelayError, type Subscription, type SubscriptionLink } from '../src/ports.ts'
import { P, T0, text } from './support/fixtures.ts'
import { closedPort } from './support/http.ts'
import { startWsServer, type WsPeer } from './support/ws-server.ts'

const NONCE = 'ab'.repeat(32)
const ENV = '{"v":1, "id" : "x","to":["a\\"}"],"nested":{"k":[1,{"z":"}"}]}}'
/** Non-ASCII of 2 and 4 UTF-8 bytes, an escape the core's writer never emits and an escaped solidus. */
const ENV2 = '{"text":"héllo 🚀 \\u00e9 \\/"}'

/** An env frame (spec/SPEC.md §8.5 step 4): the envelope as a JSON string, and received_at. */
const envFrame = (cursor: number, envelope: string, receivedAt?: number): string =>
  JSON.stringify({
    t: 'env',
    cursor,
    ...(receivedAt === undefined ? {} : { received_at: receivedAt }),
    envelope,
  })

class FakeSocket implements SocketLike {
  readonly url: string
  readonly sent: Record<string, unknown>[] = []
  closed = false
  readonly #message: ((event: { readonly data: unknown }) => void)[] = []
  readonly #close: (() => void)[] = []

  constructor(url: string) {
    this.url = url
  }

  addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void): void {
    if (type === 'message') this.#message.push(listener)
    else this.#close.push(listener as () => void)
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data) as Record<string, unknown>)
  }

  close(): void {
    this.closed = true
  }

  /** The relay sends a frame (an object is sent as its JSON text). */
  frame(data: unknown): void {
    for (const l of this.#message) l({ data: typeof data === 'string' ? data : JSON.stringify(data) })
  }

  raw(data: unknown): void {
    for (const l of this.#message) l({ data })
  }

  drop(): void {
    for (const l of this.#close) l()
  }
}

function fakes(): { sockets: FakeSocket[]; factory: SocketFactory } {
  const sockets: FakeSocket[] = []
  return {
    sockets,
    factory: (url) => {
      const s = new FakeSocket(url)
      sockets.push(s)
      return s
    },
  }
}

const tick = (ms = 0): Promise<void> => new Promise((r) => setTimeout(r, ms))

async function take(sub: Subscription, n: number): Promise<Frame[]> {
  const out: Frame[] = []
  const it = sub[Symbol.asyncIterator]()
  for (let i = 0; i < n; i++) {
    const r = await it.next()
    if (r.done) break
    out.push(r.value)
  }
  return out
}

/** `server` on a port of 127.0.0.1, closed when the test ends. */
async function listening(server: Pick<Server, 'listen' | 'address' | 'close'>): Promise<number> {
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  onTestFinished(() => void server.close())
  return (server.address() as { port: number }).port
}

function open(socket: FakeSocket, cursor = 0): void {
  socket.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
  socket.frame({ t: 'ok', cursor })
}

describe('ws-relay: subscribe over WebSocket (spec/SPEC.md §8.5)', () => {
  it('answers the challenge with an auth frame signed over the ac/sub/1 preimage', () => {
    const { sockets, factory } = fakes()
    const hop = signHop(P.jane.signing, P.session.address, [], T0 + 60)
    const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
      'https://relay.test/',
      P.jane.address,
      P.session.signing,
      [hop],
      4,
    )
    const s = sockets[0] as FakeSocket
    expect(s.url).toBe('wss://relay.test/v0/subscribe')
    s.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
    const auth = s.sent[0] as Record<string, unknown>
    expect(auth).toMatchObject({
      t: 'auth',
      mailbox: P.jane.address,
      signer: P.session.address,
      auth: [hop],
      cursor: 4,
    })
    expect(Object.keys(auth)).toEqual(['t', 'mailbox', 'signer', 'auth', 'cursor', 'sig'])
    expect(verifySubscribe(P.session.address, NONCE, P.jane.address, 4, auth.sig as string)).toBe(true)
    sub.close()
  })

  it("delivers env frames in order with the envelope string's exact bytes and the relay's received_at, and sends cumulative acks", async () => {
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
      'http://relay.test',
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    const s = sockets[0] as FakeSocket
    expect(s.url).toBe('ws://relay.test/v0/subscribe')
    open(s)
    expect(s.sent[0]).toMatchObject({ cursor: null })
    sub.ack(0)
    s.frame(envFrame(1, ENV, T0))
    // The same frame re-serialized as a whole, members reordered and indented: the envelope's bytes do not change.
    s.frame(`{ "envelope" : ${JSON.stringify(ENV)} ,\n  "received_at": ${T0 + 1}, "cursor" : 2, "t":"env" }`)
    s.frame({ t: 'env', cursor: 3, envelope: ENV })
    s.frame(envFrame(4, ENV2, T0 + 4))
    s.frame(JSON.stringify(JSON.parse(envFrame(5, ENV2, T0 + 5)), null, 2))
    const frames = await take(sub, 5)
    expect(frames.map((f) => [f.cursor, text(f.envelopeBytes), f.receivedAt])).toEqual([
      [1, ENV, T0],
      [2, ENV, T0 + 1],
      [3, ENV, undefined],
      [4, ENV2, T0 + 4],
      [5, ENV2, T0 + 5],
    ])
    expect(frames[4]?.envelopeBytes).toEqual(utf8(ENV2))
    sub.ack(3)
    sub.ack(2)
    expect(s.sent.slice(1)).toEqual([
      { t: 'ack', cursor: 0 },
      { t: 'ack', cursor: 3 },
      { t: 'ack', cursor: 2 },
    ])
    sub.close()
    expect(s.closed).toBe(true)
    expect(await sub[Symbol.asyncIterator]().next()).toEqual({ value: undefined, done: true })
  })

  it('reconnects after a lost connection with cursor null, whatever it was given and acked (spec/SPEC.md §9 item 10)', async () => {
    const { sockets, factory } = fakes()
    const delays: number[] = []
    const sub = createWsSubscriber({
      socketFactory: factory,
      reconnectDelayMs: (n) => {
        delays.push(n)
        return 0
      },
    }).subscribe('http://relay.test', P.bob.address, P.bob.signing, [], 2)
    const first = sockets[0] as FakeSocket
    open(first, 2)
    first.frame({ t: 'env', cursor: 3, envelope: '{}' })
    expect((await take(sub, 1))[0]?.cursor).toBe(3)
    sub.ack(3)
    first.drop()
    sub.ack(5)
    expect(first.sent.map((f) => f.t)).toEqual(['auth', 'ack'])
    await tick()
    const second = sockets[1] as FakeSocket
    second.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
    expect(second.sent[0]).toMatchObject({ t: 'auth', cursor: null })
    first.frame({ t: 'env', cursor: 99, envelope: '{}' })
    first.drop()
    second.frame({ t: 'ok', cursor: 5 })
    second.frame({ t: 'env', cursor: 6, envelope: '{"v":1}' })
    expect((await take(sub, 1))[0]).toEqual({ cursor: 6, envelopeBytes: utf8('{"v":1}') })
    second.drop()
    await tick()
    ;(sockets[2] as FakeSocket).drop()
    await tick()
    expect(delays).toEqual([0, 0, 1])
    expect(sockets).toHaveLength(4)
    sub.close()
  })

  it('reports each connect the relay admits and each connection lost, never admitted or dropped, and keeps trying', async () => {
    const { sockets, factory } = fakes()
    const links: SubscriptionLink[] = []
    const sub = createWsSubscriber({ socketFactory: factory, reconnectDelayMs: () => 0 }).subscribe(
      'http://relay.test',
      P.bob.address,
      P.bob.signing,
      [],
      null,
      (link) => links.push(link),
    )
    ;(sockets[0] as FakeSocket).drop()
    await tick()
    const challenged = sockets[1] as FakeSocket
    challenged.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
    challenged.drop()
    await tick()
    open(sockets[2] as FakeSocket)
    ;(sockets[2] as FakeSocket).drop()
    await tick()
    open(sockets[3] as FakeSocket)
    const said = links.map((l) => (l.admitted ? 'admitted' : l.error.message))
    const refused =
      'no response: http://relay.test: the relay refused the subscription or could not be reached'
    expect(said).toEqual([
      refused,
      refused,
      'admitted',
      'no response: http://relay.test: the connection closed',
      'admitted',
    ])
    for (const l of links) if (!l.admitted) expect(l.error).toMatchObject({ code: null, status: 0 })
    sub.close()
    ;(sockets[3] as FakeSocket).drop()
    await tick()
    expect(links).toHaveLength(5)
    expect(sockets).toHaveLength(4)
  })

  it('reports the loss before it gives up at maxReconnects, and the iteration rejects with it', async () => {
    const { sockets, factory } = fakes()
    const links: SubscriptionLink[] = []
    const sub = createWsSubscriber({ socketFactory: factory, maxReconnects: 0 }).subscribe(
      'http://relay.test',
      P.bob.address,
      P.bob.signing,
      [],
      null,
      (link) => links.push(link),
    )
    ;(sockets[0] as FakeSocket).drop()
    const [link] = links
    expect(link?.admitted).toBe(false)
    await expect(take(sub, 1)).rejects.toBe(link?.admitted === false ? link.error : null)
  })

  it('reports a refusal by error frame with its code, before the iteration rejects with it', async () => {
    const { sockets, factory } = fakes()
    const links: SubscriptionLink[] = []
    const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
      'http://relay.test',
      P.bob.address,
      P.bob.signing,
      [],
      null,
      (link) => links.push(link),
    )
    ;(sockets[0] as FakeSocket).frame({ t: 'error', error: 'rate-limited' })
    expect(links).toMatchObject([{ admitted: false, error: { code: 'rate-limited' } }])
    await expect(take(sub, 1)).rejects.toMatchObject({ code: 'rate-limited' })
  })

  it('keeps a fault of the reader out of the socket path', async () => {
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({ socketFactory: factory, reconnectDelayMs: () => 0 }).subscribe(
      'http://relay.test',
      P.bob.address,
      P.bob.signing,
      [],
      null,
      () => {
        throw new Error('the reader failed')
      },
    )
    ;(sockets[0] as FakeSocket).drop()
    await tick()
    const second = sockets[1] as FakeSocket
    open(second)
    second.frame({ t: 'env', cursor: 1, envelope: '{}' })
    expect((await take(sub, 1))[0]?.cursor).toBe(1)
    sub.close()
  })

  it.each([
    ['nothing listens', async () => closedPort()],
    [
      'the relay drops it at accept, as a direct relay at its cap does',
      () => listening(createTcpServer((socket) => socket.destroy())),
    ],
    [
      'the relay answers 503 at the upgrade, as a proxied relay at its cap does',
      () => listening(createHttpServer((_, res) => res.writeHead(503).end())),
    ],
  ])('reports a real refused subscription, attempt after attempt: %s', async (_, port) => {
    const links: SubscriptionLink[] = []
    const sub = createWsSubscriber({ reconnectDelayMs: () => 1 }).subscribe(
      `http://127.0.0.1:${await port()}`,
      P.bob.address,
      P.bob.signing,
      [],
      null,
      (link) => links.push(link),
    )
    await vi.waitFor(() => expect(links.length).toBeGreaterThan(2), { timeout: 5000 })
    sub.close()
    for (const l of links) {
      expect(l).toMatchObject({ admitted: false, error: { code: null, status: 0 } })
      expect(l.admitted === false && l.error.message).toContain('refused the subscription')
    }
  })

  it('fails on an error frame, keeping the relay code, and never reconnects', async () => {
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({ socketFactory: factory, reconnectDelayMs: () => 0 }).subscribe(
      'http://r',
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    const s = sockets[0] as FakeSocket
    s.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
    s.frame({ t: 'error', error: 'not-authorized' })
    await expect(take(sub, 1)).rejects.toMatchObject({ code: 'not-authorized', status: 0 })
    expect(s.closed).toBe(true)
    s.drop()
    await tick()
    expect(sockets).toHaveLength(1)
    const other = fakes()
    const sub2 = createWsSubscriber({ socketFactory: other.factory }).subscribe(
      'http://r',
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    ;(other.sockets[0] as FakeSocket).frame({ t: 'error', error: 'something' })
    await expect(take(sub2, 1)).rejects.toMatchObject({ code: null })
  })

  it('fails on a frame its stage does not take, and still delivers what came before', async () => {
    const cases: ((s: FakeSocket) => void)[] = [
      (s) => s.frame({ t: 'env', cursor: 1, envelope: {} }),
      (s) => s.frame({ t: 'ok', cursor: 0 }),
      (s) => s.frame({ t: 'challenge', nonce: 'short', ts: T0 }),
      (s) => s.frame('not json'),
      (s) => s.frame('[1]'),
      (s) => s.raw(new Uint8Array([1])),
      (s) => {
        open(s)
        s.frame({ t: 'env', cursor: -1, envelope: {} })
      },
      (s) => {
        open(s)
        s.frame({ t: 'env', cursor: 1 })
      },
      // An envelope that is not a string, the raw embedding included, is not re-serialized but refused.
      (s) => {
        open(s)
        s.frame({ t: 'env', cursor: 1, envelope: {} })
      },
      (s) => {
        open(s)
        s.frame(`{"t":"env","cursor":1,"envelope":${ENV}}`)
      },
      (s) => {
        open(s)
        s.frame({ t: 'env', cursor: 1, envelope: 5 })
      },
      // The envelope named twice: the core's strict parser refuses the whole frame (spec/SPEC.md §2.5).
      (s) => {
        open(s)
        s.frame('{"t":"env","cursor":1,"envelope":"{}","envelope":"{}"}')
      },
      // A received_at that is not Unix seconds as a plain integer.
      ...['"1"', '1.5', '-1', '1e3', 'null'].map((r) => (s: FakeSocket) => {
        open(s)
        s.frame(`{"t":"env","cursor":1,"received_at":${r},"envelope":"{}"}`)
      }),
      (s) => {
        open(s)
        s.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
      },
      (s) => {
        s.frame({ t: 'challenge', nonce: NONCE, ts: T0 })
        s.frame({ t: 'ok', cursor: 'x' })
      },
    ]
    for (const [i, act] of cases.entries()) {
      const { sockets, factory } = fakes()
      const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
        'http://r',
        P.bob.address,
        P.bob.signing,
        [],
        null,
      )
      act(sockets[0] as FakeSocket)
      const e = await take(sub, 1).then(
        () => null,
        (x: unknown) => x,
      )
      expect(e, `case ${i}`).toMatchObject({ code: 'bad-shape' })
    }
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
      'http://r',
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    const s = sockets[0] as FakeSocket
    open(s)
    s.frame({ t: 'env', cursor: 1, envelope: '{}' })
    s.frame({ t: 'bogus' })
    const it = sub[Symbol.asyncIterator]()
    expect((await it.next()).value).toMatchObject({ cursor: 1 })
    await expect(it.next()).rejects.toBeInstanceOf(RelayError)
  })

  it('fails after maxReconnects lost connections in a row, and when the socket cannot be made', async () => {
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({
      socketFactory: factory,
      maxReconnects: 1,
      reconnectDelayMs: () => 0,
    }).subscribe('http://r', P.bob.address, P.bob.signing, [], null)
    ;(sockets[0] as FakeSocket).drop()
    await tick()
    ;(sockets[1] as FakeSocket).drop()
    await expect(take(sub, 1)).rejects.toMatchObject({
      code: null,
      status: 0,
      message: expect.stringContaining('refused the subscription'),
    })
    const broken = createWsSubscriber({
      socketFactory: () => {
        throw new SyntaxError('bad url')
      },
    }).subscribe('ftp://r', P.bob.address, P.bob.signing, [], null)
    await expect(take(broken, 1)).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining('bad url'),
    })
  })

  it('waits 250 ms × 2^n by default, and close cancels a pending reconnect', async () => {
    // A fake timer the test drives: no real 250 ms, no wall-clock compare.
    vi.useFakeTimers()
    try {
      const { sockets, factory } = fakes()
      const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
        'http://r',
        P.bob.address,
        P.bob.signing,
        [],
        null,
      )
      ;(sockets[0] as FakeSocket).drop()
      await vi.advanceTimersByTimeAsync(249)
      expect(sockets).toHaveLength(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(sockets).toHaveLength(2)
      ;(sockets[1] as FakeSocket).drop()
      sub.close()
      await vi.advanceTimersByTimeAsync(600)
      expect(sockets).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('closes the socket when a for-await loop breaks', async () => {
    const { sockets, factory } = fakes()
    const sub = createWsSubscriber({ socketFactory: factory }).subscribe(
      'http://r',
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    const s = sockets[0] as FakeSocket
    open(s)
    s.frame({ t: 'env', cursor: 1, envelope: '{}' })
    for await (const f of sub) {
      expect(f.cursor).toBe(1)
      break
    }
    expect(s.closed).toBe(true)
    sub.ack(9)
    expect(s.sent.map((f) => f.t)).toEqual(['auth'])
  })

  it('makes the subscribe URL and reads a frame as a JSON object', () => {
    expect(subscribeUrl('http://h:1///')).toBe('ws://h:1/v0/subscribe')
    expect(jsonObject(utf8('{"a":1}'))).toEqual({ a: 1 })
    expect([jsonObject('null'), jsonObject('"s"'), jsonObject('[]'), jsonObject('{')]).toEqual([
      {},
      {},
      {},
      {},
    ])
  })

  it('fails with status 0 when the real WebSocket finds nothing listening', async () => {
    const port = await closedPort()
    const sub = createWsSubscriber({ maxReconnects: 0 }).subscribe(
      `http://127.0.0.1:${port}`,
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    await expect(take(sub, 1)).rejects.toMatchObject({ code: null, status: 0 })
    expect(webSocketFactory).toBeTypeOf('function')
  })

  it('runs the whole exchange over a real socket with the global WebSocket, across a dropped connection', async () => {
    const auths: Record<string, unknown>[] = []
    const acks: number[] = []
    let stored = 0
    const env = (peer: WsPeer, cursor: number): void => peer.send(envFrame(cursor, ENV, T0 + cursor))
    const server = await startWsServer((peer) => {
      peer.onMessage((m) => {
        const f = JSON.parse(m) as Record<string, unknown>
        if (f.t === 'auth') {
          auths.push(f)
          const ok = verifySubscribe(
            f.signer as string,
            NONCE,
            f.mailbox as string,
            f.cursor as number | null,
            f.sig as string,
          )
          if (!ok) return peer.send(JSON.stringify({ t: 'error', error: 'bad-auth' }))
          const from = (f.cursor as number | null) ?? stored
          peer.send(JSON.stringify({ t: 'ok', cursor: from }))
          env(peer, from + 1)
          env(peer, from + 2)
        } else if (f.t === 'ack') {
          acks.push(f.cursor as number)
          stored = Math.max(stored, f.cursor as number)
          if (f.cursor === 2) peer.drop()
        }
      })
      peer.send(JSON.stringify({ t: 'challenge', nonce: NONCE, ts: T0 }))
    })
    const sub = createWsSubscriber({ reconnectDelayMs: () => 10 }).subscribe(
      server.url,
      P.bob.address,
      P.bob.signing,
      [],
      null,
    )
    const seen: number[] = []
    for await (const f of sub) {
      expect(text(f.envelopeBytes)).toBe(ENV)
      expect(f.receivedAt).toBe(T0 + f.cursor)
      seen.push(f.cursor)
      sub.ack(f.cursor)
      if (f.cursor === 4) break
    }
    expect(seen).toEqual([1, 2, 3, 4])
    expect(auths.map((a) => a.cursor)).toEqual([null, null])
    expect(server.peers.map((p) => p.path)).toEqual(['/v0/subscribe', '/v0/subscribe'])
    expect(acks.slice(0, 2)).toEqual([1, 2])
    await server.close()
  })
})
