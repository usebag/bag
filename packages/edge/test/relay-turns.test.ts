import { connect, createServer } from 'node:net'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { type Leave, RELAY_TURNS, RelayTurns } from '../src/adapters/relay-turns.ts'
import { createWsSubscriber, type SocketFactory, type SocketLike } from '../src/adapters/ws-relay.ts'
import { RelayError, type Subscription } from '../src/ports.ts'
import { P } from './support/fixtures.ts'
import { startWsServer } from './support/ws-server.ts'

const UPGRADE_MS = 30
const A = 'http://relay.example/v0/publish'
const B = 'http://other.example/v0/publish'

/** A turn ends in the next check phase. */
const freed = (): Promise<void> => new Promise((done) => setImmediate(done))

/** Takes a turn at `url` for each name; the names in the order they got one, and their leaves. */
function line(turns: RelayTurns, url: string, names: readonly string[]) {
  const got: string[] = []
  const leaves = new Map<string, Leave>()
  const cancels = new Map<string, () => void>()
  for (const name of names) {
    const cancel = turns.take(url, (leave) => {
      got.push(name)
      leaves.set(name, leave)
    })
    cancels.set(name, cancel)
  }
  return { got, leaves, cancels }
}

describe('relay turns: at most the limit at a relay at once', () => {
  it('runs up to the limit at once, the next when one leaves, first come first served', async () => {
    const { got, leaves } = line(new RelayTurns(2), A, ['a', 'b', 'c', 'd'])
    expect(got).toEqual(['a', 'b'])
    leaves.get('b')?.()
    await freed()
    expect(got).toEqual(['a', 'b', 'c'])
    leaves.get('a')?.()
    await freed()
    expect(got).toEqual(['a', 'b', 'c', 'd'])
  })

  it('frees a turn only in the next check phase, when the pool has its connection back', async () => {
    const turns = new RelayTurns(1)
    const { got, leaves } = line(turns, A, ['a', 'b'])
    leaves.get('a')?.()
    expect(got).toEqual(['a'])
    expect(line(turns, A, ['c']).got).toEqual([])
    await freed()
    expect(got).toEqual(['a', 'b'])
  })

  it('counts each host apart, a stuck relay holding nothing up at another, http and ws of one host as one', async () => {
    const turns = new RelayTurns(1)
    const first = line(turns, A, ['a', 'b'])
    expect(line(turns, B, ['other']).got).toEqual(['other'])
    expect(line(turns, 'ws://relay.example/v0/subscribe', ['upgrade']).got).toEqual([])
    first.leaves.get('a')?.()
    await freed()
    expect(first.got).toEqual(['a', 'b'])
  })

  it('takes a second leave for nothing, so one turn never frees two places', async () => {
    const { got, leaves } = line(new RelayTurns(1), A, ['a', 'b', 'c'])
    leaves.get('a')?.()
    leaves.get('a')?.()
    await freed()
    await freed()
    expect(got).toEqual(['a', 'b'])
  })

  it('drops one who left the line, and a host with no one left is forgotten', async () => {
    const turns = new RelayTurns(1)
    const { got, leaves, cancels } = line(turns, A, ['a', 'b', 'c'])
    cancels.get('b')?.()
    leaves.get('a')?.()
    await freed()
    expect(got).toEqual(['a', 'c'])
    leaves.get('c')?.()
    await freed()
    expect(line(turns, A, ['d']).got).toEqual(['d'])
  })

  it('waits for a turn until its signal aborts, which leaves the line with its reason', async () => {
    const turns = new RelayTurns(1)
    const held = line(turns, A, ['a'])
    const stop = new AbortController()
    const waiting = turns.wait(A, stop.signal)
    stop.abort(new Error('timed out'))
    await expect(waiting).rejects.toThrow('timed out')
    const next = turns.wait(A, new AbortController().signal)
    held.leaves.get('a')?.()
    expect(typeof (await next)).toBe('function')
  })

  it('leaves `spare` turns to others, who pass one with no room in the line', async () => {
    const turns = new RelayTurns(3)
    const got: string[] = []
    const leaves: Leave[] = []
    const take = (name: string, spare: number) =>
      turns.take(
        A,
        (leave) => {
          got.push(name)
          leaves.push(leave)
        },
        spare,
      )
    take('up-1', 1)
    take('up-2', 1)
    take('up-3', 1)
    expect(got).toEqual(['up-1', 'up-2'])
    take('call-1', 0)
    expect(got).toEqual(['up-1', 'up-2', 'call-1'])
    take('call-2', 0)
    leaves[2]?.()
    await freed()
    expect(got).toEqual(['up-1', 'up-2', 'call-1', 'call-2'])
    leaves[3]?.()
    await freed()
    expect(got).toEqual(['up-1', 'up-2', 'call-1', 'call-2'])
    leaves[0]?.()
    await freed()
    expect(got).toEqual(['up-1', 'up-2', 'call-1', 'call-2', 'up-3'])
  })

  it('takes a url that is no url by its text, as the call then fails on its own', () => {
    expect(line(new RelayTurns(1), 'not a url', ['a']).got).toEqual(['a'])
  })
})

describe('http relay on turns', () => {
  it('holds the turn until the body is read, since the pool holds the connection until then', async () => {
    const turns = new RelayTurns(1)
    const late = new TransformStream<Uint8Array, Uint8Array>()
    const answers = [new Response(late.readable), new Response('{}')]
    const fetch = vi.fn(async () => answers.shift() as Response)
    const relay = createRelayClient({ fetch: fetch as unknown as typeof globalThis.fetch, turns })
    const first = relay.fetchRecord(A, 'a', 'address')
    const second = relay.fetchRecord(A, 'b', 'address')
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
    await freed()
    await freed()
    expect(fetch).toHaveBeenCalledTimes(1)
    await late.writable.close()
    await Promise.all([first, second])
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('counts the wait for a turn in the timeout, as no answer, and the turn is free after', async () => {
    const turns = new RelayTurns(1)
    const held = line(turns, A, ['a'])
    const relay = createRelayClient({ timeoutMs: 20, turns })
    const e = await relay.fetchRecord(A, 'a', 'address').catch((x: unknown) => x)
    expect(e).toBeInstanceOf(RelayError)
    expect((e as RelayError).status).toBe(0)
    held.leaves.get('a')?.()
    await freed()
    expect(line(turns, A, ['b']).got).toEqual(['b'])
  })

  it('frees the turn when fetch throws', async () => {
    const turns = new RelayTurns(1)
    const refused = vi.fn(async () => {
      throw new Error('refused')
    })
    const relay = createRelayClient({ fetch: refused as unknown as typeof globalThis.fetch, turns })
    await expect(relay.fetchRecord(A, 'a', 'address')).rejects.toBeInstanceOf(RelayError)
    await freed()
    expect(line(turns, A, ['b']).got).toEqual(['b'])
  })
})

describe('a subscription on turns', () => {
  afterEach(() => vi.useRealTimers())

  /** A factory of sockets that record their listeners, for frames and closes by hand. */
  function sockets() {
    const made: { message: ((e: { data: unknown }) => void)[]; close: (() => void)[] }[] = []
    const factory: SocketFactory = () => {
      const s: (typeof made)[number] = { message: [], close: [] }
      made.push(s)
      return {
        addEventListener: (type: 'message' | 'close', l: never) => s[type].push(l),
        send: () => {},
        close: () => {},
      } as SocketLike
    }
    return { made, factory }
  }
  const subscribe = (turns: RelayTurns, factory: SocketFactory): Subscription =>
    createWsSubscriber({ socketFactory: factory, turns }).subscribe(A, P.bob.address, P.bob.signing, [], null)

  it('waits its turn, and holds it until the first frame', async () => {
    const turns = new RelayTurns(1)
    const { made, factory } = sockets()
    const first = subscribe(turns, factory)
    const second = subscribe(turns, factory)
    expect(made).toHaveLength(1)
    made[0]?.message[0]?.({ data: JSON.stringify({ t: 'challenge', nonce: 'ab'.repeat(32) }) })
    await freed()
    expect(made).toHaveLength(2)
    first.close()
    second.close()
  })

  it('leaves its turn when the socket closes, or after the wait when a relay answers nothing', () => {
    vi.useFakeTimers()
    const turns = new RelayTurns(1)
    const { made, factory } = sockets()
    const a = subscribe(turns, factory)
    const b = subscribe(turns, factory)
    const c = subscribe(turns, factory)
    made[0]?.close[0]?.()
    vi.advanceTimersByTime(0)
    expect(made).toHaveLength(2)
    vi.advanceTimersByTime(10_000)
    vi.advanceTimersByTime(1)
    expect(made.length).toBeGreaterThanOrEqual(3)
    for (const s of [a, b, c]) s.close()
  })

  it('opens nothing when closed in the line, and passes its turn on', async () => {
    const turns = new RelayTurns(1)
    const { made, factory } = sockets()
    const first = subscribe(turns, factory)
    const gone = subscribe(turns, factory)
    const third = subscribe(turns, factory)
    gone.close()
    made[0]?.close[0]?.()
    first.close()
    await freed()
    await freed()
    expect(made).toHaveLength(2)
    third.close()
  })

  it('leaves a turn to the calls, however many upgrades are stuck', async () => {
    const turns = new RelayTurns(4)
    const { made, factory } = sockets()
    const subs = Array.from({ length: 8 }, () => subscribe(turns, factory))
    expect(made).toHaveLength(3)
    const leave = await turns.wait(A, new AbortController().signal)
    leave()
    for (const s of subs) s.close()
  })

  it('leaves its turn when the socket cannot be made, and the subscription fails', async () => {
    const turns = new RelayTurns(1)
    const failing = subscribe(turns, () => {
      throw new Error('no sockets')
    })
    await expect(failing[Symbol.asyncIterator]().next()).rejects.toBeInstanceOf(RelayError)
    await freed()
    expect(line(turns, A, ['next']).got).toEqual(['next'])
  })
})

/** A proxy to `port` that counts the most connections open at once, and holds each upgrade back by `UPGRADE_MS`. */
async function countingFront(port: number) {
  const counts = { open: 0, peak: 0 }
  const server = createServer((down) => {
    const up = connect(port, '127.0.0.1')
    counts.open++
    counts.peak = Math.max(counts.peak, counts.open)
    down.on('data', (chunk: Buffer) => {
      if (chunk.toString('latin1').startsWith('GET /v0/subscribe'))
        setTimeout(() => up.write(chunk), UPGRADE_MS)
      else up.write(chunk)
    })
    up.pipe(down)
    for (const s of [up, down]) s.on('error', () => (s === up ? down : up).destroy())
    down.on('close', () => {
      counts.open--
      up.destroy()
    })
    up.on('close', () => down.destroy())
  })
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  const { port: at } = server.address() as { port: number }
  return { counts, url: `http://127.0.0.1:${at}`, close: () => server.close() }
}

describe('connections at a relay: subscriptions plus the turns, on the real pool', () => {
  const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms))
  const ROUNDS = 4
  const CALLS = 16

  /**
   * Rounds through the real fetch, WebSocket and pool that leave the most idle connections when upgrades take no turn:
   * calls fill the pool, upgrades take those connections while more calls spill to new ones, and calls then reconnect
   * from the first of the pool while the spilled ones sit idle. The most connections seen, and the subscriptions.
   */
  async function peakWith(turns: RelayTurns): Promise<number> {
    const ws = await startWsServer((peer) =>
      peer.send(JSON.stringify({ t: 'challenge', nonce: 'ab'.repeat(32) })),
    )
    const front = await countingFront(Number(new URL(ws.url).port))
    const client = createRelayClient({ turns, reconnectDelayMs: () => 60_000 })
    const calls = () =>
      Array.from({ length: CALLS }, (_, i) => client.fetchRecord(front.url, `a${i}`, 'address'))
    const subs: Subscription[] = []
    try {
      for (let round = 1; round <= ROUNDS; round++) {
        await Promise.all(calls())
        for (let i = 0; i < RELAY_TURNS; i++) {
          subs.push(client.subscribe(front.url, P.bob.address, P.bob.signing, [], null))
        }
        await sleep(UPGRADE_MS / 3)
        await Promise.all(calls())
        await vi.waitFor(() => expect(ws.peers).toHaveLength(round * RELAY_TURNS), { timeout: 10_000 })
        await Promise.all(calls())
      }
      return front.counts.peak
    } finally {
      for (const s of subs) s.close()
      front.close()
      await ws.close()
    }
  }

  it('never holds more than the subscriptions plus RELAY_TURNS, whatever comes at once', async () => {
    expect(await peakWith(new RelayTurns())).toBeLessThanOrEqual(ROUNDS * RELAY_TURNS + RELAY_TURNS)
  }, 30_000)

  it('the control: with no such limit the same load goes past that', async () => {
    expect(await peakWith(new RelayTurns(100_000))).toBeGreaterThan(ROUNDS * RELAY_TURNS + RELAY_TURNS)
  }, 30_000)
})
