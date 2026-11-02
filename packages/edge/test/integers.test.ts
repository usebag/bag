import { describe, expect, it } from 'vitest'
import { createWsSubscriber, jsonObject, type SocketLike } from '../src/adapters/ws-relay.ts'
import { Audit, parseAuditLine, verifyAuditLog } from '../src/audit.ts'
import type { Frame, Subscription } from '../src/ports.ts'
import { FakeClock, MemoryAuditSink, P, T0 } from './support/fixtures.ts'

// spec/SPEC.md §2.5 (changed 2026-10-25) at the edge's own readers: the relay's subscribe frames and the
// audit log's lines take a number only when it is written as a plain decimal integer of at most 2^53 - 1.

const NOT_PLAIN = ['1.0', '1e0', '1E0', '-0', '-1', '0.5', '1e-400', '9007199254740990.9', '9007199254740992']
const NOT_JSON = ['01', '1e400', '-1e400']
const PLAIN: readonly [string, number][] = [
  ['0', 0],
  ['1', 1],
  ['9007199254740991', 9_007_199_254_740_991],
]
const NONCE = 'ab'.repeat(32)

/** A socket the test speaks for: `frame` delivers the relay's text. */
class Socket implements SocketLike {
  readonly #listeners: ((event: { readonly data: unknown }) => void)[] = []
  addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void): void {
    if (type === 'message') this.#listeners.push(listener)
  }
  send(): void {}
  close(): void {}
  frame(data: string): void {
    for (const l of this.#listeners) l({ data })
  }
}

/** A subscription, its socket, and the outcome of its first frame: the cursor, or the error's code. */
async function first(drive: (s: Socket) => void): Promise<number | string> {
  let socket: Socket | undefined
  const sub: Subscription = createWsSubscriber({
    socketFactory: () => {
      socket = new Socket()
      return socket
    },
  }).subscribe('http://r', P.bob.address, P.bob.signing, [], null)
  drive(socket as Socket)
  try {
    const r = await sub[Symbol.asyncIterator]().next()
    return (r.value as Frame).cursor
  } catch (e) {
    return (e as { code: string }).code
  } finally {
    sub.close()
  }
}

const challenge = (s: Socket): void => s.frame(`{"t":"challenge","nonce":"${NONCE}","ts":${T0}}`)

describe('subscribe frames', () => {
  it('jsonObject keeps a plain cursor and reads any other as NaN, or gives {} for text that is not JSON', () => {
    for (const [s, n] of PLAIN) expect(jsonObject(`{"cursor":${s}}`).cursor).toBe(n)
    for (const s of NOT_PLAIN) expect(jsonObject(`{"cursor":${s}}`).cursor, s).toBeNaN()
    for (const s of NOT_JSON) expect(jsonObject(`{"cursor":${s}}`), s).toEqual({})
  })

  it('refuses an ok frame whose cursor is not plain (bad-shape), and takes 0, 1 and 2^53 - 1', async () => {
    for (const s of [...NOT_PLAIN, ...NOT_JSON]) {
      const got = await first((k) => {
        challenge(k)
        k.frame(`{"t":"ok","cursor":${s}}`)
      })
      expect(got, s).toBe('bad-shape')
    }
    for (const [s, n] of PLAIN) {
      const got = await first((k) => {
        challenge(k)
        k.frame(`{"t":"ok","cursor":${s}}`)
        k.frame(`{"t":"env","cursor":${s},"envelope":"e"}`)
      })
      expect(got, s).toBe(n)
    }
  })

  it('refuses an env frame whose cursor is not plain (bad-shape)', async () => {
    for (const s of [...NOT_PLAIN, ...NOT_JSON]) {
      const got = await first((k) => {
        challenge(k)
        k.frame('{"t":"ok","cursor":0}')
        k.frame(`{"t":"env","cursor":${s},"envelope":"e"}`)
      })
      expect(got, s).toBe('bad-shape')
    }
  })
})

describe('audit lines', () => {
  const sink = new MemoryAuditSink()
  new Audit(sink, new FakeClock()).record({ event: 'verify', decision: 'accept' })
  const good = sink.lines[0] as string
  const respell = (field: string, s: string): string =>
    good.replace(new RegExp(`"${field}":[0-9]+`), `"${field}":${s}`)

  it.each(['seq', 'ts'])('refuses every non-plain spelling of %s, and takes the plain ones', (field) => {
    for (const s of [...NOT_PLAIN, ...NOT_JSON]) expect(() => parseAuditLine(respell(field, s)), s).toThrow()
    for (const [s, n] of PLAIN) expect(parseAuditLine(respell(field, s))[field as 'seq' | 'ts']).toBe(n)
    for (const s of NOT_JSON)
      expect(() => parseAuditLine(respell(field, s)), s).toThrow('an audit line is JSON text')
  })

  it('reports a line whose seq is written 1.0 or 1e0, though its hash recomputes over the canonical 1', () => {
    expect(verifyAuditLog([good])).toEqual({ ok: true, lines: 1 })
    for (const s of ['1.0', '1e0', '1E0']) {
      expect(verifyAuditLog([respell('seq', s)]), s).toEqual({
        ok: false,
        line: 1,
        problem: 'not an audit line',
      })
    }
  })
})
