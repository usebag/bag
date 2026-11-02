import type { InboundMessage } from '@usebag/edge'
import { A2aServer, type A2aServerOptions } from '../src/server.ts'

// Fixtures of the unit tests: addresses, a fixed clock, counting ids and an inbound message built by hand.

export const CLIENT = `ed25519:${'a'.repeat(64)}`
export const AGENT = `ed25519:${'b'.repeat(64)}`
export const OTHER = `ed25519:${'c'.repeat(64)}`
export const T0 = '2026-10-28T20:00:00.000Z'

/** A server with a fixed clock and ids id-1, id-2, ... */
export function server(o: Partial<A2aServerOptions> & Pick<A2aServerOptions, 'handler'>): A2aServer {
  let n = 0
  return new A2aServer({ now: () => new Date(T0), newId: () => `id-${++n}`, ...o })
}

/** A user message with one text part. */
export const say = (text: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  messageId: `m-${text}`,
  role: 'ROLE_USER',
  parts: [{ text }],
  ...extra,
})

/** An opened message as the edge delivers it. */
export function inbound(o: Partial<InboundMessage> & Pick<InboundMessage, 'type' | 'body'>): InboundMessage {
  return {
    id: 'e'.repeat(64),
    from: CLIENT,
    principal: CLIENT,
    root: CLIENT,
    to: [AGENT],
    ts: 1_793_000_000,
    thread: { id: 'f'.repeat(64), prev: [] },
    caveats: [],
    relay: 'http://127.0.0.1:1',
    ...o,
  }
}

/** A promise and its resolver. */
export function deferred<T = void>(): { readonly promise: Promise<T>; readonly resolve: (v: T) => void } {
  let resolve: (v: T) => void = () => {}
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}
