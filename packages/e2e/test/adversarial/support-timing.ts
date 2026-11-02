import { onTestFinished } from 'vitest'
import { sleep } from '../harness.ts'
import { parseResponse, type RawConn, type RawWs } from './support.ts'

// Helpers that take a clock out of a verdict (the timing hardening of 2026-10-28).
// Each one turns a sleep or a client-side band into an event the test waits on, or into a figure the relay reported.

/**
 * A probe of this process's own event loop: a 20 ms timer that remembers how late it ran. max() is the longest stall
 * seen so far (including one still going), which is the most any receipt time here can have been delayed. It is
 * reported beside the numbers, and it is the allowance of a client-side backstop only where a relay-side figure is
 * the primary assertion; it never widens a bound that stands alone. Stopped when the test ends.
 */
export function loopLag(everyMs = 20): { max(): number } {
  let last = performance.now()
  let seen = 0
  const timer = setInterval(() => {
    const t = performance.now()
    seen = Math.max(seen, t - last - everyMs)
    last = t
  }, everyMs)
  onTestFinished(() => clearInterval(timer))
  return { max: () => Math.max(seen, performance.now() - last - everyMs, 0) }
}

/**
 * Sends `GET /v0/health` on `conn` and keeps the connection alive; resolves with the status once the response head
 * has come, or null when the connection closed first or `ms` passed. An answer proves the relay accepted the
 * connection and counted it (it takes a place in its address's count at accept, before it reads a byte).
 */
export async function answered(conn: RawConn, ms = 5_000): Promise<number | null> {
  conn.socket.write('GET /v0/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
  const end = performance.now() + ms
  for (;;) {
    const head = parseResponse(conn.received())
    if (head !== null) return head.status
    if (conn.closedAfter() !== null || performance.now() > end) return null
    await sleep(10)
  }
}

/** Waits until `ws` has been pinged `atLeast` times, or has ended, or `ms` has passed; the count is read after. */
export async function waitPings(ws: RawWs, atLeast: number, ms: number): Promise<void> {
  const end = performance.now() + ms
  while (ws.pings() < atLeast && ws.close() === null && ws.endedAt() === null && performance.now() < end) {
    await sleep(20)
  }
}
