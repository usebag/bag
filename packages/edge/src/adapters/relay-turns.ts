// The connections one process holds at one relay, beside its WebSockets. Node's global fetch pools HTTP connections per
// origin with no limit and keeps each idle for 4 s, and a WebSocket's upgrade rides the same pool and takes the
// connection it rides (e2e scenario 50c). The pool hands out its first free client, so after an upgrade that client
// opens a new connection while later clients sit idle on theirs. A relay reached directly counts all of them against
// --connections-per-ip: with 64 WebSockets open, idle connections left by a burst took the places that remained, and
// every call was refused until they timed out, with at most 3 in flight (observed 2026-10-30, with the connection-cap
// margin). A turn is one call or one upgrade at a relay. With at most RELAY_TURNS in use the pool never has more clients
// than that, so a process with n subscriptions at a relay holds at most n + RELAY_TURNS connections there, whatever the
// load, beside one it has just closed and the relay has not yet seen close, as a timed-out call's. A process's clients
// share one RelayTurns, because they share the pool. A turn ends in the event loop's next check phase: the pool marks a
// connection free by setImmediate after its response, and a turn begun before that finds every connection busy and makes
// the pool one larger.

/** The calls and upgrades one process runs at one relay at once. */
export const RELAY_TURNS = 4

/** Ends a turn, freeing it for the next in the event loop's next check phase; a second call does nothing. */
export type Leave = () => void

const noop = (): void => {}

interface Waiter {
  readonly go: (leave: Leave) => void
  /** It enters while fewer than this are busy. */
  readonly room: number
}

interface Line {
  busy: number
  /** Who waits for a turn, first come first served among those with room; never anyone while none is busy. */
  readonly waiting: Set<Waiter>
}

export class RelayTurns {
  readonly #limit: number
  readonly #lines = new Map<string, Line>()

  constructor(limit = RELAY_TURNS) {
    this.#limit = limit
  }

  /**
   * Runs `go` with a turn at `url`'s host, at once when one is free, leaving `spare` of them to others; returns what
   * takes it out of the line.
   */
  take(url: string, go: (leave: Leave) => void, spare = 0): () => void {
    const host = URL.parse(url)?.host ?? url
    const line = this.#lines.get(host) ?? { busy: 0, waiting: new Set() }
    this.#lines.set(host, line)
    const room = Math.max(1, this.#limit - spare)
    if (line.busy < room) {
      this.#enter(host, line, go)
      return noop
    }
    const waiter = { go, room }
    line.waiting.add(waiter)
    return () => line.waiting.delete(waiter)
  }

  /** A turn at `url`'s host, or the reason of `signal` when it aborts first, which leaves the line. */
  wait(url: string, signal: AbortSignal): Promise<Leave> {
    return new Promise((resolve, reject) => {
      const give = (leave: Leave): void => {
        signal.removeEventListener('abort', stop)
        resolve(leave)
      }
      const stop = (): void => {
        cancel()
        reject(signal.reason)
      }
      signal.addEventListener('abort', stop, { once: true })
      const cancel = this.take(url, give)
    })
  }

  #enter(host: string, line: Line, go: (leave: Leave) => void): void {
    line.busy++
    let left = false
    go(() => {
      if (left) return
      left = true
      setImmediate(() => this.#free(host, line))
    })
  }

  #free(host: string, line: Line): void {
    line.busy--
    for (const waiter of line.waiting) {
      if (line.busy < waiter.room) {
        line.waiting.delete(waiter)
        this.#enter(host, line, waiter.go)
        return
      }
    }
    if (line.busy === 0) this.#lines.delete(host)
  }
}
