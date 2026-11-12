import type { Clock } from '@usebag/edge'
import type { Desk, Timers } from './desk.ts'
import type { RecordKeeper } from './keepalive.ts'

// The bag service's wake router (docs/bag-service.md, service/ring). Mail for an identity rings only the connection
// the person last typed in for it, the speaking window; every other connection bound to that identity gets the same
// notification with speaking false, which its shim shows as a quiet notice and never as a turn. A bind counts as
// typing (it is the person's typed word or their Yes in a dialog), so a fresh window speaks until the person types in
// another. Arrivals within SETTLE_MS make one batch: one ring per bound connection per batch. The ring carries the
// label, the unread count and the time, never a sender or a body; the shim turns a speaking ring into the wake text
// merged in packages/cli/src/omp-wake.ts (wakeText: read it and show your person, answer only on their word),
// unchanged. One fetch and one acknowledgement per message is the desk's (desk.ts), not the router's: it rings only.

/** The ring's method on the stream (docs/bag-service.md, contract 1). */
export const RING = 'service/ring'

/**
 * The line a window shows, with no turn, for a ring with speaking false: the mail is the speaking window's to show.
 * The shim prints it as a host notice (Claude Code's hook message, omp's footer), never as a prompt to the model.
 */
export const quietNotice = (as: string, unread: number): string =>
  `bag: ${unread} unread for ${as}, shown in the window you last typed in for ${as}; type here to have the next mail shown here`

/** How long a ring waits for the rest of its burst, in milliseconds (as the omp wake extension waits). */
export const SETTLE_MS = 300

/** What the router needs of a connection: the service connection (socket.ts ServiceConnection) satisfies it. */
export interface Ringable {
  /** The connection's opaque handle: it names the connection and authorises nothing. */
  readonly handle: string
  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void
}

/** The params of service/ring. */
export interface Ring {
  readonly as: string
  readonly unread: number
  readonly speaking: boolean
  readonly at: string
}

interface Seat {
  readonly conn: Ringable
  /** When the person last typed in it (or bound it), Unix seconds, and the order of that act, for ties. */
  typedAt: number
  order: number
}

export interface WakeRouterOptions {
  readonly clock: Clock
  readonly timers: Timers
  /** The unread count of an identity when its batch rings (its desk's unread list). */
  readonly unread: (label: string) => number
  readonly settleMs?: number
}

export class WakeRouter {
  readonly #o: WakeRouterOptions
  /** label to handle to seat. */
  readonly #seats = new Map<string, Map<string, Seat>>()
  /** The labels with a batch waiting to ring, each with its timer's cancel. */
  readonly #pending = new Map<string, () => void>()
  #order = 0

  constructor(options: WakeRouterOptions) {
    this.#o = options
  }

  /** A connection bound to `label` (service/bound): it speaks for it from now, until the person types elsewhere. */
  bind(label: string, conn: Ringable): void {
    const seats = this.#seats.get(label) ?? new Map<string, Seat>()
    this.#seats.set(label, seats)
    seats.set(conn.handle, { conn, typedAt: this.#o.clock.now(), order: ++this.#order })
  }

  /** The person typed in the connection `handle`: it becomes the speaking connection of every identity it is bound to. */
  typed(handle: string): void {
    const now = this.#o.clock.now()
    const order = ++this.#order
    for (const seats of this.#seats.values()) {
      const seat = seats.get(handle)
      if (seat !== undefined) Object.assign(seat, { typedAt: now, order })
    }
  }

  /** The connection is no longer bound to `label`, or (no label) to anything: its close or service/unbind. */
  unbind(handle: string, label?: string): void {
    for (const [l, seats] of this.#seats) {
      if (label !== undefined && l !== label) continue
      seats.delete(handle)
      if (seats.size === 0) this.#seats.delete(l)
    }
  }

  /** The handle of the connection that speaks for `label`: the one the person last typed in; null with none bound. */
  speaking(label: string): string | null {
    let best: Seat | null = null
    for (const s of this.#seats.get(label)?.values() ?? []) {
      if (best === null || s.typedAt > best.typedAt || (s.typedAt === best.typedAt && s.order > best.order))
        best = s
    }
    return best?.conn.handle ?? null
  }

  /**
   * Mail arrived for `label`: after SETTLE_MS, one ring per connection bound to it, speaking true on one. With no
   * connection bound nothing rings: the mail waits in the desk, and the next bind finds it unread.
   */
  arrived(label: string): void {
    if (this.#pending.has(label)) return
    const cancel = this.#o.timers.after(this.#o.settleMs ?? SETTLE_MS, () => {
      this.#pending.delete(label)
      this.ring(label)
    })
    this.#pending.set(label, cancel)
  }

  /** Rings every batch still settling now, and cancels its timer: the drain's first mail step (drainMail). */
  flush(): void {
    for (const [label, cancel] of [...this.#pending]) {
      cancel()
      this.#pending.delete(label)
      this.ring(label)
    }
  }

  /** Rings `label`'s connections now, unless nothing is unread; returns the rings sent, by handle. */
  ring(label: string): ReadonlyMap<string, Ring> {
    const speaking = this.speaking(label)
    const sent = new Map<string, Ring>()
    const at = new Date(this.#o.clock.now() * 1000).toISOString()
    const unread = this.#o.unread(label)
    // A batch that a pending wait took whole leaves nothing unread: that call already holds it, so nothing rings.
    if (unread === 0) return sent
    for (const [handle, seat] of this.#seats.get(label) ?? []) {
      const ring: Ring = { as: label, unread, speaking: handle === speaking, at }
      try {
        seat.conn.notify(RING, { ...ring })
        sent.set(handle, ring)
      } catch {
        // A connection closing under the ring misses it; its close unbinds it, and the others still ring.
      }
    }
    return sent
  }
}

/** What the drain needs of one identity's unit (server.ts Unit): its desk and its keep-alive. */
export interface MailUnit {
  readonly desk: Desk
  readonly records: RecordKeeper | null
}

/**
 * The mail lane's part of a drain (docs/bag-service.md, section 9), called by the service once tool calls have had
 * their time and before it closes each edge: rings what is still settling, stops each keep-alive, and closes each
 * desk, which answers every pending wait at once with its resume token. The returned marks need no flush: each was
 * written to the store as it was set (Desk.keepMarks), so the next service, and the one after a crash, has them.
 */
export function drainMail(units: Iterable<MailUnit>, router: WakeRouter | null): void {
  router?.flush()
  for (const u of units) {
    u.records?.stop()
    u.desk.close()
  }
}
