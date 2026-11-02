import type { AcErrorCode } from '@usebag/core'
import type { EdgeStore, InboxPatch, InboxRow, InboxState } from './ports.ts'

// The inbox state machine (spec/SPEC.md §9.2): received -> verified | rejected(code); verified -> routed(session) |
// queued; routed, queued and rejected -> acked. An acked row keeps its reason and session. A row rejected with a
// transient code goes back to received with a try count and a next_at (received -> received) and is retried until
// the relay TTL has passed since its ts, when it becomes a final rejected. A row an org policy holds is
// quarantined: received -> quarantined, then back to received on a release or to rejected on a drop. A
// receipt the sender keeps (receipts.ts) is received -> consumed, and goes no further: it reaches no session.

const NEXT: Readonly<Record<InboxState, readonly InboxState[]>> = {
  received: ['verified', 'rejected', 'received', 'quarantined', 'consumed'],
  verified: ['routed', 'queued'],
  rejected: ['acked'],
  routed: ['acked'],
  queued: ['acked'],
  acked: [],
  quarantined: ['received', 'rejected'],
  consumed: [],
}

/**
 * The codes a later check can heal, and so are retried: `resolve-failed` (a record that could not be read yet: a
 * well-known URL briefly down, a relay that does not hold the record yet) and `future-ts` (a ts ahead of this clock
 * by more than the skew, which time heals). Every other code is final at first sight.
 */
export const TRANSIENT_CODES: ReadonlySet<AcErrorCode> = new Set<AcErrorCode>(['resolve-failed', 'future-ts'])

/** True when a row waits for a retry after a transient rejection. */
export function isWaiting(row: InboxRow): boolean {
  return row.state === 'received' && row.nextAt !== null
}

/** True when an inbox row may move from `from` to `to`. */
export function isInboxTransition(from: InboxState, to: InboxState): boolean {
  return NEXT[from].includes(to)
}

/** Moves a row to its next state and persists it; throws on a move the machine does not have. */
export function advanceInbox(store: EdgeStore, row: InboxRow, patch: InboxPatch, now: number): InboxRow {
  if (!isInboxTransition(row.state, patch.state)) {
    throw new Error(`inbox: ${row.state} to ${patch.state} is not a transition`)
  }
  return store.inboxPut(row, patch, now)
}
