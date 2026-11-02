import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { advanceInbox, isInboxTransition, isWaiting, TRANSIENT_CODES } from '../src/inbox.ts'
import type { InboxState } from '../src/ports.ts'

const STATES: readonly InboxState[] = ['received', 'verified', 'rejected', 'routed', 'queued', 'acked']
const ALLOWED = new Set([
  'received verified',
  'received rejected',
  'received received',
  'verified routed',
  'verified queued',
  'rejected acked',
  'routed acked',
  'queued acked',
])

describe('inbox state machine (spec/SPEC.md §9.2)', () => {
  it('has exactly the eight moves: received -> verified | rejected | received (a retry) -> routed | queued -> acked', () => {
    for (const from of STATES) {
      for (const to of STATES)
        expect(isInboxTransition(from, to), `${from} -> ${to}`).toBe(ALLOWED.has(`${from} ${to}`))
    }
  })

  it('persists each move and refuses one it does not have, leaving the row as it was', () => {
    const store = new SqliteStore(':memory:')
    const row = store.inboxAdd('http://r', 'ed25519:mbox', 1, new Uint8Array([1]), 10)
    expect(row).toMatchObject({ state: 'received', tries: 0, nextAt: null })
    const verified = advanceInbox(store, row, { state: 'verified', id: 'i', content: '{}' }, 11)
    expect(verified).toMatchObject({ state: 'verified', id: 'i', content: '{}', updatedAt: 11 })
    expect(() => advanceInbox(store, verified, { state: 'acked' }, 12)).toThrow(
      'inbox: verified to acked is not a transition',
    )
    const routed = advanceInbox(store, verified, { state: 'routed', session: 's1' }, 13)
    const acked = advanceInbox(store, routed, { state: 'acked' }, 14)
    expect(acked).toMatchObject({ state: 'acked', session: 's1', id: 'i' })
    expect(store.inboxFind('http://r', 'ed25519:mbox', 1)).toEqual(acked)
    expect(() => advanceInbox(store, acked, { state: 'received' }, 15)).toThrow('acked to received')
    store.close()
  })

  it('keeps a row that waits received, with its tries and next_at, and names the two transient codes', () => {
    const store = new SqliteStore(':memory:')
    const row = store.inboxAdd('http://r', 'ed25519:mbox', 1, new Uint8Array([1]), 10)
    expect(isWaiting(row)).toBe(false)
    const waiting = advanceInbox(
      store,
      row,
      { state: 'received', reason: 'resolve-failed', tries: 1, nextAt: 11 },
      10,
    )
    expect(waiting).toMatchObject({ state: 'received', reason: 'resolve-failed', tries: 1, nextAt: 11 })
    expect(isWaiting(waiting)).toBe(true)
    expect(store.inboxFind('http://r', 'ed25519:mbox', 1)).toEqual(waiting)
    const rejected = advanceInbox(store, waiting, { state: 'rejected', nextAt: null }, 12)
    expect(isWaiting(rejected)).toBe(false)
    expect([...TRANSIENT_CODES].sort()).toEqual(['future-ts', 'resolve-failed'])
    store.close()
  })
})
