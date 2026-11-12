import { describe, expect, it } from 'vitest'
import { deliveryOf } from '../src/delivery.ts'
import type { OutboxState, OutboxTarget } from '../src/ports.ts'

// One send's delivery, as the CLI's send and the MCP send tool both count it (W9).
const target = (relay: string, state: OutboxState, reason: OutboxTarget['reason'] = null): OutboxTarget => ({
  id: 'ab'.repeat(32),
  relay,
  state,
  tries: 1,
  nextAt: null,
  reason,
  updatedAt: 0,
})

describe('deliveryOf', () => {
  it('counts the relays that took it, those that refused it with their reasons, and those still tried', () => {
    expect(deliveryOf([target('http://r1', 'published')])).toEqual({
      delivered: 1,
      relays: 1,
      refused: [],
      retrying: 0,
      line: 'delivered via 1 of 1 relay',
    })
    const partial = deliveryOf([
      target('http://r1', 'published'),
      target('http://r2', 'published'),
      target('http://r3', 'failed', 'envelope-too-large'),
    ])
    expect(partial).toMatchObject({ delivered: 2, relays: 3, retrying: 0 })
    expect(partial.refused).toEqual([{ relay: 'http://r3', reason: 'envelope-too-large' }])
    expect(partial.line).toBe('delivered via 2 of 3 relays; refused 1: http://r3 envelope-too-large')
    const none = deliveryOf([
      target('http://r1', 'failed', 'not-hosted'),
      target('http://r2', 'failed', null),
      target('http://r3', 'retry', 'unreachable'),
    ])
    expect(none.line).toBe(
      'delivered via 0 of 3 relays; refused 2: http://r1 not-hosted, http://r2 publish-failed; retrying 1',
    )
    expect(deliveryOf([]).line).toBe('delivered via 0 of 0 relays')
  })
})
