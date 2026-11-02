import { describe, expect, it } from 'vitest'
import {
  backoff,
  jitterOf,
  MAX_BACKOFF,
  MAX_JITTER,
  resendTarget,
  retryWait,
  sealedTarget,
  startTry,
  type TryFailure,
  tryFailed,
  tryPublished,
} from '../src/outbox.ts'
import type { OutboxTarget } from '../src/ports.ts'

const ID = 'ab'.repeat(32)
const sealed = sealedTarget(ID, 'http://relay.test', 100)
const WEEK = 604_800

/** A transient failure with no Retry-After, no jitter and a horizon a week away, unless overridden. */
const lost = (o: Partial<TryFailure> = {}): TryFailure => ({
  reason: 'publish-failed',
  permanent: false,
  retryAfter: null,
  horizon: 10 ** 9,
  jitter: 0,
  ...o,
})

describe('outbox state machine (spec/SPEC.md §9.1)', () => {
  it('starts sealed, with no tries and no time to retry', () => {
    expect(sealed).toEqual({
      id: ID,
      relay: 'http://relay.test',
      state: 'sealed',
      tries: 0,
      nextAt: null,
      reason: null,
      updatedAt: 100,
    })
  })

  it('waits 1 s × 2^n after a failure, at most an hour', () => {
    expect(Array.from({ length: 14 }, (_, n) => backoff(n))).toEqual([
      1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3600, 3600,
    ])
    expect(backoff(40)).toBe(MAX_BACKOFF)
    expect(MAX_BACKOFF).toBe(3600)
  })

  it('takes a jitter of up to 10% off each wait, in whole seconds, never under 1 s or over the hour', () => {
    expect(MAX_JITTER).toBe(0.1)
    expect([retryWait(0, 0), retryWait(0, 0.999), retryWait(4, 0.999), retryWait(4, 0.6)]).toEqual([
      1, 1, 15, 16,
    ])
    expect([retryWait(12, 0), retryWait(12, 0.5), retryWait(12, 0.999_999)]).toEqual([3600, 3420, 3241])
    expect(retryWait(40, 0.25)).toBe(3510)
    expect([jitterOf(new Uint8Array(4)), jitterOf(Uint8Array.of(0x80, 0, 0, 0, 9))]).toEqual([0, 0.5])
    const top = jitterOf(new Uint8Array(4).fill(0xff))
    expect([top < 1, top > 0.999]).toEqual([true, true])
    expect(jitterOf(new Uint8Array([7, 0x40, 0, 0, 0]).subarray(1))).toBe(0.25)
  })

  it('goes sealed -> publishing -> published, counting the try', () => {
    const publishing = startTry(sealed, 101)
    expect(publishing).toMatchObject({ state: 'publishing', tries: 0, updatedAt: 101 })
    expect(tryPublished(publishing, 102)).toMatchObject({
      state: 'published',
      tries: 1,
      nextAt: null,
      reason: null,
    })
  })

  it('goes publishing -> retry with next_at = now + the jittered wait, keeping the reason', () => {
    const retry = tryFailed(startTry(sealed, 100), 200, lost())
    expect(retry).toMatchObject({ state: 'retry', tries: 1, nextAt: 201, reason: 'publish-failed' })
    const again = tryFailed(startTry(retry, 201), 300, lost({ reason: 'not-hosted' }))
    expect(again).toMatchObject({ state: 'retry', tries: 2, nextAt: 302, reason: 'not-hosted' })
    let t: OutboxTarget = sealed
    for (let i = 0; i < 12; i++) t = tryFailed(startTry(t, 0), 0, lost())
    expect(tryFailed(startTry(t, 0), 1000, lost({ jitter: 0.5 })).nextAt).toBe(1000 + 3420)
  })

  it("waits for the relay's Retry-After when it is longer than the wait, and the wait when it is shorter", () => {
    expect(tryFailed(startTry(sealed, 0), 10, lost({ reason: 'rate-limited', retryAfter: 30 })).nextAt).toBe(
      40,
    )
    let t: OutboxTarget = sealed
    for (let i = 0; i < 5; i++) t = tryFailed(startTry(t, 0), 0, lost({ reason: 'rate-limited' }))
    expect(tryFailed(startTry(t, 0), 10, lost({ reason: 'rate-limited', retryAfter: 3 })).nextAt).toBe(
      10 + 32,
    )
  })

  it('retries until the horizon, ts + TTL, makes its last try there, and only then fails with publish-failed', () => {
    let t: OutboxTarget = sealed
    let now = 1000
    const horizon = now + WEEK
    const waits: number[] = []
    while (t.state !== 'failed') {
      t = tryFailed(startTry(t, now), now, lost({ horizon }))
      if (t.state === 'retry') {
        waits.push((t.nextAt as number) - now)
        now = t.nextAt as number
      }
    }
    expect(waits.slice(0, 14)).toEqual([1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3600, 3600])
    expect(waits.slice(12, -1).every((w) => w === 3600)).toBe(true)
    // The last wait is cut at the horizon: 604,800 - 4,095 - 166 × 3,600 = 3,105 s.
    expect(waits.at(-1)).toBe(3105)
    expect(t).toMatchObject({
      state: 'failed',
      tries: 180,
      nextAt: null,
      reason: 'publish-failed',
      updatedAt: horizon,
    })
    expect(now).toBe(horizon)
    expect(tryFailed(startTry(sealed, 0), horizon + 5, lost({ horizon }))).toMatchObject({
      state: 'failed',
      tries: 1,
      reason: 'publish-failed',
    })
    // A Retry-After past the horizon is cut to it too.
    const late = tryFailed(startTry(sealed, 0), horizon - 10, lost({ horizon, retryAfter: 600 }))
    expect(late).toMatchObject({ state: 'retry', nextAt: horizon })
  })

  it("fails at once on a permanent refusal, keeping the relay's code", () => {
    expect(
      tryFailed(startTry(sealed, 0), 5, lost({ reason: 'root-not-accepted', permanent: true })),
    ).toMatchObject({
      state: 'failed',
      tries: 1,
      nextAt: null,
      reason: 'root-not-accepted',
    })
  })

  it('reseals a failed target for resend, with its tries reset', () => {
    const failed = tryFailed(startTry(sealed, 0), 5, lost({ reason: 'bad-sig', permanent: true }))
    expect(resendTarget(failed, 9)).toEqual({ ...sealed, updatedAt: 9 })
  })

  it('tries a target again that a crash left publishing', () => {
    expect(startTry(startTry(sealed, 0), 7)).toMatchObject({ state: 'publishing', updatedAt: 7 })
  })

  it('refuses every move the machine does not have', () => {
    const published = tryPublished(startTry(sealed, 0), 0)
    const failed = tryFailed(startTry(sealed, 0), 0, lost({ reason: 'bad-sig', permanent: true }))
    const retry = tryFailed(startTry(sealed, 0), 0, lost())
    expect(() => tryPublished(sealed, 0)).toThrow('outbox: sealed to published is not a transition')
    expect(() => tryFailed(sealed, 0, lost({ permanent: true }))).toThrow('sealed to failed')
    expect(() => resendTarget(sealed, 0)).toThrow('sealed to sealed')
    expect(() => startTry(published, 0)).toThrow('published to publishing')
    expect(() => resendTarget(published, 0)).toThrow('published to sealed')
    expect(() => startTry(failed, 0)).toThrow('failed to publishing')
    expect(() => tryPublished(retry, 0)).toThrow('retry to published')
    expect(() => resendTarget(retry, 0)).toThrow('retry to sealed')
  })
})
