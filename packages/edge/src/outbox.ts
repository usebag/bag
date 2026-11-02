import type { OutboxReason, OutboxState, OutboxTarget } from './ports.ts'

// The outbox state machine of one envelope at one relay (spec/SPEC.md §9.1): sealed -> publishing -> published, or
// retry with a wait of 1 s × 2^n capped at an hour, less a jitter of up to 10%, until the relay TTL has passed since
// the envelope's ts (the horizon), then failed, kept for a resend of the same bytes. A permanent refusal fails at
// once. Pure: the Sender persists what these functions return. (Earlier versions stopped after 20 tries, 29,295 s.)
// A retry's reason is the relay's code, `unreachable` for a try that got no answer from the relay (when the
// edge asks for it), or `publish-failed`; giving up at the horizon is always `publish-failed` (Appendix A).

/** The reason of a try that got no answer from its relay: no HTTP status at all. */
export const UNREACHABLE = 'unreachable'

/** The longest wait between two tries, in seconds. */
export const MAX_BACKOFF = 3600
/** The largest share of a wait that the jitter takes off. */
export const MAX_JITTER = 0.1

const NEXT: Readonly<Record<OutboxState, readonly OutboxState[]>> = {
  sealed: ['publishing'],
  // publishing -> publishing: a try that a crash interrupted is tried again.
  publishing: ['published', 'retry', 'failed', 'publishing', 'retired'],
  retry: ['publishing'],
  published: [],
  failed: ['sealed'],
  retired: [],
}

/** The wait, in seconds, after the (n + 1)-th failed try, before the jitter: 1 s × 2^n, at most an hour. */
export function backoff(n: number): number {
  return Math.min(2 ** n, MAX_BACKOFF)
}

/**
 * The wait after the (n + 1)-th failed try: backoff(n) less up to 10% of it, `jitter` being a draw from [0, 1). Whole
 * seconds, never under 1 and never over the hour cap, so retries of many targets spread out.
 */
export function retryWait(n: number, jitter: number): number {
  const base = backoff(n)
  return base - Math.floor(base * MAX_JITTER * jitter)
}

/** A draw from [0, 1) from the first four of `bytes` (the edge's rng). */
export function jitterOf(bytes: Uint8Array): number {
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0) / 2 ** 32
}

function move(t: OutboxTarget, state: OutboxState, now: number, patch: Partial<OutboxTarget>): OutboxTarget {
  if (!NEXT[t.state].includes(state)) throw new Error(`outbox: ${t.state} to ${state} is not a transition`)
  return { ...t, ...patch, state, updatedAt: now }
}

/** A new target: the bytes are persisted and not yet published. */
export function sealedTarget(id: string, relay: string, now: number): OutboxTarget {
  return { id, relay, state: 'sealed', tries: 0, nextAt: null, reason: null, updatedAt: now }
}

/** A try begins. */
export function startTry(t: OutboxTarget, now: number): OutboxTarget {
  return move(t, 'publishing', now, {})
}

/** The relay stored the envelope (or already held it). */
export function tryPublished(t: OutboxTarget, now: number): OutboxTarget {
  return move(t, 'published', now, { tries: t.tries + 1, nextAt: null, reason: null })
}

/** How one try failed, and what bounds the next. */
export interface TryFailure {
  /** The relay's code, unreachable, or publish-failed. */
  readonly reason: OutboxReason
  /** A refusal that the same bytes would meet again: the target fails at once with `reason`. */
  readonly permanent: boolean
  /** A 429's Retry-After, in seconds. */
  readonly retryAfter: number | null
  /** The envelope's ts + the relay TTL: the last second a try is made. */
  readonly horizon: number
  /** A draw from [0, 1) for the jitter. */
  readonly jitter: number
}

/**
 * A try failed. A permanent refusal fails the target at once with its reason; a try at or past the horizon fails it
 * with publish-failed; otherwise it waits retryWait(tries - 1), or the relay's Retry-After when that is longer, but
 * never past the horizon, where one last try is made.
 */
export function tryFailed(t: OutboxTarget, now: number, f: TryFailure): OutboxTarget {
  const tries = t.tries + 1
  if (f.permanent) return move(t, 'failed', now, { tries, nextAt: null, reason: f.reason })
  if (now >= f.horizon) return move(t, 'failed', now, { tries, nextAt: null, reason: 'publish-failed' })
  const wait = Math.max(retryWait(tries - 1, f.jitter), f.retryAfter ?? 0)
  return move(t, 'retry', now, { tries, nextAt: Math.min(now + wait, f.horizon), reason: f.reason })
}

/** A try failed and the target is given up for a later listed relay (spec/SPEC.md §4.3): never tried again. */
export function tryRetired(t: OutboxTarget, now: number, reason: OutboxReason): OutboxTarget {
  return move(t, 'retired', now, { tries: t.tries + 1, nextAt: null, reason })
}

/** A failed target sealed again, its tries reset, so that resend publishes the same bytes. */
export function resendTarget(t: OutboxTarget, now: number): OutboxTarget {
  return move(t, 'sealed', now, { tries: 0, nextAt: null, reason: null })
}
