import { AcError } from './errors.ts'
import { isHex, toHex } from './hex.ts'
import { hasExactKeys, isPlainObject } from './json.ts'
import type { Rng } from './keys.ts'

/** The most parents a message names. */
export const MAX_PREV = 64

/** The sealed `thread` of a message (spec/SPEC.md §5): a 32-byte id in hex, and the ids of the messages it answers. */
export interface Thread {
  readonly id: string
  readonly prev: readonly string[]
}

const THREAD_KEYS = ['id', 'prev'] as const

/** A new thread: 32 random bytes of id, and no parents. */
export function newThread(rng: Rng): Thread {
  return checkThread({ id: toHex(rng(32)), prev: [] })
}

/** A reply in the same thread to one or more messages, by their envelope ids (1 to 64, unique). */
export function replyThread(thread: Thread, parents: readonly string[]): Thread {
  if (parents.length === 0) throw new AcError('bad-thread', 'a reply names at least one parent')
  return checkThread({ id: thread.id, prev: [...parents] })
}

/**
 * Checks a thread: `{id, prev}` with a 32-byte hex id and at most 64 unique parent ids (bad-thread, too-many-prev).
 * Returns a copy.
 */
export function checkThread(value: unknown): Thread {
  if (!isPlainObject(value) || !hasExactKeys(value, THREAD_KEYS)) {
    throw new AcError('bad-thread', 'a thread is an object with exactly id and prev')
  }
  const { id, prev } = value
  if (!isHex(id, 32)) throw new AcError('bad-thread', 'thread.id is 32 bytes of lowercase hex')
  if (!Array.isArray(prev)) throw new AcError('bad-thread', 'thread.prev is a list')
  if (prev.length > MAX_PREV)
    throw new AcError('too-many-prev', `${prev.length} parents; the cap is ${MAX_PREV}`)
  if (!prev.every((p) => isHex(p, 32)))
    throw new AcError('bad-thread', 'each parent is an envelope id (64 hex)')
  if (new Set(prev).size !== prev.length) throw new AcError('bad-thread', 'a parent is listed twice')
  return { id, prev: [...prev] }
}
