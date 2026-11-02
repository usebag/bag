import { describe, expect, it } from 'vitest'
import { checkThread, MAX_PREV, newThread, replyThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { xorshiftRng } from './support/rng.ts'

const id = (n: number): string => n.toString(16).padStart(64, '0')

describe('threads', () => {
  it('start with a 32-byte random id and no parents', () => {
    const t = newThread(xorshiftRng(7))
    expect(t.id).toMatch(/^[0-9a-f]{64}$/)
    expect(t.prev).toEqual([])
    expect(newThread(xorshiftRng(7))).toEqual(t)
  })

  it('reply in the same thread to one or more parents', () => {
    const t = newThread(xorshiftRng(8))
    expect(replyThread(t, [id(1)])).toEqual({ id: t.id, prev: [id(1)] })
    expect(replyThread(t, [id(1), id(2), id(3)]).prev).toHaveLength(3)
    expect(
      replyThread(
        t,
        Array.from({ length: MAX_PREV }, (_, i) => id(i)),
      ).prev,
    ).toHaveLength(64)
  })

  it('a reply names at least one parent, at most 64, each once', () => {
    const t = newThread(xorshiftRng(9))
    expectAcError(() => replyThread(t, []), 'bad-thread')
    expectAcError(
      () =>
        replyThread(
          t,
          Array.from({ length: 65 }, (_, i) => id(i)),
        ),
      'too-many-prev',
    )
    expectAcError(() => replyThread(t, [id(1), id(1)]), 'bad-thread')
  })

  it.each([
    ['not an object', 'x'],
    ['a list', []],
    ['a missing prev', { id: id(0) }],
    ['an extra member', { id: id(0), prev: [], depth: 1 }],
    ['an id of 31 bytes', { id: '00'.repeat(31), prev: [] }],
    ['prev not a list', { id: id(0), prev: id(1) }],
    ['a parent that is not an id', { id: id(0), prev: ['x'] }],
  ])('are rejected with %s', (_, value) => {
    expectAcError(() => checkThread(value), 'bad-thread')
  })

  it('come from an rng that returns 32 bytes', () => {
    expectAcError(() => newThread(() => new Uint8Array(16)), 'bad-thread')
  })
})
