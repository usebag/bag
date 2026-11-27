import { describe, expect, test } from 'claude-code/testing'
import { MARK_MS, typedMark } from '../hooks/typed'

// The typed-word mark's pure part (typed.ts): the prompt.submit entry and the classic UserPromptSubmit event it marks.

/** A mark on a clock the test moves. */
function rig() {
  let t = 1_000_000
  const m = typedMark(() => t)
  return {
    m,
    after: (ms: number) => {
      t += ms
    },
    submit: (kind: string, text: string) => m.submitted({ origin: { kind }, text }),
    classic: (prompt: string, prompt_id = 'p-1') =>
      m.consume({ hook_event_name: 'UserPromptSubmit', prompt, prompt_id }) as Record<string, unknown>,
  }
}

describe('the typed-word mark', () => {
  test('a composer submission marks its own classic event: bag_typed with that prompt_id', () => {
    const r = rig()
    r.submit('composer', 'use sam')
    expect(r.classic('use sam').bag_typed).toEqual({ v: 1, prompt_id: 'p-1' })
  })

  test('a classic event with other text gets no mark and clears the entry; a scheduled one with the text is not typed', () => {
    const r = rig()
    r.submit('composer', 'use sam')
    const other = r.classic('use bob')
    expect(other.bag_typed).toBeUndefined()
    expect(other.bag_not_typed).toBeUndefined()
    // Cleared: the composer's text, now in a classic event, finds no entry.
    expect(r.classic('use sam').bag_typed).toBeUndefined()
    r.submit('scheduled-trigger', 'use sam')
    const fired = r.classic('use sam', 'p-2')
    expect(fired.bag_typed).toBeUndefined()
    expect(fired.bag_not_typed).toEqual({ v: 1, prompt_id: 'p-2' })
  })

  test(`a composer entry ${MARK_MS} ms old or older marks nothing`, () => {
    const r = rig()
    r.submit('composer', 'use sam')
    r.after(MARK_MS)
    const late = r.classic('use sam')
    expect(late.bag_typed).toBeUndefined()
    expect(late.bag_not_typed).toBeUndefined()
    r.submit('composer', 'use sam')
    r.after(MARK_MS - 1)
    expect(r.classic('use sam').bag_typed).toEqual({ v: 1, prompt_id: 'p-1' })
  })

  test('two classic events after one composer submission: only the first is marked', () => {
    const r = rig()
    r.submit('composer', 'use sam')
    expect(r.classic('use sam', 'p-1').bag_typed).toEqual({ v: 1, prompt_id: 'p-1' })
    const second = r.classic('use sam', 'p-2')
    expect(second.bag_typed).toBeUndefined()
    expect(second.bag_not_typed).toBeUndefined()
  })

  test('a peer, an sdk, an unknown and a missing kind are not typed', () => {
    for (const kind of ['peer', 'sdk', 'later', '']) {
      const r = rig()
      r.submit(kind, 'use sam')
      const e = r.classic('use sam')
      expect(e.bag_typed).toBeUndefined()
      expect(e.bag_not_typed).toEqual({ v: 1, prompt_id: 'p-1' })
    }
    const r = rig()
    r.m.submitted({ text: 'use sam' })
    expect(r.classic('use sam').bag_not_typed).toEqual({ v: 1, prompt_id: 'p-1' })
  })

  test('no entry, or a classic event with no prompt_id, passes on as it came', () => {
    const r = rig()
    expect(Object.keys(r.classic('use sam')).sort()).toEqual(['hook_event_name', 'prompt', 'prompt_id'])
    r.submit('composer', 'use sam')
    const e = r.m.consume({ prompt: 'use sam' }) as Record<string, unknown>
    expect(e).toEqual({ prompt: 'use sam' })
    expect(r.classic('use sam').bag_typed).toBeUndefined()
  })
})
