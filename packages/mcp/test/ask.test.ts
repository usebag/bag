import { describe, expect, it } from 'vitest'
import {
  ASK_EVERY_S,
  ASKS_PER_HOME,
  ASKS_PER_WINDOW,
  type Ask,
  askingIn,
  askMs,
  askPerson,
  askState,
  countStart,
  forgetWindow,
  HOME_TIMES,
  type LinkAnswer,
  type LinkAsk,
  linkBudget,
  MAX_PASTE,
  NOT_SENT_PER_WINDOW,
  onAsking,
  STARTS_PER_HOME,
  STARTS_PER_WINDOW,
  textOf,
  UNANSWERED_PER_HOME,
  UNANSWERED_PER_WINDOW,
} from '../src/ask.ts'
import type { ServiceConnection } from '../src/binding.ts'
import type { PairExtra } from '../src/pairing.ts'
import { type ToolContext, ToolError } from '../src/tools.ts'

// askPerson: one function, three routes (elicitation, the omp link, none), one text
// check, a rate limit per window and act, and one policy audit line that never holds the text.

let homes = 0

/** A monotonic clock that moves `ms` at each read: a dialog's answer reads as taking `ms`. */
const pace = (ms: number): (() => number) => {
  let t = 0
  return () => (t += ms)
}
const personPace = (): (() => number) => pace(1000)

/** A fake context and window: `elicit` answers the form, `link` answers over the omp link (null: no link). */
function world(
  o: {
    elicit?: ((params: { message: string; requestedSchema: unknown }) => unknown) | null
    link?: ((q: LinkAsk) => LinkAnswer | null) | null
    mono?: () => number
    surface?: string
  } = {},
) {
  const audit: Record<string, unknown>[] = []
  const logs: unknown[] = []
  const asked: LinkAsk[] = []
  const clock = { t: 1_000_000, now: () => clock.t }
  const conn = {
    handle: `w${homes}`,
    host: o.elicit == null ? 'omp' : 'claude-code',
    cwd: '/w',
    capabilities: { elicitation: o.elicit != null, inputHook: false, raw: {} },
    ...(o.surface === undefined ? {} : { surface: o.surface }),
    closed: false,
    onClose: () => () => {},
    elicit: async (params: { message: string; requestedSchema: unknown }) => o.elicit?.(params),
    notify: () => {},
  } as unknown as ServiceConnection
  const ctx = {
    config: { home: `/home/${homes++}` },
    clock,
    // A person's pace by default: each read moves a second, so no dialog reads as answered at once (unseen).
    mono: o.mono ?? personPace(),
    canElicit: () => o.elicit != null,
    log: { log: (...a: unknown[]) => logs.push(a) },
    opened: { edge: { audit: { record: (e: Record<string, unknown>) => audit.push(e) } } },
    local:
      o.link === undefined
        ? undefined
        : {
            consent: (_w: ServiceConnection, q: LinkAsk) => {
              asked.push(q)
              const a = o.link?.(q) ?? null
              return a === null ? null : Promise.resolve(a)
            },
          },
  } as unknown as ToolContext
  const extra = { signal: new AbortController().signal, requestId: 1 } as unknown as PairExtra
  return { ctx, conn, extra, audit, logs, asked, clock }
}

const confirm: Ask = { act: 'test-act', kind: 'confirm', title: 'Yes: do it', message: 'Do it?' }
const text: Ask = { act: 'test-text', kind: 'text', title: 'paste', message: 'Paste it.', max: 32 }

describe('askPerson: routing', () => {
  it('elicits when the window can, asks the link when it cannot, and is null with neither', async () => {
    const e = world({ elicit: () => ({ action: 'accept', content: { confirm: true } }) })
    expect(await askPerson(e.ctx, e.extra, confirm, e.conn)).toEqual({ said: 'yes', text: null })
    const l = world({ link: () => ({ accepted: true }) })
    expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'yes', text: null })
    expect(l.asked[0]).toMatchObject({ kind: 'confirm', title: 'Yes: do it', message: 'Do it?' })
    const none = world({ link: null })
    expect(await askPerson(none.ctx, none.extra, confirm, none.conn)).toBeNull()
    const stdio = world({})
    expect(await askPerson(stdio.ctx, stdio.extra, confirm, undefined)).toBeNull()
  })

  it('a text ask on a link that did not register text is null, never a confirm standing in for it', async () => {
    const l = world({ link: (q) => (q.kind === 'text' ? null : { accepted: true }) })
    expect(await askPerson(l.ctx, l.extra, text, l.conn)).toBeNull()
    expect(l.asked).toHaveLength(1)
  })
})

describe('askPerson: no answer is not a No (L1)', () => {
  it('none for a timeout, a withdraw or a close (accepted null), and for a fast or cancelled dialog; no only for a No', async () => {
    const l = world({ link: () => ({ accepted: null }) })
    expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'none' })
    const no = world({ link: () => ({ accepted: false }) })
    expect(await askPerson(no.ctx, no.extra, confirm, no.conn)).toEqual({ said: 'no' })
    // A decline faster than a person is unseen (0.4.4): no-elicitation, below.
    const fast = world({ elicit: () => ({ action: 'decline' }), mono: pace(10) })
    await expect(askPerson(fast.ctx, fast.extra, confirm, fast.conn)).rejects.toMatchObject({
      code: 'no-elicitation',
    })
    const slow = world({ elicit: () => ({ action: 'decline' }), mono: pace(1000) })
    expect(await askPerson(slow.ctx, slow.extra, confirm, slow.conn)).toEqual({ said: 'no' })
    const cancel = world({ elicit: () => ({ action: 'cancel' }) })
    expect(await askPerson(cancel.ctx, cancel.extra, confirm, cancel.conn)).toEqual({ said: 'none' })
    const thrown = world({
      elicit: () => {
        throw new Error('host gone')
      },
    })
    expect(await askPerson(thrown.ctx, thrown.extra, confirm, thrown.conn)).toEqual({ said: 'none' })
    const empty = world({ elicit: () => ({ action: 'accept', content: {} }) })
    expect(await askPerson(empty.ctx, empty.extra, confirm, empty.conn)).toEqual({ said: 'none' })
  })
})

describe('askPerson: an answer faster than a person is unseen (0.4.4)', () => {
  const answers: [string, () => unknown][] = [
    ['decline', () => ({ action: 'decline' })],
    ['cancel', () => ({ action: 'cancel' })],
    [
      'a rejection',
      () => {
        throw new Error('host gone')
      },
    ],
    ['accept with Yes', () => ({ action: 'accept', content: { confirm: true } })],
    ['accept with No', () => ({ action: 'accept', content: { confirm: false } })],
  ]

  it('any answer within 250 ms (10 ms here), a Yes included, is no-elicitation: no policy line, no budget spent', async () => {
    for (const [what, elicit] of answers) {
      const w = world({ elicit, mono: pace(10) })
      // More unseen asks than the window's unanswered cap: none is refused rate-limited, for none was spent.
      for (let i = 0; i <= UNANSWERED_PER_WINDOW; i++)
        await expect(askPerson(w.ctx, w.extra, confirm, w.conn), what).rejects.toMatchObject({
          code: 'no-elicitation',
        })
      expect(w.audit, what).toEqual([])
    }
  })

  it('at 300 ms the same answers are the person: No, none, yes, No', async () => {
    const said = async (elicit: () => unknown) => {
      const w = world({ elicit, mono: pace(300) })
      return (await askPerson(w.ctx, w.extra, confirm, w.conn))?.said
    }
    expect(await said(() => ({ action: 'decline' }))).toBe('no')
    expect(await said(() => ({ action: 'cancel' }))).toBe('none')
    expect(await said(() => ({ action: 'accept', content: { confirm: true } }))).toBe('yes')
    expect(await said(() => ({ action: 'accept', content: { confirm: false } }))).toBe('no')
  })

  it('the surface changes the words only: same results on cli, claude-vscode, claude-desktop and none', async () => {
    const texts: Record<string, string> = {}
    for (const surface of ['cli', 'claude-vscode', 'claude-desktop', undefined]) {
      const fast = world({
        elicit: () => ({ action: 'decline' }),
        mono: pace(10),
        ...(surface ? { surface } : {}),
      })
      const e = await askPerson(fast.ctx, fast.extra, confirm, fast.conn).catch((x: unknown) => x)
      expect(e).toBeInstanceOf(ToolError)
      expect((e as ToolError).code).toBe('no-elicitation')
      texts[surface ?? 'none'] = (e as ToolError).message
      const slow = world({
        elicit: () => ({ action: 'accept', content: { confirm: true } }),
        mono: pace(300),
        ...(surface ? { surface } : {}),
      })
      expect(await askPerson(slow.ctx, slow.extra, confirm, slow.conn)).toEqual({ said: 'yes', text: null })
    }
    expect(texts.cli).toBe(texts.none)
    expect(texts.cli).toContain('This host answered the question at once, without showing it to your user')
    expect(texts['claude-vscode']).toContain(
      "Claude Code's VS Code extension does this with every dialog (Claude Code issue 98256)",
    )
    expect(texts['claude-desktop']).toContain(
      'Claude Desktop does this with every dialog (Claude Code issue 98256)',
    )
  })
})

describe('askPerson: the one text check', () => {
  it('textOf: printable ASCII, 1 to max after trimming; line breaks folded only when asked to', () => {
    expect(textOf('  472-tulip-orbit-cedar ')).toBe('472-tulip-orbit-cedar')
    expect(textOf('a\nb')).toBeNull()
    expect(textOf('a\r\nb', MAX_PASTE, true)).toBe('a b')
    expect(textOf('a\u0007b')).toBeNull()
    expect(textOf('café')).toBeNull()
    expect(textOf('   ')).toBeNull()
    expect(textOf('x'.repeat(513))).toBeNull()
    expect(textOf('x'.repeat(512))).toBe('x'.repeat(512))
    expect(textOf(7)).toBeNull()
  })

  it('the link refuses a line break or a control character; elicitation folds a line break and asks a bad one once more', async () => {
    const l = world({ link: () => ({ accepted: true, text: 'a\nb' }) })
    expect(await askPerson(l.ctx, l.extra, text, l.conn)).toEqual({ said: 'none' })
    const answers = ['a\u0007b', 'line one\nline two']
    const e = world({ elicit: () => ({ action: 'accept', content: { text: answers.shift() } }) })
    expect(await askPerson(e.ctx, e.extra, text, e.conn)).toEqual({ said: 'yes', text: 'line one line two' })
    const over = world({ elicit: () => ({ action: 'accept', content: { text: 'x'.repeat(33) } }) })
    expect(await askPerson(over.ctx, over.extra, text, over.conn)).toEqual({ said: 'none' })
  })

  it('a fold ask (the pasted code only) folds line breaks on the link too, and tells the service so', async () => {
    const l = world({ link: () => ({ accepted: true, text: 'ac-peer1:abc\ndef\r\nghi' }) })
    expect(await askPerson(l.ctx, l.extra, { ...text, fold: true }, l.conn)).toEqual({
      said: 'yes',
      text: 'ac-peer1:abc def ghi',
    })
    expect(l.asked[0]).toMatchObject({ kind: 'text', fold: true })
    // Without fold, the same answer on the link stays no answer, and no fold goes to the service.
    const p = world({ link: () => ({ accepted: true, text: 'ac-peer1:abc\ndef' }) })
    expect(await askPerson(p.ctx, p.extra, text, p.conn)).toEqual({ said: 'none' })
    expect(p.asked[0]).not.toHaveProperty('fold')
  })

  it('the typed-name mode: yes only on an exact match with expect; a near match is asked once more, then none', async () => {
    const named = { ...text, expect: 'research' }
    const said = ['Research', 'research']
    const e = world({ elicit: () => ({ action: 'accept', content: { text: said.shift() } }) })
    expect(await askPerson(e.ctx, e.extra, named, e.conn)).toEqual({ said: 'yes', text: 'research' })
    const near = world({ elicit: () => ({ action: 'accept', content: { text: 'researc' } }) })
    expect(await askPerson(near.ctx, near.extra, named, near.conn)).toEqual({ said: 'none' })
    const l = world({ link: () => ({ accepted: true, text: 'research ' }) })
    expect(await askPerson(l.ctx, l.extra, named, l.conn)).toEqual({ said: 'yes', text: 'research' })
  })

  it('a check normalises the text, or makes it no answer', async () => {
    const six = {
      ...text,
      check: (t: string) => (/^\d{6}$/.test(t.replace(/\s/g, '')) ? t.replace(/\s/g, '') : null),
    }
    const l = world({ link: () => ({ accepted: true, text: '227 500' }) })
    expect(await askPerson(l.ctx, l.extra, six, l.conn)).toEqual({ said: 'yes', text: '227500' })
    const bad = world({ link: () => ({ accepted: true, text: '22750' }) })
    expect(await askPerson(bad.ctx, bad.extra, six, bad.conn)).toEqual({ said: 'none' })
  })
})

describe('askPerson: the rate limit and the audit line', () => {
  it('the fourth answered ask of one act in a window within 600 s is rate-limited; another window or act is not', async () => {
    const l = world({ link: () => ({ accepted: false }) })
    for (let i = 0; i < 3; i++)
      expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'no' })
    const fourth = askPerson(l.ctx, l.extra, confirm, l.conn)
    await expect(fourth).rejects.toBeInstanceOf(ToolError)
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow(
      /^rate-limited: .*ask again in \d+ s/,
    )
    expect(await askPerson(l.ctx, l.extra, { ...confirm, act: 'other-act' }, l.conn)).toEqual({ said: 'no' })
    const other = { ...l.conn, handle: 'another-window' } as ServiceConnection
    expect(await askPerson(l.ctx, l.extra, confirm, other)).toEqual({ said: 'no' })
    l.clock.t += ASK_EVERY_S
    expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'no' })
    // An ask the service paces itself (askPending's local pair) takes no limit.
    const p = world({ link: () => ({ accepted: null }) })
    for (let i = 0; i < 8; i++)
      expect(await askPerson(p.ctx, p.extra, { ...confirm, limit: false }, p.conn)).toEqual({ said: 'none' })
  })

  it('no answer spends none of the three: six unanswered asks pass, the seventh is rate-limited', async () => {
    const l = world({ link: () => ({ accepted: null }) })
    for (let i = 0; i < 6; i++)
      expect(await askPerson(l.ctx, l.extra, text, l.conn)).toEqual({ said: 'none' })
    await expect(askPerson(l.ctx, l.extra, text, l.conn)).rejects.toThrow(
      /^rate-limited: .*left unanswered 6 times/,
    )
    // Three unanswered asks leave all three answered ones: the person's Yes after them still goes.
    let n = 0
    const m = world({ link: () => (n++ < 3 ? { accepted: null } : { accepted: true }) })
    for (let i = 0; i < 3; i++) await askPerson(m.ctx, m.extra, confirm, m.conn)
    for (let i = 0; i < 3; i++)
      expect(await askPerson(m.ctx, m.extra, confirm, m.conn)).toEqual({ said: 'yes', text: null })
  })

  it('one policy line per ask, step consent with act, kind, host and said, never the text, title or message', async () => {
    const l = world({ link: () => ({ accepted: true, text: 'SECRET-PASTE-123' }) })
    await askPerson(l.ctx, l.extra, text, l.conn)
    expect(l.audit).toEqual([
      {
        event: 'policy',
        decision: 'accept',
        reason: 'ok',
        from: null,
        detail: { step: 'consent', act: 'test-text', kind: 'text', host: 'omp', said: 'yes' },
      },
    ])
    const line = JSON.stringify(l.audit)
    for (const word of ['SECRET-PASTE-123', 'paste', 'Paste it.']) expect(line).not.toContain(`"${word}"`)
  })
})

describe('askPerson: the home caps', () => {
  it('one window alone never reaches the home caps: its own caps refuse it first, saying here', async () => {
    expect(ASKS_PER_WINDOW).toBeLessThan(ASKS_PER_HOME)
    expect(UNANSWERED_PER_WINDOW).toBeLessThan(UNANSWERED_PER_HOME)
    const l = world({ link: (q) => (q.kind === 'confirm' ? { accepted: true } : { accepted: null }) })
    for (let i = 0; i < ASKS_PER_WINDOW; i++)
      expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'yes', text: null })
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow(
      new RegExp(
        `^rate-limited: test-act was answered ${ASKS_PER_WINDOW} times lately here: ask again in \\d+ s$`,
      ),
    )
    for (let i = 0; i < UNANSWERED_PER_WINDOW; i++)
      expect(await askPerson(l.ctx, l.extra, text, l.conn)).toEqual({ said: 'none' })
    await expect(askPerson(l.ctx, l.extra, text, l.conn)).rejects.toThrow(
      new RegExp(`^rate-limited: test-text was left unanswered ${UNANSWERED_PER_WINDOW} times lately here: `),
    )
  })

  it("full windows of one home reach its caps together: a fresh window is refused with the home's reason", async () => {
    let said: boolean | null = true
    const l = world({ link: () => ({ accepted: said }) })
    const win = (h: string) => ({ ...l.conn, handle: h }) as ServiceConnection
    for (let w = 0; w < HOME_TIMES; w++)
      for (let i = 0; i < ASKS_PER_WINDOW; i++)
        expect(await askPerson(l.ctx, l.extra, confirm, win(`full-${w}`))).toEqual({
          said: 'yes',
          text: null,
        })
    await expect(askPerson(l.ctx, l.extra, confirm, win('fresh'))).rejects.toThrow(
      new RegExp(
        `^rate-limited: test-act was answered ${ASKS_PER_HOME} times lately by all windows of this bag home together`,
      ),
    )
    said = null
    for (let w = 0; w < HOME_TIMES; w++)
      for (let i = 0; i < UNANSWERED_PER_WINDOW; i++)
        expect(await askPerson(l.ctx, l.extra, text, win(`full-${w}`))).toEqual({ said: 'none' })
    await expect(askPerson(l.ctx, l.extra, text, win('fresh'))).rejects.toThrow(
      new RegExp(
        `^rate-limited: test-text was left unanswered ${UNANSWERED_PER_HOME} times lately by all windows of this bag home`,
      ),
    )
  })

  it('many windows of one home, each under its own caps (a window that reconnects is a new one), reach the home cap', async () => {
    let said: boolean | null = false
    const l = world({ link: () => ({ accepted: said }) })
    const win = (h: string) => ({ ...l.conn, handle: h }) as ServiceConnection
    for (let w = 0; w < ASKS_PER_HOME; w++)
      expect(await askPerson(l.ctx, l.extra, confirm, win(`one-${w}`))).toEqual({ said: 'no' })
    await expect(askPerson(l.ctx, l.extra, confirm, win('one-more'))).rejects.toThrow(
      /^rate-limited: .*by all windows of this bag home together.*: ask again in \d+ s$/,
    )
    said = null
    for (let w = 0; w < UNANSWERED_PER_HOME; w++)
      expect(await askPerson(l.ctx, l.extra, text, win(`one-${w}`))).toEqual({ said: 'none' })
    await expect(askPerson(l.ctx, l.extra, text, win('one-more'))).rejects.toThrow(
      /left unanswered .* by all windows of this bag home together/,
    )
    // Another home keeps its own caps, and past 600 s this one asks again.
    const m = world({ link: () => ({ accepted: false }) })
    expect(await askPerson(m.ctx, m.extra, confirm, m.conn)).toEqual({ said: 'no' })
    l.clock.t += ASK_EVERY_S
    said = false
    expect(await askPerson(l.ctx, l.extra, confirm, win('one-more'))).toEqual({ said: 'no' })
  })
})

describe('countStart: the window and home caps', () => {
  it('one window alone stops at its own start cap first, saying here', () => {
    expect(STARTS_PER_WINDOW).toBeLessThan(STARTS_PER_HOME)
    const l = world({ link: () => ({ accepted: true }) })
    for (let i = 0; i < STARTS_PER_WINDOW; i++) countStart(l.ctx, l.conn)
    expect(() => countStart(l.ctx, l.conn)).toThrow(
      new RegExp(
        `^rate-limited: ${STARTS_PER_WINDOW} pairings were started here lately: start again in \\d+ s$`,
      ),
    )
  })

  it('many windows of one home, each under its own start cap, hit the home cap; a closed window does not free it', () => {
    const l = world({ link: () => ({ accepted: true }) })
    const win = (h: string) => ({ ...l.conn, handle: h }) as ServiceConnection
    for (let w = 0; w < STARTS_PER_HOME; w++) countStart(l.ctx, win(`start-${w}`))
    for (let w = 0; w < STARTS_PER_HOME; w++) forgetWindow(`start-${w}`)
    expect(() => countStart(l.ctx, win('start-more'))).toThrow(
      new RegExp(
        `^rate-limited: ${STARTS_PER_HOME} pairings were started lately by all windows of this bag home together.*: start again in \\d+ s$`,
      ),
    )
    // Another home keeps its own cap, and past 600 s this one starts again.
    const m = world({ link: () => ({ accepted: true }) })
    expect(() => countStart(m.ctx, m.conn)).not.toThrow()
    l.clock.t += ASK_EVERY_S
    expect(() => countStart(l.ctx, win('start-more'))).not.toThrow()
  })
})

describe('askPerson: a closed window and the sweep', () => {
  it('after forgetWindow(w1), w1 asks again while w2 stays limited; past 600 s the sweep keeps no key of a quiet window', async () => {
    const l = world({ link: () => ({ accepted: false }) })
    // A time no other test uses, so that this test's first ask sweeps and the one 601 s later sweeps again.
    l.clock.t = 9_000_000
    const w1 = { ...l.conn, handle: 'forget-w1' } as ServiceConnection
    const w2 = { ...l.conn, handle: 'forget-w2' } as ServiceConnection
    // w2 asks another act, so the two windows together stay under the home's caps.
    const other = { ...confirm, act: 'other-act' }
    for (let i = 0; i < ASKS_PER_WINDOW; i++) {
      await askPerson(l.ctx, l.extra, confirm, w1)
      await askPerson(l.ctx, l.extra, other, w2)
    }
    await expect(askPerson(l.ctx, l.extra, confirm, w1)).rejects.toThrow(/lately here/)
    forgetWindow('forget-w1')
    expect(await askPerson(l.ctx, l.extra, confirm, w1)).toEqual({ said: 'no' })
    await expect(askPerson(l.ctx, l.extra, other, w2)).rejects.toThrow(/lately here/)
    expect(askState().windows).toEqual(expect.arrayContaining(['forget-w1', 'forget-w2']))
    l.clock.t += ASK_EVERY_S + 1
    const w3 = { ...l.conn, handle: 'forget-w3' } as ServiceConnection
    expect(await askPerson(l.ctx, l.extra, { ...confirm, act: 'third-act' }, w3)).toEqual({ said: 'no' })
    const held = askState()
    expect(held.windows).not.toContain('forget-w1')
    expect(held.windows).not.toContain('forget-w2')
    expect(held.windows).toContain('forget-w3')
    expect(held.homes).not.toContain(`${l.ctx.config.home}\0test-act`)
    expect(held.homes).not.toContain(`${l.ctx.config.home}\0other-act`)
    expect(held.homes).toContain(`${l.ctx.config.home}\0third-act`)
  })

  it("two homes on different clocks: one home's sweep judges the other's lists at that home's own time", async () => {
    const a = world({ link: () => ({ accepted: false }) })
    const b = world({ link: () => ({ accepted: false }) })
    a.clock.t = 50_000_000
    b.clock.t = 50_000_000
    for (let i = 0; i < ASKS_PER_WINDOW; i++) await askPerson(b.ctx, b.extra, confirm, b.conn)
    // Home a's clock runs past the window and its ask sweeps; home b's clock has not moved.
    a.clock.t += ASK_EVERY_S + 1
    expect(await askPerson(a.ctx, a.extra, confirm, a.conn)).toEqual({ said: 'no' })
    expect(askState().windows).toContain(b.conn.handle)
    b.clock.t += 1
    await expect(askPerson(b.ctx, b.extra, confirm, b.conn)).rejects.toThrow(/lately here/)
  })

  it('an ask that ends after its window closed is written again, and the next sweep takes it', async () => {
    const l = world({ link: () => ({ accepted: false }) })
    l.clock.t = 12_000_000
    let answer: (a: LinkAnswer) => void = () => {}
    ;(l.ctx as unknown as { local: unknown }).local = {
      consent: () =>
        new Promise<LinkAnswer>((r) => {
          answer = r
        }),
    }
    const w = { ...l.conn, handle: 'late-w' } as ServiceConnection
    const asked = askPerson(l.ctx, l.extra, confirm, w)
    forgetWindow('late-w')
    answer({ accepted: false })
    expect(await asked).toEqual({ said: 'no' })
    expect(askState().windows).toContain('late-w')
    l.clock.t += ASK_EVERY_S + 1
    ;(l.ctx as unknown as { local: unknown }).local = {
      consent: () => Promise.resolve({ accepted: false }),
    }
    await askPerson(l.ctx, l.extra, confirm, { ...l.conn, handle: 'late-other' } as ServiceConnection)
    expect(askState().windows).not.toContain('late-w')
  })
})

describe('askPerson: the wait and the clock', () => {
  it('the wait counts from the oldest stamp still in the window, even one written after later ones', async () => {
    const l = world({ link: () => ({ accepted: false }) })
    const port = l.ctx as unknown as { local: unknown }
    let answer: (a: LinkAnswer) => void = () => {}
    port.local = {
      consent: () =>
        new Promise<LinkAnswer>((r) => {
          answer = r
        }),
    }
    // The first ask is stamped at its start, but written only when it ends, after two later ones.
    const first = askPerson(l.ctx, l.extra, confirm, l.conn)
    port.local = { consent: () => Promise.resolve({ accepted: false }) }
    l.clock.t += 100
    for (let i = 0; i < ASKS_PER_WINDOW - 1; i++) await askPerson(l.ctx, l.extra, confirm, l.conn)
    answer({ accepted: false })
    expect(await first).toEqual({ said: 'no' })
    l.clock.t += 100
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow(
      `ask again in ${ASK_EVERY_S - 200} s`,
    )
  })

  it('a step back of ctx.clock counts the later stamps as now: still refused, never more than 600 s to wait, until the clock passes again', async () => {
    const l = world({ link: () => ({ accepted: false }) })
    for (let i = 0; i < ASKS_PER_WINDOW; i++) await askPerson(l.ctx, l.extra, confirm, l.conn)
    l.clock.t -= 300
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow(`ask again in ${ASK_EVERY_S} s`)
    l.clock.t += 300 + ASK_EVERY_S - 1
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow('ask again in 1 s')
    l.clock.t += 1
    expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'no' })
  })
})

describe('askPerson: an ask never sent (too little of its call left)', () => {
  it('six never-sent asks spend none of the unanswered asks and write no policy line', async () => {
    let sent = true
    const l = world({ link: () => (sent ? { accepted: null } : { accepted: null, sent: false }) })
    for (let i = 0; i < UNANSWERED_PER_WINDOW - 1; i++)
      expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'none' })
    expect(l.audit).toHaveLength(UNANSWERED_PER_WINDOW - 1)
    sent = false
    for (let i = 0; i < NOT_SENT_PER_WINDOW; i++)
      expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'none' })
    // No policy line and no service-log line from the ask itself: the service's link-ask line records it.
    expect(l.audit).toHaveLength(UNANSWERED_PER_WINDOW - 1)
    expect(l.logs).toEqual([])
    // The next is refused for the never-sent asks, not for unanswered ones: those still stand one under their cap.
    await expect(askPerson(l.ctx, l.extra, confirm, l.conn)).rejects.toThrow(
      new RegExp(`^rate-limited: test-act was not sent .* ${NOT_SENT_PER_WINDOW} times lately here`),
    )
  })

  it('the seventh never-sent ask in 600 s is rate-limited and reaches no consent port; past 600 s it is asked', async () => {
    const l = world({ link: () => ({ accepted: null, sent: false }) })
    for (let i = 0; i < NOT_SENT_PER_WINDOW; i++)
      expect(await askPerson(l.ctx, l.extra, text, l.conn)).toEqual({ said: 'none' })
    expect(l.asked).toHaveLength(NOT_SENT_PER_WINDOW)
    await expect(askPerson(l.ctx, l.extra, text, l.conn)).rejects.toThrow(
      /^rate-limited: test-text was not sent .*: ask again in \d+ s$/,
    )
    expect(l.asked).toHaveLength(NOT_SENT_PER_WINDOW)
    expect(l.audit).toEqual([])
    l.clock.t += ASK_EVERY_S + 1
    expect(await askPerson(l.ctx, l.extra, text, l.conn)).toEqual({ said: 'none' })
    expect(l.asked).toHaveLength(NOT_SENT_PER_WINDOW + 1)
  })
})

describe('askPerson: an identity closed during the ask', () => {
  it('opened null, or a getter that throws: one consent-ask service-log line naming the window, and no throw', async () => {
    const closed = [
      { value: null },
      {
        get: () => {
          throw new Error('not open')
        },
      },
    ]
    for (const opened of closed) {
      const l = world({ link: () => ({ accepted: true }) })
      Object.defineProperty(l.ctx, 'opened', opened)
      expect(await askPerson(l.ctx, l.extra, confirm, l.conn)).toEqual({ said: 'yes', text: null })
      expect(l.audit).toEqual([])
      expect(l.logs).toEqual([
        [
          'info',
          'consent-ask',
          {
            step: 'consent',
            act: 'test-act',
            kind: 'confirm',
            host: 'omp',
            said: 'yes',
            window: l.conn.handle,
          },
        ],
      ])
    }
  })
})

describe('askPerson: the time limit', () => {
  it('linkBudget is clamp(call_ms - 10 s, 15 s, 120 s), 25 s with no call_ms, 120 s with none', () => {
    expect([
      linkBudget(130_000),
      linkBudget(30_000),
      linkBudget(20_000),
      linkBudget(null),
      linkBudget(0),
    ]).toEqual([120_000, 20_000, 15_000, 25_000, 120_000])
  })

  it('askMs never stands past the call deadline less 5 s, and is null under 15 s left', () => {
    expect(askMs(130_000, 0)).toBe(120_000)
    expect(askMs(130_000, 25_000)).toBe(100_000)
    expect(askMs(30_000, 0)).toBe(20_000)
    expect(askMs(30_000, 11_000)).toBeNull()
    expect(askMs(null, 0)).toBe(25_000)
    expect(askMs(null, 10_001)).toBeNull()
    expect(askMs(0, 10_000_000)).toBe(120_000)
  })

  it('passes the call time so far to the link (startedAt on the monotonic clock)', async () => {
    let now = 40_000
    const l = world({ link: () => ({ accepted: null }), mono: () => now })
    const extra = { ...l.extra, startedAt: 10_000 } as PairExtra
    await askPerson(l.ctx, extra, confirm, l.conn)
    expect(l.asked[0]?.elapsedMs).toBe(30_000)
    now = 0
  })
})

describe('askPerson: the asks waiting on a person (service.json asking)', () => {
  it('counts each ask from before its dialog until it ends, over every window of the home, and tells each listener', async () => {
    const answers: ((r: unknown) => void)[] = []
    const w = world({ elicit: () => new Promise((r) => answers.push(r)) })
    const home = w.ctx.config.home
    const heard: number[] = []
    const stop = onAsking(home, () => heard.push(askingIn(home)))
    const other = { ...w.conn, handle: 'w-other' } as ServiceConnection
    const one = askPerson(w.ctx, w.extra, confirm, w.conn)
    const two = askPerson(w.ctx, w.extra, confirm, other)
    expect(askingIn(home)).toBe(2)
    answers[0]?.({ action: 'accept', content: { confirm: true } })
    expect(await one).toEqual({ said: 'yes', text: null })
    expect(askingIn(home)).toBe(1)
    answers[1]?.({ action: 'cancel' })
    expect(await two).toEqual({ said: 'none' })
    expect(askingIn(home)).toBe(0)
    expect(heard).toEqual([1, 2, 1, 0])
    stop()
    const three = askPerson(w.ctx, w.extra, confirm, w.conn)
    answers[2]?.({ action: 'cancel' })
    await three
    expect(heard).toEqual([1, 2, 1, 0])
  })

  it('an ask that throws, one never sent and one with no link all leave the count at 0; a failing listener fails no ask', async () => {
    const thrown = world({
      link: () => {
        throw new Error('host')
      },
    })
    const home = thrown.ctx.config.home
    const stop = onAsking(home, () => {
      throw new Error('disk')
    })
    await expect(askPerson(thrown.ctx, thrown.extra, confirm, thrown.conn)).rejects.toThrow('host')
    expect(askingIn(home)).toBe(0)
    stop()
    const unsent = world({ link: () => ({ accepted: null, sent: false }) })
    expect(await askPerson(unsent.ctx, unsent.extra, confirm, unsent.conn)).toEqual({ said: 'none' })
    expect(askingIn(unsent.ctx.config.home)).toBe(0)
    const none = world({ link: () => null })
    expect(await askPerson(none.ctx, none.extra, confirm, none.conn)).toBeNull()
    expect(askingIn(none.ctx.config.home)).toBe(0)
  })
})
