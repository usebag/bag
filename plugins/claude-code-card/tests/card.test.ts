import type { On } from 'claude-code'
import { describe, type Engine, expect, mock, test } from 'claude-code/testing'

/** The environment's timer (a hooks module's globals are not in the `es2023` lib the types are checked with). */
declare const setTimeout: (run: () => void, ms: number) => unknown

// The mod against the engine's own `$` (`claude plugin test plugins/claude-code-card`): the test's AskUserQuestion
// hook stands for the person (it records each card drawn and answers it), and the test's classic.Elicitation hook
// stands for what runs beneath the mod (bag's command hook), recording the request the mod passed on.

const CONFIRM = {
  message: "Show the full addresses of this machine's\nidentities to this window?",
  requested_schema: {
    type: 'object',
    properties: { confirm: { type: 'boolean', title: 'Yes: show the full addresses here' } },
    required: ['confirm'],
  },
}
const PICK = {
  message: 'Which bag identity should this window act as?\nIt acts as it until the window closes.',
  requested_schema: {
    type: 'object',
    properties: {
      identity: {
        type: 'string',
        title: 'Identity',
        enum: ['id-a', 'id-b', 'id-c', 'id-d', 'id-e'],
        default: 'id-c',
      },
    },
    required: ['identity'],
  },
}
const TEXT = {
  message: 'Every new window in /tmp/w will propose\nthe identity you type here.',
  requested_schema: {
    type: 'object',
    properties: { text: { type: 'string', title: 'bag: the identity to propose' } },
    required: ['text'],
  },
}

type Drawn = { question: string; options: string[]; header: string }
type Pick = string | { dismiss: number }

/** Wires the person (answers, in order) and the hook beneath; returns what was drawn and what was passed on. */
function world(on: On, entrypoint: string | null, answers: Pick[]) {
  const drawn: Drawn[] = []
  const passed: Record<string, unknown>[] = []
  mock.env(on, entrypoint === null ? {} : { CLAUDE_CODE_ENTRYPOINT: entrypoint })
  on('tool.call', { tool: 'AskUserQuestion' }, async (_$, e) => {
    const q = (
      e as unknown as { questions: { question: string; header: string; options: { label: string }[] }[] }
    ).questions[0]
    if (q === undefined) return { deny: 'no question' }
    drawn.push({ question: q.question, options: q.options.map((o) => o.label), header: q.header })
    const a = answers.shift()
    if (a === undefined || typeof a !== 'string') {
      await new Promise<void>((done) => setTimeout(() => done(), a?.dismiss ?? 300))
      return { deny: 'dismissed' }
    }
    return { result: { questions: [q], answers: { [q.question]: a } } }
  })
  on('classic.Elicitation', (_$, e) => {
    passed.push(e as unknown as Record<string, unknown>)
    return {}
  })
  return { drawn, passed }
}

const raise = ($: Engine, req: { message: string; requested_schema: Record<string, unknown> }) =>
  $.classic.Elicitation({ mcp_server_name: 'bag', mode: 'form', ...req })

const cardOf = (passed: Record<string, unknown>[]) =>
  (passed[0]?.bag_card as { v: number; action: string; content: Record<string, unknown> } | undefined) ?? null

describe('the surface gate', () => {
  for (const surface of ['claude-vscode', 'claude-desktop']) {
    test(`draws on ${surface}`, async ($, on) => {
      const w = world(on, surface, ['Yes: show the full addresses here'])
      await raise($, CONFIRM)
      expect(w.drawn.length).toBe(1)
      expect(cardOf(w.passed)?.content.bag_card).toBe('yes')
    })
  }
  for (const surface of ['cli', 'sdk-ts', null]) {
    test(`leaves the request alone on ${surface ?? 'no entrypoint'}`, async ($, on) => {
      const w = world(on, surface, ['Yes: show the full addresses here'])
      await raise($, CONFIRM)
      expect(w.drawn.length).toBe(0)
      expect(w.passed.length).toBe(1)
      expect('bag_card' in (w.passed[0] ?? {})).toBe(false)
    })
  }
  test('leaves another server alone', async ($, on) => {
    const w = world(on, 'claude-vscode', ['Yes: show the full addresses here'])
    await $.classic.Elicitation({ mcp_server_name: 'other', mode: 'form', ...CONFIRM })
    expect(w.drawn.length).toBe(0)
    expect('bag_card' in (w.passed[0] ?? {})).toBe(false)
  })
})

describe('the card drawn and the marker passed on', () => {
  test('a confirm: "bag: " and the folded message, Not now first, No, then the Yes words', async ($, on) => {
    const w = world(on, 'claude-vscode', ['No'])
    await raise($, CONFIRM)
    expect(w.drawn).toEqual([
      {
        question: "bag: Show the full addresses of this machine's identities to this window?",
        options: ['Not now', 'No', 'Yes: show the full addresses here'],
        header: 'bag',
      },
    ])
    const c = cardOf(w.passed)
    expect(c?.v).toBe(1)
    expect(c?.action).toBe('accept')
    expect(c?.content.bag_card).toBe('no')
    expect('confirm' in (c?.content ?? {})).toBe(false)
    expect(typeof c?.content.bag_open_ms).toBe('number')
  })

  test('a confirm answered Yes carries the field true', async ($, on) => {
    const w = world(on, 'claude-desktop', ['Yes: show the full addresses here'])
    await raise($, CONFIRM)
    expect(cardOf(w.passed)?.content).toEqual(
      expect.objectContaining({ confirm: true, bag_card: 'yes' }) as unknown as Record<string, unknown>,
    )
  })

  test('a confirm dismissed by a person is dismissed with the time it stood', async ($, on) => {
    const w = world(on, 'claude-vscode', [{ dismiss: 300 }])
    await raise($, CONFIRM)
    const c = cardOf(w.passed)
    expect(c?.content.bag_card).toBe('dismissed')
    expect((c?.content.bag_open_ms as number) >= 250).toBe(true)
  })

  test('a pick of five pages two a card, Not now first, the proposal first, More last', async ($, on) => {
    const w = world(on, 'claude-vscode', ['More', 'More', 'id-e'])
    await raise($, PICK)
    expect(w.drawn.map((d) => d.options)).toEqual([
      ['Not now', 'id-c', 'id-a', 'More'],
      ['Not now', 'id-b', 'id-d', 'More'],
      ['Not now', 'id-e', 'More'],
    ])
    expect(w.drawn[0]?.question).toBe(
      'bag: Which bag identity should this window act as? It acts as it until the window closes.',
    )
    expect(cardOf(w.passed)?.content).toEqual(
      expect.objectContaining({ identity: 'id-e', bag_card: 'yes' }) as unknown as Record<string, unknown>,
    )
  })

  test('a text card: Ask me later first, Cancel second, the typed value passed as the field', async ($, on) => {
    const w = world(on, 'claude-vscode', ['id-a'])
    await raise($, TEXT)
    expect(w.drawn[0]?.options).toEqual(['Ask me later', 'Cancel'])
    expect(cardOf(w.passed)?.content).toEqual(
      expect.objectContaining({ text: 'id-a', bag_card: 'yes' }) as unknown as Record<string, unknown>,
    )
  })

  test('a card the host refuses at once (nobody to ask, dontAsk) sends no marker', async ($, on) => {
    const w = world(on, 'claude-vscode', [{ dismiss: 0 }])
    await raise($, CONFIRM)
    expect(w.passed.length).toBe(1)
    expect('bag_card' in (w.passed[0] ?? {})).toBe(false)
  })

  test('Not now on a confirm is a dismissal, with no field', async ($, on) => {
    const w = world(on, 'claude-vscode', ['Not now'])
    await raise($, CONFIRM)
    const c = cardOf(w.passed)
    expect(c?.content.bag_card).toBe('dismissed')
    expect('confirm' in (c?.content ?? {})).toBe(false)
  })

  test('a throw before drawing sends no marker and passes the request on untouched', async ($, on) => {
    const drawn: unknown[] = []
    const passed: Record<string, unknown>[] = []
    on('env.get', () => {
      throw new Error('broken')
    })
    on('tool.call', { tool: 'AskUserQuestion' }, () => {
      drawn.push(1)
      return { deny: 'x' }
    })
    on('classic.Elicitation', (_$, e) => {
      passed.push(e as unknown as Record<string, unknown>)
      return {}
    })
    await raise($, CONFIRM)
    expect(drawn.length).toBe(0)
    expect(passed.length).toBe(1)
    expect('bag_card' in (passed[0] ?? {})).toBe(false)
    expect(passed[0]?.message).toBe(CONFIRM.message)
  })

  test('Other typed on a confirm is other, never the Yes', async ($, on) => {
    const w = world(on, 'claude-vscode', ['yes please'])
    await raise($, CONFIRM)
    const c = cardOf(w.passed)
    expect(c?.content.bag_card).toBe('other')
    expect('confirm' in (c?.content ?? {})).toBe(false)
  })
})
