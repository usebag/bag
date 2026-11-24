import { describe, expect, test } from 'claude-code/testing'
import {
  acts,
  blank,
  confirmed,
  FAST_MS,
  FIXED,
  type Plan,
  picked,
  planOf,
  question,
  runCard,
  typed,
} from '../hooks/card-logic'

// The adapter's pure part (card-logic.ts), under `claude plugin test plugins/claude-code-card`: every shape of the
// request bag sends (ROWS below) to its card, the harmless option first, the question byte for
// byte, each resolution to its marker, and the surface gate.

const bool = (title: string) => ({
  type: 'object',
  properties: { confirm: { type: 'boolean', title } },
  required: ['confirm'],
})
const text = (title: string) => ({
  type: 'object',
  properties: { text: { type: 'string', title } },
  required: ['text'],
})
const ADDRESS = { type: 'string', title: "Your peer's address, if you know it" }
const labels = (n: number) => Array.from({ length: n }, (_, i) => `id-${String.fromCharCode(97 + i)}`)
const pick = (n: number, proposal?: string) => ({
  type: 'object',
  properties: {
    identity: {
      type: 'string',
      title: 'Identity',
      enum: labels(n),
      ...(proposal ? { default: proposal } : {}),
    },
  },
  required: ['identity'],
})

/** The inventory: every request bag sends, by row: its schema, and the cards (question, options) it must draw. */
const ROWS: { row: string; message: string; schema: object; plan: Plan['kind'] }[] = [
  {
    row: '1a bind, named',
    message:
      'Act as alice in this window?\nIts tools then act as alice until it closes.\nNo: this window will not ask for alice again for a while.',
    schema: {
      type: 'object',
      properties: { bind: { type: 'boolean', title: 'Yes, act as alice', default: false } },
      required: ['bind'],
    },
    plan: 'confirm',
  },
  {
    row: '1b bind, pick of 3',
    message: 'Which bag identity should this window act as?\nIt acts as it until the window closes.',
    schema: pick(3, 'id-b'),
    plan: 'pick',
  },
  {
    row: '1b bind, pick of 5',
    message: 'Which bag identity should this window act as?\nIt acts as it until the window closes.',
    schema: pick(5, 'id-c'),
    plan: 'pick',
  },
  {
    row: '2 identities-full',
    message: "Show the full addresses of this machine's\nidentities to this window?",
    schema: bool('Yes: show the full addresses here'),
    plan: 'confirm',
  },
  {
    row: '3 local-pair',
    message:
      'alice and bob, on this machine: allow messages?\nNo: declined for 24 h; held mail goes back as declined.',
    schema: bool('Yes: allow alice and bob'),
    plan: 'confirm',
  },
  {
    row: '4 local-reask',
    message: 'Ask bob again to allow messages from alice?\nYou declined at 10:12.',
    schema: bool('Yes: ask bob'),
    plan: 'confirm',
  },
  {
    row: '5 local-hide',
    message: 'Keep alice apart from the other identities here?',
    schema: bool('Yes: keep alice apart'),
    plan: 'confirm',
  },
  {
    row: '6 pair invite, address',
    message:
      'Invite a peer: next you get a pairing code to send them.\nTheir address, if known: only it can answer. Else empty.\nThey will be named carol here.',
    schema: { type: 'object', properties: { address: ADDRESS }, required: [] },
    plan: 'text',
  },
  {
    row: '7 pair accept, paste',
    message:
      'Paste the code or invite string your peer sent.\nSpaces, hyphens and line breaks are fine.\nThey will be named carol here.',
    schema: {
      type: 'object',
      properties: { invite: { type: 'string', title: 'the code or invite string' }, address: ADDRESS },
      required: ['invite'],
    },
    plan: 'text',
  },
  {
    row: '8 pair accept, check digits',
    message:
      'Check digits: 123 456\nSecurity check: read them out, not where the code was sent.\nNot shown again. Confirm to send to ed25519:ab12...cd34.',
    schema: bool('I read them to my peer'),
    plan: 'confirm',
  },
  {
    row: '9 pair invite, compare',
    message: 'Type the six digits your peer reads to you.\nPeer: ed25519:ab12...cd34',
    schema: text('bag: type the six digits your peer reads to you'),
    plan: 'text',
  },
  {
    row: '10 identity-create',
    message: 'Make carol and publish it to these relays?',
    schema: bool('Yes: make carol and publish it'),
    plan: 'confirm',
  },
  {
    row: '11 identity-remove',
    message: 'Remove carol?',
    schema: bool('Yes: remove carol and tell its relays'),
    plan: 'confirm',
  },
  {
    row: '12 identity-relays',
    message: 'Set the relays of carol?',
    schema: bool('Yes: set the relays of carol'),
    plan: 'confirm',
  },
  {
    row: '13 keep-alive',
    message: 'Keep carol alive?',
    schema: bool('Yes: keep-alive on for carol'),
    plan: 'confirm',
  },
  {
    row: '14 local-delivery',
    message: 'Turn local delivery on?',
    schema: bool('Yes: turn local delivery on'),
    plan: 'confirm',
  },
  { row: '15 unpair', message: 'Unpair bob?', schema: bool('Yes: unpair bob'), plan: 'confirm' },
  {
    row: '16 names-add',
    message: 'Add the name bob?',
    schema: bool('Yes: add the name bob'),
    plan: 'confirm',
  },
  {
    row: '17a host-wire',
    message: 'Every new window in /w will propose alice.',
    schema: bool('Yes: wire claude-code in this folder'),
    plan: 'confirm',
  },
  {
    row: '17b host-wire, label',
    message: 'Every new window in /w will propose\nthe identity you type here.',
    schema: text('bag: the identity to propose'),
    plan: 'text',
  },
  {
    row: '17c host-unwire',
    message: 'Unwire claude-code from /w?',
    schema: bool('Yes: unwire claude-code from this folder'),
    plan: 'confirm',
  },
  {
    row: '18 service',
    message: 'Start bag at every login?',
    schema: bool('Yes: start bag at every login'),
    plan: 'confirm',
  },
  {
    row: '19 telemetry-on',
    message: 'Turn telemetry on?',
    schema: bool('Yes: turn telemetry on for this machine'),
    plan: 'confirm',
  },
  {
    row: '20 sign-out',
    message: 'Sign alice out for good?',
    schema: bool('Yes: sign alice out for good'),
    plan: 'confirm',
  },
]

/** Draws a request with a person who answers `answers` in order (a throw for null, after `ms`); the cards and result. */
async function draw(
  e: { message: string; requested_schema: unknown },
  answers: (string | null)[],
  surface = 'claude-vscode',
  ms = 400,
) {
  let t = 1000
  const cards: { question: string; options: readonly string[] }[] = []
  const ask = async (q: string, options: readonly string[]) => {
    cards.push({ question: q, options })
    t += ms
    const a = answers.shift()
    if (a === undefined || a === null) throw new Error('dismissed')
    return a
  }
  const content = await runCard({ mcp_server_name: 'bag', mode: 'form', ...e }, surface, ask, () => t)
  return { cards, content }
}

describe('every row of the inventory to its card', () => {
  for (const r of ROWS) {
    test(`${r.row}: the shape, the question byte for byte, the harmless option first`, async () => {
      const plan = planOf(r.schema)
      expect(plan?.kind).toBe(r.plan)
      const { cards } = await draw({ message: r.message, requested_schema: r.schema }, [null])
      const first = cards[0]
      expect(first?.question).toBe(`bag: ${r.message.split('\n').join(' ')}`)
      expect(first?.options[0]).toBe(r.plan === 'text' ? 'Ask me later' : 'Not now')
      if (r.plan === 'confirm') {
        const title = Object.values(
          (r.schema as { properties: Record<string, { title: string }> }).properties,
        )[0]?.title
        expect(first?.options).toEqual(['Not now', 'No', title as string])
      }
    })
  }

  test('the question keeps every byte but line breaks and controls: each one space, tab kept, no mark added', () => {
    expect(question('a\r\nb\rc\nd')).toBe('bag: a b c d')
    expect(question('a\u2028b\u2029c\vd\fe\u0001f\u001fg\th')).toBe('bag: a b c d e f g\th')
    expect(question('  two  spaces\n\nkept  ')).toBe('bag:   two  spaces  kept  ')
    expect(question('No question mark')).toBe('bag: No question mark')
  })

  test('a pick of 3 is one card; of 5, two a card with More, the proposal first, wrapping after the last', async () => {
    const three = await draw({ message: 'm', requested_schema: pick(3, 'id-b') }, ['id-c'])
    expect(three.cards.map((c) => c.options)).toEqual([['Not now', 'id-b', 'id-a', 'id-c']])
    const five = await draw({ message: 'm', requested_schema: pick(5, 'id-c') }, [
      'More',
      'More',
      'More',
      'id-a',
    ])
    expect(five.cards.map((c) => c.options)).toEqual([
      ['Not now', 'id-c', 'id-a', 'More'],
      ['Not now', 'id-b', 'id-d', 'More'],
      ['Not now', 'id-e', 'More'],
      ['Not now', 'id-c', 'id-a', 'More'],
    ])
    expect(five.content).toEqual({ identity: 'id-a', bag_card: 'yes', bag_open_ms: 1600 })
  })

  test('the pair accept form: the paste, then the address card under its own title', async () => {
    const r = ROWS.find((x) => x.row.startsWith('7 ')) as (typeof ROWS)[number]
    const both = await draw({ message: r.message, requested_schema: r.schema }, ['k7-code', 'ed25519:00'])
    expect(both.cards.map((c) => c.options)).toEqual([
      ['Ask me later', 'Cancel'],
      ['Ask me later', 'Cancel', 'Accept with no address'],
    ])
    expect(both.cards[1]?.question).toBe("bag: Your peer's address, if you know it")
    expect(both.content).toEqual({
      invite: 'k7-code',
      address: 'ed25519:00',
      bag_card: 'yes',
      bag_open_ms: 800,
    })
    const bare = await draw({ message: r.message, requested_schema: r.schema }, [
      'k7-code',
      'Accept with no address',
    ])
    expect(bare.content).toEqual({ invite: 'k7-code', bag_card: 'yes', bag_open_ms: 800 })
    const cancelled = await draw({ message: r.message, requested_schema: r.schema }, ['Cancel'])
    expect(cancelled.cards.length).toBe(1)
    expect(cancelled.content).toEqual({ bag_card: 'no', bag_open_ms: 400 })
  })

  test('the invite address form alone: Ask me later, Cancel, then Invite with no address', async () => {
    const r = ROWS.find((x) => x.row.startsWith('6 ')) as (typeof ROWS)[number]
    const d = await draw({ message: r.message, requested_schema: r.schema }, ['Invite with no address'])
    expect(d.cards[0]?.options).toEqual(['Ask me later', 'Cancel', 'Invite with no address'])
    expect(d.content).toEqual({ bag_card: 'yes', bag_open_ms: 400 })
  })

  test('a pick leaves off a Skip-like value and the adapter words in any case; the rest still draw and bind', async () => {
    const enumOf = (values: string[]) => ({
      type: 'object',
      properties: { identity: { type: 'string', title: 'Identity', enum: values, default: values[0] } },
      required: ['identity'],
    })
    const home = enumOf(['skip', 'alice'])
    expect(planOf(home)).toEqual({ kind: 'pick', field: 'identity', values: ['alice'] })
    const shown = await draw({ message: 'm', requested_schema: home }, ['alice'])
    expect(shown.cards.map((c) => c.options)).toEqual([['Not now', 'alice']])
    expect(shown.content).toEqual({ identity: 'alice', bag_card: 'yes', bag_open_ms: 400 })
    const skipped = await draw({ message: 'm', requested_schema: home }, ['skip'])
    expect(skipped.content).toEqual({ bag_card: 'dismissed', bag_open_ms: 400 })
    const words = enumOf(['no', 'NOT NOW', 'cancel', 'more', 'Ask Me Later', 'bob'])
    expect(planOf(words)).toEqual({ kind: 'pick', field: 'identity', values: ['bob'] })
    const drawn = ['Not now', 'skip', 'alice']
    expect(picked({ field: 'identity', values: ['skip', 'alice'] }, drawn, 'skip', 'claude-vscode')).toEqual({
      mark: 'dismissed',
      fields: {},
    })
  })

  test('a schema outside the inventory draws nothing', () => {
    for (const s of [
      null,
      { type: 'object', properties: {} },
      { type: 'object', properties: { a: { type: 'number', title: 'n' } } },
      {
        type: 'object',
        properties: { a: { type: 'boolean', title: 'x' }, b: { type: 'boolean', title: 'y' } },
      },
      { type: 'object', properties: { a: { type: 'boolean' } } },
      { type: 'object', properties: { a: { type: 'boolean', title: 'No' } } },
      { type: 'object', properties: { a: { type: 'string', title: 'x', enum: ['skip', 'NO', ' '] } } },
      { type: 'object', properties: { a: { type: 'string', title: 'x', enum: ['id-a', 'id-a'] } } },
      {
        type: 'object',
        properties: { a: { type: 'string', title: 'x' }, b: { type: 'string', title: 'y' } },
        required: ['a', 'b'],
      },
      {
        type: 'object',
        properties: { a: { type: 'string', title: 'x' }, note: { type: 'string', title: 'y' } },
        required: ['a'],
      },
      {
        type: 'object',
        properties: {
          a: { type: 'string', title: 'x' },
          b: { type: 'string', title: 'y' },
          c: { type: 'string', title: 'z' },
        },
      },
    ]) {
      expect(planOf(s)).toBe(null)
    }
    for (const w of FIXED) {
      expect(planOf(bool(w))).toBe(null)
      expect(planOf(bool(w.toUpperCase()))).toBe(null)
    }
  })
})

describe('each resolution to its marker', () => {
  const yes = { field: 'confirm', yes: 'Yes: unpair bob' }
  test('a confirm: the Yes label, No, Other text, blank and Skip-like, on each silent surface', () => {
    expect(confirmed(yes, 'Yes: unpair bob', 'claude-vscode')).toEqual({
      mark: 'yes',
      fields: { confirm: true },
    })
    expect(confirmed(yes, 'No', 'claude-vscode')).toEqual({ mark: 'no', fields: {} })
    expect(confirmed(yes, 'Not now', 'claude-vscode')).toEqual({ mark: 'dismissed', fields: {} })
    expect(confirmed(yes, 'Not now', 'claude-desktop')).toEqual({ mark: 'dismissed', fields: {} })
    expect(confirmed(yes, 'yes', 'claude-vscode')).toEqual({ mark: 'other', fields: {} })
    expect(confirmed(yes, 'Yes: unpair bob ', 'claude-vscode')).toEqual({ mark: 'other', fields: {} })
    expect(confirmed(yes, '', 'claude-vscode')).toEqual({ mark: 'dismissed', fields: {} })
    expect(confirmed(yes, 'Yes: unpair bob', 'claude-desktop')).toEqual({
      mark: 'yes',
      fields: { confirm: true },
    })
    expect(confirmed(yes, 'No', 'claude-desktop')).toEqual({ mark: 'no', fields: {} })
    for (const v of ['yes', 'Skip', 'skipped', '', ' ', 'whatever']) {
      expect(confirmed(yes, v, 'claude-desktop')).toEqual({ mark: 'dismissed', fields: {} })
    }
  })

  test('a pick: a drawn value, Not now, More, an exact typed value, other text, Skip-like on Desktop', () => {
    const plan = { field: 'identity', values: labels(5) }
    const drawn = ['Not now', 'id-a', 'id-b', 'More']
    expect(picked(plan, drawn, 'id-a', 'claude-vscode')).toEqual({
      mark: 'yes',
      fields: { identity: 'id-a' },
    })
    expect(picked(plan, drawn, 'Not now', 'claude-vscode')).toEqual({ mark: 'dismissed', fields: {} })
    expect(picked(plan, drawn, 'More', 'claude-vscode')).toBe(null)
    expect(picked(plan, drawn, 'id-e', 'claude-vscode')).toEqual({
      mark: 'other',
      fields: { identity: 'id-e' },
    })
    expect(picked(plan, drawn, 'ID-E', 'claude-vscode')).toEqual({ mark: 'other', fields: {} })
    expect(picked(plan, drawn, 'id-e', 'claude-desktop')).toEqual({
      mark: 'other',
      fields: { identity: 'id-e' },
    })
    for (const v of ['ID-E', 'Skip', '']) {
      expect(picked(plan, drawn, v, 'claude-desktop')).toEqual({ mark: 'dismissed', fields: {} })
    }
  })

  test('a text card: Ask me later, Cancel, typed text, blank, Skip-like and the adapter words typed', () => {
    const field = { name: 'text', title: 't', required: true }
    const drawn = ['Ask me later', 'Cancel']
    expect(typed(field, drawn, 'Cancel')).toEqual({ mark: 'no' })
    expect(typed(field, drawn, 'Ask me later')).toEqual({ mark: 'dismissed' })
    for (const v of ['cancel', 'CANCEL ', 'no', 'Not Now', 'ask me later', 'more', 'invite with no address'])
      expect(typed(field, drawn, v)).toEqual({ mark: 'dismissed' })
    expect(typed(field, drawn, 'id-a')).toEqual({ value: 'id-a' })
    expect(typed(field, drawn, ' id-a ')).toEqual({ value: ' id-a ' })
    for (const v of ['', '  ', 'Skip', 'SKIPPED', '[No preference]', ' [no preference] '])
      expect(typed(field, drawn, v)).toEqual({ mark: 'dismissed' })
    expect(blank('skip it')).toBe(false)
  })

  test('"[No preference]", what a Skip on Claude Desktop answers, is blank on every surface; the bare words and a label are not', () => {
    for (const v of ['[No preference]', ' [no preference] ', '[NO PREFERENCE]']) expect(blank(v)).toBe(true)
    for (const v of ['No preference', 'id-c', '[No preference] id-c']) expect(blank(v)).toBe(false)
    const field = { name: 'text', title: 't', required: true }
    expect(typed(field, ['Ask me later', 'Cancel'], 'No preference')).toEqual({ value: 'No preference' })
    const plan = { field: 'identity', values: ['id-a', 'id-b', 'id-c'] }
    for (const surface of ['claude-vscode', 'claude-desktop']) {
      expect(picked(plan, ['Not now', 'id-a', 'id-b', 'More'], '[No preference]', surface)).toEqual({
        mark: 'dismissed',
        fields: {},
      })
      expect(picked(plan, ['Not now', 'id-a', 'id-b', 'More'], 'id-c', surface)).toEqual({
        mark: 'other',
        fields: { identity: 'id-c' },
      })
      expect(confirmed({ field: 'confirm', yes: 'Yes: x' }, ' [no preference] ', surface)).toEqual({
        mark: 'dismissed',
        fields: {},
      })
    }
  })

  test('a text card on Desktop passes typed text: Other is asked for there', async () => {
    const d = await draw({ message: 'm', requested_schema: text('t') }, ['k7-code'], 'claude-desktop')
    expect(d.content).toEqual({ text: 'k7-code', bag_card: 'yes', bag_open_ms: 400 })
  })

  test('a dismissal by a person is dismissed with the time open; a rejection under FAST_MS sends no marker', async () => {
    const slow = await draw(
      { message: 'm', requested_schema: bool('Yes: x') },
      [null],
      'claude-vscode',
      FAST_MS,
    )
    expect(slow.content).toEqual({ bag_card: 'dismissed', bag_open_ms: FAST_MS })
    const fast = await draw(
      { message: 'm', requested_schema: bool('Yes: x') },
      [null],
      'claude-vscode',
      FAST_MS - 1,
    )
    expect(fast.content).toBe(null)
    const second = await draw(
      { message: 'm', requested_schema: pick(5) },
      ['More', null],
      'claude-vscode',
      10,
    )
    expect(second.content).toBe(null)
  })

  test('a schema the card cannot draw sends no marker and asks nothing', async () => {
    const d = await draw(
      { message: 'm', requested_schema: { type: 'object', properties: { n: { type: 'number' } } } },
      ['x'],
    )
    expect(d.cards.length).toBe(0)
    expect(d.content).toBe(null)
  })
})

describe('the surface gate', () => {
  const e = { mcp_server_name: 'bag', mode: 'form', message: 'm' }
  test('acts on claude-vscode and claude-desktop only', () => {
    expect(acts(e, 'claude-vscode')).toBe(true)
    expect(acts(e, 'claude-desktop')).toBe(true)
    expect(acts({ ...e, mode: undefined }, 'claude-vscode')).toBe(true)
    for (const s of ['cli', 'sdk-ts', 'sdk-py', 'claude-vscode-x', 'CLAUDE-VSCODE', '', undefined]) {
      expect(acts(e, s)).toBe(false)
    }
  })
  test('never on another server or a url request', () => {
    expect(acts({ ...e, mcp_server_name: 'bagel' }, 'claude-vscode')).toBe(false)
    expect(acts({ ...e, mode: 'url' }, 'claude-vscode')).toBe(false)
    expect(acts({ ...e, message: undefined }, 'claude-vscode')).toBe(false)
  })
})
