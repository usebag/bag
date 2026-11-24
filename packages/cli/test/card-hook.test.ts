import { afterEach, describe, expect, it, vi } from 'vitest'
import { CARD_IN_MAX, CARD_IN_MS, CARD_TEXT_MAX, cardAnswer } from '../src/commands/card-hook.ts'
import { type TestIo, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// bag card-hook: the answer for a well-formed marker, nothing for
// anything else, every exit 0, nothing on stderr, and no typed value anywhere but the one answer it prints.

const CANARY = 'zq-canary-7341'

const CONFIRM = {
  type: 'object',
  properties: { confirm: { type: 'boolean', title: 'Yes: show the full addresses here' } },
  required: ['confirm'],
}
const PASTE = {
  type: 'object',
  properties: {
    invite: { type: 'string', title: 'the code or invite string' },
    address: { type: 'string', title: "Your peer's address, if you know it" },
  },
  required: ['invite'],
}
const DIGITS = {
  type: 'object',
  properties: { text: { type: 'string', title: 'bag: type the six digits', maxLength: 16 } },
  required: ['text'],
}

/** A hook input as Claude Code builds it, with the mod's added key when `content` is given. */
function input(
  content?: Record<string, unknown>,
  over: Record<string, unknown> = {},
  schema: object = CONFIRM,
) {
  return {
    session_id: 's1',
    transcript_path: '/tmp/s1.jsonl',
    cwd: '/tmp',
    hook_event_name: 'Elicitation',
    mcp_server_name: 'bag',
    message: "Show the full addresses of this machine's\nidentities to this window?",
    mode: 'form',
    requested_schema: schema,
    ...(content === undefined ? {} : { bag_card: { v: 1, action: 'accept', content } }),
    ...over,
  }
}

/** Runs `bag card-hook` with `stdin` given whole (readAll, as a process has), or line by line with `lines`. */
async function hook(stdin: string | null, how: 'all' | 'lines' = 'all'): Promise<TestIo & { code: number }> {
  const io = testIo(new MemoryRelay())
  if (how === 'all')
    io.readAll = async (max) => (stdin === null || Buffer.byteLength(stdin) > max ? null : stdin)
  else io.lines.push(...(stdin ?? '').split('\n'))
  const { code } = await cli(io, 'card-hook')
  return Object.assign(io, { code })
}

const answer = (content: Record<string, unknown>) =>
  JSON.stringify({ hookSpecificOutput: { hookEventName: 'Elicitation', action: 'accept', content } })

afterEach(() => {
  vi.useRealTimers()
})

describe('bag card-hook: a well-formed marker is answered', () => {
  it('prints the accept with the content, the fields first, then the marker and the time open', async () => {
    const io = await hook(JSON.stringify(input({ bag_open_ms: 2100, confirm: true, bag_card: 'yes' })))
    expect(io.code).toBe(0)
    expect(io.stdout).toEqual([answer({ confirm: true, bag_card: 'yes', bag_open_ms: 2100 })])
    expect(io.stderr).toEqual([])
  })

  it('answers every marker value, a No with no field among them', async () => {
    for (const mark of ['yes', 'no', 'dismissed', 'other', 'idle']) {
      const io = await hook(JSON.stringify(input({ bag_card: mark, bag_open_ms: 900 })))
      expect(io.stdout).toEqual([answer({ bag_card: mark, bag_open_ms: 900 })])
    }
  })

  it('passes typed text where the schema asks for a string, up to bag own maximum exactly', async () => {
    const at = 'k'.repeat(CARD_TEXT_MAX)
    const io = await hook(JSON.stringify(input({ invite: at, bag_card: 'yes', bag_open_ms: 5 }, {}, PASTE)))
    expect(io.stdout).toEqual([answer({ invite: at, bag_card: 'yes', bag_open_ms: 5 })])
  })

  it('takes the plugin hook line as the stage writes it: card-hook --dir <home>, the home not read', async () => {
    const io = testIo(new MemoryRelay())
    const stdin = JSON.stringify(input({ confirm: true, bag_card: 'yes', bag_open_ms: 3 }))
    io.readAll = async () => stdin
    expect(await cli(io, 'card-hook', '--dir', '/nonexistent/bag home')).toEqual({
      code: 0,
      out: [answer({ confirm: true, bag_card: 'yes', bag_open_ms: 3 })],
      err: [],
    })
  })

  it('reads the input line by line where the io has no readAll', async () => {
    const io = await hook(JSON.stringify(input({ confirm: true, bag_card: 'yes', bag_open_ms: 7 })), 'lines')
    expect(io.stdout).toEqual([answer({ confirm: true, bag_card: 'yes', bag_open_ms: 7 })])
  })
})

describe('bag card-hook: anything else prints nothing and exits 0', () => {
  const nothing = async (stdin: string | null, how: 'all' | 'lines' = 'all') => {
    const io = await hook(stdin, how)
    expect({ code: io.code, out: io.stdout, err: io.stderr }).toEqual({ code: 0, out: [], err: [] })
  }
  const ok = { confirm: true, bag_card: 'yes', bag_open_ms: 900 }

  it('no marker: the terminal, a mod that could not draw, no mod', async () => {
    await nothing(JSON.stringify(input()))
  })

  it('a marker for another server, another event or a url request', async () => {
    for (const server of ['other', 'bagel', 'Bag', 'plugin:bag:bag']) {
      await nothing(JSON.stringify(input(ok, { mcp_server_name: server })))
    }
    await nothing(JSON.stringify(input(ok, { hook_event_name: 'ElicitationResult' })))
    await nothing(JSON.stringify(input(ok, { mode: 'url' })))
  })

  it('a marker not exactly {v: 1, action: accept, content}', async () => {
    const c = { v: 1, action: 'accept', content: ok }
    for (const card of [
      { ...c, v: 2 },
      { ...c, v: '1' },
      { ...c, action: 'decline' },
      { ...c, action: 'cancel' },
      { ...c, extra: true },
      { v: 1, action: 'accept' },
      { ...c, content: [ok] },
      'yes',
      null,
    ]) {
      await nothing(JSON.stringify({ ...input(), bag_card: card }))
    }
  })

  it('an unknown marker value, or a time open that is not whole ms within a day', async () => {
    for (const bad of [
      { bag_card: 'maybe', bag_open_ms: 900 },
      { bag_card: 'YES', bag_open_ms: 900 },
      { bag_card: true, bag_open_ms: 900 },
      { bag_card: 'yes' },
      { bag_card: 'yes', bag_open_ms: -1 },
      { bag_card: 'yes', bag_open_ms: 1.5 },
      { bag_card: 'yes', bag_open_ms: '900' },
      { bag_card: 'yes', bag_open_ms: 86_400_001 },
      { bag_open_ms: 900, confirm: true },
    ]) {
      await nothing(JSON.stringify(input(bad)))
    }
  })

  it('a value outside the property enum: nothing; a value in it is answered', async () => {
    const pick = {
      type: 'object',
      properties: { identity: { type: 'string', title: 'Identity', enum: ['alice', 'bob'] } },
      required: ['identity'],
    }
    await nothing(JSON.stringify(input({ identity: 'carol', bag_card: 'other', bag_open_ms: 5 }, {}, pick)))
    await nothing(JSON.stringify(input({ identity: 'Alice', bag_card: 'yes', bag_open_ms: 5 }, {}, pick)))
    const io = await hook(
      JSON.stringify(input({ identity: 'bob', bag_card: 'yes', bag_open_ms: 5 }, {}, pick)),
    )
    expect(JSON.parse(io.stdout.join('')).hookSpecificOutput.content).toEqual({
      identity: 'bob',
      bag_card: 'yes',
      bag_open_ms: 5,
    })
  })

  it('a field the schema does not name, of another type, or over bag own maximum', async () => {
    await nothing(JSON.stringify(input({ ...ok, other: 'x' })))
    await nothing(JSON.stringify(input({ ...ok, confirm: 'true' })))
    await nothing(JSON.stringify(input({ ...ok, confirm: 1 })))
    await nothing(
      JSON.stringify(
        input({ invite: 'k'.repeat(CARD_TEXT_MAX + 1), bag_card: 'yes', bag_open_ms: 5 }, {}, PASTE),
      ),
    )
    await nothing(JSON.stringify(input({ invite: ['k'], bag_card: 'yes', bag_open_ms: 5 }, {}, PASTE)))
    await nothing(
      JSON.stringify(input({ text: '1'.repeat(17), bag_card: 'yes', bag_open_ms: 5 }, {}, DIGITS)),
    )
    await nothing(JSON.stringify(input(ok, { requested_schema: { type: 'object' } })))
  })

  it('malformed JSON, no input, an input over CARD_IN_MAX bytes, a JSON that is not an object', async () => {
    await nothing('{"hook_event_name": "Elicitation", ')
    await nothing(null)
    await nothing('')
    await nothing('[1, 2]')
    await nothing(JSON.stringify(input(ok, { pad: 'x'.repeat(CARD_IN_MAX) })))
    await nothing(JSON.stringify(input(ok, { pad: 'x'.repeat(CARD_IN_MAX) })), 'lines')
  })

  it('a stdin that never ends: nothing after CARD_IN_MS', async () => {
    vi.useFakeTimers()
    const io = testIo(new MemoryRelay())
    io.readAll = () => new Promise(() => {})
    const ran = cli(io, 'card-hook')
    await vi.advanceTimersByTimeAsync(CARD_IN_MS)
    expect(await ran).toEqual({ code: 0, out: [], err: [] })
  })
})

describe('bag card-hook: no typed value in its log', () => {
  it('stderr stays empty and the canary is in no line but the answer it prints', async () => {
    const io = await hook(
      JSON.stringify(input({ invite: CANARY, bag_card: 'yes', bag_open_ms: 5 }, {}, PASTE)),
    )
    expect(io.stderr).toEqual([])
    expect(io.stdout.filter((l) => l.includes(CANARY))).toEqual([
      answer({ invite: CANARY, bag_card: 'yes', bag_open_ms: 5 }),
    ])
    for (const bad of [
      input({ invite: CANARY, bag_card: 'maybe', bag_open_ms: 5 }, {}, PASTE),
      input({ invite: CANARY.repeat(60), bag_card: 'yes', bag_open_ms: 5 }, {}, PASTE),
      input({ invite: CANARY, bag_card: 'yes', bag_open_ms: 5 }, { mcp_server_name: 'other' }, PASTE),
    ]) {
      const r = await hook(JSON.stringify(bad))
      expect([...r.stdout, ...r.stderr].join('\n')).not.toContain(CANARY)
    }
  })

  it('cardAnswer is the whole rule: null for null', () => {
    expect(cardAnswer(null)).toBe(null)
  })
})
