import type { Io } from '../io.ts'

// bag card-hook: Claude Code's Elicitation command hook beneath bag's question card (the Claude Code plugin bag,
// whose hooks module draws bag's questions where the host shows no MCP dialog: its VS Code extension and Claude
// Desktop's Code tab). The mod draws bag's question in Claude Code's own card and adds the person's pick to the hook input as `bag_card`
// ({v: 1, action: 'accept', content}); this hook, run from the plugin's hooks/hooks.json after the mod, prints the
// host's answer for it. It answers ONLY a well-formed marker for bag's own server, every value within bag's own
// maximums; anything else prints nothing and exits 0, so the request goes on as the host would take it. It never
// declines or cancels by itself, holds no consent rule (bag's cardSaid reads the marker) and writes no log line:
// stdout carries the answer alone, stderr nothing.

/** The most of the hook input read, in bytes, and the longest it is waited for, in milliseconds. */
export const CARD_IN_MAX = 65_536
export const CARD_IN_MS = 2000

/** The longest string value passed on: bag's longest text answer (packages/mcp ask.ts MAX_PASTE). */
export const CARD_TEXT_MAX = 512

/** The longest a card may have stood open, in milliseconds (a day): bag_open_ms past it is not well formed. */
export const CARD_OPEN_MAX = 86_400_000

/** The marker's values (bag_card), as bag reads them. */
export const CARD_MARKS: readonly string[] = ['yes', 'no', 'dismissed', 'other', 'idle']

/** The MCP server name of bag's entries: the only server whose card this hook answers. */
export const CARD_SERVER = 'bag'

type Json = Record<string, unknown>

const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v)

/**
 * The host's answer for a hook input, or null for none. Well formed is: an Elicitation for bag's server in form mode,
 * a requested_schema with properties, and bag_card exactly {v: 1, action: 'accept', content}, where content holds
 * bag_card (a marker), bag_open_ms (whole ms, 0 to a day) and only fields the schema names, each of the schema's type
 * (string or boolean), a string at most CARD_TEXT_MAX characters and at most the property's own maxLength, and one of
 * the property's enum where it has one.
 */
export function cardAnswer(text: string | null): Json | null {
  let input: unknown
  try {
    input = text === null ? null : JSON.parse(text)
  } catch {
    return null
  }
  if (!isObject(input) || input.hook_event_name !== 'Elicitation' || input.mcp_server_name !== CARD_SERVER)
    return null
  if (input.mode !== undefined && input.mode !== 'form') return null
  const schema = input.requested_schema
  const props = isObject(schema) ? schema.properties : undefined
  const card = input.bag_card
  if (!isObject(props) || !isObject(card)) return null
  if (Object.keys(card).sort().join() !== 'action,content,v' || card.v !== 1 || card.action !== 'accept')
    return null
  const content = card.content
  if (!isObject(content)) return null
  const mark = content.bag_card
  const open = content.bag_open_ms
  if (typeof mark !== 'string' || !CARD_MARKS.includes(mark)) return null
  if (typeof open !== 'number' || !Number.isInteger(open) || open < 0 || open > CARD_OPEN_MAX) return null
  const out: Json = {}
  for (const [k, v] of Object.entries(content)) {
    if (k === 'bag_card' || k === 'bag_open_ms') continue
    const p = Object.hasOwn(props, k) ? props[k] : undefined
    if (!isObject(p) || typeof v !== p.type || (typeof v !== 'string' && typeof v !== 'boolean')) return null
    const max = typeof p.maxLength === 'number' ? Math.min(p.maxLength, CARD_TEXT_MAX) : CARD_TEXT_MAX
    if (typeof v === 'string' && v.length > max) return null
    if (Array.isArray(p.enum) && !p.enum.includes(v)) return null
    out[k] = v
  }
  out.bag_card = mark
  out.bag_open_ms = open
  return { hookSpecificOutput: { hookEventName: 'Elicitation', action: 'accept', content: out } }
}

/** The hook input: stdin whole up to CARD_IN_MAX bytes within CARD_IN_MS, else null (then nothing is answered). */
async function hookInput(io: Io): Promise<string | null> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<null>((done) => {
    timer = setTimeout(() => {
      io.release()
      done(null)
    }, CARD_IN_MS)
  })
  try {
    if (io.readAll !== undefined) return await Promise.race([io.readAll(CARD_IN_MAX), late])
    let text = ''
    for (
      let l = await Promise.race([io.readLine(), late]);
      l !== null;
      l = await Promise.race([io.readLine(), late])
    ) {
      text += `${l}\n`
      if (text.length > CARD_IN_MAX) return null
    }
    return text
  } finally {
    clearTimeout(timer)
  }
}

/**
 * `bag card-hook [--dir <home>]`: the home is accepted as the plugin's hook line passes it and not read (any argument
 * is ignored); prints the answer or nothing, and always exits 0.
 */
export async function cardHook(_args: readonly string[], io: Io): Promise<number> {
  try {
    const answer = cardAnswer(await hookInput(io))
    if (answer !== null) io.out(JSON.stringify(answer))
  } catch {
    // nothing printed: the request goes on as the host would take it
  }
  return 0
}
