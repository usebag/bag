// bag's questions in Claude Code's own question card: the adapter's pure part (the card shapes, the marker, the
// surface gate, the adapter's own words). It draws and reports; it holds no consent rule. bag alone reads what the marker means (packages/mcp pairing.ts, cardSaid).
// No `$` here: the module card.ts hands in the drawing (`ask`) and the clock (`now`). Nothing here logs.

/** The MCP server name bag's entries carry (the user entry, packages/home host-user.ts, and every .mcp.json). */
export const SERVER = 'bag'

/** The surfaces that draw no MCP dialog themselves (Claude Code issue 98256): the only ones the card acts on. */
export const SILENT = ['claude-vscode', 'claude-desktop'] as const

/** The words the adapter adds, all of them; every other label on a card is bag's own. */
export const NO = 'No'
export const NOT_NOW = 'Not now'
export const CANCEL = 'Cancel'
export const LATER = 'Ask me later'
export const MORE = 'More'
export const INVITE_BARE = 'Invite with no address'
export const ACCEPT_BARE = 'Accept with no address'
export const FIXED: readonly string[] = [NO, NOT_NOW, CANCEL, LATER, MORE, INVITE_BARE, ACCEPT_BARE]

/** The chip beside the question. */
export const HEADER = 'bag'

/** A rejection of the card this soon after it was asked: nobody could have seen it, so it was never drawn. */
export const FAST_MS = 250

/** The most cards one question draws (paging included); past it the person is taken to have walked off. */
export const MAX_CARDS = 64

/** What the person did, in bag's words (cardSaid). `idle` is never sent by this build: $.ui.ask cannot tell it. */
export type Mark = 'yes' | 'no' | 'dismissed' | 'other' | 'idle'

/** The accepted content: the form's fields by their schema names, the marker and the time the card stood open. */
export type Content = Record<string, string | boolean | number>

/** One card on the screen: the person's pick (a label, or text typed under Other), or a throw when dismissed. */
export type Ask = (question: string, options: readonly string[]) => Promise<string>

/** The fields of a classic Elicitation hook's input the adapter reads. */
export type Elicitation = {
  readonly mcp_server_name?: unknown
  readonly mode?: unknown
  readonly message?: unknown
  readonly requested_schema?: unknown
}

type TextField = { readonly name: string; readonly title: string; readonly required: boolean }

/** The card for a schema: a confirm, a pick or a text card. A secret is asked on a text card in this build. */
export type Plan =
  | { readonly kind: 'confirm'; readonly field: string; readonly yes: string }
  | { readonly kind: 'pick'; readonly field: string; readonly values: readonly string[] }
  | { readonly kind: 'text'; readonly fields: readonly TextField[] }

/**
 * Whether the card acts on this request: bag's server, a form, on a surface that draws no dialog itself.
 * Anything else passes on untouched and the host does what it does today. A host that may not ask (dontAsk,
 * denyInsteadOfPrompting) refuses the card at once, which the FAST_MS line turns into no marker.
 */
export function acts(e: Elicitation, entrypoint: string | undefined): boolean {
  return (
    e.mcp_server_name === SERVER &&
    (e.mode === undefined || e.mode === 'form') &&
    typeof e.message === 'string' &&
    (SILENT as readonly (string | undefined)[]).includes(entrypoint)
  )
}

/**
 * bag's text on one line: CRLF, and each other line break or control character (C0 but tab, U+2028, U+2029), becomes
 * one space; nothing else changes.
 */
export const fold = (text: string): string =>
  [...text.replace(/\r\n/g, ' ')]
    .map((c) => {
      const n = c.charCodeAt(0)
      return (n < 32 && n !== 9) || n === 0x2028 || n === 0x2029 ? ' ' : c
    })
    .join('')

/** The card's question: "bag: " and bag's own text folded, byte for byte otherwise. */
export const question = (text: string): string => `bag: ${fold(text)}`

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Whether `v` is one of the adapter's own words, in any case. */
const fixed = (v: string): boolean => FIXED.some((w) => w.toLowerCase() === v.trim().toLowerCase())

/** A label bag gave that the card can draw: a non-empty string that is not one of the adapter's words, in any case. */
const drawable = (v: unknown): v is string => typeof v === 'string' && v.trim() !== '' && !fixed(v)

/**
 * The card for bag's requested schema, or null when it is none of the shapes below (then nothing is drawn).
 * One boolean: a confirm, its title the Yes words. One string with an enum: a pick, the proposal (`default`) first; a
 * value that reads as a Skip or as one of the adapter's words is left off the card (typing use and its name binds it).
 * One or two strings: a text, the required one first; an optional one only as bag sends it, the peer's `address`.
 */
export function planOf(schema: unknown): Plan | null {
  if (!isObject(schema) || (schema.type !== undefined && schema.type !== 'object')) return null
  const props = schema.properties
  if (!isObject(props)) return null
  const required = Array.isArray(schema.required) ? schema.required : []
  const names = Object.keys(props)
  if (names.length < 1 || names.length > 2) return null
  const first = props[names[0] as string]
  if (names.length === 1 && isObject(first) && first.type === 'boolean') {
    return drawable(first.title) ? { kind: 'confirm', field: names[0] as string, yes: first.title } : null
  }
  if (names.length === 1 && isObject(first) && first.type === 'string' && first.enum !== undefined) {
    const values = first.enum
    if (!Array.isArray(values) || !values.every((v) => typeof v === 'string')) return null
    if (new Set(values).size !== values.length) return null
    const shown = values.filter((v) => drawable(v) && !blank(v))
    if (shown.length < 1) return null
    const proposal = typeof first.default === 'string' && shown.includes(first.default) ? first.default : null
    const ordered = proposal === null ? shown : [proposal, ...shown.filter((v) => v !== proposal)]
    return { kind: 'pick', field: names[0] as string, values: ordered }
  }
  const fields: TextField[] = []
  for (const name of names) {
    const p = props[name]
    if (!isObject(p) || p.type !== 'string' || p.enum !== undefined || typeof p.title !== 'string')
      return null
    fields.push({ name, title: p.title, required: required.includes(name) })
  }
  fields.sort((a, b) => Number(b.required) - Number(a.required))
  const optional = fields.filter((f) => !f.required)
  if (fields.filter((f) => f.required).length > 1 || optional.some((f) => f.name !== 'address')) return null
  return { kind: 'text', fields }
}

/** How many cards a pick of `n` values pages over: one up to 3 values, else two values a card. */
export const pagesOf = (n: number): number => (n <= 3 ? 1 : Math.ceil(n / 2))

/** The options of a pick's page `page` (wrapping): "Not now" first, then up to two values and "More" past 3. */
export function pickOptions(values: readonly string[], page: number): string[] {
  if (values.length <= 3) return [NOT_NOW, ...values]
  const p = page % pagesOf(values.length)
  return [NOT_NOW, ...values.slice(p * 2, p * 2 + 2), MORE]
}

/**
 * The options of a text card for `field` of `fields`: "Ask me later" first (no answer), then "Cancel" (a No: it ends a
 * pairing, so an idle or default pick of the first option must not land on it), then an optional one's bare option.
 */
export function textOptions(fields: readonly TextField[], field: TextField): string[] {
  if (field.required) return [LATER, CANCEL]
  return [LATER, CANCEL, fields.length === 1 ? INVITE_BARE : ACCEPT_BARE]
}

/**
 * The cards of a confirm: "Not now" first (a dismissal), then "No", then bag's Yes words. A confirm's No is not
 * harmless (a local Allow declined for 24 h, a bind refusal remembered), so an idle or default pick of the first
 * option must land on no answer.
 */
export const confirmOptions = (yes: string): string[] => [NOT_NOW, NO, yes]

/**
 * Whether a resolution says nothing: empty, blank, or a Skip-like word a host's own skip may return ("[No preference]"
 * is the text Claude Desktop's Skip button answers a card with). Never a label and never typed text, on any surface.
 */
export const blank = (v: string): boolean =>
  v.trim() === '' || /^(skip|skipped|\[no preference\])$/i.test(v.trim())

type Outcome = { readonly mark: Mark; readonly fields: Record<string, string | boolean> }

/** A confirm's resolution. On Desktop a string that is not a drawn label is a dismissal. */
export function confirmed(plan: { field: string; yes: string }, v: string, surface: string): Outcome {
  if (v === plan.yes) return { mark: 'yes', fields: { [plan.field]: true } }
  if (v === NO) return { mark: 'no', fields: {} }
  if (v === NOT_NOW) return { mark: 'dismissed', fields: {} }
  if (blank(v) || surface !== 'claude-vscode') return { mark: 'dismissed', fields: {} }
  return { mark: 'other', fields: {} }
}

/**
 * A pick's resolution on a page whose options were `drawn`: a value, "More" (null: the next page), "Not now"
 * a dismissal, typed text the exact value only (bag accepts it only if it is one), anything else on Desktop dismissed.
 */
export function picked(
  plan: { field: string; values: readonly string[] },
  drawn: readonly string[],
  v: string,
  surface: string,
): Outcome | null {
  if (v === NOT_NOW || blank(v)) return { mark: 'dismissed', fields: {} }
  if (v === MORE && drawn.includes(MORE)) return null
  if (drawn.includes(v)) return { mark: 'yes', fields: { [plan.field]: v } }
  if (plan.values.includes(v)) return { mark: 'other', fields: { [plan.field]: v } }
  if (surface !== 'claude-vscode') return { mark: 'dismissed', fields: {} }
  return { mark: 'other', fields: {} }
}

/**
 * One text card's resolution: a value, "Ask me later" a dismissal, "Cancel" a No, the bare option none; blank,
 * Skip-like, or one of the adapter's words typed in any case is a dismissal, never the value.
 */
export function typed(
  field: TextField,
  drawn: readonly string[],
  v: string,
): { readonly mark: 'no' | 'dismissed' } | { readonly value: string | null } {
  if (v === LATER && drawn.includes(LATER)) return { mark: 'dismissed' }
  if (v === CANCEL && drawn.includes(CANCEL)) return { mark: 'no' }
  if (!field.required && drawn.includes(v)) return { value: null }
  if (blank(v) || fixed(v)) return { mark: 'dismissed' }
  return { value: v }
}

/** Thrown by `drawn` for a card that went away faster than a person: the card was never drawn. */
class NotDrawn extends Error {}

/**
 * Asks every card bag's request needs, one at a time, and returns the accepted content with its marker, or null when
 * the card could not be drawn (no plan, or a rejection under FAST_MS): then no marker is sent and the host's own
 * answer stands. Typed text is never logged or kept: it is only returned in the content.
 */
export async function runCard(
  e: Elicitation,
  surface: string,
  ask: Ask,
  now: () => number,
): Promise<Content | null> {
  const plan = planOf(e.requested_schema)
  if (plan === null || typeof e.message !== 'string') return null
  const message = e.message
  const t0 = now()
  const done = (o: Outcome): Content => ({
    ...o.fields,
    bag_card: o.mark,
    bag_open_ms: Math.max(0, Math.round(now() - t0)),
  })
  // One card: the pick, or null for a dismissal by a person (the card stood FAST_MS or more).
  const card = async (q: string, options: readonly string[]): Promise<string | null> => {
    const at = now()
    try {
      return await ask(q, options)
    } catch {
      if (now() - at < FAST_MS) throw new NotDrawn()
      return null
    }
  }
  const dismissed = (): Content => done({ mark: 'dismissed', fields: {} })
  try {
    if (plan.kind === 'confirm') {
      const v = await card(question(message), confirmOptions(plan.yes))
      return v === null ? dismissed() : done(confirmed(plan, v, surface))
    }
    if (plan.kind === 'pick') {
      for (let page = 0; page < MAX_CARDS; page++) {
        const drawn = pickOptions(plan.values, page)
        const v = await card(question(message), drawn)
        if (v === null) return dismissed()
        const o = picked(plan, drawn, v, surface)
        if (o !== null) return done(o)
      }
      return dismissed()
    }
    const fields: Record<string, string> = {}
    for (const [i, field] of plan.fields.entries()) {
      const drawn = textOptions(plan.fields, field)
      const v = await card(question(i === 0 ? message : field.title), drawn)
      if (v === null) return dismissed()
      const t = typed(field, drawn, v)
      if ('mark' in t) return done({ mark: t.mark, fields: {} })
      if (t.value !== null) fields[field.name] = t.value
    }
    return done({ mark: 'yes', fields })
  } catch (err) {
    if (err instanceof NotDrawn) return null
    throw err
  }
}

/** The request bag's command hook reads (`bag card-hook`): the hook input with the card's answer added (route d1). */
export const withCard = <E extends object>(e: E, content: Content): E & { bag_card: object } => ({
  ...e,
  bag_card: { v: 1, action: 'accept', content },
})
