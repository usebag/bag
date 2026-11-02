import type { PolicyModeration } from '@usebag/core'
import type { AuditValue } from '../audit.ts'

// The moderation port: the org's record names a module and an action, and the recipient's edge runs
// that module on the plaintext after unsealing, before the message is verified, so that a flagged message is held,
// dropped or only noted before any session or model sees it. Two modules ship: allow-all, which flags nothing, and
// keyword, which flags a body holding one of the record's params. Neither is a defense against prompt injection on
// its own; the port is the claim, and real classifiers plug in here.

/** What a module reads: the plaintext and who sent it, inside the recipient's edge, with the org's params. */
export interface ModerationInput {
  readonly type: string
  readonly body: unknown
  readonly from: string
  readonly root: string
  readonly caveats: readonly string[]
  readonly params: readonly string[]
}

/** A module's verdict: nothing found, or a flag naming what matched (a term's index, say), never the plaintext. */
export type ModerationVerdict = { readonly flag: false } | { readonly flag: true; readonly match: string }

export interface Moderator {
  readonly name: string
  moderate(input: ModerationInput): ModerationVerdict | Promise<ModerationVerdict>
}

/** The outcome of running the org's module: flagged or not, the rule, and the line's detail. */
export interface ModerationOutcome {
  readonly flag: boolean
  readonly rule: string
  readonly detail: Record<string, AuditValue>
}

/** Text as the matchers compare it: NFKC, lower case, white space collapsed to one space and trimmed. */
export function normalize(text: string): string {
  return text.normalize('NFKC').toLowerCase().replace(/\s+/gu, ' ').trim()
}

/** Every string of a JSON value, member names included, depth first. */
export function stringsOf(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(stringsOf)
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).flatMap(([k, v]) => [k, ...stringsOf(v)])
  }
  return []
}

/** Flags nothing: the org's choice to run the port with no filter. */
export const allowAll: Moderator = { name: 'allow-all', moderate: () => ({ flag: false }) }

/** Flags a body that holds one of the params, compared normalized: `params[i]` of the first that matches. */
export const keyword: Moderator = {
  name: 'keyword',
  moderate({ body, params }) {
    const texts = stringsOf(body).map(normalize)
    const i = params.findIndex((p) => texts.some((t) => t.includes(normalize(p))))
    return i < 0 ? { flag: false } : { flag: true, match: `params[${i}]` }
  },
}

/**
 * Runs the module the org's record names: a module the edge lacks, one that throws and one that has not answered
 * within `timeoutMs` are flags (`moderation.missing`, `.error`, `.timeout`), so a fault never lets a message through.
 */
export async function runModeration(
  config: PolicyModeration,
  module: Moderator | undefined,
  input: Omit<ModerationInput, 'params'>,
  timeoutMs: number,
): Promise<ModerationOutcome> {
  const detail = { module: config.module, action: config.action }
  if (module === undefined) return { flag: true, rule: 'moderation.missing', detail }
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => resolve('timeout'), timeoutMs)
  })
  try {
    const verdict = await Promise.race([
      Promise.resolve().then(() => module.moderate({ ...input, params: config.params })),
      late,
    ])
    if (verdict === 'timeout') return { flag: true, rule: 'moderation.timeout', detail }
    return verdict.flag
      ? { flag: true, rule: 'moderation', detail: { ...detail, match: verdict.match } }
      : { flag: false, rule: 'moderation', detail }
  } catch {
    return { flag: true, rule: 'moderation.error', detail }
  } finally {
    clearTimeout(timer)
  }
}
