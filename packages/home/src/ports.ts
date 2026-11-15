import { isDeepStrictEqual } from 'node:util'
import type { Clock, RelayClient, Rng, SecurityRunner, WsSubscriberOptions } from '@usebag/edge'

/**
 * What an act on a home needs from whoever runs it: the command line passes its terminal, the MCP server its dialog
 * and its tool result. An act prints with say and warn in the order it does its work, so the lines before a failure
 * keep their place, and asks its question with ask at the point where the person's yes is needed.
 */
export interface HomeIo {
  /** One line of the act's output. */
  say(line: string): void
  /** One line of the act's warnings. */
  warn(line: string): void
  /** The person's yes or no to `question`: true only for a yes. */
  ask(question: string): Promise<boolean>
  readonly clock: Clock
  readonly rng: Rng
  readonly env: Readonly<Record<string, string | undefined>>
  /** The macOS security tool, for a key held in the keychain. */
  readonly security?: SecurityRunner
  readonly platform?: NodeJS.Platform
  relay(options: WsSubscriberOptions): RelayClient
}

/**
 * A failure of a read or an act on a home: `code` is one of the codes the command line already reports, so
 * telemetry's closed set of codes does not move, and the message is "<code>: <detail>".
 */
export class HomeError extends Error {
  readonly code: string

  constructor(code: string, detail: string) {
    super(`${code}: ${detail}`)
    this.code = code
    this.name = 'HomeError'
  }
}

/** The start of the refusal when what an act checked before its question differs after the person's yes. */
export const CHANGED_WHILE_ASKED = 'it changed while you were asked'

/** The refusal's detail, naming what changed (sorted), so the person knows what to look at before asking again. */
export function changedWhileAsked(names: readonly string[]): string {
  return `${CHANGED_WHILE_ASKED}: ${[...names].sort().join(', ')}; nothing was changed, ask again`
}

/**
 * Asks `question`, with what the act checked before it: `check` reads every precondition the act relies on (the
 * files it read, who holds the identity, which windows are bound) as plain values under short names (a path relative
 * to the home, or ~/ under the person's home), before the question and again after a yes. A no answers false. A yes
 * whose second reading differs from the first refuses with `busy`, naming what differs, before the act writes
 * anything, since a person's answer can take as long as a dialog stays open.
 */
export async function askWithRecheck(
  io: HomeIo,
  question: string,
  check: () => Readonly<Record<string, unknown>>,
): Promise<boolean> {
  const before = check()
  if (!(await io.ask(question))) return false
  const after = check()
  const changed = [...new Set([...Object.keys(before), ...Object.keys(after)])].filter(
    (k) => !isDeepStrictEqual(before[k], after[k]),
  )
  if (changed.length > 0) throw new HomeError('busy', changedWhileAsked(changed))
  return true
}
