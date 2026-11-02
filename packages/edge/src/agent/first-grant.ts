import { isAcError } from '@usebag/core'
import type { Clock } from '../ports.ts'
import type { GrantReply } from './agent.ts'
import type { AgentClient } from './client.ts'
import { WINDOW_MAX } from './model.ts'

// A session's first grant, asked of the home's agent: the exp as a flag spells it, and the ask that falls back
// to a shorter life when the login window ends sooner than 8 hours. Shared by the MCP server's --session start.

/** A grant's exp as a flag spells it: unix seconds, or +seconds from now (at most 16 digits). */
export const EXP_TEXT = /^\+?[1-9][0-9]{0,15}$/

/** The unix second an EXP_TEXT stands for. */
export const expOf = (text: string, now: number): number =>
  text.startsWith('+') ? now + Number(text) : Number(text)

/** The shortest life asked for, in seconds: below it a refusal of the exp is final. */
export const MIN_LIFE = 60

/**
 * Runs `attempt(life)` from `life`; while it fails with exp-not-monotone (the exp is past the login window's end,
 * which no op reports) it tries half the life, down to MIN_LIFE. A renewal asks for now + life each time, so a grant
 * that was clamped once is clamped again as the window runs out, instead of being refused for good.
 */
export async function clampLife<T>(life: number, attempt: (life: number) => Promise<T>): Promise<T> {
  for (let l = life; ; l = Math.floor(l / 2)) {
    try {
      return await attempt(l)
    } catch (e) {
      if (!isAcError(e, 'exp-not-monotone') || l <= MIN_LIFE) throw e
    }
  }
}

/**
 * Asks for the first grant of `session` on a fresh connection from `connect` (closed after each ask). With `exp` null
 * it asks for the window's longest life (WINDOW_MAX) and, while the agent says exp-not-monotone (the login window
 * ends sooner), for half of it, down to a minute; no prompt is shown for a refused shape. Returns the agent's reply,
 * or null when no agent answers (no ac login yet, or the window ended).
 */
export async function requestGrant(
  connect: () => Pick<AgentClient, 'grant' | 'close'>,
  session: string,
  caveats: readonly string[],
  exp: string | null,
  clock: Clock,
  onCode: (code: string) => void,
): Promise<GrantReply | null> {
  for (let life = WINDOW_MAX; ; ) {
    const client = connect()
    let r: GrantReply
    try {
      r = await client.grant(
        session,
        caveats,
        exp === null ? clock.now() + life : expOf(exp, clock.now()),
        onCode,
      )
    } catch {
      return null
    } finally {
      client.close()
    }
    // A hop to another subject than the key asked for is not this session's grant (a stale file, another process).
    if (r.ok && r.hop.sub !== session) return { ok: false, code: 'bad-hop' }
    if (r.ok || r.code !== 'exp-not-monotone' || exp !== null || life <= MIN_LIFE) return r
    life = Math.floor(life / 2)
  }
}
