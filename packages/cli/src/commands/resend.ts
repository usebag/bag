import { parseEnvelope } from '@usebag/core'
import { CliError, parse, str } from '../args.ts'
import type { Io } from '../io.ts'
import { openSender, reportSent, unpaired } from './send.ts'

const [S, B] = [{ type: 'string' }, { type: 'boolean' }] as const
const OPTIONS = { as: S, relay: S, id: S, members: S, policy: S, auth: S, dir: S, 'allow-private-relays': B }

/** Past every next_at: the outbox's due list at this second is every target that has not ended. */
const NEVER = Number.MAX_SAFE_INTEGER

/**
 * resend --as <name> --relay <url> [--id <id>] [--members <file>] [--policy <file>] [--auth <chain.json>]
 * [--allow-private-relays] [--dir <home>]: one flush of the identity's outbox, the flush a started edge runs, since a
 * one-shot send makes one attempt and exits (spec/SPEC.md §4.3, §9 item 1): the exact bytes of each due target, through
 * the outbox's retry and failover, and a relay takes an id once. A target in retry keeps its next_at, a 429's
 * Retry-After among them. A failed target goes only under --id, which seals that envelope's failed targets again (the
 * edge's resend): the relay refused those bytes, so a person says when to try them again. Prints each envelope it tried
 * or left waiting as send prints one, its id and a line per target, then `waiting <to,...> tries=<n> next_at=<n>` per send
 * that has not resolved, or `nothing is waiting`; fails, after all of them are printed, with the reason of the first
 * that no relay took. One that some relay took and another did not is a warning line, as send prints it (reportSent).
 */
export async function resend(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: [], options: OPTIONS, required: ['as', 'relay'] })
  const id = str(p, 'id')
  const { opened } = openSender(io, p)
  try {
    const { edge, store } = opened
    if (id !== undefined && edge.status(id).length === 0) {
      throw new CliError('not-found', `no envelope ${id} in this identity's outbox`)
    }
    const tried = [...(id === undefined ? [] : await edge.resend(id)), ...(await edge.flush())]
    const left = store.outboxDue(NEVER).map((d) => d.target)
    const ids = new Set([...(id === undefined ? [] : [id]), ...[...tried, ...left].map((t) => t.id)])
    let first: unknown = null
    for (const envelope of ids) {
      try {
        const targets = edge.status(envelope).filter((t) => t.state !== 'retired')
        reportSent(io, edge, { id: envelope, targets }, () => {
          const kept = store.outboxGet(envelope)
          return kept === null ? null : unpaired(io, p, parseEnvelope(kept.bytes).to)
        })
      } catch (e) {
        first ??= e
      }
    }
    const waiting = edge.waiting()
    for (const w of waiting) io.out(`waiting ${w.to.join(',')} tries=${w.tries} next_at=${w.nextAt}`)
    first ??= waiting.length === 0 ? null : new CliError('resolve-failed', `${waiting[0]?.reason}`)
    if (first !== null) throw first
    if (ids.size === 0) io.out('nothing is waiting')
    return 0
  } finally {
    opened.close()
  }
}
