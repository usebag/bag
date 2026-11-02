import { parse, str, UsageError } from '../args.ts'
import type { Io } from '../io.ts'
import { confirmed, type HeldSend, heldLine, needTty } from '../policy.ts'
import { openSender, reportSent } from './send.ts'

const [S, B] = [{ type: 'string' }, { type: 'boolean' }] as const
const OPTIONS = { as: S, relay: S, members: S, policy: S, auth: S, dir: S, 'allow-private-relays': B }

/**
 * held list|release <id>|drop <id> --as <name> --relay <url> [--members <file>] [--policy <file>] [--auth <chain.json>]
 * [--allow-private-relays] [--dir <home>]: the sends the outbound gate holds. list prints `<id> <rule> <type>
 * <to,...>`, no body (a type that is not a short token is `(not shown)`, heldLine). release and drop are a person's
 * acts on a terminal (no-tty otherwise): the send's
 * line, a question, then release checks the deny list again (--members is required) and seals the send with a fresh
 * ts, printed as send prints, or drop prints `<id> dropped`. An id not pending is refused with the edge's message.
 */
export async function held(args: readonly string[], io: Io): Promise<number> {
  const [act, ...rest] = args
  if (act !== 'list' && act !== 'release' && act !== 'drop') {
    throw new UsageError('held list, held release <id> or held drop <id>')
  }
  const p = parse(rest, {
    positionals: act === 'list' ? [] : ['id'],
    options: OPTIONS,
    required: ['as', 'relay'],
  })
  if (act !== 'list') needTty(io, `held ${act}`)
  if (act === 'release' && str(p, 'members') === undefined) {
    throw new UsageError('held release checks the deny list again: pass --members <file>')
  }
  const { opened } = openSender(io, p)
  try {
    const { edge } = opened
    if (act === 'list') {
      for (const h of edge.held()) io.out(heldLine(h))
      return 0
    }
    const id = p.positionals[0] as string
    const apply = async () => (act === 'release' ? edge.release(id) : edge.drop(id))
    const entry = edge.held().find((h) => h.id === id)
    // A send that is not pending: the edge refuses it with its own message before it changes anything.
    if (entry === undefined) await apply()
    io.out(heldLine(entry as HeldSend))
    await confirmed(io, `${act} held send ${id}?`, `send ${id} stays held`)
    const done = await apply()
    if ('targets' in done) return reportSent(io, edge, done)
    io.out(`${done.id} ${done.state}`)
    return 0
  } finally {
    opened.close()
  }
}
