import { flag, list, type Parsed, parse, req, str, UsageError } from '../args.ts'
import type { Io } from '../io.ts'
import { NAME } from '../names.ts'
import { needTty } from '../policy.ts'
import { peer } from './peer.ts'

// pair: one guided command for the peer pairing ceremony, so a person on a host whose dialogs the model cannot answer
// (omp's no-elicitation, the VS Code extension's declined dialogs) never has to remember whether to invite or accept.
// It runs in the person's terminal, picks the side from its argument (a code or invite string means accept, none means
// invite), prompts for the peer's petname when --name is left out, prints one line of what will happen, and runs the
// same ceremony as `peer invite` / `peer accept` (packages/cli/src/commands/peer.ts): no new protocol, no new trust
// path. The MCP pair tools print the exact `bag pair` line to run when they cannot show a dialog (packages/mcp).

const S = { type: 'string' } as const

/**
 * pair --as <name> --relay <url> [--rendezvous <url>] [--name <petname>] [--for <address>] [--ttl <seconds>]
 * [--trust-domain <host>] [--allow-private-relays] [--dir <home>] [<code or invite>]: with a code or invite string it
 * accepts (shows the six check digits, which the person reads to the peer, then one y); with none it invites (prints a
 * one-use code, waits for the peer's request, and the person types the six digits the peer reads out). A terminal is
 * required (no-tty), since pairing is the person's act; --name is asked at the terminal when it is not given.
 */
/** The string-valued options whose `--flag value` form consumes the next argument when the code is split out. */
const STRING_FLAGS = new Set([
  '--as',
  '--relay',
  '--rendezvous',
  '--name',
  '--for',
  '--ttl',
  '--dir',
  '--trust-domain',
])

/**
 * Splits off the one optional positional (the code or invite string) from the flags, so pair can take it or not; the
 * arg parser wants an exact count of positionals, and accept needs one while invite needs none.
 */
function splitInvite(args: readonly string[]): { invite?: string; rest: string[] } {
  const rest: string[] = []
  let invite: string | undefined
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string
    if (a.startsWith('-')) {
      rest.push(a)
      if (STRING_FLAGS.has(a) && i + 1 < args.length) rest.push(args[++i] as string)
      continue
    }
    if (invite !== undefined) throw new UsageError('pair takes at most one code or invite string')
    invite = a
  }
  return invite === undefined ? { rest } : { invite, rest }
}

export async function pair(args: readonly string[], io: Io): Promise<number> {
  const { invite, rest } = splitInvite(args)
  const p: Parsed = parse(rest, {
    positionals: [],
    options: {
      as: S,
      relay: { type: 'string', multiple: true },
      rendezvous: S,
      name: S,
      for: S,
      ttl: S,
      dir: S,
      'trust-domain': S,
      'allow-private-relays': { type: 'boolean' },
    },
    required: ['as', 'relay'],
  })
  // A terminal first, before the petname is asked or any network: pairing is the person's act.
  needTty(io, 'pair')
  const name = str(p, 'name') ?? (await askName(io))
  if (!NAME.test(name)) throw new UsageError(`a petname is 1 to 64 of a-z, 0-9, ., - and _ (${NAME.source})`)
  const pass = (k: string): string[] => {
    const v = str(p, k)
    return v === undefined ? [] : [`--${k}`, v]
  }
  const common = [
    '--as',
    req(p, 'as'),
    ...list(p, 'relay').flatMap((r) => ['--relay', r]),
    '--name',
    name,
    ...pass('rendezvous'),
    ...pass('for'),
    ...pass('dir'),
    ...pass('trust-domain'),
    ...(flag(p, 'allow-private-relays') ? ['--allow-private-relays'] : []),
  ]
  if (invite === undefined) {
    io.out(
      'Making a one-use pairing code for a peer. Send it to them; they read you six digits, which you type here. ' +
        'Nothing is trusted until you do.',
    )
    return peer(['invite', ...common, ...pass('ttl')], io)
  }
  io.out(
    "Pairing from your peer's code. You will see six check digits: read them out to your peer, not back through " +
      'where the code reached you, then answer y.',
  )
  return peer(['accept', ...common, invite], io)
}

/** Asks the peer's petname at the terminal, for `pair` run without --name; the end of input is no name. */
async function askName(io: Io): Promise<string> {
  io.prompt("A short name for this peer (its petname in this home, e.g. 'alice'): ")
  const typed = ((await io.readLine()) ?? '').trim()
  if (typed === '') throw new UsageError('a petname is required: pass --name, or type one when asked')
  return typed
}
