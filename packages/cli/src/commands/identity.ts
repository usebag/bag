import { resolve } from 'node:path'
import { MAX_RELAYS } from '@usebag/core'
import {
  consumeRemoved,
  identityKeepAlive,
  identityRelays,
  identityRemove,
  readRemoved,
  removedRefused,
} from '@usebag/home'
import { CliError, list, parse, relayUrl, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import { localLabel } from '../identities.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'
import { connectService } from '../service.ts'
import { IDENTITY_CUSTODY_USAGE, identityCustody } from './identity-custody.ts'

// identity remove, relays and keep-alive: the command line's parse and terminal check for each, then the act itself,
// which packages/home holds (its identity.ts), printing to this terminal and asking its y there.

const S = { type: 'string' } as const
const USAGE =
  'identity remove <name> [--relay <url>...] [--to <dir>] [--project <dir>] [--dir <home>] | identity relays <name> --relay <url>... [--dir <home>] | identity keep-alive on|off|default <name> [--dir <home>]'

/**
 * identity remove <name> [--relay <url>...] [--to <dir>] [--project <dir>] [--dir <home>]: --relay required but for a
 * local-only identity (relays [] in identities.json), which takes none and tells no relay; a terminal first (no-tty
 * before any network), the identity (ENOENT when gone), then refused held (a live MCP server's mcp.lock), window-open,
 * held for a keep job's plist (with the person's bootout line), exists for a --to that is not empty, and EXDEV for one
 * on another file system. Every relay is read (one that does not answer refuses, nothing changed); one question names
 * every change; after the y the relays are read again (stale-record on a change). Prints, in order: per relay
 * `published accept-from <address> <relay>` (any relay that does not take it stops here, before anything local),
 * `untrusted <root>` or `kept trust <root>: ...`, `forgot <name> <address>`, the unpair line for each other identity
 * that paired with it, the wiring written (--project), the Codex note, `moved <from> -> <to>` per file, and last
 * `removed <name> <address>: <dir>`. An agent identity is not-authorized: it cannot sign the accept-from.
 */
export async function identity(args: readonly string[], io: Io): Promise<number> {
  const [verb, ...rest] = args
  if (verb === 'relays') return setRelays(rest, io)
  if (verb === 'keep-alive') return keepAlive(rest, io)
  if (verb === 'custody') return identityCustody(rest, io)
  if (verb !== 'remove') throw new UsageError(`${USAGE} | ${IDENTITY_CUSTODY_USAGE}`)
  const options = { relay: { ...S, multiple: true }, to: S, project: S, dir: S }
  const p = parse(rest, { positionals: ['name'], options })
  const name = p.positionals[0] as string
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  if (relays.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  const home = resolve(homeDir(io, str(p, 'dir')))
  // A local-only identity (relays []) published nothing: it leaves with no relay told, and a --relay is refused.
  const label = localLabel(home, name)
  if (label !== null && relays.length > 0)
    throw new UsageError(
      `${label} is on this machine only: no relay holds its records; run it without --relay`,
    )
  if (label === null && relays.length === 0) throw new UsageError('--relay is required')
  needTty(io, 'identity remove')
  const [to, project] = [str(p, 'to'), str(p, 'project')]
  await consumeUnserved(io, home)
  await viaHome(() =>
    identityRemove(homeIo(io), {
      home,
      name,
      relays,
      ...(to === undefined ? {} : { to }),
      ...(project === undefined ? {} : { project }),
      lent: lentHere,
      // Asked again after the y when it holds mail, so a service that started or stopped meanwhile is busy.
      lentAgain: true,
    }),
  )
  return 0
}

/**
 * Whether a bag service of this home holds `name` lent to this command (cli.ts leaseFor lends it by this name before
 * the command runs): a second lend of it answers busy, "lent to the CLI". A service that answers unknown-identity does
 * not serve it, and none answering is none: either way it never sees this remove, so this command fails the held
 * mail itself. A lend that succeeds here means no lease holds it: given back at once, and false.
 */
async function lentHere(home: string, name: string): Promise<boolean> {
  const conn = await connectService(home).catch(() => null)
  if (conn === null) return false
  try {
    await conn.call('service/lend', { label: name, verb: 'identity-remove' }, 15_000)
    await conn.call('service/return', { label: name }, 15_000).catch(() => {})
    return false
  } catch (e) {
    return e instanceof CliError && e.code === 'busy'
  } finally {
    conn.close()
  }
}

/**
 * The records of served removes a bag service never finished (run/removed.json: it stopped before the give-back), when
 * no service of the home answers: this command fails their held mail to the senders itself (consumeRemoved), each
 * line said (stdout, or `say`). With a service running, the service does it.
 */
export async function consumeUnserved(
  io: Io,
  home: string,
  say: (line: string) => void = (l) => io.out(l),
): Promise<void> {
  // A refused record is said (consumeRemoved's one line) and fails nothing.
  if (removedRefused(home) === null && readRemoved(home).length === 0) return
  const conn = await connectService(home).catch(() => null)
  if (conn !== null) return conn.close()
  for (const line of consumeRemoved(home, () => Math.floor(io.clock.now()))) say(line)
}

/**
 * identity relays <name> --relay <url>... [--dir <home>]: the relays of a bag service identity, its entry in
 * <home>/identities.json (the service's file), set to the --relay list after one y at a terminal. Beside a running
 * service the CLI borrows the identity first (service.ts), and the service reopens it with the new list. Prints
 * `relays <name> <url>...` and the record keep line that publishes its records at each of them.
 */
async function setRelays(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: { relay: { ...S, multiple: true }, dir: S },
    required: ['relay'],
  })
  const name = p.positionals[0] as string
  const next = [...new Set(list(p, 'relay').map(relayUrl))]
  if (next.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  needTty(io, 'identity relays')
  const home = resolve(homeDir(io, str(p, 'dir')))
  await consumeUnserved(io, home)
  await viaHome(() => identityRelays(homeIo(io), home, name, next))
  return 0
}

/**
 * identity keep-alive on|off|default <name> [--dir <home>]: the person's word on whether the bag service keeps the
 * identity's records alive, written by the edge's setKeepAlive into the service's table (<home>/run/keep-alive.json,
 * its lock; this command never writes the file itself): on and off hold until changed; default leaves it to the
 * service's rule. Typed at a terminal (no-tty otherwise); prints `keep-alive <name> on|off|default`.
 */
function keepAlive(args: readonly string[], io: Io): number {
  const p = parse(args, { positionals: ['word', 'name'], options: { dir: S } })
  const [word, name] = p.positionals as [string, string]
  const keep = ({ on: true, off: false, default: null } as Record<string, boolean | null>)[word]
  if (keep === undefined)
    throw new UsageError(`keep-alive takes on, off or default, not ${JSON.stringify(word)}`)
  needTty(io, 'identity keep-alive')
  const home = resolve(homeDir(io, str(p, 'dir')))
  viaHome(() => identityKeepAlive(homeIo(io), home, name, keep))
  return 0
}
