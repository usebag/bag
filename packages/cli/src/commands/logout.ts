import { CliError, parse, req, str } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { publishAddress, unrevoked, withAgent } from './login.ts'

const S = { type: 'string' } as const

/**
 * logout --as <name> [--dir <home>]: ends the window of the home's agent, which drops
 * every grant, re-signs the address record with the grants' subjects added to revoked, and closes. The record is
 * published at the relays it names, one line each; when one did not take it, it is kept in
 * <home>/logout-record-<iat>.json with the line that publishes it again (1). `logout: nothing to revoke` when no grant was given. When the agent could
 * not re-sign, nothing is published and the subjects left out are the error. On a device nothing is signed: each
 * session subject is printed `unrevoked <address> until <time>`, with the step that revokes D on P's machine.
 */
export async function logout(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: [], options: { as: S, dir: S }, required: ['as'] })
  const home = homeDir(io, str(p, 'dir'))
  const [r, held] = await withAgent(io, home, req(p, 'as'), async (c, a) => [await c.logout(), a] as const)
  if (!r.ok) throw new CliError(r.code, r.detail ?? 'the agent refused the logout')
  if (r.record !== null) return publishAddress(io, io.relay({}), home, req(p, 'as'), r.record)
  if (!unrevoked(io, held, r.unrevoked)) io.out('logout: nothing to revoke')
  return 0
}
