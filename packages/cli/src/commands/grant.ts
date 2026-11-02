import { type AcError, HOP_TAG, verifyChain, verifyPreimage } from '@usebag/core'
import { CliError, list, parse, req, str, UsageError } from '../args.ts'
import { readChain } from '../chain.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'
import { withAgent } from './login.ts'

const [S, M] = [{ type: 'string' }, { type: 'string', multiple: true }] as const

/**
 * grant --as <name> --session <address> --caveat <caveat>... --exp <unix seconds|+seconds> [--dir <home>]: asks the
 * home's agent, logged in as <name>, for a session's first grant. The agent prints it on
 * its own terminal with a short code, which this prints on stderr too, and signs only after a `y` typed there. The
 * grant, checked to be the hop asked and signed by <name>, is printed on stdout as a chain of one hop, the file that
 * send --auth and the MCP server's --auth read. Any other answer is `declined`; renewals need no command.
 * grant --device <name|address> [--caveat ...] --exp ...: the device hop P -> D to a key the name book
 * holds (ac peer), at most 30 days, caveats optional; printed the same way, for the person to carry to D by hand.
 * --chain <file> (on D, the device hop; not with --device) is printed before the hop signed, so a session there holds
 * [P -> D, D -> S]; what is printed must verify as one chain to the subject now.
 */
export async function grant(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: [],
    options: { as: S, session: S, device: S, caveat: M, exp: S, chain: S, dir: S },
    required: ['as', 'exp'],
  })
  const [session, device, caveats] = [str(p, 'session'), str(p, 'device'), list(p, 'caveat')]
  if ((session === undefined) === (device === undefined))
    throw new UsageError('--session or --device is required')
  if (session !== undefined && caveats.length === 0) throw new UsageError('--caveat is required')
  if (device && str(p, 'chain')) throw new UsageError('--chain goes with --session')
  const text = req(p, 'exp')
  const n = Number(text)
  if (!/^\+?[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(n)) {
    throw new UsageError(`--exp is unix seconds or +seconds, not ${JSON.stringify(text)}`)
  }
  const exp = text.startsWith('+') ? io.clock.now() + n : n
  const home = homeDir(io, str(p, 'dir'))
  const sub = session ?? NameBook.load(home).resolve(device as string)
  const chain = str(p, 'chain') === undefined ? [] : readChain(req(p, 'chain'))
  return withAgent(io, home, req(p, 'as'), async (client, address) => {
    const tell = (code: string): void => io.err(`request ${code}: type y at the agent if it shows ${code}`)
    const r = await (session === undefined
      ? client.deviceGrant(sub, caveats, exp, tell)
      : client.grant(sub, caveats, exp, tell))
    if (!r.ok) throw new CliError(r.code, r.code === 'declined' ? 'no y at the agent' : 'the agent refused')
    const hop = 'device' in r ? r.device : r.hop
    const asked = [HOP_TAG, address, sub, caveats, exp]
    if (JSON.stringify([HOP_TAG, hop.iss, hop.sub, hop.caveats, hop.exp]) !== JSON.stringify(asked)) {
      throw new CliError('bad-hop', `the agent here signed another hop than the one asked (${hop.iss}'s)`)
    }
    if (!verifyPreimage(address, asked, hop.sig)) {
      throw new CliError('bad-sig', `the grant is not signed by ${address}`)
    }
    try {
      verifyChain([...chain, hop], sub, io.clock.now())
    } catch (e) {
      throw new CliError((e as AcError).code, `not one chain with --chain: ${(e as Error).message}`)
    }
    io.out(JSON.stringify([...chain, hop]))
    return 0
  })
}
