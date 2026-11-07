import { connect as connectWith, VERSION } from '@usebag/enterprise-client'
import { flag, type Parsed, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { deps } from './refresher.ts'

/**
 * connect [--as <name>] [--label <text>] [--verbose] [--dir <home>]: connects this machine's agent to its organisation
 * with the console's one-time code, which names and pins the instance (@usebag/enterprise-client's connect), publishes
 * its records and sends itself one envelope through the first relay: one line, `Connected as <label>; relay round trip
 * <n> ms`. The code comes from BAG_ORG_CODE, else one line of stdin ("Paste the code: " on a terminal), never from
 * argv. --verbose adds the instance, the fingerprint and each relay's records. Exit 0 connected, 1 refused or a step
 * failed (one line naming it and the relay; the session stays), 2 usage, 4 waiting on the organisation's signer.
 */
export async function connect(args: readonly string[], io: Io): Promise<number> {
  const s = { type: 'string' } as const
  let p: Parsed
  try {
    p = parse(args, { positionals: [], options: { as: s, label: s, dir: s, verbose: { type: 'boolean' } } })
  } catch (e) {
    if (args.some((a) => a.trim().startsWith('bag')))
      throw new UsageError('the code is read from stdin or BAG_ORG_CODE, never from the command line')
    throw e
  }
  const [home, name, label] = [homeDir(io, str(p, 'dir')), str(p, 'as'), str(p, 'label')]
  let text = io.env.BAG_ORG_CODE
  if (text === undefined) {
    if (io.isTty) io.prompt('Paste the code: ')
    text = (await io.readLine()) ?? ''
  }
  if (text.trim() === '')
    throw new UsageError('no code: paste the code from the console, or set BAG_ORG_CODE')
  const named = { ...(name === undefined ? {} : { name }), ...(label === undefined ? {} : { label }) }
  return connectWith(deps(io, home), { text, version: VERSION, verbose: flag(p, 'verbose'), ...named })
}
