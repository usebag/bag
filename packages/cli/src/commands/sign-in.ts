import { isDomainHost } from '@usebag/core'
import * as enterprise from '@usebag/enterprise-client'
import { flag, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { deps } from './refresher.ts'

/**
 * sign-in <domain> [--instance <origin>] [--as <name>] [--label <text>] [--code] [--no-wait] [--dir <home>]: signs this
 * machine in to the bag enterprise instance of <domain> under a person's approval (@usebag/enterprise-client's signIn).
 * --instance pins the console origin as a connect code's is: no discovery, https or loopback http only, the
 * private-address guard before any call. Exit 0 signed in, 1 refused, 2 usage, 4 waiting on a person or the signer.
 */
export async function signIn(args: readonly string[], io: Io): Promise<number> {
  const [s, b] = [{ type: 'string' }, { type: 'boolean' }] as const
  const options = { instance: s, as: s, label: s, code: b, 'no-wait': b, dir: s }
  const p = parse(args, { positionals: ['domain'], options })
  const domain = p.positionals[0] as string
  const [given, name, label] = [str(p, 'instance'), str(p, 'as'), str(p, 'label')]
  if (!isDomainHost(domain)) throw new UsageError(`${JSON.stringify(domain)} is not a domain`)
  const d = deps(io, homeDir(io, str(p, 'dir')))
  const instance = given === undefined ? undefined : enterprise.pinnedInstance(given)
  if (instance !== undefined) await enterprise.guardOrigin(d, instance)
  return enterprise.signIn(d, {
    domain,
    ...(instance === undefined ? {} : { instance }),
    ...(name === undefined ? {} : { name }),
    ...(label === undefined ? {} : { label }),
    code: flag(p, 'code'),
    wait: !flag(p, 'no-wait'),
    version: enterprise.VERSION,
  })
}

/**
 * sign-out [--org <domain>] [--dir <home>]: ends that organisation's session (--org required with several) at its
 * instance, which revokes the agent's address for good, then removes its roots from trust.json, the session's files and
 * the sign-in and session keys; the identity, its mailbox and every other profile stay. Exit 0, 1, 2 usage, 3 none.
 */
export function signOut(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: [], options: { dir: { type: 'string' }, org: { type: 'string' } } })
  const [org, d] = [str(p, 'org'), deps(io, homeDir(io, str(p, 'dir')))]
  return enterprise.signOut(org === undefined ? d : { ...d, org })
}
