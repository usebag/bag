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
 * sign-out [--dir <home>]: ends this home's session at its instance, which revokes the agent's address for good, then
 * removes the organisation's roots from trust.json, the session's files and its sign-in and session keys; the identity
 * and its mailbox stay. Exit 0, 1 refused (nothing removed), 3 not signed in.
 */
export function signOut(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: [], options: { dir: { type: 'string' } } })
  return enterprise.signOut(deps(io, homeDir(io, str(p, 'dir'))))
}
