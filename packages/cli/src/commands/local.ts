import { resolve } from 'node:path'
import { type LocalWord, setLocalDelivery } from '@usebag/home'
import { parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2), the CLI's part. `bag local-delivery` writes the home
// word, <home>/run/local.json {"version": 2, "local_delivery", "hidden": [label]}: default on with no file; off and hide
// at once, on and show on a terminal after one y. The pairs themselves are the person's dialog in a host (pair_invite
// for an own identity), kept by the bag service in run/local-peers.json; unpair and identity remove drop an identity's
// pairs. The word file, the pairs table and the held mail are read and written by packages/home (its local.ts), which
// also holds the act itself (setLocalDelivery): the command line parses it and asks on its terminal.

export {
  dropLocalPairs,
  failHeldToSender,
  type HeldMail,
  heldMailOf,
  LOCAL_DELIVERY_DEFAULT,
  localDeliveryOn,
  needPairsTable,
  pairedLocally,
  pairs,
  pairsRefused,
  readWord,
  senderBusy,
  spooledCount,
  visibleLine,
} from '@usebag/home'

export const LOCAL_DELIVERY_USAGE = 'local-delivery on|off|hide <name>|show <name> [--dir <home>]'

/**
 * local-delivery on|off|hide <name>|show <name> [--dir <home>]: writes only run/local.json, version 2, keeping the
 * other half. off (the brake) and hide only reduce reach: no question. on and show add reach: a terminal and one y.
 */
export async function localDelivery(args: readonly string[], io: Io): Promise<number> {
  const named = args[0] === 'hide' || args[0] === 'show'
  const p = parse(args, {
    positionals: named ? ['word', 'name'] : ['word'],
    options: { dir: { type: 'string' } },
  })
  const word = p.positionals[0] as string
  const name = p.positionals[1]
  if (!['on', 'off', 'hide', 'show'].includes(word)) throw new UsageError(LOCAL_DELIVERY_USAGE)
  const home = resolve(homeDir(io, str(p, 'dir')))
  // on and show ask on a terminal (no-tty otherwise), after the name check: an unknown name is ENOENT first.
  const ask = (question: string): Promise<boolean> => {
    needTty(io, 'local-delivery')
    return io.confirm(question)
  }
  await viaHome(() => setLocalDelivery({ ...homeIo(io), ask }, home, word as LocalWord, name))
  return 0
}
