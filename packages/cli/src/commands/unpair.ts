import { MAX_RELAYS } from '@usebag/core'
import { unpairRoot } from '@usebag/home'
import { list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'
import { isTrustRoot } from '../trust.ts'

// unpair: the person's act that ends a pairing (or a typed --accept), the inverse of peer's y. The command line parses
// it and checks the terminal; packages/home (its unpair.ts) reads trust.json and the relays, asks the y and writes.

export { failed, heldBy } from '@usebag/home'

const S = { type: 'string' } as const

/**
 * unpair <address|domain:<host>> --as <name> --relay <url>... [--dir <home>]: a terminal first (no-tty
 * before any network); then trust.json and the accept-from at each relay are read, and nothing is written
 * until the y, after which every relay is read again (a change while asking is stale-record). A newest
 * record of `*` is accept-all (it admits every root, and none can leave it); a root neither holds is
 * not-trusted. Prints `untrusted <root>` or `not trusted <root>`; then `not accepted
 * <root>`, or per relay `published accept-from <agent> <relay>`, `unchanged ... stale-record` or
 * `failed ... <code>`, exiting 1 with the first such code. A record left with no root names only its owner:
 * the core refuses empty roots, and admit's rollback publishes the same `[owner]`.
 */
export async function unpair(args: readonly string[], io: Io): Promise<number> {
  const options = { as: S, relay: { ...S, multiple: true }, dir: S }
  const p = parse(args, { positionals: ['root'], options, required: ['as', 'relay'] })
  const root = p.positionals[0] as string
  if (!isTrustRoot(root)) {
    throw new UsageError(`${JSON.stringify(root)} is not a root: an address, or domain:<host> with no port`)
  }
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  if (relays.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  needTty(io, 'unpair')
  const home = homeDir(io, str(p, 'dir'))
  const as = req(p, 'as')
  await viaHome(() => unpairRoot(homeIo(io), { home, as, root, relays }))
  return 0
}
