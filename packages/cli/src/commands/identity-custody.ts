import { resolve } from 'node:path'
import { custodyMove } from '@usebag/home'
import { parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'
import { refuseReserved } from '../service-home.ts'

// identity custody: one identity moved between its two key custodies, a person's act after one y on a terminal. The
// command line parses it and checks the terminal; packages/home (its custody.ts) does the move.

const S = { type: 'string' } as const
const USAGE =
  'identity custody <name> --to keychain|file [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]'

/**
 * identity custody <name> --to keychain|file [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]:
 * a terminal first (no-tty), the identity (ENOENT when gone), not-authorized for an agent identity, exists for one in
 * that custody already, held while a live MCP server holds it, EXDEV for a Trash on another file system. One question
 * names every change; after the y: `wrote <copy>`, `verified <name> <address>`, `moved <old> -> <dest>` and
 * `custody <name> <to> <address>`, then what is left to the person (the Trash's key file, or the item's delete line).
 * A copy that does not read back the same keys is taken back (bad-key, or the read's own refusal), nothing moved.
 */
export async function identityCustody(args: readonly string[], io: Io): Promise<number> {
  const options = { to: S, keychain: S, 'keychain-access': S, dir: S }
  const p = parse(args, { positionals: ['name'], options, required: ['to'] })
  const name = p.positionals[0] as string
  refuseReserved(name)
  const to = str(p, 'to') as string
  if (to !== 'keychain' && to !== 'file')
    throw new UsageError(`--to is keychain or file, not ${JSON.stringify(to)}`)
  const keychain = str(p, 'keychain')
  const access = str(p, 'keychain-access')
  if (to === 'file' && (keychain !== undefined || access !== undefined))
    throw new UsageError('--keychain and --keychain-access go with --to keychain')
  if (access !== undefined && access !== 'prompt' && access !== 'security')
    throw new UsageError(`--keychain-access is prompt or security, not ${JSON.stringify(access)}`)
  needTty(io, 'identity custody')
  const home = resolve(homeDir(io, str(p, 'dir')))
  await viaHome(() =>
    custodyMove(homeIo(io), home, name, {
      to,
      ...(keychain === undefined ? {} : { keychain }),
      ...(access === undefined ? {} : { access: access as 'prompt' | 'security' }),
    }),
  )
  return 0
}

export { USAGE as IDENTITY_CUSTODY_USAGE }
