import { parse, str } from '../args.ts'
import { homeCustody, homeDir } from '../home.ts'
import type { Io } from '../io.ts'

/**
 * address <name> [--dir <home>]: prints the address of an identity's signing key, from its custody's entry: a key
 * file's own keys, or a keychain identity's pointer, so it reads no keychain and raises no dialog.
 */
export function address(args: readonly string[], io: Io): number {
  const p = parse(args, { positionals: ['name'], options: { dir: { type: 'string' } } })
  io.out(homeCustody(io, homeDir(io, str(p, 'dir'))).entry(p.positionals[0] as string).address)
  return 0
}
