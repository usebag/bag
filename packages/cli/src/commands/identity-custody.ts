import { timingSafeEqual } from 'node:crypto'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  utimesSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { checkName, type EdgeKeys, FsKeyStore, KeychainCustody } from '@usebag/edge'
import { CliError, parse, str, UsageError } from '../args.ts'
import { refuseWhileHeld } from '../held.ts'
import { checkIdentity, homeCustody, homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { confirmed, needTty } from '../policy.ts'
import { refuseReserved } from '../service-home.ts'

// identity custody: one identity moved between its two key custodies, a person's act after one y on a terminal. The
// new copy is written and read back through a new custody (no cached read), and compared seed by seed with the old;
// only then does the old key file (or keychain pointer) move into a dated folder under ~/.Trash, never deleted. A run
// that stopped after writing the new copy leaves both; a run again reads both, compares them, and finishes the move.
// A keychain item that --to file leaves behind is named with the line that deletes it: bag deletes no item.

const S = { type: 'string' } as const
const USAGE =
  'identity custody <name> --to keychain|file [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]'

const same = (a: EdgeKeys, b: EdgeKeys): boolean => {
  const seeds = [
    a.signing.exportSeed(),
    b.signing.exportSeed(),
    a.sealing.exportSeed(),
    b.sealing.exportSeed(),
  ]
  const [sa, sb, ea, eb] = seeds as [Uint8Array, Uint8Array, Uint8Array, Uint8Array]
  // timingSafeEqual on the copies themselves: no further copy is made, and every copy is zeroed after
  const equal = timingSafeEqual(sa, sb) && timingSafeEqual(ea, eb)
  for (const x of seeds) x.fill(0)
  return equal
}

/** The keys a keychain pointer names, read now through a new custody: one find-generic-password, one dialog. */
function readItem(io: Io, home: string, name: string): EdgeKeys {
  const fresh = homeCustody(io, home).keychain
  const { address } = fresh.entry(name)
  return { signing: fresh.signer(address), sealing: fresh.opener(address) }
}

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
  checkName('fs-keys', name)
  const keyFile = join(home, 'keys', `${name}.json`)
  const pointer = join(home, 'keychain', `${name}.json`)
  const both = existsSync(keyFile) && existsSync(pointer)
  if (!both) checkIdentity(io, home, name) // both: a run that stopped between the write and the move
  if (existsSync(join(home, 'agent', `${name}.json`)))
    throw new CliError('not-authorized', `${name} is an agent identity: it holds no key to move`)
  const now = homeCustody(io, home)
  if (!both && now.custodyOf(name) === to) throw new CliError('exists', `${name} is in ${to} custody already`)
  refuseWhileHeld(home, name, 'identity custody')
  if (!io.env.HOME) throw new UsageError('no HOME: the old copy moves into HOME/.Trash')
  const stamp = new Date(io.clock.now() * 1000)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
  const trash = join(io.env.HOME, '.Trash', `bag-custody-${name}-${stamp}`)
  let near = trash
  while (!existsSync(near)) near = dirname(near)
  if (statSync(near).dev !== statSync(home).dev)
    throw new CliError(
      'EXDEV',
      `${trash} is on another file system than ${home}: the old copy moves, never copies`,
    )
  const old = to === 'keychain' ? keyFile : pointer
  const made = to === 'keychain' ? pointer : keyFile
  const keys = to === 'keychain' ? now.files.load(name) : readItem(io, home, name)
  const address = keys.signing.address
  if (both && !same(keys, to === 'keychain' ? readItem(io, home, name) : now.files.load(name))) {
    throw new CliError(
      'bad-key',
      `${name} has a key file and a keychain item with different keys: nothing was changed; move the one that is not ` +
        `${address}'s to the Trash yourself`,
    )
  }
  const kc = keychain === undefined ? 'the default keychain' : keychain
  const where = to === 'keychain' ? `the item bag:${name} of ${kc} (access ${access ?? 'prompt'})` : keyFile
  const question = [
    `move ${name} (${address}) into ${where}:`,
    both
      ? `  ${made} is written already (an earlier run): it was read back and holds the same keys`
      : `  the new copy is written, then read back and compared with the old one before anything moves`,
    ...(to === 'keychain' && access !== 'security' && !both
      ? [
          '  reading it back raises one macOS dialog for /usr/bin/security: answer Allow; Always Allow would let any',
          '  program of yours read it through security with no dialog',
        ]
      : []),
    `  then ${old} moves into ${trash}; nothing is deleted`,
    to === 'keychain'
      ? `  that folder keeps the old key file, which holds the private key until you empty the Trash`
      : `  the keychain item bag:${name} stays in the keychain: its delete line is printed after`,
    `move ${name}?`,
  ].join('\n')
  await confirmed(io, question, 'nothing was changed')

  if (!both) {
    if (to === 'keychain') {
      const into = {
        dir: join(home, 'keychain'),
        ...(keychain === undefined ? {} : { keychain }),
        ...(access === undefined ? {} : { access: access as 'prompt' | 'security' }),
        ...(io.security === undefined ? {} : { run: io.security }),
      }
      try {
        new KeychainCustody(into).create(name, keys)
      } catch (e) {
        if ((e as { code?: unknown }).code !== 'EEXIST') throw e
        // an item an earlier --to file left behind (bag deletes no item): the person deletes it, then runs again
        const kcArg = keychain === undefined ? '' : ` ${keychain}`
        throw new CliError(
          'EEXIST',
          `the keychain holds an item bag:${name} already (an earlier --to file leaves it): nothing was changed; ` +
            `delete it with security delete-generic-password -s bag:${name} -a ${address}${kcArg}, then run again`,
        )
      }
    } else new FsKeyStore(join(home, 'keys')).save(name, keys)
    io.out(`wrote ${to === 'keychain' ? `bag:${name} in ${kc}, ${pointer}` : keyFile}`)
    let back: EdgeKeys | null = null
    let refused: unknown = null
    try {
      back = to === 'keychain' ? readItem(io, home, name) : new FsKeyStore(join(home, 'keys')).load(name)
    } catch (e) {
      refused = e
    }
    if (back === null || !same(keys, back)) {
      // Taken back: the pointer holds no seed and is unlinked; a key file this run wrote moves aside, never deleted.
      if (to === 'keychain') unlinkSync(pointer)
      else {
        mkdirSync(trash, { recursive: true, mode: 0o700 })
        renameSync(keyFile, join(trash, `${name}.unverified.json`))
      }
      const left =
        to === 'keychain'
          ? `; the item stays: security delete-generic-password -s bag:${name} -a ${address}${keychain === undefined ? '' : ` ${keychain}`}`
          : ''
      const code = refused === null ? 'bad-key' : String((refused as { code?: unknown }).code ?? 'bad-key')
      const why = refused === null ? 'it reads back other keys' : (refused as Error).message
      throw new CliError(code, `the new copy of ${name} did not verify (${why}): nothing moved${left}`)
    }
  }
  io.out(`verified ${name} ${address}: the ${to} copy reads back the same keys`)
  const was = lstatSync(old) // when the identity was made (keys list's created): the new copy keeps it
  utimesSync(made, was.atimeMs / 1000, was.mtimeMs / 1000)
  mkdirSync(trash, { recursive: true, mode: 0o700 })
  const dest = join(trash, `${name}.json`)
  renameSync(old, dest)
  io.out(`moved ${old} -> ${dest}`)
  io.out(`custody ${name} ${to} ${address}`)
  if (to === 'keychain') {
    io.out(
      `${dest} still holds the private key of ${name}: empty the Trash yourself to finish; each process that loads ` +
        `${name} now reads the item (under the prompt access, one dialog per process: Allow, never Always Allow)`,
    )
  } else {
    const kcFile = keychainOf(dest)
    io.out(
      `the keychain item of ${name} stays in the macOS keychain; to delete it: security delete-generic-password ` +
        `-s bag:${name} -a ${address}${kcFile === null ? '' : ` ${kcFile}`}`,
    )
  }
  return 0
}

/** The keychain file a moved pointer names, null for the default keychain (or a pointer that cannot be read). */
function keychainOf(file: string): string | null {
  try {
    const { keychain } = JSON.parse(readFileSync(file, 'utf8')) as { keychain?: unknown }
    return typeof keychain === 'string' ? keychain : null
  } catch {
    return null
  }
}

export { USAGE as IDENTITY_CUSTODY_USAGE }
