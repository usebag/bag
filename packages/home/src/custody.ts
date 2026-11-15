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
import { dirname, join } from 'node:path'
import {
  checkName,
  type EdgeKeys,
  FsKeyStore,
  type KeychainAccess,
  KeychainCustody,
  type SecurityRunner,
} from '@usebag/edge'
import { namedStates } from './check.ts'
import { holder, refuseWhileHeld } from './held.ts'
import { checkIdentity, homeCustody } from './keys.ts'
import { askWithRecheck, HomeError, type HomeIo } from './ports.ts'

// identity custody: one identity moved between its two key custodies, a person's act after one yes. The new copy is
// written and read back through a new custody (no cached read), and compared seed by seed with the old; only then does
// the old key file (or keychain pointer) move into a dated folder under ~/.Trash, never deleted. A run that stopped
// after writing the new copy leaves both; a run again reads both, compares them, and finishes the move. A keychain item
// that a move to a file leaves behind is named with the line that deletes it: bag deletes no item.

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
function readItem(security: SecurityRunner | undefined, home: string, name: string): EdgeKeys {
  const fresh = homeCustody(security, home).keychain
  const { address } = fresh.entry(name)
  return { signing: fresh.signer(address), sealing: fresh.opener(address) }
}

/** Where identity custody moves an identity to. */
export interface CustodyMove {
  readonly to: 'keychain' | 'file'
  /** The keychain file of a move to the keychain; the default keychain otherwise. */
  readonly keychain?: string
  readonly access?: KeychainAccess
}

/**
 * Moves the identity `name` of `home` into the custody `to`. Refuses, changing nothing: ENOENT when gone,
 * not-authorized for an agent identity, exists for one in that custody already, held while a live MCP server holds
 * it, usage with no HOME, EXDEV for a Trash on another file system. The one question names every change and comes
 * before any key is read; after the yes the old copy is read (bad-key for two copies with other keys), and it says
 * `wrote <copy>`, `verified <name> <address>`, `moved <old> -> <dest>` and `custody <name> <to> <address>`, then what
 * is left to the person (the Trash's key file, or the item's delete line). A copy that does not read back the same
 * keys is taken back (bad-key, or the read's own refusal), nothing moved.
 */
export async function custodyMove(io: HomeIo, home: string, name: string, move: CustodyMove): Promise<void> {
  const { to, keychain, access } = move
  checkName('fs-keys', name)
  const keyFile = join(home, 'keys', `${name}.json`)
  const pointer = join(home, 'keychain', `${name}.json`)
  const agentFile = join(home, 'agent', `${name}.json`)
  const both = existsSync(keyFile) && existsSync(pointer)
  if (!both) checkIdentity(io.security, home, name) // both: a run that stopped between the write and the move
  if (existsSync(agentFile))
    throw new HomeError('not-authorized', `${name} is an agent identity: it holds no key to move`)
  const now = homeCustody(io.security, home)
  if (!both && now.custodyOf(name) === to)
    throw new HomeError('exists', `${name} is in ${to} custody already`)
  refuseWhileHeld(home, name, 'identity custody')
  if (!io.env.HOME) throw new HomeError('usage', 'no HOME: the old copy moves into HOME/.Trash')
  const stamp = new Date(io.clock.now() * 1000)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
  const trash = join(io.env.HOME, '.Trash', `bag-custody-${name}-${stamp}`)
  let near = trash
  while (!existsSync(near)) near = dirname(near)
  if (statSync(near).dev !== statSync(home).dev)
    throw new HomeError(
      'EXDEV',
      `${trash} is on another file system than ${home}: the old copy moves, never copies`,
    )
  const old = to === 'keychain' ? keyFile : pointer
  const made = to === 'keychain' ? pointer : keyFile
  // The question comes first and reads no key: a keychain item's address is its pointer's (public, no dialog); a key
  // file's address is read with its key, after the yes. Only then is the old copy read (a keychain read raises its
  // dialog here), written, read back and compared, and every seed it exports zeroed (same).
  const named = to === 'file' ? ` (${now.keychain.entry(name).address})` : ''
  const kc = keychain === undefined ? 'the default keychain' : keychain
  const where = to === 'keychain' ? `the item bag:${name} of ${kc} (access ${access ?? 'prompt'})` : keyFile
  const question = [
    `move ${name}${named} into ${where}:`,
    both
      ? `  ${made} is written already (an earlier run): it is read back and compared with the old one before anything moves`
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
  const check = () => ({
    ...namedStates(home, io.env.HOME, [keyFile, pointer, agentFile, trash]),
    holder: holder(home, name),
  })
  if (!(await askWithRecheck(io, question, check))) throw new HomeError('declined', 'nothing was changed')
  const keys = to === 'keychain' ? now.files.load(name) : readItem(io.security, home, name)
  const address = keys.signing.address
  if (both && !same(keys, to === 'keychain' ? readItem(io.security, home, name) : now.files.load(name))) {
    throw new HomeError(
      'bad-key',
      `${name} has a key file and a keychain item with different keys: nothing was changed; move the one that is not ` +
        `${address}'s to the Trash yourself`,
    )
  }

  if (!both) {
    if (to === 'keychain') {
      const into = {
        dir: join(home, 'keychain'),
        ...(keychain === undefined ? {} : { keychain }),
        ...(access === undefined ? {} : { access }),
        ...(io.security === undefined ? {} : { run: io.security }),
      }
      try {
        new KeychainCustody(into).create(name, keys)
      } catch (e) {
        if ((e as { code?: unknown }).code !== 'EEXIST') throw e
        // an item an earlier move to a file left behind (bag deletes no item): the person deletes it, then runs again
        const kcArg = keychain === undefined ? '' : ` ${keychain}`
        throw new HomeError(
          'EEXIST',
          `the keychain holds an item bag:${name} already (an earlier --to file leaves it): nothing was changed; ` +
            `delete it with security delete-generic-password -s bag:${name} -a ${address}${kcArg}, then run again`,
        )
      }
    } else new FsKeyStore(join(home, 'keys')).save(name, keys)
    io.say(`wrote ${to === 'keychain' ? `bag:${name} in ${kc}, ${pointer}` : keyFile}`)
    let back: EdgeKeys | null = null
    let refused: unknown = null
    try {
      back =
        to === 'keychain' ? readItem(io.security, home, name) : new FsKeyStore(join(home, 'keys')).load(name)
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
      throw new HomeError(code, `the new copy of ${name} did not verify (${why}): nothing moved${left}`)
    }
  }
  io.say(`verified ${name} ${address}: the ${to} copy reads back the same keys`)
  const was = lstatSync(old) // when the identity was made (keys list's created): the new copy keeps it
  utimesSync(made, was.atimeMs / 1000, was.mtimeMs / 1000)
  mkdirSync(trash, { recursive: true, mode: 0o700 })
  const dest = join(trash, `${name}.json`)
  renameSync(old, dest)
  io.say(`moved ${old} -> ${dest}`)
  io.say(`custody ${name} ${to} ${address}`)
  if (to === 'keychain') {
    io.say(
      `${dest} still holds the private key of ${name}: empty the Trash yourself to finish; each process that loads ` +
        `${name} now reads the item (under the prompt access, one dialog per process: Allow, never Always Allow)`,
    )
  } else {
    const kcFile = keychainOf(dest)
    io.say(
      `the keychain item of ${name} stays in the macOS keychain; to delete it: security delete-generic-password ` +
        `-s bag:${name} -a ${address}${kcFile === null ? '' : ` ${kcFile}`}`,
    )
  }
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
