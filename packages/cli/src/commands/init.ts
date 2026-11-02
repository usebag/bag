import {
  type AddressRecord,
  MAX_ADDRESS_TTL,
  sealingKeyFromSeed,
  serializeRecord,
  signRecord,
} from '@usebag/core'
import {
  addressCopy,
  newSeeds,
  type RecoveryState,
  readSheet,
  type Seeds,
  SHEET_LINES,
  seedKeys,
  sheetChecksum,
  sheetLines,
  writeRecoveryState,
  zeroSeeds,
} from '@usebag/edge'
import { CliError, flag, parse, relayUrl, str, UsageError } from '../args.ts'
import { addressRecords, newestOf, rotateEpoch } from '../epochs.ts'
import { cliAudit, homeCustody, homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { confirmed, needTty } from '../policy.ts'
import { target } from './keygen.ts'

// ac init and ac restore: a person's identity with its second copy, and the
// same identity back from that copy. Seeds are stored, and the address record published, only after the
// person's act: the sheet's checksum typed back, or --accept-loss's exact phrase; otherwise nothing is
// written or published. Restore runs in a fixed order and publishes nothing before its one republish.

export const LOSS_PHRASE = 'I accept losing this identity'
const S = { type: 'string' } as const

/**
 * The arguments both commands take, checked before anything is printed or read: the names `<name>` and
 * `<name>.rotation` (a key name, 64 characters at most), the custody (file or keychain: the seeds need a key's
 * custody, and an agent pointer comes after, with keygen --custody agent), --relay, the home (refusing a name a custody
 * holds, and naming a rotation key an unfinished ac init left), and the terminal.
 */
function begin(
  args: readonly string[],
  io: Io,
  what: string,
  more: Record<string, { type: 'boolean' }>,
  need: string[],
) {
  const options = { relay: S, custody: S, keychain: S, 'keychain-access': S, dir: S, ...more }
  const p = parse(args, { positionals: ['name'], options, required: need })
  const name = p.positionals[0] as string
  if (!KEY_NAME.test(`${name}.rotation`)) {
    throw new UsageError(
      `${JSON.stringify(name)} is not a key name of at most 55 of [a-z0-9._-] (${KEY_NAME.source})`,
    )
  }
  if (str(p, 'custody') === 'agent') {
    throw new UsageError(
      `${what} keeps seeds in a key file or the keychain; make an agent pointer after, with keygen --custody agent`,
    )
  }
  const where = target(p)
  const relay = str(p, 'relay') === undefined ? null : relayUrl(str(p, 'relay') as string)
  const home = homeDir(io, str(p, 'dir'))
  const held = homeCustody(io, home)
    .list()
    .filter((e) => e.name === name || e.name === `${name}.rotation`)
  if (flag(p, 'reprint')) {
    if (held.length !== 2)
      throw new CliError('ENOENT', `${name} and ${name}.rotation are not both held: nothing to reprint`)
  } else if (held.length === 1 && held[0]?.name === `${name}.rotation`) {
    throw new CliError(
      'EEXIST',
      `${name}.rotation is held, but not ${name}: an ac init or restore did not finish; move ${home}/keys/${name}.rotation.json to the Trash and run again`,
    )
  } else if (held.length > 0) {
    throw new CliError('EEXIST', `${name} is held already, by its ${held[0]?.custody} custody`)
  }
  needTty(io, what)
  return { p, name, where, home, relay }
}

const KEY_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/

/**
 * ac init <name> --relay <url> [--custody file|keychain] [--keychain <path>] [--keychain-access prompt|security]
 * [--accept-loss] [--dir <home>]: on a terminal (stdin and stdout), prints the sheet once (the two seeds, the relay,
 * the checksum) and asks for the checksum typed back; then stores the identity and its rotation key (`<name>.rotation`,
 * the record's rotation_key), writes the state, publishes the address record and epoch 1 and audits `onboard`. With --accept-loss
 * no sheet is printed: the exact phrase is asked, and the state is `none`.
 */
export async function init(args: readonly string[], io: Io): Promise<number> {
  const begun = begin(
    args,
    io,
    'ac init',
    { 'accept-loss': { type: 'boolean' }, reprint: { type: 'boolean' } },
    ['relay'],
  )
  const { p, name, where, home } = begun
  const relay = begun.relay as string
  if (flag(p, 'reprint')) return reprint(io, name, home, relay)
  const loss = flag(p, 'accept-loss')
  if (!loss && io.outIsTty !== true) {
    throw new CliError('no-tty', 'the recovery sheet prints only on a terminal, never to a pipe or a file')
  }
  const seeds = newSeeds(io.rng)
  try {
    if (loss) {
      io.err(`type exactly: ${LOSS_PHRASE}`)
      if ((await io.readLine()) !== LOSS_PHRASE) throw single('the phrase was not typed exactly')
    } else {
      for (const line of sheetLines(seeds, relay)) io.out(line)
      io.err('type the last line of the sheet (8 characters), from the printed copy')
      if (!(await typedBack(io, seeds, relay)))
        throw single('the checksum typed back does not match the sheet')
    }
    const copy = loss ? 'none' : 'sheet'
    await keep(io, {
      home,
      name,
      where,
      seeds,
      relays: [relay],
      held: null,
      revoked: [],
      event: 'onboard',
      copy: async () => copy,
    })
    io.out(loss ? 'recovery: none (accepted at ac init)' : 'recovery: printed sheet confirmed')
    return 0
  } finally {
    zeroSeeds(seeds)
  }
}

/**
 * ac restore <name> [--relay <url>] [--custody ...] [--dir <home>]: (1) the sheet's lines (SHEET_LINES) from the
 * terminal, its checksum checked before any network call; (2) the keys; (3) the newest address record at the relay
 * (--relay, else the sheet's): the same keys restore in place, none publishes anew, other keys stop `sheet stale since
 * <iat>` (a rotation, not a restore); (4) custody, then the state `sheet` if the checksum is typed once more, else
 * `single-copy`; (5) the one republish, with a later iat, and a fresh epoch; then the agent's next step, `next: ac
 * keygen <name>-agent --custody agent --principal <name>, then ac login --as <name>-agent --relay <url>...`.
 */
export async function restore(args: readonly string[], io: Io): Promise<number> {
  const { name, where, home, relay: given } = begin(args, io, 'ac restore', {}, [])
  io.err(`type the ${SHEET_LINES} lines of the sheet (the terminal does not show them)`)
  // The sheet's lines that are not blank (a pasted sheet may carry blank ones), or what there is when the input ends; each
  // read with the echo off, so no seed stays on the screen or in its scrollback.
  const lines: string[] = []
  for (
    let line = await io.readSecret();
    line !== null;
    line = lines.length < SHEET_LINES ? await io.readSecret() : null
  ) {
    if (line.trim() !== '') lines.push(line)
  }
  const sheet = readSheet(lines)
  if (sheet === 'bad-sheet')
    throw new CliError('bad-sheet', `not the ${SHEET_LINES} lines of a sheet; nothing was read or written`)
  if (sheet === 'checksum-mismatch')
    throw new CliError('bad-sheet', 'the checksum line does not match the lines typed')
  const { seeds } = sheet
  try {
    const { keys, rotation } = seedKeys(seeds, io.rng.bytes(32))
    const address = keys.signing.address
    const found = await addressRecords(io, address, [
      ...(given === null ? [] : [given]),
      relayUrl(sheet.relay),
    ])
    const reject = (detail: Record<string, string | number | boolean>) => {
      const a = audit(home, name, io)
      a.record({ event: 'restore', decision: 'reject', detail })
      return a
    }
    // Ruling 2 (a): a record that revokes the address stops the restore; nothing undoes a revocation here.
    const revoking = found.find((f) => f.record.revoked.includes(address))
    if (revoking !== undefined) {
      reject({ revoked: true })
      throw new CliError(
        'revoked',
        `${revoking.url} holds a record that revokes ${address}: a restore does not undo it`,
      )
    }
    const held = newestOf(found)
    if (
      held !== null &&
      held.rotation_key !== rotation.address // the key is the address; a null sealing key names nothing
    ) {
      reject({ stale_since: held.iat })
      throw new CliError(
        'stale-record',
        `sheet stale since ${held.iat}: the newest record of ${address} names other keys`,
      )
    }
    // Restore (decided 2026-10-28) cannot prove it holds the newest record
    // (a relay it does not reach may hold a newer one of the same keys, revoking a device), so before any republish
    // the person is told so and decides. A held record that names rotated_from is kept as it is: nothing is published.
    if (!held?.rotated_from) {
      const seen =
        held === null
          ? `no relay named holds a record of ${address}`
          : `the newest record found is of iat ${held.iat}`
      io.err(`${seen}; a newer record with a revocation may exist where restore cannot look`)
      io.err('publishing replaces it: confirming may UN-REVOKE a key you revoked before')
      await confirmed(io, 'publish the address record anyway?', 'nothing was stored or published')
    }
    const copy = async (): Promise<RecoveryState['copy']> => {
      io.err('type the last line of the sheet once more, to keep it as the second copy')
      return (await typedBack(io, seeds, sheet.relay)) ? 'sheet' : 'single-copy'
    }
    // Every revocation any source carries is kept (ruling 3), the copy in this home too, and every relay the records named.
    const known = [...found.map((f) => f.record), ...[addressCopy(home, name, address) ?? []].flat()]
    const revoked = [...new Set(known.flatMap((r) => r.revoked))]
    const relays = held?.relays ?? [given ?? relayUrl(sheet.relay)]
    const kept = await keep(io, { home, name, where, seeds, relays, held, revoked, event: 'restore', copy })
    io.out(`restored ${name}${held === null ? ' (no record was held: published anew)' : ''}`)
    io.out(`recovery: ${kept === 'sheet' ? 'printed sheet confirmed' : 'single-copy'}`)
    // A restore makes a file or keychain identity, which ac login refuses (login.ts, agentAddress): the agent holds
    // an agent identity, a pointer made first.
    const login = `ac login --as ${name}-agent ${relays.map((r) => `--relay ${r}`).join(' ')}`
    io.out(`next: ac keygen ${name}-agent --custody agent --principal ${name}, then ${login}`)
    return 0
  } finally {
    zeroSeeds(seeds)
  }
}

/**
 * ac init <name> --reprint --relay <url>: the sheet of a held identity printed again from its custody (and its
 * `<name>.rotation`), on a terminal; the checksum typed back confirms it, which clears `stale_since` (a reprinted
 * sheet confirmed is a new second copy). Nothing is published; a mismatch leaves the state as it was.
 */
async function reprint(io: Io, name: string, home: string, relay: string): Promise<number> {
  if (io.outIsTty !== true)
    throw new CliError('no-tty', 'the recovery sheet prints only on a terminal, never to a pipe or a file')
  const c = homeCustody(io, home)
  const [self, rot] = [c.entry(name).address, c.entry(`${name}.rotation`).address]
  const seeds = {
    sign: c.holder(name).signer(self).exportSeed(),
    rotation: c.holder(`${name}.rotation`).signer(rot).exportSeed(),
  }
  try {
    for (const line of sheetLines(seeds, relay)) io.out(line)
    io.err('type the last line of the sheet (8 characters), from the printed copy')
    if (!(await typedBack(io, seeds, relay)))
      throw new CliError('single-copy', 'the checksum typed back does not match; the state is unchanged')
    writeRecoveryState(home, self, { v: 1, copy: 'sheet', confirmed_at: io.clock.now(), stale_since: null })
    audit(home, name, io).record({
      event: 'onboard',
      decision: 'accept',
      detail: { copy: 'sheet', reprint: true },
    })
    io.out('recovery: printed sheet confirmed (reprinted)')
    return 0
  } finally {
    zeroSeeds(seeds)
  }
}

/** single-copy: nothing was stored and nothing published. */
const single = (why: string): CliError =>
  new CliError('single-copy', `${why}; nothing was stored or published`)

const typedBack = async (io: Io, seeds: Seeds, relay: string): Promise<boolean> =>
  (await io.readLine())?.trim().toLowerCase() === sheetChecksum(seeds, relay)

const audit = cliAudit

interface Keep {
  readonly home: string
  readonly name: string
  readonly where: ReturnType<typeof target>
  readonly seeds: Seeds
  readonly relays: readonly string[]
  readonly held: AddressRecord | null
  readonly revoked: readonly string[]
  readonly event: 'onboard' | 'restore'
  readonly copy: () => Promise<RecoveryState['copy']>
}

/**
 * Stores the identity and its rotation key, writes the state, audits the act, and publishes the address record at each
 * relay with every revocation kept and no sealing key, then the identity's first epoch here: a key record over a
 * fresh sealing key (rotateEpoch: a restore recovers the identity, not past mail). A held
 * record that names `rotated_from` is left as it is: signing it again would drop the countersignature
 * only the previous key can give, so only the key record is published for it, and an epoch is refused (bad-rotation)
 * while it still names a sealing key.
 */
async function keep(io: Io, k: Keep): Promise<RecoveryState['copy']> {
  const custody = homeCustody(io, k.home)
  const { keys, rotation } = seedKeys(k.seeds, io.rng.bytes(32)) // the key file's sealing key: no record names it
  // The rotation identity only signs a rotation (SPEC section 7.3); its sealing key is never used, so a fresh one.
  custody.create(
    `${k.name}.rotation`,
    { signing: rotation, sealing: sealingKeyFromSeed(io.rng.bytes(32)) },
    k.where,
  )
  custody.create(k.name, keys, k.where)
  const copy = await k.copy()
  const now = io.clock.now()
  const address = keys.signing.address
  writeRecoveryState(k.home, address, {
    v: 1,
    copy,
    confirmed_at: copy === 'sheet' ? now : null,
    stale_since: null,
  })
  audit(k.home, k.name, io).record({ event: k.event, decision: 'accept', detail: { copy } })
  let record: AddressRecord
  if (k.held?.rotated_from) {
    io.out(
      `kept address ${address} as held: it names rotated_from ${k.held.rotated_from}, which only that key signs again`,
    )
    record = k.held
  } else {
    record = signRecord(keys.signing, {
      kind: 'address',
      key: address,
      sealing_key: null,
      relays: [...k.relays],
      rotation_key: rotation.address,
      revoked: [...k.revoked],
      ttl: MAX_ADDRESS_TTL,
      iat: Math.max(now, (k.held?.iat ?? 0) + 1),
      rotated_from: null,
    })
    for (const url of k.relays) {
      try {
        await io.relay({}).publish(url, serializeRecord(record))
      } catch (e) {
        const step = `ac record address ${k.name} --relay ${url} --rotation-key ${rotation.address}, then ac publish, then ac keys rotate ${k.name} --relay ${url}`
        const code = String((e as { code?: unknown }).code ?? 'publish-failed')
        throw new CliError(
          code,
          `${k.name} is stored with its state, but ${url} did not take its address record; make and publish it: ${step}`,
        )
      }
      io.out(`published address ${address} ${url}`)
    }
  }
  try {
    await rotateEpoch(io, { home: k.home, name: k.name, keys, relays: record.relays, held: record })
  } catch (e) {
    const code = String((e as { code?: unknown }).code ?? 'error')
    throw new CliError(code, `${k.name} is stored with its state, but ${(e as Error).message}`)
  }
  return copy
}
