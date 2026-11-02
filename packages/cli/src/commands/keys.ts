import { mkdirSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { DEFAULT_SKEW, DEFAULT_TTL, toHex } from '@usebag/core'
import { continueFrom, readRecoveryState } from '@usebag/edge'
import { CliError, flag, list, parse, relayUrl, str, UsageError } from '../args.ts'
import { readChain } from '../chain.ts'
import { addressRecords, healed, newestOf, rotateEpoch } from '../epochs.ts'
import { changeover, checkNoWindow, cliAudit, epochStore, homeCustody, homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'
import { instant } from '../names.ts'
import { groupStore } from './group.ts'

const USAGE =
  'keys list [--dir <home>] | keys rotate <name> --relay <url>... [--dir <home>] | keys prune <name> [--dir <home>]'
/** The exit when the epoch is published but a revocation it carries is not everywhere: written, not done. */
const INCOMPLETE = 3

/**
 * keys list [--dir <home>]: one line per identity of the home, in the three custodies, sorted by name:
 * `<name> <address> <custody> <created>`, the custody `file`, `keychain` or `agent` and the time it took the keys as an
 * ISO 8601 UTC instant to the second (2026-10-25T15:11:44Z), `-` when unknown. A key file is read for its address; a
 * keychain or agent identity's pointer names it, so no keychain is read, no dialog raised and the agent not asked.
 * An agent identity whose pointer holds a recovery setting has a field `recovery=<setting>`; an identity whose address
 * has a recovery state file (ac init, ac restore) has `copy=<copy>`, and `stale_since=<instant>`
 * while a rotation has made its copy stale. Never prints key material.
 */
export function keys(args: readonly string[], io: Io): number | Promise<number> {
  const [verb, ...rest] = args
  if (verb === 'rotate') return rotate(rest, io)
  if (verb === 'prune') return prune(rest, io)
  if (verb !== 'list') throw new UsageError(USAGE)
  const p = parse(rest, { positionals: [], options: { dir: { type: 'string' } } })
  const home = homeDir(io, str(p, 'dir'))
  for (const e of homeCustody(io, home).list()) {
    const created = e.created === null ? '-' : instant(e.created)
    const tail = e.recovery === undefined ? '' : ` recovery=${e.recovery}`
    let state: ReturnType<typeof readRecoveryState> | 'unreadable'
    try {
      state = readRecoveryState(home, e.address)
    } catch {
      state = 'unreadable' // a broken state file is shown, never a failed listing
    }
    const copy = state === null ? '' : ` copy=${state === 'unreadable' ? state : state.copy}`
    if (state === 'unreadable') state = null
    const stale = state?.stale_since == null ? '' : ` stale_since=${instant(state.stale_since)}`
    io.out(`${e.name} ${e.address} ${e.custody} ${created}${tail}${copy}${stale}`)
  }
  return 0
}

/**
 * keys rotate <name> --relay <url>... [--accept-loss] [--dir <home>]: publishes the identity's next epoch now: a
 * key record over a fresh sealing key, living a day, at the relays its newest address record names (read at the relays
 * given and every relay a record names), and that record re-signed with no sealing key when it still names one (refused
 * window-open while a login window holds the identity, whose logout re-signs it). With no record at any relay, the copy
 * in the home goes on, with its rotation key and revoked list, re-signed; with no copy, the first publish of an identity
 * that never published here: an address record with no sealing key at the relays given. An identity that did publish
 * and lost its copy is refused no-held-record, unless --accept-loss says the person knows its rotation key and revoked
 * list are gone. Prints rotateEpoch's lines, then `epoch <n> <address> until
 * <instant>` and, for epochs past their horizon, `deleted epochs <n>...`. ac login and record keep rotate on their own
 * once the newest epoch is 12 hours old; this is the step a failed publish names. It succeeds once a listed relay holds
 * the records, keep carrying the rest (spec/SPEC.md Appendix B 110); INCOMPLETE when a revoked list lags at a relay.
 */
async function rotate(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: {
      relay: { type: 'string', multiple: true },
      dir: { type: 'string' },
      'accept-loss': { type: 'boolean' },
    },
    required: ['relay'],
  })
  const name = p.positionals[0] as string
  const home = homeDir(io, str(p, 'dir'))
  const keys = loadKeys(io, home, name)
  const address = keys.signing.address
  const given = [...new Set(list(p, 'relay').map(relayUrl))]
  const found = newestOf(await addressRecords(io, address, given))
  const acceptLoss = flag(p, 'accept-loss')
  const held = found === null && acceptLoss ? null : continueFrom(found, home, name, address)
  if (held !== null && held.sealing_key !== null) await checkNoWindow(io, home, address)
  if (held !== null && held !== found) healed(io, home, held)
  const r = await rotateEpoch(io, {
    home,
    name,
    keys,
    relays: held?.relays ?? given,
    held: found,
    acceptLoss,
  })
  io.out(`epoch ${r.epoch} ${address} until ${instant(r.key.exp)}`)
  if (r.deleted.length > 0) io.out(`deleted epochs ${r.deleted.join(' ')}`)
  return r.lagging.some((l) => l.revokes) ? INCOMPLETE : 0
}

/**
 * keys prune <name> [--dir <home>]: retires the identity's long-term sealing key: its
 * field in the key file or keychain item gets a fresh random seed no record names; the signing key and a key file's
 * mtime (keys list's created time) are kept. Allowed when `changeover` is false: an epoch is held and epoch 1 is
 * deleted, at its exp + DEFAULT_TTL + DEFAULT_SKEW (605,100 s, its iat + 691,500) by the first rotation after; the
 * ruling's horizon is the cutover + 605,100, so the trigger is conservative. Refused before any write:
 * `custody-unsupported` (agent), `not-individual` (the org of an onboarded agent: a `<home>/*.chain.json` rooted at it,
 * whatever its name), `group-admin`, `no-forward-secrecy`, `before-horizon`, `window-open` (an `ac login` window would
 * keep the old seed). The key is then read back through a new custody: `prune-unverified` when it is not the new one
 * (a keychain update matches only within the pointer's keychain). Prints `pruned <address> long-term sealing key`, audits
 * one `rotate` line, publishes nothing. A running `inbox` or MCP process keeps the old key until it restarts.
 */
async function prune(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: ['name'], options: { dir: { type: 'string' } } })
  const name = p.positionals[0] as string
  const home = homeDir(io, str(p, 'dir'))
  const entry = homeCustody(io, home).entry(name)
  if (entry.custody === 'agent')
    throw new CliError('custody-unsupported', `${name} is held by the agent, which keeps its own keys`)
  const { address } = entry
  if (readdirSync(home).some((f) => f.endsWith('.chain.json') && chainRoot(join(home, f)) === address))
    throw new CliError('not-individual', `${name} is an org's key: its served record names it`)
  if (groupStore(home, name).state(address) !== null)
    throw new CliError('group-admin', `${name} is a group's admin: it opens its copies with that key`)
  const store = epochStore(home)
  if (changeover(store, address)) {
    if (store.epochs(address).length === 0)
      throw new CliError('no-forward-secrecy', `${name} holds no epoch: its long-term key opens all its mail`)
    const goes = store.epoch(address, 1).exp + DEFAULT_TTL + DEFAULT_SKEW
    throw new CliError(
      'before-horizon',
      `${name} holds epoch 1, deleted by the first rotation after ${instant(goes)}`,
    )
  }
  await checkNoWindow(io, home, address)
  const seed = io.rng.bytes(32)
  homeCustody(io, home).replaceSealing(name, seed)
  if (toHex(homeCustody(io, home).keys(name).sealing.exportSeed()) !== toHex(seed))
    throw new CliError(
      'prune-unverified',
      `the item of ${name} does not hold the new key: check the keychain`,
    )
  mkdirSync(join(home, 'state', name), { recursive: true, mode: 0o700 })
  const audit = cliAudit(home, name, io)
  const detail = { subject: `key:${address}`, action: 'prune-sealing' }
  audit.record({ event: 'rotate', decision: 'accept', from: address, detail })
  io.out(`pruned ${address} long-term sealing key`)
  return 0
}

/** The root of a chain file (onboard's `<name>.chain.json`: hops, root first), undefined for a file that does not read. */
function chainRoot(file: string): string | undefined {
  try {
    return readChain(file)[0]?.iss
  } catch {
    return undefined
  }
}
