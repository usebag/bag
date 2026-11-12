import { existsSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import {
  type AcceptFromRecord,
  AcError,
  type AcRecord,
  type AddressRecord,
  checkAcceptRoot,
  countersignRotation,
  isAcError,
  isAddress,
  MAX_ADDRESS_TTL,
  parseRecord,
  recordSigner,
  type SigningKey,
  serializeRecord,
  signRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import {
  acceptCopy,
  addressCopy,
  continueFrom,
  INCOMPLETE_REVOCATION,
  keepAddressCopy,
  liftMaxBytes,
  type RelayClient,
  RelayError,
  readRecoveryState,
  writeRecoveryState,
} from '@usebag/edge'
import { CliError, flag, int, list, type Parsed, parse, relayUrl, str, UsageError } from '../args.ts'
import { EPOCH_EARLY, epochDue, healed, offerKey, rotateEpoch } from '../epochs.ts'
import { checkNoWindow, homeDir, loadKeys, renewing, windowOf } from '../home.ts'
import { keyOf, readIdentities } from '../identities.ts'
import type { Io } from '../io.ts'
import { stableMains } from '../packaged.ts'
import { confirmed, needTty } from '../policy.ts'
import { crontabLine, launchdJob } from './keep-schedule.ts'
import { undate } from './login.ts'

// record address and record accept-from: a record signed by the identity's key at the clock's now, written to stdout
// or to --out. Records are public by design (spec/SPEC.md §7), so the file is written with the default mode. record
// keep re-signs the identity's records at half their ttl and republishes them.

const HOME = { dir: { type: 'string' } } as const
const OUT = { out: { type: 'string' } } as const

/** The first wait after a republish that no relay took, in seconds; it doubles up to an hour, as the outbox's does. */
export const KEEP_RETRY_S = 60
export const KEEP_RETRY_MAX_S = 3600
/** The longest wait of one timer, in milliseconds: setTimeout's limit, 2^31 - 1. */
const MAX_TIMER_MS = 2_147_483_647

/** record address <name> | record accept-from <name> | record keep --as <name>: dispatches on the kind. */
export function record(args: readonly string[], io: Io): number | Promise<number> {
  const [kind, ...rest] = args
  if (kind === 'address') return addressRecord(rest, io)
  if (kind === 'accept-from') return acceptFromRecord(rest, io)
  if (kind === 'keep') return keep(rest, io)
  throw new UsageError(
    'record address <name> ..., record accept-from <name> ... or record keep --as <name> ...',
  )
}

function write(io: Io, p: Parsed, r: AcRecord): number {
  const text = new TextDecoder().decode(serializeRecord(r))
  const out = str(p, 'out')
  if (out === undefined) io.out(text)
  else writeFileSync(out, `${text}\n`)
  return 0
}

/**
 * An address an option names: bad-address unless it is one, usage when it is the identity's own (`self`), since a
 * record names other keys as its rotation key and in its revoked list.
 */
function otherKey(option: string, value: string, self: string): string {
  if (!isAddress(value))
    throw new AcError('bad-address', `--${option} ${JSON.stringify(value)} is not an address`)
  if (value === self) throw new UsageError(`--${option} names the identity itself; it names another key`)
  return value
}

/**
 * record address <name> --relay <url>... [--sealing-key] [--ttl <seconds>] [--rotated-from <name>]
 * [--rotation-key <address>] [--revoke <address>...] [--out <file>] [--dir <home>]: the identity's address record with
 * its relays, its sealing key when --sealing-key is given (else null, as for an org root that only signs), and a ttl
 * of at most a day (default 86,400 s). With --rotated-from, the record rotates from that identity's key, which
 * countersigns it (spec/SPEC.md §7.3): rotated_from names the old key and rotation_sig is its signature over the new
 * record's preimage, so an edge that pinned the old key moves its pin. --rotation-key names a separate key that may
 * countersign this key's next rotation, and each --revoke a key whose hops the record revokes,
 * in the order given; the core refuses a duplicate (bad-record) and more than 1,024
 * (too-many-revoked). An entry must stay until its hop's exp + TTL + skew, the last second an envelope under
 * that hop passes the stale-ts check (the earlier drop at exp let a recipient who verifies after exp accept
 * revoked mail).
 */
async function addressRecord(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: {
      relay: { type: 'string', multiple: true },
      'sealing-key': { type: 'boolean' },
      ttl: { type: 'string' },
      'rotated-from': { type: 'string' },
      'rotation-key': { type: 'string' },
      revoke: { type: 'string', multiple: true },
      ...OUT,
      ...HOME,
    },
    required: ['relay'],
  })
  const home = homeDir(io, str(p, 'dir'))
  const keys = loadKeys(io, home, p.positionals[0] as string)
  const self = keys.signing.address
  await checkNoWindow(io, home, self)
  const from = str(p, 'rotated-from')
  const previous = from === undefined ? null : loadKeys(io, home, from).signing
  if (previous?.address === self) {
    throw new UsageError('--rotated-from names the identity itself; a rotation moves to another key')
  }
  const rotationKey = str(p, 'rotation-key')
  const r = signRecord(keys.signing, {
    kind: 'address',
    key: self,
    sealing_key: flag(p, 'sealing-key') ? toHex(keys.sealing.publicKey) : null,
    relays: list(p, 'relay').map(relayUrl),
    rotation_key: rotationKey === undefined ? null : otherKey('rotation-key', rotationKey, self),
    revoked: list(p, 'revoke').map((a) => otherKey('revoke', a, self)),
    ttl: int(p, 'ttl') ?? MAX_ADDRESS_TTL,
    iat: io.clock.now(),
    rotated_from: previous?.address ?? null,
  })
  undate(io, home, self, r.revoked)
  // A record signed by hand replaces the list: never silently, since an entry left out is readmitted (ruling 4).
  const copy = addressCopy(home, p.positionals[0] as string, self)
  const left = (copy?.revoked ?? []).filter((a) => !r.revoked.includes(a))
  if (left.length > 0) {
    io.err(`bag: this record leaves out revoked entries of the record kept here: ${left.join(' ')}`)
  }
  if (previous !== null) staleAtRotation(home, previous.address, self, io.clock.now())
  return write(io, p, previous === null ? r : countersignRotation(previous, r))
}

/**
 * A rotation makes the second copy of the old keys stale. With a recovery state for the old address, both the
 * old and the new address carry it with stale_since now, so ac login prints the line until a new copy is confirmed.
 */
function staleAtRotation(home: string, old: string, next: string, now: number): void {
  const state = readRecoveryState(home, old)
  if (state === null) return
  for (const a of [old, next]) writeRecoveryState(home, a, { ...state, stale_since: now })
}

/**
 * record accept-from <name> --root <address|domain:<host>|*>... --max-bytes <n> --ttl <seconds> [--out <file>]
 * [--dir <home>]: the mailbox's accept-from record: the roots it accepts, its largest envelope and its
 * retention. A `domain:<host>` root accepts the current key of the host's well-known record, which the relay resolves
 * and pins, so the record outlives the org's key rotations. Each root is checked by the core
 * first, so a bad one is named (bad-record); the record is printed, or written to --out, with the roots as given.
 */
async function acceptFromRecord(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: {
      root: { type: 'string', multiple: true },
      'max-bytes': { type: 'string' },
      ttl: { type: 'string' },
      ...OUT,
      ...HOME,
    },
    required: ['root', 'max-bytes', 'ttl'],
  })
  const name = p.positionals[0] as string
  const home = homeDir(io, str(p, 'dir'))
  const keys = loadKeys(io, home, name)
  const owner = keys.signing.address
  const roots = list(p, 'root').map(checkAcceptRoot)
  // A full replacement of the roots: dropping a held root unpairs that peer, a person's act like `unpair`, so a
  // non-terminal caller is refused before anything is written, and a person confirms the drop by name. The held set is
  // the home copy (acceptCopy), which keepAcceptCopy keeps current even when a rotation strands the relay copy; the
  // record-2026-11-11 collapse was a re-sign that rebuilt the roots from a stranded copy. onboard's run keeps every
  // held root in its --root set (acceptRoots unions the copy), so its cron run drops nothing and is never refused here.
  const dropped = (acceptCopy(home, name, owner)?.roots ?? []).filter((root) => !roots.includes(root))
  if (dropped.length > 0) {
    needTty(io, 'record accept-from that drops a root')
    await confirmed(io, `drop ${dropped.join(' ')} from the accept-from of ${name}?`, 'nothing was written')
  }
  const r = signRecord(keys.signing, {
    kind: 'accept-from',
    owner,
    roots,
    max_bytes: int(p, 'max-bytes') as number,
    ttl: int(p, 'ttl') as number,
    iat: io.clock.now(),
  })
  return write(io, p, r)
}

/** The records record keep keeps alive: the identity's address record, and its accept-from record when it has one. */
interface Kept {
  readonly address: AddressRecord
  readonly accept: AcceptFromRecord | null
}

/** One republish: the records signed, whether a relay took the address record, and the first failure. */
interface Republished {
  readonly kept: Kept
  readonly took: boolean
  readonly failure: CliError | null
}

/**
 * record keep --as <name> --relay <url>... [--every <seconds>] [--once] [--dir <home>]: keeps the identity's records
 * alive: an address record lives a day at most, and nothing else signs a self-rooted
 * identity's again. It reads the identity's newest address record, and its accept-from record when there is one, at
 * the relays named (records its own key signed, checked by the core), signs both again unchanged but for one newer iat
 * (a relay refuses a record not newer than the one it holds), and offers each to every relay named and keeps offering
 * until each holds it (spec/SPEC.md Appendix B 110), printing one line per republish: `republished <kind> <address> iat
 * <iat> <relay>`, or `failed ... <relay> <code>`, with an `incomplete revocation <address> <relay> <code>: ...` line when
 * the address record carries a revoked list. The newest epoch's key record is offered with them, to each relay that
 * does not read it back (offerKey). A republish is due at the address record's iat + every: --every, or half its ttl.
 * It reads the records again before each, so a
 * record a person published meanwhile (a new revoked entry, say) is what it keeps alive; a republish no relay took is
 * tried again after 60 s, doubling to an hour. It prints `next <unix seconds>` while it waits, and runs until SIGINT or
 * SIGTERM; --once republishes at once and fails with the first failure's code. It opens no edge store, so it takes no
 * writer lock and runs beside inbox and send. A record that names rotated_from is refused: its countersignature covers
 * its iat, and only the previous key can make a new one. While a login window of the home holds the identity, a cycle
 * is skipped with `held window-open <address>` and tried again after 60 s; --once is refused window-open. Before
 * each republish, a new epoch is published when one is due (the newest is 11 hours old, an
 * hour early so that a cron run every 11 hours never lets the day-long key record lapse, or none is held), its lines as rotateEpoch prints them, and the republish keeps the address record it leaves (one with
 * no sealing key); an epoch that fails is a `failed key <address> <code>` line, and the next cycle publishes it again
 * (it is kept unpublished, so it is due; the edge re-dates it and mints no new key); --once fails with its code.
 */
async function keep(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: [],
    options: {
      as: { type: 'string' },
      relay: { type: 'string', multiple: true },
      every: { type: 'string' },
      once: { type: 'boolean' },
      identities: { type: 'string' },
      plist: { type: 'boolean' },
      crontab: { type: 'boolean' },
      ...HOME,
    },
  })
  const file = str(p, 'identities')
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  const every = int(p, 'every')
  if (file !== undefined) {
    if (
      str(p, 'as') !== undefined ||
      relays.length > 0 ||
      str(p, 'dir') !== undefined ||
      every !== undefined
    ) {
      throw new UsageError(
        '--identities takes no --as, --relay, --dir or --every: each identity is in the file',
      )
    }
    if (!isAbsolute(file))
      throw new UsageError(`--identities takes an absolute path, not ${JSON.stringify(file)}`)
  } else {
    if (str(p, 'as') === undefined) throw new UsageError('--as is required')
    if (relays.length === 0) throw new UsageError('--relay is required')
  }
  const home = file === undefined ? resolve(homeDir(io, str(p, 'dir'))) : dirname(file)
  const name = str(p, 'as') ?? 'identities'
  if (flag(p, 'plist') || flag(p, 'crontab')) {
    // A keychain identity's job would read the keys at every run: a keychain dialog at night with no one to answer.
    // The bag service holds the keys from its one open and keeps the records alive instead.
    if (file === undefined && existsSync(join(home, 'keychain', `${name}.json`))) {
      throw new CliError(
        'custody-unsupported',
        `${name} is kept in the macOS keychain, so a keep job would ask for it at every run: the bag service keeps its records alive (bag host install service, then bag identity keep-alive on ${name})`,
      )
    }
    const own = ['--as', name, ...relays.flatMap((r) => ['--relay', r]), '--dir', home]
    const run = ['record', 'keep', ...(file === undefined ? own : ['--identities', file]), '--once']
    const log = join(home, 'keep.log')
    const { cli } = stableMains(home)
    io.out(flag(p, 'plist') ? launchdJob(`bag.keep.${name}`, run, log, cli) : crontabLine(run, log, cli))
    return 0
  }
  if (file !== undefined) {
    if (!flag(p, 'once')) throw new UsageError('--identities takes --once: a job, not a keeper that stays')
    return keepIdentities(io, file)
  }
  const interval = (r: AddressRecord): number => {
    const n = every ?? Math.max(1, Math.floor(r.ttl / 2))
    if (n >= r.ttl) {
      throw new UsageError(
        `a republish every ${n} s is not below the address record's ttl, ${r.ttl} s: it would lapse in between`,
      )
    }
    return n
  }
  if (flag(p, 'once')) {
    await keepOnce(io, home, name, relays, interval)
    return 0
  }
  const keys = loadKeys(io, home, name)
  const signer = keys.signing
  const client = io.relay({})
  let { kept } = await newestOrKept(io, client, relays, home, name, signer.address)
  let due = kept.address.iat + interval(kept.address)
  const signal = io.stopSignal()
  let misses = 0
  for (;;) {
    io.out(`next ${due}`)
    await sleepUntil(io, due, signal)
    if (signal.aborted) return 0
    if ((await windowOf(io, home, signer.address)) !== null) {
      io.out(`held window-open ${signer.address}`)
      due = io.clock.now() + KEEP_RETRY_S
      continue
    }
    if (renewing(home, name)) {
      io.out(`held session-open ${signer.address}`)
      due = io.clock.now() + KEEP_RETRY_S
      continue
    }
    kept = await newest(client, relays, signer.address, kept)
    due = kept.address.iat + interval(kept.address)
    if (io.clock.now() < due) continue
    try {
      kept = { ...kept, address: await keepEpoch(io, { home, name, keys, relays, held: kept.address }) }
    } catch (e) {
      io.out(`failed key ${signer.address} ${String((e as { code?: unknown }).code ?? 'error')}`)
    }
    const cycle = await renew(io, client, relays, home, name, signer, kept)
    if (cycle.took) {
      kept = cycle.kept
      misses = 0
      due = kept.address.iat + interval(kept.address)
    } else {
      due = io.clock.now() + Math.min(KEEP_RETRY_S * 2 ** misses, KEEP_RETRY_MAX_S)
      misses++
    }
  }
}

/** Republishes `kept`, and keeps the address record a relay took as the home's copy. */
async function renew(
  io: Io,
  client: RelayClient,
  relays: readonly string[],
  home: string,
  name: string,
  signer: SigningKey,
  kept: Kept,
): Promise<Republished> {
  const cycle = await republish(io, client, relays, signer, kept)
  if (cycle.took) keepAddressCopy(home, name, cycle.kept.address)
  const key = await offerKey(io, client, home, { signing: signer }, relays)
  if (key === null || cycle.failure !== null) return cycle
  return { ...cycle, failure: new CliError(failureCode(key), 'a relay did not take the key record') }
}

/**
 * One run for one identity: stands aside, one line and no error, for a live server that keeps its records alive; else
 * the epoch when one is due, or whatever its age on a heal, then the republish. It holds no lock, so it can never stop
 * a server opening; a server that starts in the middle of it costs a 409 at worst, and writes its own audit file.
 */
async function keepOnce(
  io: Io,
  home: string,
  name: string,
  relays: readonly string[],
  check: (r: AddressRecord) => unknown,
): Promise<void> {
  const keys = loadKeys(io, home, name)
  const signer = keys.signing
  if (renewing(home, name)) {
    io.out(`held session-open ${signer.address}`)
    return
  }
  await checkNoWindow(io, home, signer.address)
  const client = io.relay({})
  const start = await newestOrKept(io, client, relays, home, name, signer.address)
  check(start.kept.address)
  const o = { home, name, keys, relays, held: start.kept.address }
  const address = start.healed ? (await rotateEpoch(io, o)).address : await keepEpoch(io, o)
  const { failure } = await renew(io, client, relays, home, name, signer, { ...start.kept, address })
  if (failure !== null) throw failure
}

/** `keepOnce` for every identity of an identities file; one that fails stops no other, and the run ends with its code. */
async function keepIdentities(io: Io, file: string): Promise<number> {
  let first: unknown = null
  for (const e of readIdentities(file).identities) {
    try {
      await keepOnce(io, e.home, keyOf(e), e.relays.map(relayUrl), () => 0)
    } catch (x) {
      io.out(`failed ${e.label} ${String((x as { code?: unknown }).code ?? 'error')}`)
      first ??= x
    }
  }
  if (first !== null) throw first
  return 0
}

/**
 * The records keep goes on from: the newest of `own` at the relays, as `newest` reads them, unless the copy in the home
 * is newer, a relay's replay; when none holds an address record, the sweep of a lapse, the copy, so the identity comes
 * back with its rotation key and revoked list. `healed` says it did: the key record is gone too, or as good as, so an
 * epoch goes out whatever its age. Still not-found for an identity that never published here.
 */
async function newestOrKept(
  io: Io,
  client: RelayClient,
  relays: readonly string[],
  home: string,
  name: string,
  own: string,
): Promise<{ kept: Kept; healed: boolean }> {
  let found: Kept | null = null
  let missing: unknown = null
  try {
    found = await newest(client, relays, own, null)
  } catch (e) {
    if (!isAcError(e, 'not-found')) throw e
    missing = e
  }
  const address = continueFrom(found?.address ?? null, home, name, own)
  if (address === null) throw missing
  if (address === found?.address) return { kept: found, healed: false }
  healed(io, home, address)
  return {
    kept: { address, accept: found?.accept ?? (await newestAccept(client, relays, own)) },
    healed: true,
  }
}

/** An epoch when one is due (rotateEpoch), and the address record then held: the re-signed one, if it changed. */
async function keepEpoch(
  io: Io,
  o: Parameters<typeof rotateEpoch>[1] & { held: AddressRecord },
): Promise<AddressRecord> {
  // An hour early (EPOCH_EARLY): a cron's --once run that lands just short of 12 hours still rotates.
  if (!epochDue(o.home, o.keys.signing.address, io.clock.now() + EPOCH_EARLY)) return o.held
  return (await rotateEpoch(io, o)).address
}

/**
 * The newest records of `own` at the relays, or those `known` when no relay holds newer ones: not-found without an
 * address record anywhere (or the first relay's failure, when one failed), and `rotation` for one that names
 * rotated_from.
 */
export async function newest(
  client: RelayClient,
  relays: readonly string[],
  own: string,
  known: Kept | null,
): Promise<Kept> {
  let address = known?.address ?? null
  let accept = known?.accept ?? null
  let failure: unknown = null
  for (const url of relays) {
    try {
      const a = (await ownRecord(client, url, own, 'address')) as AddressRecord | null
      if (a !== null && (address === null || a.iat > address.iat)) address = a
      const f = (await ownRecord(client, url, own, 'accept-from')) as AcceptFromRecord | null
      if (f !== null && (accept === null || f.iat > accept.iat)) accept = f
    } catch (e) {
      failure ??= e
    }
  }
  if (address === null) {
    throw (
      failure ??
      new AcError(
        'not-found',
        `no address record of ${own} at ${relays.join(' ')}: publish one first (record address)`,
      )
    )
  }
  if (address.rotated_from !== null) {
    throw new CliError(
      'rotation',
      `the address record of ${own} names rotated_from ${address.rotated_from}, whose countersignature covers its iat: ` +
        'publish a new one with record address --rotated-from, or one without it once peers have moved their pins',
    )
  }
  return { address, accept }
}

/**
 * The newest accept-from record of `own` at the relays, each checked by the core (ownRecord); null when none
 * holds one. For a reader with no address record to keep (onboard, after a lapse swept it).
 */
export async function newestAccept(
  client: RelayClient,
  relays: readonly string[],
  own: string,
): Promise<AcceptFromRecord | null> {
  let accept: AcceptFromRecord | null = null
  for (const url of relays) {
    const f = (await ownRecord(client, url, own, 'accept-from')) as AcceptFromRecord | null
    if (f !== null && f.iat > (accept?.iat ?? -1)) accept = f
  }
  return accept
}

/** The record of `kind` that `own` signed, at one relay, checked by the core; null when the relay holds none. */
async function ownRecord(
  client: RelayClient,
  url: string,
  own: string,
  kind: 'address' | 'accept-from',
): Promise<AcRecord | null> {
  const bytes = await client.fetchRecord(url, own, kind)
  if (bytes === null) return null
  const parsed = parseRecord(bytes)
  // At its own iat a record is neither early nor expired, so this checks its form and its signature.
  const r = verifyRecord(parsed, parsed.iat)
  if (r.kind !== kind || recordSigner(r) !== own) {
    throw new AcError(
      'bad-record',
      `${url} answered the ${r.kind} record of ${recordSigner(r)} for the ${kind} record of ${own}`,
    )
  }
  return r
}

/** Signs both records again with one newer iat and publishes each at every relay, one line per republish. */
async function republish(
  io: Io,
  client: RelayClient,
  relays: readonly string[],
  signer: SigningKey,
  kept: Kept,
): Promise<Republished> {
  const { address: a, accept: f } = kept
  const iat = Math.max(io.clock.now(), a.iat + 1, (f?.iat ?? 0) + 1)
  const address = signRecord(signer, {
    kind: 'address',
    key: a.key,
    sealing_key: a.sealing_key,
    relays: a.relays,
    rotation_key: a.rotation_key,
    revoked: a.revoked,
    ttl: a.ttl,
    iat,
    rotated_from: null,
  })
  const accept =
    f === null
      ? null
      : signRecord(signer, {
          kind: 'accept-from',
          owner: f.owner,
          roots: f.roots,
          max_bytes: liftMaxBytes(f.max_bytes),
          ttl: f.ttl,
          iat,
        })
  let took = false
  let failure: CliError | null = null
  for (const url of relays) {
    for (const r of accept === null ? [address] : [address, accept]) {
      try {
        await client.publish(url, serializeRecord(r))
        io.out(`republished ${r.kind} ${signer.address} iat ${iat} ${url}`)
        if (r === address) took = true
      } catch (e) {
        const code = failureCode(e)
        io.out(`failed ${r.kind} ${signer.address} iat ${iat} ${url} ${code}`)
        if (r === address && r.revoked.length > 0)
          io.out(`incomplete revocation ${signer.address} ${url} ${code}: ${INCOMPLETE_REVOCATION}`)
        failure ??= new CliError(code, `${url} did not take the ${r.kind} record of iat ${iat}`)
      }
    }
  }
  return { kept: { address, accept }, took, failure }
}

/** The code of a failed publish, as cli.ts's codeOf names a relay's (this module cannot import it without a cycle). */
function failureCode(e: unknown): string {
  if (!(e instanceof RelayError)) return 'error'
  return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
}

/** Waits until the clock reads `at`, or the signal aborts, in timer steps of at most MAX_TIMER_MS. */
async function sleepUntil(io: Io, at: number, signal: AbortSignal): Promise<void> {
  while (!signal.aborted && io.clock.now() < at) {
    const ms = Math.min((at - io.clock.now()) * 1000, MAX_TIMER_MS)
    await new Promise<void>((resolve) => {
      const stop = (): void => {
        clearTimeout(timer)
        resolve()
      }
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', stop)
        resolve()
      }, ms)
      signal.addEventListener('abort', stop, { once: true })
    })
  }
}
