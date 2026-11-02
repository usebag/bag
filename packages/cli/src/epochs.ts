import {
  type AcRecord,
  type AddressRecord,
  type KeyRecord,
  parseRecord,
  serializeRecord,
  signRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import {
  addressCopy,
  continueFrom,
  type EdgeKeys,
  INCOMPLETE_REVOCATION,
  KeyRecordAdmin,
  type KeyRotation,
  keepAddressCopy,
  type Lagging,
  offerBehind,
  publishedKeyRecord,
  type RelayClient,
  RelayError,
  readRecoveryState,
} from '@usebag/edge'
import { CliError } from './args.ts'
import { cliAudit, epochStore } from './home.ts'
import type { Io } from './io.ts'
import { instant } from './names.ts'

// An individual's forward secrecy in the CLI (2026-10-28): each epoch publishes a key
// record over a fresh sealing key, living a day, and an address record with no sealing key; the epoch's private key is
// kept in <home>/key-records and deleted past its horizon (the edge's KeyRecordAdmin). Epoch 1 is the first publish
// (ac init, ac restore); a new epoch follows at ac login once the newest is 12 hours old, at record keep an hour
// earlier (EPOCH_EARLY), and at ac keys rotate on demand. Groups have no epochs: their forward secrecy is the generation.

/** How old the newest epoch is when a new one is due: half a key record's day. */
export const EPOCH_DUE = 12 * 3600

/**
 * How much earlier record keep (and onboard) rotate: a `--once` run from a cron that lands a little short of 12 hours
 * would otherwise skip, and the key record (a day) lapse before the next; so the cadence is at least every 11 hours.
 */
export const EPOCH_EARLY = 3600

/**
 * Whether `address` is due an epoch at `now`: it holds none, its newest is not yet published (a publish failed or was
 * cut off: rotate publishes that key again, re-dated, and mints none), or its newest was issued EPOCH_DUE or more ago.
 */
export function epochDue(home: string, address: string, now: number): boolean {
  const store = epochStore(home)
  const newest = store.epochs(address)[0]
  if (newest === undefined) return true
  const e = store.epoch(address, newest)
  return !e.published || now - e.iat >= EPOCH_DUE
}

/**
 * The address records of `address` at every relay given and every relay a record found names, each checked by the core at its own iat (its form and signature); a relay that answers another record is
 * bad-record. A relay that gives no answer is passed over, unless none answers: then its failure stands, since "none
 * found" would read as an identity that never published.
 */
export async function addressRecords(
  io: Io,
  address: string,
  start: readonly string[],
): Promise<{ url: string; record: AddressRecord }[]> {
  const client = io.relay({})
  const asked = new Set<string>()
  const found: { url: string; record: AddressRecord }[] = []
  let answered = false
  let silent: RelayError | null = null
  for (let todo = [...start]; todo.length > 0; ) {
    const url = todo.shift() as string
    if (asked.has(url)) continue
    asked.add(url)
    let bytes: Uint8Array | null
    try {
      bytes = await client.fetchRecord(url, address, 'address')
      answered = true
    } catch (e) {
      if (!(e instanceof RelayError)) throw e
      silent ??= e
      continue
    }
    if (bytes === null) continue
    const parsed = parseRecord(bytes)
    const r = verifyRecord(parsed, parsed.iat)
    if (r.kind !== 'address' || r.key !== address) {
      throw new CliError('bad-record', `${url} answered another record for the address record of ${address}`)
    }
    found.push({ url, record: r })
    todo.push(...r.relays)
  }
  if (!answered && silent !== null) throw silent
  return found
}

/** A failed publish's code, as cli.ts's codeOf names a relay's: its code, `unreachable`, `http-<n>`, else publish-failed. */
function relayCode(e: unknown): string {
  if (e instanceof RelayError) return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
  return String((e as { code?: unknown }).code ?? 'publish-failed')
}

/** The newest of `found`, by iat; null when none was found. */
export const newestOf = (found: readonly { record: AddressRecord }[]): AddressRecord | null =>
  found.reduce<AddressRecord | null>((a, f) => (a === null || f.record.iat > a.iat ? f.record : a), null)

export interface RotateOptions {
  readonly home: string
  /** The identity's name in the home: the rotation is audited in <home>/state/<name>/cli-audit.jsonl (cliAudit). */
  readonly name: string
  readonly keys: EdgeKeys
  /** Where both records are published: the held record's relays, or the first publish's. */
  readonly relays: readonly string[]
  /**
   * The identity's newest address record at its relays, or null when none holds one: then its copy in the home carries
   * the rotation key and the revoked list (continueFrom), and only an identity that never published starts empty.
   */
  readonly held: AddressRecord | null
  /** Starts empty though the copy is lost, refused otherwise: the person's explicit act (keys rotate --accept-loss). */
  readonly acceptLoss?: boolean
  /** The step a refused publish names, for a relay `url`: `ac keys rotate <name> --relay <url>` unless given. */
  readonly step?: (url: string) => string
}

/**
 * One line per relay that did not take a record: `failed <kind> <address> <relay> <code>`. The next keep offers it
 * again. A record that carries a revoked list adds `incomplete revocation <address> <relay> <code>: ...`, since the keys
 * it revokes are still honoured at that relay (spec/SPEC.md Appendix B 110).
 */
export function laggingLines(io: Io, address: string, lagging: readonly Lagging[]): void {
  for (const l of lagging) {
    io.out(`failed ${l.kind} ${address} ${l.relay} ${l.code}`)
    if (l.revokes) io.out(`incomplete revocation ${address} ${l.relay} ${l.code}: ${INCOMPLETE_REVOCATION}`)
  }
}

/**
 * Publishes the identity's next epoch (KeyRecordAdmin.rotate), one line per record and relay: `published key <address>
 * <url>`, then `published address <address> <url>` when the held record was re-signed with no sealing key. It succeeds
 * once a relay holds each record (spec/SPEC.md Appendix B 110), and laggingLines names the relays that did not take
 * one. When none takes a record it stops with the relay's code, as cli.ts names one (`unreachable` for no answer,
 * `http-<n>` for a status with no code): the epoch key is kept unpublished, and the error names the step that publishes
 * it again (`step`, ac keys rotate by default).
 */
export async function rotateEpoch(io: Io, o: RotateOptions): Promise<KeyRotation> {
  const client = io.relay({})
  const address = o.keys.signing.address
  const publishRecord = async (record: AcRecord, urls: readonly string[]): Promise<null[]> => {
    for (const url of urls) {
      try {
        await client.publish(url, serializeRecord(record))
      } catch (e) {
        const step = o.step?.(url) ?? `ac keys rotate ${o.name} --relay ${url}`
        throw new CliError(
          relayCode(e),
          `${url} did not take the ${record.kind} record of ${address}; publish it again: ${step}`,
        )
      }
      io.out(`published ${record.kind} ${address} ${url}`)
    }
    return urls.map(() => null)
  }
  const held = o.acceptLoss === true ? o.held : continueFrom(o.held, o.home, o.name, address)
  const admin = new KeyRecordAdmin({
    edge: { publishRecord, audit: cliAudit(o.home, o.name, io) },
    keys: o.keys,
    store: epochStore(o.home),
    clock: io.clock,
    rng: io.rng,
    relays: o.relays,
    held,
    resign: held !== o.held,
  })
  const rotation = await admin.rotate()
  keepAddressCopy(o.home, o.name, rotation.address)
  laggingLines(io, address, rotation.lagging)
  return rotation
}

/** The line a stale recovery copy prints, when a home has one; one that does not read is a line too. */
export function staleLine(io: Io, home: string, address: string, tag: string): void {
  try {
    const since = readRecoveryState(home, address)?.stale_since ?? null
    if (since !== null) io.out(`recovery: stale since ${instant(since)}`)
  } catch (e) {
    io.err(`${tag}: ${(e as Error).message}`)
  }
}

/**
 * Says that a swept identity came back from the copy in its home (ruling 4): the copy's date, since a revocation made
 * after it on another device is not in it, and a stale recovery copy.
 */
export function healed(io: Io, home: string, record: AddressRecord): void {
  io.out(`healed ${record.key} from the record kept here, signed ${instant(record.iat)}`)
  staleLine(io, home, record.key, 'heal')
}

/**
 * The identity's current key record, which a pairing carries (2026-10-29): a new
 * epoch's when one is due (epochDue: none held, or the newest 12 hours old), published at the relays of the newest
 * address record at `relay`; else the newest epoch's, signed again, the very bytes it published (an Ed25519 signature
 * over the same record is the same).
 */
export async function currentKey(
  io: Io,
  home: string,
  name: string,
  keys: EdgeKeys,
  relay: string,
): Promise<KeyRecord> {
  const address = keys.signing.address
  if (epochDue(home, address, io.clock.now())) {
    // The copy's relays too: `relay` may be the one that is down.
    const listed = addressCopy(home, name, address)?.relays ?? []
    const held = newestOf(await addressRecords(io, address, [relay, ...listed]))
    return (await rotateEpoch(io, { home, name, keys, relays: held?.relays ?? [relay], held })).key
  }
  const store = epochStore(home)
  const e = store.epoch(address, store.epochs(address)[0] as number)
  const sealing = toHex(e.key.publicKey)
  return signRecord(keys.signing, { kind: 'key', key: address, sealing_key: sealing, iat: e.iat, exp: e.exp })
}

/**
 * Offers the newest key record, which no republish signs, to each relay that does not read back as holding it: a relay
 * that missed a rotation has it by the next run (spec/SPEC.md Appendix B 110). Silent where a relay holds or takes it;
 * one `failed key <address> <relay> <code>` line where it does not. The first failure.
 */
export async function offerKey(
  io: Io,
  client: RelayClient,
  home: string,
  keys: Pick<EdgeKeys, 'signing'>,
  relays: readonly string[],
): Promise<unknown> {
  const record = publishedKeyRecord(epochStore(home), keys, io.clock.now())
  if (record === null) return null
  const offered = await offerBehind(client, record, relays)
  laggingLines(io, keys.signing.address, offered.lagging)
  return offered.first
}
