import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  generateSealingKey,
  MAX_ADDRESS_TTL,
  MAX_ENVELOPE_BYTES,
  MAX_KEY_LIFETIME,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import {
  Audit,
  acceptCopy,
  acquireLock,
  type Clock,
  coreRng,
  type EdgeKeys,
  FsAuditSink,
  heldSomewhere,
  KeyEpochStore,
  KeyRecordAdmin,
  keepAcceptCopy,
  keepAddressCopy,
  offerRecord,
  type RelayClient,
  SqliteStore,
} from '@usebag/edge'
import { loadKeys } from './keys.ts'
import { HomeError, type HomeIo } from './ports.ts'
import { failed } from './unpair.ts'

// A new identity's first records at its relays, as onboard and init make them under forward secrecy: the first epoch
// (KeyRecordAdmin with no held record: its key record, then a null-sealing address record naming the relays), then an
// accept-from that names only the identity itself. Each record succeeds once a relay holds it (spec/SPEC.md Appendix B
// 110); the home keeps its copies (<name>.address.json and <name>.accept.json in its records folder), as onboard does.

/** The audit log of what is signed outside an edge, in the identity's state directory, beside the edge's. */
export const CLI_AUDIT = 'cli-audit.jsonl'

/**
 * The audit log an act that opens no edge writes (the command line's and this package's): a chain of its own, from the
 * genesis, because a hash chain takes one live writer and a live edge may hold audit.jsonl. Each line takes this file's
 * own lock, never one the open path waits on, and then puts this file's anchor in the edge store, opened without the
 * writer lock: its row is the set's record that the file must exist, which an edge checks at start and `audit verify`
 * reads. A crash between the two leaves the file a line ahead of its anchor, as the edge's own log can be.
 */
export function cliAudit(home: string, name: string, clock: Clock): Pick<Audit, 'record'> {
  const dir = join(home, 'state', name)
  return {
    record(entry) {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const release = acquireLock(join(dir, 'cli-audit.lock'))
      try {
        const line = new Audit(new FsAuditSink(join(dir, CLI_AUDIT)), clock).record(entry)
        const store = new SqliteStore(join(dir, 'edge.sqlite'), { lock: false })
        try {
          store.auditAnchorPut(CLI_AUDIT, { seq: line.seq, hash: line.hash }, clock.now())
        } finally {
          store.close()
        }
        return line
      } finally {
        release()
      }
    },
  }
}

/** The records whose publish at a relay is audited one line each: the address record and the accept-from. */
export type AuditedRecord = 'address' | 'accept-from'

/**
 * The audit event of a publish line: the existing `policy` event, with step publish in its detail, so that no new
 * event word (a telemetry schema change) is needed and a republish is not counted as an onboarding.
 */
const PUBLISH_EVENT = 'policy'

/**
 * Publishes one address or accept-from record at one relay through `send`, and writes one line for it to `audit` (a
 * cliAudit): the event PUBLISH_EVENT with detail {step: 'publish', record, relay, outcome}. outcome is `ok`, or
 * `unchanged` when the relay keeps a record as new (stale-record), both decision accept; else the failure's code
 * (`unreachable`, `http-<status>`, the relay's code), decision reject. A failure, stale-record included, is audited,
 * then thrown on as it came. Every first publish of these two records, here and in the command line, goes through
 * it, so both paths write the same line to the same file.
 */
export async function auditedPublish(
  audit: Pick<Audit, 'record'>,
  record: AuditedRecord,
  relay: string,
  send: () => Promise<unknown>,
): Promise<void> {
  const line = (outcome: string): void => {
    audit.record({
      event: PUBLISH_EVENT,
      decision: outcome === 'ok' || outcome === 'unchanged' ? 'accept' : 'reject',
      detail: { step: 'publish', record, relay, outcome },
    })
  }
  try {
    await send()
  } catch (e) {
    const code = failed(e)
    line(code === 'stale-record' ? 'unchanged' : code)
    throw e
  }
  line('ok')
}

/** A failed line's end for an epoch key no relay took: it stays stored, unpublished, and is offered again. */
export const OFFERED_AGAIN = 'will be offered again at the next rotation'

/** The accept-from's retention, onboard's default (cut/docs/partner-install.md). */
const RETENTION = 604_800

/**
 * Publishes the first records of `name` (a key file or keychain identity of `home`, or one on this machine only being
 * promoted: its kept epoch 1 goes out re-dated, its accept-from keeps the copy's roots) to `relays`, through `client`: one
 * line per record and relay, `published <kind> <address> <url>`, or `failed <kind> <address> <url> <code>` for a relay
 * that did not take it. A record no relay takes refuses with the first relay's code; the identity stays, as onboard's
 * keys stay, and nothing after that record is published. The epoch key is kept before its record goes out, so a
 * later rotation publishes it again rather than minting another.
 */
export async function publishFirstRecords(
  io: HomeIo,
  home: string,
  name: string,
  relays: readonly string[],
  client: RelayClient = io.relay({}),
): Promise<void> {
  const keys = loadKeys(io.security, home, name)
  const address = keys.signing.address
  const lines = (
    kind: string,
    held: readonly string[],
    lagging: readonly { relay: string; code: string }[],
  ) => {
    for (const url of relays) {
      const lag = lagging.find((l) => l.relay === url)
      if (held.includes(url)) io.say(`published ${kind} ${address} ${url}`)
      else if (lag !== undefined)
        io.say(`failed ${kind} ${address} ${url} ${lag.code}${kind === 'key' ? `: ${OFFERED_AGAIN}` : ''}`)
    }
  }
  const refused = (kind: string, e: unknown): HomeError => {
    const code = failed(e)
    return new HomeError(
      code,
      `${name} is made, but no relay took its ${kind} record (${code}): nothing after it was published`,
    )
  }
  // The trace the command line leaves for the same act: each address and accept-from publish, and the rotation's line.
  const audit = cliAudit(home, name, io.clock)
  const admin = new KeyRecordAdmin({
    edge: {
      publishRecord: async (record, urls = relays) => {
        for (const url of urls) {
          const send = () => client.publish(url, serializeRecord(record))
          if (record.kind === 'address') await auditedPublish(audit, 'address', url, send)
          else await send()
        }
        return urls.map(() => null)
      },
      audit,
    },
    keys,
    store: new KeyEpochStore(join(home, 'key-records')),
    clock: io.clock,
    rng: io.rng,
    relays,
    held: null,
  })
  let rotation: Awaited<ReturnType<KeyRecordAdmin['rotate']>>
  try {
    rotation = await admin.rotate()
  } catch (e) {
    throw refused('key and address', e)
  }
  for (const kind of ['key', 'address'] as const) {
    const lag = rotation.lagging.filter((l) => l.kind === kind)
    lines(
      kind,
      relays.filter((url) => !lag.some((l) => l.relay === url)),
      lag,
    )
  }
  keepAddressCopy(home, name, rotation.address)
  // A promoted identity's accept-from goes on from its copy's roots; a new one names only itself.
  const accept = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: address,
    roots: [...(acceptCopy(home, name, address)?.roots ?? [address])],
    max_bytes: MAX_ENVELOPE_BYTES,
    ttl: RETENTION,
    iat: io.clock.now(),
  })
  const offered = await offerRecord(accept, relays, (url) =>
    auditedPublish(audit, 'accept-from', url, () => client.publish(url, serializeRecord(accept))),
  )
  lines('accept-from', offered.held, offered.lagging)
  try {
    heldSomewhere(offered)
  } catch (e) {
    throw refused('accept-from', e)
  }
  keepAcceptCopy(home, name, accept)
}

/**
 * Keeps the first records of `name`, an identity on this machine only (relays []), in its home and publishes none: no
 * relay client is made. Epoch 1's key goes to key-records/ unpublished (none minted when an epoch is held), so the first
 * local send seals to it and a promotion (identity relays) republishes it re-dated; the address copy has sealing_key
 * null and relays []; the accept-from names only itself. One cli-audit line. `keys` are the ones in hand (keygen's), so a
 * keychain identity raises no dialog. Never publishFirstRecords with []: an empty offer passes heldSomewhere and the
 * rotation would mark the epoch published. Returns `kept key|address|accept-from <address>`.
 */
export function keepFirstRecordsLocal(
  io: HomeIo,
  home: string,
  name: string,
  keys: EdgeKeys = loadKeys(io.security, home, name),
): readonly string[] {
  const address = keys.signing.address
  const now = io.clock.now()
  const store = new KeyEpochStore(join(home, 'key-records'))
  const held = store.epochs(address)[0]
  if (held === undefined)
    store.put(address, 1, generateSealingKey(coreRng(io.rng)), now, now + MAX_KEY_LIFETIME)
  const epoch = held ?? 1
  const record = store.epoch(address, epoch)
  keepAddressCopy(
    home,
    name,
    signRecord(keys.signing, {
      kind: 'address',
      key: address,
      sealing_key: null,
      relays: [],
      rotation_key: null,
      revoked: [],
      ttl: MAX_ADDRESS_TTL,
      iat: now,
      rotated_from: null,
    }),
  )
  const accept = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: address,
    roots: [address],
    max_bytes: MAX_ENVELOPE_BYTES,
    ttl: RETENTION,
    iat: now,
  })
  keepAcceptCopy(home, name, accept)
  cliAudit(home, name, io.clock).record({
    event: PUBLISH_EVENT,
    decision: 'accept',
    from: address,
    detail: {
      step: 'keep-local',
      epoch,
      sealing_key: toHex(record.key.publicKey),
      exp: record.exp,
      published: record.published,
    },
  })
  return ['key', 'address', 'accept-from'].map((k) => `kept ${k} ${address}`)
}
