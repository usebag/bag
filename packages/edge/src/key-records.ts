import {
  AcError,
  type AddressRecord,
  type Rng as CoreRng,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  generateSealingKey,
  type KeyRecord,
  MAX_ADDRESS_TTL,
  MAX_KEY_LIFETIME,
  SealingKey,
  signRecord,
  toHex,
} from '@usebag/core'
import type { Audit } from './audit.ts'
import { errno } from './custody/files.ts'
import type { KeyEpochStore } from './custody/key-records.ts'
import type { Edge } from './edge.ts'
import { heldSomewhere, type Lagging, type Offered, offerRecord } from './offer.ts'
import type { Clock, EdgeKeys, Rng } from './ports.ts'
import { coreRng } from './sender.ts'

// An individual's forward-secrecy lifecycle: the recipient edge publishes, each epoch, a short-lived key record
// over a fresh X25519 sealing key and an address record with a null sealing key, keeps the epoch's private key in a
// KeyEpochStore, and deletes it past its horizon. Senders prefer the key record (Resolver.recipient), so content is
// sealed to the current epoch key and never to a long-lived address key. The opener a recipient edge receives with is
// an EpochOpener over its held epoch keys, a drop-in for keys.sealing, exactly as groups compose memberKeys (member.ts).

/**
 * The opener of an individual's mailbox under forward secrecy: a SealingKey, because the Receiver opens with the
 * core's openSealed, which takes that class. Its open tries, newest first, each epoch key the store still
 * holds, and fails as the first of them failed; content sealed to an epoch whose private key was deleted past its
 * horizon can no longer be opened. Its publicKey is the newest epoch's, so it is a drop-in for keys.sealing.
 */
export class EpochOpener extends SealingKey {
  readonly #keys: () => readonly SealingKey[]

  constructor(keys: () => readonly SealingKey[]) {
    const current = keys()[0]
    if (current === undefined) throw errno('ENOENT', 'key-records: no epoch key is held')
    super(current.exportSeed())
    this.#keys = keys
  }

  override open(enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
    const failures: unknown[] = []
    for (const key of this.#keys()) {
      try {
        return key.open(enc, info, aad, ct)
      } catch (e) {
        failures.push(e)
      }
    }
    throw failures[0] ?? new AcError('open-failed', 'no epoch key is held')
  }
}

/** An opener over the epoch keys the store holds for `address`, newest first, read fresh at each open. */
export function epochOpener(store: KeyEpochStore, address: string): EpochOpener {
  return new EpochOpener(() => store.epochs(address).map((n) => store.epoch(address, n).key))
}

/** How the key-record lifecycle publishes a recipient's records. */
export interface KeyRecordOptions {
  /** The edge the records are published through: its own relays by default. */
  readonly edge: Pick<Edge, 'publishRecord'> & { readonly audit: Pick<Audit, 'record'> }
  /** The recipient's keys: its signing key signs both records, and its address is the subject. */
  readonly keys: EdgeKeys
  readonly store: KeyEpochStore
  readonly clock: Clock
  readonly rng: Rng
  /** The relays the address record names, where both records are published. */
  readonly relays: readonly string[]
  /**
   * The identity's current address record, so an epoch rotation preserves its revocations (ac logout, device
   * revocation; a restore) and its relays; null or omitted before the first publish. A rotation nulls the
   * sealing key of a held record that is not itself a countersigned rotation, keeping its revoked, relays and
   * rotation_key; it never re-signs one whose sealing key is already null, and refuses one whose sealing key rides a
   * rotation (rotated_from set), which only a §7.3 identity-key rotation can null.
   */
  readonly held?: AddressRecord | null
  /** `held` is not what the relays hold (a sweep, a replay; a copy in the home): re-sign and publish it at any age. */
  readonly resign?: boolean
  /** The address record's rotation key, for the first publish; none by default. */
  readonly rotationKey?: string
  /** How long each key record lives, in seconds; a day (MAX_KEY_LIFETIME) by default and at most. */
  readonly keyLifetime?: number
  /** The address record's ttl, in seconds; a day (MAX_ADDRESS_TTL) by default. */
  readonly addressTtl?: number
  /** The relay retention that bounds the deletion horizon (exp + retention + skew); DEFAULT_TTL by default. */
  readonly retention?: number
  readonly skew?: number
}

/** A published epoch: its number, the two records, the epochs this rotation deleted, and how it was published. */
export interface Rotation {
  readonly epoch: number
  readonly key: KeyRecord
  readonly address: AddressRecord
  readonly deleted: readonly number[]
  /** Whether the address record was re-signed and published (false when a held null-sealing record was kept as is). */
  readonly resigned: boolean
  /** True when this published a stored-but-unpublished epoch again (a prior publish failed), minting no new key. */
  readonly republished: boolean
  /** The relays that did not take a record; the keep-alive carries the rest (spec/SPEC.md Appendix B 110). */
  readonly lagging: readonly Lagging[]
}

/** The newest epoch's key record, signed again, when that epoch is published and has not ended; null otherwise. */
export function publishedKeyRecord(
  store: KeyEpochStore,
  keys: Pick<EdgeKeys, 'signing'>,
  now: number,
): KeyRecord | null {
  const key = keys.signing.address
  const newest = store.epochs(key)[0]
  const e = newest === undefined ? null : store.epoch(key, newest)
  if (e === null || !e.published || now >= e.exp) return null
  const sealing_key = toHex(e.key.publicKey)
  return signRecord(keys.signing, { kind: 'key', key, sealing_key, iat: e.iat, exp: e.exp })
}

export class KeyRecordAdmin {
  readonly #o: KeyRecordOptions
  readonly #rng: CoreRng

  constructor(options: KeyRecordOptions) {
    this.#o = options
    this.#rng = coreRng(options.rng)
  }

  /** The recipient's address, the subject of both records. */
  get address(): string {
    return this.#o.keys.signing.address
  }

  /**
   * Publishes this identity's epoch. When the newest held epoch is still unpublished (a prior publish failed or
   * the process crashed between keeping the key and publishing), its key is re-used, re-dated and published again, no
   * new key minted (`republished`); otherwise a fresh X25519 sealing key, independent of the signing key, is kept and
   * published as a new epoch. Either way the key record carries a fresh iat (never byte-identical, which a relay would
   * refuse as stale-record) and the epoch's private key is kept BEFORE the key record is published (crash-safe), then
   * marked published once at least one relay holds each record (spec/SPEC.md Appendix B 110): the relays that did not
   * take one come back in `lagging`, and when none took one it throws, leaving the epoch stored and unpublished for the
   * next cycle. The address record is chosen first (#addressFor), so a refusal (a held rotation that cannot be
   * nulled) keeps no epoch and publishes nothing; it nulls or preserves a held record's sealing key without ever
   * dropping its revocations. The key record goes out first (a sender prefers it over the null address record), the
   * address record only when it changed; then every epoch past its deletion horizon is deleted. One audit line names
   * the epoch, the public key, the exp and how it published, never key material.
   */
  async rotate(): Promise<Rotation> {
    const { clock, keys, store } = this.#o
    const now = clock.now()
    const held = this.#o.held ?? null
    // First, before any epoch is kept, so a bad-rotation refusal leaves nothing half-done.
    const addr = this.#addressFor(held, now)
    const resigned = addr !== held
    const exp = now + Math.min(this.#o.keyLifetime ?? MAX_KEY_LIFETIME, MAX_KEY_LIFETIME)
    const newest = store.epochs(this.address)[0]
    const current = newest === undefined ? null : store.epoch(this.address, newest)
    let epoch: number
    let sealing: SealingKey
    let republished: boolean
    if (current !== null && !current.published) {
      // A stored-but-unpublished epoch: publish its key again, re-dated, minting no new key.
      epoch = current.epoch
      sealing = current.key
      store.renew(this.address, epoch, now, exp)
      republished = true
    } else {
      sealing = generateSealingKey(this.#rng)
      epoch = (newest ?? 0) + 1
      store.put(this.address, epoch, sealing, now, exp)
      republished = false
    }
    const key = signRecord(keys.signing, {
      kind: 'key',
      key: this.address,
      sealing_key: toHex(sealing.publicKey),
      iat: now,
      exp,
    })
    // When no relay takes one this throws; the epoch stays stored and unpublished, so the next cycle publishes it again.
    const lagging = [...heldSomewhere(await this.#offer(key)).lagging]
    if (resigned) lagging.push(...heldSomewhere(await this.#offer(addr)).lagging)
    store.markPublished(this.address, epoch)
    const deleted = store.prune(
      this.address,
      now,
      this.#o.retention ?? DEFAULT_TTL,
      this.#o.skew ?? DEFAULT_SKEW,
    )
    this.#o.edge.audit.record({
      event: 'rotate',
      decision: 'accept',
      from: this.address,
      detail: {
        subject: `key:${this.address}`,
        epoch,
        sealing_key: toHex(sealing.publicKey),
        exp,
        resigned,
        republished,
        deleted: deleted.map((n) => String(n)),
        ...(lagging.length === 0 ? {} : { lagging: lagging.map((l) => `${l.kind} ${l.relay} ${l.code}`) }),
      },
    })
    return { epoch, key, address: addr, deleted, resigned, republished, lagging }
  }

  #offer(record: KeyRecord | AddressRecord): Promise<Offered> {
    const publish = (url: string) => this.#o.edge.publishRecord(record, [url])
    return offerRecord(record, this.#o.relays, publish)
  }

  /**
   * The address record to publish this epoch, given the identity's held one (for a restore). A fresh
   * null-sealing record when none is held; the held record itself, unchanged, when its sealing key is already null and
   * it still stands (so its revocations and relays are not disturbed, and the caller re-publishes nothing); a re-signed
   * null-sealing record with a new iat but the held revoked, relays and rotation_key when it carries a sealing key and
   * is not a rotation, or has lapsed (a swept record comes back here, from the copy in its home); and bad-rotation when it carries a sealing key on a countersigned rotation, whose rotation_sig a new iat
   * would invalidate and only its countersigner can redo — such an identity nulls its sealing key with a §7.3
   * identity-key rotation, the one case an epoch rotation cannot null.
   */
  #addressFor(held: AddressRecord | null, now: number): AddressRecord {
    if (held === null) {
      return signRecord(this.#o.keys.signing, {
        kind: 'address',
        key: this.address,
        sealing_key: null,
        relays: [...this.#o.relays],
        rotation_key: this.#o.rotationKey ?? null,
        revoked: [],
        ttl: this.#o.addressTtl ?? MAX_ADDRESS_TTL,
        iat: now,
        rotated_from: null,
      })
    }
    if (held.sealing_key === null && now <= held.iat + held.ttl && this.#o.resign !== true) return held
    if (held.rotated_from !== null) {
      throw new AcError(
        'bad-rotation',
        `${this.address} has a rotation address record with a sealing key; null it with a section 7.3 identity-key rotation before an epoch rotation`,
      )
    }
    return signRecord(this.#o.keys.signing, {
      kind: 'address',
      key: this.address,
      sealing_key: null,
      relays: [...held.relays],
      rotation_key: held.rotation_key,
      revoked: [...held.revoked],
      ttl: held.ttl,
      iat: Math.max(now, held.iat + 1),
      rotated_from: null,
    })
  }
}
