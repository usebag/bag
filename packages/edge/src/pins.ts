import {
  AcError,
  type AddressRecord,
  parseRecord,
  recordPreimage,
  serializeRecord,
  verifyPreimage,
  verifyRotation,
} from '@usebag/core'
import { type Audit, reasonOf } from './audit.ts'
import type { Clock, EdgeStore } from './ports.ts'

// Trust on first use (spec/SPEC.md §9.4): a subject's first verified record pins its key; a new key needs
// a rotation verifyRotation accepts (an address: one signed by its pinned rotation_key, B-9), else pin-mismatch.

/**
 * A pinned key known without its record (a domain root's key from the policy): the previous record that
 * verifyRotation reads, with no rotation key. verifyRotation checks the link only, never this record's signature.
 */
function keyOnlyRecord(key: string): AddressRecord {
  return {
    kind: 'address',
    key,
    sealing_key: null,
    relays: [],
    rotation_key: null,
    revoked: [],
    ttl: 1,
    iat: 0,
    rotated_from: null,
    rotation_sig: null,
    sig: '0'.repeat(128),
  }
}

/** An `address:` pin follows a rotation only under the pinned rotation_key (SPEC §9 item 12). */
function underRotationKey(prev: AddressRecord, next: AddressRecord): void {
  const key = prev.rotation_key
  if (key === null || !verifyPreimage(key, recordPreimage(next), next.rotation_sig as string))
    throw new AcError('bad-rotation', 'rotation_sig is not under the pinned rotation_key')
}

/** The pins of `domain:<domain>` and `address:<address>` subjects. */
export class Pins {
  readonly #store: EdgeStore
  readonly #audit: Audit
  readonly #clock: Clock

  constructor(store: EdgeStore, audit: Audit, clock: Clock) {
    this.#store = store
    this.#audit = audit
    this.#clock = clock
  }

  /**
   * Checks a verified address record against the subject's pin, or `initialKey` when nothing is pinned yet; pins
   * the record's key at first contact, keeps the newest record of the pinned key, and moves the pin on a valid
   * rotation. Throws pin-mismatch otherwise.
   */
  check(subject: string, record: AddressRecord, initialKey?: string): void {
    const now = this.#clock.now()
    const pin = this.#store.pinGet(subject)
    const pinned = pin?.key ?? initialKey
    const keep = { subject, key: record.key, record: serializeRecord(record), updatedAt: now }
    if (pinned === undefined || pinned === record.key) {
      const stored = pin?.record ? parseRecord(pin.record) : null
      if (stored === null || record.iat >= stored.iat)
        this.#store.pinPut({ ...keep, pinnedAt: pin?.pinnedAt ?? now })
      if (pin === null)
        this.#audit.record({ event: 'pin', decision: 'accept', detail: { subject, key: record.key } })
      return
    }
    const prev = pin?.record ? (parseRecord(pin.record) as AddressRecord) : keyOnlyRecord(pinned)
    try {
      verifyRotation(prev, record)
      if (subject.startsWith('address:')) underRotationKey(prev, record)
    } catch (e) {
      this.#audit.record({
        event: 'rotate',
        decision: 'reject',
        reason: 'pin-mismatch',
        detail: { subject, pinned, offered: record.key, check: reasonOf(e, 'bad-rotation') },
      })
      throw new AcError(
        'pin-mismatch',
        `${subject} is pinned to another key, and this is not a valid rotation`,
      )
    }
    this.#store.pinPut({ ...keep, pinnedAt: now })
    this.#audit.record({
      event: 'rotate',
      decision: 'accept',
      detail: { subject, from: pinned, to: record.key },
    })
  }
}
