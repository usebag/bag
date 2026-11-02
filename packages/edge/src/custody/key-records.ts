import { mkdirSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import {
  AcError,
  type AddressRecord,
  decodeAddress,
  fromHex,
  isHex,
  parseRecord,
  type SealingKey,
  SUITE,
  sealingKeyFromSeed,
  serializeRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import { EdgeError } from '../ports.ts'
import { errno, present, strict, writeNew } from './files.ts'

// The epoch key store (forward secrecy): one directory per address, <dir>/<the address's 64 hex>/, of mode 0700,
// holding e<n>.json, epoch n's private sealing key (the X25519 seed in hex), its key record's iat and exp, and whether
// that epoch's records have been published, each of mode 0600. The private key is kept BEFORE its key record is
// published (crash-safe: a key record on a relay is useless if its private key was never persisted), so a new epoch is
// written `published: false` and marked true only once its records go out; a crash or a failed publish leaves it
// unpublished, to be published again (not re-minted) at the next cycle. An individual seals received mail to the
// current epoch key and keeps each epoch's private key only until its deletion horizon (exp + the retention that
// bounds how long a relay holds mail + the skew), then deletes it, so a key stolen after the horizon opens no past
// content. A group has no epoch key store: its forward secrecy is generation rotation.

const PREFIX = 'key-records'

/** The copy of the address record last written for `name` in `home`: onboard's file, and every publisher's since. */
const copyPath = (home: string, name: string): string => join(home, 'records', `${name}.address.json`)

/**
 * That copy, when the core verifies it at its own iat, it is `address`'s and it names no rotated_from; else (or with no
 * file) null.
 */
export function addressCopy(home: string, name: string, address: string): AddressRecord | null {
  try {
    const parsed = parseRecord(readFileSync(copyPath(home, name)))
    const r = verifyRecord(parsed, parsed.iat)
    return r.kind === 'address' && r.key === address && r.rotated_from === null ? r : null
  } catch {
    return null
  }
}

/**
 * Keeps `record` as that copy, whole: a temporary file beside it, renamed over it. Records are public (spec §7). A copy
 * as new or newer stays: the copy is the home's one anchor for the revoked list, and a relay can answer an old record.
 * A rotation record is never kept: addressCopy refuses it, so it would only leave a good copy unreadable.
 */
export function keepAddressCopy(home: string, name: string, record: AddressRecord): void {
  const held = addressCopy(home, name, record.key)
  if (record.rotated_from !== null || (held !== null && held.iat >= record.iat)) return
  const file = copyPath(home, name)
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  const temp = `${file}.${process.pid}.tmp`
  writeFileSync(temp, `${new TextDecoder().decode(serializeRecord(record))}\n`)
  renameSync(temp, file)
}

/**
 * What an identity continues from, given the newest record its relays hold (`found`): that record, unless this home
 * wrote a newer one, which a relay replaying an old record would otherwise roll back; `lastAddress` when they hold none.
 */
export function continueFrom(
  found: AddressRecord | null,
  home: string,
  name: string,
  address: string,
): AddressRecord | null {
  if (found === null) return lastAddress(home, name, address)
  const copy = addressCopy(home, name, address)
  return copy !== null && copy.iat > found.iat ? copy : found
}

/**
 * What an identity continues from when no relay holds its address record, the sweep of a lapse: its copy, so its
 * rotation key and revoked list go on. Null only for an
 * identity that never published from this home, whose empty first record is right. One that did, and whose copy is
 * missing or unreadable, is `no-held-record`: an empty revoked list would undo its revocations, so nothing is published.
 */
export function lastAddress(home: string, name: string, address: string): AddressRecord | null {
  const copy = addressCopy(home, name, address)
  if (copy !== null) return copy
  const store = new KeyEpochStore(join(home, PREFIX))
  const published = store.epochs(address).some((n) => store.epoch(address, n).published)
  if (!published && !present(copyPath(home, name))) return null
  throw new EdgeError(
    'no-held-record',
    `no relay holds the address record of ${address} and ${copyPath(home, name)} is not a readable copy of it, so its revoked list and rotation key cannot go on: restore the home's backup, or rotate knowing they are lost: ac keys rotate ${name} --relay <url> --accept-loss`,
  )
}

/** One epoch an individual holds: its number, its private sealing key, the key record's iat and exp, and published. */
export interface Epoch {
  readonly epoch: number
  readonly key: SealingKey
  readonly iat: number
  readonly exp: number
  /** True once this epoch's key record (and null address record) have been published; false while a publish is owed. */
  readonly published: boolean
}

/** The JSON an epoch file holds. */
interface Stored {
  readonly suite: number
  readonly address: string
  readonly epoch: number
  readonly seal_priv: string
  readonly iat: number
  readonly exp: number
  readonly published: boolean
}

let temp = 0

export class KeyEpochStore {
  readonly #dir: string

  constructor(dir: string) {
    this.#dir = dir
  }

  /** The epochs held of an address, newest first; none when its directory does not exist. */
  epochs(address: string): number[] {
    const dir = this.#address(address)
    if (!present(dir)) return []
    strict(PREFIX, dir, true)
    return readdirSync(dir)
      .flatMap((f) => /^e([1-9][0-9]*)\.json$/.exec(f)?.slice(1, 2) ?? [])
      .map(Number)
      .sort((a, b) => b - a)
  }

  /** Epoch `n`'s held material, checked for its form and its place (bad-content); ENOENT when it is not held. */
  epoch(address: string, n: number): Epoch {
    const s = this.#read(address, n)
    return {
      epoch: n,
      key: sealingKeyFromSeed(fromHex(s.seal_priv, 32)),
      iat: s.iat,
      exp: s.exp,
      published: s.published,
    }
  }

  /** Keeps a fresh epoch's private key, unpublished, written once (EEXIST when the epoch is already held). */
  put(address: string, epoch: number, key: SealingKey, iat: number, exp: number): void {
    const dir = this.#address(address)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, this.#dir, true)
    strict(PREFIX, dir, true)
    writeNew(
      join(dir, `e${epoch}.json`),
      this.#text(address, epoch, toHex(key.exportSeed()), iat, exp, false),
    )
  }

  /**
   * Re-dates a held epoch's key record (a new iat and exp, the same private key), left unpublished: a failed or
   * crashed publish is published again with a fresh iat, never byte-identical (a relay refuses an equal iat as
   * stale-record), and never a new epoch key.
   */
  renew(address: string, epoch: number, iat: number, exp: number): void {
    const s = this.#read(address, epoch)
    this.#replace(address, epoch, this.#text(address, epoch, s.seal_priv, iat, exp, false))
  }

  /** Marks a held epoch published, once its records are on their relays. */
  markPublished(address: string, epoch: number): void {
    const s = this.#read(address, epoch)
    this.#replace(address, epoch, this.#text(address, epoch, s.seal_priv, s.iat, s.exp, true))
  }

  /**
   * Deletes every held epoch past its deletion horizon (exp + ttl + skew): once its private key is gone, content
   * sealed to it can never be opened again (the forward-secrecy mechanism). Returns the epochs deleted, newest first.
   */
  prune(address: string, now: number, ttl: number, skew: number): number[] {
    const gone: number[] = []
    for (const n of this.epochs(address)) {
      if (now > this.#read(address, n).exp + ttl + skew) {
        unlinkSync(join(this.#address(address), `e${n}.json`))
        gone.push(n)
      }
    }
    return gone
  }

  #read(address: string, n: number): Stored {
    const file = join(this.#address(address), `e${n}.json`)
    if (!present(file)) throw errno('ENOENT', `${PREFIX}: no epoch ${n} of ${address} is held`)
    strict(PREFIX, file, false)
    const v = Object(JSON.parse(readFileSync(file, 'utf8')))
    const published = v.published ?? true // an epoch written before the flag existed is taken as published
    if (
      v.suite !== SUITE ||
      v.address !== address ||
      v.epoch !== n ||
      !isHex(v.seal_priv, 32) ||
      !Number.isInteger(v.iat) ||
      !Number.isInteger(v.exp) ||
      typeof published !== 'boolean'
    ) {
      throw new AcError('bad-content', `${file} is not epoch ${n} of ${address}`)
    }
    return { suite: v.suite, address, epoch: n, seal_priv: v.seal_priv, iat: v.iat, exp: v.exp, published }
  }

  #text(
    address: string,
    epoch: number,
    sealPriv: string,
    iat: number,
    exp: number,
    published: boolean,
  ): string {
    return JSON.stringify({ suite: SUITE, address, epoch, seal_priv: sealPriv, iat, exp, published })
  }

  /** Writes `text` through a new 0600 file and a rename, so a reader sees the old text or the new (never a partial). */
  #replace(address: string, epoch: number, text: string): void {
    const file = join(this.#address(address), `e${epoch}.json`)
    const next = `${file}.${process.pid}.${temp++}.tmp`
    writeNew(next, text)
    renameSync(next, file)
  }

  #address(address: string): string {
    return join(this.#dir, toHex(decodeAddress(address)))
  }
}
