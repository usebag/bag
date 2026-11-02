import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { SUITE } from '@usebag/core'
import { checkName, errno, keysOf, keyText, names, strict, writeNew, writtenAt } from '../custody/files.ts'
import type { EdgeKeys, KeyCustody, KeyEntry, KeyStore } from '../ports.ts'

// Key files (spec/SPEC.md §9.9): `<dir>/<name>.json` holding {suite, sign_seed, seal_priv} in hex, mode 0600, in a
// directory of mode 0700. A file or directory that others can read is refused, as ssh refuses one; an existing file
// is never overwritten. No message here ever holds key material. As the file custody it lists its key files
// and gives each identity's keys, its signer and opener, by address.

const PREFIX = 'fs-keys'

/** The key store on the file system, and the file custody. */
export class FsKeyStore implements KeyStore, KeyCustody {
  readonly kind = 'file'
  readonly #dir: string
  /** The keys the custody calls have read, by address: a file is read once per store. */
  readonly #read = new Map<string, EdgeKeys>()

  constructor(dir: string) {
    this.#dir = dir
  }

  /** Writes a new key file; refuses an existing one, and a directory others can read. */
  save(name: string, keys: EdgeKeys): void {
    const file = this.#file(name)
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, this.#dir, true)
    writeNew(file, keyText(keys))
  }

  /** Reads a key file; refuses one that is not 0600 (or stricter) in a 0700 directory, or not a regular file. */
  load(name: string): EdgeKeys {
    const file = this.#file(name)
    strict(PREFIX, this.#dir, true)
    strict(PREFIX, file, false)
    const keys = keysOf(() => readFileSync(file, 'utf8'))
    if (keys === 'json') throw new Error(`fs-keys: ${file} is not JSON`)
    if (keys === 'shape') throw new Error(`fs-keys: ${file} is not a suite ${SUITE} key file`)
    return keys
  }

  /** Every key file of the directory, by name; none when the directory does not exist. A bad file throws. */
  list(): KeyEntry[] {
    return names(PREFIX, this.#dir).map((name) => this.entry(name))
  }

  /** A key file's identity, after `load`'s checks: its address, and its mtime as when it was made. */
  entry(name: string): KeyEntry {
    const keys = this.load(name)
    this.#read.set(keys.signing.address, keys)
    return { name, address: keys.signing.address, custody: 'file', created: writtenAt(this.#file(name)) }
  }

  create(name: string, keys: EdgeKeys): KeyEntry {
    this.save(name, keys)
    return this.entry(name)
  }

  signer(address: string): EdgeKeys['signing'] {
    return this.#keys(address).signing
  }

  opener(address: string): EdgeKeys['sealing'] {
    return this.#keys(address).sealing
  }

  /** The keys of `address`, read before or found by reading every key file; ENOENT when none holds them. */
  #keys(address: string): EdgeKeys {
    if (!this.#read.has(address)) this.list()
    const keys = this.#read.get(address)
    if (keys === undefined) throw errno('ENOENT', `fs-keys: no key file in ${this.#dir} is ${address}'s`)
    return keys
  }

  #file(name: string): string {
    checkName(PREFIX, name)
    return join(this.#dir, `${name}.json`)
  }
}
