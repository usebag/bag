import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { AcError, isAddress } from '@usebag/core'
import { readSession, resolveLabel } from '@usebag/enterprise-client'
import { CliError } from './args.ts'

// Petnames: a local name book per home, <home>/names.json, that maps a short name to an address. A name is
// resolved here and never sent on the wire; no relay or peer sees it. The book pins a name to one address: changing it
// takes --replace, which keeps the old address under "previous", so a message from that former address is shown with
// a warning instead of the plain name. The file is 0600, written whole to a temporary file beside it and renamed.

/** The book's file in a home. */
export const NAMES_FILE = 'names.json'
/** A name: lowercase letters, digits, dot, underscore and dash, 1 to 64, starting with a letter or digit. */
export const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/

/** An address a name had before a --replace, and when it was replaced (Unix seconds). */
export interface Previous {
  readonly address: string
  readonly replaced_at: number
}

/** A name's entry: its address, when it was added (Unix seconds), and its former addresses when it has any. */
export interface NameEntry {
  readonly address: string
  readonly added_at: number
  readonly previous?: readonly Previous[]
}

/** Who an address is in the book: the current address of a name, or a former one. */
export type Display =
  | { readonly name: string; readonly former: false }
  | { readonly name: string; readonly former: true; readonly replacedAt: number }

/** Unix seconds as an ISO 8601 UTC instant to the second: 1792941104 is 2026-10-25T15:11:44Z. */
export function instant(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** An address as "ed25519:" and its first 8 hex digits, then an ellipsis. */
export function short(address: string): string {
  return `${address.slice(0, 'ed25519:'.length + 8)}…`
}

const seconds = (v: unknown): boolean => Number.isSafeInteger(v) && (v as number) >= 0

/** The entries of a parsed file, or the reason it is not a book. */
function entries(doc: unknown): Map<string, NameEntry> | string {
  const d = doc as { version?: unknown; names?: unknown } | null
  if (d?.version !== 1) return 'version is not 1'
  if (typeof d.names !== 'object' || d.names === null || Array.isArray(d.names))
    return 'names is not an object'
  const out = new Map<string, NameEntry>()
  for (const [name, raw] of Object.entries(d.names)) {
    const e = raw as { address?: unknown; added_at?: unknown; previous?: unknown } | null
    const previous = e?.previous ?? []
    const valid =
      NAME.test(name) &&
      isAddress(e?.address) &&
      seconds(e?.added_at) &&
      Array.isArray(previous) &&
      previous.every((p: { address?: unknown; replaced_at?: unknown } | null) => {
        return isAddress(p?.address) && seconds(p?.replaced_at)
      })
    if (!valid) return `the entry ${JSON.stringify(name)} is not a name with an address`
    out.set(name, e as NameEntry)
  }
  return out
}

/** The name book of a home. Every method is synchronous; nothing reaches the network. */
export class NameBook {
  readonly home: string
  readonly path: string
  readonly #names: Map<string, NameEntry>

  private constructor(home: string, names: Map<string, NameEntry>) {
    this.home = home
    this.path = join(home, NAMES_FILE)
    this.#names = names
  }

  /** The book of a home: empty when the file is missing; names-invalid when it is not a book. */
  static load(home: string): NameBook {
    const path = join(home, NAMES_FILE)
    let text: string
    try {
      text = readFileSync(path, 'utf8')
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT') return new NameBook(home, new Map())
      throw e
    }
    let doc: unknown
    try {
      doc = JSON.parse(text)
    } catch {
      throw new CliError('names-invalid', `${path} is not JSON`)
    }
    const names = entries(doc)
    if (typeof names === 'string') throw new CliError('names-invalid', `${path}: ${names}`)
    return new NameBook(home, names)
  }

  /** Writes the book: the home made 0700 when missing, a 0600 temporary file beside names.json, renamed over it. */
  save(): void {
    mkdirSync(this.home, { recursive: true, mode: 0o700 })
    const names = Object.fromEntries([...this.#names].sort(([a], [b]) => (a < b ? -1 : 1)))
    const tmp = join(this.home, `.${NAMES_FILE}.${randomUUID()}.tmp`)
    writeFileSync(tmp, `${JSON.stringify({ version: 1, names }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
    try {
      renameSync(tmp, this.path)
    } catch (e) {
      unlinkSync(tmp)
      throw e
    }
  }

  /**
   * Refuses, as packages/mcp/src/names.ts does, a name the book has for another address (name-exists). With no address,
   * at a pairing's first step while its peer is not known yet, any entry for the name refuses.
   */
  check(name: string, address?: string): void {
    const known = this.#names.get(name)?.address
    if (known !== undefined && known !== address)
      throw new CliError(
        'name-exists',
        `${name} is ${known}: pair under another name, pass that address as --for to pair the same peer again, or change it with ac name`,
      )
  }

  /**
   * Names `address`. The same address again changes nothing; another address for a known name is name-exists unless
   * `replace`, which keeps the old address under previous with `now` as its replaced_at.
   */
  add(name: string, address: string, now: number, replace = false): void {
    if (!NAME.test(name) || isAddress(name)) {
      throw new CliError('bad-name', `${JSON.stringify(name)} is not a name (${NAME.source})`)
    }
    if (!isAddress(address)) throw new AcError('bad-address', `${JSON.stringify(address)} is not an address`)
    const known = this.#names.get(name)
    if (known?.address === address) return
    if (known === undefined) {
      this.#names.set(name, { address, added_at: now })
      return
    }
    if (!replace) {
      throw new CliError('name-exists', `${name} is ${known.address}; pass --replace to change it`)
    }
    const previous = [...(known.previous ?? []), { address: known.address, replaced_at: now }]
    this.#names.set(name, { address, added_at: now, previous: previous.filter((p) => p.address !== address) })
  }

  /** Removes a name and its former addresses; name-unknown when the book has no such name. */
  forget(name: string): void {
    if (!this.#names.delete(name)) throw this.#unknown(name)
  }

  /** The names and their entries, sorted by name. */
  list(): [string, NameEntry][] {
    return [...this.#names].sort(([a], [b]) => (a < b ? -1 : 1))
  }

  /**
   * The address `text` names: itself when it is an address, the address of a known name; name-unknown for a name the
   * book does not have, bad-address for text that is neither.
   */
  resolve(text: string): string {
    if (isAddress(text)) return text
    const known = this.#names.get(text)
    if (known !== undefined) return known.address
    if (!NAME.test(text)) {
      throw new AcError('bad-address', `${JSON.stringify(text)} is neither an address nor a name`)
    }
    throw this.#unknown(text)
  }

  /** As resolve, then, for a name the book lacks with an enterprise session in the home, the org's agent so labelled. */
  async find(text: string, fetch?: typeof globalThis.fetch, org?: string): Promise<string> {
    const book =
      isAddress(text) || this.#names.has(text) || !NAME.test(text) || readSession(this.home, org) === null
    const o = { ...(fetch && { fetch }), ...(org && { org }) }
    return (book ? undefined : await resolveLabel(this.home, text, o)) ?? this.resolve(text)
  }

  /** Who `address` is: a name's current address, else the most recent former address of a name, else null. */
  display(address: string): Display | null {
    const all = this.list()
    for (const [name, e] of all) if (e.address === address) return { name, former: false }
    for (const [name, e] of all) {
      const p = (e.previous ?? []).filter((p) => p.address === address).at(-1)
      if (p !== undefined) return { name, former: true, replacedAt: p.replaced_at }
    }
    return null
  }

  /** `address` for a person: "<name> (<short>)", the former-address warning, or the full address when unknown. */
  label(address: string): string {
    const d = this.display(address)
    if (d === null) return address
    if (!d.former) return `${d.name} (${short(address)})`
    return `${d.name}? (${short(address)}) WARNING: former address of ${d.name}, replaced ${instant(d.replacedAt)}`
  }

  #unknown(name: string): CliError {
    const known = [...this.#names.keys()].sort()
    const names = known.length === 0 ? 'the book is empty' : `the known names are ${known.join(', ')}`
    return new CliError('name-unknown', `no name ${JSON.stringify(name)} in ${this.path}; ${names}`)
  }
}
