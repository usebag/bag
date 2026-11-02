import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { AcError, isAddress, isHandle } from '@usebag/core'
import { ConfigError } from './config.ts'
import type { Message } from './desk.ts'

// The home's name book: <home>/names.json, which the CLI's `name` command writes (packages/cli/src/names.ts,
// the format's owner). The server writes it only when a pairing completes (pairing.ts), adding the pair's name as the
// CLI's peer does; the dependency rule (scripts/check-imports.sh) keeps this package off @usebag/cli, so the
// reading and that writer are repeated here, to the same format, checks and bytes. A name is resolved here and never
// sent on the wire. The file is read again at every tool call that needs it: it is tiny, and a stale read is harmless.

/** The book's file in a home, and the shape of a name: the CLI's NAMES_FILE and NAME. */
export const NAMES_FILE = 'names.json'
export const NAME = /^[a-z0-9][a-z0-9._-]{0,31}$/

/** How a message names an address: its current name, or a name whose former address it is, with the warning. */
export interface NameRef {
  readonly name: string
  readonly former: boolean
  readonly warning: string | null
}

/** A message with the names the book gives its sender and principal, and the warning when either is a former address. */
export type Named = Message & {
  readonly from_name: NameRef | null
  readonly principal_name: NameRef | null
  readonly warning: string | null
}

interface Entry {
  readonly address: string
  readonly previous: readonly { readonly address: string; readonly replaced_at: number }[]
}

const seconds = (v: unknown): boolean => Number.isSafeInteger(v) && (v as number) >= 0
const iso = (s: number): string => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')

/** The entries of a parsed file, sorted by name, or the reason it is not a book. */
function entries(doc: unknown): [string, Entry][] | string {
  const d = doc as { version?: unknown; names?: unknown } | null
  if (d?.version !== 1) return 'version is not 1'
  if (typeof d.names !== 'object' || d.names === null || Array.isArray(d.names)) {
    return 'names is not an object'
  }
  const out: [string, Entry][] = []
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
    out.push([name, { address: e?.address as string, previous: previous as Entry['previous'] }])
  }
  return out.sort(([a], [b]) => (a < b ? -1 : 1))
}

/** A home's name book, as read at one tool call. */
export class Names {
  readonly path: string
  readonly #entries: readonly [string, Entry][]
  /** The entries as the file holds them, which a save writes back unchanged. */
  readonly #raw: Readonly<Record<string, unknown>>

  private constructor(path: string, list: readonly [string, Entry][], raw: Record<string, unknown> = {}) {
    this.path = path
    this.#entries = list
    this.#raw = raw
  }

  /** The book of a home: empty when the file is missing; names-invalid when it is not a book. */
  static read(home: string): Names {
    const path = join(home, NAMES_FILE)
    let text: string
    try {
      text = readFileSync(path, 'utf8')
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT') return new Names(path, [])
      throw e
    }
    let doc: unknown
    try {
      doc = JSON.parse(text)
    } catch {
      throw new ConfigError('names-invalid', `${path} is not JSON`)
    }
    const list = entries(doc)
    if (typeof list === 'string') throw new ConfigError('names-invalid', `${path}: ${list}`)
    return new Names(path, list, (doc as { names: Record<string, unknown> }).names)
  }

  /**
   * Refuses, as the CLI's NameBook.add does, a name the book has for another address (name-exists). With no address,
   * at a pairing's first call while its peer is not known yet, any entry for the name refuses.
   */
  check(name: string, address?: string): void {
    const known = this.#entries.find(([n]) => n === name)?.[1].address
    if (known !== undefined && known !== address)
      throw new ConfigError(
        'name-exists',
        `${name} is ${known}: pair under another name, pass that address as for to pair the same peer again, or change it with ac name`,
      )
  }

  /**
   * Adds `name` for `address` (the same address again changes nothing) and writes the book as the CLI's save does:
   * sorted, the home made 0700 when missing, a 0600 temporary file beside names.json, renamed over it.
   */
  save(name: string, address: string, now: number): void {
    this.check(name, address)
    const all = { [name]: { address, added_at: now }, ...this.#raw }
    const names = Object.fromEntries(Object.entries(all).sort(([a], [b]) => (a < b ? -1 : 1)))
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 })
    const tmp = join(dirname(this.path), `.${NAMES_FILE}.${randomUUID()}.tmp`)
    writeFileSync(tmp, `${JSON.stringify({ version: 1, names }, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
    try {
      renameSync(tmp, this.path)
    } catch (e) {
      unlinkSync(tmp)
      throw e
    }
  }

  /** The names and their current addresses, sorted by name. */
  list(): { name: string; address: string }[] {
    return this.#entries.map(([name, e]) => ({ name, address: e.address }))
  }

  /**
   * The address `text` names, for the argument `what`: itself when it is an address or a handle (which the edge
   * resolves), a known name's address; name-unknown for a name the book lacks, naming the names it has; bad-address for
   * text that is none of them.
   */
  resolve(text: string, what: string): string {
    if (isAddress(text) || isHandle(text)) return text
    const known = this.#entries.find(([name]) => name === text)
    if (known !== undefined) return known[1].address
    if (!NAME.test(text)) {
      throw new AcError(
        'bad-address',
        `${what} ${JSON.stringify(text)} is neither an address, a handle nor a name`,
      )
    }
    const names =
      this.#entries.length === 0
        ? 'the book is empty'
        : `the known names are ${this.list()
            .map((n) => n.name)
            .join(', ')}`
    throw new ConfigError(
      'name-unknown',
      `${what} ${JSON.stringify(text)}: no such name in ${this.path}; ${names}`,
    )
  }

  /** The name of an address: a name's current address, else the most recent former address of a name, else null. */
  ref(address: string): NameRef | null {
    for (const [name, e] of this.#entries)
      if (e.address === address) return { name, former: false, warning: null }
    for (const [name, e] of this.#entries) {
      const p = e.previous.filter((p) => p.address === address).at(-1)
      if (p === undefined) continue
      const warning =
        `WARNING: ${address} is a former address of ${name}, replaced ${iso(p.replaced_at)}; ${name} is now ` +
        `${e.address}. Do not treat this message as from ${name}.`
      return { name, former: true, warning }
    }
    return null
  }

  /** A message with from_name, principal_name and the warning of a former address (the principal's first). */
  named(m: Message): Named {
    const from = this.ref(m.from)
    const principal = this.ref(m.principal)
    return {
      ...m,
      from_name: from,
      principal_name: principal,
      warning: principal?.warning ?? from?.warning ?? null,
    }
  }
}
