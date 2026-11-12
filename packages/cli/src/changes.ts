import { createHash } from 'node:crypto'
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { CliError } from './args.ts'

// One change to one path of a host's wiring, worked out before anything is written, so the user-scope install and the
// migration can show every path, back each one up and journal it before the first write (host-user.ts, host-migrate.ts).

/** A path's next state: a file's whole text, a symbolic link's target, or gone. */
export interface Change {
  readonly path: string
  readonly text?: string
  readonly link?: string
  readonly gone?: true
  /** The mode of a file this writes when it was not there (a file there keeps its mode). */
  readonly mode?: number
  /** The line the output and the question name it by. */
  readonly note: string
}

/** A path as it was: absent, a file (its backup copy and mode), or a link (its target). */
export type Before =
  | { readonly kind: 'absent' }
  | { readonly kind: 'file'; readonly backup: string; readonly mode: number }
  | { readonly kind: 'link'; readonly target: string }

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')

/** The sha256 of what is at `path` now: a file's bytes, `link:<target>`, or `absent`. */
export function stateOf(path: string): string {
  try {
    const st = lstatSync(path)
    if (st.isSymbolicLink()) return `link:${readlinkSync(path)}`
    return sha(readFileSync(path))
  } catch {
    return 'absent'
  }
}

/** The state a change leaves at its path, as stateOf names it. */
export const stateAfter = (c: Change): string =>
  c.gone ? 'absent' : c.link !== undefined ? `link:${c.link}` : sha(c.text ?? '')

/** Copies what is at `path` into `dir` (its n-th backup) and says what it was. */
export function backup(path: string, dir: string, n: number): Before {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(path)
  } catch {
    return { kind: 'absent' }
  }
  if (st.isSymbolicLink()) return { kind: 'link', target: readlinkSync(path) }
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const to = join(dir, `${n}-${basename(path)}`)
  copyFileSync(path, to)
  return { kind: 'file', backup: to, mode: st.mode & 0o777 }
}

/** Puts `text` (a string or bytes) at `file`, beside and renamed over, keeping a file's mode or taking `mode`. */
function put(file: string, text: string | Buffer, mode = 0o600): void {
  mkdirSync(dirname(file), { recursive: true })
  let keep = mode
  try {
    keep = statSync(file).mode & 0o777
  } catch {
    // a new file: `mode`
  }
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, text, { mode: keep })
  renameSync(tmp, file)
}

/** Removes a file or link at `path`, when there. */
function drop(path: string): void {
  try {
    lstatSync(path)
  } catch {
    return
  }
  unlinkSync(path)
}

/** Makes one change, a link through a renamed temporary link. */
export function applyChange(c: Change): void {
  if (c.gone) {
    drop(c.path)
    return
  }
  if (c.link !== undefined) {
    mkdirSync(dirname(c.path), { recursive: true })
    const tmp = `${c.path}.${process.pid}.tmp`
    drop(tmp)
    symlinkSync(c.link, tmp)
    renameSync(tmp, c.path)
    return
  }
  put(c.path, c.text ?? '', c.mode)
}

/** Puts back what `before` says was at `path`. */
export function restore(path: string, before: Before): void {
  drop(path)
  if (before.kind === 'link') applyChange({ path, link: before.target, note: '' })
  if (before.kind !== 'file') return
  put(path, readFileSync(before.backup), before.mode)
}

type Json = Record<string, unknown>

/**
 * The next state of several paths, built up by edits before anything is written: a path's text as the edits so far
 * leave it (the disk's when none touched it), its link, or gone. `changes` lists what differs from the disk.
 */
export class View {
  readonly #next = new Map<string, Change>()

  /** A file's text as the edits leave it, or null when absent or gone. */
  text(path: string): string | null {
    const c = this.#next.get(path)
    if (c !== undefined) return c.gone || c.link !== undefined ? null : (c.text ?? '')
    try {
      return lstatSync(path).isFile() ? readFileSync(path, 'utf8') : null
    } catch {
      return null
    }
  }

  set(c: Change): void {
    const was = this.#next.get(c.path)
    this.#next.set(c.path, was === undefined ? c : { ...c, note: `${was.note}; ${c.note}` })
  }

  /**
   * Edits the JSON object at `path` (an empty one when absent): `edit` changes it in place and returns true when it
   * changed something. host-file-invalid for a file that is not a JSON object.
   */
  json(path: string, note: string, edit: (doc: Json) => boolean, mode = 0o600): void {
    let doc: unknown
    try {
      doc = JSON.parse(this.text(path) ?? '{}')
    } catch {
      // refused below
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
      throw new CliError('host-file-invalid', `${path} is not a JSON object`)
    }
    if (edit(doc as Json)) this.set({ path, text: `${JSON.stringify(doc, null, 2)}\n`, mode, note })
  }

  /** The changes that differ from the disk, in the order first touched. */
  changes(): Change[] {
    return [...this.#next.values()].filter((c) => stateAfter(c) !== stateOf(c.path))
  }
}
