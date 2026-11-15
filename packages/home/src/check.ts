import { lstatSync, readdirSync, readlinkSync, statSync } from 'node:fs'
import { isAbsolute, join, relative } from 'node:path'

// What an act read before its question, as plain values under short names, that askWithRecheck compares after the
// person's yes. A file is read by its metadata only, never its contents: a key file's secret stays unread, and a FIFO
// cannot block the read. A link is read as itself and as what it points to, so a target rewritten behind it differs.

const code = (e: unknown): string => String((e as { code?: unknown }).code)

/**
 * The state of `path` as a plain value: null when absent; for a file its inode, size, mode, owner, mtime and ctime, so
 * a write, a rename over it or a chmod differs; for a link the same of the link, its target text, and the inode, size,
 * mtime and ctime of what it points to ('dangling' when nothing); for a directory its sorted entries. Never throws:
 * an error is its code.
 */
export function stateOf(path: string): unknown {
  try {
    const st = lstatSync(path)
    if (st.isDirectory()) return { dir: readdirSync(path).sort() }
    const own = {
      ino: st.ino,
      size: st.size,
      mode: st.mode,
      uid: st.uid,
      mtime: st.mtimeMs,
      ctime: st.ctimeMs,
    }
    if (!st.isSymbolicLink()) return own
    let target: unknown
    try {
      const t = statSync(path)
      target = { ino: t.ino, size: t.size, mtime: t.mtimeMs, ctime: t.ctimeMs }
    } catch (e) {
      target = code(e) === 'ENOENT' ? 'dangling' : { error: code(e) }
    }
    return { ...own, link: readlinkSync(path), target }
  } catch (e) {
    return code(e) === 'ENOENT' ? null : { error: code(e) }
  }
}

/** The states of each path, in order. */
export const statesOf = (paths: readonly string[]): unknown[] => paths.map(stateOf)

/**
 * The short name of `path` in a refusal: relative to `home` when inside it, ~/ and the rest when inside the person's
 * `userHome`, else the path itself.
 */
export function shortName(path: string, home: string, userHome?: string): string {
  const inside = (root: string): string | null => {
    const r = relative(root, path)
    return r !== '' && !r.startsWith('..') && !isAbsolute(r) ? r : null
  }
  const inHome = inside(home)
  if (inHome !== null) return inHome
  const inUser = userHome ? inside(userHome) : null
  return inUser !== null ? join('~', inUser) : path
}

/** The state of each path, under its short name (shortName). */
export function namedStates(
  home: string,
  userHome: string | undefined,
  paths: readonly string[],
): Record<string, unknown> {
  return Object.fromEntries(paths.map((p) => [shortName(p, home, userHome), stateOf(p)]))
}
