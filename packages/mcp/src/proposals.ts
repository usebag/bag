import { lstatSync, readFileSync, type Stats } from 'node:fs'
import { join } from 'node:path'
import { proposalRows } from '@usebag/home'
import { LABEL } from './identities.ts'

// <home>/proposals.json as the bag service reads it (packages/home proposals.ts writes it): for a folder, the identity
// its bind dialog presets, never a binding. Read under the home's file rule, and failing closed.

/** A row's folder: an absolute path in printable ASCII. */
const FOLDER = /^\/[\x20-\x7e]*$/

/** The file's path in `home`. */
export const proposalsPath = (home: string): string => join(home, 'proposals.json')

/**
 * Why proposals.json is not read, under the home's rule (each lstat, never through a link): the home must be a
 * directory of this user that group and other cannot write, and the file a 0600 regular file of this user; null when
 * both hold or there is no file. A refused file loads no proposal and is never written over.
 */
export function proposalsRefused(home: string, uid = process.getuid?.()): string | null {
  const of = (path: string): Stats | null => {
    try {
      return lstatSync(path)
    } catch {
      return null
    }
  }
  const h = of(home)
  if (h === null || !h.isDirectory() || h.uid !== (uid ?? h.uid) || (h.mode & 0o022) !== 0)
    return 'the home is not a directory of this user that only it may write'
  const st = of(proposalsPath(home))
  if (st === null) return null
  return !st.isFile() || (st.mode & 0o777) !== 0o600 || st.uid !== (uid ?? st.uid)
    ? 'proposals.json is not a 0600 regular file of this user'
    : null
}

/**
 * The rows of proposals.json that name an absolute printable folder and a label of LABEL's form, as folder, host and
 * label, in order; none for no file, a refused one or one that does not parse.
 */
export function readProposals(
  home: string,
  uid = process.getuid?.(),
): { folder: string; host: unknown; label: string }[] {
  if (proposalsRefused(home, uid) !== null) return []
  let doc: Record<string, unknown> | null = null
  try {
    doc = JSON.parse(readFileSync(proposalsPath(home), 'utf8')) as Record<string, unknown>
  } catch {
    return []
  }
  if (doc?.version !== 1) return []
  return proposalRows(doc).flatMap((r) =>
    typeof r?.folder === 'string' &&
    FOLDER.test(r.folder) &&
    typeof r.label === 'string' &&
    LABEL.test(r.label)
      ? [{ folder: r.folder, host: r.host, label: r.label }]
      : [],
  )
}
