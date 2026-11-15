import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Json } from './host-common.ts'
import { HomeError } from './ports.ts'

// <home>/proposals.json: for a folder, the identity the bag service presets in its bind dialog there (a default, never
// a binding). host migrate writes a row for each folder it moves; the service's host_wire writes and removes rows.

/** The rows of a parsed proposals.json: none for no file, or for a file that lists none. */
export const proposalRows = (doc: Json | null): Json[] =>
  Array.isArray(doc?.proposals) ? (doc.proposals as Json[]) : []

/** The whole text of proposals.json holding `rows`, in order. */
export const proposalsText = (rows: readonly Json[]): string =>
  `${JSON.stringify({ version: 1, proposals: rows }, null, 2)}\n`

/**
 * Changes the rows of <home>/proposals.json: read, changed, written beside it (0600) and renamed in, so a reader sees
 * the old file or the new one whole. A file there that does not read as JSON is refused, never written over.
 */
export function writeProposals(home: string, change: (rows: Json[]) => Json[], pid = process.pid): Json[] {
  const file = join(home, 'proposals.json')
  let doc: Json | null = null
  try {
    doc = JSON.parse(readFileSync(file, 'utf8')) as Json
  } catch (e) {
    if ((e as { code?: unknown }).code !== 'ENOENT')
      throw new HomeError('unsafe-path', `${file} does not read as proposals: it is not written over`)
  }
  const rows = change(proposalRows(doc))
  const tmp = `${file}.${pid}.tmp`
  rmSync(tmp, { force: true })
  writeFileSync(tmp, proposalsText(rows), { mode: 0o600 })
  renameSync(tmp, file)
  return rows
}
