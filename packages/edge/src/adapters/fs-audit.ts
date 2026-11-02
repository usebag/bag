import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { AuditSink } from '../ports.ts'

// The audit log as an append-only JSONL file, mode 0600. One edge process writes one file: the SQLite store of the
// same state directory holds its writer lock (sqlite-store.ts), and its anchor, keyed by the file's name. A tool
// that audits beside a live edge writes a file of its own, never the edge's.

/** The lines of an audit file, without the final newline; none when the file does not exist. */
export function readAuditLines(path: string): string[] {
  if (!existsSync(path)) return []
  const lines = readFileSync(path, 'utf8').split('\n')
  if (lines.at(-1) === '') lines.pop()
  return lines
}

/** An AuditSink on a JSONL file. */
export class FsAuditSink implements AuditSink {
  readonly #path: string
  /** The file's name, which keys its anchor in the edge store: `audit.jsonl` in the CLI's and the MCP server's homes. */
  readonly name: string

  constructor(path: string) {
    this.#path = path
    this.name = basename(path)
  }

  /** Appends one line and its newline. */
  append(line: string): void {
    if (line.includes('\n')) throw new Error('fs-audit: an audit line holds no newline')
    appendFileSync(this.#path, `${line}\n`, { mode: 0o600 })
  }

  /** The last line, to continue the chain; null for an empty or missing file. */
  last(): string | null {
    return readAuditLines(this.#path).at(-1) ?? null
  }

  /** Every line, so that a new edge can find the line its anchor names. */
  read(): string[] {
    return readAuditLines(this.#path)
  }

  /** The lines of the audit file `name` beside this one; null when it is not there. */
  peer(name: string): string[] | null {
    const file = join(dirname(this.#path), name)
    return existsSync(file) ? readAuditLines(file) : null
  }
}
