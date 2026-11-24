import { createHash } from 'node:crypto'
import { appendFileSync, closeSync, existsSync, fstatSync, openSync, readFileSync, readSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { AuditScan, AuditSink } from '../ports.ts'

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

  /** This file, or the file `name` beside it, past its first `from` bytes (AuditSink.scan). */
  scan(name: string | null, from: number): AuditScan | null {
    return scanAuditFile(name === null ? this.#path : join(dirname(this.#path), name), from)
  }
}

/**
 * Reads an audit file once: the sha256 of its first `from` bytes, in 1 MiB reads (no line is parsed), then the rest
 * as lines; extend(count) gives the prefix that ends after the first `count` of them, hashed from the same state. Null
 * when the file does not exist.
 */
export function scanAuditFile(path: string, from: number): AuditScan | null {
  let fd: number
  try {
    fd = openSync(path, 'r')
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw e
  }
  try {
    const size = fstatSync(fd).size
    const h = createHash('sha256')
    if (size < from) return { head: null, lines: [], complete: 0, extend: () => ({ bytes: 0, digest: '' }) }
    const chunk = Buffer.allocUnsafe(1 << 20)
    for (let at = 0; at < from; ) {
      const n = readSync(fd, chunk, 0, Math.min(chunk.length, from - at), at)
      if (n === 0) return { head: null, lines: [], complete: 0, extend: () => ({ bytes: 0, digest: '' }) }
      h.update(chunk.subarray(0, n))
      at += n
    }
    const head = h.copy().digest('hex')
    const rest = Buffer.alloc(size - from)
    for (let at = 0; at < rest.length; ) {
      const n = readSync(fd, rest, at, rest.length - at, from + at)
      if (n === 0) break
      at += n
    }
    // The end of each complete line (just past its newline), so that a prefix never ends inside a line.
    const ends: number[] = []
    for (let i = rest.indexOf(10); i >= 0; i = rest.indexOf(10, i + 1)) ends.push(i + 1)
    const lines = ends.map((end, k) => rest.toString('utf8', k === 0 ? 0 : (ends[k - 1] as number), end - 1))
    const tail = ends.at(-1) ?? 0
    if (tail < rest.length) lines.push(rest.toString('utf8', tail))
    return {
      head,
      lines,
      complete: ends.length,
      extend(count) {
        if (!Number.isInteger(count) || count < 0 || count > ends.length)
          throw new Error('fs-audit: a prefix ends after a complete line')
        const end = count === 0 ? 0 : (ends[count - 1] as number)
        return { bytes: from + end, digest: h.copy().update(rest.subarray(0, end)).digest('hex') }
      },
    }
  } finally {
    closeSync(fd)
  }
}
