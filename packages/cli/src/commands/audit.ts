import { existsSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import {
  checkAuditAnchor,
  connectionOf,
  parseAuditLine,
  readAuditAnchors,
  readAuditLines,
  verifyAuditLog,
} from '@usebag/edge'
import { CliError, parse, UsageError } from '../args.ts'
import type { Io } from '../io.ts'

/**
 * audit verify <file>: recomputes the hash chain of an edge's audit log (spec/SPEC.md §9.8) with the edge's verifier,
 * and, when the file has an edge store beside it (`edge.sqlite`, as in `<home>/state/<name>/`), compares the log with
 * the anchor the store keeps of it. Prints `ok <n> lines`, or `bad line <n>: <problem>` for the first line
 * that was edited, removed or reordered; then `truncated: ...` when the log is shorter than its anchor, `diverged: ...`
 * when the line at the anchor has another hash, or `ahead: ...` when lines follow the anchor (a crash between an
 * append and its anchor leaves one). Exits 1 on a bad line, `truncated` or `diverged`. A log the bag service has
 * written to (its lines carry `connection`) also prints `connections: <a> name one, <b> name none, <c> before the
 * service`; a log with no such line prints exactly as before.
 */
export function audit(args: readonly string[], io: Io): number {
  const [verb, ...rest] = args
  if (verb !== 'verify') throw new UsageError('audit verify <file>')
  const file = parse(rest, { positionals: ['file'], options: {} }).positionals[0] as string
  if (!existsSync(file)) throw new CliError('ENOENT', `${file} does not exist`)
  const store = join(dirname(file), 'edge.sqlite')
  const anchors = existsSync(store) ? readAuditAnchors(store) : []
  const anchor = anchors.find((a) => a.name === basename(file)) ?? null
  const lines = readAuditLines(file)
  const chain = verifyAuditLog(lines)
  const check = anchor === null ? null : checkAuditAnchor(lines, anchor)
  const broken = check?.state === 'truncated' || check?.state === 'diverged'
  if (!chain.ok) io.out(`bad line ${chain.line}: ${chain.problem}`)
  else if (!broken) io.out(`ok ${chain.lines} lines`)
  if (chain.ok) {
    const of = lines.map((l) => connectionOf(parseAuditLine(l)))
    const named = of.filter((c) => typeof c === 'string').length
    const none = of.filter((c) => c === null).length
    if (named + none > 0)
      io.out(
        `connections: ${named} name one, ${none} name none, ${of.length - named - none} before the service`,
      )
  }
  if (check?.state === 'truncated') {
    io.out(`truncated: the log has ${check.lines} lines; its anchor in ${store} is at line ${check.seq}`)
  } else if (check?.state === 'diverged') {
    io.out(`diverged: line ${check.seq} of the log does not have the hash of its anchor in ${store}`)
  } else if (check?.state === 'ahead') {
    io.out(`ahead: its anchor in ${store} is at line ${check.seq} of ${check.lines}`)
  }
  // The anchor rows are the list of the files that must exist (the last-mile rulings, section 5): the rest of the set.
  let whole = true
  for (const a of anchors.filter((a) => a.name !== basename(file))) {
    const other = join(dirname(file), a.name)
    const verdict = existsSync(other) ? verifyAuditLog(readAuditLines(other), a) : null
    if (verdict === null)
      io.out(`missing: ${a.name} is anchored at line ${a.seq} in ${store} and is not there`)
    else if (verdict.ok) io.out(`${a.name}: ok ${verdict.lines} lines`)
    else io.out(`${a.name}: bad line ${verdict.line}: ${verdict.problem}`)
    whole &&= verdict?.ok === true
  }
  return chain.ok && !broken && whole ? 0 : 1
}
