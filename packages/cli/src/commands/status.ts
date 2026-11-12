import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AuditLine,
  parseAuditLine,
  proxyStatus,
  readAuditAnchor,
  readAuditLines,
  verifyAuditLog,
} from '@usebag/edge'
import { chainText, enterpriseStatus } from '@usebag/enterprise-client'
import { CliError, flag, parse, req, str, UsageError } from '../args.ts'
import { describeHolder, holder } from '../held.ts'
import { checkIdentity, doorbellPath, homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { instant } from '../names.ts'
import { runPath, serviceLine } from '../service.ts'
import { deps, refresherJob } from './refresher.ts'

/** The detail of the edge's end of a subscription (receiver.ts, run). */
type Ended = { readonly relay: string; readonly refusals: number; readonly end: 'subscription-ended' }

/** The end a subscribe line records: a reject whose detail has the edge's shape, else null. */
function ended(line: AuditLine | undefined): Ended | null {
  if (line?.decision !== 'reject') return null
  const d = JSON.parse(line.detail ?? 'null') as Partial<Ended> | null
  const ok = typeof d?.relay === 'string' && typeof d.refusals === 'number' && d.end === 'subscription-ended'
  return ok ? (d as Ended) : null
}

/**
 * status --as <name> [--dir <home>]: first, always, `doorbell <path>`, the identity's doorbell (home.ts),
 * an absolute path whether or not the file exists yet (inbox makes it at the first accepted message). Behind a proxy,
 * then `network proxy https=<scheme://host:port|none> http=<...> no_proxy=<list|none> active=<yes|no: ...>`, the
 * proxy without its user or password (the edge's proxy.ts); active says whether Node sends through it. Then what the
 * identity's audit log, <home>/state/<name>/audit.jsonl, says of its subscriptions. When the log's last
 * `subscribe` line is the edge's end of a subscription, `subscribe reject <code>` with `subscription-ended` (three
 * permanent refusals in a row), it prints a second line: `mailbox refused: <code> at <relay> after <n> refusals; edge
 * errors <e>, last <code> at <time>`; otherwise nothing more. <e> is like the
 * MCP server's edge_errors but counts the log's audited subscribe errors (retry and reject lines, three per end). The
 * line names a relay, not a mailbox, though the subscribe lines now carry the mailbox (older ones carry none) and the
 * log holds the identity's own subscriptions and its groups' (inbox --group): this code does not read the field. The
 * edge audits no subscription that succeeds, so the line stays after a later inbox subscribed, until any later
 * `subscribe retry` line, whatever its mailbox, follows it (one refusal or one coded transient error). A log whose
 * chain or anchor (edge.sqlite beside it, read first, as audit verify reads it) does not verify is bad-audit. No key
 * is read: the custody checks the name, and a stat finds the identity.
 */
export function status(args: readonly string[], io: Io): number | Promise<number> {
  if (!args.some((a) => a === '--as' || a.startsWith('--as='))) return enterprise(args, io)
  const options = { as: { type: 'string' }, dir: { type: 'string' } } as const
  const p = parse(args, { positionals: [], options, required: ['as'] })
  const [home, name] = [homeDir(io, str(p, 'dir')), req(p, 'as')]
  checkIdentity(io, home, name)
  io.out(`doorbell ${doorbellPath(home, name)}`)
  const held = holder(home, name)
  if (held !== null) io.out(`held_by ${describeHolder(held)}`)
  // A bag service of the home: one line from its hello (service.ts), before the rest.
  if (existsSync(runPath(home, 'service.sock'))) {
    return serviceLine(home).then((line) => {
      if (line !== null) io.out(line)
      return rest(io, home, name)
    })
  }
  return rest(io, home, name)
}

/** status --as after its first lines: the proxy and what the audit log says of the subscriptions. */
function rest(io: Io, home: string, name: string): number {
  // Behind a proxy, the proxy this process sends through: scheme, host and port only, never a user or password.
  const net = proxyStatus(io.env)
  if (net.https !== null || net.http !== null) {
    const shown = `https=${net.https ?? 'none'} http=${net.http ?? 'none'} no_proxy=${net.no_proxy ?? 'none'}`
    io.out(`network proxy ${shown} active=${net.active ? 'yes' : 'no: set NODE_USE_ENV_PROXY=1'}`)
  }
  const dir = join(home, 'state', name)
  const [file, db] = [join(dir, 'audit.jsonl'), join(dir, 'edge.sqlite')]
  // The anchor before the lines: the edge appends a line, then moves its anchor, so a log read beside a running
  // inbox is at worst ahead of the anchor read before it, never short of it.
  const anchor = existsSync(db) ? readAuditAnchor(db, 'audit.jsonl') : null
  const lines = readAuditLines(file)
  const chain = verifyAuditLog(lines, anchor)
  if (!chain.ok) throw new CliError('bad-audit', `${file} line ${chain.line}: ${chain.problem}`)
  const subscribe = lines.map(parseAuditLine).filter((l) => l.event === 'subscribe')
  const last = subscribe.at(-1)
  const end = ended(last)
  if (last === undefined || end === null) return 0
  const n = subscribe.filter((l) => l.decision === 'retry' || l.decision === 'reject').length
  const errors = `edge errors ${n}, last ${last.reason} at ${instant(last.ts)}`
  io.out(`mailbox refused: ${last.reason} at ${end.relay} after ${end.refusals} refusals; ${errors}`)
  return 0
}

/**
 * status [--org <domain>] [--chain | --plist | --crontab] [--dir <home>], no --as: the enterprise session of --org, the
 * only one, or the most recently connected (named on stderr; all refreshed), after one tick. --chain prints the chain
 * JSON for an MCP server's --chain-cmd; --plist and --crontab print the hourly job that runs this status, and write
 * nothing. Exit 0 live, 1 a failed refresh or probe, 3 ended or not signed in, 4 frozen, paused or waiting.
 */
async function enterprise(args: readonly string[], io: Io): Promise<number> {
  const modes = {
    chain: { type: 'boolean' },
    plist: { type: 'boolean' },
    crontab: { type: 'boolean' },
  } as const
  const text = { type: 'string' } as const
  const p = parse(args, { positionals: [], options: { ...modes, dir: text, org: text } })
  const [home, org] = [homeDir(io, str(p, 'dir')), str(p, 'org')]
  const d = { ...deps(io, home), note: (l: string) => io.err(l), ...(org === undefined ? {} : { org }) }
  if (Object.keys(modes).filter((o) => flag(p, o)).length > 1)
    throw new UsageError('--chain, --plist and --crontab go alone')
  if (flag(p, 'plist') || flag(p, 'crontab')) io.out(refresherJob(home, flag(p, 'plist')))
  else if (flag(p, 'chain')) io.out(await chainText(d))
  else return enterpriseStatus(d)
  return 0
}
