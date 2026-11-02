import { type ChildProcessByStdio, spawn } from 'node:child_process'
import type { Writable } from 'node:stream'
import { parseEnvelope, type SealedContent } from '@usebag/core'
import type { InboxRow } from '@usebag/edge'
import { UsageError } from '../args.ts'
import type { Io } from '../io.ts'
import { inbox, REFUSED, shownType } from './inbox.ts'

// inbox --watch: the live inbox, its refusals on stderr, and with --exec a command run per
// accepted message with its summary, never its body, on stdin. The process is the identity's one receiver (the edge's
// writer lock), so it watches no file: the doorbell serves a process that is not the receiver, such as a
// Claude Code session watching the MCP server's doorbell.

/** The shell --exec runs its command with. */
export const SHELL = '/bin/sh'

/** After --exec-timeout's SIGTERM, a command still alive this long (ms) gets SIGKILL. */
export const KILL_GRACE_MS = 5000

/**
 * What --exec reads of an accepted row: `message <id> from <address>, type <type>`, the same three fields as the MCP
 * server's push notice (mcp/push) without the notice's trailing sentence; a type that is not a short token is
 * `(not shown)` (shownType); never the body.
 */
export function summary(row: InboxRow): string {
  const env = parseEnvelope(row.bytes)
  const { type } = JSON.parse(row.content as string) as SealedContent
  return `message ${env.id} from ${env.from}, type ${shownType(type)}`
}

/**
 * Runs `cmd` with `<shell> -c`, `line` and a newline on its stdin, and resolves when it has exited; it never rejects.
 * The command's stdout goes to our stderr, its stderr to our stderr: the watch's stdout stays its own lines.
 * The first failure is one line on stderr, and only the first: a spawn that throws or errors (an error may or may not
 * be followed by a close), a stdin the command closed unread (EPIPE, ECONNRESET or ENOTCONN, all three the fixed detail
 * `stdin closed unread`), a non-zero exit or a signal.
 * With `limit`, a run past `secs` (0: no limit) gets SIGTERM and, `graceMs` later, SIGKILL if it still lives, one
 * stderr line each. The signal goes to the shell only: a grandchild it started may outlive the kill.
 */
export function runExec(
  cmd: string,
  line: string,
  io: Io,
  shell: string,
  limit?: { id: string; secs: number; graceMs?: number },
): Promise<void> {
  const timers: NodeJS.Timeout[] = []
  return new Promise<void>((resolve) => {
    let failed = false
    const fail = (detail: string): void => {
      if (!failed) io.err(`bag: exec-failed: ${detail}`)
      failed = true
    }
    try {
      // fd 2 by number (no Stream type for it), so the typing of a piped stdin is stated here.
      const stdio: ['pipe', number, 'inherit'] = ['pipe', 2, 'inherit']
      const child = spawn(shell, ['-c', cmd], { stdio }) as ChildProcessByStdio<Writable, null, null>
      // A spawn error may or may not be followed by a close (Node's docs); either one resolves.
      child.on('error', (e) => {
        fail(e.message)
        resolve()
      })
      child.stdin.on('error', (e: NodeJS.ErrnoException) =>
        fail(['EPIPE', 'ECONNRESET', 'ENOTCONN'].includes(e.code ?? '') ? 'stdin closed unread' : e.message),
      )
      child.on('close', (code, signal) => {
        if (code !== 0) fail(`exit ${code ?? signal}`)
        resolve()
      })
      child.stdin.end(`${line}\n`)
      if (limit !== undefined && limit.secs > 0) {
        const kill = (sig: NodeJS.Signals): void => {
          io.err(`bag: exec-timeout: message ${limit.id} got ${sig} after ${limit.secs} s`)
          child.kill(sig)
        }
        const term = (): void => {
          kill('SIGTERM')
          timers.push(setTimeout(() => kill('SIGKILL'), limit.graceMs ?? KILL_GRACE_MS))
        }
        timers.push(setTimeout(term, limit.secs * 1000))
      }
    } catch (e) {
      fail((e as Error).message)
      resolve()
    }
  }).finally(() => {
    for (const t of timers) clearTimeout(t)
  })
}

/** inbox's arguments without --watch, --exec and --exec-timeout; the command and its limit in seconds (default 120). */
export function watchArgs(args: readonly string[]): { rest: string[]; exec: string | null; secs: number } {
  const rest: string[] = []
  let [exec, watching, secs]: [string | null, boolean, number] = [null, false, 120]
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string
    if (a === '--watch') watching = true
    else if (a === '--exec' || a.startsWith('--exec=')) {
      if (exec !== null) throw new UsageError('--exec is given once')
      exec = a === '--exec' ? (args[++i] ?? '') : a.slice('--exec='.length)
      if (exec === '' || exec.startsWith('--')) throw new UsageError('--exec needs a command')
    } else if (a === '--exec-timeout' || a.startsWith('--exec-timeout=')) {
      const v = a === '--exec-timeout' ? (args[++i] ?? '') : a.slice('--exec-timeout='.length)
      const bad = !/^\d+(\.\d+)?$/.test(v) || Number(v) > 2e6
      if (bad) throw new UsageError('--exec-timeout needs seconds (0: none)')
      secs = Number(v)
    } else rest.push(a)
  }
  if (!watching) throw new UsageError('--exec needs --watch')
  const no = rest.find((a, i) => ['--once', '--quarantined'].includes(a) || (i === 0 && !a.startsWith('-')))
  if (no !== undefined) throw new UsageError(`--watch takes no ${no}`)
  return { rest, exec, secs }
}

/**
 * inbox --watch [--exec <cmd>] with inbox's other options (not --once, --quarantined, release or drop): the live
 * inbox, each accepted message's line printed at once as inbox prints it, and a refusal's or a hold's line (`reject
 * ...`, `quarantined ...`) on stderr, never on stdout. Its stdout holds three kinds of line: `doorbell <path>` first
 * (--doorbell-path), with --group `group-key ...` lines during the first pass, among that pass's `accept` lines, then
 * `accept` lines only. --exec runs once per accepted message,
 * after its line prints, with its summary on stdin, one run at a time in arrival order. SIGINT or SIGTERM stops the
 * edge (inbox returns 0); the runs still pending then finish before it exits. A run has --exec-timeout seconds
 * (default 120, 0: none); the queue of pending runs is unbounded (a known gap).
 */
export async function watch(args: readonly string[], io: Io): Promise<number> {
  const { rest, exec, secs } = watchArgs(args)
  // The chain orders the --exec runs; a run that failed in any way still lets the next one start.
  let done = Promise.resolve()
  // A line goes by its row's state, as rowLine decides it, never by the printed text: a forged type cannot move a line.
  const shown = (row: InboxRow, line: string): void => {
    const refused = REFUSED.has(row.state)
    if (refused) io.err(line)
    else io.out(line)
    if (exec === null || refused) return
    const id = parseEnvelope(row.bytes).id
    const run = (): Promise<void> => runExec(exec, summary(row), io, SHELL, { id, secs })
    done = done.then(run, run)
  }
  try {
    return await inbox(rest, io, shown)
  } finally {
    await done
  }
}
