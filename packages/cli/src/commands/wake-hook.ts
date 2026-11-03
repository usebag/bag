import {
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import {
  codexSessionName,
  psInfo,
  readSessionFile,
  type SessionNameOptions,
  sessionAnchor,
} from '@usebag/edge/agent'
import { CliError, flag, type Parsed, parse, req, str, UsageError } from '../args.ts'
import { checkIdentity, doorbellPath, homeCustody, homeDir } from '../home.ts'
import { keyOf, readIdentities } from '../identities.ts'
import type { Io } from '../io.ts'

/** How often wake-hook looks at the doorbell, in milliseconds. */
export const POLL_MS = 1000

/**
 * The seconds a Codex Stop hook waits for mail (`--max`). Short on purpose: the hook is awaited inline in the turn
 * loop and takes no cancellation from pending input (codex-rs core/src/session/turn.rs, core/src/hook_runtime.rs
 * run_turn_stop_hooks), so a message the person types waits out the wait; only an interrupt (Esc) ends it. Codex's own
 * default hook timeout is 600 s (hooks/src/engine/discovery.rs, normalize_command_hook). A lever, not a measure: raise
 * it for an unattended session that waits on peers.
 */
export const CODEX_STOP_WAIT = 30

/**
 * The `timeout` of that hook in hooks.json, above CODEX_STOP_WAIT. A hook that timed out would fail and the turn end
 * anyway (codex-rs hooks/src/events/stop.rs), so the margin is not a correctness need.
 */
export const CODEX_STOP_TIMEOUT = 60

/** The most of a Codex Stop hook's stdin that is read, in characters, and the longest it is waited for, in milliseconds. */
const STDIN_MAX = 65_536
const STDIN_MS = 2000

/** The doorbell's mtime in milliseconds as the OS gives it (fractional where it does), 0 for a file that is not there. */
function mtime(path: string): number {
  try {
    return statSync(path).mtimeMs
  } catch {
    return 0
  }
}

/** The number a one-line state file (wake-seen: an mtime; the lock: a pid) holds, NaN if missing or anything else. */
function numberIn(file: string): number {
  try {
    const text = readFileSync(file, 'utf8').trim()
    return /^\d+(\.\d+)?$/.test(text) ? Number(text) : Number.NaN
  } catch {
    return Number.NaN
  }
}

/** Whether pid is alive: kill 0 answers, or refuses EPERM (a process of another user). */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/**
 * Whether pid is a wake-hook: one word of its command line is `wake-hook` (Linux /proc/<pid>/cmdline, elsewhere ps
 * through psInfo), so a `vitest run wake-hook.test.ts` is not one; false when neither can say.
 */
function isWakeHook(pid: number): boolean {
  let words: string[]
  try {
    words = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')
  } catch {
    words = (psInfo(pid)?.command ?? '').split(/\s+/)
  }
  return words.includes('wake-hook')
}

/** How long a new hook waits for a signalled holder to let go of the lock, and its step, in milliseconds. */
const TAKEOVER_MS = 3000
const TAKEOVER_STEP_MS = 100

/**
 * Takes the lock file: the pid is written to a temp file beside it and linked into place, so the lock is never seen
 * empty and an existing one fails the link EEXIST. The newest hook takes over. A holder that is alive, not older than
 * `max` + 60 s and a wake-hook (isWakeHook) gets SIGTERM, which ends it 0, silent, and its release removes the
 * file; the wait is up to TAKEOVER_MS while the file still holds that pid and the pid lives. A lock still holding the
 * pid judged, or a stale one (dead pid, junk, too old, a live process that is no wake-hook), is then removed, and the
 * link tried once more: losing that race is null, so of two new hooks one links and the other ends. A holder that is
 * this process (a second watch in one process) is held: null, no signal. A hook signalled before it links gives up
 * (null). The release removes the file only while it still holds this pid. Residual, same user only: a pid reused
 * between the check and the SIGTERM, or the check-then-remove gap removing a newer lock, corrects itself at the next
 * look (watch) within about 1 s, at worst one duplicate wake, never a dropped one.
 */
async function lock(file: string, max: number, signal: AbortSignal): Promise<(() => void) | null> {
  const tmp = `${file}.${process.pid}`
  for (let tries = 0; ; tries++) {
    try {
      writeFileSync(tmp, `${process.pid}\n`, { mode: 0o600 })
      linkSync(tmp, file)
      return () => {
        if (numberIn(file) === process.pid) rmSync(file, { force: true })
      }
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'EEXIST') throw e
    } finally {
      rmSync(tmp, { force: true })
    }
    const pid = numberIn(file)
    const live =
      Number.isInteger(pid) && pid > 0 && Date.now() - mtime(file) <= (max + 60) * 1000 && alive(pid)
    if (tries > 0 || signal.aborted || (live && pid === process.pid)) return null
    if (live && isWakeHook(pid)) {
      try {
        process.kill(pid, 'SIGTERM')
      } catch {
        // gone already, or EPERM: the wait below decides
      }
      for (const end = Date.now() + TAKEOVER_MS; numberIn(file) === pid && alive(pid) && Date.now() < end; ) {
        await delay(TAKEOVER_STEP_MS)
      }
      if (signal.aborted) return null
    }
    if (Object.is(numberIn(file), pid)) rmSync(file, { force: true })
  }
}

/** A watched identity: its label, its doorbell, and its wake-seen, wake-idle and lock files. */
interface Bell {
  readonly label: string
  readonly bell: string
  readonly seen: string
  readonly idle: string
  readonly held: string
}

/** wake-seen written whole to a temp file beside it (O_EXCL, 0600), then renamed over it: a reader never sees it empty. */
function remember(seen: string, m: number): number {
  const tmp = `${seen}.${process.pid}`
  rmSync(tmp, { force: true })
  writeFileSync(tmp, `${m}\n`, { flag: 'wx', mode: 0o600 })
  renameSync(tmp, seen)
  return m
}

/** A whole-number option from 0 to `top`, or `dflt` when absent. */
function whole(p: Parsed, name: string, dflt: number, top: number): number {
  const v = str(p, name)
  if (v === undefined) return dflt
  if (!/^\d+$/.test(v) || Number(v) > top) {
    throw new UsageError(`--${name} is a whole number from 0 to ${top}, not ${JSON.stringify(v)}`)
  }
  return Number(v)
}

export type Wait = {
  end: number
  signal: AbortSignal
  pollMs: number
  session?: SessionNameOptions | undefined
}

/** The session's name from the MCP server's session file, polled for till w.end; null on abort; refusals throw CliError. */
export async function sessionNameOf(io: Io, home: string, who: string, w: Wait): Promise<string | null> {
  const anchor = sessionAnchor(w.session)
  let file = readSessionFile(home, anchor)
  for (; file === null; file = readSessionFile(home, anchor)) {
    if (w.signal.aborted) return null
    if (Date.now() >= w.end) throw new CliError('no-session-file', `no file for pid ${anchor.pid} in ${home}`)
    await delay(w.pollMs, undefined, { signal: w.signal }).catch(() => undefined)
  }
  if (file.principal !== homeCustody(io, home).entry(who).address) {
    throw new CliError('session-principal', `the session file is not ${who}'s address`)
  }
  return file.name
}

/**
 * The Stop hook's stdin through io.readLine, till the end of input, STDIN_MS (io.release ends a read that never
 * closes) or the line that passes STDIN_MAX characters, whichever is first, so a stdin that stays open cannot hang
 * the hook. The lines are joined by spaces, not newlines: readline also splits at U+2028 and U+2029, which a Stop
 * JSON carries raw inside `last_assistant_message`, and a space between JSON tokens or inside a string still parses.
 * Returns the parsed object's `session_id`, or, when the text does not parse (a Stop JSON cut at STDIN_MAX, its
 * reply long), the first unescaped `"session_id": "<value>"` in it: an id quoted inside the reply has its quotes
 * escaped and is not taken. Anything else is CliError `bad-hook-input`.
 */
async function stopSessionId(io: Io): Promise<string> {
  let text = ''
  const timer = setTimeout(() => io.release(), STDIN_MS)
  try {
    for (let l = await io.readLine(); l !== null && text.length <= STDIN_MAX; l = await io.readLine())
      text += `${l} `
  } finally {
    clearTimeout(timer)
  }
  let id: unknown
  try {
    id = (JSON.parse(text) as { session_id?: unknown } | null)?.session_id
  } catch {
    id = /"session_id"\s*:\s*"([^"\\]+)"/.exec(text)?.[1]
  }
  if (typeof id !== 'string') {
    throw new CliError(
      'bad-hook-input',
      'the hook input on stdin is not a JSON object with a string session_id',
    )
  }
  return id
}

/**
 * wake-hook --as <name> [--session auto|auto:codex] [--dir <home>] [--max <seconds>] [--exit-code <n>] [--no-idle-wake]
 * [--print]: for a host hook (a Claude Code asyncRewake hook, or a Codex Stop hook).
 * Polls the identity's doorbell once a second and compares its mtime with
 * the one in <home>/state/<name>/wake-seen (one line, 0600), the mtime this command last reported; the first run,
 * with no such file, takes the current mtime as the baseline and reports nothing. On a difference it stores the
 * new mtime, writes one stderr line telling the model to read the inbox, and returns the exit code (default 2, the
 * code that wakes the host); at --max seconds (default 3500) it wakes once per mail-free stretch (wake-idle),
 * then 0, silent, till a ring; with --no-idle-wake it is 0, silent, at --max and writes or removes no wake-idle (for a
 * host that spends a model turn on any wake, a Codex Stop hook: CODEX_STOP_WAIT).
 * With --print it instead writes `doorbell <mtime>` on stdout per change and
 * runs until SIGINT or SIGTERM, its baseline and last-seen in memory: it reads wake-seen, never writes it or wake-idle.
 * A missing doorbell reads as 0. Only one wake-hook of an identity runs at a time (wake-hook.lock beside wake-seen;
 * --print takes none), the newest: it ends the holder with SIGTERM (lock says when), and a holder that finds its lock
 * holding another pid ends 0, silent. It opens no edge and no store: the doorbell's mtime, wake-seen and the lock.
 * --session auto: --as is the principal's name; the name is read from the session file the MCP server wrote
 * for this Claude Code session (found by the process tree, polled for till --max). No Claude ancestor, no file
 * by --max and a file of another principal are exit 1; the stop signal ends 0, silent. Then that identity is awaited.
 * --session auto:codex (a Codex Stop hook): --as is the principal's name; the name is
 * codexSessionName(the principal's address, the `session_id` of the Stop JSON on stdin), which is the name the MCP
 * server `--session auto:codex` gave this Codex session at its first tool call (both are the root thread's id: codex-rs
 * core/src/hook_runtime.rs, run_turn_stop_hooks). stdin is read as stopSessionId says; JSON that is not an object with
 * a string `session_id` is exit 1 `bad-hook-input`, and an id that is not a uuid is exit 1 `no-session`. An identity
 * of that name that is not in the home yet (no tool call has bound the server) ends 0 at once, silent, with no wait:
 * nothing can ring. Otherwise that identity is watched as under auto.
 * wake-hook --identities <file> watches every identity of the
 * file, each by its own doorbell, wake-seen, wake-idle and lock in its own state directory; it takes no --as, --session
 * or --dir. It takes the locks all or none: one it loses ends it 0, silent, the ones taken released. A ring names the identity's label (several
 * rung in one poll: one line naming each); the line at --max is one for all, skipped while every identity holds its
 * wake-idle; --print writes `doorbell <label> <mtime>`. An identity its home lacks, or whose key is refused, is skipped
 * with one stderr line naming its label, and the rest are watched; none left is exit 1, no-identity.
 */
export async function wakeHook(
  args: readonly string[],
  io: Io,
  pollMs = POLL_MS,
  session?: SessionNameOptions,
): Promise<number> {
  const options = {
    as: { type: 'string' },
    dir: { type: 'string' },
    max: { type: 'string' },
    'exit-code': { type: 'string' },
    'no-idle-wake': { type: 'boolean' },
    print: { type: 'boolean' },
    session: { type: 'string' },
    identities: { type: 'string' },
  } as const
  const p = parse(args, { positionals: [], options })
  const [file, principal, auto] = [str(p, 'identities'), str(p, 'as'), str(p, 'session')]
  if (file !== undefined && (principal !== undefined || auto !== undefined || str(p, 'dir') !== undefined)) {
    throw new UsageError('--identities takes no --as, --session or --dir: each identity is in the file')
  }
  if (file === undefined && principal === undefined) throw new UsageError('--as is required')
  if (auto !== undefined && auto !== 'auto' && auto !== 'auto:codex') {
    throw new UsageError(`--session takes auto or auto:codex, not ${auto}`)
  }
  const [max, code, print] = [whole(p, 'max', 3500, 2e6), whole(p, 'exit-code', 2, 255), flag(p, 'print')]
  const [end, signal, quiet] = [Date.now() + max * 1000, io.stopSignal(), flag(p, 'no-idle-wake')]
  if (file !== undefined) {
    // One identity failing never stops the others (the design's section 7): it is skipped with one line.
    const bells: Bell[] = []
    for (const e of readIdentities(file).identities) {
      try {
        checkIdentity(io, e.home, keyOf(e))
        bells.push(bellOf(e.home, keyOf(e), e.label))
      } catch (x) {
        io.err(`bag: ${e.label} skipped: ${(x as Error).message}`)
      }
    }
    if (bells.length === 0) throw new CliError('no-identity', `no identity of ${file} can be watched`)
    return watchAll(bells)
  }
  const home = homeDir(io, str(p, 'dir'))
  let name = principal as string
  if (auto === 'auto') {
    const found = await sessionNameOf(io, home, name, { end, signal, pollMs, session })
    if (found === null) return 0
    name = found
  } else if (auto === 'auto:codex') {
    name = codexSessionName(homeCustody(io, home).entry(name).address, await stopSessionId(io))
  }
  for (;;) {
    try {
      checkIdentity(io, home, name)
      break
    } catch (e) {
      if (auto === undefined || (e as { code?: unknown }).code !== 'ENOENT') throw e
      if (auto === 'auto:codex') return 0
      if (Date.now() >= end || signal.aborted) return 0
      await delay(pollMs, undefined, { signal }).catch(() => undefined)
    }
  }
  return watchAll([bellOf(home, name, name)])

  /** An identity's doorbell and the files beside it, its state directory made 0700 when missing. */
  function bellOf(at: string, key: string, label: string): Bell {
    const state = join(at, 'state', key)
    mkdirSync(state, { recursive: true, mode: 0o700 })
    const f = (n: string): string => join(state, n)
    return {
      label,
      bell: doorbellPath(at, key),
      seen: f('wake-seen'),
      idle: f('wake-idle'),
      held: f('wake-hook.lock'),
    }
  }

  /**
   * Two hooks of one session (SessionStart and every Stop) run at once: the second takes the lock over from the first,
   * which ends silently, and a race lost ends silently before it touches wake-seen. Every lock is taken or none: the
   * ones taken are released. --print takes none.
   */
  async function watchAll(bells: readonly Bell[]): Promise<number> {
    const releases: (() => void)[] = []
    try {
      for (const b of print ? [] : bells) {
        const release = await lock(b.held, max, signal)
        if (release === null) return 0
        releases.push(release)
      }
      return await watch(bells)
    } finally {
      for (const release of releases) release()
    }
  }

  async function watch(bells: readonly Bell[]): Promise<number> {
    // --print keeps its baseline and what it saw in memory: wake-seen and wake-idle are the hooks' alone.
    const last = bells.map((b) => {
      const m = numberIn(b.seen)
      return !Number.isNaN(m) ? m : print ? mtime(b.bell) : remember(b.seen, mtime(b.bell))
    })
    for (;;) {
      // Signalled, or a lock that holds another pid (a newer hook took over): it ends 0, silent. A lock that is gone
      // for a moment (a newer hook removed it and links next) is not lost: better a second wake than none.
      if (
        !print &&
        (signal.aborted || bells.some((b) => ![process.pid, Number.NaN].includes(numberIn(b.held))))
      )
        return 0
      const rung = bells.filter((b, i) => {
        const m = mtime(b.bell)
        if (m === last[i]) return false
        last[i] = m
        if (print) io.out(file === undefined ? `doorbell ${m}` : `doorbell ${b.label} ${m}`)
        else {
          rmSync(b.idle, { force: true })
          remember(b.seen, m)
        }
        return true
      })
      if (!print && rung.length > 0) {
        const to = rung.map((b) => b.label).join(', ')
        io.err(
          file === undefined
            ? `bag: a message was delivered to ${to}; read it with the inbox tool and report it`
            : rung.length === 1
              ? `bag: a message was delivered to ${to}; read it with the inbox tool as ${to} and report it`
              : `bag: a message was delivered to each of ${to}; read each with the inbox tool as its label and report it`,
        )
        return code
      }
      if (!print && Date.now() >= end) {
        if (max === 0 || quiet || bells.every((b) => numberIn(b.idle) === 1)) return 0
        for (const b of bells) {
          rmSync(b.idle, { force: true })
          writeFileSync(b.idle, '1\n', { flag: 'wx', mode: 0o600 })
        }
        const who = file === undefined ? bells[0]?.label : 'any identity'
        io.err(`bag: no message for ${who} in ${max} s`)
        return code
      }
      await delay(pollMs, undefined, { signal }).catch(() => undefined)
      if (signal.aborted) return 0
    }
  }
}

/** session-code (packages/cli/README.md): waits up to waitMs for the grant request, prints its code as JSON. */
export async function sessionCode(
  args: readonly string[],
  io: Io,
  pollMs = 250,
  session?: SessionNameOptions,
  waitMs = 10_000,
): Promise<number> {
  const options = { as: { type: 'string' }, dir: { type: 'string' }, session: { type: 'string' } } as const
  const p = parse(args, { positionals: [], options, required: ['as', 'session'] })
  if (str(p, 'session') !== 'auto') throw new UsageError('--session takes only auto')
  const [home, signal, end] = [homeDir(io, str(p, 'dir')), io.stopSignal(), Date.now() + waitMs]
  const name = await sessionNameOf(io, home, req(p, 'as'), { end, signal, pollMs, session })
  while (name !== null && !signal.aborted && !existsSync(join(home, 'state', name, 'grant.json'))) {
    let r: { v?: unknown; code?: unknown } = {}
    try {
      r = JSON.parse(readFileSync(join(home, 'state', name, 'grant-request.json'), 'utf8'))
    } catch {
      // absent, or not whole yet: the same as no request, and the poll goes on
    }
    if (r.v === 1 && typeof r.code === 'string') {
      const m = `bag: session ${name} waits for y at the agent, request code ${r.code}. Type y there only if the codes match.`
      const hookSpecificOutput = { hookEventName: 'SessionStart', additionalContext: m }
      io.out(JSON.stringify({ systemMessage: m, hookSpecificOutput }))
      break
    }
    if (Date.now() >= end) break
    await delay(pollMs, undefined, { signal }).catch(() => undefined)
  }
  return 0
}
