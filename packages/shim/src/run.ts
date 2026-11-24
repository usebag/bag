// The shim as a process: bag-shim [--dir <home>] [--input-hook] runs the proxy on stdio until stdin ends, the host
// closes the pipe (EPIPE on stdout), or SIGTERM, SIGHUP or SIGINT arrives; then it closes its connection cleanly (the
// service drops the binding and cancels the connection's pairings) and exits 0. bag-shim hook [--dir <home>] is the
// typed-word hook a host runs on each prompt (Claude Code's UserPromptSubmit): it reads the hook's JSON on stdin and,
// for a prompt that is exactly `use <name>`, posts it to its own shim (channel.ts).
import { spawn } from 'node:child_process'
import { closeSync, constants, existsSync, openSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Readable, Writable } from 'node:stream'
import {
  ancestors,
  type Channel,
  channelDir,
  endSession,
  hostPidOf,
  moveSession,
  openChannel,
  ownerHeld,
  type PsRow,
  postTyped,
  postUse,
  type SessionKey,
  safeDir,
  sessionKey,
  startOf,
  terminalOwner,
  typedName,
  writeBound,
} from './channel.ts'
import { frame, Lines, LineTooLong, type Message } from './frames.ts'
import { writeRing } from './ring.ts'
import { socketConnect } from './service.ts'
import { Shim, type ShimDeps } from './shim.ts'
import { homeOf, maxSocketPath, ownsHome, readToken, socketOf, tokenFileOf } from './wire.ts'

type Env = Readonly<Record<string, string | undefined>>
type Signal = 'SIGTERM' | 'SIGHUP' | 'SIGINT' | 'SIGUSR2'

export interface ShimIo {
  readonly argv: readonly string[]
  readonly env: Env
  readonly cwd: string
  readonly pid: number
  readonly ppid: number
  readonly stdin: Readable & { isTTY?: boolean; setRawMode?(raw: boolean): unknown }
  readonly stdout: Writable
  readonly stderr: { write(text: string): unknown }
  readonly signals: {
    once(event: Signal, listener: () => void): unknown
    on(event: Signal, listener: () => void): unknown
    removeListener(event: Signal, listener: () => void): unknown
  }
  readonly ps?: (pid: number) => PsRow
  /** This user's uid and a process's start time (channel.ts startOf); tests pass their own. */
  readonly uid?: number
  readonly startOf?: (pid: number) => string | null
  /** Starts the service detached; tests pass their own. */
  readonly startService?: (home: string, env: Env, log: Log) => boolean
  /** The platform the login agent is looked up for, and how its supervisor is asked (execStatus); tests pass their own. */
  readonly platform?: string
  readonly exec?: Exec
}

/**
 * Runs a command, no shell: resolves its exit status (null when it outlived EXEC_MS and was killed, -1 when it never
 * ran) and its stdout's first OUT_MAX characters.
 */
export type Exec = (
  file: string,
  args: readonly string[],
  env: Record<string, string>,
) => Promise<{ readonly status: number | null; readonly out: string }>

/** How long a command to the supervisor may take, and how much of its output is read. */
export const EXEC_MS = 5000
const OUT_MAX = 65_536

export const execStatus: Exec = (file, args, env) =>
  new Promise((resolve) => {
    let out = ''
    const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'ignore'], env, timeout: EXEC_MS })
    child.stdout?.setEncoding('utf8')
    child.stdout?.on('data', (d: string) => {
      if (out.length < OUT_MAX) out += d.slice(0, OUT_MAX - out.length)
    })
    child.on('error', () => resolve({ status: -1, out }))
    child.on('close', (code, signal) => resolve({ status: signal === null ? code : null, out }))
  })

/** The login agent's names, as packages/home's host-service.ts writes them (the shim imports no workspace package). */
const AGENT_LABEL = 'dev.bag.service'
const AGENT_UNIT = 'bag.service'

const unxml = (s: string): string =>
  s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
/** A unit word unquoted as host-service.ts's unitWord quotes it: backslash escapes, `%%` and `$$`. */
const unword = (s: string): string => s.replace(/\\(.)|%%|\$\$/g, (m, c?: string) => c ?? (m[0] as string))
const servesHome = (words: readonly string[], home: string): boolean => {
  const at = words.indexOf('--dir')
  return at !== -1 && words[at + 1] === home && words.includes('--service')
}

const readOrNull = (file: string): string | null => {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return null
  }
}

/**
 * The command that asks this home's login agent to start the service, or null when none is installed for this home:
 * the file `bag host install service` and the `service` tool write, whose service arguments name exactly this home
 * after --dir (another home's agent does not count). `check` asks the supervisor which file it loaded that job from,
 * which must be `file`, the one read here: a scratch HOME's file never reaches the person's live job.
 */
interface LoginAgent {
  readonly file: string
  readonly check: readonly [string, ...string[]]
  readonly ask: readonly [string, ...string[]]
  readonly launchd: boolean
}

export function loginAgentOf(
  home: string,
  env: Env,
  platform: string,
  uid: number | undefined,
  exists: (file: string) => boolean = existsSync,
): LoginAgent | null {
  if (env.HOME === undefined) return null
  if (platform === 'darwin') {
    const file = join(env.HOME, 'Library', 'LaunchAgents', `${AGENT_LABEL}.plist`)
    const text = readOrNull(file)
    if (uid === undefined || text === null) return null
    if (!text.includes(`<key>Label</key><string>${AGENT_LABEL}</string>`)) return null
    const array = text.split('<key>ProgramArguments</key>')[1]?.split('</array>')[0] ?? ''
    const words = [...array.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => unxml(m[1] as string))
    if (!servesHome(words, home)) return null
    const job = `gui/${uid}/${AGENT_LABEL}`
    return {
      file,
      check: ['/bin/launchctl', 'print', job],
      ask: ['/bin/launchctl', 'kickstart', job],
      launchd: true,
    }
  }
  if (platform !== 'linux') return null
  const file = join(env.HOME, '.config', 'systemd', 'user', AGENT_UNIT)
  const text = readOrNull(file)
  const line = text?.split('\n').find((l) => l.startsWith('ExecStart='))
  if (line === undefined) return null
  const words = [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => unword(m[1] as string))
  const systemctl = ['/usr/bin/systemctl', '/bin/systemctl'].find(exists)
  if (!servesHome(words, home) || systemctl === undefined) return null
  return {
    file,
    check: [systemctl, '--user', 'show', '-p', 'FragmentPath', AGENT_UNIT],
    ask: [systemctl, '--user', 'start', AGENT_UNIT],
    launchd: false,
  }
}

/** Asks this home's login agent to start the service: true when one was asked (the shim then waits for it). */
export async function askLoginAgent(
  home: string,
  env: Env,
  platform: string,
  uid: number | undefined,
  exec: Exec,
  log: Log,
  exists: (file: string) => boolean = existsSync,
): Promise<boolean> {
  const agent = loginAgentOf(home, env, platform, uid, exists)
  if (agent === null) return false
  const out: Record<string, string> = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }
  for (const k of ['HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS']) {
    const v = env[k]
    if (v !== undefined) out[k] = v
  }
  // The supervisor's own word on where the job came from: launchctl print's first `path = ` line, systemd's
  // FragmentPath. Not this file, a failed command or an unknown format: no ask, the shim starts its own (fails safe).
  const [check, ...checkArgs] = agent.check
  const seen = await exec(check, checkArgs, out)
  const lines = seen.out.split('\n').map((l) => l.trim())
  const from = agent.launchd
    ? lines.find((l) => l.startsWith('path = '))?.slice(7)
    : lines.find((l) => l.startsWith('FragmentPath='))?.slice(13)
  if (seen.status !== 0 || from !== agent.file) {
    log('login-agent-asked', { loaded: false, status: seen.status })
    return false
  }
  const [file, ...args] = agent.ask
  const { status } = await exec(file, args, out)
  log('login-agent-asked', { loaded: true, status })
  // launchd: 113 is a job it has not loaded; systemd's start waits for the job, so only 0 means it runs.
  return agent.launchd ? status !== -1 && status !== 113 : status === 0
}

export const USAGE = 'usage: bag-shim [--dir <home>] [--input-hook]\n       bag-shim hook [--dir <home>]'

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/** The environment the scrubbed launch passes on: an allow-list, PATH fixed. */
export function launchEnv(env: Env, home: string): Record<string, string> {
  const out: Record<string, string> = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', AC_HOME: home }
  for (const k of ['HOME', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'NODE_USE_ENV_PROXY']) {
    const v = env[k]
    if (v !== undefined) out[k] = v
  }
  for (const k of Object.keys(env)) {
    const v = env[k]
    if (/^(https?|no|all)_proxy$/i.test(k) && v !== undefined) out[k] = v
  }
  return out
}

/** The service entry of the installed package: <home>/package/versions/<current>/bag-mcp.js, or null. */
export function serviceEntry(home: string): string | null {
  try {
    const version = readFileSync(join(home, 'package', 'current'), 'utf8').trim()
    if (!/^[0-9A-Za-z.+-]{1,64}$/.test(version) || version.startsWith('.')) return null
    const entry = join(home, 'package', 'versions', version, 'bag-mcp.js')
    return existsSync(entry) ? entry : null
  } catch {
    return null
  }
}

type Log = (event: string, fields?: Record<string, unknown>) => void

/**
 * Opens <home>/run/service.log for a service the shim starts: append, created 0600 if missing, a link refused, in a
 * run directory made 0700 or checked. The child gets it as stdout and stderr, so a crash before the service opens its
 * own log still leaves a line there; the service appends to the same file, so neither writer truncates the other.
 * 'ignore' (the start goes ahead without it) when it cannot be opened.
 */
export function openServiceLog(home: string, log: Log): number | 'ignore' {
  try {
    const problem = safeDir(join(home, 'run'))
    if (problem !== null) throw Object.assign(new Error(problem), { code: 'unsafe-path' })
    const { O_WRONLY, O_CREAT, O_APPEND, O_NOFOLLOW } = constants
    return openSync(join(home, 'run', 'service.log'), O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o600)
  } catch (e) {
    log('service-log-failed', { code: (e as { code?: unknown }).code ?? 'error' })
    return 'ignore'
  }
}

/** The arguments the service entry takes (the service's own). */
export const SERVICE_ARGS = ['--service']

/**
 * Starts the service through the scrubbed launch: /bin/sh with core dumps off execs node --disable-sigusr1, detached,
 * no stdio, working directory the home (the service moves to <home>/run/ itself), the allow-listed environment.
 */
export function startService(home: string, env: Env, log: Log = () => {}): boolean {
  const entry = serviceEntry(home)
  if (entry === null) return false
  const out = openServiceLog(home, log)
  const child = spawn(
    '/bin/sh',
    [
      '-c',
      'ulimit -c 0; exec "$0" --disable-sigusr1 "$@"',
      process.execPath,
      entry,
      ...SERVICE_ARGS,
      '--dir',
      home,
    ],
    { detached: true, stdio: ['ignore', out, out], cwd: home, env: launchEnv(env, home) },
  )
  if (typeof out === 'number') closeSync(out)
  child.on('error', () => {})
  child.unref()
  return true
}

/** Runs the shim or the hook; resolves with the exit status. */
export async function run(io: ShimIo): Promise<number> {
  const [first, ...rest] = io.argv
  if (first === 'hook') return hook(io, rest)
  const unknown = io.argv.filter(
    (a, i) => a !== '--input-hook' && a !== '--dir' && io.argv[i - 1] !== '--dir',
  )
  if (unknown.length > 0 || first === '--help') {
    io.stderr.write(`${USAGE}\n`)
    return first === '--help' ? 0 : 2
  }
  const home = homeOf(io.argv, io.env)
  if (home === null) {
    io.stderr.write('bag-shim: no home directory: pass --dir, or set AC_HOME or HOME\n')
    return 2
  }
  return serve(io, home, io.argv.includes('--input-hook'))
}

const logger =
  (io: ShimIo) =>
  (event: string, fields: Record<string, unknown> = {}): void => {
    io.stderr.write(
      `${JSON.stringify({ at: new Date().toISOString(), src: 'bag-shim', event, ...fields })}\n`,
    )
  }

async function serve(io: ShimIo, home: string, wantHook: boolean): Promise<number> {
  const log = logger(io)
  const { promise: done, resolve: finish } = Promise.withResolvers<string>()
  let ended = false
  const toHost = (m: Message): void => {
    if (ended || io.stdout.destroyed) return
    io.stdout.write(frame(m))
  }
  const walked = hostPidOf(io.ppid, io.ps)
  const startedOf = io.startOf ?? startOf
  // omp 19: the window is PI_TERMINAL_OWNER_PID when the walk ended at omp's terminal-less core (channel.ts
  // terminalOwner), unless another live shim holds that window's files; then the walk stands, as before. The owner's
  // start time is kept: the core can keep this shim after the window is gone, and a reused pid is another process.
  let owner = terminalOwner(walked, io.env, io.ps, io.uid)
  if (owner !== null && ownerHeld(home, owner, io.pid)) {
    log('host', { from: 'parent', owner: 'held' })
    owner = null
  }
  const ownerStart = owner === null ? null : startedOf(owner)
  if (owner !== null && ownerStart === null) owner = null
  if (owner !== null) log('host', { from: 'owner' })
  const hostPid = owner ?? walked
  // The window's files' key: the host pid, or on Codex `<host pid>-<session id>` once a tool call names the window.
  let key: SessionKey = hostPid
  // This process's start time, in each .bound: wake-hook --end checks it before it signals (a reused pid is not us).
  const started = startOf(io.pid)
  let channel: Channel | null = null
  // Whether the window this shim keys by is still the process it was: always for a host found by the walk; for an owner,
  // until its start time differs or it is gone. Then for good: no bridge pid in the hello, no wake file written, this
  // shim's files of that key removed and its typed-word channel closed. Never the core's pid in its place.
  let ownerGone = false
  const hostLive = (): boolean => {
    if (owner === null) return true
    if (ownerGone) return false
    const now = startedOf(owner) // null: ps gave no answer (slow, or the owner gone), so kill 0 decides
    if (now === ownerStart || (now === null && alive(owner))) return true
    ownerGone = true
    endSession(home, key, io.pid) // only files naming this shim
    channel?.close()
    channel = null
    log('host-gone', {})
    return false
  }
  // False for a Codex sub-agent's shim: it keeps no wake files (its window's shim has them; sub-agents fire no hooks).
  let wakes = true
  const deps: ShimDeps = {
    connect: socketConnect(socketOf(home)),
    toHost,
    log,
    env: io.env,
    cwd: io.cwd,
    pid: io.pid,
    home,
    socketPath: socketOf(home),
    token: () => readToken(tokenFileOf(home)),
    start: () => (io.startService ?? startService)(home, io.env, log),
    ask: () =>
      askLoginAgent(
        home,
        io.env,
        io.platform ?? process.platform,
        io.uid ?? process.getuid?.(),
        io.exec ?? execStatus,
        log,
      ),
    ring: (r) => {
      // The ring lives in the channel directory: made 0700 or checked here, as for the .bound file.
      if (safeDir(channelDir(home)) !== null)
        throw Object.assign(new Error('unsafe'), { code: 'unsafe-path' })
      if (wakes && hostLive()) writeRing(home, key, io.pid, r)
    },
    consentBridge: true,
    hostPid,
    inputHook: false,
    owner: (pid) => ownsHome(home, pid, alive),
    boundChanged: (labels) => {
      try {
        if (wakes && hostLive()) writeBound(home, key, io.pid, labels, started)
      } catch (e) {
        log('bound-file-failed', { code: (e as { code?: unknown }).code ?? 'error' })
      }
    },
    windowSeen: (sessionId, subagent) => {
      if (subagent && wakes) {
        wakes = false
        endSession(home, key, io.pid) // only files naming this shim
        log('subagent', {})
      }
      if (!wakes) return
      const next = sessionKey(hostPid, sessionId)
      if (typeof next !== 'string' || next === key) return // not a uuid, or the same window
      // A new key (the first tool call, or a new session in the window): the old key's files go, the binding moves.
      try {
        moveSession(home, key, next, io.pid, shim.bound, started)
      } catch (e) {
        log('bound-file-failed', { code: (e as { code?: unknown }).code ?? 'error' })
      }
      key = next
      log('window', { keyed: true })
    },
  }
  // Read by each hello (shim.ts #capabilities reads deps.hostPid when it builds one): absent once the owner is gone, so
  // that hello names no window. A getter on the object the Shim keeps, so shim.ts is unchanged.
  Object.defineProperty(deps, 'hostPid', {
    get: () => (hostLive() ? hostPid : undefined),
    enumerable: true,
  })
  const shim = new Shim(deps)
  if (wantHook) {
    channel = await openChannel(
      home,
      hostPid,
      io.pid,
      {
        use: (name) => (hostLive() ? shim.use(name) : Promise.resolve({ bound: false, code: 'host-gone' })),
        typed: () => hostLive() && shim.typed(),
      },
      log,
      maxSocketPath(),
    )
  }
  // The hello reads it when it is sent, after the host's initialize: set before any input is read.
  shim.setInputHook(channel !== null)

  const tty = io.stdin.isTTY === true && typeof io.stdin.setRawMode === 'function'
  // A host that runs its servers on a pty (omp) would lose every line past 1,024 bytes in canonical mode, and Ctrl-C
  // and Ctrl-D would never arrive as bytes: raw mode passes every byte, and those two end the run.
  if (tty) io.stdin.setRawMode?.(true)
  const lines = new Lines()
  const onData = (chunk: Buffer | string): void => {
    const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
    if (tty && (bytes.includes(0x03) || bytes.includes(0x04))) {
      finish('terminal')
      return
    }
    let got: ReturnType<Lines['push']>
    try {
      got = lines.push(bytes)
    } catch (e) {
      if (e instanceof LineTooLong) {
        finish('line-too-long')
        return
      }
      throw e
    }
    for (const d of got.dropped) log('host-bad-line', { length: d.length })
    for (const m of got.messages) shim.fromHost(m)
  }
  const onEnd = (): void => finish('stdin-end')
  const onOutError = (e: NodeJS.ErrnoException): void => finish(e.code === 'EPIPE' ? 'epipe' : 'stdout-error')
  const onSignal = {
    SIGTERM: () => finish('SIGTERM'),
    SIGHUP: () => finish('SIGHUP'),
    SIGINT: () => finish('SIGINT'),
  }
  io.stdin.on('data', onData)
  io.stdin.once('end', onEnd)
  io.stdin.once('close', onEnd)
  io.stdout.on('error', onOutError)
  for (const s of ['SIGTERM', 'SIGHUP', 'SIGINT'] as const) io.signals.once(s, onSignal[s])
  // SIGUSR2, from Codex's SessionEnd hook (wake-hook --end): the session's files go and the binding is released.
  // Registered once with on() for the whole run: a once() re-armed in the handler leaves an instant with no listener,
  // when the signal's default action (exit) applies.
  const onRelease = (): void => {
    endSession(home, key, io.pid)
    shim.release()
  }
  io.signals.on('SIGUSR2', onRelease)
  log('start', { host_pid: hostPid, input_hook: channel !== null })

  const why = await done
  ended = true
  log('stop', { reason: why })
  io.stdin.removeListener('data', onData)
  io.stdin.removeListener('end', onEnd)
  io.stdin.removeListener('close', onEnd)
  io.stdout.removeListener('error', onOutError)
  io.stdout.on('error', () => {})
  for (const s of ['SIGTERM', 'SIGHUP', 'SIGINT'] as const) io.signals.removeListener(s, onSignal[s])
  io.signals.removeListener('SIGUSR2', onRelease)
  if (tty) io.stdin.setRawMode?.(false)
  shim.close()
  // The session's files: .bound, .ring and the wake hook's .ring-seen and .wake-hook.lock (channel.ts).
  endSession(home, key, io.pid)
  channel?.close()
  // A stdin that never ends must not hold the process open.
  io.stdin.destroy()
  return 0
}

/** The longest hook input read, in characters, and how long it is waited for. */
const HOOK_STDIN_MAX = 65_536
const HOOK_STDIN_MS = 2000

function readAll(stdin: Readable): Promise<string> {
  return new Promise((resolve) => {
    let text = ''
    const stop = (): void => {
      clearTimeout(timer)
      stdin.removeAllListeners('data')
      stdin.pause()
      resolve(text)
    }
    const timer = setTimeout(stop, HOOK_STDIN_MS)
    stdin.setEncoding('utf8')
    stdin.on('data', (c: string) => {
      text += c
      if (text.length > HOOK_STDIN_MAX) stop()
    })
    stdin.once('end', stop)
    stdin.once('error', stop)
  })
}

/**
 * The typed-word hook, run on every prompt the person submits. Every prompt tells the shim the person typed here
 * (service/typed). Silent (exit 0, nothing printed, the prompt goes on to the model) for any prompt that is not
 * exactly `use <name>`, when no shim of this window answers, and for a name the home lacks (so "use pandas" still
 * reaches the model). Otherwise it prints Claude Code's block decision with what happened, so the model never acts on
 * the word: bound, or why not.
 */
async function hook(io: ShimIo, rest: readonly string[]): Promise<number> {
  const home = homeOf(rest, io.env)
  const text = await readAll(io.stdin)
  let prompt = ''
  try {
    const doc = JSON.parse(text) as { prompt?: unknown }
    if (typeof doc.prompt === 'string') prompt = doc.prompt
  } catch {
    return 0
  }
  if (home === null) return 0
  // The same window as the shim's (serve): omp 19's owner first, only where the walk ends at omp's terminal-less core.
  const owner = terminalOwner(hostPidOf(io.ppid, io.ps), io.env, io.ps, io.uid)
  const walk = ancestors(io.ppid, io.ps)
  const pids = owner === null ? walk : [owner, ...walk.filter((p) => p !== owner)]
  const name = typedName(prompt)
  if (name === null) {
    // Any other prompt: the person typed in this window, which makes it the speaking one (service/typed).
    await postTyped(home, pids)
    return 0
  }
  const answer = await postUse(home, pids, name)
  if (answer === null || (!answer.bound && answer.code === 'unknown-identity')) return 0
  const reason = answer.bound
    ? `bag: this session now acts as ${answer.as}.`
    : `bag: this session was not bound to ${name} (${answer.code}).`
  io.stdout.write(`${JSON.stringify({ decision: 'block', reason })}\n`)
  return 0
}
