// The shim as a process: bag-shim [--dir <home>] [--input-hook] runs the proxy on stdio until stdin ends, the host
// closes the pipe (EPIPE on stdout), or SIGTERM, SIGHUP or SIGINT arrives; then it closes its connection cleanly (the
// service drops the binding and cancels the connection's pairings) and exits 0. bag-shim hook [--dir <home>] is the
// typed-word hook a host runs on each prompt (Claude Code's UserPromptSubmit): it reads the hook's JSON on stdin and,
// for a prompt that is exactly `use <name>`, posts it to its own shim (channel.ts).
import { spawn } from 'node:child_process'
import { closeSync, constants, existsSync, openSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Readable, Writable } from 'node:stream'
import { bridgeDirOf } from './bridge.ts'
import {
  ancestors,
  type Channel,
  channelDir,
  endSession,
  hostPidOf,
  openChannel,
  type PsRow,
  postTyped,
  postUse,
  safeDir,
  typedName,
  writeBound,
} from './channel.ts'
import { frame, Lines, LineTooLong, type Message } from './frames.ts'
import { writeRing } from './ring.ts'
import { socketConnect } from './service.ts'
import { Shim } from './shim.ts'
import { homeOf, maxSocketPath, ownsHome, readToken, socketOf, tokenFileOf } from './wire.ts'

type Env = Readonly<Record<string, string | undefined>>
type Signal = 'SIGTERM' | 'SIGHUP' | 'SIGINT'

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
    removeListener(event: Signal, listener: () => void): unknown
  }
  readonly ps?: (pid: number) => PsRow
  /** Starts the service detached; tests pass their own. */
  readonly startService?: (home: string, env: Env, log: Log) => boolean
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

/** The environment the scrubbed launch passes on (contract section 8): an allow-list, PATH fixed. */
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
  const hostPid = hostPidOf(io.ppid, io.ps)
  let channel: Channel | null = null
  const shim = new Shim({
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
    ring: (r) => {
      // The ring lives in the channel directory: made 0700 or checked here, as for the .bound file.
      if (safeDir(channelDir(home)) !== null)
        throw Object.assign(new Error('unsafe'), { code: 'unsafe-path' })
      writeRing(home, hostPid, io.pid, r)
    },
    consentBridge: true,
    hostPid,
    bridgeDirOf: (given) => bridgeDirOf(home, given),
    inputHook: false,
    owner: (pid) => ownsHome(home, pid, alive),
    boundChanged: (labels) => {
      try {
        writeBound(home, hostPid, io.pid, labels)
      } catch (e) {
        log('bound-file-failed', { code: (e as { code?: unknown }).code ?? 'error' })
      }
    },
  })
  if (wantHook) {
    channel = await openChannel(
      home,
      hostPid,
      io.pid,
      { use: (name) => shim.use(name), typed: () => shim.typed(), bridge: () => shim.bridgeDir },
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
  if (tty) io.stdin.setRawMode?.(false)
  shim.close()
  // The session's files: .bound, .ring and the wake hook's .ring-seen and .wake-hook.lock (channel.ts).
  endSession(home, hostPid, io.pid)
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
  const pids = ancestors(io.ppid, io.ps)
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
