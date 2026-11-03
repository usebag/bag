import { execFileSync, spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import type { Readable } from 'node:stream'
import {
  type Clock,
  createHttpRelay,
  createRecordSource,
  createWsSubscriber,
  type RecordSource,
  type RelayClient,
  type Rng,
  runSecurity,
  type SecurityRunner,
  systemClock,
  systemRng,
  type WsSubscriberOptions,
} from '@usebag/edge'

// The CLI's one port to the world outside its arguments: the terminal (a person at it confirms), the environment, the
// clock, the random source, the relay network, the record source, the stop signal, /usr/bin/security, and telemetry's
// fetch and its detached sender. Files go through the edge's fs adapters at paths the arguments name, which tests point
// at temporary directories.

/** The relay client of the CLI: the edge's RelayClient and the health probe. */
export type CliRelay = RelayClient & { health(url: string): Promise<boolean> }

export interface Io {
  /** Writes one line to stdout. */
  out(line: string): void
  /** Writes one line to stderr. */
  err(line: string): void
  readonly env: Readonly<Record<string, string | undefined>>
  readonly clock: Clock
  readonly rng: Rng
  /** A relay client; `maxReconnects` bounds a subscription's reconnects (0 for inbox --once). */
  relay(options: WsSubscriberOptions): CliRelay
  /** Where records come from: well-known URLs over https, and relays through the client. */
  records(client: RelayClient): RecordSource
  /** A signal that aborts when the user stops a long-running command (SIGINT or SIGTERM). */
  stopSignal(): AbortSignal
  /** How long inbox --once waits for another frame before it ends, in milliseconds. */
  readonly idleMs: number
  /**
   * Runs /usr/bin/security for the identities a keychain holds. Without it, the keychain custody refuses
   * ENOENT: the unit tests' io has none, so no test reaches a real keychain unless it passes a runner.
   */
  readonly security?: SecurityRunner
  /**
   * The fetch telemetry's report and erasure go out with (the edge's telemetry-send.ts). Without it nothing is sent:
   * `telemetry send` does nothing and `telemetry forget` fails unreachable, so no unit test reaches the endpoint.
   */
  readonly fetch?: typeof fetch
  /**
   * Starts `telemetry send` detached, never waited for, when a day's report is due after a command line. Without it
   * none is started: the unit tests' io has none.
   */
  readonly spawnSender?: () => void
  /** Whether stdin is a terminal: release and drop ask a person there, and refuse no-tty otherwise. */
  readonly isTty: boolean
  /** Whether stdout is a terminal: the recovery sheet prints only there, never to a pipe or a file. */
  readonly outIsTty?: boolean
  /** Writes `prompt` to stderr and reads one line from stdin: true for y or yes, false for anything else or none. */
  confirm(prompt: string): Promise<boolean>
  /** Reads one line from stdin exactly as typed (no trim, no case change) and writes nothing; null at end of input. */
  readLine(): Promise<string | null>
  /** As readLine, with the terminal's echo off while the line is typed (the seeds of a sheet: ac restore). */
  readSecret(): Promise<string | null>
  /** Pauses stdin and resolves a pending readLine with null; every later readLine is null at once, stdin not resumed. */
  release(): void
}

/** The part of a process the CLI uses. */
export interface ProcessLike {
  readonly stdout: { write(text: string): unknown; readonly isTTY?: boolean }
  readonly stderr: { write(text: string): unknown }
  readonly stdin: Readable & { readonly isTTY?: boolean }
  readonly env: Readonly<Record<string, string | undefined>>
  once(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown
  /** Turns the terminal's echo on or off; by default `stty echo` or `stty -echo` on stdin, a failure ignored. */
  readonly echo?: (on: boolean) => void
}

/**
 * `node <this CLI's main.ts> telemetry send`, detached in its own process group with no stdio and unreferenced, so
 * the command line that started it exits at once; a failure to start it is ignored.
 */
function spawnSender(): void {
  try {
    const child = spawn(process.execPath, [process.argv[1] ?? '', 'telemetry', 'send'], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    })
    child.on('error', () => {})
    child.unref()
  } catch {
    // not started: the next command line tries again while the day is due
  }
}

const stty = (on: boolean): void => {
  try {
    execFileSync('stty', [on ? 'echo' : '-echo'], { stdio: ['inherit', 'ignore', 'ignore'] })
  } catch {
    // not a terminal after all, or no stty: the line is read as it is
  }
}

/** The real io: the process's streams and environment, the system clock and CSPRNG, the relay over the network. */
export function processIo(proc: ProcessLike = process): Io {
  let stop: AbortController | null = null
  let lines: AsyncIterator<string> | null = null
  let released = false
  let cancel: (() => void) | null = null
  // One interface for the process, so lines typed ahead are kept; stdin is paused after each line: a terminal's stdin
  // left flowing keeps the process alive after its last write (e2e scenario 41 found it).
  const readLine = async (): Promise<string | null> => {
    if (released) return null
    lines ??= createInterface({ input: proc.stdin, terminal: false })[Symbol.asyncIterator]()
    proc.stdin.resume()
    const stopped = new Promise<null>((done) => {
      cancel = () => done(null)
    })
    try {
      const next = await Promise.race([lines.next(), stopped])
      return next === null || next.done === true ? null : next.value
    } finally {
      proc.stdin.pause()
    }
  }
  const echo = proc.echo ?? stty
  const readSecret = async (): Promise<string | null> => {
    if (proc.stdin.isTTY !== true) return readLine()
    echo(false)
    try {
      return await readLine()
    } finally {
      echo(true)
      proc.stderr.write('\n') // the Enter the terminal did not echo
    }
  }
  return {
    out: (line) => {
      proc.stdout.write(`${line}\n`)
    },
    err: (line) => {
      proc.stderr.write(`${line}\n`)
    },
    env: proc.env,
    clock: systemClock,
    rng: systemRng,
    // createRelayClient's type leaves out the health probe that createHttpRelay has, so the two halves are joined here.
    relay: (options) => ({ ...createHttpRelay(), ...createWsSubscriber(options) }),
    records: (client) => createRecordSource(client),
    // The handlers are installed only when a command asks, so Ctrl-C still ends every other command at once.
    stopSignal: () => {
      if (stop === null) {
        const controller = new AbortController()
        const abort = (): void => controller.abort()
        proc.once('SIGINT', abort)
        proc.once('SIGTERM', abort)
        stop = controller
      }
      return stop.signal
    },
    idleMs: 1000,
    security: runSecurity,
    fetch,
    spawnSender,
    isTty: proc.stdin.isTTY === true,
    outIsTty: proc.stdout.isTTY === true,
    confirm: async (prompt) => {
      proc.stderr.write(`${prompt} [y/N] `)
      return /^y(es)?$/i.test(((await readLine()) ?? '').trim())
    },
    readLine,
    readSecret,
    release: () => {
      released = true
      proc.stdin.pause()
      cancel?.()
    },
  }
}
