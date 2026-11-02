import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { AcError, checkChainShape, type Hop, isAcError } from '@usebag/core'
import { type Clock, EdgeError } from '@usebag/edge'
import { ConfigError } from './config.ts'
import type { Timers } from './desk.ts'
import type { Logger } from './log.ts'

// A session's chain, kept current while the server runs. It comes from a file (--auth) or
// from a credential helper's output (--chain-cmd, in the style of AWS credential_process), and is read again 60 s
// before its earliest exp, then at growing intervals until a newer chain arrives, and at once on a hop-expired
// refusal. A newer chain goes to the edge's renewChain, which verifies it, keeps the root and the principal,
// and swaps it in for every later send, subscription and fetch; the array the edge was first given is never changed.
// Chains are public, but the command line, the command's output and its stderr are never logged.

/** Where a session's chain comes from: a file, a command, or under agent custody the agent's renewal (agent.ts). */
export type ChainSource =
  | { readonly kind: 'file'; readonly path: string }
  | { readonly kind: 'command'; readonly command: string }
  | { readonly kind: 'agent'; readonly renew: () => Promise<readonly Hop[]> }

export type Env = Readonly<Record<string, string | undefined>>

/** Runs a command and resolves with its stdout; rejects when it cannot run, fails or outlives the timeout. */
export type RunCommand = (command: string, env: Env, timeoutMs: number) => Promise<string>

/** How long before the chain's earliest exp the server reads its source again, in seconds. */
export const CHAIN_LEAD_S = 60
/** The first wait between two reads that found no newer chain, in seconds; it doubles up to CHAIN_RETRY_MAX_S. */
export const CHAIN_RETRY_S = 10
export const CHAIN_RETRY_MAX_S = 900
/** How long --chain-cmd may run, and how much it may print. */
export const COMMAND_TIMEOUT_MS = 10_000
export const COMMAND_MAX_BYTES = 262_144

const noop = (): void => {}
const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()

/** A chain's text, the CLI's `delegate` format (a JSON list of hops, root first), checked by chain rules 1 to 4. */
export function parseChainText(text: string, what: string): readonly Hop[] {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new AcError('bad-json', `${what} is not JSON`)
  }
  return checkChainShape(value)
}

/**
 * The hops of a chain file (the format of the CLI's `delegate`: one JSON line, a list of hops, root first), checked by
 * chain rules 1 to 4 (spec/SPEC.md §6.2): bad-json, bad-shape, bad-hop and the caps' codes; a file that cannot be read
 * throws its errno (ENOENT).
 */
export function readChain(file: string): readonly Hop[] {
  return parseChainText(readFileSync(file, 'utf8'), file)
}

/** The earliest exp of a chain's hops (with exp-not-monotone checked, the last hop's). */
export function earliestExp(hops: readonly Hop[]): number {
  return Math.min(...hops.map((h) => h.exp))
}

const commandFailed = (detail: string): ConfigError => new ConfigError('chain-cmd-failed', detail)

/**
 * Runs `<shell> -c <command>` with the given environment, stdin closed and stderr discarded, and resolves with its
 * stdout; chain-cmd-failed for an exit other than 0, a timeout or an output over COMMAND_MAX_BYTES, the errno when
 * the shell cannot start.
 */
export function shellRunner(shell = '/bin/sh'): RunCommand {
  return (command, env, timeoutMs) =>
    new Promise((resolve, reject) => {
      const child = spawn(shell, ['-c', command], { env: { ...env }, stdio: ['ignore', 'pipe', 'ignore'] })
      const chunks: Buffer[] = []
      let size = 0
      let settled = false
      const fail = (error: Error): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        child.kill('SIGKILL')
        reject(error)
      }
      const timer = setTimeout(
        () => fail(commandFailed(`it did not finish within ${timeoutMs / 1000} s`)),
        timeoutMs,
      )
      child.once('error', fail)
      child.stdout.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > COMMAND_MAX_BYTES) fail(commandFailed(`it printed over ${COMMAND_MAX_BYTES} bytes`))
        else chunks.push(chunk)
      })
      child.once('close', (code, signal) => {
        if (code !== 0) return fail(commandFailed(`it exited with ${code ?? signal}`))
        settled = true
        clearTimeout(timer)
        resolve(Buffer.concat(chunks).toString('utf8'))
      })
    })
}

/** The command runner of the real process: /bin/sh -c. */
export const runShell: RunCommand = shellRunner()

/** The code of a failed read: the closed set's, the server's or the edge's own, an errno, or internal. */
function codeOfFailure(e: unknown): string {
  if (isAcError(e) || e instanceof ConfigError || e instanceof EdgeError) return e.code
  const errno = (e as { code?: unknown } | null)?.code
  return typeof errno === 'string' && /^E[A-Z]+$/.test(errno) ? errno : 'internal'
}

/**
 * Reads a chain from its source. A command's output is the chain JSON (it starts with "[") or the path of a chain
 * file; a failure names neither the output nor the path, which are the command's.
 */
export async function loadChain(source: ChainSource, run: RunCommand, env: Env): Promise<readonly Hop[]> {
  if (source.kind === 'file') return readChain(source.path)
  if (source.kind === 'agent') return source.renew()
  const out = (await run(source.command, env, COMMAND_TIMEOUT_MS)).trim()
  if (out.startsWith('[')) return parseChainText(out, 'the output of --chain-cmd')
  if (out === '' || out.includes('\n')) {
    throw commandFailed('it printed neither the chain JSON nor the path of one chain file')
  }
  try {
    return readChain(out)
  } catch (e) {
    throw new ConfigError(codeOfFailure(e), 'the chain file that --chain-cmd named cannot be read as a chain')
  }
}

/** The chain's state, as status reports it. */
export interface ChainStatus {
  readonly source: ChainSource['kind']
  readonly hops: number
  readonly earliest_exp: number
  readonly earliest_exp_at: string
  readonly renewals: number
  readonly last_reread: { readonly at: string; readonly why: string; readonly outcome: string } | null
  readonly next_reread_at: string | null
}

/**
 * What holds the chain in use and renews it: the edge (Edge.auth and Edge.renewChain). renewChain verifies the chain
 * to the signing key at the edge's clock (the core's codes), and throws EdgeError chain-mismatch for another root or
 * principal and chain-not-later for a chain that expires no later; a refusal changes nothing.
 */
export interface ChainHolder {
  readonly auth: readonly Hop[]
  renewChain(auth: readonly Hop[]): unknown
}

export interface ChainKeeperOptions {
  readonly source: ChainSource
  /** The edge whose chain is kept current. */
  readonly edge: ChainHolder
  readonly clock: Clock
  readonly timers: Timers
  readonly run: RunCommand
  readonly env: Env
  readonly log: Logger
  /** Called once a renewed chain is in place. */
  readonly onRenewed?: () => void
}

/**
 * Keeps a session's chain current. A read hands the chain it found to the edge's renewChain, which adopts a chain that
 * verifies now for the server's key, names the same principal and root, and expires later than the current one
 * ("renewed"); a chain that expires no later is "unchanged" (chain-not-later), one of another principal or root
 * "other-identity" (chain-mismatch: a restart is needed), and any other failure is its code.
 */
export class ChainKeeper {
  readonly #o: ChainKeeperOptions
  #renewals = 0
  /** Reads in a row, since the last renewal, that found no newer chain. */
  #misses = 0
  #last: ChainStatus['last_reread'] = null
  #next: number | null = null
  #cancel: () => void = noop
  #reading: Promise<string> | null = null
  #stopped = false

  constructor(options: ChainKeeperOptions) {
    this.#o = options
  }

  /** Schedules the first read: 60 s before the earliest exp, or now when that is past. */
  start(): void {
    this.#schedule(Math.max(this.#o.clock.now(), earliestExp(this.#o.edge.auth) - CHAIN_LEAD_S))
  }

  /** Reads the source again now and returns the outcome; a call while a read runs shares it. */
  reread(why: string): Promise<string> {
    this.#reading ??= this.#read(why).finally(() => {
      this.#reading = null
    })
    return this.#reading
  }

  status(): ChainStatus {
    const exp = earliestExp(this.#o.edge.auth)
    return {
      source: this.#o.source.kind,
      hops: this.#o.edge.auth.length,
      earliest_exp: exp,
      earliest_exp_at: iso(exp),
      renewals: this.#renewals,
      last_reread: this.#last,
      next_reread_at: this.#next === null ? null : iso(this.#next),
    }
  }

  /** Cancels the next read; a read in flight finishes but schedules nothing. */
  stop(): void {
    this.#stopped = true
    this.#cancel()
    this.#next = null
  }

  async #read(why: string): Promise<string> {
    const { clock, log, source } = this.#o
    let outcome: string
    try {
      outcome = this.#adopt(await loadChain(source, this.#o.run, this.#o.env))
    } catch (e) {
      outcome = codeOfFailure(e)
    }
    const now = clock.now()
    this.#last = { at: iso(now), why, outcome }
    const exp = earliestExp(this.#o.edge.auth)
    log.log(outcome === 'renewed' || outcome === 'unchanged' ? 'info' : 'warn', 'chain', {
      why,
      outcome,
      source: source.kind,
      hops: this.#o.edge.auth.length,
      exp,
    })
    if (outcome === 'renewed') {
      this.#renewals++
      this.#misses = 0
      if (!this.#stopped) this.#o.onRenewed?.()
    } else {
      this.#misses++
    }
    if (!this.#stopped) {
      const lead = exp - CHAIN_LEAD_S
      const wait = Math.min(CHAIN_RETRY_S * 2 ** Math.max(0, this.#misses - 1), CHAIN_RETRY_MAX_S)
      this.#schedule(now < lead ? lead : now + wait)
    }
    return outcome
  }

  #adopt(candidate: readonly Hop[]): string {
    try {
      this.#o.edge.renewChain(candidate)
    } catch (e) {
      if (e instanceof EdgeError && e.code === 'chain-not-later') return 'unchanged'
      if (e instanceof EdgeError && e.code === 'chain-mismatch') return 'other-identity'
      throw e
    }
    return 'renewed'
  }

  #schedule(at: number): void {
    this.#cancel()
    this.#next = at
    const ms = Math.max(0, (at - this.#o.clock.now()) * 1000)
    this.#cancel = this.#o.timers.after(ms, () => {
      this.#next = null
      void this.reread('timer')
    })
  }
}
