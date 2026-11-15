import { HomeError, type HomeIo } from '@usebag/home'
import { UsageError } from './args.ts'
import type { Io } from './io.ts'

// The command line's side of the acts on a home (packages/home): the terminal and the rest of its io, as the HomeIo
// those acts take. An act prints its lines to stdout and its warnings to stderr in the order it does its work, and asks
// its question with the terminal's confirm, which writes it to stderr and reads the person's y.

/** The HomeIo of the command line's io: say is stdout, warn is stderr, ask is the terminal's confirm. */
export function homeIo(io: Io): HomeIo {
  return {
    say: (line) => io.out(line),
    warn: (line) => io.err(line),
    ask: (question) => io.confirm(question),
    clock: io.clock,
    rng: io.rng,
    env: io.env,
    ...(io.security === undefined ? {} : { security: io.security }),
    ...(io.platform === undefined ? {} : { platform: io.platform }),
    relay: (options) => io.relay(options),
  }
}

/**
 * The error as the command line reports it: a home act's usage refusal becomes the command line's UsageError, which
 * also prints how to read the commands; any other error is itself.
 */
export function asCli(e: unknown): unknown {
  if (!(e instanceof HomeError) || e.code !== 'usage') return e
  // HomeError's message is "<code>: <detail>"; the detail alone goes to UsageError, which puts "usage: " back.
  const prefix = 'usage: '
  return new UsageError(e.message.startsWith(prefix) ? e.message.slice(prefix.length) : e.message)
}

/** Runs a home act, its usage refusal reported as the command line's. */
export function viaHome<T>(act: () => T): T {
  try {
    const out = act()
    return (out instanceof Promise ? out.catch((e: unknown) => Promise.reject(asCli(e))) : out) as T
  } catch (e) {
    throw asCli(e)
  }
}
