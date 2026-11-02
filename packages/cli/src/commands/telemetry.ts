import {
  machineTelemetryNotice,
  setTelemetry,
  telemetryDir,
  telemetryId,
  telemetryReport,
  telemetrySpoolBytes,
  telemetryState,
} from '@usebag/edge'
import { type OptionSpec, parse, shq, str, UsageError } from '../args.ts'
import type { Io } from '../io.ts'

const USAGE = 'telemetry on | off | status | preview [--date <YYYY-MM-DD>]'

/** The day, in seconds. */
const DAY = 86_400

const dateOf = (day: number): string => new Date(day * DAY * 1000).toISOString().slice(0, 10)

/**
 * telemetry on | off | status | preview [--date <YYYY-MM-DD>]: the machine's telemetry (opt-in; the edge's
 * telemetry.ts), one consent and one install id per machine in HOME/.bag, whatever the home. on keeps the install id
 * or makes one; off removes it and the spool of counts. Each then prints the state as status does, one line:
 * "telemetry <on|off> reason=<reason> choice=<on|off|none> id=<32 hex|none> spool=<bytes>", the id the person names
 * to ask for the machine's reports to be erased. An environment variable that turns it off (AC_TELEMETRY=off,
 * DO_NOT_TRACK, CI) is the reason whatever the choice. preview prints the report the machine would send for a UTC date (today, or --date, at most 7 days back),
 * exactly, on stdout, and its size on stderr. Nothing is sent.
 */
export function telemetry(args: readonly string[], io: Io): number {
  const [verb, ...rest] = args
  if (verb !== 'on' && verb !== 'off' && verb !== 'status' && verb !== 'preview') throw new UsageError(USAGE)
  const options: Record<string, OptionSpec> = verb === 'preview' ? { date: { type: 'string' } } : {}
  const date = str(parse(rest, { positionals: [], options }), 'date')
  const dir = telemetryDir(io.env)
  if (dir === null) throw new UsageError('no HOME: the machine telemetry directory is HOME/.bag')
  if (verb === 'preview') return preview(io, date)
  if (verb !== 'status') setTelemetry(dir, verb, io.rng)
  const { on, reason, choice } = telemetryState(io.env, dir)
  const state = `telemetry ${on ? 'on' : 'off'} reason=${reason} choice=${choice ?? 'none'}`
  io.out(`${state} id=${telemetryId(dir) ?? 'none'} spool=${telemetrySpoolBytes(dir)}`)
  return 0
}

/** The report for `date`, today when absent, on stdout exactly as it would be sent, and its size on stderr. */
function preview(io: Io, date: string | undefined): number {
  const today = Math.floor(io.clock.now() / DAY)
  const days = Array.from({ length: 8 }, (_, i) => dateOf(today - i))
  const day = date ?? dateOf(today)
  if (!days.includes(day)) throw new UsageError('--date: a UTC date from 7 days ago to today, as YYYY-MM-DD')
  const text = JSON.stringify(telemetryReport(io.env, day))
  io.out(text)
  io.err(`telemetry preview: ${Buffer.byteLength(text)} bytes for ${day}; this version sends nothing`)
  return 0
}

/** The verbs that split a job from an act, counted apart from their command. */
const SPLIT = new Set([
  'record-keep',
  'peer-invite',
  'peer-accept',
  'keys-rotate',
  'host-install-claude-code',
  'host-install-codex',
])

/** The verb a command line is counted under: help, a verb that splits, else its command (the edge places it). */
export function verbOf(argv: readonly string[]): string {
  const [name = '', a = '', b = ''] = argv
  if (name === 'help' || argv.includes('--help') || argv.includes('-h')) return 'help'
  return [`${name}-${a}-${b}`, `${name}-${a}`].find((v) => SPLIT.has(v)) ?? name
}

/**
 * The notice once per machine (machineTelemetryNotice), on stderr after a command that returned rather than threw:
 * one a person ran at a terminal, and host install, the step that wires a server whose own stderr no person reads. It
 * names the preview as this CLI is run, never `ac telemetry on`, which a guide install lacks (the spec owner's ruling
 * 13); a machine without HOME gets none.
 */
export function notice(io: Io): void {
  const cli = `node ${shq(process.argv[1] ?? 'packages/cli/src/main.ts')}`
  const text = machineTelemetryNotice(io.env, `${cli} telemetry preview`)
  if (text !== null) io.err(text)
}
