import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  BUILD_INFO,
  type BuildInfo,
  machineTelemetryNotice,
  sendDueTelemetry,
  telemetryDir,
  telemetryReport,
} from '@usebag/edge'
import { telemetrySwitch } from '@usebag/home'
import { type OptionSpec, parse, shq, str, UsageError } from '../args.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'

const USAGE = 'telemetry on | off | status | preview [--date <YYYY-MM-DD>] | send | forget'

const VERBS = new Set(['on', 'off', 'status', 'preview', 'send', 'forget'])

/** The day, in seconds. */
const DAY = 86_400

const dateOf = (day: number): string => new Date(day * DAY * 1000).toISOString().slice(0, 10)

/**
 * telemetry on | off | status | preview [--date <YYYY-MM-DD>] | send | forget: the machine's telemetry (opt-in; the
 * edge's telemetry.ts and telemetry-send.ts), one consent and one install id per machine in HOME/.bag, whatever the
 * home. on is a person's act: on a terminal (no-tty otherwise) after one y (declined, nothing changed), asked again
 * when it is already on; it keeps the install id or makes one. off removes it, the spool of counts and the sender's
 * mark, network-free.
 * Each then prints the state as status does, one line: "telemetry <on|off> reason=<reason> choice=<on|off|none>
 * id=<32 hex|none> spool=<bytes> sent=<YYYY-MM-DD|none>", the id the person names to ask for the machine's reports to
 * be erased, and sent the last day the sender took. off then names the id it removed, which can still be erased. An
 * environment variable that turns it off (AC_TELEMETRY=off, DO_NOT_TRACK, CI) is the reason whatever the choice.
 * preview prints the report the machine would send for a UTC date (today, or --date, at most 7 days back), exactly,
 * on stdout, and its size on stderr. send sends the reports that are due and prints nothing (a command line starts it
 * detached). forget turns telemetry off first, keeping the id, then asks the endpoint to erase every report under it;
 * without the endpoint's 204 it fails with sending off and the id kept, and forget again retries.
 */
export function telemetry(args: readonly string[], io: Io): number | Promise<number> {
  const [verb = '', ...rest] = args
  if (!VERBS.has(verb)) throw new UsageError(USAGE)
  const options: Record<string, OptionSpec> = verb === 'preview' ? { date: { type: 'string' } } : {}
  const date = str(parse(rest, { positionals: [], options }), 'date')
  const dir = telemetryDir(io.env)
  if (dir === null) throw new UsageError('no HOME: the machine telemetry directory is HOME/.bag')
  if (verb === 'preview') return preview(io, date)
  if (verb === 'send') return send(io)
  // on, off, status and forget are packages/home's act (telemetrySwitch); on stays a person's act on a terminal here.
  if (verb === 'on') needTty(io, 'telemetry on')
  const word = verb as 'on' | 'off' | 'status' | 'forget'
  const fetch = io.fetch === undefined ? {} : { fetch: io.fetch }
  return viaHome(() => telemetrySwitch(homeIo(io), word, fetch)).then(() => 0)
}

/** The report for `date`, today when absent, on stdout exactly as it would be sent, and its size on stderr. */
function preview(io: Io, date: string | undefined): number {
  const today = Math.floor(io.clock.now() / DAY)
  const days = Array.from({ length: 8 }, (_, i) => dateOf(today - i))
  const day = date ?? dateOf(today)
  if (!days.includes(day)) throw new UsageError('--date: a UTC date from 7 days ago to today, as YYYY-MM-DD')
  const text = JSON.stringify(telemetryReport(io.env, day))
  io.out(text)
  io.err(
    `telemetry preview: ${Buffer.byteLength(text)} bytes for ${day}; sent once, from 01:05 UTC the day after`,
  )
  return 0
}

/** Sends the reports that are due with the io's fetch, printing nothing; without a fetch, nothing. */
async function send(io: Io): Promise<number> {
  if (io.fetch !== undefined) await sendDueTelemetry(io.env, io.clock, { fetch: io.fetch })
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

/**
 * The verb a command line is counted under: help, version for `--version` (the dispatcher's two answers), a verb that
 * splits, else its command (the edge places it).
 */
export function verbOf(argv: readonly string[]): string {
  const [name = '', a = '', b = ''] = argv
  if (name === 'help' || argv.includes('--help') || argv.includes('-h')) return 'help'
  if (name === '--version') return 'version'
  return [`${name}-${a}-${b}`, `${name}-${a}`].find((v) => SPLIT.has(v)) ?? name
}

/** The `c` line of an install with a settings file: `c` is a shell function that sourcing the file defines. */
export const PREVIEW_C =
  'c telemetry preview, with c as your install defined it (after bag.dev/install: . "$HOME/.bag/install/<name>.env" first)'

/** The line when the install folder holds neither a settings file nor this version's checked package file. */
export const PREVIEW_PAGE =
  "the telemetry preview line of bag.dev/install's step 7, run in a terminal of your own"

/**
 * The command the notice names to print the report, as this CLI is run. From source: `node <main.ts> telemetry
 * preview`. From the package (`info`, the edge's build-info.ts) it reads the install folder `dir`
 * ($HOME/.bag/install). Exactly one package file of this version there (`usebag-bag-<version>-<16 hex>.tgz`, as the
 * three-line install keeps it) names the bag that runs now, so the line runs bag from that file with npx (the
 * registry by name would fetch other bytes), after it checks that the file's sha256 starts with the 16 hex its name
 * carries, else it prints STOP and runs nothing. Two such files mean one is not the published package, so neither is
 * named. Else a settings file (`<name>.env`) means an install that defines `c`, so PREVIEW_C; else PREVIEW_PAGE. The
 * path is written under "$HOME" as the install page writes it.
 */
export function previewCommand(
  info: BuildInfo | null = BUILD_INFO,
  main: string = process.argv[1] ?? 'packages/cli/src/main.ts',
  dir: string | null = null,
): string {
  if (info === null) return `node ${shq(main)} telemetry preview`
  let names: string[] = []
  try {
    names = dir === null ? [] : readdirSync(dir)
  } catch {
    // No install folder: the page's line.
  }
  const version = info.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const own = new RegExp(`^usebag-bag-${version}-([0-9a-f]{16})\\.tgz$`)
  const tgz = names.filter((n) => own.test(n))
  const [file] = tgz
  if (tgz.length === 1 && file !== undefined) {
    const prefix = own.exec(file)?.[1] ?? ''
    const f = `"$HOME/.bag/install/${file}"`
    return (
      `F=${f}; if [ "$( (sha256sum "$F" 2>/dev/null || shasum -a 256 "$F") | cut -c1-16)" = "${prefix}" ]; ` +
      `then (cd "$HOME/.bag/install" && npx --yes --package="$F" bag telemetry preview); ` +
      `else echo "STOP: $F is not the file its name says"; fi`
    )
  }
  if (tgz.length === 0 && names.some((n) => /^[a-z0-9][a-z0-9._-]*\.env$/.test(n))) return PREVIEW_C
  return PREVIEW_PAGE
}

/**
 * The notice once per machine (machineTelemetryNotice), on stderr after a command that returned rather than threw:
 * one a person ran at a terminal, and host install, the step that wires a server whose own stderr no person reads. It
 * names the preview as this CLI is run (previewCommand), never `ac telemetry on`, which a guide install lacks; a
 * machine without HOME gets none.
 */
export function notice(io: Io): void {
  const home = io.env.HOME
  const dir = home === undefined || home === '' ? null : join(home, '.bag', 'install')
  const text = machineTelemetryNotice(io.env, previewCommand(BUILD_INFO, undefined, dir))
  if (text !== null) io.err(text)
}
