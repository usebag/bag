import { randomBytes } from 'node:crypto'
import {
  appendFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { toHex } from '@usebag/core'
import { type Clock, RelayError, type Rng } from './ports.ts'
import { withPairs } from './telemetry-pairs.ts'
import {
  addCell,
  addTree,
  buildTelemetryReport,
  type Cells,
  countCell,
  dateOf,
  dayOf,
  durationCell,
  machineFacts,
  type TelemetryReport,
  treeOf,
} from './telemetry-report.ts'

// The telemetry switch and its counts (spec/SPEC.md Appendix B 111; the telemetry design note's §2 and §3):
// opt-in, one consent and one install id per machine, whatever the identity's home, in the machine's
// directory HOME/.bag (telemetryDir: a test or an e2e process points it elsewhere with HOME). telemetry.json holds the
// person's choice, written only by setTelemetry (`ac telemetry on|off`); an environment variable can only turn
// telemetry off. While it is on, every process of the machine counts into one spool beside it,
// telemetry-counts.jsonl, so the one report a day sums every home. This file builds the report (telemetryReport,
// `ac telemetry preview`) and has no network code; telemetry-send.ts sends each finished day's report once.

/**
 * The machine's choice, `{"version":2,"telemetry":"on","id":"<32 hex>","since":"<YYYY-MM-DD>"}` or
 * `{"version":2,"telemetry":"off"}`. A version-1 choice was made before the `pairs` family, which it does not cover:
 * it reads as off, `old-file`, and the notice asks again (the red team's Q2, 2026-11-03).
 */
export const TELEMETRY_FILE = 'telemetry.json'

/**
 * The machine's spool of counts beside the choice: one JSON line per flush, `{"v":1,"day":"<YYYY-MM-DD>","counts":
 * {...}}`, 0600, appended by every process of the machine. counts is a tree in the report's shape whose keys are the
 * schema's values only and whose leaves are raw counts: the caps and the buckets apply when a report is built.
 */
export const TELEMETRY_COUNTS_FILE = 'telemetry-counts.jsonl'

/** The last UTC date the sender took from the spool, `YYYY-MM-DD` and a newline (telemetry-send.ts). */
export const TELEMETRY_SENT_FILE = 'telemetry-sent'

/** The `pairs` snapshots of the machine's identities (telemetry-pairs.ts). */
export const TELEMETRY_PAIRS_FILE = 'telemetry-pairs.json'

/** The mark of a directory whose version-2 notice was shown, made exclusively by the first process that shows it. */
const NOTICED_FILE = 'telemetry-noticed-2'

/** The longest spool line a writer appends, its newline included, so that each append is one write under 4 KiB. */
const LINE_MAX = 4095

/** The spool's size past which a writer folds it: its lines summed by day, the days outside the window dropped. */
const FOLD_AT = 256 * 1024

/** The days before today a spool keeps: the Worker takes a date up to 8 days back, one of them for skew. */
export const SPOOL_DAYS = 7

/**
 * How long, in seconds, a process holds counts before it writes them, at its next count or by a timer when none comes:
 * a crash loses at most this, and a day's counts are written by 00:01 UTC, long before its report goes at 01:05.
 */
const HOLD = 60

/** The install id of a report previewed before `on` makes the machine's: 32 zeros, never a drawn id. */
export const PREVIEW_ID = '0'.repeat(32)

/** The first-run notice, a question under opt-in, once per machine: `preview` names the command that prints it. */
export function noticeText(preview: string): string {
  return [
    'bag: telemetry is off.',
    'It is used to find failures, see which versions, commands and tools are used,',
    'and decide what to build.',
    'If you turn it on, bag sends one report a day to telemetry.bag.dev:',
    'the version, OS, and counts of commands, messages, peers and error codes, under a random id.',
    'Never addresses, keys, messages, file paths or your IP address.',
    `See the exact report: ${preview}. Details: bag.dev/privacy`,
  ].join(' ')
}

/**
 * The notice for a caller that cannot name the command line; the CLI names its own (its previewCommand: `npx --yes
 * --package=@usebag/bag@<version> bag telemetry preview` from the package, `node <main.ts> telemetry preview` from
 * source). No notice names `ac telemetry on`, a command a guide install does not have (the spec owner's ruling 13).
 */
export const TELEMETRY_NOTICE = noticeText('telemetry preview, in the bag command line')

/**
 * What decided the state: the first environment variable that turns telemetry off (AC_TELEMETRY=off, 0, false or no;
 * DO_NOT_TRACK or CI set to anything but empty, 0, false, no or off), else the file: `file` for a choice, `no-file`
 * while none is made, `old-file` for a version-1 choice, `bad-file` for a file this version cannot read (each off until
 * `ac telemetry on|off` writes it again).
 */
export type TelemetryReason =
  | 'AC_TELEMETRY'
  | 'DO_NOT_TRACK'
  | 'CI'
  | 'file'
  | 'no-file'
  | 'old-file'
  | 'bad-file'

/** The state of a telemetry directory under an environment. It carries no install id: telemetryId reads that. */
export interface TelemetryState {
  /** True only when the file's choice is on and no environment variable turns it off. */
  readonly on: boolean
  readonly reason: TelemetryReason
  /** The choice in the file, whatever the environment says; null with no file or a bad one. */
  readonly choice: 'on' | 'off' | null
}

type Env = Readonly<Record<string, string | undefined>>
type Choice = { readonly choice: 'on' | 'off'; readonly id: string | null; readonly since: string | null }

const ID = /^[0-9a-f]{32}$/
const said = (v: string | undefined): boolean => v !== undefined && !/^(|0|false|no|off)$/i.test(v.trim())

/**
 * The file's choice; null when the file (or its directory) is absent; 'old' for a version-1 choice; 'bad' for one
 * this version cannot read.
 */
function readChoice(dir: string): Choice | 'old' | 'bad' | null {
  let text: string
  try {
    text = readFileSync(join(dir, TELEMETRY_FILE), 'utf8')
  } catch (e) {
    return (e as { code?: unknown }).code === 'ENOENT' ? null : 'bad'
  }
  try {
    const d = JSON.parse(text) as {
      version?: unknown
      telemetry?: unknown
      id?: unknown
      since?: unknown
    } | null
    if (d?.version === 1) return 'old'
    if (d?.version === 2 && d.telemetry === 'off') return { choice: 'off', id: null, since: null }
    const since = typeof d?.since === 'string' && dayOf(d.since) !== null ? d.since : null
    if (
      d?.version === 2 &&
      d.telemetry === 'on' &&
      typeof d.id === 'string' &&
      ID.test(d.id) &&
      since !== null
    ) {
      return { choice: 'on', id: d.id, since }
    }
  } catch {
    // not JSON: bad, as below
  }
  return 'bad'
}

/** A choice read, or null for none, an old one or a bad one. */
const chosen = (read: ReturnType<typeof readChoice>): Choice | null =>
  typeof read === 'object' ? read : null

/** The first environment variable that turns telemetry off, or null. */
function envOff(env: Env): TelemetryReason | null {
  if (/^(0|false|no|off)$/i.test(env.AC_TELEMETRY?.trim() ?? '')) return 'AC_TELEMETRY'
  if (said(env.DO_NOT_TRACK)) return 'DO_NOT_TRACK'
  return said(env.CI) ? 'CI' : null
}

/**
 * The state of the telemetry directory `dir` under `env`, read afresh on every call; it never throws, and anything
 * unreadable is off. The machine's is telemetryState(env, telemetryDir(env)), its on alone telemetryOn(env). C0's use
 * with an identity's home as `dir` is deprecated: consent is per machine.
 */
export function telemetryState(env: Env, dir: string): TelemetryState {
  const read = readChoice(dir)
  const choice = chosen(read)?.choice ?? null
  const fileReason =
    read === null ? 'no-file' : read === 'old' ? 'old-file' : read === 'bad' ? 'bad-file' : 'file'
  const reason = envOff(env) ?? fileReason
  return { on: reason === 'file' && choice === 'on', reason, choice }
}

/** The install id in `dir`, 32 lowercase hex (128 random bits), while its choice is on; else null. */
export function telemetryId(dir: string): string | null {
  return chosen(readChoice(dir))?.id ?? null
}

/** The UTC date the choice in `dir` turned on, while it is on; else null. Nothing before it is counted (Q8). */
export function telemetrySince(dir: string): string | null {
  return chosen(readChoice(dir))?.since ?? null
}

/**
 * Writes the choice to <dir>/telemetry.json, 0600, by a temporary file renamed over it, `dir` made 0700 when missing.
 * on keeps the id and the date a readable on-file holds, else draws an id from `rng`, never from the machine, a user or
 * a path, and dates it at `now` (seconds); off drops both, so the next on draws anew, and then deletes the spool of
 * counts, the sender's mark and the pairs snapshots. It makes no network call.
 */
export function setTelemetry(dir: string, choice: 'on' | 'off', rng: Rng, now = Date.now() / 1000): void {
  const held = chosen(readChoice(dir))
  const on =
    held?.choice === 'on' ? held : { id: toHex(rng.bytes(16)), since: dateOf(Math.floor(now / 86_400)) }
  const doc =
    choice === 'on'
      ? { version: 2, telemetry: choice, id: on.id, since: on.since }
      : { version: 2, telemetry: choice }
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const path = join(dir, TELEMETRY_FILE)
  const tmp = `${path}.${toHex(rng.bytes(8))}.tmp`
  writeFileSync(tmp, `${JSON.stringify(doc)}\n`, {
    flag: 'wx',
    mode: 0o600,
  })
  try {
    renameSync(tmp, path)
  } catch (e) {
    rmSync(tmp, { force: true })
    throw e
  }
  if (choice === 'off') dropSpool(dir)
}

/** Deletes the spool in `dir`, any a fold left taken, the sender's mark and the pairs snapshots. */
function dropSpool(dir: string): void {
  for (const name of readdirSync(dir)) {
    if (
      name === TELEMETRY_COUNTS_FILE ||
      name === TELEMETRY_SENT_FILE ||
      name === TELEMETRY_PAIRS_FILE ||
      /^telemetry-counts\.jsonl\.[0-9a-f]+\.taken$/.test(name)
    ) {
      rmSync(join(dir, name), { force: true })
    }
  }
}

/**
 * The machine's telemetry directory, HOME/.bag: one per machine whatever the identity's home (--dir, AC_HOME), read
 * from `env` so that a test or an e2e process points it elsewhere with HOME; null without HOME, and telemetry is off.
 */
export function telemetryDir(env: Env): string | null {
  return env.HOME ? join(env.HOME, '.bag') : null
}

/** Whether the machine's telemetry is on: its choice on, and no variable turning it off (checked first, no file). */
export function telemetryOn(env: Env): boolean {
  const dir = telemetryDir(env)
  if (dir === null || envOff(env) !== null) return false
  return chosen(readChoice(dir))?.choice === 'on'
}

/** Whether the notice asks: no choice is made, or only a version-1 one. */
const asks = (env: Env, dir: string): boolean =>
  ['no-file', 'old-file'].includes(telemetryState(env, dir).reason)

/**
 * The notice, once per `dir`: its text while no choice is made, or a version-1 one, to the first caller (any process,
 * CLI or bridge: it makes <dir>/telemetry-noticed-2, 0600, exclusively), naming `preview` when given; else null. A `dir`
 * that does not exist gets none, and it never throws: a notice must not fail the caller's command.
 */
export function telemetryNotice(env: Env, dir: string, preview?: string): string | null {
  if (!asks(env, dir)) return null
  try {
    writeFileSync(join(dir, NOTICED_FILE), '', { flag: 'wx', mode: 0o600 })
    return preview === undefined ? TELEMETRY_NOTICE : noticeText(preview)
  } catch {
    return null // shown already (EEXIST), or no such directory
  }
}

/**
 * The notice once per machine: telemetryNotice in the machine's directory, made 0700 when missing so that a new
 * machine's first command shows it; null without HOME, and it never throws.
 */
export function machineTelemetryNotice(env: Env, preview?: string): string | null {
  const dir = telemetryDir(env)
  if (dir === null || !asks(env, dir)) return null
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  } catch {
    return null
  }
  return telemetryNotice(env, dir, preview)
}

/**
 * Adds `counts` to the machine's spool for the UTC date `day` (YYYY-MM-DD): the store's one writer. counts is in
 * the report's shape: the schema's member names, each map keyed as the schema keys it, raw counts at the leaves, a
 * duration family's leaves five counts in SETS.duration's order. A key outside its set is stored as `other`, and
 * anything but a member, a key or a positive integer is left out, so the file holds the schema's values only. Each
 * line is one append under 4 KiB (O_APPEND, no lock). A no-op unless telemetry is on, and it never throws.
 */
export function addTelemetryCounts(env: Env, day: string, counts: Readonly<Record<string, unknown>>): void {
  try {
    const cells: Cells = new Map()
    addTree(cells, counts)
    writeCells(env, day, cells)
  } catch {
    // A count must not fail its caller: the counts are lost.
  }
}

function writeCells(env: Env, day: string, cells: Cells): void {
  const dir = telemetryDir(env)
  const today = dayOf(day)
  if (dir === null || today === null || cells.size === 0 || !telemetryOn(env)) return
  const file = join(dir, TELEMETRY_COUNTS_FILE)
  for (const line of linesOf(day, [...cells])) appendFileSync(file, `${line}\n`, { mode: 0o600 })
  if (statSync(file).size > FOLD_AT) foldSpool(dir, today)
}

/** A day's cells as spool lines, each under LINE_MAX: halved until each fits. */
function linesOf(day: string, cells: readonly (readonly [string, number])[]): string[] {
  const line = JSON.stringify({ v: 1, day, counts: treeOf(cells) })
  if (line.length < LINE_MAX || cells.length < 2) return [line]
  const half = Math.ceil(cells.length / 2)
  return [...linesOf(day, cells.slice(0, half)), ...linesOf(day, cells.slice(half))]
}

function parsed(line: string): Readonly<Record<string, unknown>> | null {
  try {
    const v: unknown = JSON.parse(line)
    return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/** The spool `file`, summed by day; a line that is not one, or whose day is not a date, is left out. */
function spoolOf(file: string): Map<string, Cells> {
  const days = new Map<string, Cells>()
  let text = ''
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    return days
  }
  for (const line of text.split('\n')) {
    const v = parsed(line)
    if (v?.v !== 1 || typeof v.day !== 'string' || dayOf(v.day) === null) continue
    const cells = days.get(v.day) ?? new Map<string, number>()
    days.set(v.day, cells)
    addTree(cells, v.counts)
  }
  return days
}

/** The machine's spool in `dir`, summed by day: every home's counts, from every process. */
export function readTelemetrySpool(dir: string): Map<string, Cells> {
  return spoolOf(join(dir, TELEMETRY_COUNTS_FILE))
}

/** The size of the spool in `dir`, in bytes; 0 when there is none. */
export function telemetrySpoolBytes(dir: string): number {
  try {
    return statSync(join(dir, TELEMETRY_COUNTS_FILE)).size
  } catch {
    return 0
  }
}

/**
 * Takes the spool in `dir`: renames the file (writers then start a new one), sums its lines by day, appends the days
 * `keep` holds back as lines, and returns the others; none when there is no spool. The rename is the exclusion: of two
 * takers, one gets the file and the other none, or a new one. A count appended to the taken file after it was read is
 * lost: the price of no lock.
 */
export function takeSpool(dir: string, keep: (day: string) => boolean): Map<string, Cells> {
  const file = join(dir, TELEMETRY_COUNTS_FILE)
  const taken = `${file}.${randomBytes(8).toString('hex')}.taken`
  const rest = new Map<string, Cells>()
  try {
    renameSync(file, taken)
  } catch {
    return rest
  }
  for (const [day, cells] of spoolOf(taken)) {
    if (!keep(day)) rest.set(day, cells)
    else for (const line of linesOf(day, [...cells])) appendFileSync(file, `${line}\n`, { mode: 0o600 })
  }
  rmSync(taken, { force: true })
  return rest
}

/** Folds the spool: keeps the days of the window, SPOOL_DAYS before the day number `today` to the day after. */
function foldSpool(dir: string, today: number): void {
  const [from, to] = [dateOf(today - SPOOL_DAYS), dateOf(today + 1)]
  takeSpool(dir, (day) => day >= from && day <= to)
}

/**
 * The report this machine would send for the UTC date `day`, exactly: the day's counts of its spool, every home's,
 * under its install id, or PREVIEW_ID while it has none (its spool is then empty: off drops both), with its facts.
 */
export function telemetryReport(env: Env, day: string): TelemetryReport {
  const dir = telemetryDir(env)
  const id = dir === null ? null : telemetryId(dir)
  const cells = dir === null ? new Map() : withPairs(dir, day, readTelemetrySpool(dir).get(day) ?? new Map())
  return buildTelemetryReport(day, cells, machineFacts(id ?? PREVIEW_ID))
}

/** The counts a process holds until it writes them to the spool, while it counts. */
interface Tally {
  readonly env: Env
  readonly clock: Clock
  readonly days: Map<string, Cells>
  users: number
  since: number
  /** Writes what is held HOLD seconds after a count that did not write, unless a write comes first. */
  timer: ReturnType<typeof setTimeout> | null
}

let tally: Tally | null = null

/**
 * Starts this process counting into the machine's spool while telemetry is on, and says whether it does; each start
 * that returns true is ended by one stopTelemetry. The CLI starts it for each command line, a server once.
 */
export function startTelemetry(env: Env, clock: Clock): boolean {
  if (tally === null && telemetryOn(env)) {
    tally = { env, clock, days: new Map(), users: 0, since: clock.now(), timer: null }
  }
  if (tally !== null) tally.users++
  return tally !== null
}

/** Writes the process's counts to the spool, and stops counting at the end of the last start. */
export function stopTelemetry(): void {
  const t = tally
  if (t === null) return
  flushTelemetry()
  t.users--
  if (t.users <= 0) tally = null
}

/** Writes the process's counts to the machine's spool, a line or more per day, and empties them; it never throws. */
export function flushTelemetry(): void {
  const t = tally
  if (t === null) return
  if (t.timer !== null) clearTimeout(t.timer)
  t.timer = null
  t.since = t.clock.now()
  const days = [...t.days]
  t.days.clear()
  for (const [day, cells] of days) {
    try {
      writeCells(t.env, day, cells)
    } catch {
      // A count must not fail its caller: the counts are lost.
    }
  }
}

function tallied(key: string | null): void {
  const t = tally
  if (t === null || key === null) return
  try {
    const now = t.clock.now()
    const day = dateOf(Math.floor(now / 86_400))
    const cells = t.days.get(day) ?? new Map<string, number>()
    t.days.set(day, cells)
    addCell(cells, key, 1)
    // A server that goes quiet in the last minute of a day would otherwise hold it past 01:05, when the sender takes
    // the day: what it held would then reach the spool as a second report of that day, which the endpoint drops.
    if (now - t.since >= HOLD) flushTelemetry()
    else t.timer ??= setTimeout(flushTelemetry, HOLD * 1000).unref()
  } catch {
    // A count must not fail its caller.
  }
}

/**
 * Counts one event of a count family: the schema's member name, then a key for each of its sets, a key outside its
 * set counted as `other`. Nothing while the process does not count, so a hook costs one test when telemetry is off.
 */
export function countTelemetry(member: string, keys: readonly unknown[]): void {
  if (tally !== null) tallied(countCell(member, keys))
}

/** Counts one duration of `ms` milliseconds under a key of a duration family (cli_durations, mcp_durations). */
export function countDuration(member: string, key: unknown, ms: number): void {
  if (tally !== null) tallied(durationCell(member, key, ms))
}

/** Counts one call to the relay at `url` by the relay's name, never its URL; nothing while counting is off. */
export function countRelayCall(url: string): void {
  if (tally !== null) tallied(countCell('relays', [relayName(url)]))
}

/** Counts one failure at the relay at `url` by the relay's name and the failure's code (telemetryCode). */
export function countRelayError(url: string, e: unknown): void {
  if (tally !== null) tallied(countCell('relay_errors', [relayName(url), telemetryCode(e)]))
}

/** The schema's name of a relay: relay1 or relay2 for the two public relays, else `other`, never its URL. */
export function relayName(url: string): string {
  const host = URL.canParse(url) ? new URL(url).hostname : ''
  return host === 'relay1.bag.dev' ? 'relay1' : host === 'relay2.bag.dev' ? 'relay2' : 'other'
}

/** The code a failure is counted under, as the CLI names one: its own, unreachable, http-<status>, else error. */
export function telemetryCode(e: unknown): string {
  if (e instanceof RelayError) return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
  const code = (e as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : 'error'
}
