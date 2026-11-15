import {
  eraseTelemetry,
  setTelemetry,
  telemetryDir,
  telemetryEraseIds,
  telemetryId,
  telemetrySent,
  telemetrySpoolBytes,
  telemetryState,
} from '@usebag/edge'
import { HomeError, type HomeIo } from './ports.ts'

// The machine's telemetry switch (the edge's telemetry.ts): on, off, status and forget, one consent and one install id per
// machine in HOME/.bag, whatever the home. The command line and the MCP server both run it; each asks its own question.

/** The question the command line asks for on, at the terminal; one y turns it on. */
export const TELEMETRY_ON_QUESTION = [
  'turn telemetry on for this machine? Once a day bag then sends one report to telemetry.bag.dev: the version, the OS',
  '  and counts of commands, messages, peers and error codes, under a random id; never an address, a key, a message or',
  "  a file path. The report holds no IP address and bag's server stores none; Cloudflare's rate limiter sees it.",
  '  bag telemetry preview prints the exact report; the details are at bag.dev/privacy.',
].join('\n')

/** The refusal with no HOME: the machine's telemetry directory is HOME/.bag. */
export const NO_TELEMETRY_HOME = 'no HOME: the machine telemetry directory is HOME/.bag'

/**
 * off's second line where the install id must not be shown (a tool's answer reaches the model and its provider): forget,
 * not off, is the act that also erases the reports already sent.
 */
export const OFF_USE_FORGET =
  'to also erase the reports already sent, use forget instead of off (here, or `bag telemetry forget` in a terminal); off keeps them up to 90 days'

/** The machine's telemetry directory under `env`, or usage without HOME. */
export function machineTelemetryDir(env: HomeIo['env']): string {
  const dir = telemetryDir(env)
  if (dir === null) throw new HomeError('usage', NO_TELEMETRY_HOME)
  return dir
}

/**
 * The state line: "telemetry <on|off> reason=<reason> choice=<on|off|none> id=<32 hex|none> spool=<bytes>
 * sent=<YYYY-MM-DD|none>". An environment variable that turns it off (AC_TELEMETRY=off, DO_NOT_TRACK, CI) is the
 * reason whatever the choice. With `showId` false the id is id=set or id=none, never its value.
 */
export function telemetryLine(env: HomeIo['env'], dir: string, showId = true): string {
  const { on, reason, choice } = telemetryState(env, dir)
  const state = `telemetry ${on ? 'on' : 'off'} reason=${reason} choice=${choice ?? 'none'}`
  const sent = telemetrySent(dir) ?? 'none'
  const id = telemetryId(dir)
  const shown = id === null ? 'none' : showId ? id : 'set'
  return `${state} id=${shown} spool=${telemetrySpoolBytes(dir)} sent=${sent}`
}

/** How telemetrySwitch runs: whether a line may carry the install id, and forget's fetch (none: unreachable). */
export interface TelemetryOptions {
  /** False for an MCP tool's answer: no line or refusal carries the id (the state line says id=set). */
  readonly showId?: boolean
  readonly fetch?: typeof fetch
}

/**
 * on, off, status or forget of the machine's telemetry. on asks first (io.ask, TELEMETRY_ON_QUESTION; declined on a no, with
 * nothing changed), asked again when it is already on, and keeps the install id or makes one. off removes it, the
 * spool of counts and the sender's mark, network-free, and asks nothing: it never waits on an on's question. status
 * asks nothing. forget asks nothing either (it only withdraws): it turns telemetry off first, keeping in the file
 * (telemetryEraseIds) every id it will ask to erase: those an earlier forget left unconfirmed, then the install id if
 * on. It asks the endpoint to erase each in that order and drops each the endpoint confirms (204); any failure ends
 * it with sending off and every unconfirmed id kept, so forget run again asks again. An on meanwhile draws a new id
 * and keeps the unconfirmed ones beside it, and off keeps them too. Each says the state line; off
 * then names the id it removed, which can still be erased, and forget the erasure accepted. With `showId` false no
 * line and no refusal carries the id: off says OFF_USE_FORGET in place of its id line.
 */
export async function telemetrySwitch(
  io: HomeIo,
  word: 'on' | 'off' | 'status' | 'forget',
  o: TelemetryOptions = {},
): Promise<void> {
  const dir = machineTelemetryDir(io.env)
  const showId = o.showId !== false
  if (word === 'forget') return forget(io, dir, showId, o.fetch)
  if (word === 'on') {
    if (!(await io.ask(TELEMETRY_ON_QUESTION)))
      throw new HomeError('declined', 'nothing was changed; telemetry stays as it was')
    setTelemetry(dir, 'on', io.rng, io.clock.now())
  }
  const removed = word === 'off' ? telemetryId(dir) : null
  if (word === 'off') setTelemetry(dir, 'off', io.rng, io.clock.now())
  io.say(telemetryLine(io.env, dir, showId))
  if (removed !== null)
    io.say(
      showId
        ? `telemetry off: reports already sent stay up to 90 days; to erase them, send ${removed} to privacy@bag.dev`
        : OFF_USE_FORGET,
    )
}

/** The ids a line names: each id joined by "and", or with `showId` false the machine's id or ids, never a value. */
const idsNamed = (ids: readonly string[], showId: boolean): string =>
  showId ? ids.join(' and ') : ids.length === 1 ? "this machine's id" : "this machine's ids"

/**
 * forget: off first, with every id to erase kept in the file (the unconfirmed ones first, then the install id); then
 * the erasure of each, each confirmed one dropped at once. A failure leaves sending off and every unconfirmed id kept,
 * so a second forget asks again for those alone.
 */
async function forget(io: HomeIo, dir: string, showId: boolean, f?: typeof fetch): Promise<void> {
  const current = telemetryId(dir)
  const ids = [...new Set([...telemetryEraseIds(dir), ...(current === null ? [] : [current])])]
  if (ids.length === 0)
    throw new HomeError('not-found', 'no install id: telemetry is not on, so nothing is erased from here')
  // Sending stops on disk before the network call, so a failed or slow erasure never leaves telemetry on.
  setTelemetry(dir, 'off', io.rng, io.clock.now(), ids)
  let left = ids
  let code: string | null = null
  for (const id of ids) {
    const got = f === undefined ? 'unreachable' : await eraseTelemetry(io.env, id, { fetch: f })
    if (got !== 'ok') {
      code ??= got
      continue
    }
    left = left.filter((x) => x !== id)
    setTelemetry(dir, 'off', io.rng, io.clock.now(), left)
  }
  if (code !== null) {
    // Through a tool the ids stay out of the line; at a terminal they can also be sent by hand.
    const one = left.length === 1
    const after = showId ? `, or send the ${one ? 'id' : 'ids'} to privacy@bag.dev` : ''
    const kept = one ? 'so the id is kept' : 'so the ids are kept'
    throw new HomeError(
      code,
      `sending is off; the erasure of ${idsNamed(left, showId)} failed, ${kept}: run forget again to retry${after}`,
    )
  }
  io.say(telemetryLine(io.env, dir, showId))
  io.say(`telemetry forget: the erasure of ${idsNamed(ids, showId)} was accepted; telemetry off`)
}
