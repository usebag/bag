import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Clock } from './ports.ts'
import {
  SPOOL_DAYS,
  TELEMETRY_COUNTS_FILE,
  TELEMETRY_SENT_FILE,
  takeSpool,
  telemetryDir,
  telemetryId,
  telemetryOn,
} from './telemetry.ts'
import { noteTrackedPairs, withPairs } from './telemetry-pairs.ts'
import { buildTelemetryReport, dateOf, dayOf, machineFacts } from './telemetry-report.ts'

// The sender (the telemetry design note's §4 and §5; the W6 design note in the operations records, §5): each finished
// UTC day's report, exactly the one `telemetry preview --date` prints, as one POST to telemetry.bag.dev, once. A day is
// due from 01:05 UTC of the next: every held count is written by then. The sender takes the finished days out of the
// spool before its first request, so a day goes after one try whatever the answer (the Worker's DESIGN.md: the client
// never shows an answer and never retries before the next day). One 2 s budget covers every request of a try, no
// redirect is followed, and the switch and the id are read again before each request (the privacy review's E7). It
// never throws. The CLI never sends in its own process: it starts `telemetry send` detached; the MCP server and the
// bridge send in theirs, hourly (startTelemetrySender). The only header set is the content type.

/** The endpoint's origin. */
const ORIGIN = 'https://telemetry.bag.dev'

/** The seconds after midnight UTC from which yesterday may be sent. */
const SEND_AFTER = 3_900

/** How long one try may take, every request of it together, in ms. */
const BUDGET_MS = 2_000

/** How often a long-running process tries, in ms. */
const HOUR_MS = 3_600_000

/** The day, in seconds. */
const DAY = 86_400

type Env = Readonly<Record<string, string | undefined>>

/** How a sender or an erasure reaches the endpoint. */
export interface SendOptions {
  /** The fetch to send with; the caller passes it (the CLI's and the servers' io), so a test without one sends nothing. */
  readonly fetch: typeof fetch
  /** Aborts a try in flight (startTelemetrySender's stop). */
  readonly signal?: AbortSignal
  /** The budget of one try, in ms (default 2,000), for tests. */
  readonly budgetMs?: number
}

/**
 * The URL of `path` at the endpoint: telemetry.bag.dev's, or at AC_TELEMETRY_URL when that parses as http with the
 * host exactly 127.0.0.1 or ::1 (a test's local endpoint; never a prefix or a name). Null for any other value of it,
 * and then nothing is sent.
 */
export function telemetryEndpoint(env: Env, path: '/v1/report' | '/v1/erase'): string | null {
  const local = env.AC_TELEMETRY_URL
  if (local === undefined || local === '') return `${ORIGIN}${path}`
  const url = URL.canParse(local) ? new URL(local) : null
  const loopback = url?.hostname === '127.0.0.1' || url?.hostname === '[::1]'
  return url?.protocol === 'http:' && loopback && url.username === '' && url.password === ''
    ? `${url.origin}${path}`
    : null
}

/** The last UTC date the sender took from the spool in `dir`, or null. */
export function telemetrySent(dir: string): string | null {
  try {
    const text = readFileSync(join(dir, TELEMETRY_SENT_FILE), 'utf8').trim()
    return dayOf(text) === null ? null : text
  } catch {
    return null
  }
}

/**
 * Whether a try is due at the clock's time: telemetry on, 01:05 UTC passed, a spool, and yesterday not yet taken. A
 * stat and two small reads, so the CLI asks after every command line. Never throws.
 */
export function telemetryDue(env: Env, clock: Clock): boolean {
  try {
    const dir = telemetryDir(env)
    const now = clock.now()
    const today = Math.floor(now / DAY)
    if (dir === null || now - today * DAY < SEND_AFTER || !telemetryOn(env)) return false
    const sent = telemetrySent(dir)
    return (sent === null || sent < dateOf(today - 1)) && statSync(join(dir, TELEMETRY_COUNTS_FILE)).size > 0
  } catch {
    return false
  }
}

/**
 * One try, when due: takes the spool's finished days (the window's, at most SPOOL_DAYS back; older ones are dropped)
 * and marks yesterday taken, then POSTs each day's report, oldest first, while the switch is still on under the same
 * id. Resolves when the try ends; never throws, and shows nothing of an answer.
 */
export async function sendDueTelemetry(env: Env, clock: Clock, options: SendOptions): Promise<void> {
  try {
    if (!telemetryDue(env, clock)) return
    noteTrackedPairs()
    const dir = telemetryDir(env) as string
    const today = Math.floor(clock.now() / DAY)
    const [from, yesterday] = [dateOf(today - SPOOL_DAYS), dateOf(today - 1)]
    const days = takeSpool(dir, (day) => day > yesterday)
    // The mark, 0600; a torn one reads as none, and the next try finds nothing left to send.
    writeFileSync(join(dir, TELEMETRY_SENT_FILE), `${yesterday}\n`, { mode: 0o600 })
    const id = telemetryId(dir)
    const url = telemetryEndpoint(env, '/v1/report')
    if (id === null || url === null) return
    const bodies = [...days]
      .filter(([day]) => day >= from)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([day, cells]) =>
        JSON.stringify(buildTelemetryReport(day, withPairs(dir, day, cells), machineFacts(id))),
      )
    const budget = AbortSignal.timeout(options.budgetMs ?? BUDGET_MS)
    const signal = options.signal === undefined ? budget : AbortSignal.any([budget, options.signal])
    for (const body of bodies) {
      if (!telemetryOn(env) || telemetryId(dir) !== id) return
      const res = await post(options.fetch, url, body, signal)
      if (res === null) return
    }
  } catch {
    // A try must not fail its caller: what it took is gone.
  }
}

/** One POST of a JSON body, following no redirect; the response with its body dropped, or null when it failed. */
async function post(
  f: typeof fetch,
  url: string,
  body: string,
  signal: AbortSignal,
): Promise<Response | null> {
  try {
    const res = await f(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      redirect: 'error',
      signal,
    })
    await res.body?.cancel()
    return res
  } catch {
    return null
  }
}

/**
 * A long-running process's sender (the MCP server, the bridge): a try now and every hour after, never awaited by a
 * caller. The stop it returns clears the hour and aborts a try in flight.
 */
export function startTelemetrySender(env: Env, clock: Clock, options: SendOptions): () => void {
  const stop = new AbortController()
  const tryNow = (): void => {
    void sendDueTelemetry(env, clock, { ...options, signal: stop.signal })
  }
  tryNow()
  const timer = setInterval(tryNow, HOUR_MS)
  timer.unref()
  return () => {
    clearInterval(timer)
    stop.abort()
  }
}

/**
 * Asks the endpoint to erase every report under the install id `id`: POST /v1/erase with the body exactly
 * `{"id":"<id>"}`, under the same options and budget as a try. `ok` for its 204, else the failure's code:
 * `unreachable`, `http-<status>`, or `usage` when AC_TELEMETRY_URL names no loopback endpoint.
 */
export async function eraseTelemetry(env: Env, id: string, options: SendOptions): Promise<string> {
  const url = telemetryEndpoint(env, '/v1/erase')
  if (url === null) return 'usage'
  const signal = AbortSignal.timeout(options.budgetMs ?? BUDGET_MS)
  const res = await post(options.fetch, url, JSON.stringify({ id }), signal)
  return res === null ? 'unreachable' : res.status === 204 ? 'ok' : `http-${res.status}`
}
