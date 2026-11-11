import { execFileSync } from 'node:child_process'
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { join } from 'node:path'

// Host facts: what the host (omp, Claude Code) knows and an MCP server cannot see, its model, cost and context, written
// by the host beside the identity's doorbell and read here, never guessed (docs/agent-facts.md in the cut).

/** The file, in the identity's state directory, <home>/state/<name>/: the doorbell's directory. */
export const HOST_FACTS_FILE = 'host-facts.json'
/** The largest file read, in bytes. */
export const HOST_FACTS_MAX = 16_384
/** Older than this, in seconds, the facts are stale: two missed 5-minute heartbeats of a live host. */
export const STALE_SECONDS = 600

/** What a host writes (schema v1). Absent and null both mean the host did not provide it. */
export interface HostFacts {
  readonly v: 1
  readonly host: string
  readonly updated_at: string
  readonly host_version?: string | null
  readonly host_pid?: number | null
  readonly session_id?: string | null
  readonly main_session?: boolean | null
  readonly model?: string | null
  readonly cost_usd?: number | null
  readonly context_percent?: number | null
  readonly context_tokens?: number | null
  readonly fields_at?: Readonly<Record<string, string>>
}

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/
const isTime = (v: unknown): v is string =>
  typeof v === 'string' && ISO.test(v) && !Number.isNaN(Date.parse(v))
const text = (v: unknown): boolean => typeof v === 'string' && v.length > 0 && v.length <= 256
const count = (v: unknown): boolean => Number.isSafeInteger(v) && (v as number) >= 0

/** The optional fields and their checks; the measured ones (FIGURES) carry their own time and age in a view. */
const CHECKS = {
  host_version: text,
  host_pid: (v: unknown) => count(v) && (v as number) > 0,
  session_id: text,
  main_session: (v: unknown) => typeof v === 'boolean',
  model: text,
  cost_usd: (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v >= 0,
  context_percent: (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100,
  context_tokens: count,
} as const
type Field = keyof typeof CHECKS
export const FIGURES = ['model', 'cost_usd', 'context_percent', 'context_tokens'] as const

/** One measured field as the facts tool answers it: its value with its time and age, or why there is none. */
export type Figure =
  | { readonly value: string | number; readonly updated_at: string; readonly age_s: number }
  | { readonly value: null; readonly note: string }

/** The reader's answer: never an exception. */
export type HostFactsView =
  | { readonly state: 'missing' | 'malformed'; readonly path: string; readonly detail: string }
  | {
      readonly state: 'fresh' | 'stale'
      readonly path: string
      readonly detail: string
      readonly host: string
      readonly updated_at: string
      readonly age_s: number
      /** True when host_pid is among this server's ancestors, false when not (unverified), null when either is unknown. */
      readonly own_host: boolean | null
      readonly values: { readonly [K in Field]: unknown }
      readonly figures: { readonly [K in (typeof FIGURES)[number]]: Figure }
      readonly not_provided: readonly string[]
      readonly invalid: readonly string[]
    }

/** How many ancestor processes host_pid is looked for among: a host may start this server through npx, a shell or a shim. */
export const ANCESTOR_LEVELS = 4

/**
 * This process's nearest ancestors, parent first, at most ANCESTOR_LEVELS, read with `ps -o ppid=` (a pid only, never a
 * command line); the walk stops at pid 1 or the first answer that is not a pid, so it is [] where ps is missing.
 */
export function ancestors(
  parent: number = process.ppid,
  ppidOf: (pid: number) => string = (pid) =>
    execFileSync('ps', ['-o', 'ppid=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 1000,
      stdio: 'pipe',
    }),
): number[] {
  const out: number[] = []
  for (let pid = parent; pid > 1 && out.length < ANCESTOR_LEVELS; ) {
    out.push(pid)
    try {
      pid = Number.parseInt(ppidOf(pid).trim(), 10)
    } catch {
      break
    }
    if (!Number.isSafeInteger(pid)) break
  }
  return out
}

/** Reads a file of at most `max` bytes, refusing a link, a non-regular file and group or other permission bits. */
function readSmall(path: string, max: number): string {
  if (lstatSync(path).isSymbolicLink()) throw new Error('it is a symbolic link')
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw new Error('it is not a regular file')
    if ((st.mode & 0o077) !== 0) throw new Error(`its mode is ${(st.mode & 0o777).toString(8)}, not 600`)
    if (st.size > max) throw new Error(`it holds ${st.size} bytes, over ${max}`)
    const buf = Buffer.alloc(max + 1)
    const n = readSync(fd, buf, 0, max + 1, 0)
    if (n > max) throw new Error(`it holds over ${max} bytes`)
    return buf.subarray(0, n).toString('utf8')
  } finally {
    closeSync(fd)
  }
}

/**
 * The host facts in state directory `dir` at `now` (Unix seconds), for a server whose nearest ancestor processes are
 * `elders` (ancestors()):
 * missing, malformed (with why), or fresh or stale with each field, the ones the host did not provide named.
 */
export function readHostFacts(dir: string, now: number, elders: readonly number[]): HostFactsView {
  const path = join(dir, HOST_FACTS_FILE)
  let raw: string
  try {
    raw = readSmall(path, HOST_FACTS_MAX)
  } catch (e) {
    const code = (e as { code?: unknown }).code
    if (code === 'ENOENT') {
      const detail =
        'no host has written facts for this identity: the host provides none (no model, cost or context)'
      return { state: 'missing', path, detail }
    }
    return { state: 'malformed', path, detail: `${HOST_FACTS_FILE} is refused: ${(e as Error).message}` }
  }
  let o: Record<string, unknown>
  try {
    o = JSON.parse(raw)
    if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new Error('not a JSON object')
  } catch (e) {
    return {
      state: 'malformed',
      path,
      detail: `${HOST_FACTS_FILE} is not a JSON object: ${(e as Error).message}`,
    }
  }
  const bad = [
    o.v === 1 ? null : 'v is not 1',
    typeof o.host === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(o.host)
      ? null
      : 'host is not a host name',
    isTime(o.updated_at) ? null : 'updated_at is not an ISO 8601 UTC time',
  ].filter((m) => m !== null)
  if (bad.length > 0) return { state: 'malformed', path, detail: `${HOST_FACTS_FILE}: ${bad.join('; ')}` }
  const host = o.host as string
  const updatedAt = o.updated_at as string
  const ageOf = (at: string): number => Math.max(0, Math.round(now - Date.parse(at) / 1000))
  const at = (o.fields_at ?? {}) as Record<string, unknown>
  const values = {} as Record<Field, unknown>
  const notProvided: string[] = []
  const invalid: string[] = []
  for (const [f, ok] of Object.entries(CHECKS) as [Field, (v: unknown) => boolean][]) {
    const v = o[f]
    values[f] = v === undefined || v === null || !ok(v) ? null : v
    if (v === undefined || v === null) notProvided.push(f)
    else if (!ok(v)) invalid.push(f)
  }
  const figures = Object.fromEntries(
    FIGURES.map((f) => {
      const value = values[f] as string | number | null
      if (value === null) {
        const why = invalid.includes(f)
          ? `invalid in ${HOST_FACTS_FILE}, so not used`
          : `not provided by ${host}`
        return [f, { value: null, note: why }]
      }
      const when = typeof at === 'object' && isTime(at[f]) ? (at[f] as string) : updatedAt
      return [f, { value, updated_at: when, age_s: ageOf(when) }]
    }),
  ) as Record<(typeof FIGURES)[number], Figure>
  const age = ageOf(updatedAt)
  const stale = age > STALE_SECONDS
  const pid = values.host_pid as number | null
  const ownHost = pid === null || elders.length === 0 ? null : elders.includes(pid)
  const detail = [
    stale
      ? `stale: ${host} last wrote these ${age} s ago (over ${STALE_SECONDS} s): they are as of updated_at, and the host may be idle or gone`
      : `written by ${host} ${age} s ago`,
    ownHost === false
      ? `host_pid ${pid} is not this server's parent nor among its nearest ancestors (${elders.join(', ')}); the facts may come from another host process`
      : null,
  ]
    .filter((m) => m !== null)
    .join('; ')
  return {
    state: stale ? 'stale' : 'fresh',
    path,
    detail,
    host,
    updated_at: updatedAt,
    age_s: age,
    own_host: ownHost,
    values,
    figures,
    not_provided: notProvided,
    invalid,
  }
}
