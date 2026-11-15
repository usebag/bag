import { lstatSync, readlinkSync } from 'node:fs'
import { basename, join } from 'node:path'
import { HomeError } from './ports.ts'

// What the host files' writers share: the project form (host-install.ts), the user form (host-user.ts) and the
// migration (host-migrate.ts) each read and edit the same JSON and TOML, so the pieces they share live here and none
// of the three imports another's.

export type Json = Record<string, unknown>
export type Host = 'claude-code' | 'codex' | 'omp'

/**
 * What the host acts take from the process that runs them, so a test can name its own: the node to write, the node
 * running, the process id in the names of files written beside and renamed over, and the user's id.
 */
export interface HostProcess {
  /** The node another program's files name (stableNode, packaged.ts). */
  readonly node: string
  /** The node running: an entry an earlier install wrote with it is replaced, never refused. */
  readonly execPath: string
  readonly pid: number
  /** The user's id, where the platform has one. */
  readonly uid: number | undefined
}

/** A word as the shell reads it: as is when it holds only safe characters, else in single quotes. */
export const shq = (s: string): string => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`)

/**
 * The Codex table in the common spellings: a header with spaces or quoted keys, a dotted key, `bag = {...}` or
 * `mcp_servers = { bag = ... }` on one line, bag a whole key there (handbag is another server); a comment counts.
 * plugins/codex/install.sh writes the same name: two tables start two servers for one identity.
 */
export const TABLE =
  /\[\s*['"]?mcp_servers['"]?\s*\.\s*['"]?bag['"]?\s*[.\]]|^\s*(['"]?mcp_servers['"]?\s*\.\s*)?['"]?bag['"]?\s*[.=]|mcp_servers['"]?\s*=\s*\{(.*[,\s])?['"]?bag['"]?\s*=/m

/**
 * The wait the Claude Code hooks pass to wake-hook, in s, and their timeout above it: one idle wake a day, and the
 * silent second deadline after about two days, where wake-hook's default of 3500 s gave an hour and two. Claude Code
 * 2.1.316 kept such a hook past 3600 s and woke the idle session at its exit 2 (measured 2026-11-03 at 3700 s).
 */
export const WAKE_MAX = 86_000
export const WAKE_TIMEOUT = 86_400

/**
 * The seconds a Codex Stop hook waits for mail (`--max`). Short on purpose: the hook is awaited inline in the turn
 * loop and takes no cancellation from pending input (codex-rs core/src/session/turn.rs, core/src/hook_runtime.rs
 * run_turn_stop_hooks), so a message the person types waits out the wait; only an interrupt (Esc) ends it. Codex's own
 * default hook timeout is 600 s (hooks/src/engine/discovery.rs, normalize_command_hook). A lever, not a measure: raise
 * it for an unattended session that waits on peers.
 */
export const CODEX_STOP_WAIT = 30

/**
 * The `timeout` of that hook in hooks.json, above CODEX_STOP_WAIT. A hook that timed out would fail and the turn end
 * anyway (codex-rs hooks/src/events/stop.rs), so the margin is not a correctness need.
 */
export const CODEX_STOP_TIMEOUT = 60

/** The object under `key`, made when absent; host-file-invalid when it is there and is not an object. */
export function child(parent: Json, key: string): Json {
  if (parent[key] === undefined) parent[key] = {}
  const v = parent[key]
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new HomeError('host-file-invalid', `"${key}" is not a JSON object`)
  }
  return v as Json
}

/** Appends `{hooks: [hook]}` to `events[event]` unless a group there carries `hook.command`; true when it did. */
export function addGroup(events: Json, event: string, hook: Json): boolean {
  const groups = events[event] ?? []
  if (!Array.isArray(groups)) throw new HomeError('host-file-invalid', `hooks.${event} is not a list`)
  const has = (g: unknown) => JSON.stringify(g).includes(`"command":${JSON.stringify(hook.command)}`)
  if (groups.some(has)) return false
  events[event] = [...groups, { hooks: [hook] }]
  return true
}

/** The two names the omp wake link may have (from source .ts, from the package .js). */
export const ompLinks = (dir: string): string[] =>
  ['.js', '.ts'].map((x) => join(dir, '.omp', 'hooks', 'pre', `bag-wake${x}`))

/** Whether `link` is a symbolic link to an omp wake entry of bag (any home, any version). */
export function bagLink(link: string): boolean {
  try {
    if (!lstatSync(link).isSymbolicLink()) return false
    return ['bag-omp-wake.js', 'omp-wake.ts'].includes(basename(readlinkSync(link)))
  } catch {
    return false
  }
}
