import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import { canonical, sha256hex } from '@usebag/core'
import { processStart } from '../adapters/fs-lock.ts'

// A Claude Code session's name under the agent, alike in its MCP server and wake hook: the
// topmost of the first unbroken run of `claude` ancestors; a shell between two `claude` processes ends a run.
//
// The `claude` predicate, exactly (isClaudeCommand), true for one of three forms and false for anything else:
//   1. the executable path, when ps gives one (`ps -o comm=`), has the base name `claude` (this holds for a path with
//      spaces);
//   2. the base name of the first whitespace-separated word of the command line is `claude`: `claude`,
//      `/Users/u/.local/bin/claude --model opus`, VS Code's `.../resources/native-binary/claude --output-format ...` (a
//      path with spaces is only seen through form 1);
//   3. an npm launch: the first word is `node`, and the first word after node's own options is a path whose base name is
//      `claude`, or `cli.js` under `/@anthropic-ai/claude-code/`.
// `node /x/claude.js`, `node claude` (no path), `claude-helper`, `/bin/zsh -c claude -p hi` are not claude. The walk starts at the caller's own pid (or
// options.pid) and goes up through ppid; the run begins at the first claude ancestor and ends at the first ancestor that
// is not claude (or pid 1, a process ps cannot read, or 64 steps). When no ancestor is claude, or the anchor's start
// cannot be read, sessionAnchor throws SessionNameError `no-session`: no caller falls back to another name.

/** A process as `ps` shows it: its parent's pid, its command line and, when ps gives it, its executable path. */
export type ProcessInfo = { readonly ppid: number; readonly command: string; readonly exe?: string }

/** The walk's start (default process.pid), its ps reader (psInfo) and start reader (processStart). */
export interface SessionNameOptions {
  readonly pid?: number
  readonly info?: (pid: number) => ProcessInfo | null
  readonly startOf?: (pid: number) => number | null
}

/** The resolved name, `s-<16 hex>`, and the main `claude` process it is anchored on. */
export type SessionName = {
  readonly name: string
  readonly anchor: { readonly pid: number; readonly start: number }
}

/** No `claude` ancestor, or its start cannot be read: the caller is not inside a Claude Code session. */
export class SessionNameError extends Error {
  readonly code = 'no-session'
}

/** `ps -o ppid=,command= -p <pid>` (and `-o comm=` for the executable path) in the C locale, or null when ps cannot say. */
export function psInfo(pid: number): ProcessInfo | null {
  try {
    const out = execFileSync('ps', ['-o', 'ppid=,command=', '-p', String(pid)], {
      encoding: 'utf8',
      env: { ...process.env, LC_ALL: 'C' },
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
    })
    // A line ps prints that does not parse makes m null, and m[1] below throws: the catch reads it as null.
    const m = /^(\d+)\s+(.*)$/s.exec(out.trim()) as RegExpExecArray
    const exe = execFileSync('ps', ['-o', 'comm=', '-p', String(pid)], {
      encoding: 'utf8',
      env: { ...process.env, LC_ALL: 'C' },
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
    }).trim()
    // An empty comm is kept as it is: isClaudeCommand reads basename('') as no executable.
    return { ppid: Number(m[1]), command: m[2] as string, exe }
  } catch {
    return null
  }
}

/** True when a process is claude: its executable, its command or an npm launch (see the header). */
export function isClaudeCommand(command: string, exe?: string): boolean {
  if (exe !== undefined && basename(exe) === 'claude') return true
  // split always returns at least one word (an empty string for an empty command), so words[0] is defined.
  const words = command.trim().split(/\s+/)
  const first = basename(words[0] as string)
  if (first === 'claude') return true
  if (first !== 'node') return false
  const script = words.slice(1).find((w) => !w.startsWith('-')) ?? ''
  if (!script.includes('/')) return false
  return (
    basename(script) === 'claude' ||
    (basename(script) === 'cli.js' && script.includes('/@anthropic-ai/claude-code/'))
  )
}

/** The main `claude` process of the session `options.pid` (default this process) runs in, and its start. */
export function sessionAnchor(options: SessionNameOptions = {}): {
  readonly pid: number
  readonly start: number
} {
  const { info = psInfo, startOf = processStart } = options
  let [pid, top] = [options.pid ?? process.pid, 0]
  for (let depth = 0; depth < 64 && pid > 1; depth++) {
    const p = info(pid)
    if (p === null) break
    if (isClaudeCommand(p.command, p.exe)) top = pid
    else if (top !== 0) break
    pid = p.ppid
  }
  if (top === 0) throw new SessionNameError(`no claude process above pid ${options.pid ?? process.pid}`)
  const start = startOf(top)
  if (start === null) throw new SessionNameError(`the start of claude pid ${top} cannot be read`)
  return { pid: top, start }
}

/** The session name of `principal` (an address) for the Claude Code session this process runs in. */
export function resolveSessionName(principal: string, options: SessionNameOptions = {}): SessionName {
  const anchor = sessionAnchor(options)
  const label = sha256hex(canonical(['ac/session-name/1', principal, anchor.pid, anchor.start])).slice(0, 16)
  return { name: `s-${label}`, anchor }
}

/**
 * A Codex session's id: the `sessionId` Codex puts in each tools/call's `_meta`, or its `threadId`, and the
 * `session_id` of its hooks' stdin, all the root thread's id, a uuid. Lowercased; anything else throws `no-session`.
 */
export function codexSessionId(raw: unknown): string {
  if (typeof raw !== 'string' || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(raw)) {
    throw new SessionNameError(`a Codex session id is a uuid, not ${JSON.stringify(raw)}`)
  }
  return raw.toLowerCase()
}

/** The session name of `principal` (an address) for Codex session `id`: its own domain tag, so never a Claude name. */
export const codexSessionName = (principal: string, id: string): string =>
  `s-${sha256hex(canonical(['ac/session-name/codex/1', principal, codexSessionId(id)])).slice(0, 16)}`

/**
 * What the MCP server of a session leaves for its wake hook: <home>/state/sessions/<anchor pid>-<anchor start>.json,
 * mode 0600. The hook walks to its own anchor with sessionAnchor and reads this file without hashing; a pid reused by
 * another process has another start, so it finds no file.
 */
export interface SessionFile {
  readonly v: 1
  readonly name: string
  readonly principal: string
  readonly pid: number
  readonly start: number
}

export const sessionFilePath = (
  home: string,
  anchor: { readonly pid: number; readonly start: number },
): string => join(home, 'state', 'sessions', `${anchor.pid}-${anchor.start}.json`)

/** Writes the file (a mode 0600 temporary file, then a rename), making <home>/state/sessions at mode 0700. */
export function writeSessionFile(home: string, file: SessionFile): string {
  const path = sessionFilePath(home, file)
  mkdirSync(join(home, 'state', 'sessions'), { recursive: true, mode: 0o700 })
  const temp = `${path}.${process.pid}.tmp`
  try {
    writeFileSync(temp, `${JSON.stringify(file)}\n`, { mode: 0o600 })
    renameSync(temp, path)
  } catch (e) {
    rmSync(temp, { force: true })
    throw e
  }
  return path
}

/** A session file that is present and malformed: unparsable, not version 1, a bad name, or naming another anchor. */
export class SessionFileError extends Error {
  readonly code = 'bad-session-file'
}

/**
 * The file of `anchor`; null only when it is absent (ENOENT). A present file that is malformed throws SessionFileError
 * naming the path and the fault: unparsable JSON, v not 1, a name not `s-<16 hex>`, a principal that is not a string,
 * or a pid or start that is not the anchor's (the file name carries both, so a mismatch inside is a bad file).
 */
export function readSessionFile(
  home: string,
  anchor: { readonly pid: number; readonly start: number },
): SessionFile | null {
  const path = sessionFilePath(home, anchor)
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return null
    throw new SessionFileError(`${path}: cannot be read (${String((e as { code?: unknown }).code)})`)
  }
  const bad = (fault: string): SessionFileError => new SessionFileError(`${path}: ${fault}`)
  let v: Record<string, unknown>
  try {
    v = JSON.parse(text) as Record<string, unknown>
  } catch {
    throw bad('not JSON')
  }
  if (v === null || typeof v !== 'object') throw bad('not an object')
  if (v.v !== 1) throw bad('v is not 1')
  if (typeof v.name !== 'string' || !/^s-[0-9a-f]{16}$/.test(v.name)) throw bad('name is not s-<16 hex>')
  if (typeof v.principal !== 'string') throw bad('principal is not a string')
  if (v.pid !== anchor.pid || v.start !== anchor.start) throw bad('pid or start is not the anchor asked for')
  return v as unknown as SessionFile
}
