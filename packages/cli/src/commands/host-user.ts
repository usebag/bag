import { lstatSync, readFileSync } from 'node:fs'
import { basename, extname, isAbsolute, join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { CliError, shq, UsageError } from '../args.ts'
import { applyChange, View } from '../changes.ts'
import type { Io } from '../io.ts'
import { stableNode } from '../packaged.ts'
import type { Staged } from '../stage.ts'
import { addGroup, bagLink, child, TABLE, WAKE_MAX, WAKE_TIMEOUT } from './host-install.ts'
import { CODEX_STOP_TIMEOUT, CODEX_STOP_WAIT } from './wake-hook.ts'

// host install <host> --user with no --as: the user-scope wiring of the bag service (docs/bag-service.md), one shim
// entry per host that serves every identity of the home, and its hooks; the per-folder stdio mode (--project) stays as
// the rollback. Every change is worked out first (Change), so host migrate backs each path up and journals it before
// the first write. What each host supports at user scope, verified 2026-11-12:
// Claude Code 2.1.322 `claude mcp add --scope user` writes top-level mcpServers of ~/.claude.json, and user hooks live in
// ~/.claude/settings.json (with CLAUDE_CONFIG_DIR, <dir>/.claude.json and <dir>/settings.json: claudeFiles); omp 18.18 reads <agentDir>/mcp.json (default ~/.omp/agent, PI_CODING_AGENT_DIR) at user
// level; Codex has one user table, [mcp_servers.bag] of ~/.codex/config.toml, and ~/.codex/hooks.json.

type Json = Record<string, unknown>
export type Host = 'claude-code' | 'codex' | 'omp'

/**
 * The shim's stdio entry (packages/shim: `bag-shim [--dir <home>] [--input-hook]`): it reads the launch token itself.
 * --input-hook for the hosts with a typed-word hook: Claude Code's UserPromptSubmit,
 * omp's input handler; Codex binds by dialog only.
 */
export const shimArgs = (m: Staged, home: string, host: Host): string[] => [
  m.shim,
  '--dir',
  home,
  ...(host === 'codex' ? [] : ['--input-hook']),
]

/** Whether `have` is a shim entry (any version, any home): its first argument is the shim's entry. */
export function shimOf(have: unknown): { home: string } | null {
  const a = (have as { args?: unknown } | null)?.args
  if (!Array.isArray(a) || typeof a[0] !== 'string') return null
  const isShim = basename(a[0]) === 'bag-shim.js' || a[0].endsWith(join('shim', 'src', 'main.ts'))
  const i = a.indexOf('--dir')
  return isShim && i > 0 && typeof a[i + 1] === 'string' ? { home: a[i + 1] as string } : null
}

/** The wake hook through the shim: wake-hook --session service, the identity this session's shim is bound to. */
export const serviceWake = (m: Staged, home: string, flags: readonly string[]): string =>
  [stableNode(), m.cli, 'wake-hook', '--session', 'service', '--dir', home, ...flags].map(shq).join(' ')

/** The typed-word hook (packages/shim: `bag-shim hook [--dir <home>]`). */
export const typedHook = (m: Staged, home: string): string =>
  [stableNode(), m.shim, 'hook', '--dir', home].map(shq).join(' ')

/** Whether a hook group runs bag's service hook of the same kind as `command` (any version, any home). */
function sameKind(g: unknown, command: string): boolean {
  const s = JSON.stringify(g)
  if (command.includes(' wake-hook '))
    return s.includes(' wake-hook --session service ') || s.includes("'wake-hook' '--session' 'service'")
  return /(bag-shim\.js|shim\/src\/main\.ts)'? '?hook'? /.test(s)
}

/** Puts the shim entry under mcpServers.bag of `doc`, refusing another bag server there (host migrate moves those). */
function putEntry(doc: Json, entry: Json, file: string, home: string): boolean {
  const servers = child(doc, 'mcpServers')
  const have = servers.bag
  if (isDeepStrictEqual(have, entry)) return false
  const shim = have === undefined ? null : shimOf(have)
  if (have !== undefined && (shim === null || shim.home !== home)) {
    throw new CliError(
      'exists',
      `${file} has mcpServers.bag for ${shim === null ? 'one identity (the per-folder form)' : `the home ${shim.home}`}: run host migrate, or edit or remove it first`,
    )
  }
  servers.bag = entry
  return true
}

/** The hooks of `host` in `events`: each event's shim hook in, an earlier version's out; what changed, or null. */
function putHooks(events: Json, hooks: Record<string, Json>): boolean {
  let changed = false
  for (const [event, hook] of Object.entries(hooks)) {
    const groups = events[event]
    if (Array.isArray(groups)) {
      const keep = groups.filter(
        (g) => !sameKind(g, String(hook.command)) || JSON.stringify(g).includes(JSON.stringify(hook.command)),
      )
      if (keep.length < groups.length) {
        events[event] = keep
        changed = true
      }
    }
    changed = addGroup(events, event, hook) || changed
  }
  return changed
}

/** Adds `items` to the array at `key` of `parent` that lacks them; true when it added one. */
function merge(parent: Json, key: string, items: readonly string[]): boolean {
  const have = parent[key] ?? []
  if (!Array.isArray(have)) throw new CliError('host-file-invalid', `"${key}" is not a list`)
  const more = items.filter((x) => !have.includes(x))
  parent[key] = [...have, ...more]
  return more.length > 0
}

/** The user's HOME, which every user-scope file is under. */
function userHome(io: Io): string {
  if (!io.env.HOME) throw new UsageError('no HOME: --user writes under $HOME')
  return io.env.HOME
}

/**
 * Claude Code's user files: with CLAUDE_CONFIG_DIR set, <dir>/.claude.json and <dir>/settings.json (the config dir
 * takes the place of ~/.claude, and `claude mcp add --scope user` writes <dir>/.claude.json: verified with 2.1.322);
 * else ~/.claude.json and ~/.claude/settings.json. A relative CLAUDE_CONFIG_DIR is refused: which folder it names
 * depends on where Claude Code starts, so no install can know.
 */
export function claudeFiles(io: Io): { file: string; settings: string } {
  const dir = io.env.CLAUDE_CONFIG_DIR
  if (dir) {
    if (!isAbsolute(dir)) {
      throw new UsageError(
        `CLAUDE_CONFIG_DIR is ${JSON.stringify(dir)}, a relative path: set it to the absolute folder your Claude Code reads, then run this again`,
      )
    }
    return { file: join(dir, '.claude.json'), settings: join(dir, 'settings.json') }
  }
  const HOME = userHome(io)
  return { file: join(HOME, '.claude.json'), settings: join(HOME, '.claude', 'settings.json') }
}

/** omp's agent directory: PI_CODING_AGENT_DIR, else ~/.omp/agent (omp 18.18's hook documentation). */
export const ompAgentDir = (io: Io): string =>
  io.env.PI_CODING_AGENT_DIR ?? join(userHome(io), '.omp', 'agent')

/**
 * The user-scope changes for `host`, nothing written. Claude Code: the shim entry in ~/.claude.json, the shim's
 * SessionStart and Stop hooks (asyncRewake; the shim's hook answers at once for an unbound session, so no session
 * holds a day-long wait for nothing) and its UserPromptSubmit hook (the typed word) in ~/.claude/settings.json, and the
 * sandbox rule of contract section 5: permissions.deny Read and Edit of <home>/run, and sandbox.filesystem denyRead and
 * denyWrite of it, merged into what is there; sandbox.enabled only with `sandbox` (the person's word: it confines
 * every Bash command of every session). Codex: the shim table in ~/.codex/config.toml and its Stop hook. omp: the shim
 * entry in <agentDir>/mcp.json.
 */
export function userChanges(view: View, io: Io, m: Staged, home: string, host: Host, sandbox = false): void {
  const HOME = userHome(io)
  const entry: Json = { type: 'stdio', command: stableNode(), args: shimArgs(m, home, host) }
  const run = join(home, 'run')
  const pkg = join(home, 'package')
  if (host === 'claude-code') {
    const { file, settings } = claudeFiles(io)
    view.json(file, `${file}: mcpServers.bag, the bag service's shim`, (d) => putEntry(d, entry, file, home))
    const wake = (): Json => ({
      type: 'command',
      command: serviceWake(m, home, ['--max', String(WAKE_MAX)]),
      timeout: WAKE_TIMEOUT,
      asyncRewake: true,
    })
    const typed: Json = { type: 'command', command: typedHook(m, home), timeout: 10 }
    const note = `${settings}: the shim's SessionStart, Stop and UserPromptSubmit hooks; deny rules for ${run}${sandbox ? '; sandbox.enabled true' : ''}`
    view.json(settings, note, (d) => {
      const hooks = putHooks(child(d, 'hooks'), {
        SessionStart: wake(),
        Stop: wake(),
        UserPromptSubmit: typed,
      })
      // <home>/package too, for writing: whoever writes current or versions/ picks the code the next service runs.
      // keys/ (a file-custody identity's raw private key) and state/ (the mail stores and the audit) for reading, by
      // the file tools only: they are NOT in sandbox.filesystem.denyRead, which under sandbox.enabled would also stop
      // bag's own commands that the agent runs in Bash from reading their keys.
      const denied = merge(child(d, 'permissions'), 'deny', [
        `Read(/${run}/**)`,
        `Edit(/${run}/**)`,
        `Read(/${join(home, 'keys')}/**)`,
        `Read(/${join(home, 'state')}/**)`,
        `Edit(/${pkg}/**)`,
        // The service re-reads identities.json at each hello and use and serves whatever entry it holds.
        `Edit(/${join(home, 'identities.json')})`,
      ])
      const box = child(d, 'sandbox')
      const fs = child(box, 'filesystem')
      const boxed = [merge(fs, 'denyRead', [run]), merge(fs, 'denyWrite', [run, pkg])].some(Boolean)
      const enabled = sandbox && box.enabled !== true
      if (enabled) box.enabled = true
      return hooks || denied || boxed || enabled
    })
  } else if (host === 'omp') {
    const file = join(ompAgentDir(io), 'mcp.json')
    view.json(file, `${file}: mcpServers.bag, the bag service's shim`, (d) => putEntry(d, entry, file, home))
    // The wake extension at user level, <agentDir>/hooks/pre/bag-wake.js, a link to the launcher
    // <home>/package/bag-omp-wake.js (from source, omp-wake.ts): it finds the home from the shim entry's --dir (W1).
    const dir = join(ompAgentDir(io), 'hooks', 'pre')
    const link = join(dir, `bag-wake${extname(m.omp)}`)
    const foreign = userLinks(dir).filter((l) => !bagLink(l))
    if (foreign.length > 0) {
      throw new CliError(
        'exists',
        `${foreign.join(', ')} is not bag's wake link: move it away first, then run this again`,
      )
    }
    for (const l of userLinks(dir).filter((x) => x !== link && bagLink(x))) {
      view.set({ path: l, gone: true, note: `${l}: an earlier wake link of bag's removed` })
    }
    view.set({ path: link, link: m.omp, note: `${link} -> ${m.omp}: the wake extension` })
  } else {
    const file = join(HOME, '.codex', 'config.toml')
    const toml = `[mcp_servers.bag]\ncommand = ${JSON.stringify(stableNode())}\nargs = ${JSON.stringify(shimArgs(m, home, host))}\n`
    const was = view.text(file) ?? ''
    if (!was.includes(toml)) {
      const old = tableOf(was)
      const shim =
        old !== null && /bag-shim\.js|shim\/src\/main\.ts/.test(old) && old.includes(JSON.stringify(home))
      if (old !== null && !shim) {
        throw new CliError(
          'exists',
          `${file} has [mcp_servers.bag] of one identity, or of another home: run host migrate, or edit or remove it first`,
        )
      }
      const next =
        old === null ? (was.trim() === '' ? toml : `${was.trimEnd()}\n\n${toml}`) : was.replace(old, toml)
      view.set({
        path: file,
        text: next,
        mode: 0o600,
        note: `${file}: [mcp_servers.bag], the bag service's shim`,
      })
    }
    const hooks = join(HOME, '.codex', 'hooks.json')
    const stop: Json = {
      type: 'command',
      command: serviceWake(m, home, ['--max', String(CODEX_STOP_WAIT), '--no-idle-wake']),
      timeout: CODEX_STOP_TIMEOUT,
      statusMessage: 'bag: waiting for mail',
    }
    view.json(hooks, `${hooks}: the shim's Stop hook`, (d) => putHooks(child(d, 'hooks'), { Stop: stop }))
  }
}

/** The [mcp_servers.bag] table of a Codex config as written by host install (header to the next header), else null. */
export function tableOf(text: string): string | null {
  const m = /^\[mcp_servers\.bag\]\n(?:(?!\[).*\n?)*/m.exec(text)
  if (m !== null) return m[0]
  return TABLE.test(text) ? '' : null
}

/** The lines after a user-scope install of `host`: the restart, the sandbox's state, the host's limits. */
export function userNotes(io: Io, home: string, host: Host, sandbox: boolean): string[] {
  const run = join(home, 'run')
  if (host === 'claude-code') {
    // Under a config dir, where Claude Code reads settings.json is its layout, not a live check: the person checks once.
    const check = io.env.CLAUDE_CONFIG_DIR
      ? [
          `check once in Claude Code: /permissions should list bag's deny rules for ${join(home, 'keys')} and ${run}; if it does not, say so at bag.dev`,
        ]
      : []
    return [
      ...check,
      'the bag service is wired for every Claude Code session of this user; a project .mcp.json with a bag server shadows it (project scope wins): run host migrate',
      sandbox
        ? `sandbox.enabled is true: every Bash command runs in Claude Code's sandbox, which denies ${run}`
        : `sandbox.enabled is unchanged: the deny rules hold ${run} against the file tools and the file commands Claude Code recognises in Bash, not against a script; run again with --sandbox to confine every Bash command`,
    ]
  }
  if (host === 'codex') {
    const roots = codexRoots(io)
    const under = (p: string) => roots.filter((r) => `${p}/`.startsWith(`${r.replace(/\/$/, '')}/`))
    const covered = [...new Set([...under(run), ...under(join(home, 'package'))])]
    return [
      'the bag service is wired for Codex; Codex binds by dialog only (it has no input hook). Trust the Stop hook with /hooks in Codex',
      `Codex has no deny-read entry: the model's tools can read ${run}, so on Codex the launch token protects nothing against the session's own model; keep ${join(home, 'identities.json')}, ${run} and ${join(home, 'package')} out of the model's writable roots`,
      ...(covered.length === 0
        ? []
        : [
            `warning: [sandbox_workspace_write] writable_roots names ${covered.join(', ')}, which lets the model write ${run} or ${join(home, 'package')}: take it out`,
          ]),
    ]
  }
  return [
    'the bag service is wired for every omp session of this user; a project .omp/mcp.json with a bag server shadows it: run host migrate',
    `omp has no sandbox or path-deny setting: the model's shell can read and write ${run}, and write ${join(home, 'identities.json')}, which the service serves from`,
    `the wake extension (${join(ompAgentDir(io), 'hooks', 'pre')}/bag-wake) starts a turn on a ring in the main interactive omp session, as in a wired folder`,
  ]
}

/** writable_roots of ~/.codex/config.toml, read as plain strings (no TOML parser: the bundle has no dependency). */
function codexRoots(io: Io): string[] {
  try {
    const t = readFileSync(join(userHome(io), '.codex', 'config.toml'), 'utf8')
    const m = /writable_roots\s*=\s*\[([^\]]*)\]/.exec(t)
    return m === null ? [] : [...(m[1] ?? '').matchAll(/"([^"]*)"/g)].map((x) => x[1] as string)
  } catch {
    return []
  }
}

/** host install <host> --user (no --as): the changes written, one line each, and the notes. */
export function installUser(
  io: Io,
  m: Staged,
  home: string,
  host: Host,
  sandbox: boolean,
  out: string[],
): void {
  const view = new View()
  userChanges(view, io, m, home, host, sandbox)
  const changes = view.changes()
  for (const c of changes) {
    applyChange(c)
    out.push(`wrote ${c.note}`)
  }
  if (changes.length === 0) out.push('nothing to change')
  out.push(...userNotes(io, home, host, sandbox))
}

/**
 * host remove <host> --user (no --as): the shim entry of this home and bag's service hooks out of the host's user files;
 * every other server and hook stays, and so do the deny rules for <home>/run (they protect nothing else and cost
 * nothing). A bag entry that is not this home's shim is left, named.
 */
export function removeUser(io: Io, home: string, host: Host, out: string[]): void {
  const HOME = userHome(io)
  const view = new View()
  const ours = (have: unknown) => shimOf(have)?.home === home
  const unhook = (events: Json): boolean => {
    let changed = false
    for (const [event, groups] of Object.entries(events)) {
      if (!Array.isArray(groups)) continue
      const kept = groups.filter((g) => !(sameKind(g, ' wake-hook ') || sameKind(g, 'hook')))
      if (kept.length === groups.length) continue
      changed = true
      if (kept.length > 0) events[event] = kept
      else delete events[event]
    }
    return changed
  }
  const entry = (file: string) =>
    view.json(file, `${file}: mcpServers.bag (the shim) removed`, (d) => {
      const servers = d.mcpServers as Json | undefined
      if (servers?.bag === undefined) return false
      if (!ours(servers.bag)) {
        out.push(`left ${file}: its mcpServers.bag is not the shim of ${home}`)
        return false
      }
      delete servers.bag
      return true
    })
  if (host === 'claude-code') {
    const { file, settings } = claudeFiles(io)
    entry(file)
    view.json(settings, `${settings}: bag's service hooks removed`, (d) => unhook(child(d, 'hooks')))
  } else if (host === 'omp') {
    entry(join(ompAgentDir(io), 'mcp.json'))
    for (const l of userLinks(join(ompAgentDir(io), 'hooks', 'pre')).filter(bagLink)) {
      view.set({ path: l, gone: true, note: `${l}: bag's wake link removed` })
    }
  } else {
    const file = join(HOME, '.codex', 'config.toml')
    const was = view.text(file) ?? ''
    const old = tableOf(was)
    if (old && /bag-shim\.js|shim\/src\/main\.ts/.test(old) && old.includes(JSON.stringify(home))) {
      view.set({
        path: file,
        text: was.replace(old, ''),
        mode: 0o600,
        note: `${file}: [mcp_servers.bag] (the shim) removed`,
      })
    } else if (old !== null) out.push(`left ${file}: its [mcp_servers.bag] is not the shim of ${home}`)
    const hooks = join(HOME, '.codex', 'hooks.json')
    view.json(hooks, `${hooks}: bag's service Stop hook removed`, (d) => unhook(child(d, 'hooks')))
  }
  const changes = view.changes()
  for (const c of changes) {
    applyChange(c)
    out.push(`wrote ${c.note}`)
  }
  if (changes.length === 0) out.push('nothing to change')
}

/** The two wake link names in an omp hooks/pre directory that are there (a file or a link, not followed). */
function userLinks(dir: string): string[] {
  return ['.js', '.ts']
    .map((x) => join(dir, `bag-wake${x}`))
    .filter((l) => {
      try {
        lstatSync(l)
        return true
      } catch {
        return false
      }
    })
}
