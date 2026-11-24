import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs'
import { basename, dirname, extname, isAbsolute, join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { applyChange, View } from './changes.ts'
import {
  addGroup,
  bagLink,
  CODEX_STOP_TIMEOUT,
  CODEX_STOP_WAIT,
  child,
  type Host,
  type HostProcess,
  type Json,
  shq,
  TABLE,
  WAKE_MAX,
  WAKE_TIMEOUT,
} from './host-common.ts'
import { HomeError } from './ports.ts'
import { CARD_DIR, dropDir, type Staged, stageCard } from './stage.ts'

// host install <host> --user with no --as: the user-scope wiring of the bag service (docs/bag-service.md), one shim
// entry per host that serves every identity of the home, and its hooks; the per-folder stdio mode (--project) stays as
// the rollback. Every change is worked out first (Change), so host migrate backs each path up and journals it before
// the first write. What each host supports at user scope, verified 2026-11-12:
// Claude Code 2.1.322 `claude mcp add --scope user` writes top-level mcpServers of ~/.claude.json, and user hooks live in
// ~/.claude/settings.json (with CLAUDE_CONFIG_DIR, <dir>/.claude.json and <dir>/settings.json: claudeFiles); omp 18.18 reads <agentDir>/mcp.json (default ~/.omp/agent, PI_CODING_AGENT_DIR) at user
// level; Codex has one user table, [mcp_servers.bag] of ~/.codex/config.toml, and ~/.codex/hooks.json. The files are
// found from the caller's environment (HOME, CLAUDE_CONFIG_DIR, PI_CODING_AGENT_DIR), and the node written is the
// caller's (HostProcess).

type Env = Readonly<Record<string, string | undefined>>

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
export const serviceWake = (node: string, m: Staged, home: string, flags: readonly string[]): string =>
  [node, m.cli, 'wake-hook', '--session', 'service', '--dir', home, ...flags].map(shq).join(' ')

/** The typed-word hook (packages/shim: `bag-shim hook [--dir <home>]`). */
export const typedHook = (node: string, m: Staged, home: string): string =>
  [node, m.shim, 'hook', '--dir', home].map(shq).join(' ')

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
    throw new HomeError(
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
  if (!Array.isArray(have)) throw new HomeError('host-file-invalid', `"${key}" is not a list`)
  const more = items.filter((x) => !have.includes(x))
  parent[key] = [...have, ...more]
  return more.length > 0
}

/** The question card's plugin id: the plugin "bag" of the marketplace "bag" (stage.ts's <home>/package/claude-code). */
export const CARD_ID = 'bag@bag'

/**
 * The card's two settings entries (extraKnownMarketplaces.bag, a directory marketplace, and enabledPlugins["bag@bag"]),
 * as `claude plugin marketplace add <dir>` and `claude plugin install bag@bag` write them (2.1.331). Refuses another
 * plugin named bag enabled (the repository's development plugin is one: two would draw two "bag" plugins) and another
 * marketplace named bag, before anything is written.
 */
function putCard(d: Json, dir: string, file: string): boolean {
  const on = (d.enabledPlugins ?? {}) as Json
  const other = Object.keys(on).filter((k) => k.startsWith('bag@') && k !== CARD_ID && on[k] !== false)
  if (other.length > 0) {
    throw new HomeError(
      'exists',
      `${file} enables ${other.join(', ')}, another plugin named bag: disable it in Claude Code (/plugin) or set it to false there, then run this again`,
    )
  }
  // Switched off by the person (/plugin or the file): their choice; bag leaves it, and installUser says so.
  if (on[CARD_ID] === false) return false
  const market: Json = { source: { source: 'directory', path: dir } }
  const have = (d.extraKnownMarketplaces as Json | undefined)?.bag
  if (have !== undefined && !isDeepStrictEqual(have, market)) {
    throw new HomeError(
      'exists',
      `${file} has extraKnownMarketplaces.bag, another marketplace named bag: run host remove claude-code --user with its --dir, or remove it, then run this again`,
    )
  }
  if (have !== undefined && on[CARD_ID] === true) return false
  child(d, 'extraKnownMarketplaces').bag = market
  child(d, 'enabledPlugins')[CARD_ID] = true
  return true
}

/** The card's two entries out of `d` when the marketplace is <home>'s, and any object they leave empty. */
function dropCard(d: Json, dir: string): boolean {
  const markets = d.extraKnownMarketplaces as Json | undefined
  if ((markets?.bag as { source?: { path?: unknown } } | undefined)?.source?.path !== dir) return false
  for (const [key, id] of [
    ['extraKnownMarketplaces', 'bag'],
    ['enabledPlugins', CARD_ID],
  ] as const) {
    const o = d[key] as Json | undefined
    if (o === undefined) continue
    delete o[id]
    if (Object.keys(o).length === 0) delete d[key]
  }
  return true
}

/** Whether a hook group's matcher (absent, '', '*' or a pattern) matches `name`, as Claude Code matches tool names. */
function matches(g: unknown, name: string): boolean {
  const m = (g as { matcher?: unknown } | null)?.matcher
  if (m === undefined || m === '' || m === '*') return true
  try {
    return typeof m === 'string' && new RegExp(`^(?:${m})$`).test(name)
  } catch {
    return true
  }
}

/** The hook events of `hooks` (a settings or hooks.json "hooks" object) that can answer a card in the person's place. */
function answering(hooks: unknown): string[] {
  const h = (hooks ?? {}) as Json
  const on = (e: string, name: string) =>
    Array.isArray(h[e]) && (h[e] as unknown[]).some((g) => matches(g, name))
  return [
    ...['PreToolUse', 'PermissionRequest'].filter((e) => on(e, 'AskUserQuestion')),
    ...(on('Elicitation', 'bag') ? ['Elicitation'] : []),
  ]
}

const readJson = (file: string): Json | null => {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Json
  } catch {
    return null
  }
}

/** Where Claude Code reads managed settings files on macOS (its docs: managed-settings.json and managed-settings.d/). */
export const MANAGED_DIR = '/Library/Application Support/ClaudeCode'

/** The managed settings files there: managed-settings.json, then managed-settings.d/*.json, those present. */
function managedFiles(dir: string): string[] {
  let drop: string[] = []
  try {
    drop = readdirSync(join(dir, 'managed-settings.d'))
      .filter((f) => f.endsWith('.json'))
      .sort()
  } catch {
    // no drop-in folder
  }
  return [join(dir, 'managed-settings.json'), ...drop.map((f) => join(dir, 'managed-settings.d', f))].filter(
    (f) => existsSync(f),
  )
}

/**
 * S1, read only: what else on this machine could answer one of bag's question cards in the person's place: the
 * settings hooks on PreToolUse or PermissionRequest (matching AskUserQuestion) and on Elicitation (matching bag), in
 * the managed settings files (first in the chain; one that cannot be read is named "not readable"), the user's and,
 * given `cwd`, its project's, and the installed plugins with a hooks module or such hooks. Names and files only, never
 * a hook's command or any other content. Not read: an MDM profile (com.anthropic.claudecode) and server-managed
 * settings. Nothing from the user's files when no Claude Code config is found.
 */
export function cardAnswerers(env: Env, cwd?: string, managed = MANAGED_DIR): string[] {
  const hooksIn = (f: string) => answering(readJson(f)?.hooks).map((e) => `a hook on ${e} in ${f}`)
  const lines = managedFiles(managed).flatMap((f) =>
    readJson(f) === null ? [`${f}: not readable`] : hooksIn(f),
  )
  let user: string
  try {
    user = claudeFiles(env).settings
  } catch {
    return lines
  }
  const project = cwd ? ['settings.json', 'settings.local.json'].map((f) => join(cwd, '.claude', f)) : []
  lines.push(...[user, ...project].flatMap(hooksIn))
  const root = env.CLAUDE_CODE_PLUGIN_CACHE_DIR ?? join(dirname(user), 'plugins')
  const installed = (readJson(join(root, 'installed_plugins.json'))?.plugins ?? {}) as Json
  for (const [id, list] of Object.entries(installed)) {
    if (id === CARD_ID || !Array.isArray(list)) continue
    for (const at of list.map((x) => (x as { installPath?: unknown }).installPath)) {
      const h = typeof at === 'string' ? readJson(join(at, 'hooks', 'hooks.json')) : null
      if (h === null) continue
      const kinds = [...(Array.isArray(h.modules) && h.modules.length > 0 ? ['a hooks module'] : [])]
      kinds.push(...answering(h.hooks).map((e) => `a hook on ${e}`))
      if (kinds.length > 0) lines.push(`the plugin ${id} (${at}): ${kinds.join(', ')}`)
    }
  }
  return lines
}

/** The user's HOME, which every user-scope file is under. */
function userHome(env: Env): string {
  if (!env.HOME) throw new HomeError('usage', 'no HOME: --user writes under $HOME')
  return env.HOME
}

/**
 * Claude Code's user files: with CLAUDE_CONFIG_DIR set, <dir>/.claude.json and <dir>/settings.json (the config dir
 * takes the place of ~/.claude, and `claude mcp add --scope user` writes <dir>/.claude.json: verified with 2.1.322);
 * else ~/.claude.json and ~/.claude/settings.json. A relative CLAUDE_CONFIG_DIR is refused: which folder it names
 * depends on where Claude Code starts, so no install can know.
 */
export function claudeFiles(env: Env): { file: string; settings: string } {
  const dir = env.CLAUDE_CONFIG_DIR
  if (dir) {
    if (!isAbsolute(dir)) {
      throw new HomeError(
        'usage',
        `CLAUDE_CONFIG_DIR is ${JSON.stringify(dir)}, a relative path: set it to the absolute folder your Claude Code reads, then run this again`,
      )
    }
    return { file: join(dir, '.claude.json'), settings: join(dir, 'settings.json') }
  }
  const HOME = userHome(env)
  return { file: join(HOME, '.claude.json'), settings: join(HOME, '.claude', 'settings.json') }
}

/** omp's agent directory: PI_CODING_AGENT_DIR, else ~/.omp/agent (omp 18.18's hook documentation). */
export const ompAgentDir = (env: Env): string =>
  env.PI_CODING_AGENT_DIR ?? join(userHome(env), '.omp', 'agent')

/**
 * The user-scope changes for `host`, nothing written. Claude Code: the shim entry in ~/.claude.json, the shim's
 * SessionStart and Stop hooks (asyncRewake; the shim's hook answers at once for an unbound session, so no session
 * holds a day-long wait for nothing) and its UserPromptSubmit hook (the typed word) in ~/.claude/settings.json, and the
 * sandbox rule (docs/bag-service.md): permissions.deny Read and Edit of <home>/run, and sandbox.filesystem denyRead and
 * denyWrite of it, merged into what is there; sandbox.enabled only with `sandbox` (the person's word: it confines
 * every Bash command of every session). Codex: the shim table in ~/.codex/config.toml and its Stop hook. omp: the shim
 * entry in <agentDir>/mcp.json. `node` is the node the entries and hooks run.
 */
export function userChanges(
  view: View,
  env: Env,
  node: string,
  m: Staged,
  home: string,
  host: Host,
  sandbox = false,
): void {
  const HOME = userHome(env)
  const entry: Json = { type: 'stdio', command: node, args: shimArgs(m, home, host) }
  const run = join(home, 'run')
  const pkg = join(home, 'package')
  if (host === 'claude-code') {
    const { file, settings } = claudeFiles(env)
    view.json(file, `${file}: mcpServers.bag, the bag service's shim`, (d) => putEntry(d, entry, file, home))
    const wake = (): Json => ({
      type: 'command',
      command: serviceWake(node, m, home, ['--max', String(WAKE_MAX)]),
      timeout: WAKE_TIMEOUT,
      asyncRewake: true,
    })
    const typed: Json = { type: 'command', command: typedHook(node, m, home), timeout: 10 }
    const card = m.card === undefined ? '' : `; the question card's plugin ${CARD_ID} from ${m.card}`
    const note = `${settings}: the shim's SessionStart, Stop and UserPromptSubmit hooks; deny rules for ${run}${sandbox ? '; sandbox.enabled true' : ''}${card}`
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
      const carded = m.card !== undefined && putCard(d, m.card, settings)
      return hooks || denied || boxed || enabled || carded
    })
  } else if (host === 'omp') {
    const file = join(ompAgentDir(env), 'mcp.json')
    // omp's per-server MCP timeout (ms; omp's default is 30 s): a consent question over the extension's link may stand
    // 120 s inside its tool call, plus a 10 s margin. Never 0: a hung call must still end.
    const omp = { ...entry, timeout: 130000 }
    view.json(file, `${file}: mcpServers.bag, the bag service's shim`, (d) => putEntry(d, omp, file, home))
    // The wake extension at user level, <agentDir>/hooks/pre/bag-wake.js, a link to the launcher
    // <home>/package/bag-omp-wake.js (from source, omp-wake.ts): it finds the home from the shim entry's --dir.
    const dir = join(ompAgentDir(env), 'hooks', 'pre')
    const link = join(dir, `bag-wake${extname(m.omp)}`)
    const foreign = userLinks(dir).filter((l) => !bagLink(l))
    if (foreign.length > 0) {
      throw new HomeError(
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
    const toml = `[mcp_servers.bag]\ncommand = ${JSON.stringify(node)}\nargs = ${JSON.stringify(shimArgs(m, home, host))}\n`
    const was = view.text(file) ?? ''
    if (!was.includes(toml)) {
      const old = tableOf(was)
      const shim =
        old !== null && /bag-shim\.js|shim\/src\/main\.ts/.test(old) && old.includes(JSON.stringify(home))
      if (old !== null && !shim) {
        throw new HomeError(
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
      command: serviceWake(node, m, home, ['--max', String(CODEX_STOP_WAIT), '--no-idle-wake']),
      timeout: CODEX_STOP_TIMEOUT,
      statusMessage: 'bag: waiting for mail',
    }
    // SessionEnd (a window closed or quit, or /new): the ended session's binding is released (wake-hook --end).
    // Codex 0.167 clamps a SessionEnd hook's timeout to 3 s, as a run showed; the hook takes milliseconds.
    const ended: Json = { type: 'command', command: serviceWake(node, m, home, ['--end']), timeout: 3 }
    view.json(hooks, `${hooks}: the shim's Stop and SessionEnd hooks`, (d) =>
      putHooks(child(d, 'hooks'), { Stop: stop, SessionEnd: ended }),
    )
  }
}

/** The [mcp_servers.bag] table of a Codex config as written by host install (header to the next header), else null. */
export function tableOf(text: string): string | null {
  const m = /^\[mcp_servers\.bag\]\n(?:(?!\[).*\n?)*/m.exec(text)
  if (m !== null) return m[0]
  return TABLE.test(text) ? '' : null
}

/** The lines after a user-scope install of `host`: the restart, the sandbox's state, the host's limits. */
export function userNotes(env: Env, home: string, host: Host, sandbox: boolean): string[] {
  const run = join(home, 'run')
  if (host === 'claude-code') {
    // Under a config dir, where Claude Code reads settings.json is its layout, not a live check: the person checks once.
    const check = env.CLAUDE_CONFIG_DIR
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
    const roots = codexRoots(env)
    const under = (p: string) => roots.filter((r) => `${p}/`.startsWith(`${r.replace(/\/$/, '')}/`))
    const covered = [...new Set([...under(run), ...under(join(home, 'package'))])]
    return [
      'the bag service is wired for Codex; Codex binds by dialog only (it has no input hook). Trust the Stop and SessionEnd hooks with /hooks in Codex',
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
    `the wake extension (${join(ompAgentDir(env), 'hooks', 'pre')}/bag-wake) starts a turn on a ring in the main interactive omp session, as in a wired folder`,
  ]
}

/** writable_roots of ~/.codex/config.toml, read as plain strings (no TOML parser: the bundle has no dependency). */
function codexRoots(env: Env): string[] {
  try {
    const t = readFileSync(join(userHome(env), '.codex', 'config.toml'), 'utf8')
    const m = /writable_roots\s*=\s*\[([^\]]*)\]/.exec(t)
    return m === null ? [] : [...(m[1] ?? '').matchAll(/"([^"]*)"/g)].map((x) => x[1] as string)
  } catch {
    return []
  }
}

/** Whether the person switched the card off in Claude Code's user settings (enabledPlugins bag@bag false). */
const cardOff = (env: Env): boolean =>
  (readJson(claudeFiles(env).settings)?.enabledPlugins as Json | undefined)?.[CARD_ID] === false

/**
 * Stages the card's folder before the settings name it (host install and host migrate for claude-code), when the
 * package has one, the person has not switched it off and it is not there yet; true when it staged. stage() then
 * refreshes it at each update.
 */
export function stageCardFirst(env: Env, m: Staged, home: string, pid: number): boolean {
  const src = m.versioned === null ? null : join(dirname(m.versioned.cli), CARD_DIR)
  if (m.card === undefined || src === null || cardOff(env) || existsSync(m.card)) return false
  stageCard(src, home, pid)
  return true
}

/** host install <host> --user (no --as): the changes written, one line each, and the notes; `managed`: S1's managed settings folder. */
export function installUser(
  env: Env,
  p: HostProcess,
  m: Staged,
  home: string,
  host: Host,
  sandbox: boolean,
  out: string[],
  managed = MANAGED_DIR,
): void {
  const view = new View()
  userChanges(view, env, p.node, m, home, host, sandbox)
  const off = host === 'claude-code' && cardOff(env)
  const staging = host === 'claude-code' && stageCardFirst(env, m, home, p.pid)
  const changes = view.changes()
  for (const c of changes) {
    applyChange(c, p.pid)
    out.push(`wrote ${c.note}`)
  }
  if (staging) out.push(`wrote ${m.card}: the question card's plugin bag, staged`)
  if (changes.length === 0 && !staging) out.push('nothing to change')
  out.push(...userNotes(env, home, host, sandbox))
  if (host !== 'claude-code') return
  if (off) {
    out.push(
      `bag's question card is switched off in your Claude Code settings (enabledPlugins ${CARD_ID} is false); bag left it off`,
    )
  } else if (m.card !== undefined) {
    out.push(
      `reload each Claude Code window once (a new session, or /reload-plugins): bag's questions then come in Claude Code's own question card, and each starts with "bag: "`,
      `bag's staged folder ${m.card} runs inside Claude Code at every session start, and each bag update replaces it; host remove claude-code --user takes it out`,
    )
  }
  const others = cardAnswerers(env, env.PWD, managed)
  if (others.length > 0) out.push('these could also answer a bag question card in your place:', ...others)
}

/**
 * host remove <host> --user (no --as): the shim entry of this home and bag's service hooks out of the host's user files;
 * every other server and hook stays, and so do the deny rules for <home>/run (they protect nothing else and cost
 * nothing) and the sandbox settings (turning them off could weaken a sandbox the person relies on); the output says
 * so, and that Claude Code's own plugin records are its own. A hooks object the removal empties goes. A bag entry that
 * is not this home's shim is left, named.
 */
export function removeUser(env: Env, pid: number, home: string, host: Host, out: string[]): void {
  const HOME = userHome(env)
  const view = new View()
  // What the removal leaves and why, said after what it did.
  const kept: string[] = []
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
    const { file, settings } = claudeFiles(env)
    entry(file)
    const card = join(home, 'package', CARD_DIR)
    const named = (view.text(settings) ?? '').includes(JSON.stringify(card))
    const note = `${settings}: bag's service hooks removed${named ? `; the question card's plugin ${CARD_ID} removed` : ''}`
    const run = join(home, 'run')
    let denies = false
    let boxed = false
    view.json(settings, note, (d) => {
      const had = d.hooks !== undefined
      const hooks = child(d, 'hooks')
      const unhooked = unhook(hooks)
      // A hooks object bag's removal emptied goes; one the person had, even empty, stays as it was.
      if (!had || (unhooked && Object.keys(hooks).length === 0)) delete d.hooks
      const deny = (d.permissions as Json | undefined)?.deny
      denies = Array.isArray(deny) && deny.includes(`Read(/${run}/**)`)
      const fs = ((d.sandbox as Json | undefined)?.filesystem ?? {}) as Json
      boxed = [fs.denyRead, fs.denyWrite].some((l) => Array.isArray(l) && l.includes(run))
      return dropCard(d, card) || unhooked
    })
    if (denies)
      kept.push(
        `kept the deny rules for ${home} in ${settings}: they protect the bag home whether or not bag is wired`,
      )
    if (boxed)
      kept.push(
        `kept the sandbox settings in ${settings}: turning them off could weaken a sandbox you rely on`,
      )
    if (named || existsSync(card)) {
      const plugins = env.CLAUDE_CODE_PLUGIN_CACHE_DIR ?? join(dirname(settings), 'plugins')
      kept.push(
        `Claude Code keeps its own record of the bag marketplace and the plugin's data in ${plugins}; bag does not write or delete them: remove the marketplace with /plugin in Claude Code`,
      )
    }
  } else if (host === 'omp') {
    entry(join(ompAgentDir(env), 'mcp.json'))
    for (const l of userLinks(join(ompAgentDir(env), 'hooks', 'pre')).filter(bagLink)) {
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
    view.json(hooks, `${hooks}: bag's service hooks removed`, (d) => unhook(child(d, 'hooks')))
  }
  const changes = view.changes()
  for (const c of changes) {
    applyChange(c, pid)
    out.push(`wrote ${c.note}`)
  }
  const card = join(home, 'package', CARD_DIR)
  if (host === 'claude-code' && existsSync(card)) {
    dropDir(card, pid)
    out.push(`removed ${card}, the question card's plugin`)
  } else if (changes.length === 0) out.push('nothing to change')
  out.push(...kept)
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
