import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { CliError, flag, list, type Parsed, parse, relayUrl, shq, str, UsageError } from '../args.ts'
import { checkIdentity, homeDir } from '../home.ts'
import {
  addIdentity,
  type Identities,
  type Identity,
  keyOf,
  LABEL,
  readIdentities,
  removeIdentity,
  saveIdentities,
} from '../identities.ts'
import type { Io } from '../io.ts'
import { trustedRoot } from './inbox.ts'
import { CODEX_STOP_TIMEOUT, CODEX_STOP_WAIT } from './wake-hook.ts'

type Json = Record<string, unknown>

/**
 * The Codex table in the common spellings: a header with spaces or quoted keys, a dotted key, `bag = {...}` or
 * `mcp_servers = { bag = ... }` on one line, bag a whole key there (handbag is another server); a comment counts.
 * plugins/codex/install.sh writes the same name: two tables start two servers for one identity.
 */
const TABLE =
  /\[\s*['"]?mcp_servers['"]?\s*\.\s*['"]?bag['"]?\s*[.\]]|^\s*(['"]?mcp_servers['"]?\s*\.\s*)?['"]?bag['"]?\s*[.=]|mcp_servers['"]?\s*=\s*\{(.*[,\s])?['"]?bag['"]?\s*=/m

const MCP_MAIN = fileURLToPath(new URL('../../../mcp/src/main.ts', import.meta.url))
const CLI_MAIN = fileURLToPath(new URL('../main.ts', import.meta.url))

/** The Claude Code hook that runs `wake-hook` with `flags`: asyncRewake, a timeout above wake-hook's 3500 s. */
const wakeHook = (flags: readonly string[]): Json => {
  const command = [process.execPath, CLI_MAIN, 'wake-hook', ...flags].map(shq).join(' ')
  return { type: 'command', command, timeout: 3600, asyncRewake: true }
}

const relayArgs = (e: Identity): string[] => [
  ...e.relays.flatMap((r) => ['--relay', r]),
  ...(e.rendezvous === undefined ? [] : ['--rendezvous', e.rendezvous]),
]
const rootArgs = (e: Identity): string[] => (e.trust_roots ?? []).flatMap((r) => ['--trust-root', r])

/** The single-identity `.mcp.json` entry, the form `--identities` migrates (5.3). */
const single = (e: Identity): Json => ({
  command: process.execPath,
  args: [
    MCP_MAIN,
    '--as',
    keyOf(e),
    ...relayArgs(e),
    ...rootArgs(e),
    '--dir',
    e.home,
    '--keep-alive-records',
  ],
})

/** The identity in `have` when it is exactly the entry a single-identity install writes, else null. */
function singleOf(have: unknown): Identity | null {
  const a = (have as { args?: unknown } | null)?.args
  if (!Array.isArray(a) || !a.every((x) => typeof x === 'string')) return null
  const value = (f: string) => a.filter((_, i) => i > 3 && i % 2 === 0 && a[i - 1] === f)
  const [label, meet, roots] = [a[2] ?? '', value('--rendezvous'), value('--trust-root')]
  const e: Identity = {
    label,
    key: label,
    home: value('--dir')[0] ?? '',
    relays: value('--relay'),
    ...(meet.length === 0 ? {} : { rendezvous: meet[0] }),
    ...(roots.length === 0 ? {} : { trust_roots: roots }),
    keep_alive_records: true,
  }
  return isDeepStrictEqual(have, single(e)) ? e : null
}

/** The object under `key`, made when absent; CliError when it is there and is not an object. */
function child(parent: Json, key: string): Json {
  if (parent[key] === undefined) parent[key] = {}
  const v = parent[key]
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new CliError('host-file-invalid', `"${key}" is not a JSON object`)
  }
  return v as Json
}

/** A change to one JSON file, worked out and not yet written: the document, and what it adds (null: nothing). */
interface Plan {
  readonly file: string
  readonly doc: Json
  readonly added: Json | null
}

/** Appends `{hooks: [hook]}` to `events[event]` unless a group there carries `hook.command`; true when it did. */
function addGroup(events: Json, event: string, hook: Json): boolean {
  const groups = events[event] ?? []
  if (!Array.isArray(groups)) throw new CliError('host-file-invalid', `hooks.${event} is not a list`)
  const has = (g: unknown) => JSON.stringify(g).includes(`"command":${JSON.stringify(hook.command)}`)
  if (groups.some(has)) return false
  events[event] = [...groups, { hooks: [hook] }]
  return true
}

/**
 * Works out the change to the JSON object in `file` (an empty one when absent): `change` edits it in place and
 * returns what it added, or null when everything was there. Nothing is written; a file that is not a JSON object, or
 * a change that refuses, throws here, so every refusal comes before the first write (`write`).
 */
function plan(file: string, change: (doc: Json) => Json | null): Plan {
  let doc: unknown
  try {
    doc = JSON.parse(existsSync(file) ? readFileSync(file, 'utf8') : '{}')
  } catch {
    // doc stays undefined: refused below
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new CliError('host-file-invalid', `${file} is not a JSON object`)
  }
  return { file, doc: doc as Json, added: change(doc as Json) }
}

/** Writes the plans that add something (two-space JSON) and pushes `wrote <file>` and the entry, or `unchanged <file>`. */
function write(plans: readonly Plan[], out: string[]): boolean {
  for (const { file, doc, added } of plans) {
    if (added === null) {
      out.push(`unchanged ${file}`)
      continue
    }
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`)
    out.push(`wrote ${file}`, `  ${JSON.stringify(added)}`)
  }
  return plans.some((x) => x.added !== null)
}

/** The hooks change: `hook` in SessionStart and Stop, after the groups that run `drop` are removed (5.3). */
function hookPlan(doc: Json, hook: Json, drop?: string): Json | null {
  const [events, added]: [Json, Json] = [child(doc, 'hooks'), {}]
  for (const event of ['SessionStart', 'Stop']) {
    const groups = events[event]
    if (drop !== undefined && Array.isArray(groups)) {
      const keep = groups.filter((g) => !JSON.stringify(g).includes(`"command":${JSON.stringify(drop)}`))
      if (keep.length < groups.length) [events[event], added.removed] = [keep, drop]
    }
    if (addGroup(events, event, hook)) added[event] = [{ hooks: [hook] }]
  }
  return Object.keys(added).length === 0 ? null : added
}

const RESTART = 'the change takes effect when Claude Code starts the server again'

/** Refuses an identities file that is not absolute, or that is in the project: a project is often committed. */
function outside(file: string, dir: string): void {
  if (!isAbsolute(file))
    throw new UsageError(`--identities takes an absolute path, not ${JSON.stringify(file)}`)
  const inside = relative(dir, file)
  if (inside !== '..' && !inside.startsWith(`..${sep}`) && !isAbsolute(inside)) {
    throw new CliError(
      'identities-in-project',
      `${file} is in the project ${dir}, which is often committed, and the file links every identity it lists: keep it outside`,
    )
  }
}

/**
 * host install claude-code --identities <file>:
 * `me` added to the identities file, `.mcp.json`'s bag = `[<mcp main>, --identities, <file>]` and the hook
 * `wake-hook --identities <file>`. A bag entry of exactly the single-identity form is migrated: its identity
 * goes first in the file, as the default, and the hook groups that ran its command are replaced. The three files are
 * worked out before any is written, so a refusal leaves all three as they were.
 */
function install(io: Io, file: string, dir: string, me: Identity): number {
  outside(file, dir)
  if (!LABEL.test(me.label))
    throw new UsageError(`--label is ${LABEL.source}, not ${JSON.stringify(me.label)}`)
  const was: Identities = existsSync(file) ? readIdentities(file) : { version: 1, identities: [] }
  const entry = { command: process.execPath, args: [MCP_MAIN, '--identities', file] }
  const from: { old?: Identity } = {}
  const mcp = plan(join(dir, '.mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (isDeepStrictEqual(have, entry)) return null
    const old = have === undefined ? null : singleOf(have)
    if (have !== undefined && old === null) {
      throw new CliError('exists', 'mcpServers.bag is there with other settings: edit or remove it first')
    }
    if (old !== null) from.old = old
    servers.bag = entry
    return { bag: entry }
  })
  let doc = was
  if (from.old !== undefined) {
    const { identities } = addIdentity(doc, from.old, true) ?? doc
    doc = { version: 1, default: doc.default ?? from.old.label, identities }
  }
  doc = addIdentity(doc, me) ?? doc
  const drop = from.old && (wakeHook(['--as', keyOf(from.old), '--dir', from.old.home]).command as string)
  const hook = wakeHook(['--identities', file])
  const hooks = plan(join(dir, '.claude', 'settings.json'), (d) => hookPlan(d, hook, drop))
  const added = doc.identities.filter((x) => !was.identities.some((y) => isDeepStrictEqual(x, y)))
  const out: string[] = []
  const changed = !isDeepStrictEqual(doc, was)
  if (changed) {
    saveIdentities(file, doc)
    out.push(`wrote ${file}`, `  ${JSON.stringify(added)}`)
  } else out.push(`unchanged ${file}`)
  const wrote = write([mcp, hooks], out)
  out.push(wrote || changed ? RESTART : 'nothing to change')
  for (const line of out) io.out(line)
  return 0
}

/**
 * host remove claude-code --project <dir> --identities <file> --label <label> (5.2): the identity's entry out of the
 * file, and `default` with it when it named it. No key, home, state, `.mcp.json` or `settings.json` is touched.
 */
function remove(p: Parsed, io: Io, file: string, dir: string): number {
  if (['as', 'dir', 'relay', 'rendezvous', 'trust-root'].some((k) => p.values[k] !== undefined)) {
    throw new UsageError('host remove takes only --project, --identities and --label')
  }
  outside(file, dir)
  const [doc, label] = [readIdentities(file), str(p, 'label') as string]
  const next = removeIdentity(doc, label)
  saveIdentities(file, next)
  io.out(`wrote ${file}`)
  io.out(`  removed ${label}`)
  if (doc.default === label)
    io.out(`default ${label} dropped: ${next.identities[0]?.label} is the default now`)
  io.out(RESTART)
  return 0
}

/**
 * host install <claude-code|codex> --as <name> --relay <url>... [--rendezvous <url>] [--trust-root <address>]...
 * [--dir <home>] [--grant-caveat <caveat>]... (--project <dir> | --user): registers the identity's MCP server with a
 * host and, for Claude Code, the wake hook. --rendezvous is passed to the server, the relay its pairing codes meet at.
 * Only the places packages/mcp/README.md documents are written; any other is a usage error
 * "not documented yet". claude-code --project <dir>: `.mcp.json` (mcpServers.bag = {command, args}) and
 * `.claude/settings.json` (a SessionStart and a Stop hook, `{"type": "command", "command": "<node> <cli>
 * wake-hook --as <name> --dir <home>"}` with asyncRewake and a timeout above wake-hook's 3500 s), merged into what
 * is there without touching another key; a second run changes nothing and says so. codex --user --mode worker (the
 * default: Codex has no idle wake) prints the line that runs `inbox --watch --exec 'codex exec ...'` (the README's runnable form) and writes
 * nothing; --mode mcp writes the `[mcp_servers.bag]` table in ~/.codex/config.toml instead (one receiver
 * per identity: never both; the server is `--session auto:codex --principal <name>` with the required
 * --grant-caveat, once or more, which no other host or mode takes, so each Codex session is named from its session id
 * and asks the agent for its own grant) and merges a Stop hook into ~/.codex/hooks.json (`{"type": "command",
 * "command": "<node> <cli> wake-hook --as <name> --session auto:codex --dir <home> --max 30 --no-idle-wake",
 * "timeout": 60, "statusMessage": ...}`): when a
 * turn ends, Codex waits up to 30 s for mail and continues the turn when one arrives. The
 * hook is no receiver, it reads only the doorbell, so it runs beside the MCP server. Both Codex files are worked out
 * before either is written, so a refusal leaves neither changed. No key is read and no secret printed: the entries hold the node path, the checkout's paths, the
 * name, the home, relay URLs and trust roots (addresses, public). claude-code --identities <file> [--label <label>]
 * adds the identity to an identities file instead (`install`), and host remove claude-code takes one out (`remove`).
 */
export function hostInstall(args: readonly string[], io: Io): number {
  const options = {
    as: { type: 'string' },
    dir: { type: 'string' },
    relay: { type: 'string', multiple: true },
    rendezvous: { type: 'string' },
    'trust-root': { type: 'string', multiple: true },
    project: { type: 'string' },
    user: { type: 'boolean' },
    mode: { type: 'string' },
    'grant-caveat': { type: 'string', multiple: true },
    identities: { type: 'string' },
    label: { type: 'string' },
  } as const
  const p = parse(args, { positionals: ['verb', 'host'], options })
  const [verb, host] = p.positionals
  if (verb !== 'install' && verb !== 'remove') {
    throw new UsageError(`host takes install or remove, not ${JSON.stringify(verb)}`)
  }
  if (host !== 'claude-code' && host !== 'codex') {
    throw new UsageError(`no host ${JSON.stringify(host)}: the hosts are claude-code and codex`)
  }
  if (verb === 'install' && str(p, 'as') === undefined) throw new UsageError('--as is required')
  const file = str(p, 'identities')
  if (file !== undefined && host === 'codex')
    throw new UsageError('--identities with codex is not documented yet')
  if (verb === 'remove' && (file === undefined || str(p, 'label') === undefined)) {
    throw new UsageError('host remove takes claude-code --project <dir> --identities <file> --label <label>')
  }
  if (file === undefined && str(p, 'label') !== undefined)
    throw new UsageError('--label is for --identities only')
  const [project, user, mode] = [str(p, 'project'), flag(p, 'user'), str(p, 'mode') ?? 'worker']
  if (str(p, 'mode') !== undefined && host === 'claude-code') throw new UsageError('--mode is for codex only')
  if (mode !== 'mcp' && mode !== 'worker')
    throw new UsageError(`--mode is mcp or worker, not ${JSON.stringify(mode)}`)
  const caveats = list(p, 'grant-caveat')
  if (caveats.length > 0 && !(host === 'codex' && mode === 'mcp')) {
    throw new UsageError('--grant-caveat is for codex --mode mcp only')
  }
  if (host === 'codex' && mode === 'mcp' && caveats.length === 0) {
    throw new UsageError(
      'codex --mode mcp needs --grant-caveat <caveat>: the session asks the agent for a grant',
    )
  }
  if ((project === undefined) === !user) throw new UsageError('give one of --project <dir> or --user')
  if (host === 'claude-code' && user) {
    throw new UsageError(
      'claude-code --user is not documented yet: use --project <dir> (.mcp.json, .claude/settings.json)',
    )
  }
  if (host === 'codex' && !user) {
    throw new UsageError('codex --project is not documented yet: use --user (~/.codex/config.toml)')
  }
  if (verb === 'remove') return remove(p, io, file as string, resolve(project as string))
  const name = str(p, 'as') as string
  const home = resolve(homeDir(io, str(p, 'dir')))
  checkIdentity(io, home, name)
  const relays = list(p, 'relay').map(relayUrl)
  if (relays.length === 0) throw new UsageError('--relay <url> is required, at least once')
  const roots = list(p, 'trust-root')
  for (const r of roots) trustedRoot(r)
  const meet = str(p, 'rendezvous')
  const me: Identity = {
    label: str(p, 'label') ?? name,
    key: name,
    home,
    relays,
    ...(meet === undefined ? {} : { rendezvous: relayUrl(meet) }),
    ...(roots.length === 0 ? {} : { trust_roots: roots }),
    keep_alive_records: true,
  }
  const out: string[] = []
  if (host === 'claude-code') {
    const dir = resolve(project as string)
    if (!existsSync(dir)) throw new CliError('ENOENT', `no project directory ${dir}`)
    if (file !== undefined) return install(io, file, dir, me)
    const entry = single(me)
    const hook = wakeHook(['--as', name, '--dir', home])
    const mcp = plan(join(dir, '.mcp.json'), (doc) => {
      const servers = child(doc, 'mcpServers')
      const have = servers.bag
      if (have !== undefined && !isDeepStrictEqual(have, entry)) {
        throw new CliError('exists', 'mcpServers.bag is there with other settings: edit or remove it first')
      }
      if (have !== undefined) return null
      servers.bag = entry
      return { bag: entry }
    })
    const hooks = plan(join(dir, '.claude', 'settings.json'), (doc) => hookPlan(doc, hook))
    if (!write([mcp, hooks], out)) out.push('nothing to change')
  } else if (mode === 'mcp') {
    if (!io.env.HOME) throw new UsageError('no HOME: codex --user writes $HOME/.codex/config.toml')
    const file = join(io.env.HOME, '.codex', 'config.toml')
    // One server per Codex session: --session auto:codex names each session from Codex's session id at its first
    // tool call, and the server refuses --as and --keep-alive-records beside --session (packages/mcp/src/config.ts).
    const session = [MCP_MAIN, '--session', 'auto:codex', '--principal', name]
    const grants = caveats.flatMap((c) => ['--grant-caveat', c])
    const argv = [...session, ...grants, ...relayArgs(me), ...rootArgs(me), '--dir', home]
    const toml = `[mcp_servers.bag]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify(argv)}\n`
    const old = existsSync(file) ? readFileSync(file, 'utf8') : ''
    const [there, wait] = [old.includes(toml), String(CODEX_STOP_WAIT)]
    // Both changes are worked out before either file is written: the TOML `exists` and a hooks.json that cannot take
    // the entry refuse here, so a refusal leaves neither changed.
    const hit = there ? null : TABLE.exec(old)
    if (hit) {
      throw new CliError(
        'exists',
        `${file} has [mcp_servers.bag] with other settings: edit or remove it first`,
      )
    }
    // The Stop hook: it waits up to CODEX_STOP_WAIT s for the doorbell and exits 2 with a
    // line, which Codex takes as the continuation prompt of the turn. It reads no mail, so it may run beside the MCP
    // server, the one receiver.
    const flags = ['--as', name, '--session', 'auto:codex', '--dir', home, '--max', wait, '--no-idle-wake']
    const command = [process.execPath, CLI_MAIN, 'wake-hook', ...flags].map(shq).join(' ')
    const hook = {
      type: 'command',
      command,
      timeout: CODEX_STOP_TIMEOUT,
      statusMessage: 'bag: waiting for mail',
    }
    const hooks = plan(join(io.env.HOME, '.codex', 'hooks.json'), (doc) =>
      addGroup(child(doc, 'hooks'), 'Stop', hook) ? { Stop: [{ hooks: [hook] }] } : null,
    )
    if (there) out.push(`unchanged ${file}`)
    else {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, old === '' ? toml : `${old.trimEnd()}\n\n${toml}`, { mode: 0o600 })
      out.push(
        `wrote ${file}`,
        ...toml
          .trimEnd()
          .split('\n')
          .map((l) => `  ${l}`),
      )
    }
    if (!write([hooks], out) && there) out.push('nothing to change')
    out.push(
      `mcp mode: one Codex session per server, named from Codex's session id at its first tool call; type y at the agent (ac login) for each session's grant. When a turn ends, a Stop hook waits up to ${wait} s for mail and continues the turn when one arrives; an idle session is not woken. Trust the hook in Codex with /hooks before it runs`,
    )
  } else {
    const watch = ['inbox', '--watch', '--as', name, ...relays.flatMap((r) => ['--relay', r]), '--dir', home]
    const rooted = roots.flatMap((r) => ['--trust-root', r])
    const line = [process.execPath, CLI_MAIN, ...watch, ...rooted].map(shq).join(' ')
    out.push(
      `the worker path (no MCP table written: one receiver per identity): ${line} --exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'`,
    )
  }
  for (const line of out) io.out(line)
  return 0
}
