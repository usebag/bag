import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { parseRecord, recordSigner, serializeRecord, verifyRecord } from '@usebag/core'
import { acceptCopy, addressCopy } from '@usebag/edge'
import { CliError, flag, list, type Parsed, parse, relayUrl, shq, str, UsageError } from '../args.ts'
import { checkIdentity, homeCustody, homeDir } from '../home.ts'
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
import { type Mains, stableMains, versionLine } from '../packaged.ts'
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

/**
 * The wait the Claude Code hooks pass to wake-hook, in s, and their timeout above it: one idle wake a day, and the
 * silent second deadline after about two days, where wake-hook's default of 3500 s gave an hour and two. Claude Code
 * 2.1.316 kept such a hook past 3600 s and woke the idle session at its exit 2 (measured 2026-11-03 at 3700 s).
 */
const WAKE_MAX = 86_000
const WAKE_TIMEOUT = 86_400

/** The wake-hook command with `flags`, shell-quoted; without --max, the form host install wrote before WAKE_MAX. */
const wakeCommand = (m: Mains, flags: readonly string[]): string =>
  [process.execPath, m.cli, 'wake-hook', ...flags].map(shq).join(' ')

/** The Claude Code hook that runs `wake-hook` with `flags` and --max WAKE_MAX: asyncRewake, timeout WAKE_TIMEOUT. */
const wakeHook = (m: Mains, flags: readonly string[]): Json => {
  const command = wakeCommand(m, [...flags, '--max', String(WAKE_MAX)])
  return { type: 'command', command, timeout: WAKE_TIMEOUT, asyncRewake: true }
}

const relayArgs = (e: Identity): string[] => [
  ...e.relays.flatMap((r) => ['--relay', r]),
  ...(e.rendezvous === undefined ? [] : ['--rendezvous', e.rendezvous]),
]
const rootArgs = (e: Identity): string[] => (e.trust_roots ?? []).flatMap((r) => ['--trust-root', r])

/** The single-identity `.mcp.json` entry, the form `--identities` migrates (5.3). */
const single = (m: Mains, e: Identity): Json => ({
  command: process.execPath,
  args: [m.mcp, '--as', keyOf(e), ...relayArgs(e), ...rootArgs(e), '--dir', e.home, '--keep-alive-records'],
})

/** The identity in `have` when it is exactly the entry a single-identity install writes, else null. */
function singleOf(m: Mains, have: unknown): Identity | null {
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
  return isDeepStrictEqual(have, single(m, e)) ? e : null
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

/**
 * The hooks change: `hook` in SessionStart and Stop, after the groups that run a command of `drop` are removed (5.3,
 * and an earlier install's hook); `removed` names the commands removed, one as a string.
 */
function hookPlan(doc: Json, hook: Json, drop: readonly string[]): Json | null {
  const [events, added, removed]: [Json, Json, Set<string>] = [child(doc, 'hooks'), {}, new Set()]
  const runs = (g: unknown) => drop.find((c) => JSON.stringify(g).includes(`"command":${JSON.stringify(c)}`))
  for (const event of ['SessionStart', 'Stop']) {
    const groups = events[event]
    if (Array.isArray(groups)) {
      const keep = groups.filter((g) => {
        const c = runs(g)
        if (c !== undefined) removed.add(c)
        return c === undefined
      })
      if (keep.length < groups.length) {
        events[event] = keep
        added.removed = removed.size === 1 ? [...removed][0] : [...removed]
      }
    }
    if (addGroup(events, event, hook)) added[event] = [{ hooks: [hook] }]
  }
  return Object.keys(added).length === 0 ? null : added
}

/** The omp `.omp/mcp.json` entry: the single-identity server line, as the live omp agents ran it (with --push log). */
const ompEntry = (m: Mains, e: Identity): Json => ({
  type: 'stdio',
  command: process.execPath,
  args: [...((single(m, e).args as string[]) ?? []), '--push', 'log'],
})

/** The omp wake link in a project: discovered by omp from .omp/hooks/pre/, named with the entry's own extension. */
const ompLink = (dir: string, m: Mains): string =>
  join(dir, '.omp', 'hooks', 'pre', `bag-wake${extname(m.omp)}`)

/** The two names the omp wake link may have (from source .ts, from the package .js). */
const ompLinks = (dir: string): string[] =>
  ['.js', '.ts'].map((x) => join(dir, '.omp', 'hooks', 'pre', `bag-wake${x}`))

/** Whether `link` is a symbolic link to an omp wake entry of bag (any home, any version). */
function bagLink(link: string): boolean {
  try {
    if (!lstatSync(link).isSymbolicLink()) return false
    return ['bag-omp-wake.js', 'omp-wake.ts'].includes(basename(readlinkSync(link)))
  } catch {
    return false
  }
}

/**
 * omp --project <dir>: `.omp/mcp.json` (mcpServers.bag, the single-identity line with type stdio and --push log) and
 * the wake link, `.omp/hooks/pre/bag-wake.js` a symbolic link to <home>/package/bag-omp-wake.js (from source,
 * bag-wake.ts to packages/cli/src/omp-wake.ts): one maintained file, never a copy in the project. A bag entry with
 * other settings, or a file at the link that is not bag's link, is refused before anything is written; a link of
 * bag's to another place (an older home) is replaced. A second run changes nothing and says so.
 */
function installOmp(m: Mains, dir: string, me: Identity, out: string[]): void {
  const entry = ompEntry(m, me)
  const mcp = plan(join(dir, '.omp', 'mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (have !== undefined && !isDeepStrictEqual(have, entry)) {
      throw new CliError(
        'exists',
        `${join(dir, '.omp', 'mcp.json')} has mcpServers.bag with other settings: edit or remove it first`,
      )
    }
    if (have !== undefined) return null
    servers.bag = entry
    return { bag: entry }
  })
  const link = ompLink(dir, m)
  const foreign = ompLinks(dir).filter((l) => {
    try {
      lstatSync(l)
    } catch {
      return false
    }
    return !bagLink(l)
  })
  if (foreign.length > 0) {
    throw new CliError(
      'exists',
      `${foreign.join(', ')} is not bag's wake link (a hand-written wake?): move it away first, then run this again`,
    )
  }
  const same = bagLink(link) && readlinkSync(link) === m.omp
  const stale = ompLinks(dir).filter((l) => bagLink(l) && !(l === link && same))
  write([mcp], out)
  for (const l of stale) {
    rmSync(l)
    out.push(`removed ${l} (an earlier link of bag's)`)
  }
  if (same) out.push(`unchanged ${link}`)
  else {
    mkdirSync(dirname(link), { recursive: true })
    const tmp = `${link}.${process.pid}.tmp`
    rmSync(tmp, { force: true })
    symlinkSync(m.omp, tmp)
    renameSync(tmp, link)
    out.push(`wrote ${link} -> ${m.omp}`)
  }
  for (const f of ['.mcp.json', 'mcp.json'].map((n) => join(dir, '.claude', n))) {
    try {
      const doc = JSON.parse(readFileSync(f, 'utf8')) as { mcpServers?: Json }
      if (doc.mcpServers?.bag !== undefined) {
        out.push(
          `warning: ${f} also names a bag server, which omp loads too: two servers for one folder; remove one`,
        )
      }
    } catch {
      // absent or not JSON: omp reads nothing there
    }
  }
  if (mcp.added === null && same && stale.length === 0) out.push('nothing to change')
  out.push(
    'the wake starts with the next omp session in this folder: one turn per ring of the doorbell, queued while a turn runs; only the main interactive session wakes (not omp -p, --mode rpc or a subagent), and every spawned session needs its own --model',
  )
}

/** host remove omp --project <dir> --as <name>: takes out the bag entry of that identity and bag's wake link. */
function removeOmp(dir: string, name: string, out: string[]): void {
  const file = join(dir, '.omp', 'mcp.json')
  const mcp = plan(file, (doc) => {
    const servers = child(doc, 'mcpServers')
    const args = (servers.bag as { args?: unknown } | undefined)?.args
    if (servers.bag === undefined) return null
    if (!Array.isArray(args) || args[args.indexOf('--as') + 1] !== name || !args.includes('--as')) {
      throw new CliError(
        'not-found',
        `${file} has a bag server for another identity than ${name}: not removed`,
      )
    }
    const removed = servers.bag as Json
    delete servers.bag
    return { removed }
  })
  if (mcp.added !== null) {
    writeFileSync(file, `${JSON.stringify(mcp.doc, null, 2)}\n`)
    out.push(`wrote ${file} (mcpServers.bag removed)`)
  } else out.push(`unchanged ${file}`)
  for (const l of ompLinks(dir).filter(bagLink)) {
    rmSync(l)
    out.push(`removed ${l}`)
  }
}

/** The line for a package copied to a stable place (packaged.ts), first in the output; none from source. */
const copiedLines = (m: Mains): string[] =>
  m.copied === null ? [] : [`wrote ${m.copied} (${versionLine()})`]

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
function install(io: Io, m: Mains, file: string, dir: string, me: Identity): number {
  outside(file, dir)
  if (!LABEL.test(me.label))
    throw new UsageError(`--label is ${LABEL.source}, not ${JSON.stringify(me.label)}`)
  const was: Identities = existsSync(file) ? readIdentities(file) : { version: 1, identities: [] }
  const entry = { command: process.execPath, args: [m.mcp, '--identities', file] }
  const from: { old?: Identity } = {}
  const mcp = plan(join(dir, '.mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (isDeepStrictEqual(have, entry)) return null
    const old = have === undefined ? null : singleOf(m, have)
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
  // The single-identity hook it migrates, as written now or before WAKE_MAX, and this file's hook as written before.
  const old = from.old && ['--as', keyOf(from.old), '--dir', from.old.home]
  const migrated = old ? [wakeHook(m, old).command as string, wakeCommand(m, old)] : []
  const drop = [wakeCommand(m, ['--identities', file]), ...migrated]
  const hook = wakeHook(m, ['--identities', file])
  const hooks = plan(join(dir, '.claude', 'settings.json'), (d) => hookPlan(d, hook, drop))
  const added = doc.identities.filter((x) => !was.identities.some((y) => isDeepStrictEqual(x, y)))
  const out: string[] = copiedLines(m)
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
 * host install <claude-code|codex|omp> --as <name> --relay <url>... [--rendezvous <url>] [--trust-root <address>]...
 * [--dir <home>] [--grant-caveat <caveat>]... (--project <dir> | --user): registers the identity's MCP server with a
 * host and, for Claude Code, the wake hook. --rendezvous is passed to the server, the relay its pairing codes meet at.
 * Only the places packages/mcp/README.md documents are written; any other is a usage error
 * "not documented yet". claude-code --project <dir>: `.mcp.json` (mcpServers.bag = {command, args}) and
 * `.claude/settings.json` (a SessionStart and a Stop hook, `{"type": "command", "command": "<node> <cli>
 * wake-hook --as <name> --dir <home> --max 86000"}` with asyncRewake and timeout 86400: WAKE_MAX, WAKE_TIMEOUT), merged
 * into what is there without touching another key, an earlier install's hook of that identity replaced; a second run
 * changes nothing and says so. codex --user --mode worker (the
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
export function hostInstall(args: readonly string[], io: Io): number | Promise<number> {
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
  if (host !== 'claude-code' && host !== 'codex' && host !== 'omp') {
    throw new UsageError(`no host ${JSON.stringify(host)}: the hosts are claude-code, codex and omp`)
  }
  if (host === 'omp') return hostOmp(p, io, verb)
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
  const dir = host === 'claude-code' ? resolve(project as string) : ''
  if (host === 'claude-code' && !existsSync(dir)) throw new CliError('ENOENT', `no project directory ${dir}`)
  const m = stableMains(file === undefined ? home : dirname(file))
  const out: string[] = copiedLines(m)
  if (host === 'claude-code') {
    if (file !== undefined) return install(io, m, file, dir, me)
    const entry = single(m, me)
    const flags = ['--as', name, '--dir', home]
    const hook = wakeHook(m, flags)
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
    // An earlier install's hook for the same identity (no --max, timeout 3600) is replaced.
    const earlier = [wakeCommand(m, flags)]
    const hooks = plan(join(dir, '.claude', 'settings.json'), (doc) => hookPlan(doc, hook, earlier))
    if (!write([mcp, hooks], out)) out.push('nothing to change')
  } else if (mode === 'mcp') {
    if (!io.env.HOME) throw new UsageError('no HOME: codex --user writes $HOME/.codex/config.toml')
    const file = join(io.env.HOME, '.codex', 'config.toml')
    // One server per Codex session: --session auto:codex names each session from Codex's session id at its first
    // tool call, and the server refuses --as and --keep-alive-records beside --session (packages/mcp/src/config.ts).
    const session = [m.mcp, '--session', 'auto:codex', '--principal', name]
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
    const command = [process.execPath, m.cli, 'wake-hook', ...flags].map(shq).join(' ')
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
    const line = [process.execPath, m.cli, ...watch, ...rooted].map(shq).join(' ')
    out.push(
      `the worker path (no MCP table written: one receiver per identity): ${line} --exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'`,
    )
  }
  // claude-code --project: the same read-only check of the identity's records at its relays as the omp form.
  if (host === 'claude-code') {
    return recordWarnings(io, home, relays, name).then((warnings) => {
      for (const line of [...out, ...warnings]) io.out(line)
      return 0
    })
  }
  for (const line of out) io.out(line)
  return 0
}

/**
 * The identity's records at its relays, read and mended where that is safe, as output lines. A relay that holds no
 * address or no accept-from record of `name` refuses mail to it (not-hosted). When another named relay or the home's copy
 * holds the record (<name>.address.json and <name>.accept.json in the home's records folder), the newest one is
 * published as it is to
 * each relay that lacks it, the same act as `record keep --once` with nothing re-signed, and a line says so (an identity
 * paired through the CLI floor has its records at the rendezvous relay only, helper-1's acceptance run, 2026-11-11). Only
 * a record no relay and no copy holds is a warning, pointing to `bag onboard`: --keep-alive-records keeps records alive
 * but never makes the first ones (packages/mcp/src/keepalive.ts). A relay that does not answer is named as unchecked.
 * Never a refusal: a relay may be briefly away.
 */
async function recordWarnings(
  io: Io,
  home: string,
  relays: readonly string[],
  name: string,
): Promise<string[]> {
  const address = homeCustody(io, home).entry(name).address
  const client = io.relay({})
  const kinds = ['address', 'accept-from'] as const
  const out: string[] = []
  const now = io.clock.now()
  // A record's bytes when they verify now as `name`'s record of that kind, else null.
  const own = (
    bytes: Uint8Array | null,
    kind: (typeof kinds)[number],
  ): { bytes: Uint8Array; iat: number } | null => {
    if (bytes === null) return null
    try {
      const r = verifyRecord(parseRecord(bytes), now)
      return r.kind === kind && recordSigner(r) === address ? { bytes, iat: r.iat } : null
    } catch {
      return null
    }
  }
  const held = new Map<string, (Uint8Array | null)[]>()
  for (const url of relays) {
    try {
      held.set(url, await Promise.all(kinds.map((k) => client.fetchRecord(url, address, k))))
    } catch (e) {
      const code = (e as { code?: unknown }).code
      out.push(
        `warning: ${url} did not answer (${typeof code === 'string' ? code : 'error'}): the records of ${name} there were not checked`,
      )
    }
  }
  const copies = [addressCopy(home, name, address), acceptCopy(home, name, address)]
  const missing = new Map<string, string[]>()
  for (const [i, kind] of kinds.entries()) {
    let best: { bytes: Uint8Array; iat: number; from: string } | null = null
    for (const [url, got] of held) {
      const r = own(got[i] ?? null, kind)
      if (r !== null && r.iat > (best?.iat ?? -1)) best = { ...r, from: url }
    }
    const copy = copies[i]
    if (best === null && copy) {
      const r = own(serializeRecord(copy), kind)
      if (r !== null) best = { ...r, from: `the home copy (${join(home, 'records')})` }
    }
    for (const [url, got] of held) {
      if (got[i] !== null) continue
      if (best === null) {
        missing.set(url, [...(missing.get(url) ?? []), kind])
        continue
      }
      try {
        await client.publish(url, best.bytes)
        out.push(
          `republished the ${kind} record of ${name} to ${url} (it was at ${best.from}; nothing re-signed)`,
        )
      } catch (e) {
        const code = (e as { code?: unknown }).code
        out.push(
          `warning: ${url} refused the ${kind} record of ${name} (${typeof code === 'string' ? code : 'error'}): run bag record keep --once --as ${name} with every relay`,
        )
      }
    }
  }
  for (const [url, kindsMissing] of missing) {
    out.push(
      `warning: no ${kindsMissing.join(' and ')} record at ${url} for ${name}, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to ${name}`,
    )
  }
  return out
}

/** host install|remove omp: the omp form of hostInstall (installOmp, removeOmp). */
async function hostOmp(p: Parsed, io: Io, verb: 'install' | 'remove'): Promise<number> {
  for (const f of ['user', 'mode', 'grant-caveat', 'identities', 'label'] as const) {
    if (p.values[f] !== undefined) throw new UsageError(`--${f} is not taken by omp`)
  }
  const project = str(p, 'project')
  if (project === undefined) throw new UsageError('omp needs --project <dir>: the folder omp runs in')
  const name = str(p, 'as')
  if (name === undefined) throw new UsageError('--as is required')
  const dir = resolve(project)
  if (!existsSync(dir)) throw new CliError('ENOENT', `no project directory ${dir}`)
  const out: string[] = []
  if (verb === 'remove') {
    removeOmp(dir, name, out)
    for (const line of out) io.out(line)
    return 0
  }
  const home = resolve(homeDir(io, str(p, 'dir')))
  checkIdentity(io, home, name)
  const relays = list(p, 'relay').map(relayUrl)
  if (relays.length === 0) throw new UsageError('--relay <url> is required, at least once')
  const roots = list(p, 'trust-root')
  for (const r of roots) trustedRoot(r)
  const meet = str(p, 'rendezvous')
  const me: Identity = {
    label: name,
    key: name,
    home,
    relays,
    ...(meet === undefined ? {} : { rendezvous: relayUrl(meet) }),
    ...(roots.length === 0 ? {} : { trust_roots: roots }),
    keep_alive_records: true,
  }
  const m = stableMains(home)
  out.push(...copiedLines(m))
  installOmp(m, dir, me, out)
  out.push(...(await recordWarnings(io, home, relays, name)))
  for (const line of out) io.out(line)
  return 0
}
