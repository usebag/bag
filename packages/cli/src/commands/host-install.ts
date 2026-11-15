import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import {
  copiedLines,
  type HostProcess,
  type Identity,
  installClaude,
  installCodex,
  installIdentities,
  installOmp,
  installUser,
  migrate,
  recordWarnings,
  removeIdentities,
  removeOmp,
  removeUser,
  undo,
} from '@usebag/home'
import { CliError, flag, list, type Parsed, parse, relayUrl, shq, str, UsageError } from '../args.ts'
import { checkIdentity, homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'
import { stableNode } from '../packaged.ts'
import { needTty } from '../policy.ts'
import { buildOf, type Staged, stage } from '../stage.ts'
import { serviceInstall } from './host-service.ts'
import { trustedRoot } from './inbox.ts'

// host install, remove and migrate: the command line's parse and its thin callers. The planning and the writing of the
// host files moved to packages/home (host-install.ts, host-user.ts, host-migrate.ts there), which the MCP server
// shares; the lines they return are printed here, in the order they were.

/** The node this command line writes, the node running it, its process id and its user's id. */
const processOf = (): HostProcess => ({
  node: stableNode(),
  execPath: process.execPath,
  pid: process.pid,
  uid: process.getuid?.(),
})

/** The entries for `home`, in its staged version directory (stage.ts): never written under a running server. */
const mains = (home: string, _name?: string): Staged => stage(home)

/**
 * host remove claude-code --project <dir> --identities <file> --label <label> (5.2): the identity's entry out of the
 * file (packages/home's removeIdentities); it takes no other flag.
 */
function remove(p: Parsed, io: Io, file: string, dir: string): number {
  if (['as', 'dir', 'relay', 'rendezvous', 'trust-root'].some((k) => p.values[k] !== undefined)) {
    throw new UsageError('host remove takes only --project, --identities and --label')
  }
  for (const line of removeIdentities(file, dir, str(p, 'label') as string)) io.out(line)
  return 0
}

/**
 * host install <claude-code|codex|omp> --as <name> --relay <url>... [--rendezvous <url>] [--trust-root <address>]...
 * [--dir <home>] [--session auto:codex --grant-caveat <caveat>...] (--project <dir> | --user): registers the identity's MCP server with a
 * host and, for Claude Code, the wake hook. --rendezvous is passed to the server, the relay its pairing codes meet at.
 * Only the places packages/mcp/README.md documents are written; any other is a usage error
 * "not documented yet". claude-code --project <dir>: `.mcp.json` (mcpServers.bag = {command, args}) and
 * `.claude/settings.json` (a SessionStart and a Stop hook, `{"type": "command", "command": "<node> <cli>
 * wake-hook --as <name> --dir <home> --max 86000"}` with asyncRewake and timeout 86400: WAKE_MAX, WAKE_TIMEOUT), merged
 * into what is there without touching another key, an earlier install's hook of that identity replaced; a second run
 * changes nothing and says so. codex --user --mode worker (the
 * default: Codex has no idle wake) prints the line that runs `inbox --watch --exec 'codex exec ...'` (the README's runnable form) and writes
 * nothing; --mode mcp writes the `[mcp_servers.bag]` table in ~/.codex/config.toml instead (one receiver
 * per identity: never both; by default the plain identity, the args of the claude-code entry, which can pair; with
 * --session auto:codex and the required --grant-caveat, which nothing else takes, `--session auto:codex --principal
 * <name>`, each Codex session named from its session id and asking the agent for its own grant; a table of the other
 * form is `exists`) and merges a Stop hook into ~/.codex/hooks.json (`{"type": "command",
 * "command": "<node> <cli> wake-hook --as <name> [--session auto:codex] --dir <home> --max 30 --no-idle-wake",
 * "timeout": 60, "statusMessage": ...}`): when a
 * turn ends, Codex waits up to 30 s for mail and continues the turn when one arrives. The
 * hook is no receiver, it reads only the doorbell, so it runs beside the MCP server. Both Codex files are worked out
 * before either is written, so a refusal leaves neither changed. No key is read and no secret printed: the entries hold the node path, the checkout's paths, the
 * name, the home, relay URLs and trust roots (addresses, public). claude-code --identities <file> [--label <label>]
 * adds the identity to an identities file instead (`install`), and host remove claude-code takes one out (`remove`).
 */
export function hostInstall(args: readonly string[], io: Io): number | Promise<number> {
  return viaHome(() => hostCommand(args, io))
}

function hostCommand(args: readonly string[], io: Io): number | Promise<number> {
  if (args[0] === 'migrate') return hostMigrate(args, io)
  if (args[0] === 'install' && args[1] === 'service') {
    const p = parse(args, { positionals: ['verb', 'host'], options: { dir: { type: 'string' } } })
    const home = resolve(homeDir(io, str(p, 'dir')))
    const m = mains(home)
    const self = [stableNode(), m.cli].map(shq).join(' ')
    // The staging line on stderr: stdout is the unit's text first, for the person's sed line.
    for (const line of copiedLines(m)) io.err(line)
    // The service's main is the launcher (stage.ts): a prune of the version it named never breaks the agent.
    for (const line of serviceInstall(io.env, home, m.mcp, self)) io.out(line)
    return 0
  }
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
    session: { type: 'string' },
    identities: { type: 'string' },
    label: { type: 'string' },
    sandbox: { type: 'boolean' },
  } as const
  const p = parse(args, { positionals: ['verb', 'host'], options })
  const [verb, host] = p.positionals
  if (verb !== 'install' && verb !== 'remove') {
    throw new UsageError(`host takes install, remove or migrate, not ${JSON.stringify(verb)}`)
  }
  if (host !== 'claude-code' && host !== 'codex' && host !== 'omp') {
    throw new UsageError(`no host ${JSON.stringify(host)}: the hosts are claude-code, codex and omp`)
  }
  const session = str(p, 'session')
  if (session !== undefined && !(host === 'codex' && str(p, 'mode') === 'mcp'))
    throw new UsageError('--session is for codex --mode mcp only')
  if (session !== undefined && session !== 'auto:codex')
    throw new UsageError(`--session takes auto:codex, not ${JSON.stringify(session)}`)
  if (flag(p, 'sandbox') && !(verb === 'install' && flag(p, 'user') && str(p, 'as') === undefined)) {
    throw new UsageError('--sandbox is for host install claude-code --user')
  }
  if (verb === 'remove' && flag(p, 'user') && str(p, 'as') === undefined) {
    const out: string[] = []
    removeUser(io.env, process.pid, resolve(homeDir(io, str(p, 'dir'))), host, out)
    for (const line of out) io.out(line)
    return 0
  }
  // --user with no --as: the bag service's shim for every identity of the home (host-user.ts).
  if (verb === 'install' && flag(p, 'user') && str(p, 'as') === undefined) {
    for (const f of [
      'project',
      'relay',
      'rendezvous',
      'trust-root',
      'mode',
      'session',
      'identities',
      'label',
      'grant-caveat',
    ] as const) {
      if (p.values[f] !== undefined)
        throw new UsageError(`--${f} is not taken by --user without --as: the bag service reads the home`)
    }
    if (flag(p, 'sandbox') && host !== 'claude-code') throw new UsageError('--sandbox is for claude-code')
    const home = resolve(homeDir(io, str(p, 'dir')))
    const m = mains(home)
    const out = copiedLines(m)
    installUser(io.env, processOf(), m, home, host, flag(p, 'sandbox'), out)
    for (const line of out) io.out(line)
    return 0
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
    throw new UsageError('--grant-caveat is for codex --mode mcp --session auto:codex only')
  }
  if (caveats.length > 0 && session === undefined) {
    throw new UsageError(
      '--grant-caveat is for --session auto:codex: add it for a session of the principal, or drop --grant-caveat for a plain identity',
    )
  }
  if (session !== undefined && caveats.length === 0) {
    throw new UsageError(
      'codex --session auto:codex needs --grant-caveat <caveat>: the session asks the agent for a grant',
    )
  }
  if ((project === undefined) === !user) throw new UsageError('give one of --project <dir> or --user')
  if (host === 'claude-code' && user) {
    throw new UsageError(
      'claude-code --user takes no --as: it wires the bag service for every identity of the home; --project <dir> wires one identity',
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
  const m = mains(file === undefined ? home : dirname(file), name)
  const out: string[] = copiedLines(m)
  const proc = processOf()
  if (host === 'claude-code') {
    if (file !== undefined) {
      for (const line of installIdentities(proc, m, file, dir, me)) io.out(line)
      return 0
    }
    installClaude(proc, m, dir, me, out)
  } else if (mode === 'mcp') installCodex(io.env, proc, m, me, session, caveats, out)
  else {
    const watch = ['inbox', '--watch', '--as', name, ...relays.flatMap((r) => ['--relay', r]), '--dir', home]
    const rooted = roots.flatMap((r) => ['--trust-root', r])
    const line = [proc.node, m.cli, ...watch, ...rooted].map(shq).join(' ')
    out.push(
      `the worker path (no MCP table written: one receiver per identity): ${line} --exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'`,
    )
  }
  // claude-code --project and a plain Codex identity: the same read-only check of its records as the omp form.
  if (host === 'claude-code' || (mode === 'mcp' && session === undefined)) {
    return recordWarnings(homeIo(io), home, relays, name).then((warnings) => {
      for (const line of [...out, ...warnings]) io.out(line)
      return 0
    })
  }
  for (const line of out) io.out(line)
  return 0
}

/** host install|remove omp: the omp form of hostInstall (installOmp, removeOmp). */
async function hostOmp(p: Parsed, io: Io, verb: 'install' | 'remove'): Promise<number> {
  for (const f of ['user', 'mode', 'grant-caveat', 'identities', 'label'] as const) {
    if (p.values[f] !== undefined)
      throw new UsageError(`--${f} is not taken by omp --as (omp --user takes no --as)`)
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
  const m = mains(home, name)
  out.push(...copiedLines(m))
  installOmp(processOf(), m, dir, me, out)
  out.push(...(await recordWarnings(homeIo(io), home, relays, name)))
  for (const line of out) io.out(line)
  return 0
}

/**
 * host migrate [--project <dir>...] [--sandbox] [--dir <home>] | host migrate --undo <stamp> [--dir <home>]: each asks
 * at the terminal (packages/home's migrate and undo); the package is staged after the yes.
 */
async function hostMigrate(args: readonly string[], io: Io): Promise<number> {
  const options = {
    project: { type: 'string', multiple: true },
    sandbox: { type: 'boolean' },
    undo: { type: 'string' },
    dir: { type: 'string' },
  } as const
  const p = parse(args, { positionals: ['verb'], options })
  const home = resolve(homeDir(io, str(p, 'dir')))
  const stamp = str(p, 'undo')
  if (stamp !== undefined) {
    if (list(p, 'project').length > 0 || flag(p, 'sandbox')) throw new UsageError('--undo takes only --dir')
    needTty(io, 'host migrate --undo')
    await undo(homeIo(io), home, stamp, process.pid)
    return 0
  }
  needTty(io, 'host migrate')
  const given = list(p, 'project').map((d) => resolve(d))
  await migrate(homeIo(io), { home, given, sandbox: flag(p, 'sandbox'), build: buildOf(), proc: processOf() })
  return 0
}
