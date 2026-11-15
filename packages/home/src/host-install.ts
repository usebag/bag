import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, extname, isAbsolute, join, relative, sep } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { parseRecord, recordSigner, serializeRecord, verifyRecord } from '@usebag/core'
import { acceptCopy, addressCopy } from '@usebag/edge'
import {
  addGroup,
  bagLink,
  CODEX_STOP_TIMEOUT,
  CODEX_STOP_WAIT,
  child,
  type HostProcess,
  type Json,
  ompLinks,
  shq,
  TABLE,
  WAKE_MAX,
  WAKE_TIMEOUT,
} from './host-common.ts'
import {
  addIdentity,
  type Identities,
  type Identity,
  keyOf,
  readIdentities,
  removeIdentity,
  saveIdentities,
} from './identities.ts'
import { LABEL } from './index.ts'
import { homeCustody } from './keys.ts'
import { type Mains, versionLine } from './packaged.ts'
import { HomeError, type HomeIo } from './ports.ts'
import type { Staged } from './stage.ts'

// host install and remove at project scope (claude-code, omp) and Codex's user table: each works out every file it
// changes before it writes the first, so a refusal leaves them all as they were. The command line parses the flags and
// prints the lines these return; the node written, the node running and the process id come in a HostProcess.

/** The wake-hook command with `flags`, shell-quoted; without --max, the form host install wrote before WAKE_MAX. */
const wakeCommand = (p: HostProcess, m: Mains, flags: readonly string[], node = p.node): string =>
  [node, m.cli, 'wake-hook', ...flags].map(shq).join(' ')

/** `entry` as an install before stableNode wrote it, with the resolved node path: replaced, never refused. */
const resolved = (p: HostProcess, entry: Json): Json => ({ ...entry, command: p.execPath })
const ours = (p: HostProcess, have: unknown, entry: Json) =>
  [entry, resolved(p, entry)].some((x) => isDeepStrictEqual(have, x))

/** The Claude Code hook that runs `wake-hook` with `flags` and --max WAKE_MAX: asyncRewake, timeout WAKE_TIMEOUT. */
const wakeHook = (p: HostProcess, m: Mains, flags: readonly string[]): Json => {
  const command = wakeCommand(p, m, [...flags, '--max', String(WAKE_MAX)])
  return { type: 'command', command, timeout: WAKE_TIMEOUT, asyncRewake: true }
}

/** The hook commands an earlier install wrote for `flags` (without --max; with the resolved node path), to replace. */
const earlier = (p: HostProcess, m: Mains, flags: readonly string[]): string[] =>
  [
    wakeCommand(p, m, flags),
    ...[flags, [...flags, '--max', String(WAKE_MAX)]].map((f) => wakeCommand(p, m, f, p.execPath)),
  ].filter((c) => c !== wakeHook(p, m, flags).command)

const relayArgs = (e: Identity): string[] => [
  ...e.relays.flatMap((r) => ['--relay', r]),
  ...(e.rendezvous === undefined ? [] : ['--rendezvous', e.rendezvous]),
]
const rootArgs = (e: Identity): string[] => (e.trust_roots ?? []).flatMap((r) => ['--trust-root', r])

/** The single-identity `.mcp.json` entry, the form `--identities` migrates (5.3). */
const single = (p: HostProcess, m: Mains, e: Identity): Json => ({
  command: p.node,
  args: [m.mcp, '--as', keyOf(e), ...relayArgs(e), ...rootArgs(e), '--dir', e.home, '--keep-alive-records'],
})

/** The identity in `have` when it is exactly the entry a single-identity install writes, else null. */
function singleOf(p: HostProcess, m: Mains, have: unknown): Identity | null {
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
  return ours(p, have, single(p, m, e)) ? e : null
}

/** A change to one JSON file, worked out and not yet written: the document, and what it adds (null: nothing). */
interface Plan {
  readonly file: string
  readonly doc: Json
  readonly added: Json | null
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
    throw new HomeError('host-file-invalid', `${file} is not a JSON object`)
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
const ompEntry = (p: HostProcess, m: Mains, e: Identity): Json => ({
  type: 'stdio',
  command: p.node,
  args: [...((single(p, m, e).args as string[]) ?? []), '--push', 'log'],
})

/**
 * Removes the file or symbolic link at `path` itself, when there. The links here go through unlink: Node 24's rm
 * leaves a symbolic link whose target is gone in place, with no error.
 */
function unlinkThere(path: string): void {
  try {
    unlinkSync(path)
  } catch (e) {
    if ((e as { code?: unknown }).code !== 'ENOENT') throw e
  }
}

/**
 * The temporary wake links a stopped install left in a project's .omp/hooks/pre (bag-wake.<ext>.<pid>.tmp): only
 * symbolic links to bag's omp entry, so a file or folder of that name that is not bag's stays.
 */
function leftLinks(dir: string): string[] {
  const pre = join(dir, '.omp', 'hooks', 'pre')
  let names: string[]
  try {
    names = readdirSync(pre)
  } catch {
    return []
  }
  return names
    .filter((n) => /^bag-wake\.[^.]+\.[0-9]+\.tmp$/.test(n))
    .map((n) => join(pre, n))
    .filter(bagLink)
}

/** The omp wake link in a project: discovered by omp from .omp/hooks/pre/, named with the entry's own extension. */
const ompLink = (dir: string, m: Mains): string =>
  join(dir, '.omp', 'hooks', 'pre', `bag-wake${extname(m.omp)}`)

/**
 * omp --project <dir>: `.omp/mcp.json` (mcpServers.bag, the single-identity line with type stdio and --push log) and
 * the wake link, `.omp/hooks/pre/bag-wake.js` a symbolic link to <home>/package/bag-omp-wake.js (from source,
 * bag-wake.ts to packages/cli/src/omp-wake.ts): one maintained file, never a copy in the project. A bag entry with
 * other settings, or a file at the link that is not bag's link, is refused before anything is written; a link of
 * bag's to another place (an older home) is replaced. A second run changes nothing and says so.
 */
export function installOmp(p: HostProcess, m: Mains, dir: string, me: Identity, out: string[]): void {
  const entry = ompEntry(p, m, me)
  const mcp = plan(join(dir, '.omp', 'mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (have !== undefined && !ours(p, have, entry)) {
      throw new HomeError(
        'exists',
        `${join(dir, '.omp', 'mcp.json')} has mcpServers.bag with other settings: edit or remove it first`,
      )
    }
    if (isDeepStrictEqual(have, entry)) return null
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
    throw new HomeError(
      'exists',
      `${foreign.join(', ')} is not bag's wake link (a hand-written wake?): move it away first, then run this again`,
    )
  }
  const same = bagLink(link) && readlinkSync(link) === m.omp
  const stale = ompLinks(dir).filter((l) => bagLink(l) && !(l === link && same))
  // The new link is made at its temporary name before anything else is written, so a path there that is not a link
  // (a file or folder someone put there) refuses with every file as it was; the rename puts the link in place after.
  const tmp = `${link}.${p.pid}.tmp`
  const left = leftLinks(dir).filter((l) => l !== tmp)
  if (!same) {
    mkdirSync(dirname(link), { recursive: true })
    let there: ReturnType<typeof lstatSync> | null = null
    try {
      there = lstatSync(tmp)
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'ENOENT') throw e
    }
    if (there !== null && !there.isSymbolicLink())
      throw new HomeError('exists', `${tmp} is not a link of bag's: move it away first, then run this again`)
    if (there !== null) unlinkSync(tmp)
  }
  // omp loads every file in hooks/pre, so a temporary link left there would run the wake twice: one that fails on the
  // way is taken out again before the error goes on.
  let made = false
  try {
    if (!same) {
      symlinkSync(m.omp, tmp)
      made = true
    }
    write([mcp], out)
    for (const l of stale) {
      unlinkSync(l)
      out.push(`removed ${l} (an earlier link of bag's)`)
    }
    for (const l of left) {
      unlinkSync(l)
      out.push(`removed ${l} (a temporary link a stopped install of bag left)`)
    }
    if (same) out.push(`unchanged ${link}`)
    else {
      renameSync(tmp, link)
      made = false
      out.push(`wrote ${link} -> ${m.omp}`)
    }
  } catch (e) {
    if (made) unlinkThere(tmp)
    throw e
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
  if (mcp.added === null && same && stale.length === 0 && left.length === 0) out.push('nothing to change')
  out.push(
    'the wake starts with the next omp session in this folder: one turn per ring of the doorbell, queued while a turn runs; only the main interactive session wakes (not omp -p, --mode rpc or a subagent), and every spawned session needs its own --model',
  )
}

/** host remove omp --project <dir> --as <name>: takes out the bag entry of that identity and bag's wake link. */
export function removeOmp(dir: string, name: string, out: string[]): void {
  const file = join(dir, '.omp', 'mcp.json')
  const mcp = plan(file, (doc) => {
    const servers = child(doc, 'mcpServers')
    const args = (servers.bag as { args?: unknown } | undefined)?.args
    if (servers.bag === undefined) return null
    if (!Array.isArray(args) || args[args.indexOf('--as') + 1] !== name || !args.includes('--as')) {
      throw new HomeError(
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
    unlinkSync(l)
    out.push(`removed ${l}`)
  }
  for (const l of leftLinks(dir)) {
    unlinkSync(l)
    out.push(`removed ${l} (a temporary link a stopped install of bag left)`)
  }
}

/** The line for a package staged (stage.ts), first in the output, and the running service's notice; none from source. */
export const copiedLines = (m: Staged): string[] => [
  ...(m.copied === null ? [] : [`wrote ${m.copied} (${versionLine()})`]),
  ...(m.notice === null ? [] : [m.notice]),
]

const RESTART = 'the change takes effect when Claude Code starts the server again'

/** Refuses an identities file that is not absolute, or that is in the project: a project is often committed. */
function outside(file: string, dir: string): void {
  if (!isAbsolute(file))
    throw new HomeError('usage', `--identities takes an absolute path, not ${JSON.stringify(file)}`)
  const inside = relative(dir, file)
  if (inside !== '..' && !inside.startsWith(`..${sep}`) && !isAbsolute(inside)) {
    throw new HomeError(
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
 * worked out before any is written, so a refusal leaves all three as they were. Returns the output lines.
 */
export function installIdentities(
  p: HostProcess,
  m: Staged,
  file: string,
  dir: string,
  me: Identity,
): string[] {
  outside(file, dir)
  if (!LABEL.test(me.label))
    throw new HomeError('usage', `--label is ${LABEL.source}, not ${JSON.stringify(me.label)}`)
  const was: Identities = existsSync(file) ? readIdentities(file) : { version: 1, identities: [] }
  const entry = { command: p.node, args: [m.mcp, '--identities', file] }
  const from: { old?: Identity } = {}
  const mcp = plan(join(dir, '.mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (isDeepStrictEqual(have, entry)) return null
    const old = have === undefined ? null : singleOf(p, m, have)
    if (have !== undefined && old === null && !ours(p, have, entry)) {
      throw new HomeError('exists', 'mcpServers.bag is there with other settings: edit or remove it first')
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
  const migrated = old ? [wakeHook(p, m, old).command as string, ...earlier(p, m, old)] : []
  const drop = [...earlier(p, m, ['--identities', file]), ...migrated]
  const hook = wakeHook(p, m, ['--identities', file])
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
  return out
}

/**
 * host remove claude-code --project <dir> --identities <file> --label <label> (5.2): the identity's entry out of the
 * file, and `default` with it when it named it. No key, home, state, `.mcp.json` or `settings.json` is touched. Returns
 * the output lines.
 */
export function removeIdentities(file: string, dir: string, label: string): string[] {
  outside(file, dir)
  const doc = readIdentities(file)
  const next = removeIdentity(doc, label)
  saveIdentities(file, next)
  return [
    `wrote ${file}`,
    `  removed ${label}`,
    ...(doc.default === label
      ? [`default ${label} dropped: ${next.identities[0]?.label} is the default now`]
      : []),
    RESTART,
  ]
}

/**
 * claude-code --project <dir> for one identity `me`: `.mcp.json` (mcpServers.bag = {command, args}) and
 * `.claude/settings.json` (a SessionStart and a Stop hook running wake-hook --as <name> --dir <home> --max WAKE_MAX),
 * merged into what is there, an earlier install's hook of that identity replaced; a second run says so.
 */
export function installClaude(p: HostProcess, m: Mains, dir: string, me: Identity, out: string[]): void {
  const entry = single(p, m, me)
  const flags = ['--as', keyOf(me), '--dir', me.home]
  const hook = wakeHook(p, m, flags)
  const mcp = plan(join(dir, '.mcp.json'), (doc) => {
    const servers = child(doc, 'mcpServers')
    const have = servers.bag
    if (have !== undefined && !ours(p, have, entry)) {
      throw new HomeError('exists', 'mcpServers.bag is there with other settings: edit or remove it first')
    }
    if (isDeepStrictEqual(have, entry)) return null
    servers.bag = entry
    return { bag: entry }
  })
  // An earlier install's hook for the same identity (no --max, timeout 3600, or the resolved node) is replaced.
  const hooks = plan(join(dir, '.claude', 'settings.json'), (doc) =>
    hookPlan(doc, hook, earlier(p, m, flags)),
  )
  if (!write([mcp, hooks], out)) out.push('nothing to change')
}

/** The key name the single-identity bag server in `file` acts as (its --as), null with none; refused for another form. */
export function wiredAs(file: string): string | null {
  const bag = (plan(file, () => null).doc.mcpServers as Json | undefined)?.bag as
    | { args?: unknown }
    | undefined
  if (bag === undefined) return null
  const args = bag.args
  const at = Array.isArray(args) ? args.indexOf('--as') : -1
  const name = at < 0 ? undefined : (args as unknown[])[at + 1]
  if (typeof name !== 'string')
    throw new HomeError('not-found', `${file} has a bag server of another form: not removed`)
  return name
}

/**
 * The reverse of installClaude for the identity `name` of `home`: mcpServers.bag out of `.mcp.json` when it is that
 * identity's single server, and out of `.claude/settings.json` only the hook groups that run its wake-hook. Every
 * other server and hook stays; a bag server for another identity refuses not-found, with nothing written.
 */
export function removeClaude(dir: string, name: string, home: string, out: string[]): void {
  const file = join(dir, '.mcp.json')
  if (wiredAs(file) !== name && wiredAs(file) !== null)
    throw new HomeError(
      'not-found',
      `${file} has a bag server for another identity than ${name}: not removed`,
    )
  const mcp = plan(file, (doc) => {
    const servers = child(doc, 'mcpServers')
    if (servers.bag === undefined) return null
    delete servers.bag
    return { removed: 'server' }
  })
  const flags = ` wake-hook --as ${shq(name)} --dir ${shq(home)}`
  const hooks = plan(join(dir, '.claude', 'settings.json'), (doc) => {
    const events = child(doc, 'hooks')
    let changed = false
    for (const event of ['SessionStart', 'Stop']) {
      const groups = events[event]
      if (!Array.isArray(groups)) continue
      const keep = groups.filter((g) => !JSON.stringify(g).includes(JSON.stringify(flags).slice(1, -1)))
      if (keep.length === groups.length) continue
      changed = true
      if (keep.length > 0) events[event] = keep
      else delete events[event]
    }
    return changed ? { removed: 'wake-hook' } : null
  })
  for (const x of [mcp, hooks]) {
    if (x.added === null) out.push(`unchanged ${x.file}`)
    else {
      writeFileSync(x.file, `${JSON.stringify(x.doc, null, 2)}\n`)
      out.push(`wrote ${x.file} (bag's ${x.added.removed} removed)`)
    }
  }
}

/**
 * codex --user --mode mcp for `me`: the `[mcp_servers.bag]` table in ~/.codex/config.toml (the plain identity, or with
 * `session` auto:codex one server per Codex session asking for a grant with `caveats`; a table of the other form is
 * `exists`) and the Stop hook in ~/.codex/hooks.json. Both files are worked out before either is written.
 */
export function installCodex(
  env: Readonly<Record<string, string | undefined>>,
  p: HostProcess,
  m: Mains,
  me: Identity,
  session: string | undefined,
  caveats: readonly string[],
  out: string[],
): void {
  const [name, home] = [keyOf(me), me.home]
  if (!env.HOME) throw new HomeError('usage', 'no HOME: codex --user writes $HOME/.codex/config.toml')
  const file = join(env.HOME, '.codex', 'config.toml')
  // Plain (the default): the Claude Code entry's args, one identity, which can pair. --session auto:codex: one server
  // per Codex session, named from Codex's session id at its first tool call, which registers no pair tool; the
  // server refuses --as and --keep-alive-records beside --session (packages/mcp/src/config.ts).
  const forms = [
    single(p, m, me).args as string[],
    [
      m.mcp,
      '--session',
      'auto:codex',
      '--principal',
      name,
      ...caveats.flatMap((c) => ['--grant-caveat', c]),
    ].concat(relayArgs(me), rootArgs(me), ['--dir', home]),
  ]
  const argv = forms[session === undefined ? 0 : 1] as string[]
  const toml = `[mcp_servers.bag]\ncommand = ${JSON.stringify(p.node)}\nargs = ${JSON.stringify(argv)}\n`
  const was = existsSync(file) ? readFileSync(file, 'utf8') : ''
  // An earlier install's table with the resolved node path is replaced, not refused (as its Stop hook below).
  const prior = toml.replace(JSON.stringify(p.node), JSON.stringify(p.execPath))
  const old = prior !== toml && was.includes(prior) ? was.replace(prior, '') : was
  const [there, wait] = [old.includes(toml), String(CODEX_STOP_WAIT)]
  // Both changes are worked out before either file is written: the TOML `exists` and a hooks.json that cannot take
  // the entry refuse here, so a refusal leaves neither changed.
  const hit = there ? null : TABLE.exec(old)
  if (hit) {
    throw new HomeError(
      'exists',
      `${file} has [mcp_servers.bag] with other settings (another identity, or the other form: a plain identity or --session auto:codex): edit or remove it first`,
    )
  }
  // The Stop hook: it waits up to CODEX_STOP_WAIT s for the doorbell and exits 2 with a
  // line, which Codex takes as the continuation prompt of the turn. It reads no mail, so it may run beside the MCP
  // server, the one receiver. The plain form's flags are wake-hook's own synopsis, --as --dir (wake-hook.ts).
  // The hook an earlier install wrote with the resolved node, and this identity's hook of the other form (its table
  // was removed first, or the install refuses above), are replaced: one Stop hook per identity.
  const tail = ['--dir', home, '--max', wait, '--no-idle-wake']
  const both = [
    ['--as', name, ...tail],
    ['--as', name, '--session', 'auto:codex', ...tail],
  ]
  const cmd = (n: string, f: string[]) => [n, m.cli, 'wake-hook', ...f].map(shq).join(' ')
  const command = cmd(p.node, both[session === undefined ? 0 : 1] as string[])
  const before = both.flatMap((f) => [p.node, p.execPath].map((n) => cmd(n, f))).filter((c) => c !== command)
  const hook = {
    type: 'command',
    command,
    timeout: CODEX_STOP_TIMEOUT,
    statusMessage: 'bag: waiting for mail',
  }
  const hooks = plan(join(env.HOME, '.codex', 'hooks.json'), (doc) => {
    const [events, runs] = [
      child(doc, 'hooks'),
      (g: unknown) => before.some((c) => JSON.stringify(g).includes(`"command":${JSON.stringify(c)}`)),
    ]
    const groups = events.Stop
    const drop = Array.isArray(groups) && groups.some(runs)
    if (drop) events.Stop = (groups as unknown[]).filter((g) => !runs(g))
    return addGroup(events, 'Stop', hook) || drop ? { Stop: [{ hooks: [hook] }] } : null
  })
  if (there) out.push(`unchanged ${file}`)
  else {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, old.trim() === '' ? toml : `${old.trimEnd()}\n\n${toml}`, { mode: 0o600 })
    out.push(
      `wrote ${file}`,
      ...toml
        .trimEnd()
        .split('\n')
        .map((l) => `  ${l}`),
    )
  }
  if (!write([hooks], out) && there) out.push('nothing to change')
  const stop = `When a turn ends, a Stop hook waits up to ${wait} s for mail and continues the turn when one arrives; an idle session is not woken. Trust the hook in Codex with /hooks before it runs`
  out.push(
    session === undefined
      ? `mcp mode: one plain identity ${name} for Codex; the first Codex session holds it and any other answers held-by. ${stop}. Pairing needs the interactive codex TUI, 0.113.0 or later, and an approval policy that lets MCP servers ask (on-request, the default). Codex asks before bag's tools that reach other agents: Allow for this session suits pair_invite and pair_accept only (each pairing still needs your answers in its dialogs); answer send, ask, handoff and delegate per call`
      : `mcp mode: one Codex session per server, named from Codex's session id at its first tool call; type y at the agent (ac login) for each session's grant. ${stop}`,
  )
}

/**
 * The identity's records at its relays, read and mended where that is safe, as output lines. A relay that holds no
 * address or no accept-from record of `name` refuses mail to it (not-hosted). When another named relay or the home's copy
 * holds the record (<name>.address.json and <name>.accept.json in the home's records folder), the newest one is
 * published as it is to
 * each relay that lacks it, the same act as `record keep --once` with nothing re-signed, and a line says so (an identity
 * paired through the CLI floor has its records at the rendezvous relay only). Only
 * a record no relay and no copy holds is a warning, pointing to `bag onboard`: --keep-alive-records keeps records alive
 * but never makes the first ones (packages/mcp/src/keepalive.ts). A relay that does not answer is named as unchecked.
 * Never a refusal: a relay may be briefly away. The relays are reached through the caller's relay client.
 */
export async function recordWarnings(
  io: HomeIo,
  home: string,
  relays: readonly string[],
  name: string,
): Promise<string[]> {
  const address = homeCustody(io.security, home).entry(name).address
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
