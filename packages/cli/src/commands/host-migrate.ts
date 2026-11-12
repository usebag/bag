import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { CliError, shq, UsageError } from '../args.ts'
import {
  applyChange,
  type Before,
  backup,
  type Change,
  restore,
  stateAfter,
  stateOf,
  View,
} from '../changes.ts'
import { addIdentity, type Identities, type Identity, readIdentities } from '../identities.ts'
import type { Io } from '../io.ts'
import { needTty } from '../policy.ts'
import type { Staged } from '../stage.ts'
import { bagLink, child, ompLinks } from './host-install.ts'
import { type Host, tableOf, userChanges, userNotes } from './host-user.ts'

// host migrate (docs/bag-service.md section 10; the review memos' migration rows): moves every per-folder bag entry
// that this home wrote to the user-scope shim of the bag service, on one y. Only entries whose --dir is this home (by
// realpath) and whose identity is in it are moved; any other entry is listed and left. Each identity's relay settings
// go into <home>/identities.json (a label there with other settings, or two entries of one label that differ, is a
// label collision: refused exists, nothing changed); each folder's identity becomes a proposal in
// <home>/proposals.json (a default the service proposes, never a binding). Every path
// is backed up and journalled in <home>/migrate/<stamp>.json before the first write; host migrate --undo <stamp> puts
// each back. Old keep jobs are retired by the person: one bootout line per job. Nothing here runs launchctl or cron.

type Json = Record<string, unknown>

/** One per-folder entry found: where, for which host, and the identity it runs. */
interface Found {
  readonly folder: string
  readonly host: Host
  readonly file: string
  readonly identity: Identity
  /** Where the entry's relays or rendezvous differ from install/<label>.env, and trust roots it carries: shown. */
  readonly flags: readonly string[]
}

/** RELAYS and RENDEZVOUS of <home>/install/<name>.env (the install page's settings), read as text, never sourced. */
function installEnv(home: string, name: string): { relays: string[]; rendezvous: string | null } | null {
  let text: string
  try {
    text = readFileSync(join(home, 'install', `${name}.env`), 'utf8')
  } catch {
    return null
  }
  const value = (k: string) => new RegExp(`^${k}="([^"]*)"$`, 'm').exec(text)?.[1]
  const relays = value('RELAYS')
  if (relays === undefined) return null
  return { relays: relays.split(/\s+/).filter(Boolean), rendezvous: value('RENDEZVOUS') ?? null }
}

/** The per-folder server's identity in an entry's args, when the entry is one (bag-mcp --as ... --dir ...), else null. */
function perFolder(args: unknown): Identity | null {
  if (!Array.isArray(args) || !args.every((a) => typeof a === 'string') || typeof args[0] !== 'string')
    return null
  const main = args[0]
  if (!(basename(main) === 'bag-mcp.js' || main.endsWith(join('mcp', 'src', 'main.ts')))) return null
  if (args.includes('--identities') || args.includes('--session')) return null
  const values = (f: string) => args.filter((_, i) => i > 0 && args[i - 1] === f)
  const [label, dir] = [values('--as')[0], values('--dir')[0]]
  if (label === undefined || dir === undefined) return null
  const [meet, roots] = [values('--rendezvous'), values('--trust-root')]
  const lists = {
    honor: values('--honor'),
    accept_types: values('--accept-type'),
    receipts_to: values('--receipts-to'),
  }
  const [policy, members] = [values('--policy')[0], values('--members')[0]]
  return {
    label,
    key: label,
    home: dir,
    relays: values('--relay'),
    ...(meet.length === 0 ? {} : { rendezvous: meet[0] }),
    ...(roots.length === 0 ? {} : { trust_roots: roots }),
    ...Object.fromEntries(Object.entries(lists).filter(([, v]) => v.length > 0)),
    ...(args.includes('--keep-alive-records') ? { keep_alive_records: true } : {}),
    ...(args.includes('--allow-delegate') ? { allow_delegate: true } : {}),
    ...(policy === undefined ? {} : { policy }),
    ...(members === undefined ? {} : { members }),
  }
}

const real = (p: string): string | null => {
  try {
    return realpathSync(p)
  } catch {
    return null
  }
}

const jsonAt = (file: string): Json | null => {
  try {
    const d = JSON.parse(readFileSync(file, 'utf8'))
    return typeof d === 'object' && d !== null && !Array.isArray(d) ? (d as Json) : null
  } catch {
    return null
  }
}

/** The folders bag wired from this home: --project, every install/<name>.env WORK, every state/<name>/mcp.lock cwd. */
function folders(home: string, given: readonly string[]): string[] {
  const out = [...given]
  const each = (dir: string) => {
    try {
      return readdirSync(dir)
    } catch {
      return []
    }
  }
  for (const f of each(join(home, 'install')).filter((x) => x.endsWith('.env'))) {
    const m = /^WORK="([^"]*)"$/m.exec(readFileSync(join(home, 'install', f), 'utf8'))
    if (m?.[1]) out.push(m[1])
  }
  for (const n of each(join(home, 'state'))) {
    const cwd = jsonAt(join(home, 'state', n, 'mcp.lock'))?.cwd
    if (typeof cwd === 'string') out.push(cwd)
  }
  return [
    ...new Set(out.map((f) => real(f)).filter((f): f is string => f !== null && statSync(f).isDirectory())),
  ]
}

/** Whether `name` is an identity of `home`: a key file, keychain pointer or agent pointer, by presence only. */
const inHome = (home: string, name: string): boolean =>
  ['keys', 'keychain', 'agent'].some((d) => existsSync(join(home, d, `${name}.json`)))

/** The UTC stamp of now: 20261112T124500Z. */
const stampOf = (io: Io): string =>
  new Date(io.clock.now() * 1000)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')

/** The wake-hook marker of a per-folder identity in a hook command (identity.ts's). */
const marker = (name: string, home: string) => ` wake-hook --as ${shq(name)} --dir ${shq(home)}`

/** Takes the hooks that run `marker` out of every event of `events`; true when one went. */
function dropHooks(events: Json, mark: string): boolean {
  let changed = false
  for (const [event, groups] of Object.entries(events)) {
    if (!Array.isArray(groups)) continue
    const kept = groups
      .map((g: { hooks?: unknown }) => {
        if (!Array.isArray(g?.hooks)) return g
        const runs = (c: string) => c.includes(`${mark} `) || c.endsWith(mark)
        const left = g.hooks.filter((h: { command?: unknown }) => !runs(String(h?.command ?? '')))
        changed ||= left.length < g.hooks.length
        return left.length === 0 ? null : { ...g, hooks: left }
      })
      .filter((g) => g !== null)
    if (kept.length > 0) events[event] = kept
    else delete events[event]
  }
  return changed
}

/** host migrate [--project <dir>...] [--sandbox] [--dir <home>]: see above. `m` is the staged package (stage.ts). */
export async function migrate(
  io: Io,
  m: Staged,
  home: string,
  given: readonly string[],
  sandbox: boolean,
): Promise<number> {
  needTty(io, 'host migrate')
  const HOME = io.env.HOME
  if (!HOME) throw new UsageError('no HOME: host migrate edits the user-scope files under $HOME')
  const me = real(home)
  const hm = resolve(home) // written as the person names it; `hm`, its realpath, only compared
  if (me === null) throw new CliError('ENOENT', `no home ${home}`)
  const st = lstatSync(me)
  if (st.uid !== process.getuid?.() || (st.mode & 0o022) !== 0) {
    throw new CliError(
      'unsafe-path',
      `${me} is not this user's own home (owner, or group or other may write it)`,
    )
  }
  const found: Found[] = []
  const left: string[] = []
  const view = new View()
  const consider = (folder: string, host: Host, file: string, args: unknown): Identity | null => {
    const e = perFolder(args)
    if (e === null) {
      left.push(
        `${file}: not a per-folder bag server of one identity (an identities file, a session or another form): left as it is`,
      )
      return null
    }
    if (real(e.home) !== me) {
      left.push(`${file}: ${e.label} of the home ${e.home}, not ${hm}: left as it is`)
      return null
    }
    if (!inHome(hm, e.label)) {
      left.push(`${file}: ${e.label} is not an identity of ${hm}: left as it is`)
      return null
    }
    // install/<label>.env, where there, is the source of truth for the relays and the rendezvous: a committed entry
    // the person once approved may carry others (the red team's C3). Trust roots are shown, whatever their source.
    const env = installEnv(hm, e.label)
    const flags: string[] = []
    let identity: Identity = { ...e, home: hm }
    if (env !== null) {
      const same = [...env.relays].sort().join(' ') === [...e.relays].sort().join(' ')
      if (!same)
        flags.push(
          `relays ${e.relays.join(' ')} differ from install/${e.label}.env (${env.relays.join(' ')}), which is used`,
        )
      if ((e.rendezvous ?? null) !== env.rendezvous) {
        flags.push(
          `rendezvous ${e.rendezvous ?? 'none'} differs from install/${e.label}.env (${env.rendezvous ?? 'none'}), which is used`,
        )
      }
      const { rendezvous: _drop, ...rest } = identity
      identity = {
        ...rest,
        relays: env.relays,
        ...(env.rendezvous === null ? {} : { rendezvous: env.rendezvous }),
      }
    }
    if ((e.trust_roots ?? []).length > 0)
      flags.push(`trusts ${(e.trust_roots ?? []).join(' ')}: check that these roots are yours`)
    found.push({
      folder,
      host,
      file,
      identity,
      flags,
    })
    return identity
  }
  for (const folder of folders(hm, given)) {
    const mcp = join(folder, '.mcp.json')
    const bag = (jsonAt(mcp)?.mcpServers as Json | undefined)?.bag as { args?: unknown } | undefined
    const e = bag === undefined ? null : consider(folder, 'claude-code', mcp, bag.args)
    if (e !== null) {
      view.json(mcp, `${mcp}: mcpServers.bag (${e.label}) out`, (d) => delete (d.mcpServers as Json).bag)
      const settings = join(folder, '.claude', 'settings.json')
      if (existsSync(settings)) {
        const marks = [marker(e.label, e.home), marker(e.label, bagHomeOf(bag?.args) ?? e.home)]
        view.json(settings, `${settings}: the wake hooks of ${e.label} out`, (d) =>
          marks.map((k) => dropHooks(child(d, 'hooks'), k)).some(Boolean),
        )
      }
    }
    const omp = join(folder, '.omp', 'mcp.json')
    const obag = (jsonAt(omp)?.mcpServers as Json | undefined)?.bag as { args?: unknown } | undefined
    const o = obag === undefined ? null : consider(folder, 'omp', omp, obag.args)
    if (o !== null) {
      view.json(omp, `${omp}: mcpServers.bag (${o.label}) out`, (d) => delete (d.mcpServers as Json).bag)
      for (const l of ompLinks(folder).filter(bagLink))
        view.set({ path: l, gone: true, note: `${l}: bag's wake link out` })
    }
  }
  const codex = join(HOME, '.codex', 'config.toml')
  const table = tableOf(view.text(codex) ?? '')
  if (table) {
    const args = /^args = (.*)$/m.exec(table)?.[1]
    const parsed = args === undefined ? null : (JSON.parse(args) as unknown)
    const e = consider('*', 'codex', codex, parsed)
    if (e !== null) {
      view.set({
        path: codex,
        text: (view.text(codex) ?? '').replace(table, ''),
        mode: 0o600,
        note: `${codex}: [mcp_servers.bag] (${e.label}) out`,
      })
      const hooks = join(HOME, '.codex', 'hooks.json')
      if (existsSync(hooks)) {
        view.json(hooks, `${hooks}: the Stop hook of ${e.label} out`, (d) =>
          dropHooks(child(d, 'hooks'), ` wake-hook --as ${shq(e.label)}`),
        )
      }
    }
  }
  if (found.length === 0) {
    for (const line of [...left, 'nothing to migrate: no per-folder bag entry of this home was found'])
      io.out(line)
    return 0
  }
  // Each identity once in the bag service's <home>/identities.json (the existing entry format, every entry this home).
  // Two folder entries of one label with other settings are a label collision, refused before anything is written. A
  // label the file already holds (keygen, init, restore and identity relays write it) keeps its entry; a folder entry
  // whose settings differ from it is shown with a WARNING.
  const idFile = join(hm, 'identities.json')
  const was = view.text(idFile)
  let doc: Identities = was === null ? { version: 1, identities: [] } : readIdentities(idFile, true)
  const there = new Map(doc.identities.map((e) => [e.label, e]))
  let fresh: Identities = { version: 1, identities: [] }
  for (const f of found) {
    const have = there.get(f.identity.label)
    if (have === undefined) fresh = addIdentity(fresh, f.identity, false, true) ?? fresh
    else if (!INSTALLED_SAME(have, f.identity)) {
      ;(f.flags as string[]).push(
        `${idFile} holds ${f.identity.label} with other settings (relays ${have.relays.join(' ')}), which are kept`,
      )
    }
  }
  for (const e of fresh.identities) doc = addIdentity(doc, e, false, true) ?? doc
  const labels = [...new Set(found.map((f) => f.identity.label))].join(', ')
  view.set({
    path: idFile,
    text: `${JSON.stringify(doc, null, 2)}\n`,
    mode: 0o600,
    note: `${idFile}: ${labels}`,
  })
  const stamp = stampOf(io)
  const propFile = join(hm, 'proposals.json')
  const props = jsonAt(propFile) ?? { version: 1, proposals: [] }
  const rows = (props.proposals as Json[] | undefined) ?? []
  const add = found
    .map((f) => ({ folder: f.folder, host: f.host, label: f.identity.label, from: 'migrate', stamp }))
    .filter((r) => !rows.some((x) => x.folder === r.folder && x.host === r.host))
  view.set({
    path: propFile,
    text: `${JSON.stringify({ version: 1, proposals: [...rows, ...add] }, null, 2)}\n`,
    mode: 0o600,
    note: `${propFile}: proposed ${add.map((r) => `${r.label} (${r.host})`).join(', ') || 'none new'}`,
  })
  for (const host of [...new Set(found.map((f) => f.host))]) userChanges(view, io, m, hm, host, sandbox)
  const changes = view.changes()
  const jobs = keepJobs(HOME)
  const question = [
    `migrate ${found.length} per-folder bag entries of ${hm} to the bag service (every file is backed up first; host migrate --undo ${stamp} puts them back):`,
    ...found.flatMap((f) => [
      `  ${f.host} ${f.folder === '*' ? 'for this user' : f.folder}: ${f.identity.label}, proposed there, never bound without your word`,
      `    from ${f.file}: relays ${f.identity.relays.join(' ')}${f.identity.rendezvous === undefined ? '' : `, rendezvous ${f.identity.rendezvous}`}, trust roots ${(f.identity.trust_roots ?? []).join(' ') || 'none'}`,
      ...f.flags.map((x) => `    WARNING: ${x}`),
    ]),
    ...changes.map((c) => `  edit ${c.note}`),
    // The old --keep-alive-records meant "while this server runs", which the service's default does: keep-alive stays
    // the default for every identity, and a permanent one is the person's own word, typed later.
    `  keep-alive stays the default for ${labelsOf(found)}: to keep one's records alive always, type bag identity keep-alive on <name>`,
    ...left.map((l) => `  left ${l}`),
    'migrate?',
  ].join('\n')
  if (!(await io.confirm(question))) throw new CliError('declined', 'nothing was changed')
  // The journal first, with every backup, then the edits; a run cut short is undone from it.
  const dir = join(hm, 'migrate')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const entries: { path: string; before: Before; after: string }[] = changes.map((c, i) => ({
    path: c.path,
    before: backup(c.path, join(dir, stamp), i),
    after: stateAfter(c),
  }))
  const journal = join(dir, `${stamp}.json`)
  applyChange({
    path: journal,
    text: `${JSON.stringify({ version: 1, stamp, home: hm, entries }, null, 2)}\n`,
    mode: 0o600,
    note: '',
  })
  for (const c of changes) {
    applyChange(c)
    io.out(`wrote ${c.note}`)
  }
  io.out(
    `keep-alive is your choice per identity, the default for ${labelsOf(found)}; for one kept alive always: bag identity keep-alive on <name>`,
  )
  io.out(`journal ${journal}`)
  for (const l of left) io.out(`left ${l}`)
  for (const host of [...new Set(found.map((f) => f.host))])
    for (const l of userNotes(io, hm, host, sandbox)) io.out(l)
  const uid = process.getuid?.() ?? '<uid>'
  for (const j of jobs) {
    io.out(
      `retire the old keep job in a terminal (the service keeps records now): launchctl bootout gui/${uid}/${basename(j, '.plist')} && mv ${shq(j)} ~/.Trash/`,
    )
  }
  io.out('a crontab line that runs record keep, if you set one up, is retired with crontab -e')
  io.out(
    'close the windows of the migrated folders and open them again: they start the shim, and their identity is proposed',
  )
  return 0
}

/** --dir of an entry's args, unresolved (the hook command names the home as the entry wrote it). */
function bagHomeOf(args: unknown): string | null {
  if (!Array.isArray(args)) return null
  const i = args.indexOf('--dir')
  return i >= 0 && typeof args[i + 1] === 'string' ? (args[i + 1] as string) : null
}

/** The person's keep jobs, ~/Library/LaunchAgents/bag.keep.<name>.plist, by name only. */
function keepJobs(HOME: string): string[] {
  const dir = join(HOME, 'Library', 'LaunchAgents')
  try {
    return readdirSync(dir)
      .filter((f) => /^bag\.keep\..+\.plist$/.test(f))
      .sort()
      .map((f) => join(dir, f))
  } catch {
    return []
  }
}

/**
 * host migrate --undo <stamp> [--dir <home>]: every journalled path put back as it was, last edit first, after one y.
 * A path changed since the migration (another install, the person's own edit) refuses stale-record before anything
 * is put back, naming it; the journal is kept, marked undone.
 */
export async function undo(io: Io, home: string, stamp: string): Promise<number> {
  needTty(io, 'host migrate --undo')
  if (!/^\d{8}T\d{6}Z$/.test(stamp))
    throw new UsageError(`--undo takes a stamp such as 20261112T124500Z, not ${JSON.stringify(stamp)}`)
  const file = join(resolve(home), 'migrate', `${stamp}.json`)
  const j = jsonAt(file) as {
    entries?: { path: string; before: Before; after: string }[]
    undone?: string
  } | null
  if (j === null || !Array.isArray(j.entries)) throw new CliError('not-found', `no migration journal ${file}`)
  if (j.undone !== undefined) throw new CliError('exists', `${file} was undone at ${j.undone}`)
  const moved = j.entries.filter((e) => stateOf(e.path) !== e.after)
  if (moved.length > 0) {
    throw new CliError(
      'stale-record',
      `changed since the migration, so not put back: ${moved.map((e) => e.path).join(', ')}; nothing was changed`,
    )
  }
  const question = [
    `undo the migration ${stamp}: put back`,
    ...j.entries.map((e) => `  ${e.path}`),
    'undo?',
  ].join('\n')
  if (!(await io.confirm(question))) throw new CliError('declined', 'nothing was changed')
  for (const e of [...j.entries].reverse()) {
    restore(e.path, e.before)
    io.out(`restored ${e.path}`)
  }
  const at = new Date(io.clock.now() * 1000).toISOString()
  const change: Change = {
    path: file,
    text: `${JSON.stringify({ ...j, undone: at }, null, 2)}\n`,
    mode: 0o600,
    note: '',
  }
  applyChange(change)
  io.out(
    `undone ${stamp}: the per-folder servers start again with their sessions; stop the bag service first if it runs`,
  )
  return 0
}

/** The labels of the entries found, once each. */
const labelsOf = (found: readonly Found[]): string =>
  [...new Set(found.map((f) => f.identity.label))].join(', ')

/** Whether two entries carry the same relays, rendezvous and trust roots (what a folder entry can differ in). */
const INSTALLED_SAME = (a: Identity, b: Identity): boolean =>
  a.relays.join(' ') === b.relays.join(' ') &&
  (a.rendezvous ?? null) === (b.rendezvous ?? null) &&
  (a.trust_roots ?? []).join(' ') === (b.trust_roots ?? []).join(' ')
