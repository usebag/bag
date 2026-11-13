import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import {
  type AcceptFromRecord,
  decodeAddress,
  MAX_RELAYS,
  serializeRecord,
  signRecord,
  toHex,
  WILDCARD_ROOT,
} from '@usebag/core'
import { acceptCopy, liftMaxBytes, RelayError, setKeepAlive } from '@usebag/edge'
import { CliError, list, parse, relayUrl, shq, str, UsageError } from '../args.ts'
import { refuseWhileHeld } from '../held.ts'
import { checkIdentity, checkNoWindow, homeCustody, homeDir, loadKeys } from '../home.ts'
import { readIdentities, saveIdentities } from '../identities.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'
import { confirmed, needTty } from '../policy.ts'
import { addToServiceHome } from '../service-home.ts'
import { isTrustRoot, readTrust, removeTrust } from '../trust.ts'
import { removeOmp } from './host-install.ts'
import { IDENTITY_CUSTODY_USAGE, identityCustody } from './identity-custody.ts'
import { dropLocalPairs, needPairsTable, pairedLocally } from './local.ts'
import { newestAccept } from './record.ts'
import { failed, heldBy } from './unpair.ts'

// identity remove: one identity out of a home that may keep others, a person's act after one y on a terminal. Nothing
// is deleted: the identity's files move into one folder. The accept-from is re-signed to name only its owner at every
// relay first (as unpair's last root), and only once every relay took it does anything local change, so a run again
// finds the keys still here. trust.json loses the roots of this identity's accept-from that no other identity's copy
// still names (unpair's heldBy); names.json forgets the names of its address.

const S = { type: 'string' } as const
const USAGE =
  'identity remove <name> --relay <url>... [--to <dir>] [--project <dir>] [--dir <home>] | identity relays <name> --relay <url>... [--dir <home>] | identity keep-alive on|off|default <name> [--dir <home>]'

type Json = Record<string, unknown>

/** The value after flag `f` in an argv list, else undefined. */
const flagValue = (args: readonly unknown[], f: string): unknown => {
  const i = args.indexOf(f)
  return i < 0 ? undefined : args[i + 1]
}

/** A JSON object file: null when absent; host-file-invalid when it is not an object. */
function readJson(file: string): Json | null {
  if (!existsSync(file)) return null
  try {
    const doc = JSON.parse(readFileSync(file, 'utf8'))
    if (typeof doc === 'object' && doc !== null && !Array.isArray(doc)) return doc as Json
  } catch {
    // refused below
  }
  throw new CliError('host-file-invalid', `${file} is not a JSON object`)
}

const writeJson = (file: string, doc: Json): void => writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`)

/** The wiring of `name` in project `dir`: what the question names, and the change, made after the y. */
function wiringOf(
  home: string,
  name: string,
  dir: string,
): { lines: string[]; apply: (out: string[]) => void } {
  const lines: string[] = []
  const steps: ((out: string[]) => void)[] = []
  const mine = (args: unknown): boolean =>
    Array.isArray(args) &&
    flagValue(args, '--as') === name &&
    resolve(String(flagValue(args, '--dir') ?? '')) === home
  const serverOf = (doc: Json | null): { args?: unknown } | undefined =>
    ((doc?.mcpServers ?? {}) as Json).bag as { args?: unknown } | undefined
  const omp = join(dir, '.omp', 'mcp.json')
  const ompBag = serverOf(readJson(omp))
  if (ompBag !== undefined && mine(ompBag.args)) {
    lines.push(`${omp}: its bag server and bag's wake link come out (host remove omp)`)
    steps.push((out) => removeOmp(dir, name, out))
  } else if (ompBag !== undefined) lines.push(`${omp}: its bag server is not ${name}'s: left as it is`)
  const file = join(dir, '.mcp.json')
  const doc = readJson(file)
  const bag = serverOf(doc)
  if (bag !== undefined && mine(bag.args)) {
    const settings = join(dir, '.claude', 'settings.json')
    const hooks = readJson(settings)
    const marker = ` wake-hook --as ${shq(name)} --dir ${shq(home)}`
    lines.push(
      `${file}: mcpServers.bag comes out; ${settings}: the wake hooks of ${name}; every other server and hook stays`,
    )
    steps.push((out) => {
      delete ((doc as Json).mcpServers as Json).bag
      writeJson(file, doc as Json)
      out.push(`wrote ${file} (mcpServers.bag removed)`)
      const events = hooks?.hooks as Json | undefined
      if (hooks === null || typeof events !== 'object' || events === null) return
      let changed = false
      for (const event of ['SessionStart', 'Stop']) {
        const groups = events[event]
        if (!Array.isArray(groups)) continue
        const kept = groups
          .map((g: { hooks?: unknown }) => {
            if (!Array.isArray(g?.hooks)) return g
            const left = g.hooks.filter(
              (h: { command?: unknown }) => !String(h?.command ?? '').includes(marker),
            )
            changed ||= left.length < g.hooks.length
            return left.length === 0 ? null : { ...g, hooks: left }
          })
          .filter((g) => g !== null)
        if (kept.length > 0) events[event] = kept
        else delete events[event]
      }
      if (!changed) return
      if (Object.keys(events).length === 0) delete hooks.hooks
      writeJson(settings, hooks)
      out.push(`wrote ${settings} (the wake hooks of ${name} removed)`)
    })
  } else if (bag !== undefined && Array.isArray(bag.args) && bag.args.includes('--identities')) {
    lines.push(
      `${file}: its bag server reads an identities file: left as it is; take ${name} out with host remove claude-code`,
    )
  } else if (bag !== undefined) lines.push(`${file}: its bag server is not ${name}'s: left as it is`)
  if (lines.length === 0) lines.push(`${dir}: no bag wiring of ${name}`)
  return {
    lines,
    apply: (out) => {
      for (const s of steps) s(out)
    },
  }
}

/** A path, absent or not, exists as a file, directory or link (a link is not followed). */
const there = (path: string): boolean => {
  try {
    lstatSync(path)
    return true
  } catch {
    return false
  }
}

/**
 * identity remove <name> --relay <url>... [--to <dir>] [--project <dir>] [--dir <home>]: a terminal first (no-tty
 * before any network), the identity (ENOENT when gone), then refused held (a live MCP server's mcp.lock), window-open,
 * held for a keep job's plist (with the person's bootout line), exists for a --to that is not empty, and EXDEV for one
 * on another file system. Every relay is read (one that does not answer refuses, nothing changed); one question names
 * every change; after the y the relays are read again (stale-record on a change). Prints, in order: per relay
 * `published accept-from <address> <relay>` (any relay that does not take it stops here, before anything local),
 * `untrusted <root>` or `kept trust <root>: ...`, `forgot <name> <address>`, the unpair line for each other identity
 * that paired with it, the wiring written (--project), the Codex note, `moved <from> -> <to>` per file, and last
 * `removed <name> <address>: <dir>`. An agent identity is not-authorized: it cannot sign the accept-from.
 */
export async function identity(args: readonly string[], io: Io): Promise<number> {
  const [verb, ...rest] = args
  if (verb === 'relays') return setRelays(rest, io)
  if (verb === 'keep-alive') return keepAlive(rest, io)
  if (verb === 'custody') return identityCustody(rest, io)
  if (verb !== 'remove') throw new UsageError(`${USAGE} | ${IDENTITY_CUSTODY_USAGE}`)
  const options = { relay: { ...S, multiple: true }, to: S, project: S, dir: S }
  const p = parse(rest, { positionals: ['name'], options, required: ['relay'] })
  const name = p.positionals[0] as string
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  if (relays.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  needTty(io, 'identity remove')
  const home = resolve(homeDir(io, str(p, 'dir')))
  checkIdentity(io, home, name)
  const keys = loadKeys(io, home, name)
  const agent = keys.signing.address
  const custody = homeCustody(io, home)
  // A refused local pair table (q3): the remove changes nothing, and says how to fix the file.
  needPairsTable(home)
  const twin = custody.list().find((e) => e.name !== name && e.address === agent)
  if (twin !== undefined) {
    throw new CliError(
      'exists',
      `${twin.name} of ${home} is ${agent} too (${twin.custody}): take it out first`,
    )
  }
  refuseWhileHeld(home, name, 'identity remove')
  await checkNoWindow(io, home, agent)
  const plist = join(io.env.HOME ?? '', 'Library', 'LaunchAgents', `bag.keep.${name}.plist`)
  if (io.env.HOME && existsSync(plist)) {
    const uid = process.getuid?.() ?? '<uid>'
    throw new CliError(
      'held',
      `the keep job of ${name} is set up (${plist}): stop it first, in a terminal: ` +
        `launchctl bootout gui/${uid}/bag.keep.${name} && mv ${shq(plist)} ~/.Trash/`,
    )
  }
  const stamp = new Date(io.clock.now() * 1000)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
  // A run again after a failed move continues into that run's folder: one that moved files but not yet the key, which
  // moves last. Only with no --to: a --to named by the person is never chosen for them.
  const keyDirOf = custody.entry(name).custody === 'keychain' ? 'keychain' : 'keys'
  const partial =
    str(p, 'to') === undefined
      ? partialLeft(dirname(home), name, join('home', keyDirOf, `${name}.json`))
      : null
  const to = resolve(str(p, 'to') ?? partial ?? join(dirname(home), `bag-left-${name}-${stamp}`))
  if (to !== partial && existsSync(to) && readdirSync(to).length > 0)
    throw new CliError('exists', `${to} is not empty: name another --to`)
  let near = to
  while (!existsSync(near)) near = dirname(near)
  if (statSync(near).dev !== statSync(home).dev) {
    throw new CliError(
      'EXDEV',
      `${to} is on another file system than ${home}: files move, never copy; name another --to`,
    )
  }
  const project = str(p, 'project')
  const dir = project === undefined ? null : resolve(project)
  if (dir !== null && !existsSync(dir)) throw new CliError('ENOENT', `no project directory ${dir}`)
  const wiring = dir === null ? null : wiringOf(home, name, dir)
  const codexFile = join(io.env.HOME ?? '', '.codex', 'config.toml')
  const codex = io.env.HOME && existsSync(codexFile) ? readFileSync(codexFile, 'utf8').replace(/\s/g, '') : ''
  const codexNote = codex.includes(`"--principal","${name}"`)
    ? `${codexFile} runs bag for ${name} ([mcp_servers.bag], --principal ${name}): bag never edits it; take that ` +
      `table out, and the Stop hook of ${name} in ${join(io.env.HOME ?? '', '.codex', 'hooks.json')}`
    : null

  const client = io.relay({})
  const read = (): Promise<(AcceptFromRecord | null)[]> =>
    Promise.all(
      relays.map((url) =>
        newestAccept(client, [url], agent).catch((e: unknown) => {
          if (!(e instanceof RelayError)) throw e
          const why = `${url} did not answer: nothing was changed; run identity remove again once it does`
          throw new CliError(failed(e), `${why}, or without that --relay`)
        }),
      ),
    )
  const held = await read()
  const newest = held.filter((r) => r !== null).sort((a, b) => b.iat - a.iat)[0] ?? null
  // The roots: the newest record's and the home copy's (a run after a relay refused the re-sign reads the copy's).
  const named = [...(newest?.roots ?? []), ...(acceptCopy(home, name, agent)?.roots ?? [])]
  const trust = readTrust(home)
  const roots = [...new Set(named)].filter(
    (r) => r !== agent && r !== WILDCARD_ROOT && isTrustRoot(r) && Object.hasOwn(trust, r),
  )
  const keptFor = new Map(roots.map((r) => [r, heldBy(home, name, agent, r)]))
  const leave = roots.filter((r) => keptFor.get(r)?.length === 0)
  const book = NameBook.load(home)
  const forget = book
    .list()
    .filter(([, e]) => e.address === agent)
    .map(([n]) => n)
  const keyDir = keyDirOf
  const moves = [
    join('state', name),
    join('records', `${name}.address.json`),
    join('records', `${name}.accept.json`),
    join('key-records', toHex(decodeAddress(agent))),
    join('install', `${name}.env`),
    join(keyDir, `${name}.json`), // last: a run again after a failed move still finds the identity
  ].filter((rel) => there(join(home, rel)))
  const relayList = relays.join(' ')
  const locally = custody.list().some((e) => e.address !== agent && pairedLocally(home, agent, e.address))
  const question = [
    `remove ${name} (${agent}) from ${home}:`,
    newest === null
      ? `  no accept-from of ${agent} at ${relayList}: nothing to re-sign`
      : `  its accept-from re-signed to name only ${agent}, at ${relayList}`,
    `  trust.json: ${leave.length === 0 ? 'no root leaves' : `${leave.join(' ')} leave`}`,
    ...roots
      .filter((r) => !leave.includes(r))
      .map((r) => `  trust.json keeps ${r} for ${keptFor.get(r)?.join(', ')}`),
    ...(forget.length === 0 ? [] : [`  names.json forgets ${forget.join(' ')}`]),
    ...(locally ? ['  run/local-peers.json: its local pairs leave'] : []),
    `  moved into ${to}: ${moves.map((m) => join('home', m)).join(' ')}`,
    ...(wiring?.lines.map((l) => `  ${l}`) ?? []),
    ...(codexNote === null ? [] : [`  ${codexNote}`]),
    `remove ${name}?`,
  ].join('\n')
  await confirmed(io, question, 'nothing was changed')
  const after = await read()
  if (after.some((r, i) => r?.iat !== held[i]?.iat)) {
    throw new CliError(
      'stale-record',
      `the accept-from of ${agent} changed while asking; nothing was changed: run identity remove again`,
    )
  }

  if (newest !== null) {
    const iat = Math.max(io.clock.now(), newest.iat + 1)
    const record = signRecord(keys.signing, {
      kind: 'accept-from',
      owner: agent,
      roots: [agent],
      max_bytes: liftMaxBytes(newest.max_bytes),
      ttl: newest.ttl,
      iat,
    })
    let failure: CliError | null = null
    for (const url of relays) {
      try {
        await client.publish(url, serializeRecord(record))
        io.out(`published accept-from ${agent} ${url}`)
      } catch (e) {
        const code = failed(e)
        io.out(`${code === 'stale-record' ? 'unchanged' : 'failed'} accept-from ${agent} ${url} ${code}`)
        const why = `${url} did not take the accept-from of iat ${iat}, which names only ${agent}`
        failure ??= new CliError(code, `${why}: nothing else was changed; run identity remove again`)
      }
    }
    if (failure !== null) throw failure
  } else io.out(`no accept-from of ${agent} at ${relayList}: nothing to re-sign`)
  for (const r of roots) {
    const others = keptFor.get(r) ?? []
    if (others.length > 0) io.out(`kept trust ${r}: the accept-from of ${others.join(', ')} still names it`)
    else io.out(`${removeTrust(home, r) ? 'untrusted' : 'not trusted'} ${r}`)
  }
  for (const n of forget) {
    book.forget(n)
    io.out(`forgot ${n} ${agent}`)
  }
  if (forget.length > 0) book.save()
  // Its local pairs (spec/SPEC.md 9.2); its spool moves with state/<name>.
  if (dropLocalPairs(home, (q) => q.a_addr === agent || q.b_addr === agent) > 0)
    io.out(`dropped the local pairs of ${name}`)
  const flags = relays.map((r) => `--relay ${r}`).join(' ')
  for (const other of heldBy(home, name, agent, agent)) {
    io.out(
      `${other} accepts ${agent}: to end that, run on a terminal: bag unpair ${agent} --as ${other} ${flags}`,
    )
  }
  const wrote: string[] = []
  wiring?.apply(wrote)
  for (const line of wrote) io.out(line)
  if (codexNote !== null) io.out(codexNote)
  mkdirSync(to, { recursive: true, mode: 0o700 })
  for (const rel of moves) {
    const dest = join(to, 'home', rel)
    mkdirSync(dirname(dest), { recursive: true, mode: 0o700 })
    renameSync(join(home, rel), dest)
    io.out(`moved ${join(home, rel)} -> ${dest}`)
  }
  if (keyDir === 'keychain') {
    io.out(
      `the keychain item of ${name} stays in the macOS keychain; to delete it: security delete-generic-password -s bag:${name} -a ${agent}`,
    )
  }
  io.out(`removed ${name} ${agent}: ${to}`)
  if (keyDir === 'keys') {
    io.out(
      `${to} holds the private key of ${name}: this is not a revocation, and moving the files back undoes it; to end ` +
        `${name} for good, delete that folder yourself`,
    )
  }
  return 0
}

/** The newest bag-left-<name>-* folder in `parent` that holds moved files but not `key` (relative): a partial move. */
function partialLeft(parent: string, name: string, key: string): string | null {
  let entries: string[]
  try {
    entries = readdirSync(parent)
  } catch {
    return null
  }
  const found = entries
    .filter((e) => e.startsWith(`bag-left-${name}-`))
    .sort()
    .reverse()
    .map((e) => join(parent, e))
    .find((d) => existsSync(join(d, 'home')) && !existsSync(join(d, key)))
  return found === undefined ? null : resolve(found)
}

/**
 * identity relays <name> --relay <url>... [--dir <home>]: the relays of a bag service identity, its entry in
 * <home>/identities.json (the service's file), set to the --relay list after one y at a terminal. Beside a running
 * service the CLI borrows the identity first (service.ts), and the service reopens it with the new list. Prints
 * `relays <name> <url>...` and the record keep line that publishes its records at each of them.
 */
async function setRelays(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: { relay: { ...S, multiple: true }, dir: S },
    required: ['relay'],
  })
  const name = p.positionals[0] as string
  const next = [...new Set(list(p, 'relay').map(relayUrl))]
  if (next.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  needTty(io, 'identity relays')
  const home = resolve(homeDir(io, str(p, 'dir')))
  const file = join(home, 'identities.json')
  const doc = existsSync(file) ? readIdentities(file, true) : null
  const e = doc?.identities.find((x) => x.label === name)
  const done = (): number => {
    io.out(`relays ${name} ${next.join(' ')}`)
    io.out(
      `publish its records at each: bag record keep --once --as ${name} ${next.map((r) => `--relay ${r}`).join(' ')}`,
    )
    return 0
  }
  if (doc === null || e === undefined) {
    // A name the service's file lacks (a reused identity no folder wired, or a home with no file yet): added, on the y.
    checkIdentity(io, home, name)
    await confirmed(io, `add ${name} to ${file} with the relays ${next.join(' ')}?`, 'nothing was changed')
    addToServiceHome(home, name, next)
    return done()
  }
  if (e.relays.join(' ') === next.join(' ')) {
    io.out(`relays ${name} ${next.join(' ')} (unchanged)`)
    return 0
  }
  await confirmed(
    io,
    `set the relays of ${name} in ${file}: ${e.relays.join(' ')} -> ${next.join(' ')}?`,
    'nothing was changed',
  )
  saveIdentities(file, {
    ...doc,
    identities: doc.identities.map((x) => (x === e ? { ...x, relays: next } : x)),
  })
  return done()
}

/**
 * identity keep-alive on|off|default <name> [--dir <home>]: the person's word on whether the bag service keeps the
 * identity's records alive, written by the edge's setKeepAlive into the service's table (<home>/run/keep-alive.json,
 * its lock; this command never writes the file itself): on and off hold until changed; default leaves it to the
 * service's rule. Typed at a terminal (no-tty otherwise); prints `keep-alive <name> on|off|default`.
 */
function keepAlive(args: readonly string[], io: Io): number {
  const p = parse(args, { positionals: ['word', 'name'], options: { dir: S } })
  const [word, name] = p.positionals as [string, string]
  const keep = ({ on: true, off: false, default: null } as Record<string, boolean | null>)[word]
  if (keep === undefined)
    throw new UsageError(`keep-alive takes on, off or default, not ${JSON.stringify(word)}`)
  needTty(io, 'identity keep-alive')
  const home = resolve(homeDir(io, str(p, 'dir')))
  // The table is keyed by the service's label (identities.json); <name> is that label, or the key name of an entry.
  const file = join(home, 'identities.json')
  const list = existsSync(file) ? readIdentities(file, true).identities : []
  const e = list.find((x) => x.label === name) ?? list.find((x) => (x.key ?? x.label) === name)
  checkIdentity(io, home, e === undefined ? name : (e.key ?? e.label))
  const label = e?.label ?? name
  setKeepAlive(home, label, keep)
  io.out(`keep-alive ${label} ${word}`)
  return 0
}
