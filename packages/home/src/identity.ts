import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import {
  type AcceptFromRecord,
  decodeAddress,
  serializeRecord,
  signRecord,
  toHex,
  WILDCARD_ROOT,
} from '@usebag/core'
import { acceptCopy, liftMaxBytes, RelayError, setKeepAlive } from '@usebag/edge'
import { namedStates, shortName, stateOf } from './check.ts'
import { describeHolder, holder, refuseWhileHeld } from './held.ts'
import { shq } from './host-common.ts'
import { removeOmp } from './host-install.ts'
import { type Identities, type Identity, readIdentities, saveIdentities } from './identities.ts'
import { checkIdentity, checkNoWindow, homeCustody, loadKeys } from './keys.ts'
import {
  dropLocalPairs,
  failHeldToSender,
  heldMailOf,
  needPairsTable,
  pairedLocally,
  peersPath,
  senderBusy,
} from './local.ts'
import { NameBook } from './names.ts'
import { askWithRecheck, changedWhileAsked, HomeError, type HomeIo } from './ports.ts'
import { newestAccept } from './records.ts'
import { recordRemoved, removedRefusal, removedRefused } from './removed.ts'
import { addToServiceHome } from './service-home.ts'
import { isTrustRoot, readTrust, removeTrust } from './trust.ts'
import { custodyFiles, failed, heldBy } from './unpair.ts'

// identity remove, relays and keep-alive: the acts on one identity of a home, each a person's act. remove takes one
// identity out of a home that may keep others, after one yes. Nothing is deleted: the identity's files move into one
// folder. The accept-from is re-signed to name only its owner at every relay first (as unpair's last root), and only
// once every relay took it does anything local change, so a run again finds the keys still here. trust.json loses
// the roots of this identity's accept-from that no other identity's copy still names (heldBy); names.json forgets
// the names of its address.

type Json = Record<string, unknown>

const declined = (): HomeError => new HomeError('declined', 'nothing was changed')

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
  throw new HomeError('host-file-invalid', `${file} is not a JSON object`)
}

const writeJson = (file: string, doc: Json): void => writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`)

/** The host files of project `dir` that the wiring of an identity is read from. */
const wiringFiles = (dir: string): string[] => [
  join(dir, '.omp', 'mcp.json'),
  join(dir, '.mcp.json'),
  join(dir, '.claude', 'settings.json'),
]

/** The wiring of `name` in project `dir`: what the question names, and the change, made after the yes. */
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

/** What identity remove takes. */
export interface RemoveInput {
  /** The home, resolved. */
  readonly home: string
  readonly name: string
  /** The relays its accept-from is read and re-signed at, each a checked URL. */
  readonly relays: readonly string[]
  /** The folder its files move into; by default bag-left-<name>-<stamp> beside the home. */
  readonly to?: string
  /** A project folder whose host wiring of the identity comes out with it. */
  readonly project?: string
  /** Whether a bag service of this home holds `name` lent to this act, and fails its held mail when given it back. */
  readonly lent: (home: string, name: string) => Promise<boolean>
  /**
   * Whether `lent` is asked again after the yes when the identity has held mail, refusing busy (naming the service)
   * when the answer changed, so the held mail goes the way the question said. Off by default: each ask is a lend and
   * a return at the service.
   */
  readonly lentAgain?: boolean
  /**
   * The bag service's own word, for a remove it runs as a window's tool: whether the lock on `name` (its key name) is
   * accounted for by the service's own quiet or lease of that label (refuseWhileHeld), before the question and again
   * after the Yes, under the quiet. Absent for the CLI: any live holder refuses held.
   */
  readonly heldByOwnQuiet?: (name: string) => boolean
  /** Told the count of held local mail the act fails (or leaves to the service), just before its question. */
  readonly heldMail?: (count: number) => void
}

/**
 * Removes the identity `name` from its home. Refuses, changing nothing: ENOENT when gone, held while a live MCP server
 * holds it, window-open, held for a keep job's plist (with the bootout line), exists for a `to` that is not empty, and
 * EXDEV for one on another file system. Every relay is read (one that does not answer refuses, nothing changed); one
 * question names every change; after the yes the relays are read again (stale-record on a change). Says, in order:
 * per relay `published accept-from <address> <relay>` (any relay that does not take it stops here, before anything
 * local), `untrusted <root>` or `kept trust <root>: ...`, `forgot <name> <address>`, the unpair line for each other
 * identity that paired with it, the wiring written, the Codex note, `moved <from> -> <to>` per file, and last
 * `removed <name> <address>: <dir>`. An agent identity is not-authorized: it cannot sign the accept-from.
 */
export async function identityRemove(io: HomeIo, input: RemoveInput): Promise<void> {
  const { home, name, relays } = input
  checkIdentity(io.security, home, name)
  const keys = loadKeys(io.security, home, name)
  const agent = keys.signing.address
  const custody = homeCustody(io.security, home)
  // A refused local pair table: the remove changes nothing, and says how to fix the file.
  needPairsTable(home)
  const twin = custody.list().find((e) => e.name !== name && e.address === agent)
  if (twin !== undefined) {
    throw new HomeError(
      'exists',
      `${twin.name} of ${home} is ${agent} too (${twin.custody}): take it out first`,
    )
  }
  refuseWhileHeld(home, name, 'identity remove', input.heldByOwnQuiet)
  await checkNoWindow(io.security, home, agent)
  const plist = join(io.env.HOME ?? '', 'Library', 'LaunchAgents', `bag.keep.${name}.plist`)
  if (io.env.HOME && existsSync(plist)) {
    const uid = process.getuid?.() ?? '<uid>'
    throw new HomeError(
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
  // moves last. Only with no `to`: a folder named by the person is never chosen for them.
  const keyDirOf = custody.entry(name).custody === 'keychain' ? 'keychain' : 'keys'
  const partialOf = (): string | null =>
    input.to === undefined ? partialLeft(dirname(home), name, join('home', keyDirOf, `${name}.json`)) : null
  const partial = partialOf()
  const to = resolve(input.to ?? partial ?? join(dirname(home), `bag-left-${name}-${stamp}`))
  if (to !== partial && existsSync(to) && readdirSync(to).length > 0)
    throw new HomeError('exists', `${to} is not empty: name another --to`)
  let near = to
  while (!existsSync(near)) near = dirname(near)
  if (statSync(near).dev !== statSync(home).dev) {
    throw new HomeError(
      'EXDEV',
      `${to} is on another file system than ${home}: files move, never copy; name another --to`,
    )
  }
  const dir = input.project === undefined ? null : resolve(input.project)
  if (dir !== null && !existsSync(dir)) throw new HomeError('ENOENT', `no project directory ${dir}`)
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
          throw new HomeError(failed(e), `${why}, or without that --relay`)
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
  // The bag service's own file: its entry for this identity leaves with it, or the service keeps a unit whose key is
  // gone, and its removal (the held mail failed to the senders) never runs (0.4.1's known limit).
  const service = serviceEntryOf(home, name)
  const lastEntry = service !== null && service.doc.identities.length === 1
  const keyDir = keyDirOf
  const candidates = [
    join('state', name),
    join('records', `${name}.address.json`),
    join('records', `${name}.accept.json`),
    join('key-records', toHex(decodeAddress(agent))),
    join('install', `${name}.env`),
    ...(lastEntry ? ['identities.json'] : []),
    join(keyDir, `${name}.json`), // last: a run again after a failed move still finds the identity
  ]
  const moves = candidates.filter((rel) => there(join(home, rel)))
  const relayList = relays.join(' ')
  const locally = custody.list().some((e) => e.address !== agent && pairedLocally(home, agent, e.address))
  // Its held local mail: a running bag service that lent this identity to this act fails it to the senders at the
  // give-back, its rows left for it; else this act does, in each sender's own audit log.
  const served = await input.lent(home, name)
  // A served remove writes its record: a refused one (removedRefused) stops it here, before the question.
  const refused = served ? removedRefused(home) : null
  if (refused !== null) throw new HomeError('unsafe-path', removedRefusal(home, refused))
  const keyOf = (label: string): string => labelKeys(home).get(label) ?? label
  const mailOf = () => heldMailOf(home, agent, keyOf, custody.list())
  const mail = mailOf()
  if (!served)
    for (const m of mail) {
      const h = m.sender === null ? null : holder(home, m.sender)
      if (h !== null)
        throw new HomeError(
          'held',
          `${m.sender} has local mail held for ${m.to} and is held by a running bag MCP server (${describeHolder(h)}): ` +
            'nothing was changed; close that session first, so its audit log takes the failed line',
        )
      const busy = m.sender === null ? null : senderBusy(home, m.sender)
      if (busy !== null)
        throw new HomeError(
          'held',
          `${m.sender} has local mail held for ${m.to}, and its store is in use (${busy}): nothing was changed; ` +
            'run identity remove again once that command has ended',
        )
    }
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
    ...(service === null ? [] : [`  identities.json: ${service.label} leaves`]),
    ...(mail.length === 0
      ? []
      : [
          served
            ? `  its held local mail (${mail.length}): the bag service fails it to the senders when this command gives ${name} back`
            : `  its held local mail (${mail.length}): failed to the senders, in their audit logs, and deleted`,
        ]),
    `  moved into ${to}: ${moves.map((m) => join('home', m)).join(' ')}`,
    ...(wiring?.lines.map((l) => `  ${l}`) ?? []),
    ...(codexNote === null ? [] : [`  ${codexNote}`]),
    `remove ${name}?`,
  ].join('\n')
  // Everything read above that the writes below rely on, but the relays (read again after the yes) and the store
  // locks (taken again by each write).
  const check = () => ({
    ...namedStates(home, io.env.HOME, [
      ...custodyFiles(home, name),
      peersPath(home),
      join(home, 'trust.json'),
      join(home, 'names.json'),
      join(home, 'identities.json'),
      join(home, 'records', `${name}.accept.json`),
      ...(dir === null ? [] : wiringFiles(dir)),
      ...(io.env.HOME ? [plist, codexFile] : []),
    ]),
    // The service's own lock of it (its unit before the Yes, its quiet after) reads as one value across the quiet.
    holder: input.heldByOwnQuiet?.(name) === true ? 'held by the service for this act' : holder(home, name),
    'bag-left folder': partialOf(),
    ...(to === partial ? {} : { [shortName(to, home, io.env.HOME)]: stateOf(to) }),
    'accept-from copies': roots.map((r) => heldBy(home, name, agent, r)),
    'files to move': candidates.map((rel) => there(join(home, rel))),
    'held mail': mailOf().map((m) => [m.file, m.sender, m.sender === null ? null : holder(home, m.sender)]),
  })
  input.heldMail?.(mail.length)
  if (!(await askWithRecheck(io, question, check))) throw declined()
  refuseWhileHeld(home, name, 'identity remove', input.heldByOwnQuiet)
  if (input.lentAgain === true && mail.length > 0 && (await input.lent(home, name)) !== served)
    throw new HomeError('busy', changedWhileAsked(['service']))
  const after = await read()
  if (after.some((r, i) => r?.iat !== held[i]?.iat)) {
    throw new HomeError(
      'stale-record',
      `the accept-from of ${agent} changed while asking; nothing was changed: run identity remove again`,
    )
  }
  // A served remove leaves its held mail to the service's give-back: the record of it comes first, before anything
  // moves, so a service that dies before the give-back fails that mail at its next start (run/removed.json).
  if (served)
    recordRemoved(home, {
      label: service?.label ?? name,
      key: name,
      address: agent,
      at: Math.floor(io.clock.now()),
    })

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
    let failure: HomeError | null = null
    for (const url of relays) {
      try {
        await client.publish(url, serializeRecord(record))
        io.say(`published accept-from ${agent} ${url}`)
      } catch (e) {
        const code = failed(e)
        io.say(`${code === 'stale-record' ? 'unchanged' : 'failed'} accept-from ${agent} ${url} ${code}`)
        const why = `${url} did not take the accept-from of iat ${iat}, which names only ${agent}`
        failure ??= new HomeError(code, `${why}: nothing else was changed; run identity remove again`)
      }
    }
    if (failure !== null) throw failure
  } else io.say(`no accept-from of ${agent} at ${relayList}: nothing to re-sign`)
  for (const r of roots) {
    const others = keptFor.get(r) ?? []
    if (others.length > 0) io.say(`kept trust ${r}: the accept-from of ${others.join(', ')} still names it`)
    else io.say(`${removeTrust(home, r) ? 'untrusted' : 'not trusted'} ${r}`)
  }
  for (const n of forget) {
    book.forget(n)
    io.say(`forgot ${n} ${agent}`)
  }
  if (forget.length > 0) book.save()
  // Its held local mail first, then its local pairs (spec/SPEC.md 9.2); the rest of its spool moves with state/<name>.
  if (served) {
    // The rows stay for the bag service, which drops them at the give-back and fails their held mail to the senders
    // (it reads both sides' held/): mail held in this identity's own spool moves to the other side's held/ first, as
    // state/<name> leaves the home below.
    for (const m of mail.filter((x) => x.in === name)) {
      const into = join(home, 'state', m.other, 'local-spool', 'held')
      mkdirSync(into, { recursive: true, mode: 0o700 })
      renameSync(m.file, join(into, basename(m.file)))
    }
    if (mail.length > 0)
      io.say(`the bag service tells the senders of its held mail when this command gives ${name} back to it`)
  } else {
    for (const m of mail) {
      try {
        failHeldToSender(home, m, 'identity removed', () => io.clock.now())
      } catch (e) {
        // A writer that took the sender's store since the check before the question: the held files not yet failed
        // and the rows stay, and a run again finishes the remove.
        throw new HomeError(
          'held',
          `${m.sender}'s store was taken by another writer (${String((e as Error).message ?? e)}): the remove stopped ` +
            'before its local pairs and files; run identity remove again to finish it',
        )
      }
      rmSync(m.file, { force: true })
      io.say(m.sender === null ? `dropped held mail ${m.id}` : `failed held mail ${m.id} to ${m.sender}`)
    }
    if (dropLocalPairs(home, (q) => q.a_addr === agent || q.b_addr === agent) > 0)
      io.say(`dropped the local pairs of ${name}`)
  }
  if (service !== null && !lastEntry) {
    const file = join(home, 'identities.json')
    const mode = statSync(file).mode & 0o777
    const { default: kept, ...doc } = service.doc
    const rest = doc.identities.filter((e) => e !== service.entry)
    saveIdentities(file, {
      ...doc,
      ...(kept === undefined || kept === service.label ? {} : { default: kept }),
      identities: rest,
    })
    chmodSync(file, mode)
    io.say(`took ${service.label} out of ${file}`)
  }
  const flags = relays.map((r) => `--relay ${r}`).join(' ')
  for (const other of heldBy(home, name, agent, agent)) {
    io.say(
      `${other} accepts ${agent}: to end that, run on a terminal: bag unpair ${agent} --as ${other} ${flags}`,
    )
  }
  const wrote: string[] = []
  wiring?.apply(wrote)
  for (const line of wrote) io.say(line)
  if (codexNote !== null) io.say(codexNote)
  mkdirSync(to, { recursive: true, mode: 0o700 })
  for (const rel of moves) {
    const dest = join(to, 'home', rel)
    mkdirSync(dirname(dest), { recursive: true, mode: 0o700 })
    renameSync(join(home, rel), dest)
    io.say(`moved ${join(home, rel)} -> ${dest}`)
  }
  if (keyDir === 'keychain') {
    io.say(
      `the keychain item of ${name} stays in the macOS keychain; to delete it: security delete-generic-password -s bag:${name} -a ${agent}`,
    )
  }
  io.say(`removed ${name} ${agent}: ${to}`)
  if (keyDir === 'keys') {
    io.say(
      `${to} holds the private key of ${name}: this is not a revocation, and moving the files back undoes it; to end ` +
        `${name} for good, delete that folder yourself`,
    )
  }
}

/** The bag service's entry of key name `name` in <home>/identities.json, with the file as read; null when none reads. */
function serviceEntryOf(
  home: string,
  name: string,
): { readonly doc: Identities; readonly entry: Identity; readonly label: string } | null {
  const file = join(home, 'identities.json')
  if (!existsSync(file)) return null
  const doc = readIdentities(file, true)
  const entry = doc.identities.find((e) => (e.key ?? e.label) === name)
  return entry === undefined ? null : { doc, entry, label: entry.label }
}

/** The key name of each label of <home>/identities.json (a label not listed is its own key name). */
function labelKeys(home: string): Map<string, string> {
  const file = join(home, 'identities.json')
  try {
    return new Map(readIdentities(file, true).identities.map((e) => [e.label, e.key ?? e.label]))
  } catch {
    return new Map()
  }
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
 * Sets the relays of a bag service identity, its entry in <home>/identities.json (the service's file), to `next`
 * after one yes. A name the file lacks (a reused identity no folder wired, or a home with no file yet) is added, on
 * the yes; the same relays change nothing and ask nothing. Says `relays <name> <url>...` and the record keep line
 * that publishes its records at each of them.
 */
export async function identityRelays(
  io: HomeIo,
  home: string,
  name: string,
  next: readonly string[],
): Promise<void> {
  const file = join(home, 'identities.json')
  const doc = existsSync(file) ? readIdentities(file, true) : null
  const e = doc?.identities.find((x) => x.label === name)
  const done = (): void => {
    io.say(`relays ${name} ${next.join(' ')}`)
    io.say(
      `publish its records at each: bag record keep --once --as ${name} ${next.map((r) => `--relay ${r}`).join(' ')}`,
    )
  }
  const check = () => namedStates(home, io.env.HOME, [file, ...custodyFiles(home, name)])
  if (doc === null || e === undefined) {
    checkIdentity(io.security, home, name)
    if (!(await askWithRecheck(io, `add ${name} to ${file} with the relays ${next.join(' ')}?`, check)))
      throw declined()
    addToServiceHome(home, name, next)
    return done()
  }
  if (e.relays.join(' ') === next.join(' ')) {
    io.say(`relays ${name} ${next.join(' ')} (unchanged)`)
    return
  }
  const question = `set the relays of ${name} in ${file}: ${e.relays.join(' ')} -> ${next.join(' ')}?`
  if (!(await askWithRecheck(io, question, check))) throw declined()
  saveIdentities(file, {
    ...doc,
    identities: doc.identities.map((x) => (x === e ? { ...x, relays: [...next] } : x)),
  })
  done()
}

/**
 * The person's word on whether the bag service keeps the identity's records alive, written by the edge's setKeepAlive
 * into the service's table (<home>/run/keep-alive.json, its lock; never written here directly): true and false hold
 * until changed; null leaves it to the service's rule. `name` is the service's label or the key name of an entry. Says
 * `keep-alive <label> on|off|default` and returns the label.
 */
export function identityKeepAlive(io: HomeIo, home: string, name: string, keep: boolean | null): string {
  // The table is keyed by the service's label (identities.json); <name> is that label, or the key name of an entry.
  const file = join(home, 'identities.json')
  const list = existsSync(file) ? readIdentities(file, true).identities : []
  const e = list.find((x) => x.label === name) ?? list.find((x) => (x.key ?? x.label) === name)
  checkIdentity(io.security, home, e === undefined ? name : (e.key ?? e.label))
  const label = e?.label ?? name
  setKeepAlive(home, label, keep)
  io.say(`keep-alive ${label} ${keep === null ? 'default' : keep ? 'on' : 'off'}`)
  return label
}
