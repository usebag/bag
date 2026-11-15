import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { parseEnvelope } from '@usebag/core'
import { Audit, acquireLock, FsAuditSink, LOCAL_RELAY, SqliteStore, storeLockPath } from '@usebag/edge'
import { readIdentities } from './identities.ts'
import { homeCustody } from './keys.ts'
import { HomeError, type HomeIo } from './ports.ts'
import { RESERVED } from './service-home.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2): the home word, <home>/run/local.json {"version": 2,
// "local_delivery", "hidden": [label]}, default on with no file, and the bag service's table of local pairs,
// <home>/run/local-peers.json, with the mail a pair holds. The service's own reader is packages/mcp/src/local.ts; the
// file shapes are repeated here, read the way it reads them.

/** The home word's file. */
export const wordPath = (home: string): string => join(home, 'run', 'local.json')
/** The local pairs' table. */
export const peersPath = (home: string): string => join(home, 'run', 'local-peers.json')

/** Writes `body` at `file`, 0600, in a 0700 run directory: a temporary file beside it, renamed over it. */
export function writeWhole(home: string, file: string, body: unknown): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, `${JSON.stringify(body)}\n`, { mode: 0o600 })
  renameSync(tmp, file)
}

/** One pair of the service's local table. */
export interface Pair {
  readonly a: string
  readonly b: string
  readonly a_addr: string
  readonly b_addr: string
  /** The envelope ids a requested pair holds for b (the service's LocalPair.held); any other entry is skipped. */
  readonly held?: readonly unknown[]
}

/**
 * Why run/local-peers.json is refused, by the bag service's own file check (packages/mcp/src/local.ts pairsRefused):
 * not a 0600 regular file of this user (a symlink included); null when absent or fine. A refused table is never read
 * or written here.
 */
export function pairsRefused(home: string): string | null {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(peersPath(home))
  } catch {
    return null
  }
  return !st.isFile() || st.uid !== (process.getuid?.() ?? st.uid) || (st.mode & 0o777) !== 0o600
    ? 'run/local-peers.json is not a 0600 regular file of this user'
    : null
}

/** Throws unsafe-path while the table is refused: the act changes nothing, and says how to fix it. */
export function needPairsTable(home: string): void {
  const why = pairsRefused(home)
  if (why !== null)
    throw new HomeError(
      'unsafe-path',
      `${why}: nothing was changed; to fix it: chmod 600 ${peersPath(home)}, or put a regular file of yours there ` +
        'in place of a link',
    )
}

/** A row of the table's shape, as the bag service's isPair checks it (packages/mcp/src/local.ts): else skipped. */
const isPair = (p: unknown): p is Pair => {
  const v = p as Record<string, unknown> | null
  return (
    typeof v === 'object' &&
    v !== null &&
    ['a', 'b', 'a_addr', 'b_addr'].every((k) => typeof v[k] === 'string') &&
    typeof v.added_at === 'number'
  )
}

/** The table's pairs; an absent, unreadable or refused file holds none, and a malformed row is skipped. */
export function pairs(home: string): Pair[] {
  if (pairsRefused(home) !== null) return []
  try {
    const v = JSON.parse(readFileSync(peersPath(home), 'utf8')) as { version?: unknown; pairs?: unknown }
    // A null or malformed entry is skipped, never a throw.
    return v.version === 1 && Array.isArray(v.pairs) ? v.pairs.filter(isPair) : []
  } catch {
    return []
  }
}

/** The home word as the service reads it (readWord: absent is LOCAL_DELIVERY_DEFAULT, a refused file is off). */
export function localDeliveryOn(home: string): boolean {
  return readWord(home).on
}

/** How many envelopes wait in an identity's spool, <home>/state/<name>/local-spool/<64 hex>.env (as mcp spooled). */
export function spooledCount(home: string, name: string): number {
  try {
    return readdirSync(join(home, 'state', name, 'local-spool')).filter((f) => /^[0-9a-f]{64}\.env$/.test(f))
      .length
  } catch {
    return 0
  }
}

/**
 * The pairs of the table `drop` names, taken out of it; the rest are written back whole, each row as read (parsed and
 * written again unchanged, so the running service's check of rows it did not write keeps them). The count taken. A
 * refused table is never rewritten (needPairsTable first). A dropped pair's spooled mail (spooledOf) can never be
 * delivered: each envelope is failed to its sender in the sender's own audit log, as the bag service fails one
 * (failHeldToSender, reason unpaired), and deleted, as the service's own drop deletes it. A sender whose store is in use
 * refuses held before the table is written, so nothing is changed.
 */
export function dropLocalPairs(
  home: string,
  drop: (p: Pair) => boolean,
  now: () => number = () => Math.floor(Date.now() / 1000),
): number {
  needPairsTable(home)
  const all = pairs(home)
  const gone = all.filter((p) => drop(p))
  const mail = spooledOf(home, gone)
  for (const m of mail) {
    const busy = m.sender === null ? null : senderBusy(home, m.sender)
    if (busy !== null)
      throw new HomeError(
        'held',
        `${m.sender} has local mail spooled for ${m.to}, and its store is in use (${busy}): nothing was changed; ` +
          'run it again once that command has ended',
      )
  }
  if (gone.length > 0)
    writeWhole(home, peersPath(home), { version: 1, pairs: all.filter((p) => !gone.includes(p)) })
  for (const m of mail) {
    failHeldToSender(home, m, 'unpaired', now)
    rmSync(m.file, { force: true })
  }
  return gone.length
}

/**
 * The spooled mail of `rows` (envelopes waiting in a spool, <home>/state/<key name>/local-spool/<id>.env, not held):
 * for each side of a row that is an identity of this home, each envelope its spool holds from the other side's
 * address. Its sender is the other side's key name, when that side is an identity of this home too. A file that does
 * not parse as an envelope is no one's mail and stays.
 */
export function spooledOf(home: string, rows: readonly Pair[]): HeldMail[] {
  let own: readonly { readonly name: string; readonly address: string }[] = []
  try {
    own = homeCustody(undefined, home).list()
  } catch {}
  const nameOf = (address: string): string | null => own.find((o) => o.address === address)?.name ?? null
  const found: HeldMail[] = []
  for (const r of rows)
    for (const [to, at, from] of [
      [r.a, r.a_addr, r.b_addr],
      [r.b, r.b_addr, r.a_addr],
    ] as const) {
      const name = nameOf(at)
      if (name === null) continue
      const dir = join(home, 'state', name, 'local-spool')
      let files: string[] = []
      try {
        files = readdirSync(dir).filter((f) => /^[0-9a-f]{64}\.env$/.test(f))
      } catch {}
      for (const f of files.sort()) {
        const file = join(dir, f)
        try {
          if (!lstatSync(file).isFile() || parseEnvelope(new Uint8Array(readFileSync(file))).from !== from)
            continue
        } catch {
          continue
        }
        const sender = nameOf(from)
        found.push({ id: f.slice(0, 64), file, in: name, other: sender ?? name, sender, from, to })
      }
    }
  return found
}

/** Whether `x` and `y` (addresses) are a local pair of the table. */
export function pairedLocally(home: string, x: string, y: string): boolean {
  return pairs(home).some((p) => (p.a_addr === x && p.b_addr === y) || (p.a_addr === y && p.b_addr === x))
}

/**
 * Local delivery with no word file is on (spec/SPEC.md 9.2): the bag service's LOCAL_DELIVERY_DEFAULT, kept equal by a
 * test.
 */
export const LOCAL_DELIVERY_DEFAULT = true

/**
 * The word file as the bag service reads it (packages/mcp/src/local.ts localWord): absent, the default with none
 * hidden; a file that is not a 0600 regular file of this user, or does not read as version 1 or 2, is off, with why.
 */
export function readWord(home: string): { on: boolean; hidden: string[]; why: string | null } {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(wordPath(home))
  } catch {
    return { on: LOCAL_DELIVERY_DEFAULT, hidden: [], why: null }
  }
  if (!st.isFile() || st.uid !== (process.getuid?.() ?? st.uid) || (st.mode & 0o777) !== 0o600)
    return { on: false, hidden: [], why: 'run/local.json is not a 0600 regular file of this user' }
  try {
    const v = JSON.parse(readFileSync(wordPath(home), 'utf8')) as Record<string, unknown>
    if (v.version !== 1 && v.version !== 2) throw new Error('version')
    const hidden =
      v.version === 2 && Array.isArray(v.hidden) ? v.hidden.filter((h) => typeof h === 'string') : []
    return { on: v.local_delivery === 'on', hidden, why: null }
  } catch {
    return { on: false, hidden: [], why: 'run/local.json does not read' }
  }
}

/** The line keygen prints with the word on. */
export const visibleLine = (name: string): string =>
  `${name} is visible to your other identities on this machine; to keep it apart: bag local-delivery hide ${name}`

/** The home's identities by key name, for the on question: every one it joins. */
export function identitiesOf(home: string): string[] {
  try {
    return readdirSync(join(home, 'keys'))
      .concat(existsSync(join(home, 'keychain')) ? readdirSync(join(home, 'keychain')) : [])
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.slice(0, -'.json'.length))
      .sort()
  } catch {
    return []
  }
}

/**
 * The labels hide and show take, by every name that may be given for one: the hidden list holds the bag service's
 * labels (packages/mcp/src/local.ts localRootsOf), so a name is mapped to its label. An entry of the service's own
 * file, <home>/identities.json, is named by its label or its key name and maps to its label; an identity on disk (key
 * file, Keychain or agent pointer, as checkIdentity reads them) that no entry keys is its own label. The service's own
 * key files (RESERVED: <label>.service.json and the like) are no identity. A file that does not read adds no entry.
 */
export function labelsByName(home: string): Map<string, string> {
  const onDisk = ['keys', 'keychain', 'agent'].flatMap((d) => {
    try {
      return readdirSync(join(home, d))
        .filter((f) => f.endsWith('.json'))
        .map((f) => f.slice(0, -'.json'.length))
        .filter((n) => !RESERVED.some((x) => n.endsWith(x)))
    } catch {
      return []
    }
  })
  let entries: readonly { readonly label: string; readonly key?: string }[] = []
  try {
    entries = readIdentities(join(home, 'identities.json'), true).identities
  } catch {}
  const by = new Map<string, string>()
  for (const n of onDisk) by.set(n, n)
  for (const e of entries) by.set(e.key ?? e.label, e.label)
  for (const e of entries) by.set(e.label, e.label)
  return by
}

/** One envelope a pair of the table holds, as identity remove finds it on disk. */
export interface HeldMail {
  readonly id: string
  /** The held file: <home>/state/<key name>/local-spool/held/<id>.env, a regular file. */
  readonly file: string
  /** The key name whose spool holds it. */
  readonly in: string
  /** The other side's key name: where the bag service also looks for it (its #dropRemoved reads both sides). */
  readonly other: string
  /** Its sender's key name, an identity of this home other than the one removed; null when none (gone or unread). */
  readonly sender: string | null
  readonly from: string | null
  /** The row's b, the label it was held for (the service's failed-local `to`). */
  readonly to: string
}

const HELD = /^[0-9a-f]{64}$/

/**
 * The held mail of the local pairs naming `address` (identity remove): for each row naming it, each envelope id of
 * its held list (envelope ids only, as the service's cleanHeld keeps them), found as a regular file in either side's
 * spool held/ (the key name of a label: `keyOf`). Its sender is the home identity (`own`: key name and address) whose
 * address is the envelope's from, other than `address`. A refused table holds none.
 */
export function heldMailOf(
  home: string,
  address: string,
  keyOf: (label: string) => string,
  own: readonly { readonly name: string; readonly address: string }[],
): HeldMail[] {
  const found: HeldMail[] = []
  for (const r of pairs(home).filter((p) => p.a_addr === address || p.b_addr === address)) {
    const ids = (Array.isArray(r.held) ? r.held : []).filter(
      (x): x is string => typeof x === 'string' && HELD.test(x),
    )
    const [ka, kb] = [keyOf(r.a), keyOf(r.b)]
    for (const id of ids)
      for (const [k, other] of [
        [ka, kb],
        [kb, ka],
      ] as const) {
        const file = join(home, 'state', k, 'local-spool', 'held', `${id}.env`)
        let from: string | null = null
        try {
          if (!lstatSync(file).isFile()) continue
          from = parseEnvelope(new Uint8Array(readFileSync(file))).from
        } catch (e) {
          if ((e as { code?: unknown }).code === 'ENOENT') continue
        }
        const sender = own.find((o) => o.address === from && o.address !== address)?.name ?? null
        found.push({ id, file, in: k, other, sender, from, to: r.b })
      }
  }
  return found
}

/**
 * Why `sender`'s store cannot take its writer now (its writer lock held by a live edge or another CLI command for it),
 * else null: the lock taken and given back at once, nothing left behind; a sender with no state folder has no writer.
 * identity remove asks it of each sender before its question, so a busy store refuses with nothing changed rather than
 * stopping the remove after the relays did (F3).
 */
export function senderBusy(home: string, sender: string): string | null {
  const dir = join(home, 'state', sender)
  if (!existsSync(dir)) return null
  try {
    acquireLock(storeLockPath(join(dir, 'edge.sqlite')))()
    return null
  } catch (e) {
    return String((e as Error).message ?? e)
  }
}

/**
 * Fails one held envelope to its sender as the bag service does (#failedLocal): the line publish reject {relay
 * local:, delivery failed-local, reason, to} in the sender's own audit.jsonl, which status(id) reads. Opened as the edge
 * opens it: its store's writer lock first (busy while a live edge holds the identity, so no second writer forks the
 * chain), then the log checked against its anchor and the anchor put after the line.
 */
export function failHeldToSender(home: string, m: HeldMail, reason: string, now: () => number): void {
  if (m.sender === null) return
  const dir = join(home, 'state', m.sender)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const store = new SqliteStore(join(dir, 'edge.sqlite'))
  try {
    const sink = new FsAuditSink(join(dir, 'audit.jsonl'))
    const log = sink.name
    const clock = { now }
    const audit = new Audit(sink, clock, {
      get: () => store.auditAnchorGet(log),
      put: (anchor) => store.auditAnchorPut(log, anchor, now()),
      others: () => store.auditAnchors().filter((a) => a.name !== log),
    })
    const detail = { relay: LOCAL_RELAY, delivery: 'failed-local', reason, to: m.to }
    audit.record({ event: 'publish', decision: 'reject', id: m.id, from: m.from, detail })
  } finally {
    store.close()
  }
}

/** What local-delivery sets: the home word on or off, or one identity hidden or shown. */
export type LocalWord = 'on' | 'off' | 'hide' | 'show'

/** The on question: every identity it joins, what it means, and how to keep one apart. */
export function localOnQuestion(home: string, hidden: readonly string[]): string {
  const all = identitiesOf(home).filter((n) => !hidden.includes(n))
  return [
    `let ${all.length === 0 ? "this home's identities" : all.join(', ')}, and any identity you add later, find and`,
    '  message each other on this machine? Messages stay here and never go to a relay. A message from one of your',
    "  identities still reaches the other's model as mail it may act on, so keep apart any identity that should",
    '  not hear from the others (bag local-delivery hide <name>). On Codex and omp a command your agent runs can',
    '  change this setting; bag tells every window when it does.',
  ].join('\n')
}

/**
 * local-delivery: writes only run/local.json, version 2, keeping the other half. off (the brake) and hide only reduce
 * reach: no question. on and show add reach: one yes. hide and show name an identity of the home, by its label or key
 * name, and write its label: any other name is ENOENT before anything is written, so no hidden row is ever written for
 * a non-identity, nor a key name the service would not read as its label. The one exception: show of a name already
 * hidden takes it out (after the same yes), as it adds no reach, so an old stray row can still be cleaned. Warns when
 * the word file read as off; says `hidden <label>: <file>`, `shown <label>: <file>` or `local_delivery <word>: <file>`.
 * With `askEvery` (a window, where no terminal shows that a person typed it) off and hide ask too.
 */
export async function setLocalDelivery(
  io: HomeIo,
  home: string,
  word: LocalWord,
  name?: string,
  o: { readonly askEvery?: boolean } = {},
): Promise<void> {
  const named = word === 'hide' || word === 'show'
  const file = wordPath(home)
  const w = readWord(home)
  const by = labelsByName(home)
  const label = name === undefined ? undefined : (by.get(name) ?? name)
  if (named && !by.has(name as string) && !(word === 'show' && w.hidden.includes(name as string))) {
    const labels = [...new Set(by.values())].sort()
    throw new HomeError(
      'ENOENT',
      `no identity ${name} in ${home}: nothing was changed; ${word} takes one of: ` +
        (labels.length === 0 ? 'none, this home has no identity' : labels.join(', ')),
    )
  }
  if (w.why !== null) io.warn(`local-delivery: ${w.why}, so it reads as off; this writes it whole`)
  const question =
    word === 'on'
      ? localOnQuestion(home, w.hidden)
      : word === 'show'
        ? `show ${label} to this home's other identities again? They can then message it on this machine.`
        : o.askEvery !== true
          ? null
          : word === 'off'
            ? "turn local delivery off? This home's identities stop finding and messaging each other on this machine."
            : `hide ${label} from this home's other identities? It then sees none of them, and none of them reaches it.`
  if (question !== null && !(await io.ask(question))) throw new HomeError('declined', 'nothing was changed')
  // show takes out the label and the name as given (a stray key name written before this check).
  const rest = w.hidden.filter((h) => h !== label && h !== name)
  const hidden = word === 'hide' ? [...rest, label as string] : word === 'show' ? rest : w.hidden
  const on = word === 'on' ? true : word === 'off' ? false : w.on
  writeWhole(home, file, {
    version: 2,
    local_delivery: on ? 'on' : 'off',
    hidden: [...new Set(hidden)].sort(),
  })
  io.say(
    named ? `${word === 'hide' ? 'hidden' : 'shown'} ${label}: ${file}` : `local_delivery ${word}: ${file}`,
  )
}
