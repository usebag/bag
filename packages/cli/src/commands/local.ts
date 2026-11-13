import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { CliError, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { confirmed, needTty } from '../policy.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2, decisions 98, 103 and 104), the CLI's part. `bag
// local-delivery` writes the home word, <home>/run/local.json {"version": 2, "local_delivery", "hidden": [label]}:
// default on with no file; off and hide at once, on and show on a terminal after one y. The pairs themselves are the
// person's dialog in a host (pair_invite for an own identity), kept by the bag service in run/local-peers.json; unpair
// and identity remove drop an identity's pairs here (M6). The bag service's own reader is packages/mcp/src/local.ts:
// check-imports keeps the CLI off that package, so the file shapes are repeated here.

export const LOCAL_DELIVERY_USAGE = 'local-delivery on|off|hide <name>|show <name> [--dir <home>]'

const wordPath = (home: string): string => join(home, 'run', 'local.json')
const peersPath = (home: string): string => join(home, 'run', 'local-peers.json')

/** Writes `body` at `file`, 0600, in a 0700 run directory: a temporary file beside it, renamed over it. */
function writeWhole(home: string, file: string, body: unknown): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, `${JSON.stringify(body)}\n`, { mode: 0o600 })
  renameSync(tmp, file)
}

/** One pair of the service's local table. */
interface Pair {
  readonly a: string
  readonly b: string
  readonly a_addr: string
  readonly b_addr: string
}

/**
 * Why run/local-peers.json is refused, by the bag service's own file check (packages/mcp/src/local.ts pairsRefused):
 * not a 0600 regular file of this user (a symlink included); null when absent or fine. A refused table is never read
 * or written here (item q3).
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
    throw new CliError(
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

function pairs(home: string): Pair[] {
  if (pairsRefused(home) !== null) return []
  try {
    const v = JSON.parse(readFileSync(peersPath(home), 'utf8')) as { version?: unknown; pairs?: unknown }
    // A null or malformed entry is skipped, never a throw (s3).
    return v.version === 1 && Array.isArray(v.pairs) ? v.pairs.filter(isPair) : []
  } catch {
    return []
  }
}

/**
 * The pairs of the table `drop` names, taken out of it; the rest are written back whole, each row as read (parsed and
 * written again unchanged, so the running service's check of rows it did not write keeps them). The count taken. A
 * refused table is never rewritten (needPairsTable first).
 */
export function dropLocalPairs(home: string, drop: (p: Pair) => boolean): number {
  needPairsTable(home)
  const all = pairs(home)
  const rest = all.filter((p) => !drop(p))
  if (rest.length !== all.length) writeWhole(home, peersPath(home), { version: 1, pairs: rest })
  return all.length - rest.length
}

/** Whether `x` and `y` (addresses) are a local pair of the table. */
export function pairedLocally(home: string, x: string, y: string): boolean {
  return pairs(home).some((p) => (p.a_addr === x && p.b_addr === y) || (p.a_addr === y && p.b_addr === x))
}

/** Local delivery with no word file (decision 104): the bag service's LOCAL_DELIVERY_DEFAULT, kept equal by a test. */
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

/** The line keygen prints with the word on (C4). */
export const visibleLine = (name: string): string =>
  `${name} is visible to your other identities on this machine; to keep it apart: bag local-delivery hide ${name}`

/** The home's identities by key name, for the on question (S1): every one it joins. */
function identitiesOf(home: string): string[] {
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
 * local-delivery on|off|hide <name>|show <name> [--dir <home>]: writes only run/local.json, version 2, keeping the
 * other half. off (the brake) and hide only reduce reach: no question. on and show add reach: a terminal and one y.
 */
export async function localDelivery(args: readonly string[], io: Io): Promise<number> {
  const named = args[0] === 'hide' || args[0] === 'show'
  const p = parse(args, {
    positionals: named ? ['word', 'name'] : ['word'],
    options: { dir: { type: 'string' } },
  })
  const word = p.positionals[0] as string
  const name = p.positionals[1]
  if (!['on', 'off', 'hide', 'show'].includes(word)) throw new UsageError(LOCAL_DELIVERY_USAGE)
  const home = resolve(homeDir(io, str(p, 'dir')))
  const file = wordPath(home)
  const w = readWord(home)
  if (w.why !== null) io.err(`local-delivery: ${w.why}, so it reads as off; this writes it whole`)
  if (word === 'on') {
    needTty(io, 'local-delivery')
    const all = identitiesOf(home).filter((n) => !w.hidden.includes(n))
    const question = [
      `let ${all.length === 0 ? "this home's identities" : all.join(', ')}, and any identity you add later, find and`,
      '  message each other on this machine? Messages stay here and never go to a relay. A message from one of your',
      "  identities still reaches the other's model as mail it may act on, so keep apart any identity that should",
      '  not hear from the others (bag local-delivery hide <name>). On Codex and omp a command your agent runs can',
      '  change this setting; bag tells every window when it does.',
    ].join('\n')
    await confirmed(io, question, 'nothing was changed')
  }
  if (word === 'show') {
    needTty(io, 'local-delivery')
    const q = `show ${name} to this home's other identities again? They can then message it on this machine.`
    await confirmed(io, q, 'nothing was changed')
  }
  const rest = w.hidden.filter((h) => h !== name)
  const hidden = word === 'hide' ? [...rest, name as string] : word === 'show' ? rest : w.hidden
  const on = word === 'on' ? true : word === 'off' ? false : w.on
  writeWhole(home, file, {
    version: 2,
    local_delivery: on ? 'on' : 'off',
    hidden: [...new Set(hidden)].sort(),
  })
  io.out(
    named ? `${word === 'hide' ? 'hidden' : 'shown'} ${name}: ${file}` : `local_delivery ${word}: ${file}`,
  )
  return 0
}
