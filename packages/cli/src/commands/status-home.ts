import { existsSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { custodyClass } from '@usebag/edge'
import { removedRefusal, removedRefused } from '@usebag/home'
import { flag, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { type Identities, keyOf, LABEL, readIdentities } from '../identities.ts'
import type { Io } from '../io.ts'
import { type ServiceHello, serviceHello } from '../service.ts'
import { RESERVED } from '../service-home.ts'
import { consumeUnserved } from './identity.ts'
import { pairs, readWord, spooledCount } from './local.ts'
import { type BoundWindow, boundWindows } from './wake-hook.ts'

// status --home: one read of the whole home for the person.
// Read-only: one hello to the service (no lend, no other call), and the home's own files. No key and no Keychain item
// is read (the custody class is which pointer or key file exists, the edge's custodyClass), no dialog, no write.
// The readers are the existing ones: service.ts's hello, local.ts's word, table and spool, wake-hook.ts's .bound files,
// identities.ts's identities.json. Two facts the home's files cannot give: whether the service holds an identity open
// (it answers no such list without a host's elicitation), so `open` is "bound in a live window"; and the grant class,
// which a binding gives inside the service, so the custody shown is the home's: file, keychain or agent.

export const STATUS_HOME_USAGE = 'status --home [--json] [--dir <home>]'

/** One identity of the home: from identities.json (served by the service) or a key file or pointer alone. */
export interface HomeIdentity {
  readonly label: string
  readonly key: string
  readonly custody: string
  readonly served: boolean
  /** Kept apart from the home's other identities (local-delivery hide): its label is in the word's hidden list. */
  readonly hidden: boolean
  readonly open: boolean
  readonly spooled: number
  readonly relays: readonly string[]
}

/** The whole read, the --json form; the text form prints the same facts one per line, in this order. */
export interface HomeStatus {
  readonly version: 1
  readonly home: string
  /** identities.json: ok, absent, or `invalid <code>` (then read as holding no entry: this read refuses nothing). */
  readonly identities_file: string
  readonly service: ServiceHello
  readonly local_delivery: 'on' | 'off'
  readonly identities: readonly HomeIdentity[]
  readonly local_pairs: readonly { readonly a: string; readonly b: string }[]
  readonly windows: readonly BoundWindow[]
  readonly relays: readonly { readonly url: string; readonly identities: readonly string[] }[]
}

/** The names of <home>/<dir>/*.json that are identity names (no reserved suffix: the service's own files). */
function names(home: string, dir: string): string[] {
  try {
    return readdirSync(join(home, dir))
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.slice(0, -'.json'.length))
      .filter((n) => LABEL.test(n) && !RESERVED.some((s) => n.endsWith(s)))
  } catch {
    return []
  }
}

/** The custody class by which file exists, or what stops it: none (no file), conflict (two custodies), the code. */
function custodyOf(home: string, key: string): string {
  try {
    return custodyClass(home, key)
  } catch (e) {
    const code = (e as { code?: unknown }).code
    return code === 'ENOENT' ? 'none' : code === 'EEXIST' ? 'conflict' : String(code ?? 'unreadable')
  }
}

/** The whole read of `home`, `alive` deciding which shim pids are live (tests pass their own). */
export async function readHome(home: string, alive?: (pid: number) => boolean): Promise<HomeStatus> {
  const file = join(home, 'identities.json')
  let doc: Identities = { version: 1, identities: [] }
  let identities_file = 'absent'
  if (existsSync(file)) {
    try {
      doc = readIdentities(file, true)
      identities_file = 'ok'
    } catch (e) {
      identities_file = `invalid ${String((e as { code?: unknown }).code ?? 'unreadable')}`
    }
  }
  const windows = boundWindows(home, alive)
  const bound = new Set(windows.flatMap((w) => w.as))
  const byKey = new Map<string, { label: string; served: boolean; relays: readonly string[] }>()
  for (const e of doc.identities) byKey.set(keyOf(e), { label: e.label, served: true, relays: e.relays })
  for (const n of ['keys', 'keychain', 'agent'].flatMap((d) => names(home, d)))
    if (!byKey.has(n)) byKey.set(n, { label: n, served: false, relays: [] })
  const word = readWord(home)
  const identities = [...byKey.entries()]
    .map(([key, v]) => ({
      label: v.label,
      key,
      custody: custodyOf(home, key),
      served: v.served,
      hidden: word.hidden.includes(v.label),
      open: bound.has(v.label),
      spooled: spooledCount(home, key),
      relays: [...v.relays],
    }))
    .sort((x, y) => (x.label < y.label ? -1 : x.label > y.label ? 1 : 0))
  const local_pairs = pairs(home)
    .map((p) => (p.a <= p.b ? { a: p.a, b: p.b } : { a: p.b, b: p.a }))
    .sort((x, y) => `${x.a} ${x.b}`.localeCompare(`${y.a} ${y.b}`))
  const urls = new Map<string, string[]>()
  for (const i of identities) for (const u of i.relays) urls.set(u, [...(urls.get(u) ?? []), i.label])
  const relays = [...urls.entries()]
    .map(([url, ids]) => ({ url, identities: ids }))
    .sort((x, y) => (x.url < y.url ? -1 : x.url > y.url ? 1 : 0))
  return {
    version: 1,
    home,
    identities_file,
    service: await serviceHello(home),
    local_delivery: word.on ? 'on' : 'off',
    identities,
    local_pairs,
    windows,
    relays,
  }
}

/** The text form: one fact per line, in HomeStatus's order. */
export function homeLines(s: HomeStatus): string[] {
  const v = s.service
  const service =
    v.state === 'none'
      ? `no service at ${v.socket}`
      : v.state === 'refused'
        ? `service refused ${v.code} at ${v.socket}`
        : `service bag ${v.version} pid ${v.pid} since ${v.since ?? 'unknown'} contract ${v.contract} socket ${v.socket}`
  const yes = (b: boolean): string => (b ? 'yes' : 'no')
  return [
    `home ${s.home}`,
    `identities_file ${s.identities_file}`,
    service,
    `local_delivery ${s.local_delivery}`,
    ...s.identities.map(
      (i) =>
        `identity ${i.label} key ${i.key} custody ${i.custody} served ${yes(i.served)} hidden ${yes(i.hidden)} open ${yes(i.open)} spooled ${i.spooled}`,
    ),
    ...s.local_pairs.map((p) => `local_pair ${p.a} ${p.b}`),
    ...s.windows.map(
      (w) => `window ${w.host} session ${w.session ?? 'none'} as ${w.as.join(',')} shim ${w.shim}`,
    ),
    ...s.relays.map((r) => `relay ${r.url} for ${r.identities.join(',')}`),
  ]
}

/** status --home [--json] [--dir <home>]: the read, as lines or as one JSON object; exit 0, whatever it finds. */
export async function statusHome(args: readonly string[], io: Io): Promise<number> {
  const options = { home: { type: 'boolean' }, json: { type: 'boolean' }, dir: { type: 'string' } } as const
  const p = parse(args, { positionals: [], options })
  if (!flag(p, 'home')) throw new UsageError(STATUS_HOME_USAGE)
  const home = resolve(homeDir(io, str(p, 'dir')))
  // A served remove's record left by a service that stopped first: failed here when no service runs (identity.ts);
  // a refused record is named below, whether a service runs or not, and fails nothing.
  const refused = removedRefused(home)
  if (refused === null) await consumeUnserved(io, home, (line) => io.err(line))
  const s = await readHome(home)
  if (flag(p, 'json')) io.out(JSON.stringify(s))
  else for (const l of homeLines(s)) io.out(l)
  if (refused !== null) {
    const line = `removed_record refused: ${removedRefusal(home, refused)}`
    if (flag(p, 'json')) io.err(line)
    else io.out(line)
  }
  return 0
}
