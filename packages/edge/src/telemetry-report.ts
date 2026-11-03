import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MAX_CELLS,
  MAX_COUNT,
  MAX_KEYS,
  MEMBERS,
  type Member,
  SETS,
  type SetName,
} from './telemetry-schema.ts'

// The client's report (spec/SPEC.md Appendix B 111; the telemetry design note's §5): one machine's
// counts for one UTC day, every home summed, built into exactly one schema-1 report. A count family keeps its largest
// cells, one fewer than its cap (MAX_CELLS), and sums the rest into its `other` cell, `other` at every level; a
// duration family keeps its keys of the most calls, one fewer than MAX_KEYS, and sums the rest into `other` bucket by
// bucket (the red team's F-size). Every count is then the largest power of two not above it, at most 2^19, and ties
// keep the sets' order, so the same counts make the same bytes. build is the checkout's commit when it is a published
// cut, else `other`; node is the major from the list, else `other`; host is the kind with the most of the day's MCP
// sessions, `other` on a tie or with none. Every string in a report is a member's name, the date, the id or a value of
// the schema's sets.

/**
 * A day's counts: each counted leaf by its key, the member's name and the set values below it joined by spaces (a
 * duration family's last value is its bucket's place in SETS.duration), to its raw count.
 */
export type Cells = Map<string, number>

type Entry = readonly [string, number]

/** The day, in seconds. */
const DAY = 86_400

/** The YYYY-MM-DD date of a day number (days since 1970-01-01). */
export function dateOf(day: number): string {
  return new Date(day * DAY * 1000).toISOString().slice(0, 10)
}

/** The day number of a YYYY-MM-DD calendar date; null for anything else. */
export function dayOf(text: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return null
  const day = Date.parse(`${text}T00:00:00Z`) / (DAY * 1000)
  return Number.isInteger(day) && dateOf(day) === text ? day : null
}

/** Each set's values, by the set's name, to their places in it. */
const INDEX = new Map<string, ReadonlyMap<string, number>>()
for (const [name, values] of Object.entries(SETS)) {
  INDEX.set(name, new Map(values.map((v, i): [string, number] => [v, i])))
}

const NAMES = Object.keys(MEMBERS)

function memberOf(name: string): Member | undefined {
  return Object.hasOwn(MEMBERS, name) ? MEMBERS[name] : undefined
}

function isMap(v: unknown): v is Readonly<Record<string, unknown>> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Whether a leaf is a count to add: a positive safe integer. */
function isCount(v: unknown): v is number {
  return Number.isSafeInteger(v) && (v as number) > 0
}

/** The value as a report may carry it: itself when its set holds it, else `other`. */
export function place(set: SetName, value: unknown): string {
  return typeof value === 'string' && INDEX.get(set)?.has(value) === true ? value : 'other'
}

/** Adds `n` to the cell `key`, kept a safe integer. */
export function addCell(cells: Cells, key: string, n: number): void {
  cells.set(key, Math.min(Number.MAX_SAFE_INTEGER, (cells.get(key) ?? 0) + n))
}

/** The key of one count of a count family, each value placed in its set; null for another member or path length. */
export function countCell(member: string, keys: readonly unknown[]): string | null {
  const m = memberOf(member)
  if (m?.kind !== 'counts' || keys.length !== m.keys.length) return null
  return [member, ...m.keys.map((set, i) => place(set, keys[i]))].join(' ')
}

/** The place in SETS.duration of `ms` milliseconds: under 100 ms, 1 s, 10 s, 60 s, or 60 s or more. */
export function durationIndex(ms: number): number {
  return [100, 1000, 10_000, 60_000].filter((edge) => ms >= edge).length
}

/** The key of one duration of a duration family, its key placed in its set; null for another member. */
export function durationCell(member: string, key: unknown, ms: number): string | null {
  const m = memberOf(member)
  return m?.kind === 'hist' ? `${member} ${place(m.key, key)} ${durationIndex(ms)}` : null
}

/**
 * Adds a tree in the store's shape to `cells`: each member's map keyed as the schema keys it, raw counts at its
 * leaves, a duration family's leaves one count per bucket. Members of the schema only, but `pairs`, which only a
 * snapshot gives (telemetry-pairs.ts); a key outside its set counts as `other`; a leaf that is not a positive safe
 * integer, or not at its depth, is left out.
 */
export function addTree(cells: Cells, tree: unknown): void {
  if (!isMap(tree)) return
  for (const [name, value] of Object.entries(tree)) {
    const m = memberOf(name)
    if (m?.kind === 'counts' && name !== 'pairs') addBranch(cells, [name], value, m.keys)
    if (m?.kind !== 'hist' || !isMap(value)) continue
    for (const [k, row] of Object.entries(value)) {
      if (!Array.isArray(row) || row.length !== SETS.duration.length) continue
      for (const [i, n] of row.entries()) {
        if (isCount(n)) addCell(cells, `${name} ${place(m.key, k)} ${i}`, n)
      }
    }
  }
}

function addBranch(cells: Cells, path: readonly string[], v: unknown, sets: readonly SetName[]): void {
  const [set, ...rest] = sets
  if (set === undefined) {
    if (isCount(v)) addCell(cells, path.join(' '), v)
    return
  }
  if (!isMap(v)) return
  for (const [k, x] of Object.entries(v)) addBranch(cells, [...path, place(set, k)], x, rest)
}

/** A key's places: its member's in the report, then each value's in its set (a bucket's place is its own). */
function places(key: string): number[] {
  const [name = '', ...path] = key.split(' ')
  const m = memberOf(name)
  const sets: readonly string[] = m?.kind === 'counts' ? m.keys : m?.kind === 'hist' ? [m.key] : []
  return [NAMES.indexOf(name), ...path.map((v, i) => INDEX.get(sets[i] ?? '')?.get(v) ?? Number(v))]
}

/** Orders two keys as a report lists them. */
function byPlace(a: string, b: string): number {
  const [x, y] = [places(a), places(b)]
  for (const [i, n] of x.entries()) if (n !== y[i]) return n - (y[i] ?? 0)
  return x.length - y.length
}

/** The map under `k` in `at`, made when missing. */
function child(at: Record<string, unknown>, k: string): Record<string, unknown> {
  const v = at[k]
  if (isMap(v)) return v as Record<string, unknown>
  const made: Record<string, unknown> = {}
  at[k] = made
  return made
}

/** The store's shape of cells, each map's keys in their sets' order (a duration family's rows are lists of five). */
export function treeOf(cells: Iterable<readonly [string, number]>): Record<string, unknown> {
  const tree: Record<string, unknown> = {}
  for (const [key, n] of [...cells].sort(([a], [b]) => byPlace(a, b))) {
    const [name = '', ...path] = key.split(' ')
    if (memberOf(name)?.kind === 'hist') {
      const rows = child(tree, name)
      const k = path[0] ?? 'other'
      const row = Array.isArray(rows[k]) ? (rows[k] as number[]) : SETS.duration.map(() => 0)
      row[Number(path[1])] = n
      rows[k] = row
    } else {
      const last = path.pop() ?? ''
      let at = child(tree, name)
      for (const k of path) at = child(at, k)
      at[last] = n
    }
  }
  return tree
}

/** A count as a report carries it: the largest power of two not above it, at most MAX_COUNT; 0 for none. */
export function bucket(n: number): number {
  return n < 1 ? 0 : 2 ** (31 - Math.clz32(Math.min(n, MAX_COUNT)))
}

/**
 * A family within its cap. Its units (a count family's cells, a duration family's keys) rank by count, largest
 * first, ties in the sets' order; past the cap, the first `cap - 1` units stay and every other cell is summed into the
 * `other` unit's cell beside it (`other` at every level for a count family, bucket by bucket for a duration family).
 */
function capped(own: readonly Entry[], cap: number, unit: (key: string) => string, other: string): Entry[] {
  const totals: Cells = new Map()
  for (const [k, n] of own) addCell(totals, unit(k), n)
  const rest = [...totals].filter(([k]) => k !== other).sort(([a, x], [b, y]) => y - x || byPlace(a, b))
  if (rest.length + (totals.has(other) ? 1 : 0) <= cap) return [...own]
  const kept = new Set(rest.slice(0, cap - 1).map(([k]) => k))
  const out: Cells = new Map()
  for (const [k, n] of own) addCell(out, kept.has(unit(k)) ? k : `${other}${k.slice(unit(k).length)}`, n)
  return [...out]
}

/** A family's map in the report: each count bucketed, each map's keys in their sets' order. */
function branch(name: string, own: readonly Entry[]): unknown {
  return treeOf(own.map(([k, n]): Entry => [k, bucket(n)]))[name] ?? {}
}

/** The unit of a count family's cell: the cell itself. */
function cellUnit(key: string): string {
  return key
}

/** The unit of a duration family's cell: its member and key, without the bucket. */
function keyUnit(key: string): string {
  return key.slice(0, key.lastIndexOf(' '))
}

/**
 * The machine's host kind, the coordinator's rule of 2026-11-02: the kind with the most sessions in the day's counts
 * (the MCP servers' `sessions`), `other` on a tie or when there are none.
 */
function hostOf(cells: Cells): string {
  const kinds = [...cells].filter(([k]) => k.startsWith('sessions ')).sort(([, x], [, y]) => y - x)
  const [first, second] = kinds
  return first === undefined || first[1] === second?.[1] ? 'other' : first[0].slice('sessions '.length)
}

/** The machine's facts, raw: each reaches a report only placed in its set (a commit only when it is a cut). */
export interface TelemetryFacts {
  /** The install id, 32 lowercase hex. */
  readonly id: string
  /** The running checkout's commit, or null. */
  readonly build: string | null
  readonly os: string
  readonly arch: string
  readonly node: string
}

type Fact = 'build' | 'os' | 'arch' | 'node'

/** A report: the schema's members, in its order. */
export type TelemetryReport = Record<string, unknown>

function memberValue(name: string, m: Member, cells: Cells, day: string, facts: TelemetryFacts): unknown {
  const own = [...cells].filter(([k]) => k.startsWith(`${name} `))
  if (m.kind === 'const') return m.value
  if (m.kind === 'date') return day
  if (m.kind === 'id') return facts.id
  if (m.kind === 'one') return place(m.set, name === 'host' ? hostOf(cells) : facts[name as Fact])
  if (m.kind === 'hist') return branch(name, capped(own, MAX_KEYS[name] ?? 1, keyUnit, `${name} other`))
  const other = [name, ...m.keys.map(() => 'other')].join(' ')
  return branch(name, capped(own, MAX_CELLS[name] ?? 1, cellUnit, other))
}

/**
 * The report for the UTC date `day`, exactly as it would be sent, from that day's cells and the machine's facts: the
 * schema's members in its order, each count family within MAX_CELLS, each duration family within MAX_KEYS, every
 * count a power of two. At its caps it fits MAX_BYTES (deploy/telemetry measures the worst case).
 */
export function buildTelemetryReport(day: string, cells: Cells, facts: TelemetryFacts): TelemetryReport {
  const report: Record<string, unknown> = {}
  for (const [name, m] of Object.entries(MEMBERS)) report[name] = memberValue(name, m, cells, day, facts)
  return report
}

const COMMIT = /^[0-9a-f]{40}$/

/**
 * The commit of the checkout this file runs from: HEAD when it is detached (a cut is checked out by its commit), else
 * the commit of the branch HEAD names, from its loose or packed ref; null without a readable .git directory (a git
 * worktree's .git is a file, so null).
 */
export function checkoutCommit(root = fileURLToPath(new URL('../../../', import.meta.url))): string | null {
  const read = (path: string): string => (existsSync(path) ? readFileSync(path, 'utf8') : '')
  try {
    const head = read(join(root, '.git', 'HEAD')).trim()
    const ref = /^ref: (refs\/[\w./-]+)$/.exec(head)?.[1]
    if (ref === undefined) return COMMIT.test(head) ? head : null
    const loose = read(join(root, '.git', ref)).trim()
    const packed = read(join(root, '.git', 'packed-refs')).split('\n')
    const commit = COMMIT.test(loose) ? loose : (packed.find((l) => l.endsWith(` ${ref}`)) ?? '').slice(0, 40)
    return COMMIT.test(commit) ? commit : null
  } catch {
    return null
  }
}

/** This machine's facts under the install id `id`: the checkout's commit, the platform, the arch and Node's major. */
export function machineFacts(id: string): TelemetryFacts {
  const node = process.versions.node.split('.')[0] ?? ''
  return { id, build: checkoutCommit(), os: process.platform, arch: process.arch, node }
}
