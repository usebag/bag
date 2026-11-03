import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { buildEnvelope, newThread } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { systemRng } from '../src/adapters/system-clock.ts'
import { sealedTarget } from '../src/outbox.ts'
import { coreRng } from '../src/sender.ts'
import { setTelemetry, TELEMETRY_PAIRS_FILE, telemetryReport } from '../src/telemetry.ts'
import { notePairs, noteTrackedPairs, trackPairs, withPairs } from '../src/telemetry-pairs.ts'
import { dateOf } from '../src/telemetry-report.ts'
import { DAY, P, type Party, seededRng, T0, tempDir } from './support/fixtures.ts'

// The `pairs` snapshot: the four cells of a day from a home's trust file and its outbox, never before the consent's
// date (Q8); the largest of a home's identities, cell by cell, summed over homes; nothing while off; nothing of it in a
// report but four floored counts. Temp directories and a real SQLite store; nothing is sent.

const tmp = tempDir('telemetry-pairs')
afterAll(() => tmp.cleanup())
let n = 0
const rng = coreRng(seededRng('telemetry-pairs'))

/** T0 is 2027-01-15 08:00 UTC; the snapshot's last finished day is the 14th, which ends at TODAY. */
const TODAY = Math.floor(T0 / DAY) * DAY
const YESTERDAY = dateOf(TODAY / DAY - 1)
const clock = { now: () => T0 }

/** A machine with telemetry on since `since` (seconds), and a home in it. */
function machine(since = T0 - 30 * DAY): { env: Record<string, string>; dir: string; home: string } {
  const root = join(tmp.dir, `machine-${n++}`)
  const dir = join(root, '.bag')
  setTelemetry(dir, 'on', systemRng, since)
  const home = join(root, 'home')
  mkdirSync(home)
  return { env: { HOME: root }, dir, home }
}

/** Writes `home`'s trust file: each root with its added_at. */
function trust(home: string, roots: Record<string, number>): void {
  const doc = {
    version: 1,
    roots: Object.fromEntries(Object.entries(roots).map(([r, at]) => [r, { added_at: at }])),
  }
  writeFileSync(join(home, 'trust.json'), JSON.stringify(doc))
}

/** An identity's store, in a directory of its own (its writer lock), with one envelope to each of `to`, added at `at`. */
function store(sends: readonly (readonly [Party, number])[]): SqliteStore {
  const dir = join(tmp.dir, `state-${n++}`)
  mkdirSync(dir)
  const s = new SqliteStore(join(dir, 'edge.sqlite'))
  for (const [to, at] of sends) {
    const { envelope, bytes } = buildEnvelope({
      from: P.jane.signing,
      to: [{ address: to.address, sealingKey: to.sealing.publicKey }],
      type: 'chat.v1',
      thread: newThread(rng),
      body: { text: 'x' },
      ts: at,
      rng,
    })
    s.outboxAdd({ id: envelope.id, bytes, thread: 't', session: null, createdAt: at }, [
      sealedTarget(envelope.id, 'http://r', at),
    ])
  }
  return s
}

const pairsOf = (env: Record<string, string>, day = YESTERDAY): unknown => telemetryReport(env, day).pairs

describe('notePairs: the four cells of each finished day, from the trust file and the outbox', () => {
  it('counts peers by age at the day end, and those sent to in the 7 days before, leaving out domains', () => {
    const m = machine()
    trust(m.home, {
      [P.bob.address]: TODAY - 30 * DAY, // old, sent to 3 days ago
      [P.carol.address]: TODAY - 2 * DAY, // new, sent to yesterday
      [P.mallory.address]: TODAY - 10 * DAY, // old, sent to 9 days ago: outside the week
      [P.other.address]: TODAY - DAY + 60, // new, never sent to
      [P.org.address]: TODAY + 3600, // added after the day ended: not yet a peer
      'domain:acme.test': TODAY - 30 * DAY,
    })
    const s = store([
      [P.bob, TODAY - 3 * DAY],
      [P.carol, TODAY - 3600],
      [P.mallory, TODAY - 9 * DAY],
      [P.carol, TODAY + 60], // today: not in yesterday's week
    ])
    notePairs(m.env, clock, m.home, 'jane', s)
    expect(pairsOf(m.env)).toEqual({
      'under-7d': 2,
      'under-7d-sending': 1,
      '7d-or-more': 2,
      '7d-or-more-sending': 1,
    })
    const file = join(m.dir, TELEMETRY_PAIRS_FILE)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    // Seven finished days, the 8th to the 14th; keys are hashes, never the home's path or the identity's name.
    const text = readFileSync(file, 'utf8')
    expect(text).not.toContain(m.home)
    expect(text).not.toContain('jane')
    expect(text).not.toContain(P.bob.address)
    const rows = (JSON.parse(text) as { rows: { day: string; counts: number[] }[] }).rows
    expect(rows).toHaveLength(7)
    // The raw counts, before the floor: the domain root and the root added after the day are not peers.
    expect(rows.find((r) => r.day === YESTERDAY)?.counts).toEqual([2, 1, 2, 1])
    s.close()
  })

  it('never reaches before the consent date: no row for an earlier day, and no send before it counted (Q8)', () => {
    const m = machine(TODAY - DAY + 600) // on since the 14th
    trust(m.home, { [P.bob.address]: TODAY - 30 * DAY })
    const s = store([[P.bob, TODAY - 3 * DAY]])
    notePairs(m.env, clock, m.home, 'jane', s)
    expect(pairsOf(m.env)).toEqual({ '7d-or-more': 1 })
    const days = (
      JSON.parse(readFileSync(join(m.dir, TELEMETRY_PAIRS_FILE), 'utf8')) as { rows: { day: string }[] }
    ).rows
    expect(days.map((r) => r.day)).toEqual([YESTERDAY])
    s.close()
  })

  it('writes nothing while off, and off deletes the snapshots', () => {
    const m = machine()
    trust(m.home, { [P.bob.address]: TODAY - 30 * DAY })
    const s = store([])
    notePairs({ ...m.env, DO_NOT_TRACK: '1' }, clock, m.home, 'jane', s)
    expect(() => statSync(join(m.dir, TELEMETRY_PAIRS_FILE))).toThrow()
    notePairs(m.env, clock, m.home, 'jane', s)
    expect(statSync(join(m.dir, TELEMETRY_PAIRS_FILE)).size).toBeGreaterThan(0)
    setTelemetry(m.dir, 'off', systemRng)
    expect(() => statSync(join(m.dir, TELEMETRY_PAIRS_FILE))).toThrow()
    s.close()
  })

  it('takes the largest of a home identities cell by cell, sums the homes, and floors the sums in the report', () => {
    const m = machine()
    const other = join(m.home, '..', 'second-home')
    mkdirSync(other)
    trust(m.home, { [P.bob.address]: TODAY - 30 * DAY, [P.carol.address]: TODAY - 30 * DAY })
    trust(other, { [P.mallory.address]: TODAY - 30 * DAY })
    const [jane, joe, ann] = [store([[P.bob, TODAY - DAY]]), store([[P.carol, TODAY - DAY]]), store([])]
    notePairs(m.env, clock, m.home, 'jane', jane)
    notePairs(m.env, clock, m.home, 'joe', joe)
    notePairs(m.env, clock, other, 'ann', ann)
    // Home 1: 2 peers, each identity sent to 1 (the largest, 1, not the union, 2); home 2: 1 peer, none sent to.
    // 3 floors to 2.
    expect(pairsOf(m.env)).toEqual({ '7d-or-more': 2, '7d-or-more-sending': 1 })
    for (const s of [jane, joe, ann]) s.close()
  })

  it('never takes pairs from the spool, and a tracked identity is written again before each try', () => {
    const m = machine()
    trust(m.home, { [P.bob.address]: TODAY - 30 * DAY })
    const cells = new Map([['pairs other', 9]])
    expect([...withPairs(m.dir, YESTERDAY, cells)]).toEqual([])
    const s = store([])
    const untrack = trackPairs(m.env, clock, m.home, 'jane', s)
    expect(pairsOf(m.env)).toEqual({ '7d-or-more': 1 })
    writeFileSync(join(m.dir, TELEMETRY_PAIRS_FILE), '{"v":1,"rows":[]}\n')
    noteTrackedPairs()
    expect(pairsOf(m.env)).toEqual({ '7d-or-more': 1 })
    untrack()
    writeFileSync(join(m.dir, TELEMETRY_PAIRS_FILE), 'not json')
    noteTrackedPairs()
    expect(pairsOf(m.env)).toEqual({})
    s.close()
  })
})

describe('outboxBetween: the bytes of the envelopes added in [from, to)', () => {
  it('reads by created_at, from inclusive, to exclusive', () => {
    const s = store([
      [P.bob, T0 - 10],
      [P.carol, T0],
      [P.mallory, T0 + 10],
    ])
    expect(s.outboxBetween(T0, T0 + 10)).toHaveLength(1)
    expect(s.outboxBetween(T0 - 10, T0 + 11)).toHaveLength(3)
    s.close()
  })
})
