import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcRecord,
  type AddressRecord,
  type BuiltEnvelope,
  type Hop,
  recordSigner,
  verifyRecord,
} from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { WINDOW_MAX } from '../../../src/agent/index.ts'
import { addressRecord, P, T0, tempDir } from '../../support/fixtures.ts'
import { CAVEAT, EXP, envelope, text, threadId } from '../support.ts'
import {
  audited,
  type Booted,
  boot,
  closeAll,
  codes,
  Driver,
  gone,
  granted,
  measure,
  type Outcome,
  outcome,
  SessionWire,
  Wire,
} from './support-a.ts'

// G3, the window. After (a) `ac logout` (its uid-only logout
// frame), (b) SIGINT of the agent's terminal, (c) SIGHUP, (d) the window's end on the fake clock (the pure timer),
// (e) the agent process dying: signatures and openings served are counted over 10 signs, 10 opens, a register, a
// `grant` and a `resign`. At (a) the address record is re-signed with the add rule's set in `revoked` (the live
// grants and every subject noted this window whose exp + TTL + skew >= now) and `iat` risen; at (d) the timer signs
// nothing. The keys' zeroing is counted at the custody's zero hook here (the buffers are read in the cli's g3). Pass:
// 0 served after any end, and the re-signed record verifying under section 7. Also: `--window 32400` at the agent.

const tmp = tempDir('s38-g3')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)

const J = P.jane.address
const S = P.session.address
const B = P.bob.address
const M = P.mallory.address
const T = threadId(0x5c00)
const MAIL: BuiltEnvelope[] = [
  ...[0, 1, 2, 3, 4].map(() => envelope({ type: 'coding.task.v1' })),
  ...[0, 1, 2, 3, 4].map((i) =>
    envelope({ type: 'chat.message.v1', thread: { id: T, prev: [threadId(0x5d00 + i)] } }),
  ),
]

interface Lived {
  readonly m: Booted
  readonly first: Hop
  readonly open: SessionWire
  readonly held: AddressRecord
  readonly end: number
}

/**
 * The window as lived before its end: the session's first grant and mallory's (which ends at T0 + 100), a thread
 * registered, a derived hop to bob, a renewal of the session's grant to the window's end, one opening; then 200 s.
 */
async function lived(): Promise<Lived> {
  const m = await boot({ home: home(), answers: ['y', 'y'] })
  const held = addressRecord(P.jane, { revoked: [P.carol.address] })
  m.records.set('address', held)
  const first = await granted(m, S, [CAVEAT], EXP)
  await granted(m, M, [CAVEAT], T0 + 100)
  const end = m.agent.windowEnd() as number
  const open = await SessionWire.open(m.path, P.session.signing, [first])
  const env = MAIL[5] as BuiltEnvelope
  for (const r of [
    await open.request('register', [T]),
    await open.request('sign', [B, [CAVEAT], EXP]),
    await open.request('sign', [S, [CAVEAT], end]),
    await open.request('open', [J, env.envelope.id], { envelope: text(env) }),
  ]) {
    expect(r?.ok).toBe(true)
  }
  m.clock.advance(200)
  return { m, first, open, held, end }
}

interface After {
  readonly out: Outcome[]
  readonly signatures: number
  readonly openings: number
}

/** Every request a session, `ac grant` and the keep-alive could send after the end, and what was served. */
async function attempts(l: Lived): Promise<After> {
  const { m } = l
  const signs = audited(m.sink, 'sign', 'accept')
  const opens = audited(m.sink, 'open', 'accept')
  const record = m.records.get('address')
  const d = new Driver(m.path, P.session.signing, [l.first])
  d.adopt(l.open)
  const out: Outcome[] = []
  for (let i = 0; i < 10; i++) out.push(await d.request('sign', [B, [CAVEAT], EXP]))
  for (const env of MAIL) out.push(await d.request('open', [J, env.envelope.id], { envelope: text(env) }))
  out.push(await d.request('register', [T]))
  const uid = async (line: string): Promise<Outcome> => {
    const w = new Wire(m.path)
    const first = await w.next()
    if (first?.nonce === undefined) return outcome(first, w.error)
    return outcome((await w.askPast(line)).reply, w.error)
  }
  const grant = await uid(JSON.stringify({ op: 'grant', args: [P.other.address, [CAVEAT], EXP] }))
  const resign = await uid('{"op":"resign","args":["address"]}')
  out.push(grant, resign)
  const served = (o: Outcome | undefined): number => (o?.served === true ? 1 : 0)
  const signatures =
    out.slice(0, 10).filter((o) => o.served).length +
    served(grant) +
    served(resign) +
    audited(m.sink, 'sign', 'accept') -
    signs +
    (m.records.get('address') === record ? 0 : 1)
  const openings =
    out.slice(10, 20).filter((o) => o.served).length + audited(m.sink, 'open', 'accept') - opens
  return { out, signatures, openings }
}

function verified(r: AcRecord | null | undefined, now: number): boolean {
  if (r === null || r === undefined) return false
  try {
    verifyRecord(r, now)
    return recordSigner(r) === J
  } catch {
    return false
  }
}

const sorted = (xs: readonly unknown[]): string => JSON.stringify([...xs].map(String).sort())

function report(arm: string, l: Lived, a: After, extra: string): void {
  measure(
    'G3',
    arm,
    `after the end: ${a.out.length} requests; signatures ${a.signatures}; openings ${a.openings}; codes ` +
      `${codes(a.out)}; keys zeroed (the custody's zero hook) ${l.m.zeroed.n}; ${extra}`,
  )
  expect(a.out.filter((o) => o.served)).toEqual([])
  expect([a.signatures, a.openings]).toEqual([0, 0])
}

describe('G3: the window', () => {
  it('(a) ac logout: 0 served after it; the record re-signed with the add rule set, iat risen, verifying', async () => {
    const l = await lived()
    const w = new Wire(l.m.path)
    await w.next()
    const reply = await w.ask('{"op":"logout"}')
    const record = reply?.record as AddressRecord | null | undefined
    const now = l.m.clock.now()
    await gone(l.m.path)
    // The add rule, from what this window noted: S (grant, renewal), mallory (grant, expired at T0 + 100), bob
    // (derived), each with exp + TTL + skew >= now; carol, held before, kept.
    const want = [P.carol.address, S, B, M]
    const a = await attempts(l)
    report(
      'a',
      l,
      a,
      `record re-signed ${record != null}; verifies under section 7 ${verified(record, now)}; iat ${l.held.iat} -> ` +
        `${record?.iat}; revoked as the add rule predicts (carol kept; session, bob, and mallory expired inside the ` +
        `window) ${sorted(record?.revoked ?? []) === sorted(want) ? 'yes' : `no: ${sorted(record?.revoked ?? [])}`}`,
    )
    expect(verified(record, now)).toBe(true)
    expect(record?.iat).toBeGreaterThan(l.held.iat)
  })

  for (const signal of ['SIGINT', 'SIGHUP'] as const) {
    const arm = signal === 'SIGINT' ? 'b' : 'c'
    it(`(${arm}) ${signal} of the agent's terminal: 0 served after it; the live grants revoked`, async () => {
      const l = await lived()
      l.m.signals.emit(signal)
      const now = l.m.clock.now()
      await gone(l.m.path)
      const record = l.m.outcomes[0]?.record
      const want = [P.carol.address, S, B]
      const a = await attempts(l)
      report(
        arm,
        l,
        a,
        `outcomes ${l.m.outcomes.length}; record re-signed ${record != null}; verifies ${verified(record, now)}; ` +
          `revoked the live grants only (carol kept; session, bob; not mallory, expired) ` +
          `${sorted(record?.revoked ?? []) === sorted(want) ? 'yes' : `no: ${sorted(record?.revoked ?? [])}`}`,
      )
      if (record != null) expect(verified(record, now)).toBe(true)
    })
  }

  it("(d) the window's end on the fake clock: the timer signs nothing, and 0 served after it", async () => {
    const l = await lived()
    const before = l.m.records.get('address')
    const signs = audited(l.m.sink, 'sign', 'accept')
    l.m.clock.t = l.end
    l.m.timers.fn?.()
    const timer = l.m.outcomes[0]
    const signed =
      audited(l.m.sink, 'sign', 'accept') - signs + (l.m.records.get('address') === before ? 0 : 1)
    const a = await attempts(l)
    report(
      'd',
      l,
      a,
      `the timer's outcome ${JSON.stringify(timer)}; signatures at the timer ${signed} (a renewal to the window's ` +
        `end was live until it); predicted 0 and no re-signed record: ` +
        `${signed === 0 && timer?.record === null ? 'yes' : 'no'}; the agent still listens ${existsSync(l.m.path)}`,
    )
  })

  it('(e) the agent process dies: 0 served after it', async () => {
    const l = await lived()
    await l.m.server.close()
    await gone(l.m.path)
    const a = await attempts(l)
    report(
      'e',
      l,
      a,
      "simulated in process (the listener and its connections closed; a real kill would take the test's own " +
        'process): the zero hook is not run, as no code runs at a real death; the keys leave with the process ' +
        `memory; outcomes ${l.m.outcomes.length}`,
    )
  })

  it('--window 32400 (9 h) at the agent: capped at 8 h', async () => {
    const m = await boot({ home: home(), window: 32_400 })
    const end = m.agent.windowEnd() as number
    measure(
      'G3',
      'window 32400',
      `the agent's window ends ${end - T0} s after login (cap ${WINDOW_MAX}); its timer is armed for ` +
        `${m.timers.ms / 1000} s; ac login's own refusal of the flag is in packages/cli/test/study38/g3.test.ts`,
    )
    expect(end - T0).toBe(WINDOW_MAX)
  })
})
