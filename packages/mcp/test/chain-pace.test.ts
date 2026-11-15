import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { AcError, type Hop } from '@usebag/core'
import { EdgeError, generateEdgeKeys } from '@usebag/edge'
import { AgentClient, clampLife } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RENEW_MIN_S, sessionAgent } from '../src/agent.ts'
import { ChainKeeper, earliestExp } from '../src/chain.ts'
import { type FakeClock, MemoryLog, P, seededRng, T0 } from './support/fixtures.ts'
import { type AgentHome, agentHome, CAVEAT } from './support/sessions.ts'

// The unit keeper's pace near the agent window's end, against the real agent of the session tests: the session's
// renewal is refused rate-limited inside its 300 s pace, so the keeper reads at the pace's end, never inside it. A
// renewal past the window's end halves its life down to the first one the agent takes and stops there, so each renewal
// signs one hop; the last grant may end short of the window, by at most one pace, never after it.

let h: AgentHome

beforeEach(async () => {
  h = await agentHome()
})

afterEach(async () => {
  await h.agent.close()
  h.tmp.cleanup()
})

const settle = (): Promise<void> => new Promise((r) => setImmediate(r))

/** The agent's sign lines so far: all of them, and the accepted ones (each an accepted one a hop it signed). */
function signs(): { all: number; accepted: number } {
  const lines = readFileSync(join(h.tmp.dir, 'agent-audit.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as { event?: unknown; decision?: unknown })
    .filter((l) => l.event === 'sign')
  return { all: lines.length, accepted: lines.filter((l) => l.decision === 'accept').length }
}

/** Timers in the fake clock's time: `to(t)` runs each timer due by t in order, the clock moved to it. */
class Timeline {
  readonly q: { at: number; fn: () => void; off: boolean }[] = []
  idle: () => Promise<unknown> = async () => {}
  readonly clock: FakeClock
  constructor(clock: FakeClock) {
    this.clock = clock
  }

  after(ms: number, fn: () => void): () => void {
    const t = { at: this.clock.t + ms / 1000, fn, off: false }
    this.q.push(t)
    return () => {
      t.off = true
    }
  }

  async to(at: number): Promise<void> {
    for (;;) {
      const next = this.q.filter((t) => !t.off && t.at <= at).sort((x, y) => x.at - y.at)[0]
      if (next === undefined) break
      next.off = true
      this.clock.t = Math.max(this.clock.t, Math.ceil(next.at))
      next.fn()
      await this.idle()
      for (let i = 0; i < 5; i++) await settle()
    }
    this.clock.t = Math.max(this.clock.t, at)
  }
}

describe('a renewal near the window end: refusals only, one hop', () => {
  it('halves to the first life the agent takes and stops: 2 asks, 1 accepted, no upward step', async () => {
    const asked: number[] = []
    let granted = 0
    const end = 400 // the window ends 400 s from now; the life asked is 700
    const life = await clampLife(700, async (l) => {
      asked.push(l)
      if (l > end) throw new AcError('exp-not-monotone', `exp is past ${end}`)
      granted++
      return l
    })
    expect([life, asked, granted]).toEqual([350, [700, 350], 1])
  })
})

describe('the unit keeper near the window end', () => {
  it('no read inside the 300 s pace; the last grant ends by the window end, within one pace', async () => {
    const end = T0 + 640 + RENEW_MIN_S + 100 // the first renewal at T0 + 640; its pace slot T0 + 940
    h.agent.login(P.jane.keys, end - T0)
    const key = generateEdgeKeys(seededRng('pace-session')).signing
    h.type('y')
    const plain = new AgentClient(join(h.tmp.dir, 'agent.sock'))
    const r = await plain.grant(key.address, [CAVEAT], T0 + 700)
    plain.close()
    if (!r.ok) throw new Error(`grant: ${r.code}`)
    const codes = h.codes().length
    const holder = {
      auth: [r.hop] as readonly Hop[],
      renewChain(next: readonly Hop[]): void {
        if (earliestExp(next) <= earliestExp(holder.auth)) throw new EdgeError('chain-not-later', 'not later')
        holder.auth = next
      },
    }
    const agent = sessionAgent(h.tmp.dir, key, r.hop, () => holder.auth, h.clock, seededRng('pace-rng'))
    const reads: { at: number; left: number; asks: number; accepted: number }[] = []
    let inflight: Promise<unknown> = Promise.resolve()
    const tl = new Timeline(h.clock)
    tl.idle = () => inflight
    const keeper = new ChainKeeper({
      source: {
        kind: 'agent',
        renew: () => {
          const before = signs()
          const at = h.clock.t
          const left = earliestExp(holder.auth) - at
          const p = agent.renew()
          inflight = p
            .catch(() => {})
            .then(() => {
              const after = signs()
              reads.push({
                at,
                left,
                asks: after.all - before.all,
                accepted: after.accepted - before.accepted,
              })
            })
          return p
        },
        allowedAt: agent.allowedAt,
      },
      edge: holder,
      clock: h.clock,
      timers: tl,
      run: async () => '',
      env: {},
      log: new MemoryLog(),
    })
    keeper.start()
    await tl.to(end)
    keeper.stop()
    agent.close()
    // the near-end renewal: two asks, one hop
    expect(reads[0]).toMatchObject({ at: T0 + 640, asks: 2, accepted: 1 })
    for (const read of reads) expect(read.accepted).toBe(1)
    for (let i = 1; i < reads.length; i++)
      expect((reads[i]?.at as number) - (reads[i - 1]?.at as number)).toBeGreaterThanOrEqual(RENEW_MIN_S)
    // the chain was live at every read
    for (const read of reads) expect(read.left).toBeGreaterThan(0)
    // the pace's next slot falls after the last exp: nothing more is read, and the chain ends with the window,
    // at or before its end and within one pace of it; nothing is asked of the person
    const last = earliestExp(holder.auth)
    expect(agent.allowedAt()).toBeGreaterThanOrEqual(last)
    expect(last).toBeLessThanOrEqual(end)
    expect(end - last).toBeLessThanOrEqual(RENEW_MIN_S)
    expect(h.codes().length).toBe(codes)
  })
})
