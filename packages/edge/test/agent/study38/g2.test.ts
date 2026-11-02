import { join } from 'node:path'
import { type Hop, signHop } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { addressRecord, P, tempDir } from '../../support/fixtures.ts'
import { CAVEAT, EXP, JANE_KEYS } from '../support.ts'
import { type Booted, boot, closeAll, codes, Driver, granted, measure, type Outcome } from './support-a.ts'

// G2, renewal: a renewal is a `sign` whose `sub` is
// the requesting session, whose presented chain is its first grant alone, whose caveats are an exact prefix of it and
// whose `exp` is at most the window's end; it is signed silently, one printed line and no `y`. Arms: (a) caveats equal,
// `exp` within the window; (b) narrowed by an appended caveat; (c) widened or reordered; (d) `exp` past the window;
// (e) a different subject (and a chain longer than the first grant); (f) no first grant in the window. Counted: signed,
// lines printed on the agent's terminal, prompts asked. Pass: (a) and (b) silent, (c) to (f) not signed, with the
// codes (not-in-grant; exp-not-monotone; exp-not-monotone; not-in-grant).

const tmp = tempDir('s38-g2')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)

const S = P.session.address
const B = P.bob.address
const G = [CAVEAT, 'repo=r'] as const

interface Counted {
  readonly o: Outcome
  readonly lines: number
  readonly asks: number
  readonly renewal: boolean
}

/** A session with its first grant, in a fresh window, and a way to count what one request did at the terminal. */
async function granted1(): Promise<{
  m: Booted
  first: Hop
  d: Driver
  count: (f: () => Promise<Outcome>) => Promise<Counted>
}> {
  const m = await boot({ home: home(), answers: ['y'] })
  const first = await granted(m, S, G, EXP)
  const d = new Driver(m.path, P.session.signing, [first])
  const count = async (f: () => Promise<Outcome>): Promise<Counted> => {
    const [lines, asks] = [m.terminal.renewed(), m.terminal.asks]
    const o = await f()
    return {
      o,
      lines: m.terminal.renewed() - lines,
      asks: m.terminal.asks - asks,
      renewal: o.reply?.renewal === true,
    }
  }
  return { m, first, d, count }
}

function show(arm: string, cs: readonly Counted[], predicted: string): void {
  const signed = cs.filter((c) => c.o.served).length
  const lines = cs.reduce((n, c) => n + c.lines, 0)
  const asks = cs.reduce((n, c) => n + c.asks, 0)
  measure(
    'G2',
    arm,
    `${cs.length} request${cs.length === 1 ? '' : 's'}; signed ${signed}; terminal lines ${lines}; prompts ${asks}; ` +
      `codes ${codes(cs.map((c) => c.o))}; predicted ${predicted}`,
  )
}

describe('G2: renewal', () => {
  it('(a) and (b): signed silently, one printed line each, no prompt', async () => {
    const { m, d, count } = await granted1()
    const end = m.agent.windowEnd() as number
    const a = [
      await count(() => d.request('sign', [S, [...G], EXP + 600])),
      await count(() => d.request('sign', [S, [...G], end])),
    ]
    const b = [await count(() => d.request('sign', [S, [...G, 'x=1'], EXP + 1200]))]
    show('a', a, 'signed silently, one line each')
    show('b', b, 'signed silently, one line each')
    for (const c of [...a, ...b]) {
      expect(c.o.served && c.renewal).toBe(true)
      expect([c.lines, c.asks]).toEqual([1, 0])
    }
  })

  it('(c) to (f): none signed, each with its expected code', async () => {
    const { m, first, d, count } = await granted1()
    const end = m.agent.windowEnd() as number
    const c = [
      await count(() => d.request('sign', [S, [CAVEAT], EXP])),
      await count(() => d.request('sign', [S, ['repo=r', CAVEAT], EXP])),
      await count(() => d.request('sign', [S, ['type=*', 'repo=r'], EXP])),
      await count(() => d.request('sign', [S, [], EXP])),
    ]
    const dd = [
      await count(() => d.request('sign', [S, [...G], end + 1])),
      await count(() => d.request('sign', [S, [...G, 'x=1'], end + 3600])),
    ]
    const past = await count(() => d.request('sign', [S, [...G], EXP + 3600]))
    const onward = signHop(P.session.signing, B, ['x=1'], EXP)
    const bob = new Driver(m.path, P.bob.signing, [first, onward])
    const e = [
      await count(() => d.request('sign', [B, [...G], EXP + 600])),
      await count(() => bob.request('sign', [B, [...G, 'x=1'], EXP + 600])),
    ]
    // (f): a principal hop no `ac grant` of this window put in the grant-set, and a first grant of an earlier window.
    // EXP - 60, not EXP: the same fields would be the first grant's own bytes (Ed25519 is deterministic).
    const direct = new Driver(m.path, P.session.signing, [signHop(P.jane.signing, S, [...G], EXP - 60)])
    const f = [await count(() => direct.request('sign', [S, [...G], EXP + 600]))]
    m.records.set('address', addressRecord(P.jane))
    m.server.logout()
    m.server.login(JANE_KEYS)
    const earlier = new Driver(m.path, P.session.signing, [first])
    f.push(await count(() => earlier.request('sign', [S, [...G], EXP + 600])))

    show('c', c, 'not-in-grant, none signed (drop, reorder, a wider rewrite, empty)')
    show('d', dd, 'exp-not-monotone, none signed')
    measure(
      'G2',
      'd past the first grant',
      `exp past the first grant's, inside the window (a renewal, not refused): signed ` +
        `${past.o.served ? 1 : 0}, terminal lines ${past.lines}, prompts ${past.asks}, code ${past.o.code}`,
    )
    show('e', e, 'exp-not-monotone, none signed (another subject; a chain longer than the first grant)')
    show('f', f, 'not-in-grant, none signed (a hop not in the grant-set; a first grant of an earlier window)')
    const refused = [...c, ...dd, ...e, ...f]
    measure(
      'G2',
      'c-f',
      `${refused.length} requests; widened or longer renewals signed ${refused.filter((x) => x.o.served).length}; ` +
        `prompts ${refused.reduce((n, x) => n + x.asks, 0)}`,
    )
    expect(refused.filter((x) => x.o.served)).toEqual([])
    expect(refused.reduce((n, x) => n + x.asks + x.lines, 0)).toBe(0)
    for (const x of c) expect(x.o.code).toBe('not-in-grant')
    for (const x of [...dd, ...e]) expect(x.o.code).toBe('exp-not-monotone')
    for (const x of f) expect(x.o.code).toBe('not-in-grant')
  })
})
