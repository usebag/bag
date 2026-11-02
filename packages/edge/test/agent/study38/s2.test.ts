import { join } from 'node:path'
import { type Hop, MAX_CAVEAT_BYTES, MAX_CAVEATS, utf8, verifyChain } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { P, T0, tempDir } from '../../support/fixtures.ts'
import {
  S2_CASES,
  S2_GRANT_EXP_AFTER_T0,
  S2_REQUESTS,
  S2_WINDOW,
  type S2Case,
  type S2Request,
} from './requests-s2.ts'
import { boot, closeAll, codes, Driver, granted, measure, type Outcome } from './support-a.ts'

// S2, the derived hop attenuates: the pre-registered 200 `sign` requests (requests-s2.ts), 20 each of
// ten cases, each case on its own agent (so the per-minute signature cap never bites), the session
// holding the case's first grant. Counted: derived hops signed that are not a string-prefix extension of the grant
// with `exp` at most the chain's earliest and at least one caveat. Pass: 0 of the 180 refusals signed, the 20 appends
// signed. A refusal under another code than the expected one is a deviation, printed, not red.

const tmp = tempDir('s38-s2')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)

const S = P.session.address
const EXP1 = T0 + S2_GRANT_EXP_AFTER_T0
const NAMES = {
  bob: P.bob.address,
  carol: P.carol.address,
  mallory: P.mallory.address,
  other: P.other.address,
  org: P.org.address,
} as const

/** True when a signed hop is an allowed attenuation, judged here from the request and the grant alone. */
function attenuates(hop: Hop, r: S2Request): boolean {
  const prefix = r.grant.every((c, i) => hop.caveats[i] === c)
  const shape =
    hop.caveats.length >= 1 &&
    hop.caveats.length <= MAX_CAVEATS &&
    hop.caveats.every((c) => utf8(c).length <= MAX_CAVEAT_BYTES)
  const asked = hop.sub === NAMES[r.sub] && JSON.stringify(hop.caveats) === JSON.stringify(r.caveats)
  let verifies = true
  try {
    verifyChain([hop], hop.sub, T0)
  } catch {
    verifies = false
  }
  return prefix && shape && asked && hop.exp <= EXP1 && hop.iss === P.jane.address && verifies
}

interface Ran {
  readonly r: S2Request
  readonly o: Outcome
}

async function runCase(c: S2Case): Promise<Ran[]> {
  const set = S2_REQUESTS.filter((r) => r.case === c)
  const m = await boot({ home: home(), answers: ['y'] })
  const grant = set[0]?.grant ?? []
  const first = await granted(m, S, grant, EXP1)
  const d = new Driver(m.path, P.session.signing, [first])
  const out: Ran[] = []
  for (const r of set)
    out.push({ r, o: await d.request('sign', [NAMES[r.sub], r.caveats, T0 + r.expAfterT0]) })
  expect(m.agent.windowEnd()).toBe(T0 + S2_WINDOW)
  return out
}

describe('S2: the derived hop attenuates', () => {
  it('V3: the request set holds 200, 20 of each of the ten cases', () => {
    measure(
      'S2',
      'set',
      `${S2_REQUESTS.length} requests: ${codes(S2_REQUESTS.map((r) => ({ code: r.case })))}`,
    )
    expect(S2_REQUESTS).toHaveLength(200)
  })

  it('0 of the 180 refusals signed, the 20 appends signed, every code as expected', async () => {
    const all: Ran[] = []
    for (const c of S2_CASES) {
      const ran = await runCase(c)
      all.push(...ran)
      const signed = ran.filter((x) => x.o.served).length
      const predicted = ran.filter((x) =>
        x.r.expect === 'signed' ? x.o.served : x.o.code === x.r.expect,
      ).length
      measure(
        'S2',
        c,
        `${ran.length} requests; signed ${signed}; codes ${codes(ran.map((x) => x.o))}; predicted ` +
          `${ran[0]?.r.expect}: ${predicted} of ${ran.length}`,
      )
    }
    const refusals = all.filter((x) => x.r.expect !== 'signed')
    const appends = all.filter((x) => x.r.expect === 'signed')
    const refusedSigned = refusals.filter((x) => x.o.served).length
    const appendsSigned = appends.filter((x) => x.o.served).length
    const bad = all.filter((x) => x.o.served && !attenuates(x.o.reply?.hop as Hop, x.r)).length
    const deviations = refusals.filter((x) => !x.o.served && x.o.code !== x.r.expect)
    measure(
      'S2',
      'all',
      `${all.length} requests; refusal set signed ${refusedSigned} of ${refusals.length}; appends signed ` +
        `${appendsSigned} of ${appends.length}; signed hops that are not a prefix extension with exp at most the ` +
        `chain's earliest and at least one caveat ${bad}; refusals under another code than predicted ` +
        `${deviations.length}${deviations.length === 0 ? '' : ` (${codes(deviations.map((x) => ({ code: `${x.r.case}:${x.o.code}` })))})`}`,
    )
    expect(refusals).toHaveLength(180)
    expect(refusedSigned).toBe(0)
    expect(bad).toBe(0)
    expect(appendsSigned).toBe(20)
  })
})
