import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { P, T0, type TestServer } from './support/fixtures.ts'
import { type AgentHome, agentHome, grantedSession } from './support/sessions.ts'

// A renewal asks for now + life, and the window's end is not known to a session (r11 red team 7): a grant clamped to
// the window once must not be refused exp-not-monotone for good when the window runs out; the renewal asks for less.

let h: AgentHome
let s: TestServer | null

beforeEach(async () => {
  h = await agentHome()
  s = null
})

afterEach(async () => {
  await s?.close()
  await h.agent.close()
  h.tmp.cleanup()
})

describe('a session renewal near the window end', () => {
  it('is clamped by the agent answer, not refused exp-not-monotone', async () => {
    h.agent.login(P.jane.keys, 3 * 3600) // the window ends at T0 + 10,800
    s = await grantedSession(h, 's-one', 1) // the first grant: 8 h, 4 h, 2 h (T0 + 7,200)
    const agent = s.running.opened.agent
    h.clock.t = T0 + 3700 // now + 7,200 is past the window's end; the renewal may not ask for it
    const [hop] = (await agent?.renew()) ?? []
    expect(hop?.exp).toBeGreaterThan(T0 + 3700)
    expect(hop?.exp).toBeLessThanOrEqual(T0 + 10_800)
  })

  it('is clamped from the first renewal of a full 8-hour grant: now + 8 h is always past the window end', async () => {
    h.agent.login(P.jane.keys)
    s = await grantedSession(h, 's-one', 1)
    h.clock.t = T0 + 1000
    const [hop] = (await s.running.opened.agent?.renew()) ?? []
    expect(hop?.exp).toBeGreaterThan(T0 + 1000)
    expect(hop?.exp).toBeLessThanOrEqual(T0 + 28_800)
  })
})
