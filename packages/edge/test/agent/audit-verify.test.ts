import { describe, expect, it } from 'vitest'
import { Audit, parseAuditLine, verifyAuditLog } from '../../src/audit.ts'
import { P } from '../support/fixtures.ts'
import { CAVEAT, EXP, envelope, session, setup } from './support.ts'

// The edge's audit reader accepts the agent's own lines: the events `sign` and `open`, the
// reasons `agent-locked` and `not-in-grant` (on those events only), and its chain continues with the edge's own events.

describe('verifyAuditLog and parseAuditLine accept the agent log', () => {
  it('verifies a log of accepted and refused signatures and openings (none after the lock), and the edge continues it', () => {
    const { agent, sink, clock } = setup()
    const s = session(agent)
    s.sign(P.bob.address, [CAVEAT, 'repo=r'], EXP)
    s.sign(P.bob.address, ['other'], EXP)
    s.open(envelope())
    agent.logout()
    s.sign(P.bob.address, [CAVEAT], EXP)
    expect(sink.steps()).toEqual([
      'sign accept ok',
      'sign accept ok',
      'sign reject not-in-grant',
      'open accept ok',
    ])
    expect(sink.read()).toHaveLength(4)
    expect(verifyAuditLog(sink.read())).toEqual({ ok: true, lines: 4 })
    new Audit(sink, clock).record({ event: 'verify', decision: 'accept' })
    expect(verifyAuditLog(sink.read())).toEqual({ ok: true, lines: 5 })
  })

  it('still refuses a reason that is no code', () => {
    const { agent, sink } = setup()
    session(agent)
    const line = JSON.parse(sink.read()[0] as string) as Record<string, unknown>
    const parse = (changed: object) => parseAuditLine(JSON.stringify({ ...line, ...changed }))
    expect(parse({}).event).toBe('sign')
    expect(() => parse({ reason: 'made-up' })).toThrow('exactly seq')
    expect(parse({ reason: 'agent-locked' }).reason).toBe('agent-locked')
    for (const reason of ['agent-locked', 'not-in-grant']) {
      expect(() => parse({ event: 'verify', reason })).toThrow('exactly seq')
    }
  })
})
