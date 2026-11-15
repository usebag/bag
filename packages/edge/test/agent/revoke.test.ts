import { signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { GRANT_ACTS, grantAuditEntry } from '../../src/agent/index.ts'
import { verifyAuditLog } from '../../src/audit.ts'
import { P } from '../support/fixtures.ts'
import { CAVEAT, EXP, grant, hopOf, lines, Session, session, setup, threadId } from './support.ts'

// The agent's session revoke (uid-only): a session's grants leave the window, its next request is not-in-grant, the
// others' grants stay; and regrant's lines in the identity's own log, one `policy` shape built from named members only.

describe('Agent.revoke', () => {
  it("ends one session's grants and only its own: the next sign is not-in-grant, the other session still signs", () => {
    const { agent, sink } = setup()
    const s = session(agent)
    const other = session(agent, P.bob.signing)
    expect(s.sign(P.carol.address, [CAVEAT, 'repo=r'], EXP)).toMatchObject({ ok: true })
    expect(agent.revoke(P.session.address)).toEqual({ ok: true, op: 'revoke', grants: 1 })
    expect(s.sign(P.carol.address, [CAVEAT], EXP)).toEqual({ ok: false, code: 'not-in-grant' })
    expect(other.sign(P.carol.address, [CAVEAT], EXP)).toMatchObject({ ok: true })
    expect(agent.revoke(P.session.address)).toEqual({ ok: true, op: 'revoke', grants: 0 })
    expect(agent.revoke(P.mallory.address)).toEqual({ ok: true, op: 'revoke', grants: 0 })
    const revokes = lines(sink)
      .filter((l) => l.event === 'revoke')
      .map((l): Record<string, unknown> => ({ ...l, detail: JSON.parse(String(l.detail)) as unknown }))
    expect(revokes.map((l) => [l.decision, l.reason, l.id, l.from, l.root])).toEqual(
      Array(3).fill(['accept', 'ok', null, null, P.jane.address]),
    )
    expect(revokes.map((l) => l.detail)).toEqual([
      { sub: P.session.address, grants: 1 },
      { sub: P.session.address, grants: 0 },
      { sub: P.mallory.address, grants: 0 },
    ])
    expect(verifyAuditLog(sink.read())).toEqual({ ok: true, lines: sink.read().length })
  })

  it("ends a chain rooted at the session's first grant (the cascade), not a hop signed for another subject", () => {
    const { agent } = setup()
    const g = grant(agent)
    const s = new Session(agent, P.session.signing, [g])
    // A chain the session extended itself: its own hop S -> bob after the first grant J -> S.
    const onward = signHop(P.session.signing, P.bob.address, ['repo=r'], EXP)
    const rooted = new Session(agent, P.bob.signing, [g, onward])
    // A hop the agent signed for bob at the session's request: J -> bob, its own grant-set entry, sub bob.
    const derived = new Session(agent, P.bob.signing, [hopOf(s.sign(P.bob.address, [CAVEAT], EXP))])
    expect(rooted.sign(P.carol.address, [CAVEAT, 'repo=r'], EXP)).toMatchObject({ ok: true })
    expect(derived.sign(P.carol.address, [CAVEAT], EXP)).toMatchObject({ ok: true })
    agent.revoke(P.session.address)
    expect(rooted.sign(P.carol.address, [CAVEAT, 'repo=r'], EXP)).toEqual({ ok: false, code: 'not-in-grant' })
    expect(derived.sign(P.carol.address, [CAVEAT], EXP)).toMatchObject({ ok: true })
    expect(agent.revoke(P.bob.address)).toMatchObject({ ok: true, grants: 1 })
    expect(derived.sign(P.carol.address, [CAVEAT], EXP)).toEqual({ ok: false, code: 'not-in-grant' })
  })

  it('stops every request of the session (a register too), and answers agent-locked with no line once the window is closed', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    agent.revoke(P.session.address)
    expect(s.register(threadId(1))).toEqual({ ok: false, code: 'not-in-grant' })
    const before = sink.read().length
    agent.logout()
    expect(agent.revoke(P.session.address)).toEqual({ ok: false, code: 'agent-locked' })
    expect(sink.read()).toHaveLength(before)
  })
})

describe('grantAuditEntry: regrant as a policy line', () => {
  it('gives each act its decision under policy, step grant, reason ok, from null', () => {
    const decisions = GRANT_ACTS.map((act) => [act, grantAuditEntry(act).decision])
    expect(decisions).toEqual([
      ['grant-renewed', 'accept'],
      ['regrant-asked', 'queue'],
      ['regrant-granted', 'accept'],
      ['regrant-refused', 'reject'],
    ])
    expect(grantAuditEntry('regrant-granted', { label: 'work', from: 'a', to: 'b', exp: 7 })).toEqual({
      event: 'policy',
      decision: 'accept',
      reason: 'ok',
      from: null,
      detail: { step: 'grant', act: 'regrant-granted', label: 'work', from: 'a', to: 'b', exp: 7 },
    })
  })

  it('carries only its named members: no key, no caveat, nothing else a caller passes', () => {
    const smuggled = {
      label: 'work',
      code: 'declined',
      key: 'SECRET-KEY',
      caveats: ['type=coding.*'],
      exp: '9',
    }
    const line = grantAuditEntry('regrant-refused', smuggled as never)
    expect(line.detail).toEqual({ step: 'grant', act: 'regrant-refused', label: 'work', code: 'declined' })
    expect(JSON.stringify(line)).not.toContain('SECRET-KEY')
    expect(JSON.stringify(line)).not.toContain('type=coding')
  })
})
