import { AUDIT_GENESIS, type AuditFields, auditHash } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { AgentAudit, hopDigest, openEntry, signEntry } from '../../src/agent/index.ts'
import { parseAuditLine, verifyAuditLog } from '../../src/audit.ts'
import { FakeClock, MemoryAuditSink, P, T0 } from '../support/fixtures.ts'
import { setup } from './support.ts'

// The agent's audit: `sign` and `open` lines in the hash-chained format of §9 item 8,
// through the edge's AuditSink, with no key, no caveat text, no sealed type and no thread id in any line.

const J = P.jane.address
const S = P.session.address
const HOP = { iss: J, sub: P.bob.address, caveats: ['type=coding.*', 'repo=secret'], exp: T0 + 60 }
const OPEN = { id: 'ab'.repeat(32), session: S, mailbox: J }

describe('the sign and open entries', () => {
  it('records a sign by the hop digest, the requester, the principal and counts', () => {
    expect(signEntry('ok', HOP, S)).toEqual({
      event: 'sign',
      decision: 'accept',
      reason: 'ok',
      id: hopDigest(HOP),
      from: S,
      root: J,
      detail: { tag: 'ac/hop/1', sub: P.bob.address, exp: T0 + 60, caveats: 2 },
    })
    const reject = signEntry('not-in-grant', HOP, null)
    expect(reject).toMatchObject({ decision: 'reject', reason: 'not-in-grant', from: null })
  })

  it('records an open by the envelope id, the session, the mailbox and the limb that decided', () => {
    expect(openEntry('ok', OPEN, J, 'thread')).toEqual({
      event: 'open',
      decision: 'accept',
      reason: 'ok',
      id: OPEN.id,
      from: S,
      root: J,
      detail: { mailbox: J, rule: 'thread' },
    })
    const failed = openEntry('open-failed', OPEN, J, null)
    expect(failed).toMatchObject({ decision: 'reject', detail: { mailbox: J } })
  })
})

describe('AgentAudit', () => {
  it('chains its lines from the genesis and continues a log it is handed', () => {
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const audit = new AgentAudit(sink, clock)
    audit.record(signEntry('ok', HOP, S))
    clock.advance(5)
    new AgentAudit(sink, clock).record(openEntry('caveat-failed', OPEN, J, 'root'))
    const [a, b] = sink.lines.map((l) => JSON.parse(l) as AuditFields & { hash: string })
    expect([a?.seq, a?.prev, a?.ts]).toEqual([1, AUDIT_GENESIS, T0])
    expect([b?.seq, b?.prev, b?.ts]).toEqual([2, a?.hash, T0 + 5])
    for (const line of [a, b]) {
      const { hash, ...fields } = line as AuditFields & { hash: string }
      expect(auditHash(fields)).toBe(hash)
      expect(Object.keys(line ?? {})).toEqual([
        'seq',
        'prev',
        'ts',
        'event',
        'decision',
        'reason',
        'id',
        'from',
        'root',
        'detail',
        'hash',
      ])
    }
    expect(sink.steps()).toEqual(['sign accept ok', 'open reject caveat-failed'])
    expect(sink.lines.join('\n')).not.toContain('secret')
  })

  it('refuses to continue a log whose last line is not an audit line', () => {
    for (const last of ['{"seq":"1","hash":"00"}', 'null', '7']) {
      const sink = new MemoryAuditSink()
      sink.append(last)
      expect(() => new AgentAudit(sink, new FakeClock())).toThrow('a bad last line')
    }
    const sink = new MemoryAuditSink()
    sink.append('not json')
    expect(() => new AgentAudit(sink, new FakeClock())).toThrow(SyntaxError)
  })
})

describe('a declined grant prompt', () => {
  it('writes one declined line for a non-y answer and one for no answer, and the log verifies', () => {
    const { agent, sink } = setup()
    for (const answer of ['n', '']) {
      const before = sink.lines.length
      const pending = agent.prepareGrant({ session: S, caveats: ['type=coding.*'], exp: T0 + 60 })
      if (!pending.ok) throw new Error(`prepareGrant: ${pending.code}`)
      expect(agent.confirmGrant(pending, answer)).toEqual({ ok: false, code: 'declined' })
      const added = sink.lines.slice(before).map((l) => JSON.parse(l) as Record<string, unknown>)
      expect(added.map((l) => [l.event, l.decision, l.reason, l.id, l.from, l.root])).toEqual([
        ['declined', 'reject', 'declined', null, null, J],
      ])
    }
    expect(verifyAuditLog(sink.lines).ok).toBe(true)
  })

  it('parses declined only on the declined event, and only declined there', () => {
    const audit = new AgentAudit(new MemoryAuditSink(), new FakeClock())
    const good = audit.record({ ...signEntry('declined', HOP, null), event: 'declined', id: null })
    expect(parseAuditLine(good)).toMatchObject({ event: 'declined', reason: 'declined' })
    const signDeclined = audit.record(signEntry('declined', HOP, null))
    const declinedOk = audit.record({ ...signEntry('ok', HOP, null), event: 'declined' })
    for (const line of [signDeclined, declinedOk])
      expect(() => parseAuditLine(line)).toThrow('an audit line has')
  })

  it('writes no declined line for a y: the grant is signed and audited as a sign', () => {
    const { agent, sink } = setup()
    const pending = agent.prepareGrant({ session: S, caveats: ['type=coding.*'], exp: T0 + 60 })
    if (!pending.ok) throw new Error(`prepareGrant: ${pending.code}`)
    expect(agent.confirmGrant(pending, 'y')).toMatchObject({ ok: true })
    const events = sink.lines.map((l) => (JSON.parse(l) as { event: string }).event)
    expect(events).toEqual(['sign'])
  })
})
