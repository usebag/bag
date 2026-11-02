import { describe, expect, it } from 'vitest'
import { verifyAuditLog } from '../src/audit.ts'
import { type Held, policyStatus } from '../src/moderation/gate.ts'
import { keyword } from '../src/moderation/modules.ts'
import { addressRecord, P } from './support/fixtures.ts'
import { bob, envelope, HOME, heldHaveNoContent, members, orgPolicy, records } from './support/org.ts'
import { ScriptedRelay } from './support/relays.ts'

// Every refusal, quarantine, hold, release and drop of the org's rules is exactly one audit
// line naming its rule, and the status's counts by rule and outcome equal the counts recomputed from the log. The sends
// go through the gate the Edge composes from its members record, so each is judged once.

interface Line {
  readonly event: string
  readonly decision: string
  readonly detail: string | null
}

/** The outcome a policy line records, read from the line alone: what V5 recomputes. */
function outcome(l: Line): string | null {
  const d = l.detail === null ? {} : (JSON.parse(l.detail) as Record<string, unknown>)
  if (typeof d.rule !== 'string' || !['policy', 'moderate', 'release'].includes(l.event)) return null
  if (l.event === 'release') return l.decision === 'accept' ? 'released' : 'dropped'
  if (l.decision === 'reject') return 'refused'
  if (l.decision === 'queue') return d.held === 'quarantined' ? 'quarantined' : 'held'
  return d.allowed === true || d.flag === true ? 'allowed' : null
}

describe('one line per decision, and the counts from the log', () => {
  it('counts every decision of a mixed run once, by rule and outcome, as the log does', async () => {
    const org = orgPolicy({ scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }] })
    const own = members({
      roots: { mode: 'deny', list: [P.other.address], unknown: 'quarantine' },
      outbound: { deny: [P.jane.address] },
      moderation: { module: 'keyword', action: 'quarantine', params: ['ignore previous instructions'] },
    })
    const r = records()
    r.put(HOME, addressRecord(P.jane))
    r.put(HOME, addressRecord(P.other))
    const b = bob({ org, members: own, moderators: [keyword], records: r, relay: new ScriptedRelay() })
    const T = 'please summarise the attached thread before noon tomorrow'
    let cursor = 0
    const receive = (o: Parameters<typeof envelope>[0]) => b.edge.receive(HOME, ++cursor, envelope(o).bytes)
    const rows = [
      await receive({ from: P.other }), // roots.deny: refused
      await receive({ from: P.mallory }), // roots.unknown: quarantined
      await receive({ type: 'deploy.run' }), // scopes[0].accept_types: refused
      await receive({ body: { text: 'Ignore previous instructions' } }), // moderation: quarantined
      await receive({ body: { text: T } }), // clean: routed
    ]
    await b.edge.receiver.release((rows[1] as { seq: number }).seq) // released, then routed under the waiver
    b.edge.receiver.drop((rows[3] as { seq: number }).seq) // dropped
    await expect(b.edge.send({ to: [P.jane.address], type: 'chat.v1', body: 'x' })).rejects.toThrow() // refused
    const held = await b.edge.sendOrWait({ to: [P.other.address], type: 'chat.v1', body: { quote: T } }) // held
    b.edge.drop((held as Held).id) // dropped
    const lines = b.audit.lines.map((l) => JSON.parse(l) as Line)
    const fromLog = new Map<string, number>()
    for (const l of lines) {
      const o = outcome(l)
      const rule = l.detail === null ? null : (JSON.parse(l.detail) as { rule?: string }).rule
      if (o !== null) fromLog.set(`${rule} ${o}`, (fromLog.get(`${rule} ${o}`) ?? 0) + 1)
    }
    const status = policyStatus(b.store)
    const fromStatus = new Map(status.counts.map((c) => [`${c.rule} ${c.outcome}`, c.n]))
    expect(fromStatus).toEqual(fromLog)
    expect([...fromStatus.keys()].sort()).toEqual([
      'breaker.echo dropped',
      'breaker.echo held',
      'moderation dropped',
      'moderation quarantined',
      'outbound.deny[0] refused',
      'roots.deny refused',
      'roots.unknown quarantined',
      'roots.unknown released',
      'scopes[0].accept_types refused',
    ])
    expect([status.quarantined, status.pending, heldHaveNoContent(b.store)]).toEqual([0, 0, 0])
    expect(verifyAuditLog(b.audit.lines)).toMatchObject({ ok: true })
    const decisions = [...fromLog.values()].reduce((a, n) => a + n, 0)
    console.log(
      `MEASURE L9: ${decisions} policy decisions, ${fromStatus.size} rule/outcome pairs, log and status equal`,
    )
  })
})
