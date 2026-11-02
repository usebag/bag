import { AcError, buildEnvelope, newThread } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { AgentError } from '../src/agent/model.ts'
import { Edge } from '../src/edge.ts'
import { coreRng } from '../src/sender.ts'
import { envelopeOpener } from './support/agent-fakes.ts'
import { FakeClock, FakeRecords, MemoryAuditSink, P, seededRng, T0 } from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// The Receiver's awaited opener: when the keys' opener opens a whole envelope (the agent's does, through its
// read rule), the unseal step awaits it; every other opener is called in the same turn, as before.

const HOME = 'http://home.test'
const rng = coreRng(seededRng('agent-receiver'))

/** A chat message from carol to bob, each one different. */
function message(): { readonly id: string; readonly bytes: Uint8Array } {
  const built = buildEnvelope({
    from: P.carol.signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'hello' },
    ts: T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes }
}

/** Bob's edge, his sealing key behind an EnvelopeOpener (or his own key, as the control). */
function bob(agent: boolean) {
  const opener = envelopeOpener(P.bob.sealing, P.bob.address)
  const audit = new MemoryAuditSink()
  const clock = new FakeClock()
  const edge = new Edge({
    keys: { signing: P.bob.signing, sealing: agent ? opener : P.bob.sealing },
    store: new SqliteStore(':memory:'),
    relays: { client: new ScriptedRelay(), urls: [HOME] },
    records: new FakeRecords(),
    policy: { roots: [{ address: P.carol.address }], types: ['chat.*'] },
    clock,
    rng: seededRng('bob'),
    audit,
  })
  return { edge, opener, audit, clock }
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5))

describe('Receiver: an EnvelopeOpener opens the envelope', () => {
  it('queues what the opener releases, as the key itself would, asking it for the exact bytes', async () => {
    const agent = bob(true)
    const control = bob(false)
    const m = message()
    const row = await agent.edge.receive(HOME, 1, m.bytes)
    const same = await control.edge.receive(HOME, 1, m.bytes)
    expect(row).toMatchObject({ state: 'queued', id: m.id, reason: null })
    expect(row.content).toBe(same.content)
    expect(agent.opener.log.map((b) => Array.from(b))).toEqual([Array.from(m.bytes)])
    expect(agent.audit.steps()).toEqual(control.audit.steps())
  })

  it('rejects for good what the agent refuses, as open-failed or by code, id seen', async () => {
    const { edge, opener } = bob(true)
    const m = message()
    opener.fail = new AgentError('not-in-grant', 'the thread is not registered')
    expect(await edge.receive(HOME, 1, m.bytes)).toMatchObject({ state: 'rejected', reason: 'open-failed' })
    opener.fail = new AcError('bad-sig', 'the agent refused')
    const n = message()
    expect(await edge.receive(HOME, 2, n.bytes)).toMatchObject({ state: 'rejected', reason: 'bad-sig' })
    expect(await edge.receive(HOME, 3, m.bytes)).toMatchObject({ state: 'rejected', reason: 'duplicate' })
  })

  it('defers what a retry can undo, then opens it: the agent down, locked, or rate-limited', async () => {
    const down = new Error('agent: the socket closed')
    const locked = new AgentError('agent-locked', 'no login window is open')
    const limited = new AcError('rate-limited', 'open is capped at 600 a minute per session')
    for (const error of [down, locked, limited]) {
      const { edge, opener, audit, clock } = bob(true)
      const m = message()
      opener.fail = error
      const row = await edge.receive(HOME, 1, m.bytes)
      expect(row).toMatchObject({ state: 'received', reason: 'open-failed', id: m.id, tries: 1 })
      expect(audit.steps().at(-1)).toBe('unseal retry open-failed')
      opener.fail = null
      clock.advance(3600)
      expect(await edge.receive(HOME, 1, m.bytes)).toMatchObject({ state: 'queued', id: m.id, reason: null })
    }
  })

  it('rejects the copy that loses the race for an id while the opener is awaited', async () => {
    const { edge, opener } = bob(true)
    const m = message()
    let release = (): void => {}
    opener.gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const both = Promise.all([edge.receive(HOME, 1, m.bytes), edge.receive(HOME, 2, m.bytes)])
    await tick()
    expect(opener.log).toHaveLength(2)
    release()
    const rows = await both
    expect(rows.map((r) => r.state).sort()).toEqual(['queued', 'rejected'])
    expect(rows.find((r) => r.state === 'rejected')?.reason).toBe('duplicate')
  })
})
