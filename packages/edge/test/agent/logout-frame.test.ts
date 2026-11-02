import { once } from 'node:events'
import { join } from 'node:path'
import { type AcRecord, DEFAULT_SKEW, DEFAULT_TTL, type RecordKind } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient, AgentServer, type Terminal } from '../../src/agent/index.ts'
import { addressRecord, P, T0, tempDir } from '../support/fixtures.ts'
import { CAVEAT, JANE_KEYS, setup } from './support.ts'

// `ac logout` from its own process: a uid-only frame that ends the window through the
// explicit path, replies with the re-signed address record or the subjects left out, and closes the agent.

const tmp = tempDir('lf')
afterAll(() => tmp.cleanup())
let n = 0
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})

const timers = { set: () => 1, clear: () => {} }
const signals = { on: () => 0, off: () => 0 }

/** A server on a socket of its own, its window opened through it unless `login` is false. */
async function boot(answers: string[] = [], login = true, expiry = new Map<string, number>()) {
  const terminal: Terminal = { print: () => {}, ask: async () => answers.shift() ?? 'n' }
  const { agent, clock } = setup({ login: false })
  const records = new Map<RecordKind, AcRecord>()
  const home = join(tmp.dir, `l${n++}`)
  const opts = { agent, clock, home, terminal, records, ended: () => {}, timers, signals, expiry }
  const server = new AgentServer(opts)
  servers.push(server)
  await server.listen()
  if (login) server.login(JANE_KEYS)
  const closed = once(server.listener, 'close')
  return { agent, clock, records, server, closed, client: new AgentClient(server.path) }
}

describe('AgentServer: the logout frame', () => {
  it('re-signs the address record with the live grant revoked, replies it, and closes', async () => {
    const m = await boot(['y'])
    m.records.set('address', addressRecord(P.jane, { revoked: [P.bob.address] }))
    expect(await m.client.grant(P.session.address, [CAVEAT], T0 + 1000)).toMatchObject({ ok: true })
    m.clock.advance(10)
    const reply = await m.client.logout()
    const revoked = [P.bob.address, P.session.address]
    expect(reply).toMatchObject({ ok: true, record: { revoked, iat: T0 + 10 } })
    await m.closed
    expect(m.records.get('address')).toEqual(reply.ok ? reply.record : null)
    expect(m.agent.windowEnd()).toBeNull()
  })

  it('flushes a reply larger than the socket buffer before it closes (1,000 revoked entries, about 70 KB)', async () => {
    const m = await boot(['y'])
    const many = Array.from({ length: 1000 }, (_, i) => `ed25519:${i.toString(16).padStart(64, '0')}`)
    m.records.set('address', addressRecord(P.jane, { revoked: many }))
    await m.client.grant(P.session.address, [CAVEAT], T0 + 1000)
    const reply = await m.client.logout()
    expect(reply.ok && reply.record?.revoked).toHaveLength(1001)
    await m.closed
  })

  it('replies a null record when there is nothing to revoke, and closes', async () => {
    const m = await boot([], false)
    expect(await m.client.logout()).toEqual({ ok: true, record: null })
    await m.closed
  })

  it('replies bad-record and the subjects left out when nothing is signed, on a second connection', async () => {
    const m = await boot(['y'])
    await m.client.grant(P.session.address, [CAVEAT], T0 + 1000)
    m.client.close()
    const reply = await new AgentClient(m.server.path).logout()
    expect(reply).toMatchObject({ ok: false, code: 'bad-record', unrevoked: [P.session.address] })
    expect(reply.ok ? '' : reply.detail).toMatch(/no address record/)
    await m.closed
  })
})

describe('the revoked cap through the logout frame', () => {
  const addr = (i: number): string => `ed25519:${i.toString(16).padStart(64, '0')}`
  const full = (k: number): string[] => Array.from({ length: k }, (_, i) => addr(i))

  it('signs 1,024 entries, and refuses 1,025 with every name and the held record kept', async () => {
    const at = await boot(['y'])
    at.records.set('address', addressRecord(P.jane, { revoked: full(1023) }))
    await at.client.grant(P.session.address, [CAVEAT], T0 + 1000)
    const signed = await at.client.logout()
    expect(signed.ok && signed.record?.revoked).toHaveLength(1024)
    const over = await boot(['y'])
    const held = addressRecord(P.jane, { revoked: full(1024) })
    over.records.set('address', held)
    await over.client.grant(P.session.address, [CAVEAT], T0 + 1000)
    const refused = await over.client.logout()
    expect(refused).toMatchObject({ ok: false, code: 'bad-record' })
    expect(refused.ok ? [] : refused.unrevoked).toHaveLength(1025)
    expect(refused.ok ? '' : refused.detail).toMatch(/too many revoked/)
    expect(over.records.get('address')).toBe(held)
    await over.closed
  })

  it('leaves the dated map unchanged when the cap refuses: no entry pruned for a record never signed', async () => {
    const old = P.bob.address
    const past = T0 - DEFAULT_TTL - DEFAULT_SKEW - 1
    const expiry = new Map([[old, past]])
    const m = await boot(['y'], true, expiry)
    m.records.set('address', addressRecord(P.jane, { revoked: full(1024) }))
    await m.client.grant(P.session.address, [CAVEAT], T0 + 1000)
    expect(await m.client.logout()).toMatchObject({ ok: false, code: 'bad-record' })
    expect([...expiry]).toEqual([
      [old, past],
      [P.session.address, T0 + 1000],
    ])
  })
})
