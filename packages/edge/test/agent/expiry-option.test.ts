import { join } from 'node:path'
import { type AcRecord, DEFAULT_SKEW, DEFAULT_TTL, type RecordKind } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient, AgentServer, type Terminal } from '../../src/agent/index.ts'
import { addressRecord, P, T0, tempDir } from '../support/fixtures.ts'
import { CAVEAT, JANE_KEYS, setup } from './support.ts'

// AgentServerOptions.expiry: the hop exps a caller kept from earlier windows date the `revoked`
// entries at logout, and this window's grants are noted into the same map, for the caller to keep.

const tmp = tempDir('ex')
afterAll(() => tmp.cleanup())
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})

describe('AgentServer: a caller-kept map of hop exps', () => {
  it('drops an entry it dates past exp + TTL + skew, keeps an undated one, and notes its grants in the map', async () => {
    const terminal: Terminal = { print: () => {}, ask: async () => 'y' }
    const { agent, clock } = setup({ login: false })
    const records = new Map<RecordKind, AcRecord>()
    const [old, manual] = [P.bob.address, P.mallory.address]
    const expiry = new Map([[old, T0 - DEFAULT_TTL - DEFAULT_SKEW - 1]])
    const timers = { set: () => 1, clear: () => {} }
    const signals = { on: () => 0, off: () => 0 }
    const home = join(tmp.dir, 'h')
    const opts = { agent, clock, home, terminal, records, ended: () => {}, expiry, timers, signals }
    const server = new AgentServer(opts)
    servers.push(server)
    await server.listen()
    server.login(JANE_KEYS)
    records.set('address', addressRecord(P.jane, { revoked: [old, manual] }))
    const client = new AgentClient(server.path)
    expect(await client.grant(P.session.address, [CAVEAT], T0 + 600)).toMatchObject({ ok: true })
    client.close()
    expect(expiry.get(P.session.address)).toBe(T0 + 600)
    expect(server.logout()?.revoked).toEqual([manual, P.session.address])
  })
})
