import { createConnection } from 'node:net'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { AcError, type AcRecord, type RecordKind, signRecord, verifyRecord } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient } from '../../src/agent/client.ts'
import { AgentError } from '../../src/agent/model.ts'
import { AgentServer, type Terminal } from '../../src/agent/server.ts'
import { addressRecord, keyRecord, P, T0, tempDir } from '../support/fixtures.ts'
import { CAVEAT, JANE_KEYS, setup } from './support.ts'

// `resign <kind>`: a uid-only frame; the agent re-signs the principal's held record of that
// kind with every member equal and `iat` moved, inside a window, once per half ttl.

const tmp = tempDir('rs')
afterAll(() => tmp.cleanup())
let n = 0
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})

/** A timer that never fires and signals that never arrive: the window's end and the process are not under test. */
const timers = { set: () => 1, clear: () => {} }
const signals = { on: () => 0, off: () => 0 }

/** A server on a socket of its own; `window` opens the window through the server, at the agent only, or not at all. */
async function boot(window: 'server' | 'agent' | 'none' = 'server', answers: string[] = []) {
  const terminal: Terminal = { print: () => {}, ask: async () => answers.shift() ?? 'n' }
  const { agent, clock } = setup({ login: window === 'agent' })
  const records = new Map<RecordKind, AcRecord>()
  const home = join(tmp.dir, `r${n++}`)
  const server = new AgentServer({ agent, clock, home, terminal, records, ended: () => {}, timers, signals })
  servers.push(server)
  await server.listen()
  if (window === 'server') server.login(JANE_KEYS)
  return { agent, clock, records, server, client: new AgentClient(server.path) }
}

/** One frame on a fresh connection, and the reply line. */
async function frame(path: string, line: string): Promise<unknown> {
  const socket = createConnection(path)
  socket.on('error', () => {})
  const lines = createInterface({ input: socket })[Symbol.asyncIterator]()
  await lines.next()
  socket.write(`${line}\n`)
  const reply = JSON.parse(String((await lines.next()).value))
  socket.destroy()
  return reply
}

/** A record without its signature. */
const members = (r: AcRecord): Record<string, unknown> => {
  const { sig: _sig, ...rest } = r
  return rest
}

/** An accept-from record of jane with a ttl of two hours, issued at T0. */
const accept = (): AcRecord =>
  signRecord(P.jane.signing, {
    kind: 'accept-from',
    owner: P.jane.address,
    roots: ['*'],
    max_bytes: 65_536,
    ttl: 7200,
    iat: T0,
  })

describe('AgentServer: resign', () => {
  it('re-signs the address record with every member equal and iat moved, once per half ttl', async () => {
    const m = await boot()
    const held = addressRecord(P.jane, { revoked: [P.bob.address], relays: ['http://r.test'] })
    m.records.set('address', held)
    await expect(m.client.resign('address')).rejects.toMatchObject({ code: 'rate-limited' })
    m.clock.advance(1799)
    await expect(m.client.resign('address')).rejects.toMatchObject({ code: 'rate-limited' })
    m.clock.advance(1)
    const record = await m.client.resign('address')
    expect(members(record)).toEqual({ ...members(held), iat: T0 + 1800 })
    expect(verifyRecord(record, T0 + 1800)).toEqual(record)
    expect(m.records.get('address')).toEqual(record)
    await expect(m.client.resign('address')).rejects.toMatchObject({ code: 'rate-limited' })
    m.clock.advance(1800)
    expect((await m.client.resign('address')).iat).toBe(T0 + 3600)
  })

  it('re-signs an accept-from record by its ttl and a key record by its life, exp kept', async () => {
    const m = await boot()
    m.records.set('accept-from', accept())
    m.records.set('key', keyRecord(P.jane, T0 + 3600))
    m.clock.advance(1799)
    for (const kind of ['accept-from', 'key'] as const) {
      await expect(m.client.resign(kind)).rejects.toMatchObject({ code: 'rate-limited' })
    }
    m.clock.advance(1)
    expect(await m.client.resign('key')).toMatchObject({ kind: 'key', iat: T0 + 1800, exp: T0 + 3600 })
    await expect(m.client.resign('accept-from')).rejects.toMatchObject({ code: 'rate-limited' })
    m.clock.advance(1800)
    expect(await m.client.resign('accept-from')).toMatchObject({ kind: 'accept-from', iat: T0 + 3600 })
  })

  it('refuses with no held record, a rotation, a record of another key, and outside a window', async () => {
    const m = await boot()
    await expect(m.client.resign('address')).rejects.toBeInstanceOf(AcError)
    m.records.set('address', addressRecord(P.jane, { rotated_from: P.org.address }))
    await expect(m.client.resign('address')).rejects.toMatchObject({ code: 'bad-record' })
    m.records.set('key', keyRecord(P.bob, T0 + 3600))
    m.clock.advance(1800)
    await expect(m.client.resign('key')).rejects.toMatchObject({ code: 'bad-key' })
    m.agent.logout()
    m.records.set('accept-from', accept())
    await expect(m.client.resign('accept-from')).rejects.toBeInstanceOf(AgentError)
    await expect(m.client.resign('accept-from')).rejects.toMatchObject({ code: 'agent-locked' })
  })

  it('leaves revoked exactly as held: a stale record and an expired grant keep their entries', async () => {
    const m = await boot('server', ['y', 'y'])
    const S = P.session.address
    const [B, M] = [P.bob.address, P.mallory.address]
    m.records.set('address', addressRecord(P.jane, { iat: T0 - 30_000, revoked: [S, B, M] }))
    expect(await m.client.resign('address')).toMatchObject({ revoked: [S, B, M], iat: T0 })
    await m.client.grant(S, [CAVEAT], T0 + 1000)
    await m.client.grant(B, [CAVEAT], T0 + 5000)
    m.clock.advance(3600)
    expect(await m.client.resign('address')).toMatchObject({ revoked: [S, B, M], iat: T0 + 3600 })
  })

  it('answers a frame that is not [kind] with bad-shape', async () => {
    const m = await boot()
    for (const args of ['"nope"', '[]', '["x"]', '[1]', '[["address"]]']) {
      const reply = await frame(m.server.path, `{"op":"resign","args":${args}}`)
      expect(reply).toEqual({ ok: false, code: 'bad-shape' })
    }
    expect(await frame(m.server.path, '{"op":"resign"}')).toEqual({ ok: false, code: 'bad-shape' })
  })

  it('is agent-locked when the server holds no window: not opened through it, or logged out', async () => {
    const here = await boot('agent')
    here.records.set('address', addressRecord(P.jane))
    here.clock.advance(1800)
    await expect(here.client.resign('address')).rejects.toMatchObject({ code: 'agent-locked' })
    const none = await boot('none')
    none.records.set('address', addressRecord(P.jane))
    none.clock.advance(1800)
    await expect(none.client.resign('address')).rejects.toMatchObject({ code: 'agent-locked' })
    const out = await boot()
    out.records.set('address', addressRecord(P.jane))
    out.clock.advance(1800)
    out.server.logout()
    await expect(out.client.resign('address')).rejects.toMatchObject({ code: 'agent-locked' })
  })
})
