import { once } from 'node:events'
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { parseRecord } from '@usebag/core'
import { INCOMPLETE_REVOCATION, RelayError } from '@usebag/edge'
import { Agent, AgentAudit, AgentServer } from '@usebag/edge/agent'
import { afterAll, afterEach, describe, expect, it, onTestFinished } from 'vitest'
import { agentHome, CAVEAT, loggedIn, publishRecord, RELAY } from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// ac logout: the agent's window ended from another process; the re-signed address
// record published at the relays it names, and every failure reported.

const tmp = tempDir('logout')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
const dir = (): string => join(tmp.dir, `h${n++}`)
const S = `ed25519:${'cd'.repeat(32)}`
const OTHER = 'http://127.0.0.1:8'

/** A window with one first grant to S, and the io that asked for it. */
async function granted(relay: MemoryRelay, h: ReturnType<typeof agentHome>) {
  const login = await loggedIn(relay, h)
  login.io.lines.push('y')
  const io = testIo(relay)
  const args = ['--as', 'jane', '--session', S, '--caveat', CAVEAT, '--exp', '+60', '--dir', h.dir]
  const g = await cli(io, 'grant', ...args)
  expect(g.code).toBe(0)
  return { login, io, logout: () => cli(io, 'logout', '--as', 'jane', '--dir', h.dir) }
}

describe('ac logout', () => {
  it('is agent-locked when no agent listens', async () => {
    const h = agentHome(dir())
    expect((await cli(testIo(new MemoryRelay()), 'logout', '--as', 'jane', '--dir', h.dir)).err).toEqual([
      `bag: agent-locked: no agent listens at ${join(h.dir, 'agent.sock')}: run ac login`,
    ])
  })

  it('prints nothing to revoke while an agent still listens with no window, before its close', async () => {
    const h = agentHome(dir())
    const io = testIo(new MemoryRelay())
    const sink = { append: () => {}, last: () => null, read: () => [] }
    const audit = new AgentAudit(sink, io.clock)
    const agent = new Agent({ principal: h.address, clock: io.clock, rng: io.rng, audit, evaluators: [] })
    const terminal = { print: () => {}, ask: async () => '' }
    const quiet = { timers: { set: () => 1, clear: () => {} }, signals: { on: () => 0, off: () => 0 } }
    const records = new Map()
    const opts = { agent, clock: io.clock, home: h.dir, terminal, records, ended: () => {}, ...quiet }
    const server = new AgentServer(opts)
    onTestFinished(() => server.close())
    await server.listen()
    const closed = once(server.listener, 'close')
    const r = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    expect(r).toEqual({ code: 0, out: ['logout: nothing to revoke'], err: [] })
    await closed
  })

  it('is agent-locked after the agent closed at the end of its window', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const login = await loggedIn(relay, h)
    process.emit('SIGHUP')
    expect((await login.ran).code).toBe(0)
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).err).toEqual([
      `bag: agent-locked: no agent listens at ${join(h.dir, 'agent.sock')}: run ac login`,
    ])
  })

  it('keeps the record, 0600, with the line to publish it again, when no relay took it', async () => {
    // The epoch at login re-signed the held record one second past its iat, so the logout's record is T0 + 2.
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h, { relays: [RELAY, OTHER] })
    const w = await granted(relay, h)
    relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'no answer'))
    relay.failRecordPublish.set(OTHER, Object.assign(new Error('down'), { code: 'unreachable' }))
    const file = join(h.dir, `logout-record-${T0 + 2}.json`)
    expect(await w.logout()).toEqual({
      code: 1,
      out: [
        `failed address ${h.address} iat ${T0 + 2} ${RELAY} error`,
        `incomplete revocation ${h.address} ${RELAY} error: ${INCOMPLETE_REVOCATION}`,
        `failed address ${h.address} iat ${T0 + 2} ${OTHER} unreachable`,
        `incomplete revocation ${h.address} ${OTHER} unreachable: ${INCOMPLETE_REVOCATION}`,
      ],
      err: [
        `bag: the logout record is kept in ${file}; it revokes ${S}`,
        `bag: publish it again: ac publish ${RELAY} ${file}`,
        `bag: publish it again: ac publish ${OTHER} ${file}`,
      ],
    })
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(parseRecord(readFileSync(file))).toMatchObject({ revoked: [S], iat: T0 + 2 })
    expect((await w.login.ran).code).toBe(0)
  })

  it('keeps every record no relay took, one file each: a second logout overwrites none', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'no answer'))
    const first = await granted(relay, h)
    expect((await first.logout()).code).toBe(1)
    await first.login.ran
    const second = await loggedIn(relay, h)
    second.io.time.now = T0 + 100
    second.io.lines.push('y')
    const io = testIo(relay)
    io.time.now = T0 + 100
    const args = ['--as', 'jane', '--session', S, '--caveat', CAVEAT, '--exp', '+60', '--dir', h.dir]
    expect((await cli(io, 'grant', ...args)).code).toBe(0)
    expect((await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(1)
    await second.ran
    const kept = [T0 + 1, T0 + 100].map((iat) => readFileSync(join(h.dir, `logout-record-${iat}.json`)))
    expect(kept.map((bytes) => parseRecord(bytes).iat)).toEqual([T0 + 1, T0 + 100])
  })

  it('exits 1 when one relay of two did not take the record, and keeps it for that one', async () => {
    // The epoch at login re-signed the held record one second past its iat, so the logout's record is T0 + 2.
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h, { relays: [RELAY, OTHER] })
    const w = await granted(relay, h)
    relay.failRecordPublish.set(OTHER, new RelayError('rate-limited', 429, 30, 'slow down'))
    const r = await w.logout()
    expect(r.code).toBe(1)
    expect(r.out).toEqual([
      `published address ${h.address} iat ${T0 + 2} ${RELAY}`,
      `failed address ${h.address} iat ${T0 + 2} ${OTHER} rate-limited`,
      `incomplete revocation ${h.address} ${OTHER} rate-limited: ${INCOMPLETE_REVOCATION}`,
    ])
    const file = join(h.dir, `logout-record-${T0 + 2}.json`)
    expect(r.err.at(-1)).toBe(`bag: publish it again: ac publish ${OTHER} ${file}`)
    await w.login.ran
  })

  it('refuses a record that names no relay, and keeps it', async () => {
    // The epoch at login re-signed the held record one second past its iat, so the logout's record is T0 + 2.
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h, { relays: [] })
    const w = await granted(relay, h)
    const file = join(h.dir, `logout-record-${T0 + 2}.json`)
    expect((await w.logout()).err).toEqual([
      `bag: the logout record is kept in ${file}; it revokes ${S}`,
      `bag: no-relays: the address record of ${h.address} names no relay`,
    ])
    await w.login.ran
  })

  it('reports the subjects the agent could not revoke, and publishes nothing', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    const full = Array.from({ length: 1024 }, (_, i) => `ed25519:${i.toString(16).padStart(64, '0')}`)
    publishRecord(relay, h, { revoked: full })
    const w = await granted(relay, h)
    relay.published.length = 0
    const r = await w.logout()
    expect(r.code).toBe(1)
    expect(r.err[0]).toMatch(/^bag: bad-record: revoke: too many revoked for one record; not revoked/)
    expect(r.err[0]).toContain(S)
    expect(relay.published).toEqual([])
    await w.login.ran
  })
})
