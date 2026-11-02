import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { Hop } from '@usebag/core'
import { generateEdgeKeys, HomeCustody } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { GRANT_RETRY_MS } from '../src/session.ts'
import { P, seededRng, T0, type TestServer } from './support/fixtures.ts'
import { type AgentHome, agentHome, CAVEAT, eventually, sessionServer } from './support/sessions.ts'

// --session's first start: the server makes the session's key, asks jane's agent for the first grant and
// answers every tool with the waiting line and the request code until the y; then it opens under the grant, which the
// agent renews. At close the key file goes and the state stays.

let h: AgentHome
let s: TestServer | null

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
  s = null
})

afterEach(async () => {
  await s?.close()
  await h.agent.close()
  h.tmp.cleanup()
})

const keyFile = (name: string): string => join(h.tmp.dir, 'keys', `${name}.json`)

describe('--session: the first start', () => {
  it('answers the waiting line with the request code until the y, then opens under the grant', async () => {
    s = await sessionServer(h, 's-one', 1)
    const server = s
    expect(existsSync(keyFile('s-one'))).toBe(true)
    await eventually('the prompt', async () => h.codes().length === 1)
    const [code] = h.codes()
    expect(h.printed).toContain(`grant to session ${new HomeCustody(h.tmp.dir).entry('s-one').address}`)
    await eventually('the code in the waiting line', async () => {
      const r = await server.call('status')
      return r.isError && String(r.value.detail).includes(`request ${code}`)
    })
    for (const tool of ['status', 'inbox', 'send']) {
      const args = tool === 'send' ? { to: [P.bob.address], type: 'chat.v1', body: 'early' } : {}
      expect(await server.call(tool, args)).toMatchObject({
        isError: true,
        value: { error: 'grant-pending', detail: `s-one: waiting for y at the agent, request ${code}` },
      })
    }
    h.type('y')
    await server.running.ready
    const status = await server.call('status')
    expect(status).toMatchObject({
      isError: false,
      value: { session: 's-one', desk: true, mailbox: P.jane.address },
    })
    expect(status.value.chain).toMatchObject({ source: 'agent', hops: 1 })
    const [hop] = JSON.parse(readFileSync(join(h.tmp.dir, 'state', 's-one', 'grant.json'), 'utf8')) as Hop[]
    expect(hop).toMatchObject({ iss: P.jane.address, caveats: [CAVEAT], exp: T0 + 28_800 })
  })

  it('removes its key file at close and keeps its state for the audit', async () => {
    s = await sessionServer(h, 's-one', 1)
    h.type('y')
    await s.running.ready
    await s.close()
    s = null
    expect(existsSync(keyFile('s-one'))).toBe(false)
    expect(existsSync(join(h.tmp.dir, 'state', 's-one', 'edge.sqlite'))).toBe(true)
    expect(existsSync(join(h.tmp.dir, 'state', 's-one', 'mcp.lock'))).toBe(false)
  })

  it('answers declined after a no at the agent, and removes its key at close', async () => {
    s = await sessionServer(h, 's-one', 1)
    h.type('n')
    await expect(s.running.ready).rejects.toMatchObject({ code: 'declined' })
    expect(await s.call('status')).toMatchObject({ isError: true, value: { error: 'declined' } })
    await s.close()
    s = null
    expect(existsSync(keyFile('s-one'))).toBe(false)
  })

  it('asks again while no agent window is open, and opens after ac login and a y', async () => {
    h.core.logout()
    s = await sessionServer(h, 's-one', 1)
    const server = s
    await eventually('the no-agent line', async () => {
      const r = await server.call('status')
      return String(r.value.detail).includes('run ac login')
    })
    expect(h.codes()).toEqual([])
    h.agent.login(P.jane.keys)
    h.timers.fire((ms) => ms === GRANT_RETRY_MS)
    await eventually('the prompt', async () => h.codes().length === 1)
    h.type('y')
    await server.running.ready
    expect((await server.call('status')).isError).toBe(false)
  })

  it('halves the life it asks for until the window admits it (a window shorter than 8 hours)', async () => {
    h.core.logout()
    h.agent.login(P.jane.keys, 3 * 3600)
    s = await sessionServer(h, 's-one', 1)
    h.type('y')
    await s.running.ready
    const [hop] = JSON.parse(readFileSync(join(h.tmp.dir, 'state', 's-one', 'grant.json'), 'utf8')) as Hop[]
    expect(hop?.exp).toBe(T0 + 7200)
    expect(h.codes()).toHaveLength(1)
  })

  it('refuses a second server of one session busy, before any prompt', async () => {
    s = await sessionServer(h, 's-one', 1)
    await expect(sessionServer(h, 's-one', 2)).rejects.toMatchObject({ code: 'busy' })
    h.type('y')
    await s.running.ready
    expect(h.codes()).toHaveLength(1)
    expect(existsSync(keyFile('s-one'))).toBe(true)
  })

  it('removes only a key file it made: one that was there already stays at close', async () => {
    new HomeCustody(h.tmp.dir).create('s-one', generateEdgeKeys(seededRng('mine')), { custody: 'file' })
    s = await sessionServer(h, 's-one', 1)
    h.type('y')
    await s.running.ready
    await s.close()
    s = null
    expect(existsSync(keyFile('s-one'))).toBe(true)
  })

  it('writes grant.json by a temporary file and a rename, mode 0600, leaving no temporary file', async () => {
    s = await sessionServer(h, 's-one', 1)
    h.type('y')
    await s.running.ready
    const dir = join(h.tmp.dir, 'state', 's-one')
    expect(statSync(join(dir, 'grant.json')).mode & 0o777).toBe(0o600)
    expect(readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([])
  })
})
