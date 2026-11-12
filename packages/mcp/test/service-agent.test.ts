import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { parseEnvelope, serializeRecord } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { Service } from '../src/service.ts'
import { runPaths } from '../src/socket.ts'
import { acceptFrom, fakeRecords, MemoryLog, P, RELAY, seededRng } from './support/fixtures.ts'
import { type AgentHome, agentHome, CAVEAT } from './support/sessions.ts'

// The bag service's agent identity end to end, with W1's real openAgentUnit and the fake agent of the session tests
// (agentHome: an AgentServer on <home>/agent.sock holding jane, whose terminal the test types y into): the first bind
// opens the unit (one y) and asks the window's grant (one y), and a send goes out under the window's grant.

type Json = Record<string, unknown>

async function until(test: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

const codeOf = (r: Json): unknown => ((r.error as Json | undefined)?.data as Json | undefined)?.code

let h: AgentHome
let service: Service | null = null
const sockets: Socket[] = []

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
})

afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  await service?.drain()
  service = null
  await h.agent.close()
  h.tmp.cleanup()
})

async function line(sock: string) {
  const socket = createConnection(sock)
  sockets.push(socket)
  await new Promise<void>((r) => socket.once('connect', () => r()))
  const waiters = new Map<number, (m: Json) => void>()
  let buf = ''
  socket.on('data', (b: Buffer) => {
    buf += b.toString()
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const m = JSON.parse(buf.slice(0, i)) as Json
      buf = buf.slice(i + 1)
      if (typeof m.id === 'number') waiters.get(m.id)?.(m)
    }
  })
  let id = 0
  const request = (method: string, params: Json = {}): Promise<Json> =>
    new Promise((resolve) => {
      const n = ++id
      waiters.set(n, resolve)
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: n, method, params })}\n`)
    })
  const call = async (name: string, args: Json = {}): Promise<Json> => {
    const r = (await request('tools/call', { name, arguments: args })).result as {
      content: { text: string }[]
    }
    return JSON.parse(r.content[0]?.text ?? '{}') as Json
  }
  return { request, call }
}

describe("an agent identity in the service, through W1's openAgentUnit and a real agent", () => {
  /** The service of agentHome's home holding jane (agent custody); `alive` counts this service's pid alive. */
  async function startJane(
    alive: (pid: number) => boolean = (pid) => pid === 4242,
    more: readonly Json[] = [],
    drainCallsMs?: number,
  ): Promise<Service> {
    const home = h.tmp.dir
    await h.relay.publish(RELAY, serializeRecord(acceptFrom(P.bob)))
    const file = join(home, 'identities.json')
    const entry = { label: 'jane', key: 'jane', home, relays: [RELAY], trust_roots: [P.bob.address] }
    const identities = [{ ...entry, grant_caveats: [CAVEAT] }, ...more.map((m) => ({ ...m, home }))]
    writeFileSync(file, JSON.stringify({ version: 1, identities }), {
      mode: 0o600,
    })
    const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
    service = await Service.start(config, home, {
      clock: h.clock,
      rng: seededRng('svc-agent'),
      relayFor: () => h.relay,
      records: fakeRecords(new Map()),
      timers: h.timers,
      pid: 4242,
      alive,
      log: new MemoryLog(),
      resubscribeDelayMs: () => 0,
      helloMs: 2000,
      ...(drainCallsMs === undefined ? {} : { drainCallsMs }),
    })
    await service.opening
    return service
  }

  /** A hello with an input hook and the typed bind of jane; the bind's answer. */
  async function bindJane(s: Service) {
    const l = await line(runPaths(h.tmp.dir).sock)
    const token = s.token.toString('hex')
    await l.request('service/hello', { contract: 1, token, host: 'claude-code', cwd: '/w', input_hook: true })
    return { l, bound: await l.request('service/use', { label: 'jane', via: 'typed' }) }
  }

  const settle = async (): Promise<void> => {
    for (let i = 0; i < 10; i++) {
      h.timers.fire()
      await new Promise((r) => setTimeout(r, 20))
    }
  }

  it('the first bind opens the unit and asks the window its grant (two y), and a send goes out under the grant', async () => {
    const s = await startJane()
    expect(s.unit('jane')?.opened).toBeNull()
    const { l, bound } = await bindJane(s)
    expect(bound.result).toMatchObject({
      bound: true,
      custody: 'agent',
    })
    // The window's grant and the unit's open: one y each at the agent's terminal.
    h.type('y')
    h.type('y')
    const conn = [...s.connections][0] as Parameters<typeof s.table.grantOf>[0]
    const grant = await s.table.grantOf(conn, 'jane')
    const end = Date.now() + 5000
    while (s.unit('jane')?.opened === null) {
      if (Date.now() > end) throw new Error(`the unit did not open: ${String(s.unit('jane')?.failure)}`)
      await new Promise((r) => setTimeout(r, 20))
    }
    expect(h.codes()).toHaveLength(2)
    expect(s.unit('jane')?.config.as).toBe('jane.service')
    const before = new Set(h.relay.envelopes.keys())
    const r = await l.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(r.error, JSON.stringify(r)).toBeUndefined()
    const key = [...h.relay.envelopes.keys()].find((k) => !before.has(k)) as string
    const env = parseEnvelope(h.relay.envelopes.get(key) as Uint8Array)
    expect(env.from).toBe(grant.keys.signing.address)
    expect(env.auth.map((x) => [x.iss, x.sub])).toEqual([[P.jane.address, grant.keys.signing.address]])
    // The open took no second lock (its session holds it, this service's pid alive), and no third y ever comes.
    await settle()
    expect((await l.call('status')).error).toBeUndefined()
    expect(h.codes()).toHaveLength(2)
  })

  it('a local failure asks the agent nothing: a lock held by another live process, a foreign key file', async () => {
    const home = h.tmp.dir
    mkdirSync(join(home, 'state', 'jane.service'), { recursive: true })
    writeFileSync(
      join(home, 'state', 'jane.service', 'mcp.lock'),
      JSON.stringify({ pid: 999, started_at: new Date(0).toISOString() }),
    )
    const s = await startJane((pid) => pid === 4242 || pid === 999)
    const { l } = await bindJane(s)
    await settle()
    expect(String(s.unit('jane')?.failure)).toContain('held by another process (pid 999)')
    expect(JSON.stringify(await l.call('status'))).toContain('held by another process')
    expect(h.codes()).toHaveLength(0)
    // The lock gone, a key file that is not this service's marked session key: still nothing asked.
    unlinkSync(join(home, 'state', 'jane.service', 'mcp.lock'))
    writeFileSync(join(home, 'keys', 'jane.service.json'), readFileSync(join(home, 'keys', 'bob.json')))
    await l.request('service/unbind', {})
    await l.request('service/use', { label: 'jane', via: 'typed' })
    await settle()
    expect(String(s.unit('jane')?.failure)).toContain("is not this service's session key")
    expect(h.codes()).toHaveLength(0)
  })

  it('during a drain a bind of the agent identity, typed or by dialog, answers draining and asks the agent nothing', async () => {
    // bob, a key-file identity of the same home, holds the drain open with a wait in flight (its timer is manual).
    const bob = { label: 'bob', key: 'bob', relays: [RELAY], trust_roots: [P.jane.address] }
    const s = await startJane(undefined, [bob], 1500)
    const hello = async (): Promise<Awaited<ReturnType<typeof line>>> => {
      const l = await line(runPaths(h.tmp.dir).sock)
      await l.request('service/hello', {
        contract: 1,
        token: s.token.toString('hex'),
        host: 'claude-code',
        cwd: '/w',
        input_hook: true,
        client_capabilities: { elicitation: { form: {} } },
      })
      return l
    }
    const b = await hello()
    expect((await b.request('service/use', { label: 'bob', via: 'typed' })).result).toMatchObject({
      as: 'bob',
    })
    const waiting = b.call('wait', { timeout_s: 60 })
    await until(() => s.calls() === 1)
    const a = await hello()
    const drained = s.drain()
    await until(() => s.draining)
    for (const via of ['typed', 'dialog']) {
      const r = await a.request('service/use', { label: 'jane', via })
      expect([via, codeOf(r)]).toEqual([via, 'draining'])
    }
    // The use tool's dialog path (an MCP call, past the socket's service/ refusal) answers draining too.
    const tool = await a.call('use', { name: 'jane' })
    expect(tool).toMatchObject({ error: 'draining' })
    expect(await s.ensureOpen('jane')).toBe(false)
    await waiting
    await drained
    service = null
    expect(h.codes()).toHaveLength(0)
    expect(h.printed.filter((x) => x.startsWith('request '))).toEqual([])
  })

  it('an unknown identity, and a lock naming a dead pid: nothing asked, and the dead holder does not count', async () => {
    const home = h.tmp.dir
    mkdirSync(join(home, 'state', 'jane.service'), { recursive: true })
    writeFileSync(join(home, 'state', 'jane.service', 'mcp.lock'), JSON.stringify({ pid: 999 }))
    const s = await startJane()
    const { l } = await bindJane(s)
    expect(codeOf(await l.request('service/use', { label: 'nobody', via: 'typed' }))).toBe('unknown-identity')
    // pid 999 is dead: the bind opens jane as if no lock were there (two y's), and a send goes out.
    h.type('y')
    h.type('y')
    const end = Date.now() + 5000
    while (s.unit('jane')?.opened === null) {
      if (Date.now() > end) throw new Error(`the unit did not open: ${String(s.unit('jane')?.failure)}`)
      await new Promise((r) => setTimeout(r, 20))
    }
    const r = await l.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(r.error, JSON.stringify(r)).toBeUndefined()
    expect(h.codes()).toHaveLength(2)
  })
})
