import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { CallToolRequest, CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { HomeCustody } from '@usebag/edge'
import { codexSessionName } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config.ts'
import { startSession } from '../src/session.ts'
import { type Outcome, P, RELAY, seededRng, type TestServer } from './support/fixtures.ts'
import { type AgentHome, agentHome, CAVEAT, eventually, sessionServer } from './support/sessions.ts'

// --session auto:codex: the server starts unbound and takes its name from the first tools/call whose _meta
// carries Codex's sessionId (else its threadId): codexSessionName(jane's address, id), the name the wake hook
// derives from the hook's session_id, so that equality is the seam. From then on it is a fixed-name session; a call
// from another Codex session, or with no usable id before the bind, is refused and changes nothing.

const ID = '7f3a9c1e-2b4d-4e6f-8a0b-1c2d3e4f5a6b'
const OTHER = '0d1e2f3a-4b5c-4d6e-9f70-8192a3b4c5d6'
const THIRD = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'

let h: AgentHome
let servers: TestServer[]

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
  servers = []
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  await h.agent.close()
  h.tmp.cleanup()
})

const nameOf = (id: string): string => codexSessionName(P.jane.address, id)

async function codex(pid = 1): Promise<TestServer> {
  const s = await sessionServer(h, 'auto:codex', pid)
  servers.push(s)
  return s
}

async function close(s: TestServer): Promise<void> {
  servers.splice(servers.indexOf(s), 1)
  await s.close()
}

/** A tool call with `meta` as its _meta (none when undefined), as Codex makes one. */
async function call(
  s: TestServer,
  tool: string,
  meta?: Record<string, unknown>,
  args: Record<string, unknown> = {},
): Promise<Outcome> {
  const params = {
    name: tool,
    arguments: args,
    ...(meta === undefined ? {} : { _meta: meta as CallToolRequest['params']['_meta'] }),
  }
  const result = (await s.client.callTool(params)) as CallToolResult
  const value = JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>
  return { isError: result.isError === true, value, result }
}

/** The session names that have a key file or a state directory in the home. */
function made(): string[] {
  const of = (dir: string): string[] =>
    (existsSync(dir) ? readdirSync(dir) : [])
      .filter((f) => f.startsWith('s-'))
      .map((f) => f.replace(/\.json$/, ''))
  return [...new Set([...of(join(h.tmp.dir, 'keys')), ...of(join(h.tmp.dir, 'state'))])].sort()
}

/** The waiting line of the session named for `id`. */
const pending = (id: string) => ({
  error: 'grant-pending',
  detail: expect.stringMatching(`^${nameOf(id)}: `),
})

const WAY_OUT = /rust-v0\.123\.0 or later sends; or start the server with --session <name>$/

describe('--session auto:codex: the bind at the first tool call', () => {
  it('starts unbound: no name, lock, key file or grant request until a call carries an id', async () => {
    const s = await codex()
    await new Promise((r) => setTimeout(r, 20))
    expect(made()).toEqual([])
    expect(h.codes()).toEqual([])
    expect(() => s.running.opened).toThrow(/^no-session: not named before Codex's first tool call; /)
  })

  it('binds from _meta.sessionId, preferred to threadId: the name is codexSessionName(the principal, id)', async () => {
    const s = await codex()
    const first = await call(s, 'status', { sessionId: ID, threadId: OTHER })
    expect(first).toMatchObject({ isError: true, value: pending(ID) })
    expect(nameOf(ID)).not.toBe(nameOf(OTHER))
    expect(made()).toEqual([nameOf(ID)])
    await eventually('the prompt', async () => h.codes().length === 1)
    expect(h.printed).toContain(`grant to session ${new HomeCustody(h.tmp.dir).entry(nameOf(ID)).address}`)
    const [code] = h.codes()
    expect((await call(s, 'status', { sessionId: ID })).value).toEqual({
      error: 'grant-pending',
      detail: `${nameOf(ID)}: waiting for y at the agent, request ${code}`,
    })
    h.type('y')
    await s.running.ready
    expect((await call(s, 'status', { sessionId: ID })).value).toMatchObject({
      session: nameOf(ID),
      desk: true,
      mailbox: P.jane.address,
    })
    expect(existsSync(join(h.tmp.dir, 'state', nameOf(ID), 'grant.json'))).toBe(true)
  })

  it('binds from _meta.threadId when the call has no sessionId (Codex rust-v0.123.0 to v0.155.0)', async () => {
    const s = await codex()
    expect((await call(s, 'inbox', { threadId: ID, progressToken: 1 })).value).toMatchObject(pending(ID))
    expect(made()).toEqual([nameOf(ID)])
  })

  it('binds from _meta.threadId when sessionId is null', async () => {
    const s = await codex()
    expect((await call(s, 'status', { sessionId: null, threadId: ID })).value).toMatchObject(pending(ID))
    expect(made()).toEqual([nameOf(ID)])
  })

  it('refuses a first call with no usable id, names the way out, and makes nothing', async () => {
    const s = await codex()
    for (const meta of [
      undefined,
      { progressToken: 'p' },
      { sessionId: 'x', threadId: ID },
      { threadId: 42 },
    ]) {
      const r = await call(s, 'status', meta)
      expect(r).toMatchObject({ isError: true, value: { error: 'no-session' } })
      expect(r.value.detail).toMatch(WAY_OUT)
    }
    expect((await call(s, 'status')).value.detail).toMatch(
      /^this call's _meta has no sessionId or threadId; /,
    )
    expect((await call(s, 'status', { sessionId: 'x' })).value.detail).toMatch(
      /^a Codex session id is a uuid, not "x"; --session auto:codex takes its name /,
    )
    expect(made()).toEqual([])
    expect(h.codes()).toEqual([])
    expect((await call(s, 'status', { sessionId: ID })).value).toMatchObject(pending(ID))
    expect(made()).toEqual([nameOf(ID)])
  })

  it('serves its own session after the bind: the same id or none; another id is refused busy, changing nothing', async () => {
    const s = await codex()
    await call(s, 'status', { sessionId: ID })
    expect(await call(s, 'status', { sessionId: OTHER, threadId: ID })).toMatchObject({
      isError: true,
      value: {
        error: 'busy',
        detail:
          `this server serves Codex session ${ID} (${nameOf(ID)}), not ${OTHER}: one server serves one Codex ` +
          'session; restart Codex, or start the server with --session <name>',
      },
    })
    expect((await call(s, 'status', { sessionId: 'nope' })).value.error).toBe('no-session')
    for (const meta of [undefined, { sessionId: ID.toUpperCase() }, { threadId: ID }])
      expect((await call(s, 'status', meta)).value).toMatchObject(pending(ID))
    expect(made()).toEqual([nameOf(ID)])
    h.type('y')
    await s.running.ready
    expect((await call(s, 'status', { sessionId: OTHER })).value.error).toBe('busy')
    expect((await call(s, 'status', { sessionId: ID })).isError).toBe(false)
    expect(h.codes()).toHaveLength(1)
  })

  it('binds once when two first calls come at once, and to one session when their ids differ', async () => {
    const s = await codex(1)
    const same = await Promise.all([
      call(s, 'status', { sessionId: ID }),
      call(s, 'inbox', { sessionId: ID }),
    ])
    for (const r of same) expect(r.value).toMatchObject(pending(ID))
    expect(made()).toEqual([nameOf(ID)])
    await eventually('the prompt', async () => h.codes().length === 1)
    await new Promise((r) => setTimeout(r, 20))
    expect(h.codes()).toHaveLength(1)
    const t = await codex(2)
    const raced = await Promise.all([
      call(t, 'status', { sessionId: OTHER }),
      call(t, 'status', { sessionId: THIRD }),
    ])
    expect(raced.map((r) => r.value.error).sort()).toEqual(['busy', 'grant-pending'])
    const won = raced[0]?.value.error === 'grant-pending' ? OTHER : THIRD
    expect(made()).toEqual([nameOf(ID), nameOf(won)].sort())
  })

  it('binds at whatever tool Codex calls first', async () => {
    const calls: [string, Record<string, unknown>][] = [
      ['send', { to: [P.bob.address], type: 'chat.v1', body: 'early' }],
      ['inbox', {}],
      ['wait', {}],
      ['ask', { to: P.bob.address, body: 'q' }],
      ['handoff', { to: P.bob.address, threads: ['ab'.repeat(32)] }],
      ['status', {}],
      ['lookup', { address: P.bob.address }],
    ]
    for (const [i, [tool, args]] of calls.entries()) {
      const s = await codex(10 + i)
      const r = await call(s, tool, { sessionId: ID }, args)
      expect([tool, r.value]).toMatchObject([tool, pending(ID)])
      expect(made()).toEqual([nameOf(ID)])
      await close(s)
    }
  })
})

describe('--session auto:codex: failures, close and regrant', () => {
  it('leaves no lock of its own after a bind refused busy, and binds at a later call once the holder is gone', async () => {
    const a = await codex(1)
    await call(a, 'status', { sessionId: ID })
    const b = await codex(2)
    expect((await call(b, 'status', { sessionId: ID })).value).toMatchObject({
      error: 'busy',
      detail: expect.stringContaining('the MCP server with pid 1 holds this identity'),
    })
    expect(() => b.running.opened).toThrow(/^no-session: not named/)
    const lock = join(h.tmp.dir, 'state', nameOf(ID), 'mcp.lock')
    expect(JSON.parse(readFileSync(lock, 'utf8'))).toEqual({ pid: 1 })
    await close(a)
    expect(existsSync(lock)).toBe(false)
    expect((await call(b, 'status', { sessionId: ID })).value).toMatchObject(pending(ID))
    expect(JSON.parse(readFileSync(lock, 'utf8'))).toEqual({ pid: 2 })
  })

  it('closes unbound: the stop settles, the start rejects busy, and nothing was made', async () => {
    const s = await codex()
    const ready = s.running.ready
    await close(s)
    await expect(ready).rejects.toMatchObject({
      code: 'busy',
      message: 'busy: the server closed before its first tool call',
    })
    expect(made()).toEqual([])
  })

  it('refuses a bind after close, making nothing', async () => {
    const args = ['--session', 'auto:codex', '--principal', 'jane', '--grant-caveat', CAVEAT]
    const config = parseConfig([...args, '--dir', h.tmp.dir, '--relay', RELAY], {})
    if (config === 'help') throw new Error('unexpected help')
    const deps = { clock: h.clock, rng: seededRng('closed'), timers: h.timers, pid: 1, alive: () => true }
    const session = startSession(config, deps)
    session.close()
    expect(() => session.bind({ sessionId: ID })).toThrow('busy: the server is closing')
    await expect(session.granted).rejects.toMatchObject({ code: 'busy' })
    expect(made()).toEqual([])
  })

  it('asks a new grant after a new login, under its bound name, as a fixed name does', async () => {
    const s = await codex()
    await call(s, 'status', { sessionId: ID })
    h.type('y')
    await s.running.ready
    h.core.logout()
    h.agent.login(P.jane.keys)
    s.running.opened.agent?.probe()
    await eventually('the new request', async () => {
      const r = await call(s, 'status', { sessionId: ID })
      return r.value.error === 'grant-pending' && h.codes().length === 2
    })
    h.type('y')
    await eventually('open again', async () => !(await call(s, 'status', { sessionId: ID })).isError)
    expect((await call(s, 'status', { sessionId: ID })).value.session).toBe(nameOf(ID))
  })

  it('leaves a fixed name as it was: its calls bind nothing, whatever their _meta', async () => {
    const s = await sessionServer(h, 's-one', 1)
    servers.push(s)
    expect((await call(s, 'status', { sessionId: ID })).value).toMatchObject({
      error: 'grant-pending',
      detail: expect.stringMatching(/^s-one: /),
    })
    expect(made()).toEqual(['s-one'])
  })
})
