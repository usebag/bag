import { request, Server } from 'node:http'
import type { SessionHandler } from '@usebag/edge'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { A2A_TYPE, MAX_RPC_BYTES, responseBody } from '../src/binding.ts'
import {
  A2aBridge,
  type A2aBridgeOptions,
  type BridgeEdge,
  DEFAULT_PORT,
  endpointUrl,
} from '../src/bridge.ts'
import type { CardRecord } from '../src/card.ts'
import { success } from '../src/jsonrpc.ts'
import { textOf } from '../src/protocol.ts'
import { type A2aHandler, type A2aServerOptions, type AgentEdge, a2aSessionHandler } from '../src/server.ts'
import { AGENT, CLIENT, inbound, OTHER, say, server } from './support.ts'

// The bridge over real HTTP on 127.0.0.1, its edge a loop in memory: what the bridge sends is delivered to the agent's
// session handler as the opened message, and the agent's reply to the bridge's session, as an edge and a relay would.

type Sent = Parameters<BridgeEdge['send']>[0]
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

const bridges: A2aBridge[] = []
afterEach(async () => {
  for (const b of bridges.splice(0)) await b.close()
})

/** The records the fake edge's resolver answers with, by address: a record, null, or an error it throws. */
const records = new Map<string, CardRecord | null | Error>([
  [AGENT, { key: AGENT, relays: ['https://relay.test'] }],
])

/** A bridge on a free port whose sends `answer` handles. */
async function bridgeOn(
  answer: (input: Sent, handler: SessionHandler) => void | Promise<void>,
  options: Omit<A2aBridgeOptions, 'edge'> = {},
): Promise<{ readonly bridge: A2aBridge; readonly sent: Sent[] }> {
  const sent: Sent[] = []
  let handler: SessionHandler | null = null
  const edge: BridgeEdge = {
    attach: (h) => {
      handler = h
    },
    send: async (input) => {
      sent.push(input)
      await answer(input, handler as unknown as SessionHandler)
      return { id: 'd'.repeat(64) }
    },
    resolver: {
      address: async (address) => {
        const r = records.get(address) ?? null
        if (r instanceof Error) throw r
        return r
      },
    },
  }
  const bridge = await A2aBridge.start({ edge, port: 0, ...options })
  bridges.push(bridge)
  return { bridge, sent }
}

/** A bridge whose sends reach an A2A server through a2aSessionHandler and come back as its replies. */
function loop(
  handler: A2aHandler,
  o: Partial<A2aServerOptions> = {},
  b: Omit<A2aBridgeOptions, 'edge'> = {},
) {
  const agent = server({ handler, ...o })
  return bridgeOn((input, bridgeHandler) => {
    const agentEdge: AgentEdge = {
      reply: async (m, reply) => {
        const thread = { id: m.thread.id, prev: [m.id] }
        const answer = inbound({ ...reply, principal: AGENT, from: AGENT, to: [CLIENT], thread })
        setImmediate(() => bridgeHandler.deliver(answer))
      },
    }
    const opened = inbound({ type: input.type, body: input.body, thread: { ...input.thread, prev: [] } })
    setImmediate(() => a2aSessionHandler(agentEdge, agent).deliver(opened))
  }, b)
}

const rpc = (method: string, params: Record<string, unknown>, id: number | string = 1): string =>
  JSON.stringify({ jsonrpc: '2.0', id, method, params })

const A2A_HEADERS = { 'content-type': 'application/json', 'a2a-version': '1.0' }

async function post(
  url: string,
  body: string,
  headers: Record<string, string> = A2A_HEADERS,
): Promise<{ readonly status: number; readonly json: Record<string, unknown> }> {
  const res = await fetch(url, { method: 'POST', headers, body })
  return { status: res.status, json: (await res.json()) as Record<string, unknown> }
}

/** One request with node:http, whose Host and Origin headers are the caller's to set (fetch sets its own Host). */
function raw(
  url: string,
  method: string,
  headers: Record<string, string>,
  body = '',
): Promise<{ readonly status: number; readonly text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method, headers }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        resolve({ status: res.statusCode as number, text: Buffer.concat(chunks).toString() })
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

const echo: A2aHandler = (turn) => ({ parts: [{ text: `done: ${textOf(turn.message)}` }] })

describe('A2aBridge: an A2A JSON-RPC endpoint on localhost that seals each call to the agent', () => {
  it('SendMessage and GetTask go through as A2A envelopes on new threads, and the answers come back as sent', async () => {
    const { bridge, sent } = await loop(echo, {}, { host: '127.0.0.1', session: 'calls' })
    expect(bridge.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
    const url = bridge.endpoint(AGENT)
    expect(url).toBe(`${bridge.url}/a2a/${AGENT}`)
    const sendRes = await post(url, rpc('SendMessage', { message: say('book a room') }, 'req-1'))
    expect(sendRes.status).toBe(200)
    const completed = { state: 'TASK_STATE_COMPLETED', message: { parts: [{ text: 'done: book a room' }] } }
    const answered = { jsonrpc: '2.0', id: 'req-1', result: { task: { status: completed } } }
    expect(sendRes.json).toMatchObject(answered)
    const task = (sendRes.json.result as { task: { id: string } }).task
    const getRes = await post(url, rpc('GetTask', { id: task.id }, 2))
    const state = { state: 'TASK_STATE_COMPLETED' }
    expect(getRes.json).toMatchObject({ id: 2, result: { id: task.id, status: state } })
    expect(sent.map((s) => [s.to, s.type, s.session, s.thread.prev])).toEqual([
      [[AGENT], A2A_TYPE, 'calls', []],
      [[AGENT], A2A_TYPE, 'calls', []],
    ])
    expect(sent[0]?.thread.id).toMatch(/^[0-9a-f]{64}$/)
    expect(sent[0]?.thread.id).not.toBe(sent[1]?.thread.id)
    const request = JSON.parse(rpc('SendMessage', { message: say('book a room') }, 'req-1'))
    expect(sent[0]?.body).toEqual({ a2a: '1.0', request })
  })

  it("replays the specification's own JSON-RPC requests byte for byte (A2A 1.0.0 sections 9.4.1, 6.1 and 9.4.3)", async () => {
    // Section 9.4.1's SendMessage request, its params placeholder filled with section 6.1's SendMessageRequest body,
    // and section 9.4.3's GetTask request, each as the specification prints it (white space included).
    const sec941 = `{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "SendMessage",
  "params": { /* SendMessageRequest object */ }
}`
    const sec61 = `{
  "message": {
    "role": "ROLE_USER",
    "parts": [{"text": "What is the weather today?"}],
    "messageId": "msg-uuid"
  }
}`
    const sec943 = `{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "GetTask",
  "params": {
    "id": "task-uuid",
    "historyLength": 10
  }
}`
    const ids = ['task-uuid', 'context-uuid', 'reply-uuid']
    const { bridge } = await loop(echo, { newId: () => ids.shift() as string })
    const url = bridge.endpoint(AGENT)
    const sent = await post(url, sec941.replace('{ /* SendMessageRequest object */ }', sec61))
    expect(sent.json).toMatchObject({
      jsonrpc: '2.0',
      id: 1,
      result: {
        task: { id: 'task-uuid', contextId: 'context-uuid', status: { state: 'TASK_STATE_COMPLETED' } },
      },
    })
    const got = await post(url, sec943)
    expect(got.json).toMatchObject({ jsonrpc: '2.0', id: 2, result: { id: 'task-uuid' } })
    expect((got.json.result as { history: unknown[] }).history).toHaveLength(2)
  })

  it('refuses DNS rebinding: a foreign Host header or any Origin gets 403', async () => {
    const { bridge, sent } = await bridgeOn(() => {})
    const port = new URL(bridge.url).port
    const url = bridge.endpoint(AGENT)
    const body = rpc('GetTask', { id: 'x' })
    const json = { 'content-type': 'application/json' }
    const next = Number(port) + 1
    const foreign = [`evil.example:${port}`, `127.0.0.1:${next}`, '127.0.0.1', `127.0.0.2:${port}`]
    for (const host of foreign) {
      expect(await raw(url, 'POST', { ...json, host }, body)).toEqual({
        status: 403,
        text: '{"error":"forbidden-host"}\n',
      })
    }
    const origin = { ...json, host: `127.0.0.1:${port}`, origin: `http://127.0.0.1:${port}` }
    const crossSite = { status: 403, text: '{"error":"forbidden-origin"}\n' }
    expect(await raw(url, 'POST', origin, body)).toEqual(crossSite)
    expect((await raw(`${url}/.well-known/agent-card.json`, 'GET', { origin: 'null' })).status).toBe(403)
    // The loopback names at the bridge's port pass, in any case, and reach the JSON-RPC layer (no version: -32009).
    for (const host of [`localhost:${port}`, `LOCALHOST:${port}`, `[::1]:${port}`]) {
      const r = await raw(url, 'POST', { ...json, host }, body)
      expect([r.status, JSON.parse(r.text).error.code]).toEqual([200, -32009])
    }
    expect(sent).toEqual([])
  })

  it("serves each agent's full AgentCard at its loopback path, from the record the edge resolved", async () => {
    const { bridge } = await bridgeOn(() => {}, { agents: [AGENT, OTHER, CLIENT], card: { name: 'Booking' } })
    const cardOf = (address: string) => fetch(`${bridge.endpoint(address)}/.well-known/agent-card.json`)
    const res = await cardOf(AGENT)
    expect([res.status, res.headers.get('content-type'), res.headers.get('cache-control')]).toEqual([
      200,
      'application/json',
      'no-store',
    ])
    const card = (await res.json()) as Record<string, unknown>
    expect(card).toMatchObject({
      name: 'Booking',
      supportedInterfaces: [
        { url: bridge.endpoint(AGENT), protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
      ],
      capabilities: {
        streaming: false,
        extensions: [{ params: { address: AGENT, envelopeType: A2A_TYPE } }],
      },
    })
    records.set(OTHER, null)
    expect((await cardOf(OTHER)).status).toBe(404)
    records.set(OTHER, { key: CLIENT, relays: [] })
    expect(await (await cardOf(OTHER)).json()).toEqual({ error: 'no-record' })
    records.set(CLIENT, new Error('resolve-failed'))
    expect([(await cardOf(CLIENT)).status, (await (await cardOf(CLIENT)).json()) as unknown]).toEqual([
      502,
      { error: 'resolve-failed' },
    ])
    const post405 = await fetch(`${bridge.endpoint(AGENT)}/.well-known/agent-card.json`, { method: 'POST' })
    expect([post405.status, post405.headers.get('allow')]).toEqual([405, 'GET'])
    const outside = `ed25519:${'e'.repeat(64)}`
    expect((await cardOf(outside)).status).toBe(404)
  })

  it('answers 404, 405, 415 and 413 at the HTTP layer, before anything is sent', async () => {
    const { bridge, sent } = await bridgeOn(() => {}, { agents: [AGENT] })
    const body = rpc('GetTask', { id: 'x' })
    expect((await post(`${bridge.url}/a2a/ed25519:xyz`, body)).status).toBe(404)
    expect((await post(`${bridge.url}/other/${AGENT}`, body)).status).toBe(404)
    expect(await post(bridge.endpoint(OTHER), body)).toEqual({ status: 404, json: { error: 'not-found' } })
    const get = await fetch(bridge.endpoint(AGENT))
    expect([get.status, get.headers.get('allow'), await get.json()]).toEqual([
      405,
      'POST',
      { error: 'method-not-allowed' },
    ])
    expect((await post(bridge.endpoint(AGENT), body, { 'content-type': 'text/plain' })).status).toBe(415)
    expect((await post(bridge.endpoint(AGENT), body, {})).status).toBe(415)
    const huge = rpc('SendMessage', { message: say('x'.repeat(MAX_RPC_BYTES)) })
    expect(await post(bridge.endpoint(AGENT), huge)).toEqual({ status: 413, json: { error: 'too-large' } })
    expect(sent).toEqual([])
  })

  it('drops a request whose client goes away mid-body, and goes on serving', async () => {
    const { bridge, sent } = await bridgeOn(() => {})
    const req = request(bridge.endpoint(AGENT), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': '1000' },
    })
    req.on('error', () => {})
    req.write('{"jsonrpc":')
    await sleep(50)
    req.destroy()
    await sleep(50)
    const r = await post(bridge.endpoint(AGENT), '{')
    expect(r.json).toMatchObject({ error: { code: -32700 } })
    expect(sent).toEqual([])
  })

  it('answers Parse error, Invalid Request and VersionNotSupportedError itself, an absent version read as 0.3', async () => {
    const { bridge, sent } = await bridgeOn(() => {})
    const url = bridge.endpoint(AGENT)
    const code = async (body: string, headers?: Record<string, string>) => {
      const r = await post(url, body, headers)
      return [r.status, (r.json.error as { code: number }).code, r.json.id]
    }
    expect(await code('{')).toEqual([200, -32700, null])
    expect(await code('{"jsonrpc":"2.0","method":"GetTask"}')).toEqual([200, -32600, null])
    const plain = { 'content-type': 'application/json; charset=utf-8' }
    expect(await code(rpc('GetTask', { id: 'x' }, 5), plain)).toEqual([200, -32009, 5])
    const old = { ...plain, 'a2a-version': '0.3' }
    expect(await code(rpc('GetTask', { id: 'x' }, 6), old)).toEqual([200, -32009, 6])
    const r = await post(url, rpc('GetTask', { id: 'x' }, 7), { ...plain, 'a2a-version': ' ' })
    expect((r.json.error as { message: string }).message).toBe(
      'A2A version 0.3 is not supported; this bridge speaks 1.0',
    )
    expect(sent).toEqual([])
  })

  it('times out without an answer, ignoring a reply from another principal, of another type or on another thread', async () => {
    const { bridge } = await bridgeOn(
      (input, handler) => {
        const body = responseBody(success(1, {}))
        const { thread } = input
        handler.deliver(inbound({ type: A2A_TYPE, body, principal: OTHER, thread }))
        handler.deliver(inbound({ type: 'chat.v1', body, principal: AGENT, thread }))
        const elsewhere = { id: 'f'.repeat(64), prev: [] }
        handler.deliver(inbound({ type: A2A_TYPE, body, principal: AGENT, thread: elsewhere }))
      },
      { timeoutMs: 100 },
    )
    const r = await post(bridge.endpoint(AGENT), rpc('GetTask', { id: 'x' }))
    expect(r.json).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32603, message: `no answer from ${AGENT} within 100 ms` },
    })
  })

  it("answers InvalidAgentResponseError for a reply that is not a response to the request, and a failed send's error", async () => {
    const wrong = await bridgeOn((input, handler) => {
      const body = responseBody(success(99, {}))
      handler.deliver(inbound({ type: A2A_TYPE, body, principal: AGENT, thread: input.thread }))
    })
    const r = await post(wrong.bridge.endpoint(AGENT), rpc('GetTask', { id: 'x' }))
    expect(r.json).toMatchObject({ id: 1, error: { code: -32006 } })
    const down = await bridgeOn(() => {
      throw new Error('unresolved')
    })
    const d = await post(down.bridge.endpoint(AGENT), rpc('GetTask', { id: 'x' }))
    expect(d.json).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32603, message: 'the agent could not be reached: unresolved' },
    })
  })

  it('takes a reply from a key two hops below the address: its principal is the middle key, its root the address', async () => {
    // The edge verified the chain address -> middle -> session and delivers principal = middle, root = address
    // (receiver.ts, verifyChain); the fake edge hands the bridge exactly that message.
    const middle = `ed25519:${'9'.repeat(64)}`
    const { bridge } = await bridgeOn((input, handler) => {
      const body = responseBody(success(1, { id: 't' }))
      const from = `ed25519:${'8'.repeat(64)}`
      const { thread } = input
      handler.deliver(inbound({ type: A2A_TYPE, body, from, principal: middle, root: AGENT, thread }))
    })
    const r = await post(bridge.endpoint(AGENT), rpc('GetTask', { id: 't' }))
    expect(r.json).toEqual({ jsonrpc: '2.0', id: 1, result: { id: 't' } })
  })

  it('answers a request still waiting when the bridge closes', async () => {
    const { bridge, sent } = await bridgeOn(() => {})
    const waiting = post(bridge.endpoint(AGENT), rpc('GetTask', { id: 'x' }))
    while (sent.length === 0) await sleep(5)
    bridges.splice(0)
    await bridge.close()
    expect((await waiting).json).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32603, message: 'the bridge closed' },
    })
  })

  it('asks for port 7741 by default, the port the cards name, and refuses a port already taken', async () => {
    const edge: BridgeEdge = {
      attach: () => {},
      send: async () => ({}),
      resolver: { address: async () => null },
    }
    expect(DEFAULT_PORT).toBe(7741)
    // The listen call is watched and given port 0 instead, so that no test binds a fixed port.
    const listen = Server.prototype.listen as (...args: unknown[]) => Server
    const asked: unknown[] = []
    const zero = function (this: Server, ...args: unknown[]): Server {
      asked.push(args[0])
      return listen.call(this, 0, ...args.slice(1))
    }
    const spy = vi.spyOn(Server.prototype, 'listen').mockImplementation(zero as never)
    const first = await A2aBridge.start({ edge }).finally(() => spy.mockRestore())
    bridges.push(first)
    expect(asked).toEqual([DEFAULT_PORT])
    const port = Number(new URL(first.url).port)
    expect(port).toBeGreaterThan(0)
    await expect(A2aBridge.start({ edge, port })).rejects.toThrow(/EADDRINUSE/)
  })

  it('endpointUrl joins a base without its trailing slashes to /a2a/<address>', () => {
    expect(endpointUrl('http://127.0.0.1:7741//', AGENT)).toBe(`http://127.0.0.1:7741/a2a/${AGENT}`)
  })
})

// The method as the request names it: the edge's countTelemetry counts one outside METHODS as `other`.
describe('the bridge counts each JSON-RPC answer by method and outcome, ok or the error name', () => {
  it('a success, a body that is not JSON, an old A2A version, and a method the agent does not know', async () => {
    const counted: [string, string][] = []
    const count = (method: string, outcome: string) => counted.push([method, outcome])
    const { bridge } = await loop(echo, {}, { count })
    const url = bridge.endpoint(AGENT)
    await post(url, rpc('SendMessage', { message: say('hi') }))
    await post(url, 'not json')
    await post(url, rpc('GetTask', { id: 'x' }), { 'content-type': 'application/json', 'a2a-version': '0.3' })
    await post(url, rpc('Nope', {}))
    expect(counted).toEqual([
      ['SendMessage', 'ok'],
      ['other', 'parseError'],
      ['GetTask', 'versionNotSupported'],
      ['Nope', 'methodNotFound'],
    ])
  })
})
