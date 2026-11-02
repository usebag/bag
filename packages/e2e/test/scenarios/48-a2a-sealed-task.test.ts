import { execFile } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { A2A_TYPE, A2aBridge, A2aServer, AGENT_CARD_PATH, a2aSessionHandler, textOf } from '@usebag/a2a'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  holdsNoSecret,
  party,
  REPO,
  relayEvents,
  sleep,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 48 (packages/a2a, A2A 1.0.0, https://a2a-protocol.org/v1.0.0/specification/): a
// standard A2A client completes a task with one of our agents through a release relay that sees only ciphertext.
// The client here is an A2A JSON-RPC client in plain fetch, nothing of ours. It reads the org's public A2A extension
// at /.well-known/bag/a2a.json beside the agent's address record (written by deploy/make-a2a-extension.sh,
// served by a local stand-in for the well-known Worker that serves the files of the site; with no loopback URL
// and no /.well-known/agent-card.json, which A2A section 14.3 reserves for an AgentCard), then the full AgentCard at the local A2A bridge's loopback path (A2aBridge on the client's edge, which builds it
// from the record it resolved and verified), and calls the card's interface URL, the bridge's endpoint of the
// address. The bridge seals each JSON-RPC call to the agent as an a2a.jsonrpc.v1 envelope;
// the agent's edge opens it, its A2aServer runs the task, and the reply comes back sealed in the same thread.
// Then the relay's SQLite files are read, as bytes and as rows: the request text, the reply text, the artifact text,
// the JSON-RPC method names, the envelope type and the task state appear nowhere, in UTF-8 or in hex, while the
// envelopes themselves are there, each with the nine outer members of spec/SPEC.md §5.1 and nothing else.

const hex = (s: string): string => Buffer.from(s, 'utf8').toString('hex')

/** One A2A JSON-RPC call, as any A2A 1.0 client makes it: POST, application/json, A2A-Version 1.0. */
async function a2aCall(
  url: string,
  method: string,
  params: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'a2a-version': '1.0' },
    body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method, params }),
  })
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, unknown>
}

interface Parts {
  readonly parts: { readonly text?: string }[]
}

interface TaskView {
  readonly id: string
  readonly contextId: string
  readonly status: { readonly state: string; readonly message?: Parts }
  readonly artifacts?: Parts[]
}

interface ScriptRun {
  readonly code: number
  readonly out: string
  readonly err: string
}

/** The script's run: its exit code and output. */
function script(args: readonly string[]): Promise<ScriptRun> {
  // Node 24 first in PATH, as the script asks: the one running this test.
  const env = { ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH ?? ''}` }
  const file = join(REPO, 'deploy', 'make-a2a-extension.sh')
  return new Promise((resolve) => {
    execFile('bash', [file, ...args], { cwd: REPO, env }, (error, out, err) => {
      resolve({ code: error === null ? 0 : typeof error.code === 'number' ? error.code : -1, out, err })
    })
  })
}

describe('e2e scenario 48: an A2A client completes a task with our agent through a relay that sees only ciphertext', () => {
  it('(48) no agent-card.json is published; the public a2a.json beside the record names the address and no loopback URL; the bridge serves the full card; SendMessage answers a completed task; GetTask reads it and a second task started with returnImmediately until completed; an unknown task is TaskNotFoundError; the relay files hold the envelopes and none of the plaintext, the method names or the type', async () => {
    const w = await withSpawnedRelays(() => world('s48'))
    const C = party('client')
    const A = party('agent')
    const client = w.node('client', { keys: C.keys, roots: [{ address: A.address }], types: [A2A_TYPE] })
    const agent = w.node('agent', { keys: A.keys, roots: [{ address: C.address }], types: [A2A_TYPE] })
    const record = addressRecord(A, { relays: [w.url] })
    await agent.edge.publishRecord(record)
    await agent.edge.publishRecord(acceptFrom(A, [C.address]))
    await client.edge.publishRecord(addressRecord(C, { relays: [w.url] }))
    await client.edge.publishRecord(acceptFrom(C, [A.address]))

    // The plaintext the relay must never hold: unique, so that a match can only be a leak.
    const token = randomBytes(8).toString('hex')
    const REQUEST = `please book room ${token}`
    const REPLY = `booked ${token} for you`
    const ARTIFACT = `confirmation-${token}`
    const server = new A2aServer({
      handler: (turn) => {
        const room = textOf(turn.message).replace('please book room ', '')
        return {
          parts: [{ text: `booked ${room} for you` }],
          artifacts: [{ name: 'confirmation', parts: [{ text: `confirmation-${room}` }] }],
        }
      },
    })
    const agentErrors: unknown[] = []
    agent.edge.setDefault(a2aSessionHandler(agent.edge, server, { onError: (e) => agentErrors.push(e) }))
    await agent.edge.start()
    await client.edge.start()
    // Port 0, so that runs in parallel never collide; the path is the default endpoint shape the card names.
    const options = { edge: client.edge, agents: [A.address], timeoutMs: 20_000, port: 0 }
    const bridge = await A2aBridge.start(options)
    let bridgeOpen = true
    onTestFinished(async () => {
      if (bridgeOpen) await bridge.close()
    })

    // The public extension, made by the deploy script from the agent's record and written beside it; the stand-in
    // origin serves every file of the site, as the Worker serves its tree.
    const root = join(w.dir, 'site')
    const dir = join(root, '.well-known', 'bag')
    mkdirSync(dir, { recursive: true })
    const recordFile = join(dir, 'address.json')
    writeFileSync(recordFile, `${JSON.stringify(record)}\n`)
    const made = await script(['--domain', 'agent.e2e.test', '--record', recordFile, '--out', dir])
    expect([made.code, made.err]).toEqual([0, ''])
    expect(made.out).toBe(
      `extension urn:bag:a2a:v1 address ${A.address} envelope ${A2A_TYPE} ` +
        `out ${join(dir, 'a2a.json')}\n`,
    )
    expect(existsSync(join(root, '.well-known', 'agent-card.json'))).toBe(false)
    const origin = createServer((req, res) => {
      const file = join(root, new URL(String(req.url), 'http://site').pathname)
      if (req.method === 'GET' && existsSync(file) && statSync(file).isFile()) {
        res.writeHead(200, { 'content-type': 'application/json' }).end(readFileSync(file))
      } else {
        res.writeHead(404).end()
      }
    })
    await new Promise<void>((resolve) => origin.listen(0, '127.0.0.1', resolve))
    onTestFinished(() => new Promise<void>((resolve) => origin.close(() => resolve())))
    const base = `http://127.0.0.1:${(origin.address() as AddressInfo).port}`

    // No AgentCard at the org's card path (A2A section 14.3); the public extension beside the record, no loopback URL.
    expect((await fetch(`${base}${AGENT_CARD_PATH}`)).status).toBe(404)
    const publicText = await (await fetch(`${base}/.well-known/bag/a2a.json`)).text()
    expect(publicText).not.toMatch(/127\.0\.0\.1|localhost|\[::1\]/)
    const doc = JSON.parse(publicText) as { uri: string; params: { address: string; envelopeType: string } }
    const recordUrl = `${base}/.well-known/bag/address.json`
    const served = (await (await fetch(recordUrl)).json()) as { key: string }
    const named = { address: served.key, envelopeType: A2A_TYPE }
    expect(doc).toMatchObject({ uri: 'urn:bag:a2a:v1', params: named })
    expect(served.key).toBe(A.address)

    // The A2A client: the full card from the bridge's loopback path (built from the record the client's edge fetched
    // from the relay and verified), then the card's preferred interface.
    const cardUrl = `${bridge.endpoint(doc.params.address)}/.well-known/agent-card.json`
    const card = (await (await fetch(cardUrl)).json()) as {
      supportedInterfaces: { url: string; protocolBinding: string; protocolVersion: string }[]
      capabilities: { streaming: boolean; extensions: { params: Record<string, unknown> }[] }
      skills: { id: string }[]
    }
    const iface = card.supportedInterfaces[0]
    const expected = { url: bridge.endpoint(A.address), protocolBinding: 'JSONRPC', protocolVersion: '1.0' }
    expect(iface).toEqual(expected)
    expect(card.capabilities.streaming).toBe(false)
    const params = card.capabilities.extensions[0]?.params
    expect(params).toMatchObject({ address: A.address, relays: [w.url], envelopeType: A2A_TYPE })
    expect(card.skills.map((s) => s.id)).toEqual(['message'])
    const url = iface?.url as string

    // SendMessage, blocking: a completed task with the reply and the artifact.
    const message = { messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: REQUEST }] }
    const sent = await a2aCall(url, 'SendMessage', { message })
    expect(sent.error).toBeUndefined()
    const task = (sent.result as { task: TaskView }).task
    expect(task.status.state).toBe('TASK_STATE_COMPLETED')
    expect(task.status.message?.parts).toEqual([{ text: REPLY }])
    expect(task.artifacts?.[0]?.parts).toEqual([{ text: ARTIFACT }])

    // GetTask reads the same task.
    const got = await a2aCall(url, 'GetTask', { id: task.id })
    const completed = { state: 'TASK_STATE_COMPLETED' }
    expect(got.result).toMatchObject({ id: task.id, contextId: task.contextId, status: completed })

    // A second task with returnImmediately answers working at once; GetTask reads it until it is completed.
    const again = [{ text: `please book room ${token}2` }]
    const second = { messageId: randomUUID(), role: 'ROLE_USER', parts: again }
    const configuration = { returnImmediately: true }
    const started = await a2aCall(url, 'SendMessage', { message: second, configuration })
    const working = (started.result as { task: TaskView }).task
    expect(working.status.state).toBe('TASK_STATE_WORKING')
    let state = working.status.state
    let polls = 0
    while (state !== 'TASK_STATE_COMPLETED' && polls < 50) {
      polls++
      const read = await a2aCall(url, 'GetTask', { id: working.id })
      state = (read.result as TaskView).status.state
      if (state !== 'TASK_STATE_COMPLETED') await sleep(50)
    }
    expect(state).toBe('TASK_STATE_COMPLETED')

    // An unknown task is TaskNotFoundError, answered by the agent through the relay.
    const unknown = await a2aCall(url, 'GetTask', { id: randomUUID() })
    expect(unknown.error).toMatchObject({ code: -32001 })
    const calls = 4 + polls
    expect(agentErrors).toEqual([])
    expect([client.errors, agent.errors]).toEqual([[], []])

    // The relay's files: every envelope is there, outer members only, and no plaintext in UTF-8 or hex.
    const db = join(w.dir, 'relay.sqlite')
    const raw = [db, `${db}-wal`]
      .filter((f) => existsSync(f))
      .map((f) => readFileSync(f).toString('latin1'))
      .join('')
    const rows: string[] = []
    const envelopes: Record<string, unknown>[] = []
    const store = new DatabaseSync(db, { readOnly: true })
    try {
      const tables = store.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()
      for (const { name } of tables as { name: string }[]) {
        for (const row of store.prepare(`SELECT * FROM "${name}"`).all()) {
          for (const v of Object.values(row)) {
            rows.push(v instanceof Uint8Array ? Buffer.from(v).toString('utf8') : String(v))
          }
        }
      }
      for (const row of store.prepare('SELECT bytes FROM envelopes').all() as { bytes: Uint8Array }[]) {
        envelopes.push(JSON.parse(Buffer.from(row.bytes).toString('utf8')) as Record<string, unknown>)
      }
    } finally {
      store.close()
    }
    const dump = rows.join('\n')
    // The control: the envelopes are in the store, a request and a reply per call, between the two addresses.
    expect(envelopes.length).toBeGreaterThanOrEqual(2 * calls)
    for (const e of envelopes) {
      expect(Object.keys(e).sort()).toEqual(['auth', 'from', 'id', 'sealed', 'sig', 'suite', 'to', 'ts', 'v'])
      expect([A.address, C.address]).toContain((e.to as string[])[0])
      expect(dump).toContain(e.id as string)
    }
    const plaintext = [
      REQUEST,
      REPLY,
      ARTIFACT,
      token,
      'SendMessage',
      'GetTask',
      'jsonrpc',
      A2A_TYPE,
      'TASK_STATE_COMPLETED',
      'ROLE_USER',
      task.id,
      working.id,
    ]
    const stderr = w.relay.stderr()
    const found = (p: string): boolean => [dump, raw, stderr].some((t) => t.includes(p) || t.includes(hex(p)))
    const leaks = plaintext.filter(found)
    expect(leaks).toEqual([])
    expect(relayEvents(w.relay).length).toBeGreaterThan(0)
    for (const n of [client, agent]) {
      expect(holdsNoSecret(readFileSync(n.auditPath, 'utf8'), [A, C])).toBe(true)
    }
    console.log(
      `MEASURE 48: ${calls} A2A calls (polls ${polls}), ${envelopes.length} envelopes in the relay store, ` +
        `${plaintext.length} plaintext strings searched in ${dump.length} characters of rows ` +
        `and ${raw.length} bytes of files, 0 found`,
    )
    bridgeOpen = false
    await bridge.close()
  }, 60_000)
})
