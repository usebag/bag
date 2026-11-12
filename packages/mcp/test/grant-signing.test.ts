import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { parseEnvelope, serializeRecord, signHop } from '@usebag/core'
import { generateEdgeKeys } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Bindings, type Custody, type ServiceConnection, serveBindings } from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { startIdentities } from '../src/server.ts'
import type { ConnectionGrant } from '../src/session.ts'
import { registerTools, type ToolContext } from '../src/tools.ts'
import {
  acceptFrom,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// An agent-class binding's acts sign with its own connection's grant (tools.ts signerOf over binding.ts grantOf): the
// grant's fresh key under the agent's hop, never the identity's keys and never another window's grant. One
// --identities server stands in for the service's units (personal: alice's key file, research: carol's), the table's
// custody says research is an agent identity, and each fake connection gets its own MCP server, as the service does.

type Json = Record<string, unknown>

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let table: Bindings
let root: ToolContext
let clock: FakeClock
let ctxs: Map<string, ToolContext>
const stops: (() => Promise<void>)[] = []
let n = 0
const grants: string[] = []

beforeEach(async () => {
  tmp = tempDir('grant-signing')
  relay = new MemoryRelay()
  const id = (label: string, p: typeof P.alice): Json => {
    const home = join(tmp.dir, label)
    saveKeys(home, p)
    return { label, key: p.name, home, relays: [RELAY], trust_roots: [P.bob.address] }
  }
  const file = join(tmp.dir, 'identities.json')
  writeFileSync(
    file,
    JSON.stringify({ version: 1, identities: [id('personal', P.alice), id('research', P.carol)] }),
    { mode: 0o600 },
  )
  clock = new FakeClock()
  const running = await startIdentities(parseServerConfig(['--identities', file], {}) as ServerConfig, {
    clock,
    rng: seededRng('grant'),
    relayFor: () => relay,
    records: fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4242,
    alive: () => false,
    log: new MemoryLog(),
    resubscribeDelayMs: () => 0,
  })
  stops.push(() => running.stop())
  root = (running.units.get('personal') as { ctx: ToolContext }).ctx
  const research = (running.units.get('research') as { ctx: ToolContext }).ctx
  ctxs = new Map([
    ['personal', root],
    ['research', research],
  ])
  const custody: Record<string, Custody> = { personal: 'home-key', research: 'agent' }
  const rng = seededRng('grants')
  table = new Bindings(
    {
      home: root.config.home,
      identities: () => Object.entries(custody).map(([label, c]) => ({ label, address: null, custody: c })),
      draining: false,
    },
    {
      custody: (l) => custody[l] ?? null,
      // The agent's grant, as connectionGrant gives it: a fresh key, and carol's hop to it under the caveats.
      grant: async (): Promise<ConnectionGrant> => {
        const keys = generateEdgeKeys(rng)
        grants.push(keys.signing.address)
        return {
          keys,
          hop: signHop(P.carol.keys.signing, keys.signing.address, ['type=chat.*'], clock.now() + 3600),
        }
      },
    },
  )
  // Each identity's home is its own directory here; both read the one table, as one service home does.
  serveBindings(table, root.config.home)
  serveBindings(table, research.config.home)
  await publishAddress(relay, P.bob)
  await relay.publish(RELAY, serializeRecord(acceptFrom(P.bob)))
})

afterEach(async () => {
  for (const s of stops.splice(0)) await s()
  grants.splice(0)
  tmp.cleanup()
})

/** A connection bound to `label` by the typed word, with its own MCP server; returns its send's envelope. */
async function window(label: string): Promise<{
  conn: ServiceConnection
  call(name: string, args: Json): Promise<Json>
  send(): Promise<Json>
}> {
  const conn = {
    handle: (n++).toString(16).padStart(32, 'e'),
    host: 'claude-code',
    cwd: `/w/${n}`,
    capabilities: { elicitation: true, inputHook: true, raw: {} },
    closed: false,
    onClose: () => () => {},
    elicit: async () => ({ action: 'cancel' as const }),
    notify() {},
  } as unknown as ServiceConnection
  const server = new McpServer({ name: 'svc', version: '0.0.0' })
  // The service derives each identity's context with the connection (service.ts #attach): one identity here.
  const { identities: _all, ...ctx } = ctxs.get(label) as ToolContext
  registerTools(server, { ...ctx, connection: conn } as ToolContext)
  const [a, b] = InMemoryTransport.createLinkedPair()
  await server.connect(b)
  const client = new Client({ name: 'shim', version: '0.0.0' })
  await client.connect(a)
  stops.push(async () => {
    await client.close()
    await server.close()
  })
  table.bindByWord(conn, label)
  return {
    conn,
    async call(name: string, args: Json) {
      const r = await client.callTool({ name, arguments: args })
      return JSON.parse((r.content as { text: string }[])[0]?.text ?? '{}') as Json
    },
    async send() {
      const before = new Set(relay.envelopes.keys())
      const r = await client.callTool({
        name: 'send',
        arguments: { to: [P.bob.address], type: 'chat.v1', body: 'hi' },
      })
      const value = JSON.parse((r.content as { text: string }[])[0]?.text ?? '{}') as Json
      expect(r.isError, JSON.stringify(value)).not.toBe(true)
      const key = [...relay.envelopes.keys()].find((k) => !before.has(k)) as string
      return parseEnvelope(relay.envelopes.get(key) as Uint8Array) as unknown as Json
    },
  }
}

const hops = (e: Json): string[][] => (e.auth as { iss: string; sub: string }[]).map((h) => [h.iss, h.sub])

describe("an agent binding's acts sign with its connection's grant", () => {
  it('two windows on one agent identity sign with two grants, never its key; a key-file window signs with its key', async () => {
    const a = await window('research')
    const b = await window('research')
    const ea = await a.send()
    const eb = await b.send()
    const [ga, gb] = [await table.grantOf(a.conn, 'research'), await table.grantOf(b.conn, 'research')]
    expect([ea.from, eb.from]).toEqual([ga.keys.signing.address, gb.keys.signing.address])
    expect(ea.from).not.toBe(eb.from)
    expect([ea.from, eb.from]).not.toContain(P.carol.address)
    expect(hops(ea)).toEqual([[P.carol.address, ga.keys.signing.address]])
    expect(hops(eb)).toEqual([[P.carol.address, gb.keys.signing.address]])
    expect(grants).toEqual([ga.keys.signing.address, gb.keys.signing.address])
    // A second act of the same window signs with the same grant (asked once per bind).
    expect((await a.send()).from).toBe(ga.keys.signing.address)
    const c = await window('personal')
    const ec = await c.send()
    expect([ec.from, ec.auth]).toEqual([P.alice.address, []])
  })

  it("past its exp a window's act says how to rebind, never a bare hop-expired", async () => {
    const a = await window('research')
    await a.send()
    clock.t += 3601
    const r = await a.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(r).toMatchObject({ error: 'hop-expired', as: 'research' })
    expect(String(r.detail)).toContain('binds the window again (unbind it, then type use research')
  })
})
