import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { TELEMETRY_SETS } from '@usebag/edge'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { registerTools, type ToolContext } from '../src/tools.ts'

// A tool the telemetry schema does not name is counted as `other`, so a new tool added here without the schema would
// drop out of the numbers unseen. The schema is copied from the telemetry Worker (usebag/infra workers/telemetry) as
// text, and both sides change in one release (agree.mjs), so this test fails the build instead.

/**
 * Names the schema holds for a tool not registered yet: none. The schema's tool names are this server's tools; the
 * standalone bag mcp (packages/enterprise-client) records no telemetry, so its own tools need no names here. A name
 * added to the schema before its tool is registered goes here, and the last check below fails once it is registered.
 */
const PENDING: string[] = []

/**
 * The context with every registration branch of registerTools on: delegate (allowDelegate), use (a service
 * connection), and the home acts and pairing tools (no session, auth or chain command). Registration reads only
 * these fields; the tools are listed, never called.
 */
const EVERY_BRANCH = {
  config: { allowDelegate: true, session: null, auth: null, chainCmd: null },
  // A service connection as a hello leaves it: the use tool's description reads its input hook.
  connection: { capabilities: { elicitation: false, inputHook: false, raw: {} } },
} as unknown as ToolContext

describe('telemetry: every tool the MCP server registers is a name of the schema', () => {
  const named = TELEMETRY_SETS.tool.filter((name) => name !== 'other')
  const server = new McpServer({ name: 'telemetry-tools', version: '0.0.0' })
  const client = new Client({ name: 'telemetry-tools', version: '0.0.0' })
  let registered: string[] = []

  beforeAll(async () => {
    registerTools(server, EVERY_BRANCH)
    const [a, b] = InMemoryTransport.createLinkedPair()
    await server.connect(b)
    await client.connect(a)
    registered = (await client.listTools()).tools.map((t) => t.name)
  })

  afterAll(async () => {
    await client.close()
    await server.close()
  })

  it('lists the tools of every branch', () => {
    expect(registered).toEqual(expect.arrayContaining(['delegate', 'use', 'identities', 'pair_invite']))
  })

  it('names every registered tool, so none is counted as other', () => {
    expect(registered.filter((tool) => !named.includes(tool))).toEqual([])
  })

  it('names nothing else but the pending names', () => {
    expect(named.filter((name) => !registered.includes(name))).toEqual(PENDING)
  })

  it('keeps no pending name that is registered already', () => {
    expect(PENDING.filter((name) => registered.includes(name))).toEqual([])
  })
})
