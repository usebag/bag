import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterAll, describe, expect, it } from 'vitest'
import { createMcpServer, homeLines, identitiesAnswer, UNBOUND_LISTING } from '../src/mcp.ts'
import { type EnterprisePorts, type HomeReads, VERSION } from '../src/ports.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// The standalone server with the home's reads: the identities tool and status's leading lines, through an MCP client. With no reads the server is as before (mcp.test.ts).

const tmp = tempDir('mcp-home')
afterAll(() => tmp.cleanup())

async function setup(reads: HomeReads | undefined) {
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => T0 },
    rng: seededRng('mcp-home'),
    fetch: undefined,
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => '192.0.2.10' },
    },
    sleep: async () => {},
    relays: new FakeRelay(),
    ...(reads === undefined ? {} : { home: reads }),
  }
  const [a, b] = InMemoryTransport.createLinkedPair()
  await createMcpServer(ports, tmp.dir).connect(a)
  const client = new Client({ name: 'test', version: '0' })
  await client.connect(b)
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as {
      content: { type: string; text: string }[]
      isError?: boolean
    }
    return { text: r.content.map((c) => c.text).join('\n'), isError: r.isError === true }
  }
  return { client, call }
}

const TWO: HomeReads = {
  identities: () => [
    { label: 'omp', relays: ['https://r1.example', 'https://r2.example'] },
    { label: 'qrfolk', relays: ['https://r1.example'] },
  ],
  relaysHealth: async (relays) => relays.map((relay) => ({ relay, ok: relay === 'https://r1.example' })),
}

describe('the standalone server with the home reads', () => {
  it('adds identities to the three tools, and describes status as the home first', async () => {
    const { tools } = await (await setup(TWO)).client.listTools()
    expect(tools.map((t) => t.name)).toEqual(['connect', 'sign_in', 'status', 'identities'])
    expect(tools[2]?.description).toMatch(/^Shows this machine's bag: the version/)
    expect(tools[3]?.inputSchema.properties).toEqual({})
    expect((await (await setup(undefined)).client.listTools()).tools.map((t) => t.name)).toEqual([
      'connect',
      'sign_in',
      'status',
    ])
  })

  it("status leads with the version, the identities' count and the relays' health as counts; signed out is no error", async () => {
    const r = await (await setup(TWO)).call('status')
    expect(r.isError).toBe(false)
    expect(r.text.split('\n')).toEqual([
      `bag ${VERSION}`,
      'identities 2',
      'relays 2, ok 1',
      'signed-out: not signed in: bag sign-in <domain>',
    ])
    expect(r.text).not.toContain('example')
  })

  it("under 'labels' status names each relay and its answer", async () => {
    expect(await homeLines(TWO, '/unused', 'labels')).toEqual([
      `bag ${VERSION}`,
      'identities 2',
      'relay https://r1.example ok',
      'relay https://r2.example unreachable',
    ])
  })

  it('status with no relay listed says so', async () => {
    const none: HomeReads = { identities: () => [], relaysHealth: async () => [] }
    const r = await (await setup(none)).call('status')
    expect(r.text.split('\n').slice(0, 3)).toEqual([`bag ${VERSION}`, 'identities 0', 'relays none listed'])
  })

  it('identities answers a count by default, and no name in the text', async () => {
    expect(UNBOUND_LISTING).toBe('count')
    const r = await (await setup(TWO)).call('identities')
    expect(r.isError).toBe(false)
    const answer = JSON.parse(r.text) as Record<string, unknown>
    expect(answer).toMatchObject({ bound: false, identities: 2 })
    expect(String(answer.note)).toContain('2 identities are on this machine')
    expect(r.text).not.toContain('omp')
    expect(r.text).not.toContain('qrfolk')
  })

  it("identities' failure is its public line", async () => {
    const bad: HomeReads = {
      identities: () => {
        throw Object.assign(new Error('identities-invalid: identities.json is not JSON'), {
          code: 'identities-invalid',
        })
      },
      relaysHealth: async () => [],
    }
    expect(await (await setup(bad)).call('identities')).toEqual({
      text: 'identities-invalid: identities.json is not JSON',
      isError: true,
    })
  })
})

describe('identitiesAnswer', () => {
  it('the labels only, when the switch says labels', () => {
    expect(identitiesAnswer(['omp', 'qrfolk'], 'labels')).toEqual({
      bound: false,
      identities: [{ label: 'omp' }, { label: 'qrfolk' }],
      note: expect.stringContaining('Addresses show once a window is bound'),
    })
  })

  it('one identity, and none, in both forms', () => {
    expect(identitiesAnswer(['omp']).note).toContain('one identity is on this machine')
    expect(identitiesAnswer([])).toEqual({
      bound: false,
      identities: 0,
      note: 'no identity on this machine yet.',
    })
    expect(identitiesAnswer([], 'labels')).toEqual({
      bound: false,
      identities: [],
      note: 'no identity on this machine yet.',
    })
  })
})

describe('the standalone server refuses an argument a tool does not define, before it runs', () => {
  it('each listed tool, called with a misspelt key whose value is a marker: usage naming the key and its own names', async () => {
    const marker = 'MARKER-standalone-never-echoed'
    let read = 0
    const counted: HomeReads = {
      ...TWO,
      identities: (h) => {
        read++
        return TWO.identities(h)
      },
    }
    const { client, call } = await setup(counted)
    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name)).toEqual(['connect', 'sign_in', 'status', 'identities'])
    for (const t of tools) {
      const keys = Object.keys(t.inputSchema.properties ?? {})
      const r = await call(t.name, { cdoe: marker })
      const takes = keys.length === 0 ? 'no argument' : keys.join(', ')
      expect([r.isError, r.text]).toEqual([true, `usage: unknown argument "cdoe": ${t.name} takes ${takes}`])
    }
    // Nothing ran: the home's identities were never read.
    expect(read).toBe(0)
  })
})
