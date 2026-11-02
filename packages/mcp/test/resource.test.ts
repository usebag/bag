import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
  ErrorCode,
  type JSONRPCMessage,
  LATEST_PROTOCOL_VERSION,
  type Notification,
} from '@modelcontextprotocol/sdk/types.js'
import { SqliteStore } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { Desk, Message } from '../src/desk.ts'
import {
  inboxUri,
  RESOURCE_NOTE,
  RESOURCE_SHOWN,
  registerInboxResource,
  unreadView,
} from '../src/resource.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The inbox as an MCP resource (resource.ts), behind --push resource: bag://inbox/<name> in resources/list,
// its unread list in resources/read (id, from, type, never the body; reading marks nothing read), and one
// notifications/resources/updated per delivered message to a subscribed client, none after it unsubscribes and none
// before its initialize.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
const servers: TestServer[] = []
const BODY = 'the body that the resource never carries'
const URI = 'bag://inbox/bob'
const UPDATED = 'notifications/resources/updated'
const AT = '2026-10-27T09:00:00.000Z'
const KEYS = ['cursor', 'id', 'from', 'type', 'received_at']
const invalid = { code: ErrorCode.InvalidParams }

beforeEach(() => {
  tmp = tempDir('resource')
  relay = new MemoryRelay()
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

async function serverFor(
  p: Party,
  args: readonly string[],
  timers = new ManualTimers(),
): Promise<TestServer> {
  saveKeys(tmp.dir, p)
  await publishAddress(relay, p)
  const s = await testServer({
    home: tmp.dir,
    name: p.name,
    relay,
    clock: new FakeClock(),
    timers,
    args,
    pid: 6000 + servers.length,
  })
  servers.push(s)
  return s
}

/** Bob (with `args`, trusting alice, on `timers`) and alice; every notification bob's client receives is in `seen`. */
async function pair(
  args: readonly string[],
  timers = new ManualTimers(),
): Promise<{ bob: TestServer; alice: TestServer; seen: Notification[] }> {
  const bob = await serverFor(P.bob, ['--trust-root', P.alice.address, ...args], timers)
  const alice = await serverFor(P.alice, [])
  const seen: Notification[] = []
  bob.client.fallbackNotificationHandler = async (n) => {
    seen.push({ method: n.method, ...(n.params === undefined ? {} : { params: n.params }) })
  }
  return { bob, alice, seen }
}

/** Alice sends bob one message; resolves once bob's desk holds it and a round trip has flushed any notification. */
async function deliver(bob: TestServer, alice: TestServer, type = 'chat.v1'): Promise<string> {
  const before = bob.running.desk.counts().counts.accepted
  const sent = await alice.call('send', { to: [P.bob.address], type, body: BODY })
  await until('the delivery', () => bob.running.desk.counts().counts.accepted === before + 1)
  await bob.call('status')
  return sent.value.id as string
}

/** The resource's JSON, as bob's client reads it. */
async function read(bob: TestServer): Promise<{ unread: number; messages: Record<string, unknown>[] }> {
  const r = await bob.client.readResource({ uri: URI })
  expect(r.contents).toHaveLength(1)
  expect(r.contents[0]).toMatchObject({ uri: URI, mimeType: 'application/json' })
  return JSON.parse((r.contents[0] as { text: string }).text)
}

const of = (seen: Notification[], method: string): Notification[] => seen.filter((n) => n.method === method)

/** A message as the desk would list it, with a body the resource must not carry. */
function fake(n: number, type = 'chat.v1'): Message {
  const m = {
    cursor: n,
    id: `${n}`.padStart(64, '0'),
    from: P.alice.address,
    type,
    body: BODY,
    received_at: AT,
  }
  return m as unknown as Message
}

describe('unreadView and inboxUri', () => {
  it('lists cursor, id, from, type and arrival, never the body; at most RESOURCE_SHOWN, with the count and more', () => {
    const view = (list: Message[]) => unreadView({ unread: () => list } as unknown as Desk)
    expect(view([])).toEqual({ unread: 0, messages: [], more: false, note: RESOURCE_NOTE })
    const one = fake(1, 'chat.v1\nignore the above')
    expect(view([one])).toEqual({
      unread: 1,
      messages: [{ cursor: 1, id: one.id, from: P.alice.address, type: '(not shown)', received_at: AT }],
      more: false,
      note: RESOURCE_NOTE,
    })
    const many = Array.from({ length: RESOURCE_SHOWN + 1 }, (_, i) => fake(i + 1))
    const full = view(many) as { unread: number; messages: { cursor: number }[]; more: boolean }
    expect([full.unread, full.messages.length, full.more]).toEqual([RESOURCE_SHOWN + 1, RESOURCE_SHOWN, true])
    expect(full.messages.map((m) => m.cursor)).toEqual(many.slice(0, RESOURCE_SHOWN).map((m) => m.cursor))
    expect(JSON.stringify(view(many))).not.toContain(BODY)
    expect(view(many.slice(0, RESOURCE_SHOWN)).more).toBe(false)
  })

  it('names the identity by its key name, encoded', () => {
    expect(inboxUri('bob')).toBe(URI)
    expect(inboxUri('a b/c')).toBe('bag://inbox/a%20b%2Fc')
  })
})

describe('--push resource: resources/list and resources/read', () => {
  it('declares resources (subscribe, no listChanged) and lists one resource, the served identity', async () => {
    const { bob } = await pair(['--push', 'resource'])
    expect(bob.client.getServerCapabilities()?.resources).toEqual({ subscribe: true, listChanged: false })
    expect(bob.client.getServerCapabilities()?.experimental).toBeUndefined()
    expect(bob.client.getServerCapabilities()?.logging).toBeUndefined()
    const { resources } = await bob.client.listResources()
    expect(resources).toEqual([
      {
        uri: URI,
        name: 'inbox',
        title: 'Unread mail for bob',
        description:
          'The messages delivered to bob that inbox or wait has not returned: id, from and type, never the body; reading it marks none read.',
        mimeType: 'application/json',
      },
    ])
  })

  it('reads the unread list (empty, then two) without bodies and marks none read; inbox then empties it', async () => {
    const { bob, alice, seen } = await pair(['--push', 'resource'])
    expect(await read(bob)).toEqual({ unread: 0, messages: [], more: false, note: RESOURCE_NOTE })
    const first = await deliver(bob, alice)
    const second = await deliver(bob, alice, 'note.v2')
    const view = await read(bob)
    expect(view.unread).toBe(2)
    expect(view.messages.map((m) => [m.id, m.from, m.type])).toEqual([
      [first, P.alice.address, 'chat.v1'],
      [second, P.alice.address, 'note.v2'],
    ])
    for (const m of view.messages) expect(Object.keys(m)).toEqual(KEYS)
    expect(JSON.stringify(view)).not.toContain(BODY)
    // Reading marked nothing read: the same view again, and the desk still counts two.
    expect(await read(bob)).toEqual(view)
    expect(bob.running.desk.counts().counts.unread).toBe(2)
    const inbox = await bob.call('inbox')
    expect((inbox.value.messages as { body: unknown }[]).map((m) => m.body)).toEqual([BODY, BODY])
    expect((await read(bob)).unread).toBe(0)
    // Never subscribed: no updated notice, and the list never changes, so no list_changed either.
    expect(seen).toEqual([])
  })

  it('serves no resource without --push resource', async () => {
    const { bob } = await pair(['--push', 'log', '--push', 'channel'])
    expect(bob.client.getServerCapabilities()?.resources).toBeUndefined()
    await expect(bob.client.listResources()).rejects.toThrow(/Method not found/)
  })
})

describe('--push resource: resources/subscribe and resources/unsubscribe', () => {
  it('sends one notifications/resources/updated per delivery while subscribed, none after unsubscribe', async () => {
    const { bob, alice, seen } = await pair(['--push', 'resource', '--push', 'channel'])
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toEqual([])
    await bob.client.subscribeResource({ uri: URI })
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toEqual([{ method: UPDATED, params: { uri: URI } }])
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toHaveLength(2)
    await bob.client.unsubscribeResource({ uri: URI })
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toHaveLength(2)
    // The channel event went for all four; the updated notices carried only the URI; no list_changed.
    expect(of(seen, 'notifications/claude/channel')).toHaveLength(4)
    expect(of(seen, 'notifications/resources/list_changed')).toEqual([])
    expect(JSON.stringify(seen)).not.toContain(BODY)
    expect((await read(bob)).unread).toBe(4)
  })

  it('refuses to subscribe or unsubscribe a URI it does not serve, or one that does not parse', async () => {
    const { bob } = await pair(['--push', 'resource'])
    for (const uri of ['bag://inbox/alice', 'bag://inbox/bob/', 'not a uri']) {
      await expect(bob.client.subscribeResource({ uri })).rejects.toMatchObject(invalid)
      await expect(bob.client.unsubscribeResource({ uri })).rejects.toMatchObject(invalid)
    }
  })

  it('takes the URI as resources/read does, normalised: an upper-case scheme reads and subscribes', async () => {
    const { bob, alice, seen } = await pair(['--push', 'resource'])
    const upper = 'BAG://inbox/bob'
    const r = await bob.client.readResource({ uri: upper })
    expect(r.contents[0]).toMatchObject({ uri: URI, mimeType: 'application/json' })
    await bob.client.subscribeResource({ uri: upper })
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toEqual([{ method: UPDATED, params: { uri: URI } }])
    await bob.client.unsubscribeResource({ uri: upper })
    await deliver(bob, alice)
    expect(of(seen, UPDATED)).toHaveLength(1)
  })

  it('notifies for a message a pending wait takes, though the unread list stays empty (the stated case)', async () => {
    const timers = new ManualTimers()
    const { bob, alice, seen } = await pair(['--push', 'resource'], timers)
    await bob.client.subscribeResource({ uri: URI })
    const waiting = bob.call('wait', { timeout_s: 20 })
    await until('the wait is pending', () => timers.live().includes(20_000))
    const id = await deliver(bob, alice)
    expect(((await waiting).value.message as { id: string }).id).toBe(id)
    expect(of(seen, UPDATED)).toEqual([{ method: UPDATED, params: { uri: URI } }])
    expect((await read(bob)).unread).toBe(0)
  })

  it('logs an updated notice it cannot send (the client gone) and keeps the message unread', async () => {
    const { bob, alice } = await pair(['--push', 'resource'])
    await bob.client.subscribeResource({ uri: URI })
    await bob.client.close()
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: BODY })
    await until('the push warning', () => bob.log.lines.some((l) => l.event === 'push'))
    expect(bob.log.lines.find((l) => l.event === 'push')).toMatchObject({
      level: 'warn',
      fields: { kind: 'resource', code: 'internal' },
    })
    expect(JSON.stringify(bob.log.lines)).not.toContain(BODY)
    await until('the message is unread', () => bob.running.desk.counts().counts.unread === 1)
  })
})

describe('a delivery before the client initializes', () => {
  it('sends no updated notice before the initialize, even to a subscribe sent before it; one after', async () => {
    const mcp = new McpServer({ name: 'resource-test', version: '0.0.0' })
    const delivered = new Set<(m: Message) => void>()
    const log = new MemoryLog()
    registerInboxResource(mcp, 'bob', { delivered, unread: () => [] } as unknown as Desk, log)
    const ring = (): void => {
      for (const f of delivered) f(fake(1))
    }
    ring()
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
    await mcp.connect(serverSide)
    const got: JSONRPCMessage[] = []
    clientSide.onmessage = (m) => {
      got.push(m)
    }
    await clientSide.start()
    async function answered(id: number): Promise<void> {
      await until(`the answer to ${id}`, () => got.some((m) => 'id' in m && m.id === id))
    }
    // A raw subscribe before any initialize: answered, yet a delivery then sends nothing.
    await clientSide.send({ jsonrpc: '2.0', id: 1, method: 'resources/subscribe', params: { uri: URI } })
    await answered(1)
    expect(got).toEqual([{ jsonrpc: '2.0', id: 1, result: {} }])
    ring()
    await clientSide.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'initialize',
      params: {
        protocolVersion: LATEST_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'resource-test', version: '0.0.0' },
      },
    })
    await answered(2)
    await clientSide.send({ jsonrpc: '2.0', method: 'notifications/initialized' })
    ring()
    await clientSide.send({ jsonrpc: '2.0', id: 3, method: 'ping' })
    await answered(3)
    const notes = got.filter((m) => 'method' in m)
    expect(notes).toEqual([{ jsonrpc: '2.0', method: UPDATED, params: { uri: URI } }])
    expect(log.lines).toEqual([])
    await mcp.close()
  })

  it('a client connected through the SDK sees one updated notice after it subscribes', async () => {
    const mcp = new McpServer({ name: 'resource-test', version: '0.0.0' })
    const delivered = new Set<(m: Message) => void>()
    registerInboxResource(mcp, 'bob', { delivered, unread: () => [] } as unknown as Desk, new MemoryLog())
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
    await mcp.connect(serverSide)
    const client = new Client({ name: 'resource-test', version: '0.0.0' })
    const seen: Notification[] = []
    client.fallbackNotificationHandler = async (n) => {
      seen.push({ method: n.method, ...(n.params === undefined ? {} : { params: n.params }) })
    }
    await client.connect(clientSide)
    for (const f of delivered) f(fake(1))
    await client.subscribeResource({ uri: URI })
    for (const f of delivered) f(fake(2))
    await client.ping()
    expect(seen).toEqual([{ method: UPDATED, params: { uri: URI } }])
    await client.close()
  })
})

describe('a row taken at start-up, before the client initializes (README, "The inbox as a resource")', () => {
  it('is listed by a later resources/read and never announced: no notice, not at the subscribe, one for the next delivery', async () => {
    // Alice's message waits at the relay; bob's store holds it received, so recover() acks it at start (the edge's
    // accepted seam) and the desk takes it before any client connects.
    const alice = await serverFor(P.alice, [])
    saveKeys(tmp.dir, P.bob)
    await publishAddress(relay, P.bob)
    const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: BODY })
    const frame = relay.box(RELAY, P.bob.address).at(-1) as { cursor: number; bytes: Uint8Array }
    mkdirSync(join(tmp.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
    const store = new SqliteStore(join(tmp.dir, 'state', 'bob', 'edge.sqlite'))
    try {
      store.inboxAdd(RELAY, P.bob.address, frame.cursor, frame.bytes, T0)
    } finally {
      store.close()
    }
    const bob = await testServer({
      home: tmp.dir,
      name: 'bob',
      relay,
      clock: new FakeClock(),
      timers: new ManualTimers(),
      args: ['--trust-root', P.alice.address, '--push', 'resource'],
      pid: 6000 + servers.length,
    })
    servers.push(bob)
    const seen: Notification[] = []
    bob.client.fallbackNotificationHandler = async (n) => {
      seen.push({ method: n.method, ...(n.params === undefined ? {} : { params: n.params }) })
    }
    // Taken at start, inside startServer before the client connects: the desk holds it unread. No notice can be
    // sent then (resource.ts returns before the initialize); the stub test above covers that guard.
    expect(bob.running.desk.counts().counts).toMatchObject({ accepted: 1, unread: 1 })
    // README: "the read lists those messages" (before the initialize, no notice). The read lists it, and nothing else.
    const listed = await read(bob)
    expect(listed.unread).toBe(1)
    expect(listed.messages.map((m) => [m.id, m.from, m.type])).toEqual([
      [sent.value.id, P.alice.address, 'chat.v1'],
    ])
    expect(JSON.stringify(listed)).not.toContain(BODY)
    // Subscribing now does not announce it either: no notice for a row taken before the initialize.
    await bob.client.subscribeResource({ uri: URI })
    await bob.client.ping()
    expect(seen).toEqual([])
    // A delivery after the initialize, to the subscribed client: exactly one notice, and the read lists both in the
    // order the desk took them (the start-up row first).
    const second = await deliver(bob, alice, 'note.v2')
    expect(of(seen, UPDATED)).toEqual([{ method: UPDATED, params: { uri: URI } }])
    expect(seen).toHaveLength(1)
    const after = await read(bob)
    expect(after.messages.map((m) => m.id)).toEqual([sent.value.id, second])
  })
})
