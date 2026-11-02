import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { Notification } from '@modelcontextprotocol/sdk/types.js'
import { SqliteStore } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  FakeClock,
  ManualTimers,
  P,
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

// The edge's `accepted` seam as the MCP server takes it: every
// accepted row reaches the desk once, at its ack, whichever path acks it: a frame, recover() at start, a release. A
// row recover() finishes at start lands in the unread list before the client initializes, so it gets no push notice;
// a release in this process gets one. A released row behind a cursor handed out while it was held is listed once
// past that cursor (desk.ts, inbox).

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
const servers: TestServer[] = []
let started = 0

beforeEach(async () => {
  tmp = tempDir('accepted')
  relay = new MemoryRelay()
  clock = new FakeClock()
  started = 0
  for (const p of [P.alice, P.bob]) {
    saveKeys(tmp.dir, p)
    await publishAddress(relay, p)
  }
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

async function start(name: 'alice' | 'bob', args: readonly string[]): Promise<TestServer> {
  const s = await testServer({
    home: tmp.dir,
    name,
    relay,
    clock,
    timers: new ManualTimers(),
    args,
    pid: 6000 + started++,
  })
  servers.push(s)
  return s
}

/** Bob's server, trusting alice, with --push channel; every channel notice its client gets is kept in `seen`. */
async function bobServer(): Promise<{ bob: TestServer; seen: string[] }> {
  const bob = await start('bob', ['--trust-root', P.alice.address, '--push', 'channel'])
  const seen: string[] = []
  bob.client.fallbackNotificationHandler = async (n: Notification) => {
    if (n.method === 'notifications/claude/channel') seen.push((n.params as { meta: { id: string } }).meta.id)
  }
  return { bob, seen }
}

/** Alice's message to bob, sent while bob's server is not running: its id, and the relay's bytes and cursor. */
async function waitingAtRelay(alice: TestServer): Promise<{ id: string; bytes: Uint8Array; cursor: number }> {
  const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'held at the relay' })
  const row = relay.box(RELAY, P.bob.address).at(-1) as { cursor: number; bytes: Uint8Array }
  return { id: sent.value.id as string, bytes: row.bytes, cursor: row.cursor }
}

/** Puts a row into bob's store before his server starts: received (a crash before its check) or held by a rule. */
function seedBob(frame: { bytes: Uint8Array; cursor: number }, held: boolean): void {
  mkdirSync(join(tmp.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
  const store = new SqliteStore(join(tmp.dir, 'state', 'bob', 'edge.sqlite'))
  try {
    const row = store.inboxAdd(RELAY, P.bob.address, frame.cursor, frame.bytes, T0)
    if (held) {
      store.inboxPut(row, { state: 'quarantined' }, T0)
      store.holdPut(row.seq, { rule: 'test-hold', code: 'policy-refused', detail: null }, T0)
    }
  } finally {
    store.close()
  }
}

describe('accepted: a frame, recover() at start and a release each reach the desk once', () => {
  it('a frame: one unread message and one notice; the same row acked again gives nothing', async () => {
    const { bob, seen } = await bobServer()
    const alice = await start('alice', [])
    const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    await until('the delivery', () => bob.running.desk.counts().counts.unread === 1)
    const { opened } = bob.running
    const row = opened.store.inboxList(['acked']).find((r) => r.content !== null)
    expect(row).toBeDefined()
    if (row !== undefined) opened.edge.receiver.ack({ ...row, state: 'routed' })
    await bob.call('status')
    expect([bob.running.desk.counts().counts.unread, seen]).toEqual([1, [sent.value.id]])
  })

  it('recover() at start: the row lands unread before the client initializes, with no notice, once', async () => {
    const alice = await start('alice', [])
    const frame = await waitingAtRelay(alice)
    seedBob(frame, false)
    const { bob, seen } = await bobServer()
    expect(bob.running.desk.counts().counts).toMatchObject({ accepted: 1, unread: 1 })
    const waited = await bob.call('wait', { timeout_s: 0 })
    expect(waited.value).toMatchObject({ message: { id: frame.id, body: 'held at the relay' } })
    // The subscription resumes past the acked row: the relay does not send it again, so nothing is taken twice.
    const inbox = await bob.call('inbox')
    expect((inbox.value.messages as { id: string }[]).map((m) => m.id)).toEqual([frame.id])
    expect(seen).toEqual([])
  })

  it('a release in this process: one notice, and the row listed once past a cursor handed out while it was held', async () => {
    const alice = await start('alice', [])
    const frame = await waitingAtRelay(alice)
    seedBob(frame, true)
    const { bob, seen } = await bobServer()
    expect(bob.running.desk.counts().counts).toMatchObject({ quarantined: 1, unread: 0 })
    const later = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'later' })
    await until('the later delivery', () => bob.running.desk.counts().counts.unread === 1)
    const first = await bob.call('inbox')
    expect((first.value.messages as { id: string }[]).map((m) => m.id)).toEqual([later.value.id])
    const cursor = first.value.next_cursor as number
    const released = bob.running.opened.store.inboxList(['quarantined'])[0]
    expect(released).toBeDefined()
    await bob.running.opened.edge.receiver.release(released?.seq as number)
    await bob.call('status')
    expect(seen).toEqual([later.value.id, frame.id])
    const past = await bob.call('inbox', { since: cursor })
    expect((past.value.messages as { id: string }[]).map((m) => m.id)).toEqual([frame.id])
    expect(past.value.next_cursor).toBe(cursor)
    const again = await bob.call('inbox', { since: cursor })
    expect(again.value.messages).toEqual([])
  })

  it('a row released before the row a cursor names arrived is not listed again past that cursor', async () => {
    const alice = await start('alice', [])
    const frame = await waitingAtRelay(alice)
    seedBob(frame, true)
    const { bob } = await bobServer()
    const released = bob.running.opened.store.inboxList(['quarantined'])[0]
    await bob.running.opened.edge.receiver.release(released?.seq as number)
    clock.t = T0 + 10
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'after the release' })
    await until('the later delivery', () => bob.running.desk.counts().counts.unread === 2)
    // Past the later row's cursor, before anything was read: the release (at T0) is older than that row (T0 + 10).
    const last = Math.max(...bob.running.opened.store.inboxList(['acked']).map((r) => r.seq))
    const past = await bob.call('inbox', { since: last })
    expect(past.value.messages).toEqual([])
    const all = await bob.call('inbox')
    expect((all.value.messages as { id: string }[])[0]?.id).toBe(frame.id)
  })

  it('a row released strictly after the cursor row arrived is listed once past it, and not again', async () => {
    const alice = await start('alice', [])
    const frame = await waitingAtRelay(alice)
    seedBob(frame, true)
    const { bob } = await bobServer()
    const later = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'later' })
    await until('the later delivery', () => bob.running.desk.counts().counts.unread === 1)
    const first = await bob.call('inbox')
    expect((first.value.messages as { id: string }[]).map((m) => m.id)).toEqual([later.value.id])
    const cursor = first.value.next_cursor as number
    // Five seconds on: the release (T0 + 5) is later than the row the cursor names (T0), not equal to it.
    clock.t = T0 + 5
    const released = bob.running.opened.store.inboxList(['quarantined'])[0]
    await bob.running.opened.edge.receiver.release(released?.seq as number)
    const past = await bob.call('inbox', { since: cursor })
    expect((past.value.messages as { id: string }[]).map((m) => m.id)).toEqual([frame.id])
    const again = await bob.call('inbox', { since: cursor })
    expect(again.value.messages).toEqual([])
  })

  it('a row released before a restart is listed once by the next server, and again after another restart', async () => {
    const alice = await start('alice', [])
    const frame = await waitingAtRelay(alice)
    seedBob(frame, true)
    const roots = ['--trust-root', P.alice.address]
    let bob = await start('bob', roots)
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'later' })
    await until('the later delivery', () => bob.running.desk.counts().counts.unread === 1)
    const cursor = (await bob.call('inbox')).value.next_cursor as number
    // A CLI release runs while the server is down (it holds the writer lock) and leaves the store acked, with
    // content and a hold record. Releasing in process leaves the same store: do that, then stop the server.
    clock.t = T0 + 5
    const held = bob.running.opened.store.inboxList(['quarantined'])[0]
    await bob.running.opened.edge.receiver.release(held?.seq as number)
    await bob.close()
    servers.splice(servers.indexOf(bob), 1)
    const ids = async (s: TestServer): Promise<string[]> =>
      ((await s.call('inbox', { since: cursor })).value.messages as { id: string }[]).map((m) => m.id)
    // The next server has returned nothing yet: it lists the released row once past the cursor, not twice.
    bob = await start('bob', roots)
    expect(await ids(bob)).toEqual([frame.id])
    expect(await ids(bob)).toEqual([])
    // Another restart on a quiet mailbox (no row arrived after the release): the row is listed once more.
    await bob.close()
    servers.splice(servers.indexOf(bob), 1)
    bob = await start('bob', roots)
    expect(await ids(bob)).toEqual([frame.id])
    expect(await ids(bob)).toEqual([])
  })
})
