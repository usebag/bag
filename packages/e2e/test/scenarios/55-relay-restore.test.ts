import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import type { SocketFactory } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  cliProcess,
  type Node,
  nodeAt,
  party,
  relayAt,
  until,
  world,
} from '../harness.ts'

// e2e scenario 55 (spec/SPEC.md §9 item 2, Appendix B item 102): a relay restored from
// an older copy of its database issues used cursors again. The relay is stopped, its file copied and put back by this
// scenario, on one port, so the URL in the records stays true. M1 is in the copy, M2 is after it and taken by bob's edge,
// and M3 lands after the restore at M2's cursor. M3 must arrive, with bob's edge connected when it lands (the frame
// comes, and the id decides: §9 item 2) and with bob's edge closed then (the frame comes only because the edge resumes
// with cursor null: §9 item 10). In both, every record the scenario needs was published before the copy.

const FILES = ['relay.sqlite', 'relay.sqlite-wal', 'relay.sqlite-shm']

/** Copies the database files of a stopped relay from `from` to `to`, and removes those the source lacks. */
function copyFiles(from: string, to: string): void {
  mkdirSync(to, { recursive: true })
  for (const file of FILES) {
    if (existsSync(join(from, file))) copyFileSync(join(from, file), join(to, file))
    else rmSync(join(to, file), { force: true })
  }
}

/** A socket factory that counts the subscriptions the relay has answered ok. */
function watched(): { factory: SocketFactory; answered(): number } {
  let oks = 0
  const factory: SocketFactory = (url) => {
    const ws = new WebSocket(url)
    ws.addEventListener('message', (event) => {
      if ((JSON.parse(String(event.data)) as { t: string }).t === 'ok') oks++
    })
    return {
      addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void) {
        ws.addEventListener(type, (event) => listener(event as MessageEvent))
      },
      send: (data) => ws.send(data),
      close: () => ws.close(),
    }
  }
  return { factory, answered: () => oks }
}

/**
 * The story up to the restore: M1 taken by bob and in the copy, M2 after the copy and taken by bob. Returns the nodes,
 * the parties, M2 and what puts the copy back; the relay stops with the test.
 */
async function beforeRestore(name: string, sockets?: SocketFactory) {
  const w = await world(name)
  const [alice, bob] = [party('alice'), party('bob')]
  const [dir, copy] = [join(w.dir, 'restored'), join(w.dir, 'copy')]
  mkdirSync(dir)
  const relay = await relayAt(dir, 0)
  const a = nodeAt(w, 'alice', relay.url, { keys: alice.keys })
  const b = nodeAt(w, 'bob', relay.url, {
    keys: bob.keys,
    roots: [{ address: alice.address }],
    ...(sockets === undefined ? {} : { socketFactory: sockets }),
  })
  await b.edge.publishRecord(addressRecord(bob, { relays: [relay.url] }))
  await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
  b.edge.setDefault(b.handler('bob'))
  await b.edge.start()

  const taken = async (n: number): Promise<{ id: string; cursor: number }> => {
    const { id } = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n } })
    await until(`M${n} at bob`, () => b.received.some((m) => m.id === id))
    await until(`M${n} acked`, () => b.rows(id).some((r) => r.state === 'acked'))
    return { id, cursor: b.rows(id)[0]?.cursor as number }
  }
  await taken(1)
  expect(await relay.stop()).toBe(0)
  copyFiles(dir, copy)
  let running = await relayAt(dir, relay.port)
  onTestFinished(async () => {
    await running.stop()
  })
  const m2 = await taken(2)
  return {
    w,
    a,
    b,
    alice,
    bob,
    m2,
    url: relay.url,
    restore: async () => {
      expect(await running.stop()).toBe(0)
      copyFiles(copy, dir)
      running = await relayAt(dir, relay.port)
    },
  }
}

/** A message from alice to `bob`: published, and its id. */
async function sent(a: Node, bob: string, n: number): Promise<string> {
  const m = await a.edge.send({ to: [bob], type: 'chat.v1', body: { n } })
  expect(m.targets.map((t) => t.state)).toEqual(['published'])
  return m.id
}

describe('e2e scenario 55: a relay restored from an older copy issues used cursors again', () => {
  it("(55a) with bob's edge connected, M3 at M2's cursor arrives, stored beside M2's row", async () => {
    const sockets = watched()
    const s = await beforeRestore('s55a', sockets.factory)
    const before = sockets.answered()
    await s.restore()
    await until('bob subscribed to the restored relay', () => sockets.answered() > before, 40_000)
    const m3 = await sent(s.a, s.bob.address, 3)
    await until('M3 at bob', () => s.b.received.some((m) => m.id === m3), 40_000)
    await until('M3 acked', () => s.b.rows(m3).some((r) => r.state === 'acked'))
    const position = s.b.store.inboxAt(s.url, s.bob.address, s.m2.cursor)
    expect(position.map((r) => r.id)).toEqual([s.m2.id, m3])
    expect(s.b.received.filter((m) => m.id === s.m2.id)).toHaveLength(1)
  }, 90_000)

  it("(55b) with bob's edge closed when it lands, M3 at M2's cursor arrives when the edge comes back", async () => {
    const s = await beforeRestore('s55b')
    await s.b.close()
    await s.restore()
    const m3 = await sent(s.a, s.bob.address, 3)
    const again = nodeAt(s.w, 'bob', s.url, { keys: s.bob.keys, roots: [{ address: s.alice.address }] })
    again.edge.setDefault(again.handler('bob'))
    await again.edge.start()
    await until('M3 at bob', () => again.received.some((m) => m.id === m3), 20_000)
    expect(again.rows(m3).map((r) => r.cursor)).toEqual([s.m2.cursor])
  }, 90_000)

  it('(55c) inbox --once run twice prints a refused message once: cursor null resumes after the ack the relay kept', async () => {
    const w = await world('s55c')
    const dir = ['--dir', join(w.dir, 'cli-home')]
    const cli = async (...args: string[]): Promise<string[]> => {
      const run = await cliProcess(args)
      expect([run.code, run.err]).toEqual([0, []])
      return run.out
    }
    const [alice, bob] = [
      (await cli('keygen', 'alice', ...dir))[0],
      (await cli('keygen', 'bob', ...dir))[0],
    ] as [string, string]
    const [address, accept] = [join(w.dir, 'address.json'), join(w.dir, 'accept.json')]
    await cli('record', 'address', 'bob', '--relay', w.url, '--sealing-key', '--out', address, ...dir)
    const limits = ['--max-bytes', '65536', '--ttl', '86400']
    await cli('record', 'accept-from', 'bob', '--root', alice, ...limits, '--out', accept, ...dir)
    await cli('publish', w.url, address)
    await cli('publish', w.url, accept)
    const to = ['--as', 'alice', '--to', bob, '--relay', w.url, '--type', 'chat.v1', '--body', '{}']
    const [id] = await cli('send', ...to, ...dir)
    const inbox = ['inbox', '--as', 'bob', '--relay', w.url, '--once', ...dir]
    expect(await cli(...inbox)).toEqual([`reject ${id} untrusted-root`])
    expect(await cli(...inbox)).toEqual([])
  })
})
