import { type ChildProcess, spawn } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { DEFAULT_SKEW, DEFAULT_TTL } from '@usebag/core'
import { readAuditLines, type SocketFactory, verifyAuditLog } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  DEFAULT_RELAY_CMD,
  holdsNoSecret,
  Node,
  type Node as NodeType,
  party,
  sleep,
  URL_LINE,
  until,
  world,
} from '../harness.ts'

// e2e scenario 20: the receiver keeps its mailbox when the relay ends the subscription. (a) The
// relay's own error frame (bad-shape, its answer to an ack past the last cursor it sent) ends it, and the receiver
// subscribes again, with cursor null; (b) the relay process stops and starts again on the same port and
// database, and the adapter reconnects; (c) a subscription the relay refuses ends after three refusals.

/** A socket factory that records each auth frame's cursor and can send a bad ack through the newest socket. */
function watched(): { factory: SocketFactory; cursors: (number | null)[]; poison(): void } {
  const sockets: WebSocket[] = []
  const cursors: (number | null)[] = []
  const factory: SocketFactory = (url) => {
    const ws = new WebSocket(url)
    sockets.push(ws)
    return {
      addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void) {
        ws.addEventListener(type, (event) => listener(event as MessageEvent))
      },
      send(data) {
        const frame = JSON.parse(data) as { t: string; cursor?: number | null }
        if (frame.t === 'auth') cursors.push(frame.cursor ?? null)
        ws.send(data)
      },
      close: () => ws.close(),
    }
  }
  // An ack for a cursor the relay never sent breaks the protocol: the relay answers bad-shape and closes (4002).
  const poison = (): void => sockets.at(-1)?.send(JSON.stringify({ t: 'ack', cursor: 1_000_000_000 }))
  return { factory, cursors, poison }
}

/**
 * A relay on a database of its own that the scenario stops and starts itself (the harness uses one process per
 * world). With port 0 it takes a port from the OS and reports it; with a port given (the restart) it binds that one,
 * and when that bind fails because another process took the port in the down window it tries again, a few times.
 */
async function fixedRelay(
  dir: string,
  port: number,
): Promise<{ url: string; port: number; stop(): Promise<number | null> }> {
  const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
  const args = ['--port', String(port), '--db', join(dir, 'relay.sqlite'), '--ttl', String(DEFAULT_TTL)]
  for (let attempt = 1; ; attempt++) {
    // stdin is a pipe this process holds and never writes: the relay stops whenever this process ends.
    const child: ChildProcess = spawn(cmd, [...args, '--skew', String(DEFAULT_SKEW), '--exit-on-stdin-eof'], {
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    child.stdin?.on('error', () => {})
    const started = await new Promise<{ url: string; port: number } | string>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        reject(new Error('the fixed relay printed no URL line within 10 s'))
      }, 10_000)
      createInterface({ input: child.stdout as NodeJS.ReadableStream }).once('line', (line) => {
        clearTimeout(timer)
        const m = URL_LINE.exec(line)
        if (m === null) reject(new Error(`the fixed relay printed ${line}`))
        else resolve({ url: m[1] as string, port: Number(m[2]) })
      })
      child.once('exit', (code, signal) => {
        clearTimeout(timer)
        resolve(`the fixed relay exited (${code ?? signal}) before printing its URL line`)
      })
    })
    if (typeof started === 'string') {
      if (port !== 0 && attempt < 10) {
        await sleep(200)
        continue
      }
      throw new Error(started)
    }
    return {
      ...started,
      // A relay that has already exited resolves at once: an 'exit' listener added after the event never runs.
      stop: () =>
        new Promise((resolve) => {
          if (child.exitCode !== null || child.signalCode !== null) {
            resolve(child.exitCode)
          } else {
            child.once('exit', (code) => resolve(code))
            child.kill('SIGTERM')
          }
        }),
    }
  }
}

/** Sends `n` from alice's node to bob, expecting each target published, and keeps the ids. */
async function sender(a: NodeType, to: string, ids: string[], n: number, published = true): Promise<void> {
  const r = await a.edge.send({ to: [to], type: 'chat.v1', body: { n } })
  if (published) expect(r.targets.map((t) => t.state)).toEqual(['published'])
  ids.push(r.id)
}

describe('e2e scenario 20: a subscription the relay ends is made again, from the cursor, with no loss', () => {
  it("(20) bob's receiver keeps his mailbox: after the relay's error frame it subscribes again, with cursor null; after the relay process restarts on the same port and database the adapter reconnects; every envelope arrives exactly once, in cursor order, with no duplicate; and a subscription the relay refuses three times ends with subscription-ended in the audit log and one error", async () => {
    const w = await world('s20')
    const alice = party('alice')
    const bob = party('bob')
    const a = w.node('alice', { keys: alice.keys })
    const sockets = watched()
    const b = w.node('bob', {
      keys: bob.keys,
      roots: [{ address: alice.address }],
      socketFactory: sockets.factory,
    })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    // (a) The relay's error frame ends the subscription; the receiver subscribes again, with cursor null.
    const sent: string[] = []
    for (let n = 1; n <= 3; n++) await sender(a, bob.address, sent, n)
    await until('three acked', () => b.store.inboxList(['acked']).length === 3)
    sockets.poison()
    await until('the resubscription', () => b.steps().includes('subscribe retry bad-shape'))
    for (let n = 4; n <= 6; n++) await sender(a, bob.address, sent, n)
    await until('six acked', () => b.store.inboxList(['acked']).length === 6)
    expect(b.received.map((m) => m.id)).toEqual(sent)
    expect(b.store.inboxList().map((r) => [r.cursor, r.id, r.state, r.reason])).toEqual(
      sent.map((id, i) => [i + 1, id, 'acked', null]),
    )
    expect(b.steps().filter((s) => s.startsWith('subscribe'))).toEqual(['subscribe retry bad-shape'])
    expect(b.steps().filter((s) => s.startsWith('dedup reject'))).toEqual([])
    expect([...new Set(sockets.cursors)]).toEqual([null])
    console.log(
      `MEASURE L3(a): 6 sent, ${b.received.length} received, auth cursors ${JSON.stringify(sockets.cursors)}`,
    )

    // (c) A subscription the relay refuses (bob's key at alice's mailbox: not-authorized) ends after three refusals.
    const m = w.node('mallory', { keys: bob.keys, mailbox: alice.address, roots: [] })
    await m.edge.start()
    await until('the refused subscription ends', () => m.errors.length === 1)
    expect(m.errors[0]).toMatchObject({ code: 'not-authorized' })
    expect(m.steps()).toEqual([
      'subscribe retry not-authorized',
      'subscribe retry not-authorized',
      'subscribe reject not-authorized',
    ])
    expect(JSON.parse(m.audit().at(-1)?.detail as string)).toEqual({
      relay: w.url,
      mailbox: alice.address,
      refusals: 3,
      end: 'subscription-ended',
    })
    await new Promise((r) => setTimeout(r, 1000))
    expect(m.errors).toHaveLength(1)

    // (b) The relay process stops and starts again on the same port and database; the adapter reconnects.
    let restarts = 0
    if (w.relay.spawned) {
      const dir = join(w.dir, 'fixed')
      mkdirSync(dir)
      // The first start takes its port from the OS (--port 0); the restart binds that exact port again.
      let relay = await fixedRelay(dir, 0)
      const { port } = relay
      const a2 = new Node('alice2', join(w.dir, 'alice2'), relay.url, { keys: alice.keys })
      const b2 = new Node('bob2', join(w.dir, 'bob2'), relay.url, {
        keys: bob.keys,
        roots: [{ address: alice.address }],
      })
      try {
        await b2.edge.publishRecord(addressRecord(bob, { relays: [relay.url] }))
        await b2.edge.publishRecord(acceptFrom(bob, [alice.address]))
        b2.edge.setDefault(b2.handler('bob2'))
        await b2.edge.start()
        await a2.edge.start()
        const ids: string[] = []
        for (let n = 1; n <= 2; n++) await sender(a2, bob.address, ids, n)
        await until('two acked', () => b2.store.inboxList(['acked']).length === 2)
        expect(await relay.stop()).toBe(0)
        // While the relay is down the outbox keeps the bytes and retries them.
        for (let n = 3; n <= 4; n++) await sender(a2, bob.address, ids, n, false)
        expect(ids.slice(2).map((id) => a2.edge.status(id)[0]?.state)).toEqual(['retry', 'retry'])
        relay = await fixedRelay(dir, port)
        restarts++
        await until('four acked', () => b2.store.inboxList(['acked']).length === 4)
        await sender(a2, bob.address, ids, 5)
        await until('five acked', () => b2.store.inboxList(['acked']).length === 5)
        // Exactly once each, in cursor order. The two envelopes sent while the relay was down are published again
        // together when it returns, so the relay may take them, and number them, in either order.
        expect([...b2.received.map((x) => x.id)].sort()).toEqual([...ids].sort())
        expect(b2.store.inboxList().map((r) => [r.cursor, r.state, r.reason])).toEqual(
          ids.map((_, i) => [i + 1, 'acked', null]),
        )
        expect(b2.received.map((x) => x.id)).toEqual(b2.store.inboxList().map((r) => r.id))
        expect(
          b2.store
            .inboxList()
            .map((r) => r.id)
            .slice(0, 2),
        ).toEqual(ids.slice(0, 2))
        expect(b2.steps().filter((s) => s.startsWith('dedup reject'))).toEqual([])
        const order = b2.store.inboxList().map((r) => ids.indexOf(r.id as string) + 1)
        console.log(
          `MEASURE L3(b): 5 sent across a relay restart, ${b2.received.length} received once each, in cursor order; send order by cursor ${JSON.stringify(order)}`,
        )
      } finally {
        await a2.close()
        await b2.close()
        await relay.stop()
      }
    }
    console.log(`MEASURE L3: relay restarts ${restarts} (0 under AC_RELAY_URL)`)

    for (const n of [a, b, m]) {
      expect(verifyAuditLog(readAuditLines(n.auditPath))).toMatchObject({ ok: true })
      expect(holdsNoSecret(readFileSync(n.auditPath, 'utf8'), [alice, bob])).toBe(true)
    }
    expect([a.errors, b.errors]).toEqual([[], []])
  }, 60_000)
})
