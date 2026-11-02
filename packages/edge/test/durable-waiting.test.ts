import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseEnvelope, serializeRecord } from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { SqliteStore, type SqliteStoreOptions } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import type { RelayClient } from '../src/ports.ts'
import { MAX_WAITING, type WaitingSend } from '../src/sender.ts'
import {
  acceptFrom,
  addressRecord,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { closedPort } from './support/http.ts'
import { MemoryRelay } from './support/relays.ts'

// The durable waiting send (last mile, ruling 1 (b)): a send whose recipient does not resolve is kept on the sender's
// disk, plaintext, under the identity's state directory, and survives a restart to the same `until`. A restart here
// closes the store and opens a new store and a new Edge on the same file, as a new process does; the crash cases drop
// the old Edge with a publish still hanging, so nothing after the write it stopped at ever runs.

const ACME = 'http://relay-acme.test'
/** Short of the hour Bob's address record lasts, so that he still resolves at `until`. */
const TTL = 1800
const SECRET = 'the plaintext of the waiting send'
const chat = { to: [P.bob.address], type: 'chat.v1', body: { text: SECRET } }

/** A MemoryRelay whose envelope publishes hang while `hang` is set, as a process that died in that call never hears. */
class HangingRelay extends MemoryRelay {
  hang = false
  hung = 0

  override publish(url: string, bytes: Uint8Array) {
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: string }
    if (this.hang && v.kind === undefined) {
      this.hung++
      return new Promise<never>(() => {})
    }
    return super.publish(url, bytes)
  }
}

interface Node {
  readonly edge: Edge
  readonly store: SqliteStore
  readonly audit: MemoryAuditSink
  readonly path: string
  readonly clock: FakeClock
}

const homes: string[] = []
afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true })
})

/** A new home with the state directory of `name`, as the CLI and the MCP server make it: 0700. */
function stateDir(
  name: string,
  home = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-edge-durable-')),
): string {
  if (!homes.includes(home)) homes.push(home)
  const dir = join(home, 'state', name)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

/** An identity's edge on the store at `dir`: what one process opens. */
function open(
  keys: Party['keys'],
  dir: string,
  relay: RelayClient,
  clock = new FakeClock(),
  audit = new MemoryAuditSink(),
  options: SqliteStoreOptions = {},
  urls = [ACME],
): Node {
  const path = join(dir, 'edge.sqlite')
  const store = new SqliteStore(path, options)
  const edge = new Edge({
    keys,
    store,
    relays: { client: relay, urls },
    policy: { roots: [{ address: P.jane.address }, { address: P.bob.address }], types: ['chat.*'] },
    clock,
    rng: seededRng(`durable ${keys.signing.address} ${clock.t}`),
    audit,
    lookup: PUBLIC_LOOKUP,
    window: { ttl: TTL, skew: 300 },
  })
  return { edge, store, audit, path, clock }
}

/** The same identity in a new process: the old store closed, a new one on the file, the same clock and audit log. */
function restart(n: Node, keys: Party['keys'], relay: MemoryRelay, options: SqliteStoreOptions = {}): Node {
  n.store.close()
  return open(keys, join(n.path, '..'), relay, n.clock, n.audit, options)
}

/** Bob's records at ACME, so that he resolves. */
async function bobAppears(relay: MemoryRelay): Promise<void> {
  await relay.publish(ACME, serializeRecord(addressRecord(P.bob, { relays: [ACME] })))
  await relay.publish(ACME, serializeRecord(acceptFrom(P.bob)))
}

const parked = async (n: Node, input: Parameters<Edge['sendOrWait']>[0] = chat): Promise<WaitingSend> =>
  (await n.edge.sendOrWait(input)) as WaitingSend

describe('a waiting send says why it waits', () => {
  it('a relay that answered it holds no record: answered, and the reason says none', async () => {
    const waiting = await parked(open(P.jane.keys, stateDir('jane'), new MemoryRelay()))
    expect(waiting.unanswered).toBe(false)
    expect(waiting.reason).toContain(`${ACME} (none)`)
  })

  it('a relay that refused the connection, at a closed port: unanswered, and the reason never says none', async () => {
    const url = `http://127.0.0.1:${await closedPort()}`
    const n = open(P.jane.keys, stateDir('jane'), createRelayClient({}), undefined, undefined, {}, [url])
    const waiting = await parked(n)
    expect(waiting.unanswered).toBe(true)
    expect(waiting.reason).toContain(`${url} (unreachable)`)
    expect(waiting.reason).not.toContain('(none)')
    expect(n.edge.waiting()).toEqual([waiting])
  })
})

describe('a waiting send outlives a restart (ruling 1 (b))', () => {
  it('reloads it with its key, thread and backoff, and sends it on the same thread and session', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    const waiting = await parked(first, { ...chat, session: 'chat-1' })
    expect(waiting).toMatchObject({ key: 'waiting-1', tries: 1, nextAt: T0 + 1, until: T0 + TTL })

    const second = restart(first, P.jane.keys, relay)
    expect(second.edge.waiting()).toEqual([waiting])
    await bobAppears(relay)
    second.clock.t = T0 + 5
    const [target] = await second.edge.flush()
    expect(target).toMatchObject({ state: 'published', relay: ACME })
    expect(second.edge.waiting()).toEqual([])
    expect(second.store.waitingList()).toEqual([])
    expect(second.store.threadGet(waiting.thread.id)).toBe('chat-1')
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    expect(second.store.outboxGet(target?.id as string)?.thread).toBe(waiting.thread.id)
    second.store.close()
  })

  it("flushes at start: a started edge's first tick sends what a restart found, with no further trigger", async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    const second = restart(first, P.jane.keys, relay)
    await bobAppears(relay)
    second.clock.t = T0 + 5
    await second.edge.start()
    await expect.poll(() => relay.box(ACME, P.bob.address).length).toBe(1)
    await second.edge.stop()
    second.store.close()
  })

  it("keeps its keys unique across restarts: a seq is never reused, a sent row's included", async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    const second = restart(first, P.jane.keys, relay)
    await bobAppears(relay)
    second.clock.t = T0 + 5
    await second.edge.flush()
    const third = restart(second, P.jane.keys, relay)
    const carol = await parked(third, { ...chat, to: [P.carol.address] })
    expect(carol.key).toBe('waiting-2')
    third.store.close()
  })

  it('never lengthens the horizon: a row found past until is dropped with no try and an audit line', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    const waiting = await parked(first)
    await bobAppears(relay)
    const second = restart(first, P.jane.keys, relay)
    second.clock.t = waiting.until + 1
    const fetches = relay.recordFetches.length
    expect(await second.edge.flush()).toEqual([])
    expect(relay.recordFetches).toHaveLength(fetches)
    expect(relay.box(ACME, P.bob.address)).toEqual([])
    expect(second.store.waitingList()).toEqual([])
    const last = JSON.parse(second.audit.lines.at(-1) as string)
    expect([last.event, last.decision, last.reason]).toEqual(['publish', 'reject', 'resolve-failed'])
    expect(JSON.parse(last.detail)).toMatchObject({
      waiting: waiting.key,
      next_at: null,
      until: waiting.until,
    })
    second.store.close()
  })

  it('keeps the last try at until itself, as before', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    const waiting = await parked(first)
    await bobAppears(relay)
    const second = restart(first, P.jane.keys, relay)
    second.clock.t = waiting.until
    expect((await second.edge.flush()).map((t) => t.state)).toEqual(['published'])
    second.store.close()
  })

  it('throws resolve-failed once MAX_WAITING sends wait, and keeps nothing more', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    for (let i = 0; i < MAX_WAITING; i++) first.store.waitingAdd('{}', '{}', T0 + TTL)
    await expect(first.edge.sendOrWait(chat)).rejects.toMatchObject({ code: 'resolve-failed' })
    expect(first.store.waitingList()).toHaveLength(MAX_WAITING)
    first.store.close()
  })
})

describe('one message, one id, whatever the crash', () => {
  it('a crash after sealing, with the publish in flight: the outbox holds it, the row is gone, one id goes out', async () => {
    const relay = new HangingRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    await bobAppears(relay)
    first.clock.t = T0 + 5
    relay.hang = true
    void first.edge.flush()
    await expect.poll(() => relay.hung).toBe(1)

    // Sealed and persisted, the old process gone before it ever heard back.
    relay.hang = false
    const second = restart(first, P.jane.keys, relay)
    expect(second.edge.waiting()).toEqual([])
    const flushed = await second.edge.flush()
    expect(flushed.map((t) => t.state)).toEqual(['published'])
    second.clock.t = T0 + 600
    await second.edge.flush()
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    second.store.close()
  })

  it('two flushes at once seal a row once', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    await bobAppears(relay)
    first.clock.t = T0 + 5
    await Promise.all([first.edge.flush(), first.edge.flush()])
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    first.store.close()
  })

  it('a crash before the commit: outbox and row move together, so nothing is half done', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    const [row] = first.store.waitingList()
    const target = {
      id: 'x',
      relay: ACME,
      state: 'sealed',
      tries: 0,
      nextAt: null,
      reason: null,
      updatedAt: T0,
    } as const
    const entry = { id: 'x', bytes: new Uint8Array(1), thread: 't', session: null, createdAt: T0 }
    // Two targets on one relay break the primary key inside the transaction, after the row's delete.
    expect(() => first.store.outboxAdd(entry, [target, target], { waiting: row?.seq })).toThrow()
    expect(first.store.waitingList()).toHaveLength(1)
    expect(first.store.outboxGet('x')).toBeNull()
    first.store.close()
  })

  it('a fault after the outbox write does not seal it again on the next flush', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    await bobAppears(relay)
    first.clock.t = T0 + 5
    const targets = first.store.outboxTargets.bind(first.store)
    first.store.outboxTargets = () => {
      first.store.outboxTargets = targets
      throw new Error('a bookkeeping fault')
    }
    await first.edge.flush()
    expect(first.store.waitingList()).toEqual([])
    first.clock.t = T0 + 10
    await first.edge.flush()
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    first.store.close()
  })
})

describe('whose queue it is', () => {
  it('an entry never crosses identities: each identity flushes its own, under its own key', async () => {
    const relay = new MemoryRelay()
    const home = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-edge-durable-'))
    const jane = open(P.jane.keys, stateDir('jane', home), relay)
    const carol = open(P.carol.keys, stateDir('carol', home), relay)
    await parked(jane)
    expect(carol.edge.waiting()).toEqual([])

    const carolAgain = restart(carol, P.carol.keys, relay)
    await bobAppears(relay)
    carolAgain.clock.t = T0 + 5
    expect(await carolAgain.edge.flush()).toEqual([])
    expect(relay.box(ACME, P.bob.address)).toEqual([])

    jane.clock.t = T0 + 5
    await jane.edge.flush()
    const [row] = relay.box(ACME, P.bob.address)
    expect(parseEnvelope(row?.bytes as Uint8Array).from).toBe(P.jane.keys.signing.address)
    jane.store.close()
    carolAgain.store.close()
  })

  it('one writer: a second process of the identity is refused the store, so it cannot flush', async () => {
    const relay = new MemoryRelay()
    const first = open(P.jane.keys, stateDir('jane'), relay)
    await parked(first)
    expect(() => new SqliteStore(first.path)).toThrow(expect.objectContaining({ code: 'busy' }))
    first.store.close()
  })

  it('a store opened waitingInMemory keeps none of it on disk, and a new process finds none', async () => {
    const relay = new MemoryRelay()
    const options = { waitingInMemory: true }
    const dir = stateDir('s-0123456789abcdef')
    const first = open(P.jane.keys, dir, relay, new FakeClock(), new MemoryAuditSink(), options)
    const waiting = await parked(first)
    expect(first.edge.waiting()).toEqual([waiting])
    await bobAppears(relay)
    first.clock.t = T0 + 5
    await first.edge.flush()
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    await parked(first, { ...chat, to: [P.carol.address] })
    expect(first.edge.waiting()).toHaveLength(1)
    for (const file of ['edge.sqlite', 'edge.sqlite-wal']) {
      expect(readFileSync(join(dir, file)).includes(SECRET)).toBe(false)
    }
    const second = restart(first, P.jane.keys, relay, options)
    expect(second.edge.waiting()).toEqual([])
    second.store.close()
  })
})

describe('where the plaintext is', () => {
  it('sits in the 0600 store of a 0700 directory, and leaves its row when the send goes', async () => {
    const relay = new MemoryRelay()
    const dir = stateDir('jane')
    const n = open(P.jane.keys, dir, relay)
    await parked(n)
    expect(n.store.waitingList()[0]?.input).toContain(SECRET)
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(n.path).mode & 0o777).toBe(0o600)
    expect(statSync(`${n.path}-wal`).mode & 0o777).toBe(0o600)
    await bobAppears(relay)
    n.clock.t = T0 + 5
    await n.edge.flush()
    expect(n.store.waitingList()).toEqual([])
    n.store.close()
  })

  it('reaches no audit line and no result, waiting, retried, dropped or sent', async () => {
    const relay = new MemoryRelay()
    const n = open(P.jane.keys, stateDir('jane'), relay)
    const seen: unknown[] = [await parked(n), n.edge.waiting()]
    n.clock.t = T0 + 5
    seen.push(await n.edge.flush(), n.edge.waiting())
    const dropped = await parked(n, { ...chat, to: [P.carol.address] })
    await bobAppears(relay)
    n.clock.t = T0 + 600
    seen.push(await n.edge.flush())
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    n.clock.t = dropped.until + 1
    seen.push(await n.edge.flush())
    expect(n.store.waitingList()).toEqual([])
    expect(JSON.stringify(seen)).not.toContain(SECRET)
    expect(n.audit.lines.join('\n')).not.toContain(SECRET)
    expect(n.audit.lines.length).toBeGreaterThan(3)
    n.store.close()
  })
})
