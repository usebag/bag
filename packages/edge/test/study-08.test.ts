import { spawn } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { auditHash, buildEnvelope, type Hop, newThread, signHop, toHex } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { FsAuditSink, readAuditLines } from '../src/adapters/fs-audit.ts'
import { readAuditAnchor, SqliteStore } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import {
  type InboundMessage,
  type PublishResult,
  type RelayClient,
  RelayError,
  type Subscription,
} from '../src/ports.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
  tempDir,
} from './support/fixtures.ts'

// Edge hardening on the edge in process: each test prints its measurement as a MEASURE line, and asserts the line's
// rule. L3 and the CLI halves of L4 and L5 are e2e scenarios 20 and 21.

const HOME = 'http://home.test'
const R2 = 'http://relay-2.test'
const WEEK = 604_800
const tmp = tempDir('study-08')
afterAll(() => tmp.cleanup())

/** A relay that gives no answer until the fake clock reaches `back`, and stores every envelope after. */
class DownUntil implements RelayClient {
  readonly published: { url: string; at: number; bytes: Uint8Array }[] = []
  back: number
  readonly #clock: FakeClock

  constructor(clock: FakeClock, back: number) {
    this.#clock = clock
    this.back = back
  }

  async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.published.push({ url, at: this.#clock.now(), bytes })
    if (this.#clock.now() < this.back) throw new RelayError(null, 0, null, 'connection refused')
    return { id: 'x', duplicate: false, delivered: 1 }
  }

  async fetch(): Promise<Uint8Array> {
    throw new RelayError('not-found', 404, null, 'here')
  }

  async fetchRecord(): Promise<null> {
    return null
  }

  subscribe(): Subscription {
    throw new Error('not here')
  }
}

function sender(clock: FakeClock, relay: RelayClient, records: FakeRecords, o: { urls?: string[] } = {}) {
  return new Edge({
    keys: P.carol.keys,
    store: new SqliteStore(':memory:'),
    relays: { client: relay, urls: o.urls ?? [HOME] },
    records,
    policy: { roots: [], types: ['*'] },
    clock,
    rng: seededRng('study-08'),
    audit: new MemoryAuditSink(),
    lookup: PUBLIC_LOOKUP,
  })
}

/** Sends one envelope to bob (relay R2) with the relay silent for `outage` seconds, and flushes until it settles. */
async function outage(seconds: number) {
  const clock = new FakeClock()
  const relay = new DownUntil(clock, T0 + seconds)
  const records = new FakeRecords()
  records.put(HOME, addressRecord(P.bob, { relays: [R2], ttl: 86_400 }))
  const edge = sender(clock, relay, records)
  const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { n: 1 } })
  let t = sent.targets[0]
  while (t?.state === 'retry') {
    clock.t = t.nextAt as number
    t = (await edge.flush())[0]
  }
  const bytes = new Set(relay.published.map((p) => toHex(p.bytes)))
  return { edge, sent, target: t, relay, clock, bytes }
}

describe('L1: the outbox outlasts an outage of the relay, until the relay TTL', () => {
  it('L1: a relay silent for 7,200 s gets the envelope at the first try due after it answers again', async () => {
    const { target, relay, bytes } = await outage(7200)
    const failed = relay.published.length - 1
    const at = (relay.published.at(-1)?.at as number) - T0
    console.log(
      `MEASURE L1: state ${target?.state}, failed tries ${failed}, delivered ${at} s after the send`,
    )
    expect(target).toMatchObject({ state: 'published' })
    expect(bytes.size).toBe(1)
    expect(at).toBeGreaterThanOrEqual(7200)
    expect(at).toBeLessThanOrEqual(10_800)
  })

  it('L1b: a relay silent for 172,800 s (48 h), which earlier versions gave up on at 29,295 s, gets it too', async () => {
    const { target, relay, bytes } = await outage(172_800)
    const failed = relay.published.length - 1
    const at = (relay.published.at(-1)?.at as number) - T0
    console.log(
      `MEASURE L1b: state ${target?.state}, failed tries ${failed}, delivered ${at - 172_800} s after the return`,
    )
    expect(target).toMatchObject({ state: 'published' })
    expect(bytes.size).toBe(1)
    expect(at - 172_800).toBeLessThanOrEqual(3600)
  })

  it('L1c: a relay that never answers: failed at ts + 604,800 and not before, then resend publishes the same bytes', async () => {
    const { edge, sent, target, relay, clock, bytes } = await outage(10 ** 9)
    console.log(
      `MEASURE L1c: state ${target?.state} (${target?.reason}) at ts + ${(target?.updatedAt as number) - T0} s after ${target?.tries} tries`,
    )
    expect(target).toMatchObject({ state: 'failed', reason: 'publish-failed', updatedAt: T0 + WEEK })
    expect(relay.published.slice(0, -1).every((p) => p.at < T0 + WEEK)).toBe(true)
    expect(target?.tries).toBeGreaterThanOrEqual(180)
    expect(target?.tries).toBeLessThanOrEqual(202)
    relay.back = clock.now()
    expect((await edge.resend(sent.id))[0]).toMatchObject({ state: 'published', tries: 1 })
    expect(new Set(relay.published.map((p) => toHex(p.bytes))).size).toBe(bytes.size)
  })

  it("L1d: a 4xx but 408 and 429 still fails at once with the relay's code; a 429 still waits for its Retry-After", async () => {
    const clock = new FakeClock()
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { relays: [R2], ttl: 86_400 }))
    const refusing: RelayClient = Object.assign(new DownUntil(clock, 0), {
      publish: async (): Promise<PublishResult> => {
        throw new RelayError('not-hosted', 403, null, 'no mailbox')
      },
    })
    const refused = await sender(clock, refusing, records).send({ to: [P.bob.address], type: 't', body: 1 })
    const limited: RelayClient = Object.assign(new DownUntil(clock, 0), {
      publish: async (): Promise<PublishResult> => {
        throw new RelayError('rate-limited', 429, 50, 'slow down')
      },
    })
    const waiting = await sender(clock, limited, records).send({ to: [P.bob.address], type: 't', body: 1 })
    console.log(
      `MEASURE L1d: 403 -> ${refused.targets[0]?.state} ${refused.targets[0]?.reason} after ${refused.targets[0]?.tries} try; 429 Retry-After 50 -> next_at ts + ${(waiting.targets[0]?.nextAt as number) - T0}`,
    )
    expect(refused.targets[0]).toMatchObject({ state: 'failed', reason: 'not-hosted', tries: 1 })
    expect(waiting.targets[0]).toMatchObject({ state: 'retry', reason: 'rate-limited', nextAt: T0 + 50 })
  })
})

const rng = coreRng(seededRng('study-08-envelopes'))
const hop = (): Hop[] => [signHop(P.jane.signing, P.session.address, [], T0 + 30 * 86_400)]

function envelope(o: { auth?: readonly Hop[]; ts?: number; from?: typeof P.carol } = {}) {
  const built = buildEnvelope({
    from: (o.from ?? P.session).signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    auth: o.auth ?? hop(),
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'hello' },
    ts: o.ts ?? T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes }
}

function receiver(records = new FakeRecords()) {
  const clock = new FakeClock()
  const got: InboundMessage[] = []
  const edge = new Edge({
    keys: P.bob.keys,
    store: new SqliteStore(':memory:'),
    relays: { client: new DownUntil(clock, 0), urls: [HOME] },
    records,
    policy: { roots: [{ address: P.jane.address }, { address: P.carol.address }], types: ['*'] },
    clock,
    rng: seededRng('study-08-bob'),
    audit: new MemoryAuditSink(),
  })
  edge.setDefault({ session: 'inbox', deliver: (m) => void got.push(m) })
  return { edge, clock, records, got }
}

describe('L2: a transient rejection waits, and is delivered once it heals', () => {
  it('L2: a chain whose root record is missing waits, not acked, and is routed by the first due retry after the record appears', async () => {
    const { edge, clock, records, got } = receiver()
    const e = envelope()
    let row = await edge.receive(HOME, 1, e.bytes)
    const first = row
    // ack reads the row's state in the store, so the check that a waiting row stays unacked is made while it waits.
    const ackedWhileWaiting = edge.receiver.ack(first).state
    // Every retry due before ts + 5 fails; the record appears at ts + 5.
    while ((row.nextAt as number) < T0 + 5) {
      clock.t = row.nextAt as number
      row = await edge.receive(HOME, 1, e.bytes)
    }
    const failedBefore = row.tries
    records.put(HOME, addressRecord(P.jane))
    clock.t = row.nextAt as number
    row = await edge.receive(HOME, 1, e.bytes)
    console.log(
      `MEASURE L2: first ${first.state} ${first.reason} next_at ts + ${(first.nextAt as number) - T0}; ${failedBefore} failed tries; then ${row.state} at ts + ${clock.now() - T0} (record at ts + 5)`,
    )
    expect([first.state, first.reason, ackedWhileWaiting]).toEqual(['received', 'resolve-failed', 'received'])
    expect(row).toMatchObject({ state: 'routed', session: 'inbox' })
    expect(failedBefore).toBeGreaterThanOrEqual(2)
    expect(failedBefore).toBeLessThanOrEqual(4)
    expect(got.map((m) => m.id)).toEqual([e.id])
    expect(edge.receiver.ack(row).state).toBe('acked')
  })

  it('L2b: a resolve failure that never heals becomes a final rejection at ts + TTL, and not before, then is acked', async () => {
    const { edge, clock } = receiver()
    const e = envelope()
    let row = await edge.receive(HOME, 1, e.bytes)
    while (row.state === 'received') {
      clock.t = row.nextAt as number
      row = await edge.receive(HOME, 1, e.bytes)
    }
    console.log(
      `MEASURE L2b: ${row.state} ${row.reason} at ts + ${clock.now() - T0} after ${row.tries} checks`,
    )
    expect(row).toMatchObject({ state: 'rejected', reason: 'resolve-failed' })
    expect(clock.now()).toBe(T0 + WEEK)
    expect(edge.receiver.ack(row).state).toBe('acked')
  })

  it('L2c: an envelope 400 s ahead (skew 300) waits, and is accepted once the clock reaches ts - skew', async () => {
    const { edge, clock, got } = receiver()
    const e = envelope({ auth: [], from: P.carol, ts: T0 + 400 })
    let row = await edge.receive(HOME, 1, e.bytes)
    const first = row
    while (row.state === 'received') {
      clock.t = row.nextAt as number
      row = await edge.receive(HOME, 1, e.bytes)
    }
    console.log(
      `MEASURE L2c: first ${first.state} ${first.reason}; ${row.state} at ts - ${T0 + 400 - clock.now()} s`,
    )
    expect([first.state, first.reason]).toEqual(['received', 'future-ts'])
    expect(row.state).toBe('routed')
    expect(clock.now()).toBeGreaterThanOrEqual(T0 + 100)
    expect(got).toHaveLength(1)
  })
})

describe('L4: the audit anchor sees a log cut short or rewritten, which the chain alone does not', () => {
  /** An edge's state directory with a log of exactly 20 lines, written through the edge's own Audit and store. */
  function twenty(name: string) {
    const dir = join(tmp.dir, name)
    mkdirSync(dir)
    const store = new SqliteStore(join(dir, 'edge.sqlite'))
    const sink = new FsAuditSink(join(dir, 'audit.jsonl'))
    const edge = new Edge({
      keys: P.bob.keys,
      store,
      relays: { client: new DownUntil(new FakeClock(), 0), urls: [HOME] },
      policy: { roots: [], types: ['*'] },
      clock: new FakeClock(),
      rng: seededRng('l4'),
      audit: sink,
    })
    for (let i = 0; i < 20; i++) edge.audit.record({ event: 'verify', decision: 'accept', detail: { i } })
    store.close()
    return { dir, log: join(dir, 'audit.jsonl'), db: join(dir, 'edge.sqlite') }
  }

  function reopen(dir: string): unknown {
    const store = new SqliteStore(join(dir, 'edge.sqlite'))
    try {
      new Edge({
        keys: P.bob.keys,
        store,
        relays: { client: new DownUntil(new FakeClock(), 0), urls: [HOME] },
        policy: { roots: [], types: ['*'] },
        clock: new FakeClock(),
        rng: seededRng('l4'),
        audit: new FsAuditSink(join(dir, 'audit.jsonl')),
      })
      return 'opened'
    } catch (e) {
      return (e as { code?: unknown }).code
    } finally {
      store.close()
    }
  }

  it('L4: truncated and diverged by the library, ok as before when intact, refused by a new edge, and re-anchored when ahead', () => {
    const s = twenty('l4')
    const lines = readAuditLines(s.log)
    const anchor = readAuditAnchor(s.db, 'audit.jsonl')
    expect(anchor).toEqual({ seq: 20, hash: JSON.parse(lines[19] as string).hash })
    const intact = verifyAuditLog(lines)
    writeFileSync(s.log, `${lines.slice(0, 17).join('\n')}\n`)
    const cut = readAuditLines(s.log)
    const truncated = verifyAuditLog(cut, anchor)
    const refusedCut = reopen(s.dir)
    let prev = JSON.parse(lines[8] as string).hash as string
    const rewritten = lines.slice(0, 9)
    for (const text of lines.slice(9)) {
      const l = JSON.parse(text)
      if (l.seq === 10) l.decision = 'reject'
      l.prev = prev
      l.hash = auditHash(l)
      prev = l.hash
      rewritten.push(JSON.stringify(l))
    }
    writeFileSync(s.log, `${rewritten.join('\n')}\n`)
    const diverged = verifyAuditLog(rewritten, anchor)
    const refusedRewrite = reopen(s.dir)
    console.log(
      `MEASURE L4: intact ${JSON.stringify(intact)}; cut chain ${JSON.stringify(verifyAuditLog(cut))}, with anchor ${truncated.anchor?.state}; rewritten chain ${JSON.stringify(verifyAuditLog(rewritten))}, with anchor ${diverged.anchor?.state}; a new edge: ${refusedCut}, ${refusedRewrite}`,
    )
    expect(intact).toEqual({ ok: true, lines: 20 })
    expect(verifyAuditLog(cut)).toEqual({ ok: true, lines: 17 })
    expect(truncated).toMatchObject({ ok: false, anchor: { state: 'truncated', seq: 20, lines: 17 } })
    expect(verifyAuditLog(rewritten)).toEqual({ ok: true, lines: 20 })
    expect(diverged).toMatchObject({ ok: false, anchor: { state: 'diverged', seq: 20 } })
    expect([refusedCut, refusedRewrite]).toEqual(['truncated', 'diverged'])
    // (e) The log back, with one line past its anchor (as a crash between an append and its anchor leaves it): a new
    // edge opens and moves the anchor.
    const { hash: last, ...fields } = JSON.parse(lines[19] as string) as Record<string, unknown> & {
      hash: string
    }
    const line21 = { ...fields, seq: 21, prev: last, detail: null }
    const extra = JSON.stringify({ ...line21, hash: auditHash(line21 as never) })
    writeFileSync(s.log, `${[...lines, extra].join('\n')}\n`)
    expect(reopen(s.dir)).toBe('opened')
    expect(readAuditAnchor(s.db, 'audit.jsonl')?.seq).toBe(21)
  })
})

describe('L5: one writer per state directory', () => {
  it('L5 (a, b, c): a second store refuses with busy, in this process and against a child process, until the holder is gone', async () => {
    const dir = join(tmp.dir, 'l5')
    mkdirSync(dir)
    const path = join(dir, 'edge.sqlite')
    const first = new SqliteStore(path)
    const inProcess = (() => {
      try {
        new SqliteStore(path).close()
        return 'opened'
      } catch (e) {
        return (e as { code?: unknown }).code
      }
    })()
    first.close()
    const STORE = resolve(import.meta.dirname, '../src/adapters/sqlite-store.ts')
    const script = `import { SqliteStore } from ${JSON.stringify(STORE)}; new SqliteStore(process.argv[1]); process.stdout.write('held\\n'); setInterval(() => {}, 1000)`
    const child = spawn(process.execPath, ['--input-type=module', '--no-warnings', '-e', script, path], {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    await new Promise<void>((done, fail) => {
      child.stdout?.on('data', (d: Buffer) => d.toString().includes('held') && done())
      child.once('exit', (c) => fail(new Error(`the child exited with ${c}`)))
    })
    let againstChild: unknown
    try {
      new SqliteStore(path).close()
      againstChild = 'opened'
    } catch (e) {
      againstChild = (e as { code?: unknown }).code
    }
    child.kill('SIGKILL')
    await new Promise((r) => child.once('exit', r))
    const lock = JSON.parse(readFileSync(join(dir, 'audit.lock'), 'utf8')) as { pid: number }
    const after = new SqliteStore(path)
    after.close()
    console.log(
      `MEASURE L5: in process ${inProcess}; against a live child ${againstChild}; the killed child's lock (pid ${lock.pid === child.pid ? 'of the child' : lock.pid}) taken over`,
    )
    expect([inProcess, againstChild]).toEqual(['busy', 'busy'])
    expect(lock.pid).toBe(child.pid)
  }, 20_000)
})

describe('L6: the private-address guard refuses 12 relay URLs and allows 6', () => {
  const REFUSED = [
    'http://127.0.0.1:7701',
    'http://[::1]:7701',
    'http://169.254.169.254',
    'http://10.1.2.3',
    'http://172.16.0.1',
    'http://192.168.1.1',
    'http://[fd00::1]',
    'http://224.0.0.1',
    'http://0.0.0.0:7701',
    'http://[::ffff:127.0.0.1]',
    'http://[fe80::1]',
    'http://localhost:7701',
  ]

  /** One send to bob, whose record names `url`, with the given lookup and options; the target and the calls made. */
  async function publishTo(
    url: string,
    o: { lookup?: (h: string) => Promise<readonly string[]>; urls?: string[]; open?: boolean } = {},
  ) {
    const clock = new FakeClock()
    const relay = new DownUntil(clock, 0)
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { relays: [url], ttl: 86_400 }))
    const edge = new Edge({
      keys: P.carol.keys,
      store: new SqliteStore(':memory:'),
      relays: { client: relay, urls: o.urls ?? [HOME] },
      records,
      policy: { roots: [], types: ['*'] },
      clock,
      rng: seededRng('l6'),
      audit: new MemoryAuditSink(),
      lookup: o.lookup ?? (async () => ['93.184.215.14']),
      ...(o.open === true ? { allowPrivateRelays: true } : {}),
    })
    const sent = await edge.send({ to: [P.bob.address], type: 't', body: 1 })
    return { target: sent.targets[0], calls: relay.published.length, edge }
  }

  // Post-hoc, 2026-10-25: L6 pre-registered a name resolving to one public and one private address as
  // allowed; that expectation is reversed, and such a name is refused with no request, as the core's judgeAddresses does.
  it('L6: refused at publish with no request, a mixed name too; allowed for public hosts, an own relay and allowPrivateRelays', async () => {
    const refused: string[] = []
    for (const url of REFUSED) {
      const { target, calls } = await publishTo(url)
      if (target?.state === 'failed' && target.reason === 'resolve-failed' && calls === 0) refused.push(url)
    }
    const allowed = [
      await publishTo('https://1.1.1.1'),
      await publishTo('https://[2606:4700:4700::1111]'),
      await publishTo('https://relay.example.test', { lookup: async () => ['93.184.215.14'] }),
      await publishTo('http://127.0.0.1:7701', { urls: [HOME, 'http://127.0.0.1:7701/'] }),
      await publishTo('http://10.1.2.3', { open: true }),
    ].filter((r) => r.target?.state === 'published' && r.calls === 1).length
    const inside = await publishTo('https://inside.example.test', {
      lookup: async () => ['10.0.0.1', 'fd00::1'],
    })
    const mixed = await publishTo('https://mixed.example.test', {
      lookup: async () => ['10.0.0.5', '1.1.1.1'],
    })
    console.log(
      `MEASURE L6: refused ${refused.length} of ${REFUSED.length} at publish with 0 requests; allowed ${allowed} of 5; a name resolving only inside: ${inside.target?.state} ${inside.target?.reason}; a name resolving to 10.0.0.5 and 1.1.1.1: ${mixed.target?.state} ${mixed.target?.reason}, ${mixed.calls} requests`,
    )
    expect(refused).toEqual(REFUSED)
    expect(allowed).toBe(5)
    expect([inside.target?.state, inside.calls]).toEqual(['failed', 0])
    expect([mixed.target?.state, mixed.target?.reason, mixed.calls]).toEqual(['failed', 'resolve-failed', 0])
  })

  it('L6: refused at a record fetch and at a subscribe too', async () => {
    const { edge } = await publishTo('https://1.1.1.1')
    await expect(edge.resolver.address(P.mallory.address, ['http://192.168.1.1'])).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    await expect(edge.receiver.run('http://[fd00::1]')).rejects.toMatchObject({ code: 'resolve-failed' })
    console.log('MEASURE L6: a hint relay at 192.168.1.1 and a run at [fd00::1]: resolve-failed, no call')
  })
})
