import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  codingEvaluator,
  GROUP_KEY_TYPE,
  groupEvaluator,
  openGroupKey,
  openSealed,
  parseEnvelope,
  type SealingKey,
} from '@usebag/core'
import {
  acceptGroupKey,
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  GroupAdmin,
  GroupKeyStore,
  type InboundMessage,
  memberKeys,
  membershipHop,
  RelayError,
  type SocketFactory,
  SqliteStore,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Party,
  party,
  rawPublish,
  relayEvents,
  sleep,
  until,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 42 (the counterpart on the release relay of the CLI's read on the in-process relay): a removed member holding a LIVE subscription at the group's mailbox is cut at the
// relay the moment the group's new record is stored. Scenario 40 asserts the relay's `subscribe-closed revoked` line,
// a raw handshake refused `revoked` and the post's target `failed revoked`; this one reads the cut from the removed
// member's own edge: the close code on her socket, the error frame, the delay from the record's store to the close, her
// edge's audit lines and surfaced error, and that no subscription of hers is admitted again; then her fetch by id
// (403 `revoked`, 200 before the cut) and the relay's status for her post (403 `revoked`), against the remaining
// member, whose live subscription the record does not end and who reads the next post under generation 2.

/** A wall-clock instant in microseconds, from the relay's RFC 3339 timestamp (tracing's JSON lines). */
function micros(ts: string): number {
  const m = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?Z$/.exec(ts)
  if (m === null) throw new Error(`not an RFC 3339 UTC timestamp: ${ts}`)
  const fraction = (m[2] ?? '').padEnd(6, '0').slice(0, 6)
  return Date.parse(`${m[1]}Z`) * 1000 + Number(fraction)
}

/** The spawned relay's JSON log lines: the fields and the timestamp of each. */
function relayLines(w: World): { at: number; fields: Record<string, unknown> }[] {
  return w.relay
    .stderr()
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => {
      const line = JSON.parse(l) as { timestamp: string; fields: Record<string, unknown> }
      return { at: micros(line.timestamp), fields: line.fields }
    })
}

/** A member's own edge, which accepts group keys into its store. */
async function own(w: World, p: Party, group: string): Promise<{ store: GroupKeyStore; kept: string[] }> {
  const n = w.node(p.name, { keys: p.keys, roots: [{ address: group }], types: [GROUP_KEY_TYPE] })
  await n.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
  await n.edge.publishRecord(acceptFrom(p, [group]))
  const store = new GroupKeyStore(join(w.dir, `${p.name}-groups`))
  const kept: string[] = []
  n.edge.setDefault({
    session: 'groups',
    deliver: (m) =>
      void kept.push(
        acceptGroupKey(m, { keys: p.keys, store, clock: systemClock, audit: n.edge.audit }).kept,
      ),
  })
  await n.edge.start()
  return { store, kept }
}

/** What the subscription sockets of one edge saw: each socket opened, each error frame, each close and its code. */
interface Watched {
  opened: number
  oks: number
  errors: string[]
  closes: { code: number; at: number }[]
}

/** Microseconds on the wall clock, as precise as the process's monotonic clock allows. */
const wallMicros = (): number => Math.round((performance.timeOrigin + performance.now()) * 1000)

/**
 * A member's edge at the group's mailbox on real files, with the groups evaluator beside the coding one, its
 * subscription sockets watched (the global WebSocket, with listeners added beside the edge's own) and the errors its
 * run surfaces kept.
 */
function at(w: World, p: Party, group: string, store: GroupKeyStore, roots: readonly string[]) {
  const dir = join(w.dir, `${p.name}-at-group`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const sqlite = new SqliteStore(join(dir, 'edge.sqlite'))
  const watched: Watched = { opened: 0, oks: 0, errors: [], closes: [] }
  const socketFactory: SocketFactory = (url) => {
    const ws = new WebSocket(url)
    watched.opened++
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as { t: string; error?: string }
      if (f.t === 'ok') watched.oks++
      if (f.t === 'error') watched.errors.push(String(f.error))
    })
    ws.addEventListener('close', (event) => void watched.closes.push({ code: event.code, at: wallMicros() }))
    return ws
  }
  const client = createRelayClient({ socketFactory })
  const surfaced: unknown[] = []
  const auditPath = join(dir, 'audit.jsonl')
  const edge = new Edge({
    keys: memberKeys(store, group, p.keys, systemClock),
    mailbox: group,
    auth: [membershipHop(store, group)],
    store: sqlite,
    relays: { client, urls: [w.url] },
    records: createRecordSource(client, { allowInsecureHttp: true }),
    policy: {
      roots: roots.map((address) => ({ address })),
      types: ['*'],
      evaluators: [codingEvaluator, groupEvaluator],
    },
    clock: systemClock,
    rng: systemRng,
    audit: new FsAuditSink(auditPath),
    flushEveryMs: 200,
    onError: (e) => void surfaced.push(e),
  })
  const received: InboundMessage[] = []
  edge.setDefault({ session: 'group', deliver: (m) => void received.push(m) })
  onTestFinished(async () => {
    await edge.stop()
    sqlite.close()
  })
  const has = (id: string): boolean => received.some((m) => m.id === id)
  /** The subscribe lines of its audit log: "decision reason" each, with the detail's end when it has one. */
  const subscribeAudit = (): string[] =>
    readFileSync(auditPath, 'utf8')
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l) as { event: string; decision: string; reason: string; detail: string | null })
      .filter((l) => l.event === 'subscribe')
      .map((l) => {
        const end = l.detail === null ? undefined : (JSON.parse(l.detail) as { end?: string }).end
        return [l.decision, l.reason, end].filter((s) => s !== undefined).join(' ')
      })
  return { edge, sqlite, received, has, watched, surfaced, subscribeAudit, auditPath }
}

/** The answer to a fetch by id through an edge: "200" or "<status> <code>". */
async function fetchOutcome(edge: Edge, url: string, id: string): Promise<string> {
  try {
    await edge.fetch(url, id)
    return '200'
  } catch (e) {
    if (e instanceof RelayError) return `${e.status} ${e.code}`
    throw e
  }
}

/** Every regular file under a directory, recursively. */
function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : e.isFile() ? [join(dir, e.name)] : [],
  )
}

/** The text forms of a secret (hex, upper hex, base64, base64url) and its raw bytes. */
function forms(secret: Uint8Array): Buffer[] {
  const b = Buffer.from(secret)
  return [
    b,
    ...[
      b.toString('hex'),
      b.toString('hex').toUpperCase(),
      b.toString('base64'),
      b.toString('base64url'),
    ].map((t) => Buffer.from(t)),
  ]
}

/** How many times any form of any secret occurs in the byte strings: a count, never the secret. */
function count(haystacks: readonly Buffer[], secrets: readonly Uint8Array[]): number {
  let n = 0
  for (const bytes of haystacks)
    for (const needle of secrets.flatMap(forms))
      for (let i = bytes.indexOf(needle); i >= 0; i = bytes.indexOf(needle, i + 1)) n++
  return n
}

/** How long the scenario watches for a resubscription after the edge's last refusal. */
const QUIET_MS = 5_000

describe('e2e scenario 42: a group removal is cut at the relay', () => {
  it('(42) remove(carol) while she is subscribed: her live subscription ends revoked with 4001 at the record, her edge stops after its refusals and is never admitted again; her fetch is 403 revoked and her post 403 revoked; bob stays subscribed and reads the next post under generation 2; no key in any file', async () => {
    // The scenario reads the relay's own log (the cut, the subscribe lines), so it spawns its relay even under
    // AC_RELAY_URL.
    const w = await withSpawnedRelays(() => world('s42'))
    const group = party('group')
    const [bob, carol, alice, dave] = [party('bob'), party('carol'), party('alice'), party('dave')]
    const adminStore = new GroupKeyStore(join(w.dir, 'admin-groups'))
    const adminNode = w.node('admin', { keys: group.keys })
    const admin = new GroupAdmin({
      edge: adminNode.edge,
      keys: group.keys,
      store: adminStore,
      clock: systemClock,
      rng: systemRng,
    })
    const cold = party('group-rotation')
    await admin.create({ relays: [w.url], roots: [alice.address, dave.address], rotationKey: cold.address })
    const t = systemClock.now()
    const mine = { bob: await own(w, bob, group.address), carol: await own(w, carol, group.address) }
    for (const p of [bob, carol]) await admin.add(p.address, { exp: t + 3600 })
    await until('bob and carol to accept generation 1', () =>
      Object.values(mine).every((m) => m.kept.length === 1),
    )

    // Both members hold a live subscription at the group's mailbox, and both receive m1 over it.
    const roots = [alice.address, dave.address, group.address]
    const atCarol = at(w, carol, group.address, mine.carol.store, roots)
    const atBob = at(w, bob, group.address, mine.bob.store, roots)
    await atCarol.edge.start()
    await atBob.edge.start()
    const subscribed = (signer: string): number =>
      relayEvents(w.relay).filter(
        (e) => e.event === 'subscribe' && e.mailbox === group.address && e.signer === signer,
      ).length
    await until(
      'carol and bob subscribed at the group',
      () => subscribed(carol.address) === 1 && subscribed(bob.address) === 1,
    )
    const d = w.node('dave', { keys: dave.keys })
    const m1 = await d.edge.send({ to: [group.address], type: 'chat.v1', body: { n: 1 } })
    await until('m1 at carol and bob, live', () => atCarol.has(m1.id) && atBob.has(m1.id))
    const fetchBefore = await fetchOutcome(atCarol.edge, w.url, m1.id)
    expect(fetchBefore).toBe('200')
    const subscribesBefore = subscribed(carol.address)
    expect([subscribesBefore, atCarol.watched.opened, atCarol.watched.oks, atCarol.watched.closes]).toEqual([
      1,
      1,
      1,
      [],
    ])

    // The removal: generation 2 to bob alone, then the group's new record, which revokes carol.
    const rotation = await admin.remove(carol.address)
    expect([rotation.generation, rotation.record.revoked]).toEqual([2, [carol.address]])

    // (1) The cut: carol's live socket gets the error frame `revoked` and close 4001, read on her own edge's socket.
    await until('carol to be closed', () => atCarol.watched.closes.length >= 1)
    const lines = relayLines(w)
    const recordLine = lines.find(
      (l) =>
        l.fields.event === 'publish-record' &&
        l.fields.kind === 'address' &&
        l.fields.signer === group.address &&
        l.fields.iat === rotation.record.iat,
    )
    const cutLine = lines.find(
      (l) =>
        l.fields.event === 'subscribe-closed' &&
        l.fields.mailbox === group.address &&
        l.fields.signer === carol.address,
    )
    expect(recordLine).toBeDefined()
    expect(cutLine?.fields.reason).toBe('revoked')
    const firstClose = atCarol.watched.closes[0] as { code: number; at: number }
    expect([atCarol.watched.errors[0], firstClose.code]).toEqual(['revoked', 4001])
    // The delay from the record's store (the relay's publish-record line) to the close at carol's socket, and to the
    // relay's own subscribe-closed line, on the one machine's wall clock.
    const recordAt = (recordLine as { at: number }).at
    const closeMs = (firstClose.at - recordAt) / 1000
    const relayMs = ((cutLine as { at: number }).at - recordAt) / 1000
    // The claim is the relay's: from the stored record to its own subscribe-closed line, both stamped by the relay's
    // clock, so a test process or socket that is starved cannot move it. The close at carol's socket is awaited
    // above, and its wall-clock latency (which includes this process) is a loose backstop and the MEASURE line.
    expect(relayMs).toBeLessThan(1000)
    expect(closeMs).toBeLessThan(5000)

    // Her edge treats `revoked` as a refusal (receiver.ts REFUSALS): it tries twice more, each handshake refused
    // `revoked` with 4001, and ends the subscription for good on the third refusal in a row, surfacing the error.
    await until('carol to end her subscription', () =>
      atCarol.subscribeAudit().includes('reject revoked subscription-ended'),
    )
    const endedAt = relayLines(w).length
    await sleep(QUIET_MS)
    const after = relayLines(w).map((l) => l.fields)
    const refusedAfter = after
      .slice(lines.indexOf(cutLine as (typeof lines)[number]) + 1)
      .filter((e) => e.event === 'subscribe-refused')
      .map((e) => String(e.code))
    const subscribesAfter = subscribed(carol.address) - subscribesBefore
    const quietLines = after.slice(endedAt).filter((e) => String(e.event).startsWith('subscribe')).length
    expect({
      audit: atCarol.subscribeAudit(),
      surfaced: atCarol.surfaced.map((e) => (e instanceof RelayError ? e.code : String(e))),
      opened: atCarol.watched.opened,
      errors: atCarol.watched.errors,
      codes: atCarol.watched.closes.map((c) => c.code),
      refusedAfter,
      subscribesAfter,
      quietLines,
    }).toEqual({
      audit: ['retry revoked', 'retry revoked', 'reject revoked subscription-ended'],
      surfaced: ['revoked'],
      opened: 3,
      errors: ['revoked', 'revoked', 'revoked'],
      codes: [4001, 4001, 4001],
      refusedAfter: ['revoked', 'revoked'],
      subscribesAfter: 0,
      quietLines: 0,
    })

    // (2) Her fetch by id of the envelope she read before the cut is now 403 `revoked`; bob's is 200.
    const fetchAfter = await fetchOutcome(atCarol.edge, w.url, m1.id)
    const bobFetch = await fetchOutcome(atBob.edge, w.url, m1.id)
    expect([fetchAfter, bobFetch]).toEqual(['403 revoked', '200'])

    // (3) Her post to the group: her edge's target fails `revoked`, and the relay's answer to its exact bytes is 403
    // `revoked`, with no publish line for it.
    const p1 = await atCarol.edge.send({
      to: [group.address],
      type: 'chat.v1',
      body: { from: 'carol, removed' },
    })
    expect(p1.targets.map((x) => `${x.state} ${x.reason}`)).toEqual(['failed revoked'])
    const p1Bytes = atCarol.sqlite.outboxGet(p1.id)?.bytes as Uint8Array
    const raw = await rawPublish(w.url, p1Bytes)
    expect([raw.status, raw.body]).toEqual([403, { error: 'revoked' }])
    expect(relayEvents(w.relay).filter((e) => e.event === 'publish' && e.id === p1.id)).toEqual([])

    // (4) Bob accepted generation 2; his subscription, under a hop the record does not revoke, is still the first one,
    // and the next post, from a sender who reads the new record, is sealed to generation 2 and reaches him over it.
    await until('bob to accept generation 2', () => mine.bob.kept.length === 2)
    expect(mine.carol.kept.length).toBe(1)
    const a = w.node('alice', { keys: alice.keys })
    const m2 = await a.edge.send({ to: [group.address], type: 'chat.v1', body: { n: 2 } })
    await until('m2 at bob', () => atBob.has(m2.id))
    expect(atCarol.has(m2.id)).toBe(false)
    const generations: SealingKey[] = [1, 2].map(
      (n) =>
        openGroupKey(
          adminStore.body(group.address, n),
          { address: group.address, key: group.sealing },
          systemClock.now(),
        ).key,
    )
    const m2Env = parseEnvelope(a.store.outboxGet(m2.id)?.bytes as Uint8Array)
    const opened = openSealed(m2Env, { address: group.address, key: generations[1] as SealingKey }).body
    let underGen1 = 'opened'
    try {
      openSealed(m2Env, { address: group.address, key: generations[0] as SealingKey })
    } catch {
      underGen1 = 'refused'
    }
    const bobBody = atBob.received.find((m) => m.id === m2.id)?.body
    const bobLines = relayEvents(w.relay).filter(
      (e) =>
        e.mailbox === group.address && e.signer === bob.address && String(e.event).startsWith('subscribe'),
    )
    expect({ opened, underGen1, bobBody, bobLines: bobLines.map((e) => e.event) }).toEqual({
      opened: { n: 2 },
      underGen1: 'refused',
      bobBody: { n: 2 },
      bobLines: ['subscribe'],
    })

    // (5) No generation key and no identity seed in any file of the world (the relay's log, the edges' stores and
    // audit logs, the members' group stores), in the lines this scenario prints, or in argv and env; the controls.
    const seeds = [group, bob, carol, alice, dave, cold].flatMap((p) => [
      p.signing.exportSeed(),
      p.sealing.exportSeed(),
    ])
    const secrets = [...generations.map((k) => k.exportSeed()), ...seeds]
    const measure = `MEASURE 42: carol's live subscription cut at the group's new record: error frame ${atCarol.watched.errors[0]} close ${firstClose.code}, ${closeMs.toFixed(2)} ms from the relay's publish-record line to the close at her socket (the relay's subscribe-closed revoked line at ${relayMs.toFixed(2)} ms); her edge: audit ${atCarol.subscribeAudit().join(', ')}, surfaced ${atCarol.surfaced.map((e) => (e instanceof RelayError ? e.code : '?')).join(',')}; her sockets ${atCarol.watched.opened} opened, close codes ${atCarol.watched.closes.map((c) => c.code).join(',')}; relay subscribe lines for her at the group ${subscribesBefore} before the cut and ${subscribesAfter} after, subscribe-refused ${refusedAfter.join(',')} after it, ${quietLines} subscribe lines in ${QUIET_MS} ms after her edge ended; her fetch of m1 ${fetchBefore} before and ${fetchAfter} after (bob ${bobFetch}); her post ${p1.targets.map((x) => `${x.state} ${x.reason}`).join(',')} at her edge and ${raw.status} ${(raw.body as { error: string }).error} raw, no publish line; bob kept generations ${mine.bob.kept.length}, his one subscription not ended, m2 sealed to generation 2 (generation 1 ${underGen1}) read by him`
    const all = files(w.dir)
    const inFiles = count(
      all.map((f) => readFileSync(f)),
      secrets,
    )
    const inProcess = count(
      [
        Buffer.from(process.argv.join(' ')),
        Buffer.from(Object.values(process.env).join('\n')),
        Buffer.from(measure),
        Buffer.from(atCarol.surfaced.map(String).join('\n')),
      ],
      secrets,
    )
    expect([inFiles, inProcess]).toEqual([0, 0])
    const planted = join(w.dir, 'control', 'planted.txt')
    mkdirSync(join(w.dir, 'control'))
    writeFileSync(planted, `key=${Buffer.from(generations[1]?.exportSeed() as Uint8Array).toString('hex')}\n`)
    const plantedLine = `seed ${Buffer.from(carol.signing.exportSeed()).toString('base64url')}`
    expect([count([readFileSync(planted)], secrets), count([Buffer.from(plantedLine)], secrets)]).toEqual([
      1, 1,
    ])
    console.log(measure)
    console.log(
      `MEASURE L-keys 42: ${all.length} files, ${secrets.length} secrets (2 generations, ${seeds.length} seeds), occurrences ${inFiles} in files and ${inProcess} in argv, env, the measure line and the surfaced errors; controls: a planted file and a planted line counted 1 and 1`,
    )
  })
})
