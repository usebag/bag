import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  codingEvaluator,
  GROUP_KEY_TYPE,
  groupEvaluator,
  type Hop,
  openGroupKey,
  openSealed,
  parseEnvelope,
  type SealingKey,
  type SigningKey,
  signMembership,
  signSubscribe,
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
  SqliteStore,
  subscribeUrl,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Party,
  party,
  relayEvents,
  until,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 40: removal through the release relay. The admin
// removes carol: generation 2 goes to bob and erin before the group's new record; a fresh sender seals to generation
// 2, which bob and erin open; a sender that cached the generation-1 record still seals to it, which bob and erin open
// (no forward secrecy in v1); carol's hop past its exp is refused at subscribe. No generation key and no identity seed
// is written anywhere in plaintext. (Changed 2026-10-26: once the relay stores the group's new record it ends carol's subscription with `revoked`
// and refuses her chain, so neither post reaches her, her unexpired hop is refused `revoked` at subscribe and her post
// 403 `revoked`. Before it, carol's edge received both posts, refused m2 open-failed and opened m3, and the relay
// admitted her unexpired hop and stored her post.)

/** The relay's answer to a subscribe: `ok`, or `error <code>`, read from its frame by a raw client. */
async function subscribeOutcome(
  url: string,
  mailbox: string,
  key: SigningKey,
  auth: readonly Hop[],
): Promise<string> {
  const ws = new WebSocket(subscribeUrl(url))
  return await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.close()
      reject(new Error('no answer within 10 s'))
    }, 10_000)
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as { t: string; nonce?: string; error?: string }
      if (f.t === 'challenge') {
        const sig = signSubscribe(key, f.nonce as string, mailbox, null)
        ws.send(JSON.stringify({ t: 'auth', mailbox, signer: key.address, auth, cursor: null, sig }))
      } else if (f.t === 'ok' || f.t === 'error') {
        clearTimeout(timer)
        ws.close()
        resolve(f.t === 'ok' ? 'ok' : `error ${f.error}`)
      }
    })
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

/** A member's edge at the group's mailbox, on real files, with the groups evaluator beside the coding one. */
function at(w: World, p: Party, group: string, store: GroupKeyStore, roots: readonly string[]) {
  const dir = join(w.dir, `${p.name}-at-group`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const sqlite = new SqliteStore(join(dir, 'edge.sqlite'))
  const client = createRelayClient()
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
    audit: new FsAuditSink(join(dir, 'audit.jsonl')),
    flushEveryMs: 200,
  })
  const received: InboundMessage[] = []
  edge.setDefault({ session: 'group', deliver: (m) => void received.push(m) })
  onTestFinished(async () => {
    await edge.stop()
    sqlite.close()
  })
  const has = (id: string): boolean => received.some((m) => m.id === id)
  const reason = (id: string): string | null | undefined =>
    sqlite.inboxList().find((r) => r.id === id)?.reason
  return { edge, received, has, reason }
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

describe('e2e scenario 40: removal rotates the group key', () => {
  it('(40) remove(carol): generation 2 to bob and erin before the new record; the relay then cuts carol off: neither a fresh sender nor a cached record reaches her, her hop is refused revoked and her post 403; carol past her hop is refused; no key in any file', async () => {
    // The relay's own log orders the publishes (L5 (a)), so this scenario spawns its relay even under AC_RELAY_URL.
    const w = await withSpawnedRelays(() => world('s40'))
    const group = party('group')
    const [bob, carol, erin, alice, dave] = [
      party('bob'),
      party('carol'),
      party('erin'),
      party('alice'),
      party('dave'),
    ]
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
    const mine = {
      bob: await own(w, bob, group.address),
      carol: await own(w, carol, group.address),
      erin: await own(w, erin, group.address),
    }
    for (const p of [bob, carol, erin]) await admin.add(p.address, { exp: t + 3600 })
    await until('three members to accept generation 1', () =>
      Object.values(mine).every((m) => m.kept.length === 1),
    )
    // The short hop expires 8 s after the control, whatever the setup cost on a loaded machine.
    const shortExp = systemClock.now() + 8
    const shortHop = signMembership(group.signing, carol.address, shortExp)
    expect(await subscribeOutcome(w.url, group.address, carol.signing, [shortHop])).toBe('ok')

    const roots = [alice.address, dave.address, group.address]
    const atCarol = at(w, carol, group.address, mine.carol.store, roots)
    const atErin = at(w, erin, group.address, mine.erin.store, roots)
    await atCarol.edge.start()
    await atErin.edge.start()
    const a = w.node('alice', { keys: alice.keys })
    const m1 = await a.edge.send({ to: [group.address], type: 'chat.v1', body: { n: 1 } })
    const p0 = await atErin.edge.send({ to: [group.address], type: 'chat.v1', body: { from: 'erin' } })
    await until('m1 and p0 at carol and erin', () =>
      [m1, p0].every((s) => atCarol.has(s.id) && atErin.has(s.id)),
    )

    // L5 (a): generation 2 to the two remaining members, both published before the group's new record.
    const rotation = await admin.remove(carol.address)
    expect(rotation.generation).toBe(2)
    const sentTo = rotation.sent.map(
      (s) => parseEnvelope(adminNode.store.outboxGet(s.id)?.bytes as Uint8Array).to,
    )
    expect(sentTo).toEqual([[bob.address], [erin.address]])
    expect(rotation.record).toMatchObject({
      revoked: [carol.address],
      sealing_key: adminStore.body(group.address, 2).sealing_key,
      rotation_key: cold.address,
    })
    const events = relayEvents(w.relay)
    const keyAt = rotation.sent.map((s) => events.findIndex((e) => e.event === 'publish' && e.id === s.id))
    const recordAt = events.findIndex(
      (e) =>
        e.event === 'publish-record' &&
        e.kind === 'address' &&
        e.signer === group.address &&
        e.iat === rotation.record.iat,
    )
    expect(keyAt.every((i) => i >= 0 && i < recordAt)).toBe(true)
    await until(
      'bob and erin to accept generation 2',
      () => mine.bob.kept.length === 2 && mine.erin.kept.length === 2,
    )
    expect(mine.carol.kept.length).toBe(1)
    const atBob = at(w, bob, group.address, mine.bob.store, roots)
    await atBob.edge.start()
    await until('the backlog at bob', () => atBob.has(m1.id) && atBob.has(p0.id))

    // Storing the group's new record ended carol's subscription at the group's mailbox, `revoked`.
    await until('the relay to end carol at the new record', () =>
      relayEvents(w.relay).some(
        (e) => e.event === 'subscribe-closed' && e.signer === carol.address && e.reason === 'revoked',
      ),
    )

    // L5 (b): a fresh sender seals to generation 2: bob and erin open it; carol, cut off at the relay, never receives it.
    const d = w.node('dave', { keys: dave.keys })
    const m2 = await d.edge.send({ to: [group.address], type: 'chat.v1', body: { n: 2 } })
    await until('m2 at bob and erin', () => atBob.has(m2.id) && atErin.has(m2.id))
    expect([atCarol.has(m2.id), atCarol.reason(m2.id)]).toEqual([false, undefined])

    // L5 (c): the sender whose cache holds the generation-1 record seals to generation 1, which bob and erin open; it
    // does not reach carol either.
    const cached = a.store.cacheGet(`address:${group.address}`, 'address', systemClock.now())
    expect(cached).not.toBeNull()
    const m3 = await a.edge.send({ to: [group.address], type: 'chat.v1', body: { n: 3 } })
    await until('m3 at bob and erin', () => [atBob, atErin].every((e) => e.has(m3.id)))
    expect(atCarol.has(m3.id)).toBe(false)

    // L5x: carol's unexpired hop is refused at subscribe, and her post is refused 403 revoked by the relay, which
    // reads the group's kept revoked list for the group root its accept-from record admits by its address.
    const longHop = membershipHop(mine.carol.store, group.address)
    const lateSubscribe = await subscribeOutcome(w.url, group.address, carol.signing, [longHop])
    expect(lateSubscribe).toBe('error revoked')
    const p1 = await atCarol.edge.send({
      to: [group.address],
      type: 'chat.v1',
      body: { from: 'carol, removed' },
    })
    expect(p1.targets.map((t) => [t.state, t.reason])).toEqual([['failed', 'revoked']])
    const p1Line = relayEvents(w.relay).find((e) => e.event === 'publish' && e.id === p1.id)
    expect(p1Line).toBeUndefined()

    // L5 (d): carol's hop past its exp is refused at subscribe.
    await until('the short hop to expire', () => systemClock.now() > shortExp, 15_000)
    const expired = await subscribeOutcome(w.url, group.address, carol.signing, [shortHop])
    expect(expired).toBe('error hop-expired')

    // L6: no generation key and no identity seed in any file, argument or environment value; the two controls.
    const generations: SealingKey[] = [1, 2].map(
      (n) =>
        openGroupKey(
          adminStore.body(group.address, n),
          { address: group.address, key: group.sealing },
          systemClock.now(),
        ).key,
    )
    const seeds = [group, bob, carol, erin, alice, dave].flatMap((p) => [
      p.signing.exportSeed(),
      p.sealing.exportSeed(),
    ])
    const secrets = [...generations.map((k) => k.exportSeed()), ...seeds]
    const all = files(w.dir)
    const inFiles = count(
      all.map((f) => readFileSync(f)),
      secrets,
    )
    const inProcess = count(
      [Buffer.from(process.argv.join(' ')), Buffer.from(Object.values(process.env).join('\n'))],
      secrets,
    )
    expect([inFiles, inProcess]).toEqual([0, 0])
    const m2Bytes = d.store.outboxGet(m2.id)?.bytes as Uint8Array
    const m3Bytes = a.store.outboxGet(m3.id)?.bytes as Uint8Array
    const opened = [
      openSealed(parseEnvelope(m3Bytes), { address: group.address, key: generations[0] as SealingKey }).body,
      openSealed(parseEnvelope(m2Bytes), { address: group.address, key: generations[1] as SealingKey }).body,
    ]
    expect(opened).toEqual([{ n: 3 }, { n: 2 }])
    const planted = join(w.dir, 'control', 'planted.txt')
    mkdirSync(join(w.dir, 'control'))
    writeFileSync(planted, `key=${Buffer.from(generations[0]?.exportSeed() as Uint8Array).toString('hex')}\n`)
    const argv = [
      'ac-relay',
      '--key',
      Buffer.from(generations[1]?.exportSeed() as Uint8Array).toString('base64url'),
    ]
    expect([count([readFileSync(planted)], secrets), count([Buffer.from(argv.join(' '))], secrets)]).toEqual([
      1, 1,
    ])
    console.log(
      `MEASURE 40: generation 2 to ${sentTo.length} members (not carol), keys at relay log lines ${keyAt.join(',')} before the record at ${recordAt}; carol's subscription ended revoked at the record; m2 (fresh sender) opened by bob and erin, not received by carol; m3 (cached record, generation 1) opened by bob and erin, not received by carol; carol's expired hop ${expired}`,
    )
    console.log(
      `MEASURE 40: carol's unexpired hop after removal: subscribe ${lateSubscribe}; her post ${p1.targets.map((t) => `${t.state} ${t.reason}`).join(', ')} at the relay, no publish line`,
    )
    console.log(
      `MEASURE L6 40: ${all.length} files, ${secrets.length} secrets (2 generations, ${seeds.length} seeds), occurrences ${inFiles} in files and ${inProcess} in argv and env; controls: the recovered keys open m3 and m2, a planted file and a planted argument counted 1 and 1`,
    )
  })
})
