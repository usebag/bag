import { mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import {
  codingEvaluator,
  GROUP_KEY_TYPE,
  groupCaveat,
  groupEvaluator,
  type Hop,
  hopPreimage,
  openGroupKey,
  openSealed,
  parseEnvelope,
  type SigningKey,
  serializeRecord,
  signMembership,
  signPreimage,
  signSubscribe,
  toHex,
} from '@usebag/core'
import {
  acceptGroupKey,
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  GroupAdmin,
  GroupKeyStore,
  groupOpener,
  type InboundMessage,
  memberKeys,
  membershipHop,
  RelayError,
  SqliteStore,
  subscribeUrl,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import { acceptFrom, addressRecord, type Party, party, until, type World, world } from '../harness.ts'

// e2e scenario 38: a group through the release relay. The admin
// makes the group's records and its first generation; each member's own edge accepts its group-key.v1 message; a
// member subscribes to the group's mailbox and fetches from it with its hop under the relay's existing rule, and a
// non-member is refused, each outcome read from the relay's own frame or answer.

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
function at(w: World, name: string, p: Party, group: string, store: GroupKeyStore, roots: readonly string[]) {
  const dir = join(w.dir, name)
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
  return { edge, received }
}

/** Every regular file under a directory, recursively. */
function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : e.isFile() ? [join(dir, e.name)] : [],
  )
}

/** How many times any secret occurs in the files, as text forms or raw bytes: a count, never the secret. */
function occurrences(paths: readonly string[], secrets: readonly Uint8Array[]): number {
  let n = 0
  for (const path of paths) {
    const bytes = readFileSync(path)
    for (const s of secrets) {
      const b = Buffer.from(s)
      const needles = [
        b,
        ...[
          b.toString('hex'),
          b.toString('hex').toUpperCase(),
          b.toString('base64'),
          b.toString('base64url'),
        ].map((t) => Buffer.from(t)),
      ]
      for (const needle of needles)
        for (let i = bytes.indexOf(needle); i >= 0; i = bytes.indexOf(needle, i + 1)) n++
    }
  }
  return n
}

describe('e2e scenario 38: a group, its membership hops and its first generation', () => {
  it('(38) the admin publishes the group record and accept-from; members accept generation 1; a member reads the group mailbox with its hop; non-members are refused by the relay', async () => {
    const w = await world('s38')
    const group = party('group')
    const bob = party('bob')
    const carol = party('carol')
    const alice = party('alice')
    const dave = party('dave')
    const mallory = party('mallory')
    // The group's rotation key, its cold key, which create names.
    const cold = party('group-rotation')
    const adminStore = new GroupKeyStore(join(w.dir, 'admin-groups'))
    const adminNode = w.node('admin', { keys: group.keys })
    const admin = new GroupAdmin({
      edge: adminNode.edge,
      keys: group.keys,
      store: adminStore,
      clock: systemClock,
      rng: systemRng,
    })

    // L1: the group's identity, records and first generation.
    const { record, accept } = await admin.create({
      relays: [w.url],
      roots: [alice.address],
      rotationKey: cold.address,
    })
    const served = async (kind: string) =>
      new Uint8Array(await (await fetch(`${w.url}/v0/fetch/record/${group.address}/${kind}`)).arrayBuffer())
    expect(Buffer.from(await served('address')).equals(Buffer.from(serializeRecord(record)))).toBe(true)
    expect(Buffer.from(await served('accept-from')).equals(Buffer.from(serializeRecord(accept)))).toBe(true)
    expect(record).toMatchObject({
      key: group.address,
      relays: [w.url],
      ttl: 3600,
      revoked: [],
      rotation_key: cold.address,
    })
    expect(record.sealing_key).not.toBe(toHex(group.sealing.publicKey))
    expect(accept.roots).toEqual([group.address, alice.address])
    const groupDir = join(w.dir, 'admin-groups', group.address.slice('ed25519:'.length))
    const mode = (p: string): string => (statSync(p).mode & 0o777).toString(8)
    expect([mode(groupDir), mode(join(groupDir, 'g1.json'))]).toEqual(['700', '600'])

    // L3: the distribution, one group-key.v1 envelope to each member's own mailbox.
    const b = await own(w, bob, group.address)
    const c = await own(w, carol, group.address)
    const sentBob = await admin.add(bob.address)
    await admin.add(carol.address)
    expect(sentBob.targets.map((t) => [t.relay, t.state])).toEqual([[w.url, 'published']])
    await until('both members to accept generation 1', () => b.kept.length === 1 && c.kept.length === 1)
    expect([b.kept, c.kept]).toEqual([['new'], ['new']])
    const keyBytes = adminNode.store.outboxGet(sentBob.id)?.bytes as Uint8Array
    expect(parseEnvelope(keyBytes)).toMatchObject({ from: group.address, to: [bob.address], auth: [] })
    expect(b.store.body(group.address, 1)).toMatchObject({
      group: group.address,
      generation: 1,
      member: bob.address,
      sealing_key: record.sealing_key,
    })

    // L2 (a), (b): the hop, and the relay's existing rule admitting the member.
    const hop = membershipHop(b.store, group.address)
    expect(hop).toMatchObject({ iss: group.address, sub: bob.address, caveats: [groupCaveat(group.address)] })
    expect(await subscribeOutcome(w.url, group.address, bob.signing, [hop])).toBe('ok')
    const atBob = at(w, 'bob-at-group', bob, group.address, b.store, [alice.address, group.address])
    await atBob.edge.start()
    const a = w.node('alice', { keys: alice.keys })
    const sent = await a.edge.send({ to: [group.address], type: 'chat.v1', body: { text: 'hello group' } })
    await until('the post at bob', () => atBob.received.length === 1)
    expect(atBob.received[0]).toMatchObject({
      id: sent.id,
      from: alice.address,
      body: { text: 'hello group' },
    })
    const outbox = a.store.outboxGet(sent.id)?.bytes as Uint8Array
    expect(Buffer.from(await atBob.edge.fetch(w.url, sent.id)).equals(Buffer.from(outbox))).toBe(true)

    // L1 (c): the admin's own opener opens the group's mail.
    const adminOpener = groupOpener(
      adminStore,
      group.address,
      { address: group.address, key: group.sealing },
      systemClock,
    )
    expect(openSealed(parseEnvelope(outbox), { address: group.address, key: adminOpener }).body).toEqual({
      text: 'hello group',
    })

    // L2 (c): non-members, each refused in the relay's error frame, and a non-member's fetch refused 403.
    const exp = systemClock.now() + 3600
    const selfHop = signMembership(dave.signing, dave.address, exp)
    const claim = { iss: group.address, sub: dave.address, caveats: [groupCaveat(group.address)], exp }
    const forged = { ...claim, sig: signPreimage(mallory.signing, hopPreimage(claim)) }
    const refusals = [
      await subscribeOutcome(w.url, group.address, dave.signing, []),
      await subscribeOutcome(w.url, group.address, dave.signing, [selfHop]),
      await subscribeOutcome(w.url, group.address, dave.signing, [forged]),
      await subscribeOutcome(w.url, group.address, dave.signing, [hop]),
    ]
    expect(refusals).toEqual([
      'error not-authorized',
      'error not-authorized',
      'error bad-hop-sig',
      'error chain-not-to-sender',
    ])
    const d = w.node('dave', { keys: dave.keys })
    const fetched = await d.edge.fetch(w.url, sent.id).then(
      () => '200',
      (e: unknown) => (e instanceof RelayError ? `${e.status} ${e.code}` : String(e)),
    )
    expect(fetched).toBe('403 not-authorized')

    // L6 (part): no generation key, in any form, in any file of the scenario.
    const key = openGroupKey(
      adminStore.body(group.address, 1),
      { address: group.address, key: group.sealing },
      systemClock.now(),
    ).key
    const parties = [group, bob, carol, alice]
    const secrets = [
      key.exportSeed(),
      ...parties.flatMap((p) => [p.signing.exportSeed(), p.sealing.exportSeed()]),
    ]
    const all = files(w.dir)
    expect(occurrences(all, secrets)).toBe(0)
    console.log(
      `MEASURE L1/L2/L3 38: records served byte-identical; 2 members accepted generation 1; bob subscribed ok and fetched the exact bytes; refusals ${refusals.join(', ')}; dave's fetch ${fetched}; ${all.length} files, 0 secrets; group-key envelope ${keyBytes.length} bytes`,
    )
  })
})
