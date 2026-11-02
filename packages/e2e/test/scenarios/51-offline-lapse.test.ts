import { spawn } from 'node:child_process'
import { mkdirSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import {
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Hop,
  MAX_ENVELOPE_BYTES,
  parseRecord,
  serializeRecord,
  signHop,
  signRecord,
  signSubscribe,
} from '@usebag/core'
import {
  type EdgeKeys,
  epochOpener,
  FsKeyStore,
  KeyEpochStore,
  KeyRecordAdmin,
  keepAddressCopy,
  parseAuditLine,
  readAuditLines,
  subscribeUrl,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  CLI_MAIN,
  cliProcess,
  nodeAt,
  now,
  type Party,
  party,
  REPO,
  rawPublish,
  relayEvents,
  sleep,
  startRelay,
  until,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// Scenario 51: an identity left closed past its record lapse, and its coming back.
// Real relay, real CLI and MCP processes, a home made
// by keygen; only the lifetimes are short: Bob's records come from the same KeyRecordAdmin.rotate that `keys rotate`
// runs, with keyLifetime and addressTtl in place of its day, and the relay sweeps each second in place of each minute.
// The 7-day horizon is read with a test clock on the reader, and with short retentions.

const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
const KEY_LIFE = 10
const ADDRESS_TTL = 18

type Json = Record<string, unknown>
type Kind = 'address' | 'key' | 'accept-from'

interface Server {
  call(tool: string, args?: Json): Promise<{ readonly isError: boolean; readonly value: Json }>
  close(): Promise<void>
}

/** The MCP server of `name` as a child process, driven by the SDK's Client, as a host runs it. */
async function server(
  name: string,
  home: string,
  url: string,
  args: readonly string[] = [],
): Promise<Server> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [MAIN, '--as', name, '--dir', home, '--relay', url, ...args],
    cwd: REPO,
    stderr: 'ignore',
  })
  const client = new Client({ name: `e2e-${name}`, version: '0.0.0' })
  await client.connect(transport)
  onTestFinished(() => client.close())
  return {
    async call(tool, a = {}) {
      const r = await client.callTool({ name: tool, arguments: a }, undefined, { timeout: 30_000 })
      const text = (r.content as { text: string }[])[0]?.text ?? ''
      return { isError: r.isError === true, value: JSON.parse(text) as Json }
    },
    close: () => client.close(),
  }
}

const cli = (...args: string[]) => cliProcess(args)

/** A home made by keygen: its keys and its address. */
async function home(dir: string, name: string): Promise<{ keys: EdgeKeys; address: string }> {
  const made = await cli('keygen', name, '--dir', dir)
  expect(made.code).toBe(0)
  return { keys: new FsKeyStore(join(dir, 'keys')).load(name), address: made.out[0] as string }
}

/**
 * Bob's records as an install leaves them, with the given lifetimes: epoch 1 by KeyRecordAdmin.rotate, whose key stays
 * in his home, and the accept-from a pairing writes (edge pairing.ts: MAX_ENVELOPE_BYTES and `retention`, DEFAULT_TTL
 * there). Then nothing of his runs: he is closed.
 */
async function closeAfterPublishing(
  w: World,
  url: string,
  dir: string,
  keys: EdgeKeys,
  peer: string,
  lifetimes: { keyLifetime?: number; addressTtl?: number; retention?: number } = {},
) {
  const { retention = DEFAULT_TTL, ...lives } = lifetimes
  const node = nodeAt(w, 'bob-publishes', url, { keys })
  const admin = new KeyRecordAdmin({
    edge: node.edge,
    keys,
    store: new KeyEpochStore(join(dir, 'key-records')),
    clock: systemClock,
    rng: systemRng,
    relays: [url],
    ...lives,
  })
  const rotation = await admin.rotate()
  keepAddressCopy(dir, 'bob', rotation.address) // as rotateEpoch does: this is what a sweep leaves a home
  const accept = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: keys.signing.address,
    roots: [peer],
    max_bytes: MAX_ENVELOPE_BYTES,
    ttl: retention,
    iat: now(),
  })
  expect((await rawPublish(url, serializeRecord(accept))).status).toBe(200)
  await node.close()
  return rotation
}

/** What the relay answers for a record now: 200 while it stands, 404 once swept (spec/SPEC.md §8.7). */
async function recordStatus(url: string, address: string, kind: Kind): Promise<number> {
  const res = await fetch(`${url}/v0/fetch/record/${address}/${kind}`)
  await res.arrayBuffer()
  return res.status
}

/** Waits for the relay to have swept a record: its answer turns 404. */
async function swept(url: string, address: string, kind: Kind): Promise<void> {
  const end = Date.now() + 30_000
  while ((await recordStatus(url, address, kind)) !== 404) {
    if (Date.now() > end) throw new Error(`the ${kind} record of ${address} was not swept within 30 s`)
    await sleep(100)
  }
}

/** Polls `test` every 100 ms for up to 15 s. */
async function sleepUntil(test: () => Promise<boolean>): Promise<void> {
  for (const end = Date.now() + 15_000; !(await test()); await sleep(100)) {
    if (Date.now() > end) throw new Error('timed out')
  }
}

/** A record as the relay serves it now. */
async function addressAt(url: string, address: string): Promise<Json> {
  const res = await fetch(`${url}/v0/fetch/record/${address}/address`)
  return parseRecord(new Uint8Array(await res.arrayBuffer())) as unknown as Json
}

/** What the relay answers `s`, subscribing to `mailbox` under `hop`: `ok`, or the code of its refusal. */
async function subscribeAs(url: string, s: Party, mailbox: string, hop: Hop): Promise<string> {
  const ws = new WebSocket(subscribeUrl(url))
  return await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no answer to the subscribe within 10 s')), 10_000)
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as { t: string; nonce?: string; error?: string }
      if (f.t === 'challenge') {
        const sig = signSubscribe(s.signing, f.nonce as string, mailbox, null)
        ws.send(JSON.stringify({ t: 'auth', mailbox, signer: s.address, auth: [hop], cursor: null, sig }))
      } else if (f.t === 'ok' || f.t === 'error') {
        clearTimeout(timer)
        ws.close()
        resolve(f.t === 'ok' ? 'ok' : (f.error as string))
      }
    })
  })
}

describe('e2e scenario 51: an identity left closed past its record lapse', () => {
  it("(51) A's new sends fail resolve-failed once B's key record lapses, the MCP path's wait survives A's restart, mail sealed before the lapse still arrives, and B comes back with record keep --once from the copy in its home: the waits go out and new sends reach B", async () => {
    const w = await withSpawnedRelays(() => world('offline-lapse', { relayArgs: ['--sweep-interval', '1'] }))
    const R = w.url
    const [aliceHome, bobHome] = [join(w.dir, 'alice-home'), join(w.dir, 'bob-home')]
    const { address: alice } = await home(aliceHome, 'alice')
    const { address: bob, keys } = await home(bobHome, 'bob')
    expect((await cli('keys', 'rotate', 'alice', '--relay', R, '--dir', aliceHome)).code).toBe(0)
    const rotation = await closeAfterPublishing(w, R, bobHome, keys, alice, {
      keyLifetime: KEY_LIFE,
      addressTtl: ADDRESS_TTL,
    })
    expect([rotation.key.exp - rotation.key.iat, rotation.address.ttl]).toEqual([KEY_LIFE, ADDRESS_TTL])
    expect(rotation.address.sealing_key).toBeNull()

    const send = (n: number) =>
      cli(
        'send',
        '--as',
        'alice',
        '--to',
        bob,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        `{"n":${n}}`,
        '--dir',
        aliceHome,
      )
    const refused = `bag: resolve-failed: address:${bob} from relay; tried ${R} (none)`

    // Before the lapse: A seals to B's epoch key, and the relay holds it.
    const before = await send(1)
    expect([before.code, before.err]).toEqual([0, []])
    const sealed = before.out[0] as string

    // The key record lapses first, as it does in life (it is up to 12 hours older than the address record).
    await swept(R, bob, 'key')
    expect(await recordStatus(R, bob, 'address')).toBe(200)
    expect(await send(2)).toEqual({ code: 1, out: [], err: [refused] })

    // Then the address record. The accept-from record stays: it does not expire.
    await swept(R, bob, 'address')
    expect(await recordStatus(R, bob, 'accept-from')).toBe(200)
    expect(await send(3)).toEqual({ code: 1, out: [], err: [refused] })

    // The MCP path does not fail: it waits, in the memory of A's server, retrying while that lives.
    const first = await server('alice', aliceHome, R)
    const queued = await first.call('send', { to: [bob], type: 'chat.v1', body: { n: 4 } })
    expect(queued).toMatchObject({ isError: false, value: { waiting: true, to: [bob], tried: [R] } })
    expect((await first.call('status')).value.waiting).toHaveLength(1)
    await first.close()
    const decisions = readAuditLines(join(aliceHome, 'state', 'alice', 'audit.jsonl'))
      .map(parseAuditLine)
      .filter((l) => l.event === 'publish' && l.reason === 'resolve-failed')
      .map((l) => l.decision)
    expect(decisions[0]).toBe('queue')
    expect(decisions).not.toContain('reject')

    // A's session ends and a new one starts on the same home: the wait is there still, from the store (durable waiting).
    const second = await server('alice', aliceHome, R)
    expect((await second.call('status')).value.waiting).toHaveLength(1)

    // Mail sealed before the lapse arrives while B's records are still gone: subscribing needs no record, and the home
    // keeps the epoch key.
    const inbox = ['inbox', '--as', 'bob', '--relay', R, '--once', '--trust-root', alice, '--dir', bobHome]
    expect(await cli(...inbox)).toEqual({
      code: 0,
      out: [`accept ${sealed} ${alice} ${alice} chat.v1 {"n":1}`],
      err: [],
    })
    expect([await recordStatus(R, bob, 'key'), await recordStatus(R, bob, 'address')]).toEqual([404, 404])

    // B comes back: the guide's renewal step re-signs the copy in its home and publishes a new epoch.
    const waits = await second.call('send', { to: [bob], type: 'chat.v1', body: { n: 5 } })
    expect(waits).toMatchObject({ isError: false, value: { waiting: true } })
    const renewal = await cli('record', 'keep', '--as', 'bob', '--relay', R, '--once', '--dir', bobHome)
    expect([renewal.code, renewal.err]).toEqual([0, []])
    expect(renewal.out[0]).toMatch(new RegExp(`^healed ${bob} from the record kept here, signed `))
    expect(renewal.out).toContain(`published key ${bob} ${R}`)
    expect([await recordStatus(R, bob, 'key'), await recordStatus(R, bob, 'address')]).toEqual([200, 200])

    // The wait in the session that stayed up goes out, and a new sender reaches B at once.
    const end = Date.now() + 40_000
    while (((await second.call('status')).value.waiting as unknown[]).length > 0) {
      if (Date.now() > end) throw new Error('the waiting send did not go out within 40 s of the renewal')
      await sleep(250)
    }
    await second.close()
    const fresh = await send(6)
    expect([fresh.code, fresh.err]).toEqual([0, []])
    const late = await cli(...inbox)
    expect(late.code).toBe(0)
    expect(late.out.map((l) => l.slice(l.lastIndexOf(' ') + 1)).sort()).toEqual([
      '{"n":4}',
      '{"n":5}',
      '{"n":6}',
    ])

    console.log(
      `MEASURE 51: key lapse and address lapse each refuse the CLI's send (exit 1, resolve-failed); the MCP send waits, publish decisions ${decisions.join(' ')}, and the wait survives a restart; B after the lapse: inbox --once reads the mail sealed before it, record keep --once heals from the copy, and of n 1 to 6, B read 1, 4, 5 and 6, never 2 or 3, which the CLI refused`,
    )
  }, 120_000)

  it('(51) mail sealed before the lapse opens on a reader whose clock stands 6.9 days on, its epoch key in the home; the relay TTL is 7 days', async () => {
    expect(DEFAULT_TTL).toBe(604_800)
    const w = await world('offline-reader')
    const [aliceHome, bobHome] = [join(w.dir, 'alice-home'), join(w.dir, 'bob-home')]
    const { address: alice } = await home(aliceHome, 'alice')
    const { address: bob, keys } = await home(bobHome, 'bob')
    expect((await cli('keys', 'rotate', 'alice', '--relay', w.url, '--dir', aliceHome)).code).toBe(0)
    await closeAfterPublishing(w, w.url, bobHome, keys, alice)
    const body = ['--type', 'chat.v1', '--body', '{"n":1}', '--dir', aliceHome]
    const sent = await cli('send', '--as', 'alice', '--to', bob, '--relay', w.url, ...body)
    expect(sent.code).toBe(0)

    const opener = epochOpener(new KeyEpochStore(join(bobHome, 'key-records')), bob)
    const reader = w.node('bob', {
      keys: { signing: keys.signing, sealing: opener },
      roots: [{ address: alice }],
      clockOffset: Math.floor(6.9 * 86_400),
    })
    reader.edge.setDefault(reader.handler('bob-inbox'))
    await reader.edge.start()
    await until('the mail at the reader', () => reader.received.length === 1)
    expect(reader.received[0]).toMatchObject({ id: sent.out[0], from: alice, body: { n: 1 } })
  })

  it('(51) a server opened after the sweep under --keep-alive-records heals from the copy: both records come back', async () => {
    const w = await withSpawnedRelays(() => world('offline-open', { relayArgs: ['--sweep-interval', '1'] }))
    const bobHome = join(w.dir, 'bob-home')
    const { address: bob, keys } = await home(bobHome, 'bob')
    await closeAfterPublishing(w, w.url, bobHome, keys, bob, { keyLifetime: 1, addressTtl: 1 })
    await swept(w.url, bob, 'address')
    await swept(w.url, bob, 'key')
    const open = await server('bob', bobHome, w.url, ['--keep-alive-records'])
    type Kept = { healed: { signed_at: string } | null; last: { outcome: string } | null }
    let kept = (await open.call('status')).value.keep_alive as Kept
    for (let i = 0; i < 200 && kept.last === null; i++) {
      await sleep(100)
      kept = (await open.call('status')).value.keep_alive as Kept
    }
    // With a 1 s ttl a cycle that crosses a second finds the healed record due, and re-signs it: both are healthy.
    expect(['not-due', 're-signed']).toContain(kept.last?.outcome)
    expect(kept.healed?.signed_at).toEqual(expect.any(String))
    expect([await recordStatus(w.url, bob, 'key'), await recordStatus(w.url, bob, 'address')]).toEqual([
      200, 200,
    ])
  })

  it('(51) keys rotate after a sweep carries the rotation key and the revoked list of the copy; with the copy lost it is refused no-held-record and publishes nothing, until --accept-loss says so', async () => {
    const w = await withSpawnedRelays(() =>
      world('offline-revoked', { relayArgs: ['--sweep-interval', '1'] }),
    )
    const bobHome = join(w.dir, 'bob-home')
    const { address: bob, keys } = await home(bobHome, 'bob')
    const rotate = ['keys', 'rotate', 'bob', '--relay', w.url, '--dir', bobHome]
    await closeAfterPublishing(w, w.url, bobHome, keys, bob, { keyLifetime: 1, addressTtl: 1 })
    const [rotationKey, gone] = [`ed25519:${'ab'.repeat(32)}`, `ed25519:${'cd'.repeat(32)}`]
    const lapsing = (revoked: string[], rotation_key: string | null) =>
      signRecord(keys.signing, {
        kind: 'address',
        key: bob,
        sealing_key: null,
        relays: [w.url],
        rotation_key,
        revoked,
        ttl: 2,
        iat: now() + 1,
        rotated_from: null,
      })
    const record = lapsing([gone], rotationKey)
    keepAddressCopy(bobHome, 'bob', record)
    expect((await rawPublish(w.url, serializeRecord(record))).status).toBe(200)
    await swept(w.url, bob, 'address')
    const back = await cli(...rotate)
    expect([back.code, back.out[0]]).toEqual([0, expect.stringMatching(/^healed /)])
    expect(await addressAt(w.url, bob)).toMatchObject({
      rotation_key: rotationKey,
      revoked: [gone],
      sealing_key: null,
    })

    // The copy is gone and the record lapses again: nothing goes out, and an empty revoked list least of all.
    const again = lapsing([gone], rotationKey)
    expect((await rawPublish(w.url, serializeRecord(again))).status).toBe(200)
    await swept(w.url, bob, 'address')
    renameSync(join(bobHome, 'records', 'bob.address.json'), join(bobHome, 'records', 'moved-away'))
    const refused = await cli(...rotate)
    expect(refused.code).toBe(1)
    expect(refused.err[0]).toMatch(/^bag: no-held-record: /)
    expect(await recordStatus(w.url, bob, 'address')).toBe(404)
    const renewal = await cli('record', 'keep', '--as', 'bob', '--relay', w.url, '--once', '--dir', bobHome)
    expect([renewal.code, renewal.err[0]]).toEqual([1, expect.stringMatching(/^bag: no-held-record: /)])
    expect(await recordStatus(w.url, bob, 'address')).toBe(404)

    // The person's explicit act, which knows what it loses.
    expect((await cli(...rotate, '--accept-loss')).code).toBe(0)
    expect(await addressAt(w.url, bob)).toMatchObject({ rotation_key: null, revoked: [] })
  })

  it("(51) the relay keeps a lapsed record's revoked list past the sweep, and a newer record with an empty list empties it: the revoked key subscribes again", async () => {
    const w = await withSpawnedRelays(() =>
      world('offline-kept-list', { relayArgs: ['--sweep-interval', '1'] }),
    )
    const [B, S] = [party('bob'), party('session')]
    const hop = signHop(B.signing, S.address, [], now() + 3600)
    const subscribes = () => subscribeAs(w.url, S, B.address, hop)
    expect((await rawPublish(w.url, serializeRecord(acceptFrom(B, ['*'])))).status).toBe(200)
    const revoking = addressRecord(B, { relays: [w.url], ttl: 2, revoked: [S.address], sealing: false })
    expect((await rawPublish(w.url, serializeRecord(revoking))).status).toBe(200)
    expect(await subscribes()).toBe('revoked')
    await swept(w.url, B.address, 'address')
    expect(await subscribes()).toBe('revoked')
    const empty = addressRecord(B, { relays: [w.url], ttl: 3600, revoked: [], sealing: false })
    expect((await rawPublish(w.url, serializeRecord(empty))).status).toBe(200)
    expect(await subscribes()).toBe('ok')
  })

  it('(51) a rotation beside a live edge leaves its audit chain whole, for record keep and keys rotate beside a server and keys rotate beside inbox --watch: audit verify passes and the identity starts again', async () => {
    const w = await world('offline-fork')
    const [aliceHome, bobHome] = [join(w.dir, 'alice-home'), join(w.dir, 'bob-home')]
    const { address: alice } = await home(aliceHome, 'alice')
    const { address: bob, keys } = await home(bobHome, 'bob')
    expect((await cli('keys', 'rotate', 'alice', '--relay', w.url, '--dir', aliceHome)).code).toBe(0)
    await closeAfterPublishing(w, w.url, bobHome, keys, alice)
    const send = [
      'send',
      '--as',
      'alice',
      '--to',
      bob,
      '--relay',
      w.url,
      '--type',
      'chat.v1',
      '--dir',
      aliceHome,
    ]
    const log = join(bobHome, 'state', 'bob', 'audit.jsonl')
    const store = new KeyEpochStore(join(bobHome, 'key-records'))
    /** Makes the newest epoch 13 hours old, so that a keep rotates. */
    const due = (): void => {
      const n = store.epochs(bob)[0] as number
      const e = store.epoch(bob, n)
      store.renew(bob, n, e.iat - 13 * 3600, e.exp - 13 * 3600)
      store.markPublished(bob, n)
    }

    const live = await server('bob', bobHome, w.url, ['--keep-alive-records', '--trust-root', alice])
    expect(((await live.call('inbox')).value.messages as unknown[]).length).toBe(0)
    due()
    expect(
      (await cli('record', 'keep', '--as', 'bob', '--relay', w.url, '--once', '--dir', bobHome)).code,
    ).toBe(0)
    // A second apart: a relay refuses a key record no newer than the one it holds, stale-record.
    await sleep(1100)
    due()
    expect((await cli('keys', 'rotate', 'bob', '--relay', w.url, '--dir', bobHome)).code).toBe(0)
    expect((await cli(...send, '--body', '{"n":1}')).code).toBe(0)
    await sleepUntil(async () => ((await live.call('inbox')).value.messages as unknown[]).length === 1)
    await live.close()
    expect((await cli('audit', 'verify', log)).code).toBe(0)

    const again = await server('bob', bobHome, w.url, ['--keep-alive-records', '--trust-root', alice])
    expect((await again.call('status')).isError).toBe(false)
    await again.close()

    const args = [
      'inbox',
      '--as',
      'bob',
      '--relay',
      w.url,
      '--watch',
      '--trust-root',
      alice,
      '--dir',
      bobHome,
    ]
    const watch = spawn(process.execPath, [CLI_MAIN, ...args], { stdio: 'ignore' })
    onTestFinished(() => void watch.kill('SIGKILL'))
    await sleep(1500)
    due()
    expect((await cli('keys', 'rotate', 'bob', '--relay', w.url, '--dir', bobHome)).code).toBe(0)
    expect((await cli(...send, '--body', '{"n":2}')).code).toBe(0)
    await sleep(1500)
    watch.kill('SIGTERM')
    await new Promise((r) => watch.once('exit', r))
    expect((await cli('audit', 'verify', log)).code).toBe(0)
    const start = await cli(
      'inbox',
      '--as',
      'bob',
      '--relay',
      w.url,
      '--once',
      '--trust-root',
      alice,
      '--dir',
      bobHome,
    )
    expect([start.code, start.err]).toEqual([0, []])
  }, 60_000)

  it.each([
    ['the relay TTL', { ttl: 3, skew: 1 }, DEFAULT_TTL],
    ["B's accept-from ttl", { ttl: DEFAULT_TTL, skew: DEFAULT_SKEW }, 3],
  ] as const)(
    '(51) past %s the relay has dropped the mail: B reads nothing and nobody is told',
    async (_, window, retention) => {
      const w = await world('offline-retention')
      const relayDir = join(w.dir, 'relay')
      mkdirSync(relayDir)
      const relay = await withSpawnedRelays(() => startRelay(relayDir, window, ['--sweep-interval', '1']))
      onTestFinished(async () => {
        await relay.stop()
      })
      const [aliceHome, bobHome] = [join(w.dir, 'alice-home'), join(w.dir, 'bob-home')]
      const { address: alice } = await home(aliceHome, 'alice')
      const { address: bob, keys } = await home(bobHome, 'bob')
      expect((await cli('keys', 'rotate', 'alice', '--relay', relay.url, '--dir', aliceHome)).code).toBe(0)
      await closeAfterPublishing(w, relay.url, bobHome, keys, alice, { retention })
      const body = ['--type', 'chat.v1', '--body', '{"n":1}', '--dir', aliceHome]
      expect((await cli('send', '--as', 'alice', '--to', bob, '--relay', relay.url, ...body)).code).toBe(0)
      await until('the sweep of the mailbox row', () =>
        relayEvents(relay).some((e) => e.event === 'sweep' && (e.mailbox as number) > 0),
      )
      const inbox = ['inbox', '--as', 'bob', '--relay', relay.url, '--once', '--trust-root', alice]
      expect(await cli(...inbox, '--dir', bobHome)).toEqual({ code: 0, out: [], err: [] })
    },
  )
})
