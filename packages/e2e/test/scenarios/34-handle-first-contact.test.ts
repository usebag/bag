import { mkdirSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import {
  type AddressRecord,
  checkDiscovered,
  codingEvaluator,
  discover,
  handlePath,
  parseHandleRecord,
  parseRecord,
  parseTxtPresentation,
  serializeHandleRecord,
  serializeRecord,
  signHandleRecord,
  verifyHandleRecord,
  verifyRecord,
} from '@usebag/core'
import {
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  SqliteStore,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  extraRelay,
  now,
  type Party,
  party,
  rawPublish,
  until,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 34 (spec/SPEC.md §12.4 item 4): a first contact by
// handle, with the earlier failure removed. bob's records live only at globex's relay G;
// alice's edge has its own relay A and has never had mail from bob, so a send to bob's address fails resolve-failed,
// as it did on 2026-10-26. A reference resolution written here from @usebag/core alone, the steps an edge is to
// take, resolves bob@globex.e2e.test: globex's TXT (given as its text form: no DNS
// is asked) names g1 and host=bag, so the org record and the handle record are both at the one origin
// https://bag.globex.e2e.test, then bob's address record from the org record's
// relays. Sent with those relays to look up at, the message reaches bob: alice's address is in bob's accept-from record
// and bob's edge trusts it, since a handle finds an address and admits no one. Handle records of another key, of
// another handle and out of date resolve nothing. The https URLs map to a node:http server of this scenario on
// 127.0.0.1 (no TLS, no DNS).

const GLOBEX = 'globex.e2e.test'
const WELL_KNOWN = '/.well-known/bag/address.json'

describe('e2e scenario 34: a first contact by handle', () => {
  it('(34) bob@globex.e2e.test resolves through the TXT, the org record and a handle record to an address whose record is at the org relay; alice, with no hint, reaches bob by it; handle records of another key, another handle or out of date resolve nothing', async () => {
    const served = new Map<string, Uint8Array>()
    const server = createServer((req, res) => {
      const body = served.get(String(req.url))
      if (body === undefined) res.writeHead(404).end()
      else res.writeHead(200, { 'content-type': 'application/json' }).end(body)
    })
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
    onTestFinished(
      () =>
        new Promise<void>((done) => {
          server.closeAllConnections()
          server.close(() => done())
        }),
    )
    const local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    /** An https URL of the scenario's hosts, read from the local server by its path. */
    const get = async (url: string): Promise<Uint8Array | null> => {
      const { pathname } = new URL(url)
      const res = await fetch(`${local}${pathname}`)
      return res.status === 200 ? new Uint8Array(await res.arrayBuffer()) : null
    }

    const w = await withSpawnedRelays(() => world('s34', {}))
    const relayA = await extraRelay(w, 'relay-a', [])
    const [g1, bob, alice, mallory] = ['g1', 'bob', 'alice', 'mallory'].map((n) => party(n)) as [
      Party,
      Party,
      Party,
      Party,
    ]
    // globex: its org record names its relay G; bob's records are published at G only.
    const orgRecord = addressRecord(g1, { relays: [w.url], sealing: false })
    served.set(WELL_KNOWN, serializeRecord(orgRecord))
    const handle = (h: string, address: string, signer = g1, iat = now(), ttl = 3600) =>
      serializeHandleRecord(
        signHandleRecord(signer.signing, {
          kind: 'handle',
          org: signer.address,
          handle: h,
          address,
          iat,
          ttl,
        }),
      )
    served.set(handlePath(`bob@${GLOBEX}`), handle(`bob@${GLOBEX}`, bob.address))
    served.set(handlePath(`eve@${GLOBEX}`), handle(`eve@${GLOBEX}`, mallory.address, mallory))
    served.set(handlePath(`carl@${GLOBEX}`), handle(`bob@${GLOBEX}`, bob.address))
    served.set(handlePath(`old@${GLOBEX}`), handle(`old@${GLOBEX}`, bob.address, g1, now() - 7200, 3600))
    for (const r of [addressRecord(bob, { relays: [w.url] }), acceptFrom(bob, [alice.address])]) {
      expect((await rawPublish(w.url, serializeRecord(r))).status).toBe(200)
    }
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    // alice's edge: its own relay is A; G is another loopback relay, which the guard allows only by this option.
    const dir = join(w.dir, 'alice')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const store = new SqliteStore(join(dir, 'edge.sqlite'))
    const client = createRelayClient({})
    const a = new Edge({
      keys: alice.keys,
      store,
      relays: { client, urls: [relayA.url] },
      records: createRecordSource(client, { allowInsecureHttp: true }),
      policy: { roots: [], types: ['*'], evaluators: [codingEvaluator] },
      clock: systemClock,
      rng: systemRng,
      audit: new FsAuditSink(join(dir, 'audit.jsonl')),
      allowPrivateRelays: true,
    })
    onTestFinished(async () => {
      await a.stop()
      store.close()
    })

    // The earlier failure: no hint, no shared relay.
    await expect(a.send({ to: [bob.address], type: 'chat.v1', body: { n: 0 } })).rejects.toMatchObject({
      code: 'resolve-failed',
    })

    // The reference resolution of a handle (spec/SPEC.md §12.4 item 4).
    const txt = parseTxtPresentation(`"v=ac1; key=${g1.address}; host=bag"`)
    expect(discover([txt], GLOBEX).origin).toBe(`https://bag.${GLOBEX}`)
    const resolve = async (h: string): Promise<{ address: string; org: AddressRecord }> => {
      const t = now()
      const found = discover([txt], GLOBEX)
      const org = verifyRecord(parseRecord((await get(found.url)) as Uint8Array), t) as AddressRecord
      checkDiscovered(org, found)
      const bytes = await get(`${found.origin}${handlePath(h)}`)
      if (bytes === null) throw Object.assign(new Error('no such handle'), { code: 'resolve-failed' })
      const record = verifyHandleRecord(
        parseHandleRecord(bytes),
        { org: org.key, handle: h, revoked: org.revoked },
        t,
      )
      for (const relay of org.relays) {
        const res = await fetch(`${relay}/v0/fetch/record/${record.address}/address`)
        if (res.status !== 200) continue
        const addressRec = verifyRecord(parseRecord(new Uint8Array(await res.arrayBuffer())), t)
        if (addressRec.kind === 'address' && addressRec.key === record.address)
          return { address: record.address, org }
      }
      throw Object.assign(new Error('no address record at the org relays'), { code: 'resolve-failed' })
    }
    const found = await resolve(`bob@${GLOBEX}`)
    expect(found.address).toBe(bob.address)
    expect(found.org.relays).toEqual([w.url])
    const sent = await a.send({
      to: [found.address],
      relays: found.org.relays,
      type: 'chat.v1',
      body: { n: 1 },
    })
    expect(sent.targets.map((x) => [x.relay, x.state])).toEqual([[w.url, 'published']])
    await until('the first message at bob', () => b.received.length === 1)
    expect(b.received[0]?.from).toBe(alice.address)

    // Handle records that resolve nothing.
    const code = async (h: string) =>
      resolve(h).then(
        () => 'ok',
        (e: { code?: string }) => e.code ?? 'thrown',
      )
    expect(await code(`eve@${GLOBEX}`)).toBe('resolve-failed')
    expect(await code(`carl@${GLOBEX}`)).toBe('resolve-failed')
    expect(await code(`old@${GLOBEX}`)).toBe('record-expired')
    expect(await code(`nobody@${GLOBEX}`)).toBe('resolve-failed')
  })
})
