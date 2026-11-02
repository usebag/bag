import { readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import {
  isAcError,
  type MembersRecord,
  type PolicyRecord,
  parseMembersRecord,
  parsePolicyRecord,
  serializePolicyRecord,
  signPolicyRecord,
  verifyMembersRecord,
  verifyPolicyRecord,
} from '@usebag/core'
import {
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  PolicyRefusal,
  SqliteStore,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import { acceptFrom, addressRecord, now, type Party, party, until, world } from '../harness.ts'

// e2e scenario 37: the two policy records from files and the served one over HTTP.
// Bob's org root signs a served record (its scopes) and a members record (what its own edges alone enforce); bob's edge
// loads both from files through the core: a tampered served record is bad-record-sig, one dated ahead is future-iat,
// and a members record offered where the served one belongs is bad-record, so the members' rules cannot be served by
// mistake. The valid served record is enforced on a message through the release relay. Carol's org serves its own
// served record over HTTP at /.well-known/bag/policy.json (a node:http server on 127.0.0.1 standing in for
// https://<domain>/; where the record is served is still open), and bob's gate, reading it
// through its hook, refuses before sealing a type that carol's org does not accept: the gate bob's Edge composes from
// its members record, the hook given in its `gate` option, so each send is judged once.

const POLICY_PATH = '/.well-known/bag/policy.json'
const SCOPES = [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }]

function served(root: Party, iat = now()): PolicyRecord {
  return signPolicyRecord(root.signing, {
    kind: 'policy',
    key: root.address,
    scopes: SCOPES,
    external: null,
    inspection: null,
    iat,
  })
}

function members(root: Party): MembersRecord {
  return signPolicyRecord(root.signing, {
    kind: 'policy-members',
    key: root.address,
    roots: { mode: 'deny', list: ['domain:evil.example'], unknown: 'refuse' },
    rates: null,
    outbound: { deny: ['domain:evil.example'] },
    moderation: null,
    iat: now(),
  })
}

const code = (f: () => unknown): string => {
  try {
    f()
    return 'ok'
  } catch (e) {
    return isAcError(e) ? e.code : String(e)
  }
}

describe('e2e scenario 37: the policy records from files and over HTTP', () => {
  it('(37) a tampered, future or misplaced record is refused by the core, the valid one is enforced through the relay, and a recipient org record read over HTTP refuses a type before sealing', async () => {
    const w = await world('s37')
    const O = party('bobs-org')
    const Q = party('carols-org')
    const A = party('alice')
    const B = party('bob')
    const C = party('carol')
    const servedFile = join(w.dir, 'policy.json')
    const membersFile = join(w.dir, 'members.json')
    writeFileSync(servedFile, serializePolicyRecord(served(O)))
    writeFileSync(membersFile, serializePolicyRecord(members(O)))
    const text = readFileSync(servedFile, 'utf8')
    // One accepted type changed after signing: the form holds, the signature does not.
    const tampered = text.replace('"chat.*"', '"chit.*"')
    const ahead = serializePolicyRecord(served(O, now() + 3600))
    const misplaced = readFileSync(membersFile)
    expect([
      code(() => verifyPolicyRecord(parsePolicyRecord(tampered), now())),
      code(() => verifyPolicyRecord(parsePolicyRecord(ahead), now())),
      code(() => verifyPolicyRecord(parsePolicyRecord(misplaced), now())),
    ]).toEqual(['bad-record-sig', 'future-iat', 'bad-record'])
    const org = verifyPolicyRecord(parsePolicyRecord(readFileSync(servedFile)), now())
    const own = verifyMembersRecord(parseMembersRecord(readFileSync(membersFile)), now())

    const theirs = served(Q)
    let asked = 0
    const site = createServer((req, res) => {
      asked++
      if (req.url !== POLICY_PATH) return void res.writeHead(404).end()
      res.writeHead(200, { 'content-type': 'application/json' }).end(serializePolicyRecord(theirs))
    })
    await new Promise<void>((resolve) => site.listen(0, '127.0.0.1', resolve))
    onTestFinished(() => new Promise<void>((resolve) => site.close(() => resolve())))
    const base = `http://127.0.0.1:${(site.address() as AddressInfo).port}`
    const recipientPolicy = async (address: string): Promise<PolicyRecord | null> => {
      if (address !== C.address) return null
      const res = await fetch(`${base}${POLICY_PATH}`)
      return verifyPolicyRecord(parsePolicyRecord(new Uint8Array(await res.arrayBuffer())), now())
    }

    const a = w.node('alice', { keys: A.keys, roots: [{ address: B.address }] })
    const c = w.node('carol', { keys: C.keys, roots: [{ address: B.address }] })
    const store = new SqliteStore(join(w.dir, 'bob.sqlite'))
    const client = createRelayClient({})
    const edge = new Edge({
      keys: B.keys,
      store,
      relays: { client, urls: [w.url] },
      records: createRecordSource(client, { allowInsecureHttp: true }),
      policy: { roots: [{ address: A.address }], types: ['*'], org, members: own },
      gate: { recipientPolicy },
      clock: systemClock,
      rng: systemRng,
      audit: new FsAuditSink(join(w.dir, 'bob-audit.jsonl')),
      flushEveryMs: 200,
    })
    onTestFinished(async () => {
      await edge.stop()
      store.close()
    })
    for (const [n, p] of [
      [a, A],
      [c, C],
    ] as const) {
      await n.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
      await n.edge.publishRecord(acceptFrom(p, ['*']))
    }
    await edge.publishRecord(addressRecord(B, { relays: [w.url] }))
    await edge.publishRecord(acceptFrom(B, ['*']))
    edge.setDefault({ session: 'bob', deliver: () => {} })
    c.edge.setDefault(c.handler('carol'))
    await c.edge.start()
    await edge.start()

    const deploy = await a.edge.send({ to: [B.address], type: 'deploy.run', body: { target: 'prod' } })
    const chat = await a.edge.send({ to: [B.address], type: 'chat.v1', body: { text: 'hello' } })
    await until(
      "bob's two rows settled",
      () => store.inboxList().filter((r) => r.state === 'acked').length === 2,
    )
    expect(store.inboxList().map((r) => [r.id, r.reason])).toEqual([
      [deploy.id, 'type-not-accepted'],
      [chat.id, null],
    ])

    const refused = await edge
      .send({ to: [C.address], type: 'deploy.run', body: {} })
      .catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(PolicyRefusal)
    expect((refused as PolicyRefusal).rule).toBe('recipient.scopes[0].accept_types')
    const passed = await edge.send({ to: [C.address], type: 'chat.v1', body: { text: 'hi carol' } })
    await until('carol received the chat', () => c.received.length === 1)
    expect([c.received[0]?.id, asked]).toEqual([passed.id, 2])
  })
})
