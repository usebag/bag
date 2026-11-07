import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { acquireLock } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { connect, sayRelayFailures } from '../src/connect.ts'
import { connectCodeOf } from '../src/connect-code.ts'
import {
  type EnterpriseDeps,
  enterpriseStatus,
  fingerprint,
  recordProbe,
  roundTrip,
  signIn,
  signOut,
} from '../src/flow.ts'
import { EnterpriseError } from '../src/instance.ts'
import { createMcpServer } from '../src/mcp.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from '../src/ports.ts'
import {
  chainPath,
  lockAt,
  ownerOnly,
  profileHome,
  readSession,
  type Session,
  selectOrg,
} from '../src/session.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// The edges of connect, status, sign-out, the probes, the profiles and the MCP tools that the walk-through tests do not
// reach: an organisation with no relay, a grant that names no label, records a failed refresh left unpublished, a
// relay that serves no record, an older frame ahead of the probe, a held lock, the profile files' odd shapes.

const tmp = tempDir('branches')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const SECRET = 'branch-test-secret-only-for-these-tests-000'
let n = 0

function world(o: { relays?: FakeRelay | { publish: FakeRelay['publish'] } } = {}) {
  const time = { now: T0 }
  const fake = new FakeInstance({ domain: DOMAIN, now: () => time.now })
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  const relay = new FakeRelay()
  const home = join(tmp.dir, `home-${n++}`)
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => time.now },
    rng: seededRng(`branches-${n}`),
    fetch: fake.fetch,
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => null },
    },
    sleep: async () => {},
    relays: o.relays ?? relay,
  }
  const out: string[] = []
  const d = (org?: string): EnterpriseDeps => ({
    ...enterpriseDeps(
      ports,
      home,
      (l) => out.push(l),
      async () => null,
    ),
    ...(org === undefined ? {} : { org }),
  })
  const run = async (f: () => Promise<number>) => {
    out.length = 0
    try {
      return { exit: await f(), out: [...out], error: null as EnterpriseError | null }
    } catch (e) {
      if (!(e instanceof EnterpriseError)) throw e
      return { exit: e.exit, out: [...out], error: e }
    }
  }
  const connected = () => run(() => connect(d(), { text: code, version: VERSION }))
  return { fake, code, relay, home, ports, d, run, connected, time, out }
}

describe('connect and status at the edges', () => {
  it('an organisation with no relay: connected, but the round trip fails at none (no-relay), exit 1', async () => {
    const w = world()
    w.fake.relays.splice(0)
    const r = await w.connected()
    expect([r.exit, r.out]).toEqual([
      1,
      [
        'Connected as acme-example-1, but the relay round trip failed at none (no-relay): bag status tries again',
      ],
    ])
    // status has no relay to probe: its own lines, exit 0, no round-trip line.
    const s = await w.run(() => enterpriseStatus(w.d()))
    expect(s.exit).toBe(0)
    expect(s.out.some((l) => l.includes('relay round trip'))).toBe(false)
  })

  it('a grant that names no label: the key name is the label, in connect, status and the MCP sign_in', async () => {
    const w = world()
    w.fake.codeLabels.set(w.code, '')
    const r = await w.connected()
    expect(r.out).toEqual([expect.stringMatching(/^Connected as acme-example; relay round trip \d+ ms$/)])
    expect(readSession(w.home)?.label).toBeUndefined()
    const s = await w.run(() => enterpriseStatus(w.d()))
    expect(s.out.at(-1)).toMatch(/^Connected as acme-example; relay round trip \d+ ms$/)
  })

  it('records a failed refresh left unpublished: connected, but not published (not-published), exit 1', async () => {
    const w = world()
    expect((await w.connected()).exit).toBe(0)
    // The copy gone and the refresh unreachable: the tick publishes nothing, and connect says so.
    writeFileSync(join(profileHome(w.home, DOMAIN), 'enterprise', 'records.json'), '{}', { mode: 0o600 })
    w.time.now += 13 * 3600
    w.fake.down.set('/agent/refresh', 1)
    const r = await w.connected()
    expect([r.exit, r.out]).toEqual([
      1,
      [
        'Connected as acme-example-1, but its records were not published at https://relay.example.test (not-published): bag status tries again',
      ],
    ])
  })

  it('status with a publisher alone probes through bag own client: the relay fails the probe, exit 1', async () => {
    const relay = new FakeRelay()
    const w = world({ relays: { publish: relay.publish.bind(relay) } })
    // connect's round trip goes through bag's own client too, which reaches no relay here.
    const r = await w.connected()
    expect(r.exit).toBe(1)
    expect(r.out[0]).toMatch(
      /^Connected as acme-example-1, but the relay round trip failed at https:\/\/relay\.example\.test \(/,
    )
    const s = await w.run(() => enterpriseStatus(w.d()))
    expect([s.exit, s.out.at(-1)]).toEqual([
      1,
      expect.stringMatching(
        /^Connected as acme-example-1, but the relay round trip failed at https:\/\/relay\.example\.test \(/,
      ),
    ])
  })

  it('a held refresh lock: status says so and reports the session as it is', async () => {
    const w = world()
    await w.connected()
    const release = acquireLock(lockAt(profileHome(w.home, DOMAIN)))
    try {
      const s = await w.run(() => enterpriseStatus(w.d()))
      expect(s.out[0]).toBe(`held refresh ${lockAt(profileHome(w.home, DOMAIN))}`)
    } finally {
      release()
    }
  })

  it('a connect code waiting (label_taken left it pending): status names a console code, exit 4', async () => {
    const w = world()
    w.fake.liveLabels.add('taken')
    expect((await w.run(() => connect(w.d(), { text: w.code, label: 'taken', version: VERSION }))).exit).toBe(
      1,
    )
    const s = await w.run(() => enterpriseStatus(w.d()))
    expect([s.exit, s.out[0]]).toEqual([
      4,
      'waiting acme.example: a person is to approve the code (a console code)',
    ])
  })

  it('sayRelayFailures: one line per relay that did not take both records, its first code; nothing when all did', () => {
    const w = world()
    const r = 'https://r1.example.test'
    const outcomes = [
      { kind: 'address' as const, relay: r, ok: false, code: 'http-403' },
      { kind: 'accept-from' as const, relay: r, ok: false, code: 'unreachable' },
      { kind: 'address' as const, relay: 'https://r2.example.test', ok: false, code: null },
      { kind: 'address' as const, relay: 'https://r3.example.test', ok: true, code: null },
    ]
    sayRelayFailures(w.d(), outcomes)
    expect(w.out).toEqual([
      `relay ${r}: records not published (http-403)`,
      'relay https://r2.example.test: records not published (error)',
    ])
  })
})

describe('the probes on their own', () => {
  it('roundTrip without a relay or a chain, recordProbe without a relay or a record', async () => {
    const w = world()
    await w.connected()
    const s = readSession(w.home) as Session
    const fail = (p: Promise<number>) =>
      p.then(
        () => null,
        (e: Error) => e.message,
      )
    expect(await fail(roundTrip(w.d(), { ...s, org: { ...s.org, relays: [] } }))).toBe(
      'the relay round trip failed at none (no-relay)',
    )
    expect(await fail(roundTrip(w.d(), { ...s, local_hop: null }))).toBe(
      'the relay round trip failed at https://relay.example.test (no-chain)',
    )
    expect(await fail(recordProbe(w.d(), { ...s, org: { ...s.org, relays: [] } }))).toBe(
      'the relay round trip failed at none (no-relay)',
    )
    const other = { ...s, org: { ...s.org, relays: ['https://empty.example.test'] } }
    expect(await fail(recordProbe(w.d(), other))).toBe(
      'the relay round trip failed at https://empty.example.test (no-record)',
    )
  })

  it('an older frame ahead of the probe: found all the same, and nothing acknowledged', async () => {
    const w = world()
    await w.connected()
    const s = readSession(w.home) as Session
    const key = `https://relay.example.test ${s.agent_address}`
    w.relay.acks.clear()
    expect(await roundTrip(w.d(), s)).toBeGreaterThanOrEqual(0)
    expect(w.relay.acks.get(key)).toBeUndefined()
  })

  it('fingerprint of a short address is empty', () => {
    expect(fingerprint('ed25519:')).toBe('')
  })
})

describe('sign-in, sign-out and the profile files', () => {
  it('a waiting sign-in pinned to one instance refuses another; sign-out of an organisation not held', async () => {
    const w = world()
    const o = { domain: DOMAIN, instance: w.fake.origin, code: false, wait: false, version: VERSION }
    expect((await w.run(() => signIn(w.d(), o))).error?.code).toBe('authorization_pending')
    const other = await w.run(() => signIn(w.d(), { ...o, instance: 'https://other.example.test' }))
    expect([other.error?.code, other.error?.message]).toEqual([
      'pending',
      'pending: a sign-in to https://ent.example.test is waiting: bag sign-out drops it',
    ])
    const none = await w.run(() => signOut(w.d('other.example')))
    expect(none.error?.message).toBe('signed-out: other.example is not signed in')
    const empty = world()
    const status = await empty.run(() => enterpriseStatus(empty.d('other.example')))
    expect(status.error?.message).toBe('signed-out: not signed in to other.example')
  })

  it('selectOrg falls back to the first by name when current.json names none held; chainPath with no profile', async () => {
    const w = world()
    expect(chainPath(w.home)).toBe(join(w.home, 'enterprise', 'chain.json'))
    for (const d of ['a.example', 'b.example']) {
      mkdirSync(join(w.home, 'orgs', d, 'enterprise'), { recursive: true, mode: 0o700 })
      writeFileSync(join(w.home, 'orgs', d, 'enterprise', 'pending.json'), '{"v":1}', { mode: 0o600 })
    }
    mkdirSync(join(w.home, 'enterprise'), { recursive: true, mode: 0o700 })
    writeFileSync(join(w.home, 'enterprise', 'current.json'), '{"v":1,"domain":"gone.example"}', {
      mode: 0o600,
    })
    expect(selectOrg(w.home)).toBe('a.example')
  })

  it('an older session of no domain is refused; one beside its profile is dropped, the profile kept', async () => {
    const bad = world()
    mkdirSync(join(bad.home, 'enterprise'), { recursive: true, mode: 0o700 })
    writeFileSync(join(bad.home, 'enterprise', 'session.json'), '{"v":1,"domain":"Not A Domain"}', {
      mode: 0o600,
    })
    expect(() => readSession(bad.home)).toThrow(/^session-invalid: .* holds a session of no domain$/)
    const w = world()
    await w.connected()
    const kept = readSession(w.home)
    writeFileSync(join(w.home, 'enterprise', 'session.json'), JSON.stringify({ ...kept, generation: 99 }), {
      mode: 0o600,
    })
    expect(readSession(w.home)?.generation).toBe(kept?.generation)
  })

  it('ownerOnly names 0700 for a directory others may enter', () => {
    const dir = join(tmp.dir, 'open-dir')
    mkdirSync(dir, { mode: 0o755 })
    chmodSync(dir, 0o755)
    expect(() => ownerOnly('enterprise', dir, true)).toThrow(/has mode 0755; it must be 0700$/)
  })
})

describe('the MCP tools at the edges', () => {
  async function mcp() {
    const w = world()
    const [a, b] = InMemoryTransport.createLinkedPair()
    await createMcpServer(w.ports, w.home).connect(a)
    const client = new Client({ name: 'test', version: '0' })
    await client.connect(b)
    const call = async (name: string, args?: Record<string, unknown>) => {
      const r = (await client.callTool({ name, ...(args === undefined ? {} : { arguments: args }) })) as {
        content: { text: string }[]
        isError?: boolean
      }
      return { text: r.content.map((c) => c.text).join('\n'), isError: r.isError === true }
    }
    return { w, call }
  }

  it('a code or a domain that is not a string; status with org, an empty org and no arguments', async () => {
    const { w, call } = await mcp()
    expect(await call('connect', { code: 5 })).toEqual({
      text: 'usage: no code: paste the code from the console',
      isError: true,
    })
    expect((await call('sign_in', { domain: 5, instance: 5 })).isError).toBe(true)
    expect((await call('connect', { code: w.code })).isError).toBe(false)
    for (const args of [{ org: DOMAIN }, { org: '' }, undefined])
      expect((await call('status', args)).text.split('\n').at(-1)).toMatch(/relay round trip \d+ ms$/)
  })

  it('sign_in whose grant names no label says the key name', async () => {
    const { w, call } = await mcp()
    const args = { domain: DOMAIN, instance: w.fake.origin }
    expect((await call('sign_in', args)).text.split('\n').at(-1)).toBe(
      'Waiting for a person to approve it; ask again to see the state',
    )
    w.fake.approve('BCDF-GGG0')
    w.fake.byUser('BCDF-GGG0').label = ''
    expect((await call('sign_in', args)).text.split('\n').at(-1)).toBe('Connected as acme-example')
  })

  it('connect waiting on the signer is exit 4, not a tool error', async () => {
    const { w, call } = await mcp()
    w.fake.signer = false
    const r = await call('connect', { code: w.code })
    expect([r.isError, r.text]).toEqual([
      false,
      "Waiting for the organisation's signer: run bag status in a minute",
    ])
  })
})
