import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { type ConnectOptions, connect } from '../src/connect.ts'
import { connectCodeOf, parseConnectCode } from '../src/connect-code.ts'
import { CHECK_TYPE, enterpriseStatus, PROBE_MS, tick } from '../src/flow.ts'
import { EnterpriseError } from '../src/instance.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from '../src/ports.ts'
import { readSession } from '../src/session.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// connect against the recorded fake instance and a relay in memory (no network): the pasted code alone, the code's
// origin pinned (no record fetched, no BAG_ENTERPRISE_*), the origin's rules (https or loopback http, the
// private-address guard), the records and the round trip through the first relay, one line, no key, token or code
// said, AGENT_EXIT's exits. Where the code comes from (BAG_ORG_CODE or a line of stdin,
// never argv) is the command's rule, tested with bag's CLI.

const tmp = tempDir('connect')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
// A test secret of the minted form: 43 base64url characters.
const SECRET = 'connect-test-secret-only-for-these-tests-00'
let n = 0

interface Run {
  readonly exit: number
  readonly out: string[]
  readonly error: EnterpriseError | null
}

function setup(
  o: {
    origin?: string
    guard?: () => Promise<string | null>
    relays?: string[]
    down?: Record<string, number>
  } = {},
) {
  const time = { now: T0 }
  const fake = new FakeInstance({
    domain: DOMAIN,
    now: () => time.now,
    ...(o.origin ? { origin: o.origin } : {}),
  })
  const pasted = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(pasted)
  if (o.relays !== undefined) fake.relays.splice(0, fake.relays.length, ...o.relays)
  // The org's relays: each takes the records unless `down` names it with the status it fails with (0: no answer).
  const relays = new FakeRelay()
  for (const [url, status] of Object.entries(o.down ?? {})) relays.down.set(url, status)
  const published = relays.published
  const seen: string[] = []
  const home = join(tmp.dir, `home-${n++}`)
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => time.now },
    rng: seededRng(`connect-${n}`),
    fetch: fake.fetch,
    net: {
      txt: async (name) => {
        seen.push(`txt ${name}`)
        return []
      },
      get: async (url) => {
        seen.push(`get ${url}`)
        return { status: 200, body: new TextEncoder().encode('{"v":1,"instance":"https://other.example"}') }
      },
      guard: {
        connectTo: async (url) => {
          seen.push(`guard ${url}`)
          return o.guard === undefined ? '192.0.2.10' : o.guard()
        },
      },
    },
    sleep: async () => {
      throw new Error('connect never waits')
    },
    relays,
  }
  const out: string[] = []
  const deps = () =>
    enterpriseDeps(
      ports,
      home,
      (l) => out.push(l),
      async () => {
        throw new Error('connect reads no code of its own')
      },
    )
  const run = async (text: string, more: Partial<ConnectOptions> = {}): Promise<Run> => {
    out.length = 0
    try {
      const exit = await connect(deps(), { text, version: VERSION, ...more })
      return { exit, out: [...out], error: null }
    } catch (e) {
      if (!(e instanceof EnterpriseError)) throw e
      return { exit: e.exit, out: [...out], error: e }
    }
  }
  const status = async (): Promise<{ exit: number; out: string[] }> => {
    out.length = 0
    const exit = await enterpriseStatus(deps())
    return { exit, out: [...out] }
  }
  return { fake, seen, home, run, status, pasted, published, relays, time, deps }
}

/** The key seeds of a home: none may ever be said. */
const ROUND_TRIP = /^Connected as acme-example-1; relay round trip \d+ ms$/

const seeds = (home: string): string[] =>
  readdirSync(join(home, 'keys')).map(
    (f) => JSON.parse(readFileSync(join(home, 'keys', f), 'utf8')).sign_seed as string,
  )

describe('connect', () => {
  it('connects with the pasted code alone: the code names the instance, one line, Connected as <label> with the round trip', async () => {
    const w = setup()
    const r = await w.run(`  ${w.pasted}\n`)
    expect(r.exit).toBe(0)
    expect(r.out).toEqual([expect.stringMatching(ROUND_TRIP)])
    expect(w.fake.calls[0]?.path).toBe('/agent/redeem')
    // The WHOLE string is the code the instance redeems.
    expect(w.fake.calls[0]?.body?.code).toBe(w.pasted)
    expect(w.fake.calls[0]?.body?.bag_version).toBe(VERSION)
    // The code's origin is pinned: no TXT, no record, and an https origin went through the guard first.
    expect(w.seen).toEqual(['guard https://ent.example.test'])
    const s = readSession(w.home)
    expect([s?.instance, s?.domain, s?.state]).toEqual(['https://ent.example.test', DOMAIN, 'live'])
    const status = await w.status()
    expect([status.exit, status.out.at(-1)]).toEqual([0, expect.stringMatching(ROUND_TRIP)])
    // No key, token or code on any line.
    const said = [...r.out, ...status.out].join('\n')
    for (const secret of [w.fake.row().token, w.pasted, SECRET, ...seeds(w.home)])
      expect(said).not.toContain(secret)
  })

  it('--label names the agent; --as names its keys', async () => {
    const w = setup()
    const r = await w.run(w.pasted, { label: 'build-box', name: 'box' })
    expect([r.exit, r.out]).toEqual([
      0,
      [expect.stringMatching(/^Connected as build-box; relay round trip \d+ ms$/)],
    ])
    expect(w.fake.calls[0]?.body?.label).toBe('build-box')
    expect(readSession(w.home)?.name).toBe('box')
  })

  it('a code that is not one: usage, exit 2, nothing written, nothing called, the code never said', async () => {
    const w = setup()
    const raw = (doc: unknown, secret = SECRET) =>
      `bagcode_${Buffer.from(JSON.stringify(doc)).toString('base64url')}.${secret}`
    const good = { v: 1, instance: 'https://ent.example.test', domain: DOMAIN }
    for (const text of [
      'garbage',
      'bagcode_0123456789abcdef',
      w.pasted.slice(0, w.pasted.indexOf('.')),
      w.pasted.slice(0, -1),
      `${w.pasted}.x`,
      raw({ ...good, v: 2 }),
      raw({ ...good, extra: 1 }),
      raw({ domain: DOMAIN, instance: good.instance, v: 1 }),
      raw({ ...good, domain: 'Not A Domain' }),
      raw({ ...good, instance: 'http://ent.example.test' }),
      raw({ ...good, instance: 'https://ent.example.test/path' }),
      raw({ ...good, instance: 'ftp://ent.example.test' }),
      raw(
        { ...good, domain: `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.example` },
        'x'.repeat(43),
      ).padEnd(901, 'x'),
    ]) {
      const r = await w.run(text)
      expect([r.exit, r.error?.code, r.out], text).toEqual([2, 'usage', []])
      expect(r.error?.message, text).toMatch(/^usage: this is not a connect code from the console: /)
      expect(r.error?.message).not.toContain(SECRET)
    }
    expect(w.fake.calls).toEqual([])
    expect(w.seen).toEqual([])
    expect(readSession(w.home)).toBeNull()
  })

  it('a loopback http origin is a local instance (no guard); the guard refusing an https origin stops before any call', async () => {
    const local = setup({ origin: 'http://127.0.0.1:18788' })
    const r = await local.run(local.pasted)
    expect([r.exit, r.out]).toEqual([0, [expect.stringMatching(ROUND_TRIP)]])
    expect(local.seen).toEqual([])
    const { GuardRefused } = await import('@usebag/edge')
    const refused = setup({
      guard: async () => {
        throw new GuardRefused({ range: 'private', detail: 'ent.example.test resolves to a private address' })
      },
    })
    const g = await refused.run(refused.pasted)
    expect([g.exit, g.error?.code, g.out]).toEqual([1, 'resolve-failed', []])
    expect(g.error?.message).toMatch(/^resolve-failed: https:\/\/ent\.example\.test is refused: /)
    expect(refused.fake.calls).toEqual([])
    // A guard that fails with no code of its own: discovery_failed.
    const plain = setup({
      guard: async () => {
        throw new Error('no answer')
      },
    })
    expect((await plain.run(plain.pasted)).error?.code).toBe('discovery_failed')
  })

  it("approved, but the organisation's signer has not signed: exit 4 with its line; a used code is refused, exit 1", async () => {
    const w = setup()
    w.fake.signer = false
    const r = await w.run(w.pasted)
    expect([r.exit, r.out.at(-1)]).toEqual([
      4,
      "Waiting for the organisation's signer: run bag status in a minute",
    ])
    const used = setup()
    used.fake.consoleCodes.clear()
    const u = await used.run(used.pasted)
    expect([u.exit, u.error?.code]).toEqual([1, 'invalid_grant'])
    expect(u.out).toEqual([])
    expect(u.error?.message).not.toContain(used.pasted)
  })

  it('a session that is no longer live: Not connected, with its state and reason', async () => {
    const w = setup()
    expect((await w.run(w.pasted)).exit).toBe(0)
    w.fake.row().state = 'frozen'
    w.time.now += 13 * 3600
    await tick(w.deps())
    const r = await w.run(w.pasted)
    expect([r.exit, r.out.at(-1)]).toEqual([4, 'Not connected: the session is frozen (agent_frozen)'])
  })

  it('publishes both records at every relay; a relay that did not take them is one line naming it, exit 1, the session kept', async () => {
    const R = ['http://127.0.0.1:47860', 'https://relay2.example.test', 'https://relay3.example.test']
    const all = setup({ relays: R })
    const ok = await all.run(all.pasted)
    expect([ok.exit, ok.out]).toEqual([0, [expect.stringMatching(ROUND_TRIP)]])
    expect(all.published.filter((p) => !p.endsWith('envelope'))).toEqual(
      R.flatMap((r) => [`${r} address`, `${r} accept-from`]),
    )
    const some = setup({ relays: R, down: { 'https://relay3.example.test': 403 } })
    const r = await some.run(some.pasted)
    expect([r.exit, r.out]).toEqual([
      1,
      [
        'Connected as acme-example-1, but its records were not published at https://relay3.example.test (http-403): bag status tries again',
      ],
    ])
    // Connect itself succeeded: the session stays, and status retries the records once the relay is back.
    expect(readSession(some.home)?.state).toBe('live')
    some.relays.down.clear()
    const status = await some.status()
    expect([status.exit, status.out.at(-1)]).toEqual([0, expect.stringMatching(ROUND_TRIP)])
    expect(some.published.filter((p) => p.startsWith('https://relay3'))).toEqual([
      'https://relay3.example.test address',
      'https://relay3.example.test accept-from',
    ])
  })

  it('the round trip: one envelope from the session key to the agent, read back at the first relay and acknowledged', async () => {
    const w = setup()
    expect((await w.run(w.pasted)).exit).toBe(0)
    const s = readSession(w.home)
    const relay = s?.org.relays[0] as string
    expect(w.published.filter((p) => p.endsWith('envelope'))).toEqual([`${relay} envelope`])
    const [bytes] = w.relays.box(relay, s?.agent_address as string)
    const env = JSON.parse(Buffer.from(bytes as Uint8Array).toString('utf8'))
    expect([env.from, env.to]).toEqual([s?.session_address, [s?.agent_address]])
    // Acknowledged at the relay as the agent's first frame: the agent's own inbox resumes after it.
    expect(w.relays.acks.get(`${relay} ${s?.agent_address}`)).toBe(1)
    expect(CHECK_TYPE).toBe('bag.connect-check')
  })

  it('a relay that does not deliver: the round trip fails at the 5 s bound, one line naming it, exit 1', async () => {
    const w = setup()
    w.relays.hold = true
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      let done = false
      const running = w.run(w.pasted).finally(() => {
        done = true
      })
      await vi.advanceTimersByTimeAsync(PROBE_MS - 1)
      expect(done).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      const r = await running
      expect(PROBE_MS).toBe(5000)
      expect([r.exit, r.out]).toEqual([
        1,
        [
          'Connected as acme-example-1, but the relay round trip failed at https://relay.example.test (timeout): bag status tries again',
        ],
      ])
      expect(readSession(w.home)?.state).toBe('live')
    } finally {
      vi.useRealTimers()
    }
  })

  it('a relay that refuses the envelope: the round trip fails naming the relay and its reason', async () => {
    const w = setup()
    const publish = w.relays.publish.bind(w.relays)
    w.relays.publish = async (url, bytes) => {
      if (JSON.parse(Buffer.from(bytes).toString('utf8')).kind === undefined)
        throw new (await import('@usebag/edge')).RelayError('root-not-accepted', 403, null, 'refused')
      return publish(url, bytes)
    }
    const r = await w.run(w.pasted)
    expect([r.exit, r.out]).toEqual([
      1,
      [
        'Connected as acme-example-1, but the relay round trip failed at https://relay.example.test (root-not-accepted): bag status tries again',
      ],
    ])
  })

  it('--verbose adds the instance, the fingerprint and each relay outcome before the one line', async () => {
    const w = setup()
    const r = await w.run(w.pasted, { verbose: true })
    expect(r.out).toEqual([
      'Connecting to acme.example at https://ent.example.test',
      expect.stringMatching(/^Approved: agent [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}$/),
      'records address https://relay.example.test published',
      'records accept-from https://relay.example.test published',
      expect.stringMatching(ROUND_TRIP),
    ])
  })

  it('status probes the path without sending: the address record read back, its line; a relay down is exit 1', async () => {
    const w = setup()
    expect((await w.run(w.pasted, { label: 'build-box' })).exit).toBe(0)
    const sent = w.published.length
    const ok = await w.status()
    expect([ok.exit, ok.out.at(-1)]).toEqual([
      0,
      expect.stringMatching(/^Connected as build-box; relay round trip \d+ ms$/),
    ])
    expect(w.published.length).toBe(sent)
    w.relays.down.set('https://relay.example.test', 0)
    const down = await w.status()
    expect([down.exit, down.out.at(-1)]).toEqual([
      1,
      'Connected as build-box, but the relay round trip failed at https://relay.example.test (unreachable)',
    ])
  })

  it("the code's label: none is sent without --label, and the label the grant returns is printed and kept", async () => {
    const w = setup()
    w.fake.codeLabels.set(w.pasted, 'build-box-7')
    const r = await w.run(w.pasted)
    expect(w.fake.calls[0]?.body).not.toHaveProperty('label')
    expect([r.exit, r.out]).toEqual([
      0,
      [expect.stringMatching(/^Connected as build-box-7; relay round trip \d+ ms$/)],
    ])
    expect(readSession(w.home)?.label).toBe('build-box-7')
    const status = await w.status()
    expect(status.out.at(-1)).toMatch(/^Connected as build-box-7; relay round trip \d+ ms$/)
  })

  it('a label a live agent holds: the code without --label takes the next number', async () => {
    const plain = setup()
    plain.fake.liveLabels.add('acme-example-1')
    const r = await plain.run(plain.pasted)
    expect(r.out).toEqual([expect.stringMatching(/^Connected as acme-example-2; relay round trip \d+ ms$/)])
    const carried = setup()
    carried.fake.codeLabels.set(carried.pasted, 'ci-3')
    for (const l of ['ci-3', 'ci-4']) carried.fake.liveLabels.add(l)
    expect((await carried.run(carried.pasted)).out).toEqual([
      expect.stringMatching(/^Connected as ci-5; relay round trip \d+ ms$/),
    ])
  })

  it('--label a live agent holds: label_taken, exit 1, the label named; the code is unused and connects without it', async () => {
    const w = setup()
    w.fake.liveLabels.add('build-box')
    const r = await w.run(w.pasted, { label: 'build-box' })
    expect([r.exit, r.error?.code, r.out]).toEqual([1, 'label_taken', []])
    expect(r.error?.message).toBe(
      'label_taken: the label build-box is held by a live agent of acme.example: connect again without --label, or with another',
    )
    expect(w.fake.calls[0]?.body?.label).toBe('build-box')
    expect(readSession(w.home)).toBeNull()
    const again = await w.run(w.pasted)
    expect([again.exit, again.out]).toEqual([0, [expect.stringMatching(ROUND_TRIP)]])
  })

  it('the code parser keeps one origin source', () => {
    const code = connectCodeOf({ instance: 'https://ent.example.test', domain: DOMAIN }, SECRET)
    expect(parseConnectCode(`\n${code} `)).toEqual({
      origin: 'https://ent.example.test',
      domain: DOMAIN,
      code,
    })
  })
})
