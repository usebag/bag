import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { type ConnectOptions, connect } from '../src/connect.ts'
import { connectCodeOf, parseConnectCode } from '../src/connect-code.ts'
import { enterpriseStatus, tick } from '../src/flow.ts'
import { EnterpriseError } from '../src/instance.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from '../src/ports.ts'
import { readSession } from '../src/session.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// connect against the recorded fake instance (no network): the pasted code alone, the code's origin pinned (no record
// fetched, no BAG_ENTERPRISE_*), the origin's rules (https or loopback http, the private-address guard), one line per
// state, no key, token or code said, AGENT_EXIT's exits. Where the code comes from (BAG_ORG_CODE or a line of stdin,
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
  const published: string[] = []
  const relays = {
    async publish(url: string, bytes: Uint8Array) {
      const status = o.down?.[url]
      if (status !== undefined) throw Object.assign(new Error('refused'), { status })
      published.push(`${url} ${JSON.parse(Buffer.from(bytes).toString('utf8')).kind}`)
      return {} as never
    },
  }
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
  return { fake, seen, home, run, status, pasted, published, time, deps }
}

/** The key seeds of a home: none may ever be said. */
const seeds = (home: string): string[] =>
  readdirSync(join(home, 'keys')).map(
    (f) => JSON.parse(readFileSync(join(home, 'keys', f), 'utf8')).sign_seed as string,
  )

describe('connect', () => {
  it('connects with the pasted code alone: the code names the instance, one line per state, Connected as <label>', async () => {
    const w = setup()
    const r = await w.run(`  ${w.pasted}\n`)
    expect(r.exit).toBe(0)
    expect(r.out).toEqual([
      'Connecting to acme.example at https://ent.example.test',
      expect.stringMatching(/^Approved: agent [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}$/),
      'Connected as acme-example',
    ])
    expect(w.fake.calls[0]?.path).toBe('/agent/redeem')
    // The WHOLE string is the code the instance redeems.
    expect(w.fake.calls[0]?.body?.code).toBe(w.pasted)
    expect(w.fake.calls[0]?.body?.bag_version).toBe(VERSION)
    // The code's origin is pinned: no TXT, no record, and an https origin went through the guard first.
    expect(w.seen).toEqual(['guard https://ent.example.test'])
    const s = readSession(w.home)
    expect([s?.instance, s?.domain, s?.state]).toEqual(['https://ent.example.test', DOMAIN, 'live'])
    const status = await w.status()
    expect(status.exit).toBe(0)
    // No key, token or code on any line.
    const said = [...r.out, ...status.out].join('\n')
    for (const secret of [w.fake.row().token, w.pasted, SECRET, ...seeds(w.home)])
      expect(said).not.toContain(secret)
  })

  it('--label names the agent; --as names its keys', async () => {
    const w = setup()
    const r = await w.run(w.pasted, { label: 'build-box', name: 'box' })
    expect([r.exit, r.out.at(-1)]).toEqual([0, 'Connected as build-box'])
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
    expect([r.exit, r.out[0]]).toEqual([0, 'Connecting to acme.example at http://127.0.0.1:18788'])
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
    expect(u.out).toEqual(['Connecting to acme.example at https://ent.example.test'])
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

  it('prints nothing more when every relay took both records, and one line per relay that did not; exit stays 0', async () => {
    const R = ['http://127.0.0.1:47860', 'https://relay2.example.test', 'https://relay3.example.test']
    const all = setup({ relays: R })
    const ok = await all.run(all.pasted)
    expect([ok.exit, ok.out.at(-1), ok.out.length]).toEqual([0, 'Connected as acme-example', 3])
    expect(all.published).toEqual(R.flatMap((r) => [`${r} address`, `${r} accept-from`]))
    const some = setup({
      relays: R,
      down: { 'http://127.0.0.1:47860': 0, 'https://relay3.example.test': 403 },
    })
    const r = await some.run(some.pasted)
    expect(r.exit).toBe(0)
    expect(r.out.slice(2)).toEqual([
      'Connected as acme-example',
      'relay http://127.0.0.1:47860: records not published (unreachable)',
      'relay https://relay3.example.test: records not published (http-403)',
    ])
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
