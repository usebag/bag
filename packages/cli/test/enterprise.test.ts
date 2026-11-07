import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { connectCodeOf, readSession } from '@usebag/enterprise-client'
import { FakeInstance } from '@usebag/enterprise-client/testing'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// bag connect, sign-in, sign-out and status (with no --as), run as command lines against the recorded fake of a bag
// enterprise instance (@usebag/enterprise-client/testing; no network): the exits (0 done, 1 refused, 2 usage, 3 ended,
// 4 waiting), the lines, the code never from argv, the pinned instance and its guard, the chain and the hourly job. After
// every test, no line on stdout or stderr, and no prompt, holds the code, its secret part, a device code, a token or a
// key seed.

const tmp = tempDir('enterprise')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const ORIGIN = 'https://ent.example.test'
// A test secret of the minted form: 43 base64url characters.
const SECRET = 'cli-test-secret-only-for-these-tests-000000'
let n = 0
const ROUND_TRIP = (label: string) => new RegExp(`^Connected as ${label}; relay round trip \\d+ ms$`)
const worlds: World[] = []

interface World {
  readonly io: TestIo
  readonly fake: FakeInstance
  readonly code: string
  readonly dir: string
  /** The origins the private-address guard was asked about, in order. */
  readonly guarded: string[]
  /** The organisation's relays, in memory: connect's records and round trip, status's probe. */
  readonly relay: MemoryRelay
}

function setup(
  env: Record<string, string> = {},
  o: { waits?: boolean; guard?: () => Promise<string | null> } = {},
): World {
  const io = testIo(new MemoryRelay(), { BAG_ENTERPRISE_URL: ORIGIN, ...env })
  const fake = new FakeInstance({ domain: DOMAIN, now: () => io.time.now })
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  const [guarded, relay] = [[] as string[], new MemoryRelay()]
  let approve = true
  Object.assign(io, {
    fetch: fake.fetch,
    enterpriseNet: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: {
        connectTo: async (url: string) => {
          guarded.push(url)
          return o.guard === undefined ? '192.0.2.10' : o.guard()
        },
      },
    },
    enterpriseRelays: relay,
    sleep: async (ms: number) => {
      if (o.waits === false) throw new Error('no wait in this test')
      io.time.now += ms / 1000
      if (approve) fake.approve('BCDF-GGG0')
      approve = false
    },
  })
  const w = { io, fake, code, dir: join(tmp.dir, `home-${n++}`), guarded, relay }
  worlds.push(w)
  return w
}

/** Every secret a world holds now: the code and its secret part, the device codes, the tokens, the key seeds. */
function secrets(w: World): string[] {
  const keys = join(w.dir, 'keys')
  const seeds = existsSync(keys)
    ? readdirSync(keys).flatMap((f) =>
        Object.entries(JSON.parse(readFileSync(join(keys, f), 'utf8')) as Record<string, unknown>)
          .filter(([k, v]) => (k === 'sign_seed' || k === 'seal_priv') && typeof v === 'string')
          .map(([, v]) => v as string),
      )
    : []
  const tokens = [...w.fake.rows.values()].flatMap((r) => [r.token, r.prev ?? ''])
  return [w.code, SECRET, ...w.fake.codes.keys(), ...tokens, ...seeds].filter((s) => s.length >= 8)
}

afterEach(() => {
  for (const w of worlds.splice(0)) {
    const said = [...w.io.stdout, ...w.io.stderr, ...w.io.prompts].join('\n')
    for (const secret of secrets(w)) expect(said).not.toContain(secret)
  }
})

describe('bag connect', () => {
  it('connects with the code from BAG_ORG_CODE: one line, Connected as <label> with the relay round trip', async () => {
    const w = setup()
    Object.assign(w.io.env, { BAG_ORG_CODE: w.code })
    const r = await cli(w.io, 'connect', '--label', 'build-box', '--dir', w.dir)
    expect(r).toEqual({ code: 0, out: [expect.stringMatching(ROUND_TRIP('build-box'))], err: [] })
    expect(w.io.prompts).toEqual([])
    expect(w.fake.calls[0]?.path).toBe('/agent/redeem')
    expect(w.fake.calls[0]?.body?.code).toBe(w.code)
    expect(w.guarded).toEqual([ORIGIN])
    const status = await cli(w.io, 'status', '--dir', w.dir)
    expect(status.code).toBe(0)
    expect(status.out[0]).toMatch(/^signed-in acme\.example agent ed25519:[0-9a-f]{64} state live$/)
    expect(status.out.at(-1)).toMatch(ROUND_TRIP('build-box'))
  })

  it('--verbose adds the instance, the fingerprint and each relay outcome before the one line', async () => {
    const w = setup()
    Object.assign(w.io.env, { BAG_ORG_CODE: w.code })
    const r = await cli(w.io, 'connect', '--verbose', '--dir', w.dir)
    const relay = w.fake.relays[0] as string
    expect([r.code, r.out]).toEqual([
      0,
      [
        `Connecting to ${DOMAIN} at ${ORIGIN}`,
        expect.stringMatching(/^Approved: agent [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}$/),
        `records address ${relay} published`,
        `records accept-from ${relay} published`,
        expect.stringMatching(ROUND_TRIP('acme-example-1')),
      ],
    ])
  })

  it('reads one line of stdin: "Paste the code: " on a terminal, no prompt on a pipe', async () => {
    const tty = setup()
    tty.io.tty = true
    tty.io.lines.push(`  ${tty.code}  `)
    const r = await cli(tty.io, 'connect', '--dir', tty.dir)
    expect([r.code, r.out, tty.io.prompts]).toEqual([
      0,
      [expect.stringMatching(ROUND_TRIP('acme-example-1'))],
      ['Paste the code: '],
    ])
    const pipe = setup()
    pipe.io.lines.push(pipe.code)
    const p = await cli(pipe.io, 'connect', '--as', 'box', '--dir', pipe.dir)
    expect([p.code, p.out.at(-1), pipe.io.prompts]).toEqual([
      0,
      expect.stringMatching(ROUND_TRIP('acme-example-1')),
      [],
    ])
    expect(readSession(pipe.dir)?.name).toBe('box')
  })

  it('refuses the code on the command line (exit 2, nothing called) and an empty code', async () => {
    const w = setup()
    for (const argv of [[w.code], ['--label', 'x', ` ${w.code}`]]) {
      const r = await cli(w.io, 'connect', ...argv, '--dir', w.dir)
      expect([r.code, r.out, r.err[0]]).toEqual([
        2,
        [],
        'bag: usage: the code is read from stdin or BAG_ORG_CODE, never from the command line',
      ])
    }
    expect(w.fake.calls).toEqual([])
    expect(w.guarded).toEqual([])
    for (const line of [null, '   ']) {
      if (line !== null) w.io.lines.push(line)
      const r = await cli(w.io, 'connect', '--dir', w.dir)
      expect([r.code, r.err[0]]).toEqual([
        2,
        'bag: usage: no code: paste the code from the console, or set BAG_ORG_CODE',
      ])
    }
    const bad = await cli(w.io, 'connect', '--dir', w.dir, '--x')
    expect([bad.code, bad.err[0]]).toEqual([2, expect.stringMatching(/^bag: usage: /)])
    const cut = setup({ BAG_ORG_CODE: w.code.slice(0, -1) })
    const c = await cli(cut.io, 'connect', '--dir', cut.dir)
    expect([c.code, c.err[0]]).toEqual([
      2,
      'bag: usage: this is not a connect code from the console: it is cut short or changed',
    ])
    expect(c.err.join('\n')).not.toContain(SECRET.slice(0, 20))
  })

  it("exit 4 while the organisation's signer waits; a relay that did not take the records is one line, exit 1", async () => {
    const w = setup()
    w.fake.signer = false
    Object.assign(w.io.env, { BAG_ORG_CODE: w.code })
    const r = await cli(w.io, 'connect', '--dir', w.dir)
    expect(r.code).toBe(4)
    expect(r.out).toEqual(["Waiting for the organisation's signer: run bag status in a minute"])
    const live = setup()
    const relay = live.fake.relays[0] as string
    live.relay.failRecordPublish.set(relay, Object.assign(new Error('refused'), { status: 403 }))
    Object.assign(live.io.env, { BAG_ORG_CODE: live.code })
    const l = await cli(live.io, 'connect', '--dir', live.dir)
    expect([l.code, l.out]).toEqual([
      1,
      [
        `Connected as acme-example-1, but its records were not published at ${relay} (http-403): bag status tries again`,
      ],
    ])
    // The session stays; status publishes the records once the relay takes them, and its probe reads them back.
    live.relay.failRecordPublish.clear()
    const status = await cli(live.io, 'status', '--dir', live.dir)
    expect([status.code, status.out.at(-1)]).toEqual([0, expect.stringMatching(ROUND_TRIP('acme-example-1'))])
  })

  it('a used code is refused: exit 1, the error line without the code', async () => {
    const w = setup()
    w.fake.consoleCodes.clear()
    Object.assign(w.io.env, { BAG_ORG_CODE: w.code })
    const r = await cli(w.io, 'connect', '--dir', w.dir)
    expect([r.code, r.out, r.err[0]]).toEqual([1, [], expect.stringMatching(/^bag: invalid_grant: /)])
  })
})

describe('two organisations in one home', () => {
  it('connect keeps the first; status names the one shown on stderr, --org picks; sign-out needs --org', async () => {
    const w = setup()
    const other = new FakeInstance({
      domain: 'walk2.example.test',
      origin: 'https://ent2.example.test',
      now: () => w.io.time.now,
    })
    const code2 = connectCodeOf({ instance: other.origin, domain: other.domain }, SECRET)
    other.consoleCodes.add(code2)
    const fetch = w.io.fetch as (u: string, i: RequestInit) => Promise<Response>
    Object.assign(w.io, {
      fetch: (u: string, i: RequestInit) => (u.startsWith(other.origin) ? other.fetch(u, i) : fetch(u, i)),
    })
    Object.assign(w.io.env, { BAG_ORG_CODE: code2 })
    expect((await cli(w.io, 'connect', '--dir', w.dir)).code).toBe(0)
    Object.assign(w.io.env, { BAG_ORG_CODE: w.code })
    const r = await cli(w.io, 'connect', '--dir', w.dir)
    expect([r.code, r.out]).toEqual([
      0,
      [
        expect.stringMatching(
          /^Connected as acme-example-1 \(acme\.example\); relay round trip \d+ ms; also signed in to walk2\.example\.test: bag status --org walk2\.example\.test$/,
        ),
      ],
    ])
    expect(other.revoked.size).toBe(0)
    const status = await cli(w.io, 'status', '--dir', w.dir)
    expect([status.code, status.err]).toEqual([
      0,
      [
        'bag: showing acme.example, the most recently connected; also signed in to walk2.example.test (--org)',
      ],
    ])
    const two = await cli(w.io, 'status', '--org', 'walk2.example.test', '--dir', w.dir)
    expect([two.code, two.err, two.out[0]]).toEqual([
      0,
      [],
      expect.stringMatching(/^signed-in walk2\.example\.test /),
    ])
    const refused = await cli(w.io, 'sign-out', '--dir', w.dir)
    expect([refused.code, refused.err[0]]).toEqual([
      2,
      'bag: usage: signed in to acme.example and walk2.example.test: bag sign-out --org <domain>, one of them',
    ])
    const out = await cli(w.io, 'sign-out', '--org', 'walk2.example.test', '--dir', w.dir)
    expect([out.code, other.revoked.size, w.fake.revoked.size]).toEqual([0, 1, 0])
  })
})

describe('bag sign-in, status and sign-out', () => {
  it('signs in by the device flow, reports the session, prints the chain and the hourly job, and signs out', async () => {
    const w = setup()
    const signed = await cli(w.io, 'sign-in', DOMAIN, '--dir', w.dir)
    expect(signed.code).toBe(0)
    expect(signed.out[0]).toBe('open https://id.example.test/auth/agent and enter the code BCDF-GGG0')
    expect(signed.out[2]).toBe('approve only a code you started yourself')
    expect(signed.out).toContain(`trust domain:${DOMAIN} source org:${DOMAIN}`)
    const chainFile = join(w.dir, 'orgs', DOMAIN, 'enterprise', 'chain.json')
    expect(signed.out.at(-1)).toBe(
      `chain ${chainFile}: bag send --as acme-example.session --auth ${chainFile} ...`,
    )
    const status = await cli(w.io, 'status', '--dir', w.dir)
    expect(status.code).toBe(0)
    expect(status.out[0]).toMatch(/^signed-in acme\.example agent ed25519:[0-9a-f]{64} state live$/)
    expect(status.out[1]).toBe(`instance ${ORIGIN} generation 0 refreshed 2027-01-15T08:00:05Z`)
    const chain = await cli(w.io, 'status', '--chain', '--dir', w.dir)
    expect(JSON.parse(chain.out[0] as string)).toEqual(JSON.parse(readFileSync(chainFile, 'utf8')))
    const plist = (await cli(w.io, 'status', '--plist', '--dir', w.dir)).out.join('\n')
    expect(plist).toContain('<string>status</string>')
    expect(plist).toContain('<key>Label</key><string>bag.refresh</string>')
    expect(plist).toMatch(/<dict><key>Minute<\/key><integer>\d+<\/integer><\/dict>/)
    expect(plist).not.toContain('<key>Hour</key>')
    expect((await cli(w.io, 'status', '--crontab', '--dir', w.dir)).out[0]).toMatch(
      /^\d+ \* \* \* \* .* status --dir .* >> .*refresh\.log 2>&1$/,
    )
    const out = await cli(w.io, 'sign-out', '--dir', w.dir)
    expect([out.code, out.out[0]]).toEqual([
      0,
      expect.stringMatching(/^signed-out acme\.example: ed25519:[0-9a-f]{64} is revoked for good/),
    ])
    expect(w.fake.revoked.size).toBe(1)
    const gone = await cli(w.io, 'status', '--dir', w.dir)
    expect([gone.code, gone.err[0]]).toEqual([3, 'bag: signed-out: not signed in: bag sign-in <domain>'])
    expect((await cli(w.io, 'sign-out', '--dir', w.dir)).code).toBe(3)
    expect((await cli(w.io, 'status', '--chain', '--dir', w.dir)).code).toBe(3)
  })

  it('usage errors exit 2: no domain, a bad domain, two domains, two status modes, an unknown option', async () => {
    const w = setup()
    for (const argv of [
      ['sign-in'],
      ['sign-in', 'Not A Domain'],
      ['sign-in', 'a.example', 'b.example'],
      ['status', '--chain', '--plist'],
      ['sign-out', '--x'],
      ['mcp', 'extra'],
    ]) {
      const r = await cli(w.io, ...argv, '--dir', w.dir)
      expect([r.code, r.err[0]], argv.join(' ')).toEqual([2, expect.stringMatching(/^bag: usage: /)])
    }
    // status --as stays the identity's status, with its exit 1.
    expect((await cli(w.io, 'status', '--as', 'nobody', '--dir', w.dir)).code).toBe(1)
    expect(w.fake.calls).toEqual([])
  })

  it('--no-wait exits 4 and status says it waits; --code redeems BAG_ORG_CODE; a waiting signer is exit 4', async () => {
    const w = setup({}, { waits: false })
    const waiting = await cli(w.io, 'sign-in', DOMAIN, '--no-wait', '--dir', w.dir)
    expect([waiting.code, waiting.err[0]]).toEqual([
      4,
      'bag: authorization_pending: a person is to approve the code BCDF-GGG0: bag sign-in acme.example resumes',
    ])
    const status = await cli(w.io, 'status', '--dir', w.dir)
    expect([status.code, status.out[0]]).toEqual([
      4,
      'waiting acme.example: a person is to approve the code BCDF-GGG0',
    ])
    const coded = setup({ BAG_ORG_CODE: 'bagcode_0123456789' })
    coded.fake.consoleCodes.add('bagcode_0123456789')
    coded.fake.signer = false
    const r = await cli(coded.io, 'sign-in', DOMAIN, '--code', '--as', 'ci-1', '--dir', coded.dir)
    expect(r.code).toBe(4)
    expect(r.out.some((l) => l.startsWith("waiting: the organisation's signer"))).toBe(true)
    expect(coded.fake.calls[0]?.path).toBe('/agent/redeem')
    expect(r.out.join('\n')).not.toContain('bagcode_0123456789')
    const none = setup()
    const u = await cli(none.io, 'sign-in', DOMAIN, '--code', '--dir', none.dir)
    expect([u.code, u.err[0]]).toEqual([
      2,
      expect.stringMatching(/^bag: usage: --code reads a bagcode_ code/),
    ])
  })

  it('sign-in --instance --no-wait: the link, the user code and the fingerprint, exit 4; the rerun resumes; 0 once approved', async () => {
    // BAG_ENTERPRISE_URL names another origin, so a sign-in that did not pin --instance would fail at the fake.
    const w = setup({ BAG_ENTERPRISE_URL: 'https://other.example.test' }, { waits: false })
    const line = ['sign-in', DOMAIN, '--instance', ORIGIN, '--no-wait', '--dir', w.dir]
    const first = await cli(w.io, ...line)
    expect([first.code, first.out[0], first.out[2]]).toEqual([
      4,
      'open https://id.example.test/auth/agent and enter the code BCDF-GGG0',
      'approve only a code you started yourself',
    ])
    expect(first.out[1]).toMatch(/^fingerprint [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} /)
    expect(w.guarded).toEqual([ORIGIN])
    const again = await cli(w.io, ...line)
    expect([again.code, again.err[0]]).toEqual([4, expect.stringMatching(/^bag: authorization_pending: /)])
    w.fake.approve('BCDF-GGG0')
    const done = await cli(w.io, ...line)
    expect(done.code).toBe(0)
    expect(done.out).toContainEqual(
      expect.stringMatching(/^signed-in acme\.example agent ed25519:[0-9a-f]{64} state live$/),
    )
    expect(done.out.at(-1)).toMatch(/^chain .*chain\.json: bag send --as acme-example\.session --auth /)
    expect(readSession(w.dir)?.instance).toBe(ORIGIN)
  })

  it('sign-in --instance: a refusal by the person exits 1', async () => {
    const w = setup({}, { waits: false })
    const line = ['sign-in', DOMAIN, '--instance', ORIGIN, '--no-wait', '--dir', w.dir]
    expect((await cli(w.io, ...line)).code).toBe(4)
    w.fake.deny('BCDF-GGG0')
    const refused = await cli(w.io, ...line)
    expect([refused.code, refused.err[0]]).toEqual([1, expect.stringMatching(/^bag: access_denied: /)])
  })

  it('sign-in --instance: not https and not loopback is usage, a private address is refused, both before any call', async () => {
    const w = setup()
    for (const origin of [
      'http://ent.example.test',
      'https://ent.example.test/path',
      'ftp://ent.example.test',
    ]) {
      const r = await cli(w.io, 'sign-in', DOMAIN, '--instance', origin, '--dir', w.dir)
      expect([r.code, r.err[0]], origin).toEqual([
        2,
        'bag: usage: the instance is the console origin: https, or http on this machine',
      ])
    }
    expect(w.guarded).toEqual([])
    const { GuardRefused } = await import('@usebag/edge')
    const g = setup(
      {},
      {
        guard: async () => {
          throw new GuardRefused({
            range: 'private',
            detail: 'ent.example.test resolves to a private address',
          })
        },
      },
    )
    const r = await cli(g.io, 'sign-in', DOMAIN, '--instance', ORIGIN, '--dir', g.dir)
    expect([r.code, r.err[0]]).toEqual([
      1,
      expect.stringMatching(/^bag: resolve-failed: https:\/\/ent\.example\.test is refused: /),
    ])
    expect([w.fake.calls, g.fake.calls]).toEqual([[], []])
    expect(existsSync(join(g.dir, 'keys'))).toBe(false)
  })

  it('a copied home reports frozen and exits 4', async () => {
    const w = setup()
    await cli(w.io, 'sign-in', DOMAIN, '--dir', w.dir)
    w.io.time.now += 13 * 3600
    w.fake.row().state = 'frozen'
    const r = await cli(w.io, 'status', '--dir', w.dir)
    expect(r.code).toBe(4)
    expect(r.out).toContain('frozen: an admin of the organisation unfreezes or revokes this agent')
  })
})
