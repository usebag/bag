import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { connect } from '../src/connect.ts'
import { connectCodeOf } from '../src/connect-code.ts'
import { enterpriseStatus } from '../src/flow.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from '../src/ports.ts'
import { enterpriseDir, ownerOnly, readSession, secureHome } from '../src/session.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// The bag home held to its owner on every run: a home made 0755 before the client (the prompt's mkdir -p ~/.bag)
// becomes 0700, and the files the client writes 0600, chain.json among them; another user's home is refused.

const tmp = tempDir('home-mode')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const SECRET = 'connect-test-secret-only-for-these-tests-00'
// One relay for every home: status reads back the records connect published there.
const RELAY = new FakeRelay()
/** The organisation's profile files: <home>/orgs/<domain>/enterprise. */
const org = (home: string) => join(home, 'orgs', DOMAIN, 'enterprise')
const mode = (p: string) => (statSync(p).mode & 0o777).toString(8)

function deps(fake: FakeInstance, home: string) {
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => T0 },
    rng: seededRng(home),
    fetch: fake.fetch,
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => '192.0.2.10' },
    },
    sleep: async () => {},
    relays: RELAY,
  }
  return enterpriseDeps(
    ports,
    home,
    () => {},
    async () => null,
  )
}

async function connected(home: string): Promise<{ fake: FakeInstance; exit: number }> {
  const fake = new FakeInstance({ domain: DOMAIN, now: () => T0 })
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  return { fake, exit: await connect(deps(fake, home), { text: code, version: VERSION }) }
}

describe('the bag home', () => {
  it('a home made 0755 before the client ends 0700, every file the client writes 0600, chain.json included', async () => {
    const home = join(tmp.dir, 'made-755')
    mkdirSync(home, { mode: 0o755 })
    chmodSync(home, 0o755)
    writeFileSync(join(home, 'trust.json'), '{"version":1,"roots":{}}\n', { mode: 0o644 })
    chmodSync(join(home, 'trust.json'), 0o644)
    expect((await connected(home)).exit).toBe(0)
    expect(mode(home)).toBe('700')
    expect(mode(join(home, 'enterprise'))).toBe('700')
    for (const dir of [join(home, 'orgs'), join(home, 'orgs', DOMAIN), org(home)])
      expect([dir, mode(dir)]).toEqual([dir, '700'])
    for (const f of ['session.json', 'chain.json', 'records.json'])
      expect([f, mode(join(org(home), f))]).toEqual([f, '600'])
    expect(mode(join(home, 'enterprise', 'current.json'))).toBe('600')
    expect(mode(join(home, 'trust.json'))).toBe('600')
    expect(mode(join(home, 'keys'))).toBe('700')
  })

  it('an older chain.json of 0644 is tightened on the next run; status keeps the home 0700', async () => {
    const home = join(tmp.dir, 'older')
    const { fake } = await connected(home)
    chmodSync(join(org(home), 'chain.json'), 0o644)
    chmodSync(home, 0o755)
    expect(await enterpriseStatus(deps(fake, home))).toBe(0)
    expect([mode(home), mode(join(org(home), 'chain.json'))]).toEqual(['700', '600'])
  })

  it("a home of the older shape, its one session in enterprise/, moves into its organisation's profile and works", async () => {
    const home = join(tmp.dir, 'old-shape')
    const { fake } = await connected(home)
    // Back to the shape of a home written before profiles: the files directly in <home>/enterprise, no current.json.
    for (const f of ['session.json', 'chain.json', 'records.json'])
      renameSync(join(org(home), f), join(home, 'enterprise', f))
    unlinkSync(join(home, 'enterprise', 'current.json'))
    chmodSync(join(home, 'enterprise', 'chain.json'), 0o644)
    expect(readSession(home)?.domain).toBe(DOMAIN)
    const lines: string[] = []
    expect(await enterpriseStatus({ ...deps(fake, home), say: (l) => lines.push(l) })).toBe(0)
    expect(lines.at(-1)).toMatch(/^Connected as acme-example-1; relay round trip \d+ ms$/)
    for (const f of ['session.json', 'chain.json', 'records.json']) {
      expect([f, existsSync(join(home, 'enterprise', f))]).toEqual([f, false])
      expect([f, mode(join(org(home), f))]).toEqual([f, '600'])
    }
    expect(JSON.parse(readFileSync(join(home, 'enterprise', 'current.json'), 'utf8'))).toEqual({
      v: 1,
      domain: DOMAIN,
    })
  })

  it("refuses another user's home and changes nothing; a missing home is left to the first write", () => {
    const home = join(tmp.dir, 'theirs')
    mkdirSync(home, { mode: 0o755 })
    chmodSync(home, 0o755)
    const uid = statSync(home).uid
    expect(() => secureHome(home, uid + 1)).toThrow(/^home-invalid: .* belongs to another user/)
    expect(mode(home)).toBe('755')
    expect(() => secureHome(join(tmp.dir, 'absent'))).not.toThrow()
  })

  it('refuses a home that is a file; a symbolic link among the files is not followed or changed', () => {
    const file = join(tmp.dir, 'a-file')
    writeFileSync(file, '')
    expect(() => secureHome(file)).toThrow(/^home-invalid: .* is not a directory/)
    const home = join(tmp.dir, 'linked')
    mkdirSync(enterpriseDir(home), { recursive: true, mode: 0o700 })
    const target = join(tmp.dir, 'link-target')
    writeFileSync(target, '{}', { mode: 0o644 })
    chmodSync(target, 0o644)
    symlinkSync(target, join(enterpriseDir(home), 'session.json'))
    secureHome(home)
    expect(mode(target)).toBe('644')
    // The strict read refuses the link: it is not a regular file.
    expect(() => ownerOnly('enterprise', join(enterpriseDir(home), 'session.json'), false)).toThrow(
      /is not a regular file/,
    )
    expect(() => ownerOnly('enterprise', target, false)).toThrow(/has mode 0644; it must be 0600/)
  })
})
