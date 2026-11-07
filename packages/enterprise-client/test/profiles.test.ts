import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { connect } from '../src/connect.ts'
import { connectCodeOf } from '../src/connect-code.ts'
import { type EnterpriseDeps, enterpriseStatus, signOut, tick } from '../src/flow.ts'
import type { EnterpriseError } from '../src/instance.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from '../src/ports.ts'
import { profiles, readSession, selectOrg } from '../src/session.ts'
import { readTrustFile } from '../src/trust-file.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// One home, two organisations: connect to a second organisation keeps the first one's profile as it was (nothing
// revoked, nothing signed out), names it in its line, and becomes the most recently connected; status reports that one
// and says which on the note line (stderr in the CLI), or the one --org names; sign-out without --org refuses with the
// list, and with it revokes that one only.

const tmp = tempDir('profiles')
afterAll(() => tmp.cleanup())
const [A, B] = ['walk2.example.test', 'acme.example']
const SECRET = 'profile-test-secret-only-for-these-tests-00'
const ROUND = '; relay round trip \\d+ ms'
let n = 0

function world() {
  const time = { now: T0 }
  const a = new FakeInstance({ domain: A, origin: 'https://ent-a.example.test', now: () => time.now })
  const b = new FakeInstance({ domain: B, origin: 'https://ent-b.example.test', now: () => time.now })
  a.relays.splice(0, 1, 'https://relay-a.example.test')
  const codes = [a, b].map((f) => {
    const code = connectCodeOf({ instance: f.origin, domain: f.domain }, SECRET)
    f.consoleCodes.add(code)
    return code
  })
  const home = join(tmp.dir, `home-${n++}`)
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => time.now },
    rng: seededRng(`profiles-${n}`),
    fetch: (url, init) => (url.startsWith(a.origin) ? a.fetch(url, init) : b.fetch(url, init)),
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => null },
    },
    sleep: async () => {},
    relays: new FakeRelay(),
  }
  const [out, notes] = [[] as string[], [] as string[]]
  const d = (org?: string): EnterpriseDeps => ({
    ...enterpriseDeps(
      ports,
      home,
      (l) => out.push(l),
      async () => null,
    ),
    note: (l) => notes.push(l),
    ...(org === undefined ? {} : { org }),
  })
  const run = async <T>(f: () => Promise<T>): Promise<{ result: T; out: string[]; notes: string[] }> => {
    out.length = 0
    notes.length = 0
    const result = await f()
    return { result, out: [...out], notes: [...notes] }
  }
  return { a, b, codes, home, d, run, time }
}

describe('two organisations in one home', () => {
  it('connect to a second organisation keeps the first, says both, and revokes nothing', async () => {
    const w = world()
    const first = await w.run(() => connect(w.d(), { text: w.codes[0] as string, version: VERSION }))
    expect([first.result, first.out]).toEqual([
      0,
      [expect.stringMatching(`^Connected as walk2-example-test-1${ROUND}$`)],
    ])
    const second = await w.run(() => connect(w.d(), { text: w.codes[1] as string, version: VERSION }))
    expect([second.result, second.out]).toEqual([
      0,
      [
        expect.stringMatching(
          `^Connected as acme-example-1 \\(acme\\.example\\)${ROUND}; also signed in to walk2\\.example\\.test: bag status --org walk2\\.example\\.test$`,
        ),
      ],
    ])
    // The first organisation was never asked to sign out, and its session is live as it was.
    expect(w.a.calls.some((c) => c.path === '/agent/sign-out')).toBe(false)
    expect(w.a.revoked.size).toBe(0)
    expect([readSession(w.home, A)?.state, readSession(w.home, B)?.state]).toEqual(['live', 'live'])
    expect([profiles(w.home), selectOrg(w.home)]).toEqual([[B, A], B])
    expect(readSession(w.home)?.domain).toBe(B)
    // Each profile has its own files; the keys stay in the home's one keys directory.
    for (const o of [A, B]) expect(existsSync(join(w.home, 'orgs', o, 'enterprise', 'chain.json'))).toBe(true)
  })

  it('status reports the most recent and names the others on the note line; --org reports that one', async () => {
    const w = world()
    for (const code of w.codes) await connect(w.d(), { text: code, version: VERSION })
    const both = await w.run(() => enterpriseStatus(w.d()))
    expect(both.result).toBe(0)
    expect(both.notes).toEqual([
      'bag: showing acme.example, the most recently connected; also signed in to walk2.example.test (--org)',
    ])
    expect(both.out[0]).toMatch(/^signed-in acme\.example agent /)
    expect(both.out.at(-1)).toMatch(new RegExp(`^Connected as acme-example-1 \\(acme\\.example\\)${ROUND}$`))
    const one = await w.run(() => enterpriseStatus(w.d(A)))
    expect([one.result, one.notes]).toEqual([0, []])
    expect(one.out[0]).toMatch(/^signed-in walk2\.example\.test agent /)
    expect(one.out.at(-1)).toMatch(
      new RegExp(`^Connected as walk2-example-test-1 \\(walk2\\.example\\.test\\)${ROUND}$`),
    )
    const none = await w.run(() => enterpriseStatus(w.d('other.example')).catch((e: EnterpriseError) => e))
    expect((none.result as EnterpriseError).message).toBe(
      'signed-out: not signed in to other.example: one of acme.example, walk2.example.test',
    )
  })

  it('sign-out without --org refuses with the list and removes nothing; with it, revokes that one only', async () => {
    const w = world()
    for (const code of w.codes) await connect(w.d(), { text: code, version: VERSION })
    const refused = await signOut(w.d()).catch((e: EnterpriseError) => e)
    expect([(refused as EnterpriseError).code, (refused as EnterpriseError).exit]).toEqual(['usage', 2])
    expect((refused as EnterpriseError).message).toBe(
      'usage: signed in to acme.example and walk2.example.test: bag sign-out --org <domain>, one of them',
    )
    expect([w.a.revoked.size, w.b.revoked.size]).toEqual([0, 0])
    const out = await w.run(() => signOut(w.d(A)))
    expect([out.result, out.out[0]]).toEqual([0, expect.stringMatching(/^signed-out walk2\.example\.test: /)])
    expect([w.a.revoked.size, w.b.revoked.size]).toEqual([1, 0])
    expect([profiles(w.home), readSession(w.home, B)?.state]).toEqual([[B], 'live'])
    // One profile again: status needs no --org and says nothing on the note line.
    const after = await w.run(() => enterpriseStatus(w.d()))
    expect([after.result, after.notes, after.out.at(-1)]).toEqual([
      0,
      [],
      expect.stringMatching(new RegExp(`^Connected as acme-example-1${ROUND}$`)),
    ])
  })

  it('signing out the most recent one moves current to the one left', async () => {
    const w = world()
    for (const code of w.codes) await connect(w.d(), { text: code, version: VERSION })
    expect(await signOut(w.d(B))).toBe(0)
    expect([selectOrg(w.home), readSession(w.home)?.domain]).toEqual([A, A])
  })

  it("each organisation's trust sync keeps to its own peer links: neither removes the other's", async () => {
    const w = world()
    for (const code of w.codes) await connect(w.d(), { text: code, version: VERSION })
    const peer = (root: string, source: string) => ({ root, source, granted_by: null, granted_at: 5 })
    w.a.extraRoots = [peer('domain:peer-a.example', 'peer:link-a')]
    w.b.extraRoots = [peer('domain:peer-b.example', 'peer:link-b')]
    w.a.trustEtag = w.b.trustEtag = 't2'
    w.time.now += 13 * 3600
    for (const o of [A, B, A]) expect((await tick(w.d(o))).error).toBeNull()
    const roots = () => readTrustFile(w.home, (d) => new Error(d))
    expect([roots()['domain:peer-a.example']?.source, roots()['domain:peer-b.example']?.source]).toEqual([
      'peer:link-a',
      'peer:link-b',
    ])
    // Signing one organisation out removes its own roots only.
    expect(await signOut(w.d(A))).toBe(0)
    expect(Object.keys(roots()).sort()).toEqual(['domain:acme.example', 'domain:peer-b.example'])
  })
})
