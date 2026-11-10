import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Hop, parseRecord, sha256hex, signPreimage, verifyChain } from '@usebag/core'
import { FsKeyStore, systemRng } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import type { DiscoveryNet } from '../src/discovery.ts'
import {
  chainText,
  type EnterpriseDeps,
  enterpriseStatus,
  refreshDue,
  type SignInOptions,
  signIn,
  signOut,
  tick,
} from '../src/flow.ts'
import { EnterpriseError } from '../src/instance.ts'
import { bindNonce, bindPreimage } from '../src/layer-auth.ts'
import { type Publisher, readRecordsCopy } from '../src/records.ts'
import {
  chainPath,
  profileHome,
  readPending,
  readSession,
  receiptsAnswered,
  secureHome,
} from '../src/session.ts'
import { readTrustFile, writeTrustFile } from '../src/trust-file.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { DAY, T0, tempDir } from './support/fixtures.ts'

// The agent side of a bag enterprise session against the recorded fake instance (no network): sign-in by the device
// flow and by a console code with the binding, the refresher with its lock, the generation and its grace, the freeze of
// a copied home, the two-hop chain and its renewal, the trust provenance and its removal, sign-out, and the
// never-expired walk (statement NE) over 60 simulated days.

const tmp = tempDir('enterprise')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const NO_RECORD: DiscoveryNet = {
  txt: async () => [],
  get: async () => ({ status: 404, body: null }),
  guard: { connectTo: async () => null },
}
let n = 0

interface World {
  readonly d: EnterpriseDeps
  readonly fake: FakeInstance
  readonly time: { now: number }
  readonly lines: string[]
  /** Runs once, at the next wait between polls (a person approving, say). */
  onSleep: (() => void) | null
}

function world(env: Record<string, string> = {}): World {
  const time = { now: T0 }
  const fake = new FakeInstance({ domain: DOMAIN, now: () => time.now })
  const lines: string[] = []
  const w: World = {
    fake,
    time,
    lines,
    onSleep: null,
    d: {
      home: join(tmp.dir, `home-${n++}`),
      env: { BAG_ENTERPRISE_URL: fake.origin, ...env },
      clock: { now: () => time.now },
      rng: systemRng,
      fetch: fake.fetch,
      net: NO_RECORD,
      sleep: async (ms) => {
        time.now += ms / 1000
        const hook = w.onSleep
        w.onSleep = null
        hook?.()
      },
      say: (line) => lines.push(line),
      readCode: async () => env.BAG_ORG_CODE ?? null,
    },
  }
  return w
}

const opts = (o: Partial<SignInOptions> = {}): SignInOptions => ({
  domain: DOMAIN,
  code: false,
  wait: true,
  version: 'test',
  ...o,
})

/** Signs a world in by the device flow, the person approving at the first wait. */
async function signedIn(w: World): Promise<number> {
  w.onSleep = () => w.fake.approve('BCDF-GGG0')
  return signIn(w.d, opts())
}

const chainOf = (w: World): Hop[] => JSON.parse(readFileSync(chainPath(w.d.home), 'utf8'))
/** A file of the organisation's profile: <home>/orgs/<domain>/enterprise/<file>. */
const profileFile = (w: World, file: string): string =>
  join(profileHome(w.d.home, DOMAIN), 'enterprise', file)

async function refusal(p: Promise<unknown>): Promise<EnterpriseError> {
  try {
    await p
  } catch (e) {
    if (e instanceof EnterpriseError) return e
    throw e
  }
  throw new Error('no refusal')
}

describe('sign-in by the device flow', () => {
  it('prints what a person approves, binds on every poll, and writes the session, the chain and the trust root', async () => {
    const w = world()
    expect(await signedIn(w)).toBe(0)
    expect(w.lines[0]).toBe('open https://id.example.test/auth/agent and enter the code BCDF-GGG0')
    const s = readSession(w.d.home)
    expect(s?.state).toBe('live')
    const agent = s?.agent_address as string
    expect(w.lines[1]).toBe(
      `fingerprint ${agent.slice(8, 16)} ${agent.slice(16, 24)} ${agent.slice(24, 32)} ${agent.slice(32, 40)} (the agent's key, as that page shows it)`,
    )
    const polls = w.fake.calls.filter((c) => c.path === '/agent/token')
    expect(polls.map((c) => c.body?.binding !== undefined)).toEqual([true, true])
    const code = w.fake.calls.find((c) => c.path === '/agent/code')?.body
    expect(code?.label).toBe('acme-example')
    expect(code?.signin_address).toMatch(/^ed25519:[0-9a-f]{64}$/)
    expect(code?.bind_nonce).toBeUndefined()
    // Refresh and state name the session by the sign-in key's address.
    const state = w.fake.calls.find((c) => c.path === '/agent/state')?.body
    expect([state?.agent_address, state?.signin_address]).toEqual([agent, code?.signin_address])
    // The chain verifies as the session key's, under the org root, with A as the principal (replies reach A).
    const chain = chainOf(w)
    const result = verifyChain(chain, s?.session_address as string, T0)
    expect(result).toEqual({ root: w.fake.root.address, principal: agent, caveats: [] })
    expect(chain[1]?.exp).toBe(T0 + 5 + DAY)
    expect(readTrustFile(w.d.home, (d) => new Error(d))).toEqual({
      [`domain:${DOMAIN}`]: {
        added_at: T0 + 5,
        source: `org:${DOMAIN}`,
        granted_by: 'person-1',
        granted_at: 1,
      },
    })
    expect(w.lines).toContain(`trust domain:${DOMAIN} source org:${DOMAIN}`)
    expect(readPending(w.d.home)).toBeNull()
    // Key files and the session are 0600; no line printed holds the token or a seed.
    expect(statSync(profileFile(w, 'session.json')).mode & 0o777).toBe(0o600)
    expect(statSync(join(w.d.home, 'keys', 'acme-example.signin.json')).mode & 0o777).toBe(0o600)
    expect(w.lines.join('\n')).not.toContain(s?.access_token as string)
  })

  it('--no-wait exits 4 waiting, and a second sign-in resumes the same code', async () => {
    const w = world()
    const e = await refusal(signIn(w.d, opts({ wait: false })))
    expect([e.code, e.exit]).toEqual(['authorization_pending', 4])
    expect(readPending(w.d.home)?.device_code).toMatch(/^[0-9a-f]{32}$/)
    w.fake.approve('BCDF-GGG0')
    expect(await signIn(w.d, opts())).toBe(0)
    expect(w.fake.calls.filter((c) => c.path === '/agent/code')).toHaveLength(1)
  })

  it('the instance takes only a binding over the nonce derived from this device code, at the exchange', async () => {
    const w = world()
    await refusal(signIn(w.d, opts({ wait: false })))
    const p = readPending(w.d.home)
    const keys = new FsKeyStore(join(w.d.home, 'keys'))
    const [agent, signin] = [keys.load('acme-example').signing, keys.load('acme-example.signin').signing]
    w.fake.approve('BCDF-GGG0')
    const poll = async (secret: string | null) => {
      const pre = bindPreimage(DOMAIN, agent.address, signin.address, bindNonce(secret ?? ''), T0)
      const binding = secret === null ? {} : { binding: { ts: T0, sig: signPreimage(agent, pre) } }
      const body = {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: p?.device_code,
        ...binding,
      }
      const r = await w.fake.fetch(`${w.fake.origin}/api/v1/auth/agent/token`, {
        method: 'POST',
        body: JSON.stringify(body),
      })
      return (await r.json()) as Record<string, unknown>
    }
    expect((await poll(null)).error).toBe('authorization_pending')
    expect((await poll('another device code')).detail).toBe('bad-bind-sig')
    expect(bindNonce('x')).toBe(sha256hex('bag-ent/bind-nonce/1\nx'))
    expect((await poll(p?.device_code as string)).generation).toBe(0)
  })

  it('a code answer whose bind_nonce is not derived from its device code is refused', async () => {
    const w = world()
    w.fake.wrongNonce = true
    expect((await refusal(signIn(w.d, opts()))).code).toBe('bad-answer')
  })

  it('denied, expired, an unknown domain and a usage error refuse with their codes and exits', async () => {
    const denied = world()
    denied.onSleep = () => denied.fake.deny('BCDF-GGG0')
    expect((await refusal(signIn(denied.d, opts()))).code).toBe('access_denied')
    expect(readPending(denied.d.home)).toBeNull()
    const late = world()
    expect((await refusal(signIn(late.d, opts({ wait: true })))).code).toBe('expired_token')
    const other = world()
    expect((await refusal(signIn(other.d, opts({ domain: 'other.example' })))).code).toBe('unknown_domain')
    const bad = world()
    expect(await refusal(signIn(bad.d, opts({ domain: 'Not A Domain' })))).toMatchObject({
      code: 'usage',
      exit: 2,
    })
  })

  it('an existing key file is never overwritten, and --as names another agent', async () => {
    const w = world()
    await signedIn(w)
    await signOut(w.d)
    const again = { ...w.d }
    expect((await refusal(signIn(again, opts()))).code).toBe('EEXIST')
    w.onSleep = () => w.fake.approve('BCDF-GGG1')
    expect(await signIn(w.d, opts({ name: 'acme-2', label: 'build box' }))).toBe(0)
    expect(w.fake.calls.at(-0)?.path).toBeDefined()
    expect(w.fake.calls.filter((c) => c.path === '/agent/code').at(-1)?.body?.label).toBe('build box')
  })

  it('a signer that has not signed yet: exit 4, then a status tick brings the hop and the chain', async () => {
    const w = world()
    // A relay that serves the agent's records: status's probe of the path reads the address record back.
    ;(w.d as { relays?: unknown }).relays = new FakeRelay()
    w.fake.signer = false
    expect(await signedIn(w)).toBe(4)
    expect(w.lines.some((l) => l.startsWith("waiting: the organisation's signer"))).toBe(true)
    expect((await refusal(chainText(w.d))).code).toBe('no-hop')
    w.fake.signer = true
    w.lines.length = 0
    expect(await enterpriseStatus(w.d)).toBe(0)
    expect(w.lines.at(-1)).toMatch(/^Connected as acme-example; relay round trip \d+ ms$/)
    expect(readSession(w.d.home)?.generation).toBe(3)
    expect(JSON.parse(await chainText(w.d))).toHaveLength(2)
  })
})

describe('sign-in by a console code (--code)', () => {
  it('reads BAG_ORG_CODE, redeems it, shows no user code, and refuses a malformed code as usage', async () => {
    const w = world({ BAG_ORG_CODE: 'bagcode_abcdefgh1234' })
    w.fake.consoleCodes.add('bagcode_abcdefgh1234')
    expect(await signIn(w.d, opts({ code: true }))).toBe(0)
    expect(w.lines.filter((l) => /^(open|signed-in) /.test(l)).map((l) => l.split(' ')[0])).toEqual([
      'signed-in',
    ])
    expect(w.fake.calls.map((c) => c.path).slice(0, 2)).toEqual(['/agent/redeem', '/agent/trust'])
    expect((w.fake.calls[0]?.body?.binding as { sig?: string })?.sig).toMatch(/^[0-9a-f]{128}$/)
    const bad = world({ BAG_ORG_CODE: 'nope' })
    expect(await refusal(signIn(bad.d, opts({ code: true })))).toMatchObject({ code: 'usage', exit: 2 })
    const used = world({ BAG_ORG_CODE: 'bagcode_abcdefgh1234' })
    expect((await refusal(signIn(used.d, opts({ code: true })))).code).toBe('invalid_grant')
  })
})

describe('the refresher', () => {
  it('refreshes under 12 h left, re-signs the local hop under 12 h and on a new org hop, and states hourly', async () => {
    const w = world()
    await signedIn(w)
    const s0 = readSession(w.d.home)
    expect(s0 && refreshDue(s0, w.time.now)).toBe(false)
    w.time.now += 13 * 3600
    await tick(w.d)
    const s1 = readSession(w.d.home)
    expect(s1?.generation).toBe(1)
    expect(chainOf(w)[1]?.exp).toBe(w.time.now + DAY)
    const states = w.fake.calls.filter((c) => c.path === '/agent/state')
    expect(states).toHaveLength(2)
    expect(states[1]?.body?.generation).toBe(1)
    // The org hop past half its life: the instance re-signs it, and the local hop follows at once.
    w.time.now += 3 * DAY
    await tick(w.d)
    const chain = chainOf(w)
    expect(chain[0]?.exp).toBe(w.time.now + 7 * DAY)
    expect(chain[1]?.exp).toBe(w.time.now + DAY)
  })

  it('two refreshers at once: one runs, the other stands aside, and the stored token is the live one', async () => {
    const w = world()
    await signedIn(w)
    w.time.now += 13 * 3600
    const [a, b] = await Promise.all([tick(w.d), tick(w.d)])
    expect([a.held, b.held].sort()).toEqual([false, true])
    expect(readSession(w.d.home)?.access_token).toBe(w.fake.row().token)
    expect(w.fake.row().state).toBe('live')
  })

  it('a copied home freezes on its stale generation: frozen, exit 4, the line says so; the real home too, later', async () => {
    const w = world()
    await signedIn(w)
    const copy = join(tmp.dir, `copy-${n++}`)
    execFileSync('cp', ['-Rp', w.d.home, copy])
    w.time.now += 13 * 3600
    await tick(w.d)
    w.time.now += 600
    const c = { ...w.d, home: copy, say: (l: string) => w.lines.push(`copy ${l}`) }
    w.lines.length = 0
    expect(await enterpriseStatus(c)).toBe(4)
    expect(readSession(copy)?.state).toBe('frozen')
    expect(w.lines.some((l) => l.includes('frozen: the organisation saw a stale generation'))).toBe(true)
    expect(w.lines.some((l) => l.includes('refresh stale_generation'))).toBe(true)
    expect((await refusal(chainText(c))).code).toBe('no-hop')
    // The instance froze the agent: the real home's next refresh reads agent_frozen.
    w.time.now += 12 * 3600
    expect(await enterpriseStatus(w.d)).toBe(4)
    expect(readSession(w.d.home)?.reason).toBe('agent_frozen')
  })

  it('a retry inside the grace gets the current token, no freeze', async () => {
    const w = world()
    await signedIn(w)
    const copy = join(tmp.dir, `copy-${n++}`)
    execFileSync('cp', ['-Rp', w.d.home, copy])
    w.time.now += 13 * 3600
    await tick(w.d)
    w.time.now += 30
    await tick({ ...w.d, home: copy })
    expect(readSession(copy)?.state).toBe('live')
    expect(readSession(copy)?.access_token).toBe(w.fake.row().token)
  })

  it('revoked: ended, the organisation roots leave trust.json (a person root stays), the chain goes, exit 3', async () => {
    const w = world()
    await signedIn(w)
    const trust = readTrustFile(w.d.home, (d) => new Error(d))
    writeTrustFile(w.d.home, { ...trust, 'domain:friend.example': { added_at: T0 } })
    w.fake.row().state = 'ended'
    w.time.now += 13 * 3600
    expect(await enterpriseStatus(w.d)).toBe(3)
    expect(Object.keys(readTrustFile(w.d.home, (d) => new Error(d)))).toEqual(['domain:friend.example'])
    expect(existsSync(profileFile(w, 'chain.json'))).toBe(false)
    expect((await refusal(chainText(w.d))).exit).toBe(3)
    expect((await refusal(signIn(w.d, opts()))).code).toBe('signed-in')
    expect(await signOut(w.d)).toBe(0)
  })

  it('lapsed is final for the session: exit 3, no refresh revives it, the roots stay; sign-in again keeps the address', async () => {
    const w = world()
    await signedIn(w)
    const agent = readSession(w.d.home)?.agent_address
    w.fake.row().state = 'lapsed'
    w.time.now += 13 * 3600
    expect(await enterpriseStatus(w.d)).toBe(3)
    expect(w.lines.some((l) => l.startsWith('lapsed: final for this session'))).toBe(true)
    expect(Object.keys(readTrustFile(w.d.home, (d) => new Error(d)))).toEqual([`domain:${DOMAIN}`])
    expect((await refusal(chainText(w.d))).exit).toBe(3)
    const before = w.fake.calls.length
    w.time.now += 13 * 3600
    expect(await enterpriseStatus(w.d)).toBe(3)
    expect(w.fake.calls.length).toBe(before)
    w.onSleep = () => w.fake.approve('BCDF-GGG1')
    expect(await signIn(w.d, opts())).toBe(0)
    expect([readSession(w.d.home)?.agent_address, readSession(w.d.home)?.state]).toEqual([agent, 'live'])
    w.fake.row().state = 'lapsed'
    w.time.now += 13 * 3600
    await tick(w.d)
    expect(await signOut(w.d)).toBe(0)
  })

  it('suspended: paused, exit 4; offline: the session stays and the line says why; skew prints the server time', async () => {
    const w = world()
    ;(w.d as { relays?: unknown }).relays = new FakeRelay()
    await signedIn(w)
    w.time.now += 13 * 3600
    w.fake.down.set('/agent/refresh', 1)
    expect(await enterpriseStatus(w.d)).toBe(0)
    expect(w.lines.some((l) => l.startsWith('refresh unreachable:'))).toBe(true)
    w.fake.row().state = 'paused'
    expect(await enterpriseStatus(w.d)).toBe(4)
    expect(readSession(w.d.home)?.state).toBe('paused')
    w.fake.row().state = 'live'
    expect(await enterpriseStatus(w.d)).toBe(0)
    const skewed = { ...w.d, clock: { now: () => w.time.now + 1000 } }
    w.time.now += 13 * 3600
    w.lines.length = 0
    await enterpriseStatus(skewed)
    expect(w.lines.some((l) => /refresh clock_skew: .*server time \d+/.test(l))).toBe(true)
  })

  it('trust roots follow their etag: a peer root added with its provenance, then removed; never *, at most 64', async () => {
    const w = world()
    await signedIn(w)
    const peer = { root: 'domain:peer.example', source: 'peer:link-1', granted_by: 'person-2', granted_at: 5 }
    w.fake.extraRoots = [peer]
    w.fake.trustEtag = 't2'
    w.time.now += 13 * 3600
    await tick(w.d)
    expect(readTrustFile(w.d.home, (d) => new Error(d))['domain:peer.example']?.source).toBe('peer:link-1')
    w.fake.extraRoots = [{ ...peer, root: '*' }]
    w.fake.trustEtag = 't3'
    w.time.now += 13 * 3600
    expect((await tick(w.d)).error?.code).toBe('trust-invalid')
    w.fake.extraRoots = Array.from({ length: 64 }, (_, i) => ({ ...peer, root: `domain:p${i}.example` }))
    w.fake.trustEtag = 't4'
    expect((await tick(w.d)).error?.code).toBe('trust-invalid')
    w.fake.extraRoots = []
    w.fake.trustEtag = 't5'
    await tick(w.d)
    expect(Object.keys(readTrustFile(w.d.home, (d) => new Error(d)))).toEqual([`domain:${DOMAIN}`])
  })

  it('never expired (NE): ticking hourly for 60 days, asleep for up to 11 h at a time, no clock is found expired', async () => {
    const w = world()
    await signedIn(w)
    const sleeps = [1, 1, 11, 3, 1, 7, 11, 2]
    for (let i = 0; w.time.now < T0 + 60 * DAY; i++) {
      w.time.now += (sleeps[i % sleeps.length] as number) * 3600
      const t = await tick(w.d)
      expect(t.error).toBeNull()
      const s = readSession(w.d.home)
      const chain = JSON.parse(await chainText(w.d)) as Hop[]
      expect(verifyChain(chain, s?.session_address as string, w.time.now).principal).toBe(s?.agent_address)
      expect((s?.token_exp ?? 0) - w.time.now).toBeGreaterThan(12 * 3600 - 1)
    }
    expect(w.fake.row().state).toBe('live')
  })
})

describe('sign-out', () => {
  it('revokes at the instance, removes the org roots, the session files and the sign-in and session keys; A stays', async () => {
    const w = world()
    await signedIn(w)
    w.time.now += 23.95 * 3600
    expect(await signOut(w.d)).toBe(0)
    expect(w.fake.revoked.size).toBe(1)
    expect(readSession(w.d.home)).toBeNull()
    expect(readTrustFile(w.d.home, (d) => new Error(d))).toEqual({})
    expect(existsSync(join(w.d.home, 'keys', 'acme-example.json'))).toBe(true)
    expect(existsSync(join(w.d.home, 'keys', 'acme-example.signin.json'))).toBe(false)
    expect(existsSync(join(w.d.home, 'keys', 'acme-example.session.json'))).toBe(false)
    expect((await refusal(signOut(w.d))).exit).toBe(3)
    expect((await refusal(enterpriseStatus(w.d))).exit).toBe(3)
  })

  it('an unreachable instance removes nothing; a waiting sign-in is dropped', async () => {
    const w = world()
    await signedIn(w)
    w.fake.down.set('/agent/sign-out', 1)
    expect((await refusal(signOut(w.d))).code).toBe('unreachable')
    expect(readSession(w.d.home)?.state).toBe('live')
    const p = world()
    await refusal(signIn(p.d, opts({ wait: false })))
    expect(await enterpriseStatus(p.d)).toBe(4)
    // Another organisation is a profile of its own: the waiting sign-in stays, and the other goes to its instance.
    expect((await refusal(signIn(p.d, opts({ domain: 'other.example' })))).code).toBe('unknown_domain')
    expect(readPending(p.d.home, DOMAIN)?.domain).toBe(DOMAIN)
    // Two profiles: sign-out names the one, never a guess.
    const both = await refusal(signOut(p.d))
    expect([both.code, both.message]).toEqual([
      'usage',
      'usage: signed in to acme.example and other.example: bag sign-out --org <domain>, one of them',
    ])
    expect(await signOut({ ...p.d, org: DOMAIN })).toBe(0)
    expect(readPending(p.d.home, DOMAIN)).toBeNull()
  })
})

describe('the agent records follow the org relays (records.ts through the refresh)', () => {
  it('publishes both records at a relay added after sign-in, at the first refresh after it appears', async () => {
    const w = world()
    const sent: Array<{ url: string; kind: string; key: string }> = []
    const publisher: Publisher = {
      async publish(url, bytes) {
        const r = parseRecord(bytes)
        sent.push({ url, kind: r.kind, key: r.kind === 'accept-from' ? r.owner : r.key })
        return { id: '', duplicate: false, delivered: 0 }
      },
    }
    ;(w.d as { relays?: Publisher }).relays = publisher
    expect(await signedIn(w)).toBe(0)
    const agent = readSession(w.d.home)?.agent_address as string
    expect(sent.map((s) => `${s.kind} ${s.url}`)).toEqual([
      'address https://relay.example.test',
      'accept-from https://relay.example.test',
    ])
    expect(w.lines).toContain('records address https://relay.example.test published')

    // A second relay becomes active at the instance. The next tick does not refresh yet: nothing moves.
    w.fake.relays.push('https://relay2.example.test')
    w.time.now += 3_600
    await tick(w.d)
    expect(sent).toHaveLength(2)
    expect(readSession(w.d.home)?.org.relays).toEqual(['https://relay.example.test'])

    // The token under 12 h left: the tick refreshes, the answer names both relays, and both records go to both.
    w.time.now += 12 * 3_600
    const t = await tick(w.d)
    expect(t.error).toBeNull()
    expect(readSession(w.d.home)?.org.relays).toEqual([
      'https://relay.example.test',
      'https://relay2.example.test',
    ])
    expect(sent.slice(2).map((s) => `${s.kind} ${s.url} ${s.key === agent}`)).toEqual([
      'address https://relay.example.test true',
      'accept-from https://relay.example.test true',
      'address https://relay2.example.test true',
      'accept-from https://relay2.example.test true',
    ])
    expect(readRecordsCopy(profileHome(w.d.home, DOMAIN))?.relays).toEqual([
      'https://relay.example.test',
      'https://relay2.example.test',
    ])
  })

  it("signs the accept list's roots at the next tick, republishes when its etag moves, and claims partner roots", async () => {
    const w = world()
    const sent: { url: string; roots: readonly string[] }[] = []
    const publisher: Publisher = {
      async publish(url, bytes) {
        const r = parseRecord(bytes)
        if (r.kind === 'accept-from') sent.push({ url, roots: r.roots })
        return { id: '', duplicate: false, delivered: 0 }
      },
    }
    ;(w.d as { relays?: Publisher }).relays = publisher
    expect(await signedIn(w)).toBe(0)
    const own = readSession(w.d.home)?.org.root as string
    expect(sent.map((s) => s.roots)).toEqual([[own]])
    const partner = `ed25519:${'7c'.repeat(32)}`
    w.fake.acceptList = [own, partner]
    w.time.now += 60
    await tick(w.d)
    expect(sent.map((s) => s.roots)).toEqual([[own], [own, partner]])
    expect(readSession(w.d.home)?.accept_etag).toBe('a1')
    // The same etag: a 304, nothing republished; a new one with another partner: republished at once.
    w.time.now += 60
    await tick(w.d)
    expect(sent).toHaveLength(2)
    w.fake.acceptList = [own, partner, 'domain:okok.example']
    w.fake.acceptEtag = 'a2'
    await tick(w.d)
    expect(sent.at(-1)?.roots).toEqual([own, partner, 'domain:okok.example'])
    // The partnership's root on /agent/trust is claimed as peer links are, and leaves when the partnership does.
    const grant = {
      root: partner,
      source: 'partner:3f2c9a1e-0b7d-4e55-9a61-2c4d8e0f1a2b',
      granted_by: 'partnership',
      granted_at: 5,
    }
    w.fake.extraRoots = [grant]
    w.fake.trustEtag = 't2'
    w.time.now += 13 * 3600
    expect((await tick(w.d)).trust?.added).toEqual([partner])
    expect(readTrustFile(w.d.home, (d) => new Error(d))[partner]?.source).toBe(grant.source)
    w.fake.extraRoots = []
    w.fake.trustEtag = 't3'
    w.time.now += 13 * 3600
    expect((await tick(w.d)).trust?.removed).toEqual([partner])
    // An instance older than the list (404): the record is the org root alone again.
    w.fake.acceptList = null
    await tick(w.d)
    expect(sent.at(-1)?.roots).toEqual([own])
  })

  it("keeps the organisation's receipts: false with the trust sync, and drops it on true or an answer without it", async () => {
    const w = world()
    expect(await signedIn(w)).toBe(0)
    const s = () => readSession(w.d.home)
    expect([s()?.receipts, receiptsAnswered(w.d.home, s()?.name as string)]).toEqual([undefined, true])
    const step = async (receipts: boolean | null, etag: string) => {
      w.fake.receipts = receipts
      w.fake.trustEtag = etag
      w.time.now += 13 * 3600
      expect((await tick(w.d)).error).toBeNull()
      return [s()?.receipts, receiptsAnswered(w.d.home, s()?.name as string)]
    }
    expect(await step(false, 'r1')).toEqual([false, false])
    expect(receiptsAnswered(w.d.home, 'another-agent')).toBe(true)
    expect(await step(true, 'r2')).toEqual([undefined, true])
    expect(await step(false, 'r3')).toEqual([false, false])
    expect(await step(null, 'r4')).toEqual([undefined, true])
  })

  it('keeps the session org when a refresh names another root', async () => {
    const w = world()
    ;(w.d as { relays?: Publisher }).relays = {
      publish: async () => ({ id: '', duplicate: false, delivered: 0 }),
    }
    expect(await signedIn(w)).toBe(0)
    const before = readSession(w.d.home)?.org
    const realFetch = w.fake.fetch
    ;(w.d as { fetch: typeof realFetch }).fetch = async (url, init) => {
      const res = await realFetch(url, init)
      if (!url.endsWith('/agent/refresh')) return res
      const body = (await res.json()) as Record<string, unknown>
      const org = body.org as { relays: string[] }
      const other = `ed25519:${'1'.repeat(64)}`
      return new Response(
        JSON.stringify({ ...body, org: { ...org, root: other, relays: ['https://evil.example.test'] } }),
        {
          status: res.status,
          headers: { 'content-type': 'application/json' },
        },
      )
    }
    w.time.now += 13 * 3_600
    await tick(w.d)
    expect(readSession(w.d.home)?.org).toEqual(before)
  })
})

describe('the files and the answers', () => {
  it('a session file that is not one is refused; a home under a file is an error, not a missing home', async () => {
    const w = world()
    mkdirSync(join(w.d.home, 'enterprise'), { recursive: true, mode: 0o700 })
    writeFileSync(join(w.d.home, 'enterprise', 'session.json'), '{"v":2}', { mode: 0o600 })
    expect(() => readSession(w.d.home)).toThrow(/^session-invalid: /)
    expect((await refusal(enterpriseStatus(w.d))).code).toBe('session-invalid')
    const file = join(w.d.home, 'a-file')
    writeFileSync(file, '')
    expect(() => secureHome(join(file, 'home'))).toThrow(/ENOTDIR/)
  })

  it('a grant naming no organisation, or a hop not from its root to this agent, is a bad answer', async () => {
    for (const change of [
      (g: Record<string, unknown>) => ({ ...g, org: { domain: 'other.example', root: 'x', relays: [] } }),
      (g: Record<string, unknown>) => ({ ...g, org: { ...(g.org as object), relays: ['ftp://relay'] } }),
      (g: Record<string, unknown>) => ({ ...g, hop: { ...(g.hop as object), sig: '00'.repeat(64) } }),
      (g: Record<string, unknown>) => ({ ...g, generation: 1 }),
    ]) {
      const w = world({ BAG_ORG_CODE: 'bagcode_abcdefgh1234' })
      w.fake.consoleCodes.add('bagcode_abcdefgh1234')
      const real = w.fake.fetch
      ;(w.d as { fetch: typeof real }).fetch = async (url, init) => {
        const res = await real(url, init)
        if (!url.endsWith('/agent/redeem')) return res
        return new Response(JSON.stringify(change((await res.json()) as Record<string, unknown>)), {
          status: 200,
        })
      }
      const e = await refusal(signIn(w.d, opts({ code: true })))
      expect(e.code).toBe('bad-answer')
      expect(readSession(w.d.home)).toBeNull()
      expect(e.message).not.toContain('bagcode_abcdefgh1234')
    }
  })
})
