import { chmodSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { DIRECTORY_PATH, directory, directoryPath, resolveHandle, resolveLabel } from '../src/directory.ts'
import { EnterpriseError, type Fetch } from '../src/instance.ts'
import { enterpriseDir, profileHome, writeJson } from '../src/session.ts'
import { tempDir } from './support/fixtures.ts'

// The organisation's directory, client side: a faked instance answers 200, 304, 401, a timeout and a failure; the copy
// in the home serves under 60 s and, with a warning line, when the call fails; labels resolve in any case, to one
// address, and two agents under one label is an error naming both.

const tmp = tempDir('directory')
afterAll(() => tmp.cleanup())
const ORIGIN = 'https://bag.acme.example'
const TOKEN = 'directory-test-bearer-only-for-these-tests'
const T = 1_800_000_000_000
const A = `ed25519:${'a'.repeat(64)}`
const B = `ed25519:${'b'.repeat(64)}`
const C = `ed25519:${'c'.repeat(64)}`
const ME = `ed25519:${'e'.repeat(64)}`
const at = '2026-11-07T04:00:00.000Z'
let homes = 0

/** A home with a session of `domain` in its profile (<home>/orgs/<domain>), or added to the home `h` given. */
function home(
  instance = ORIGIN,
  agent = ME,
  domain = 'acme.example',
  h = join(tmp.dir, `home-${homes++}`),
): string {
  mkdirSync(enterpriseDir(profileHome(h, domain)), { recursive: true, mode: 0o700 })
  const session = { v: 1, domain, instance, agent_address: agent, access_token: TOKEN }
  writeJson(join(enterpriseDir(profileHome(h, domain)), 'session.json'), session)
  return h
}

interface Call {
  readonly url: string
  readonly init: RequestInit
}

/** A faked instance: each call takes the next answer; `null` never answers, but honours the call's signal. */
function instance(...answers: (Response | Error | null)[]): { fetch: Fetch; calls: Call[] } {
  const calls: Call[] = []
  const fetch: Fetch = async (url, init) => {
    calls.push({ url, init })
    const next = answers.shift()
    if (next === undefined) throw new Error('no answer left')
    if (next instanceof Error) throw next
    if (next !== null) return next
    return new Promise((_, reject) =>
      init.signal?.addEventListener('abort', () => reject(init.signal?.reason)),
    )
  }
  return { fetch, calls }
}

const ok = (agents: unknown[], etag = 'e1') => new Response(JSON.stringify({ agents, etag }), { status: 200 })
const agent = (label: string, address: string) => ({ label, address, connectedAt: at })
const header = (c: Call | undefined, name: string) => new Headers(c?.init.headers).get(name)
const refusal = async (p: Promise<unknown>) => {
  const e = await p.then(
    () => null,
    (e: unknown) => e,
  )
  expect(e).toBeInstanceOf(EnterpriseError)
  return e as EnterpriseError
}

describe('directory', () => {
  it('fetches the directory from the pinned origin with the bearer, no redirect, a timeout, and keeps it 0600', async () => {
    const h = home()
    const f = instance(ok([agent('alice', A), agent('bob', B)]))
    const d = await directory(h, { fetch: f.fetch, now: () => T })
    expect(d).toEqual({ agents: [agent('alice', A), agent('bob', B)], fetchedAt: T, source: 'instance' })
    expect(f.calls).toHaveLength(1)
    const [c] = f.calls
    expect(c?.url).toBe(`${ORIGIN}${DIRECTORY_PATH}`)
    expect(c?.init).toMatchObject({ method: 'GET', redirect: 'error' })
    expect(c?.init.signal).toBeInstanceOf(AbortSignal)
    expect(header(c, 'authorization')).toBe(`Bearer ${TOKEN}`)
    expect(header(c, 'if-none-match')).toBeNull()
    expect(statSync(directoryPath(h, 'acme.example')).mode & 0o777).toBe(0o600)
    expect(readFileSync(directoryPath(h, 'acme.example'), 'utf8')).not.toContain(TOKEN)
  })

  it('serves the copy while under 60 s old, and asks again with refresh or after 60 s', async () => {
    const h = home()
    const f = instance(ok([agent('alice', A)]), ok([agent('alice', A), agent('bob', B)], 'e2'))
    await directory(h, { fetch: f.fetch, now: () => T })
    const warm = await directory(h, { fetch: f.fetch, now: () => T + 59_999 })
    expect(warm).toEqual({ agents: [agent('alice', A)], fetchedAt: T, source: 'cache' })
    expect(f.calls).toHaveLength(1)
    const refreshed = await directory(h, { fetch: f.fetch, now: () => T + 1000, refresh: true })
    expect(refreshed.agents).toHaveLength(2)
    expect(header(f.calls[1], 'if-none-match')).toBe('e1')
  })

  it('takes a 304 as the copy confirmed: the same list, a new fetch time', async () => {
    const h = home()
    const f = instance(ok([agent('alice', A)]), new Response(null, { status: 304 }))
    await directory(h, { fetch: f.fetch, now: () => T })
    const d = await directory(h, { fetch: f.fetch, now: () => T + 61_000 })
    expect(d).toEqual({ agents: [agent('alice', A)], fetchedAt: T + 61_000, source: 'instance' })
    expect(header(f.calls[1], 'if-none-match')).toBe('e1')
    const warm = await directory(h, { fetch: f.fetch, now: () => T + 100_000 })
    expect(warm.source).toBe('cache')
  })

  it('refuses a 304 to a call that held no copy', async () => {
    const f = instance(new Response(null, { status: 304 }))
    expect((await refusal(directory(home(), { fetch: f.fetch }))).code).toBe('bad-answer')
  })

  it('throws the refusal on 401 or 403, even with a copy, and names the code the instance gave', async () => {
    const h = home()
    const body = JSON.stringify({ error: 'agent_revoked', error_description: 'revoked' })
    const f = instance(ok([agent('alice', A)]), new Response(body, { status: 401 }))
    await directory(h, { fetch: f.fetch, now: () => T })
    const e = await refusal(directory(h, { fetch: f.fetch, now: () => T + 61_000, warn: () => {} }))
    expect([e.code, e.exit]).toEqual(['agent_revoked', 3])
    const g = instance(new Response('<html>', { status: 403 }))
    expect((await refusal(directory(home(), { fetch: g.fetch }))).code).toBe('session-not-live')
  })

  it('times out after 3 s: unreachable with no copy, the stale copy with its age on the warning line', async () => {
    const started = Date.now()
    const e = await refusal(directory(home(), { fetch: instance(null).fetch }))
    const took = Date.now() - started
    expect(e.code).toBe('unreachable')
    expect(took).toBeGreaterThanOrEqual(2900)
    expect(took).toBeLessThan(5000)
    const h = home()
    const lines: string[] = []
    await directory(h, { fetch: instance(ok([agent('alice', A)])).fetch, now: () => T })
    const d = await directory(h, {
      fetch: instance(null).fetch,
      now: () => T + 75_000,
      warn: (l) => lines.push(l),
    })
    expect(d).toEqual({ agents: [agent('alice', A)], fetchedAt: T, source: 'stale' })
    expect(lines).toHaveLength(1)
    expect(lines[0]).toContain('using the copy from 75 s ago')
    expect(lines[0]).toContain(ORIGIN)
    // Two 3 s timeouts in one test: past vitest's default 5 s, so the test has its own bound.
  }, 10_000)

  it('serves a stale copy on a failed call: a 500, a network error, an answer that is no directory', async () => {
    const h = home()
    await directory(h, { fetch: instance(ok([agent('alice', A)])).fetch, now: () => T })
    const answers = [
      new Response('oops', { status: 500 }),
      new TypeError('fetch failed: redirect'),
      new Response('{"rows":[]}', { status: 200 }),
      new Response('not json', { status: 200 }),
    ]
    for (const [i, a] of answers.entries()) {
      const lines: string[] = []
      const d = await directory(h, {
        fetch: instance(a).fetch,
        now: () => T + 120_000,
        warn: (l) => lines.push(l),
      })
      expect([d.source, lines.length], `answer ${i}`).toEqual(['stale', 1])
      expect(lines[0]).toContain('120 s ago')
    }
    const e = await refusal(directory(home(), { fetch: instance(new Response('x', { status: 502 })).fetch }))
    expect(e.message).toContain('http-502')
  })

  it('needs a session, and refuses an instance that is not a pinned origin', async () => {
    const bare = join(tmp.dir, 'no-session')
    mkdirSync(bare)
    expect((await refusal(directory(bare, { fetch: instance().fetch }))).code).toBe('no-session')
    for (const bad of ['http://bag.acme.example', `${ORIGIN}/path`, 'not a url', 'ftp://bag.acme.example']) {
      const f = instance()
      expect((await refusal(directory(home(bad), { fetch: f.fetch }))).code).toBe('session-invalid')
      expect(f.calls).toHaveLength(0)
    }
    const local = 'http://127.0.0.1:8787'
    const f = instance(ok([agent('alice', A)]))
    await directory(home(local), { fetch: f.fetch })
    expect(f.calls[0]?.url).toBe(`${local}${DIRECTORY_PATH}`)
  })

  it('refuses a copy that is a symbolic link or open to others; ignores one of another session or not JSON', async () => {
    const linked = home()
    writeFileSync(join(linked, 'elsewhere.json'), '{}', { mode: 0o600 })
    symlinkSync(join(linked, 'elsewhere.json'), directoryPath(linked, 'acme.example'))
    expect((await refusal(directory(linked, { fetch: instance().fetch }))).code).toBe('home-invalid')
    const open = home()
    await directory(open, { fetch: instance(ok([agent('alice', A)])).fetch, now: () => T })
    chmodSync(directoryPath(open, 'acme.example'), 0o644)
    expect((await refusal(directory(open, { fetch: instance().fetch, now: () => T }))).code).toBe(
      'home-invalid',
    )
    const other = home(ORIGIN, A)
    writeJson(directoryPath(other, 'acme.example'), {
      v: 1,
      session: `acme.example ${ORIGIN} ${ME}`,
      etag: 'x',
      fetchedAt: T,
      agents: [],
    })
    const f = instance(ok([agent('bob', B)]))
    expect((await directory(other, { fetch: f.fetch, now: () => T })).source).toBe('instance')
    expect(header(f.calls[0], 'if-none-match')).toBeNull()
    const junk = home()
    writeFileSync(directoryPath(junk, 'acme.example'), 'not json', { mode: 0o600 })
    expect((await directory(junk, { fetch: instance(ok([])).fetch })).source).toBe('instance')
  })

  it('leaves out malformed entries', async () => {
    const entries = [
      agent('alice', A),
      agent('bob', 'ed25519:XYZ'),
      { label: 'carol', address: C },
      agent('', C),
      agent('tab\there', C),
      null,
      'dave',
    ]
    const d = await directory(home(), { fetch: instance(ok(entries)).fetch })
    expect(d.agents).toEqual([agent('alice', A)])
  })
})

describe('resolveLabel', () => {
  it('resolves a label in any case to its one address, and undefined when no agent has it', async () => {
    const h = home()
    const f = instance(ok([agent('Alice', A), agent('bob', B), agent('bob', B)]))
    expect(await resolveLabel(h, 'alice', { fetch: f.fetch, now: () => T })).toBe(A)
    expect(await resolveLabel(h, 'ALICE', { fetch: f.fetch, now: () => T })).toBe(A)
    expect(await resolveLabel(h, 'bob', { fetch: f.fetch, now: () => T })).toBe(B)
    expect(f.calls).toHaveLength(1)
  })

  it('asks the instance once more on a miss in a warm copy, so an agent connected since then resolves', async () => {
    const h = home()
    const f = instance(
      ok([agent('alice', A)]),
      ok([agent('alice', A), agent('carol', C)], 'e2'),
      ok([], 'e3'),
    )
    expect(await resolveLabel(h, 'alice', { fetch: f.fetch, now: () => T })).toBe(A)
    expect(await resolveLabel(h, 'carol', { fetch: f.fetch, now: () => T + 5000 })).toBe(C)
    expect(f.calls).toHaveLength(2)
    expect(await resolveLabel(h, 'zed', { fetch: f.fetch, now: () => T + 6000 })).toBeUndefined()
    expect(f.calls).toHaveLength(3)
  })

  it('does not ask again for a miss in a list fetched just now', async () => {
    const f = instance(ok([agent('alice', A)]))
    expect(await resolveLabel(home(), 'zed', { fetch: f.fetch })).toBeUndefined()
    expect(f.calls).toHaveLength(1)
  })

  it('refuses a label two agents hold, naming both addresses', async () => {
    const f = instance(ok([agent('ops', A), agent('OPS', B)]))
    const e = await refusal(resolveLabel(home(), 'ops', { fetch: f.fetch }))
    expect(e.code).toBe('ambiguous-label')
    expect(e.message).toContain(A)
    expect(e.message).toContain(B)
  })

  it('refuses what is not a label, before any call', async () => {
    for (const bad of ['', '-ops', 'a b', 'x'.repeat(65), A, 'ops/1']) {
      const f = instance()
      expect((await refusal(resolveLabel(home(), bad, { fetch: f.fetch }))).code).toBe('usage')
      expect(f.calls).toHaveLength(0)
    }
    const f = instance(ok([agent('a.b_c-9', A)]))
    expect(await resolveLabel(home(), 'A.B_C-9', { fetch: f.fetch })).toBe(A)
    const long = instance(ok([agent('x'.repeat(64), B)]))
    expect(await resolveLabel(home(), 'X'.repeat(64), { fetch: long.fetch })).toBe(B)
  })
})

describe('directory: one copy per organisation', () => {
  it("keeps each profile's list in its own profile, so one organisation's copy never answers for another", async () => {
    const h = home()
    home('https://bag.walk2.example', C, 'walk2.example', h)
    const acme = instance(ok([agent('alice', A)]))
    expect(await resolveLabel(h, 'alice', { fetch: acme.fetch, now: () => T, org: 'acme.example' })).toBe(A)
    // walk2's list is asked of walk2's instance, under a minute after acme's copy was kept, and has no alice.
    const walk2 = instance(ok([agent('bob', B)]), ok([agent('bob', B)]))
    expect(
      await resolveLabel(h, 'alice', { fetch: walk2.fetch, now: () => T, org: 'walk2.example' }),
    ).toBeUndefined()
    expect(walk2.calls[0]?.url).toBe(`https://bag.walk2.example${DIRECTORY_PATH}`)
    expect(
      await resolveLabel(h, 'alice', { fetch: instance().fetch, now: () => T, org: 'acme.example' }),
    ).toBe(A)
    expect(JSON.parse(readFileSync(directoryPath(h, 'walk2.example'), 'utf8')).agents).toEqual([
      agent('bob', B),
    ])
    expect(statSync(directoryPath(h, 'walk2.example')).mode & 0o777).toBe(0o600)
    expect(directoryPath(h, 'acme.example')).toBe(
      join(h, 'orgs', 'acme.example', 'enterprise', 'directory.json'),
    )
  })
})

describe("resolveHandle: an own-organisation handle through its profile's directory", () => {
  it('resolves <label>@<domain> of a profile with a session, in that profile, and undefined on a miss', async () => {
    const h = home()
    home('https://bag.walk2.example', C, 'walk2.example', h)
    const f = instance(ok([agent('Alice', A)]), ok([agent('Alice', A)]))
    expect(await resolveHandle(h, 'alice@walk2.example', { fetch: f.fetch, now: () => T })).toBe(A)
    expect(f.calls[0]?.url).toBe(`https://bag.walk2.example${DIRECTORY_PATH}`)
    expect(await resolveHandle(h, 'bob@walk2.example', { fetch: f.fetch, now: () => T })).toBeUndefined()
  })

  it('never asks for a non-handle, another domain, or a profile with no session (a pending sign-in)', async () => {
    const h = home()
    mkdirSync(enterpriseDir(profileHome(h, 'wait.example')), { recursive: true, mode: 0o700 })
    writeJson(join(enterpriseDir(profileHome(h, 'wait.example')), 'pending.json'), { v: 1 })
    const f = instance()
    for (const to of ['alice', A, 'alice@partner.example', 'alice@wait.example']) {
      expect(await resolveHandle(h, to, { fetch: f.fetch, now: () => T })).toBeUndefined()
    }
    expect(f.calls).toHaveLength(0)
  })

  it('falls back with one line when the directory cannot answer, and keeps two agents under one label an error', async () => {
    const h = home()
    const lines: string[] = []
    const down = instance(new Error('connect ECONNREFUSED'))
    const o = { fetch: down.fetch, now: () => T, warn: (l: string) => lines.push(l) }
    expect(await resolveHandle(h, 'alice@acme.example', o)).toBeUndefined()
    expect(lines).toEqual([
      'bag: the directory of acme.example did not resolve alice@acme.example (' +
        `unreachable: ${ORIGIN} did not answer: connect ECONNREFUSED); using its handle record`,
    ])
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    try {
      expect(await resolveHandle(h, 'alice@acme.example', { fetch: instance(new Error('x')).fetch })).toBe(
        undefined,
      )
      expect(String(write.mock.calls[0]?.[0])).toMatch(
        /^bag: the directory of acme\.example did not resolve /,
      )
    } finally {
      write.mockRestore()
    }
    const two = instance(ok([agent('ops', A), agent('OPS', B)]))
    const e = await refusal(resolveHandle(h, 'ops@acme.example', { fetch: two.fetch, now: () => T }))
    expect(e.code).toBe('ambiguous-label')
  })
})
