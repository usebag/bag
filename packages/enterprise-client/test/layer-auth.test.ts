import { readFileSync } from 'node:fs'
import * as core from '@usebag/core'
import { GuardRefused, setTestZone } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { bareOrigin, type DiscoveryNet, discoverInstance } from '../src/discovery.ts'
import { call, EnterpriseError, type Fetch } from '../src/instance.ts'
import {
  AGENT_TAGS,
  bindNonce,
  bindPreimage,
  layerNonce,
  refreshPreimage,
  reportedHash,
  statePreimage,
} from '../src/layer-auth.ts'
import { generationOutcome } from './support/fake-instance.ts'
import { seededRng } from './support/fixtures.ts'

// The layer-auth preimages against test/fixtures/bag-ent-auth.json (the agent contract's tag spec),
// discovery's three steps, and the instance client's reading of a refusal.

const V = JSON.parse(readFileSync(new URL('./fixtures/bag-ent-auth.json', import.meta.url), 'utf8'))
const CONTRACT = JSON.parse(
  readFileSync(new URL('./fixtures/agent-contract-vectors.json', import.meta.url), 'utf8'),
)
type Case = Record<string, unknown> & { name: string }
const build = (kind: string, f: unknown[], relays: core.CanonicalValue[] = []): core.CanonicalValue => {
  const [a, b, c, d, e] = f as [never, never, never, never, never]
  if (kind === 'bind') return bindPreimage(a, b, c, d, e)
  if (kind === 'refresh') return refreshPreimage(a, b, c, d)
  return statePreimage(a, b, c, d, relays as never)
}

describe('test/fixtures/bag-ent-auth.json', () => {
  it('each positive case: the preimage from its fields, its canonical bytes, digest, key and signature, verified strictly', () => {
    for (const c of V.positive.cases as Case[]) {
      const p = c.preimage as core.CanonicalValue[]
      const tag = p[0]
      const again =
        tag === AGENT_TAGS.bind
          ? bindPreimage(p[1] as string, p[2] as string, p[3] as string, p[5] as string, p[6] as number)
          : tag === AGENT_TAGS.refresh
            ? refreshPreimage(p[1] as string, p[2] as number, p[3] as string, p[4] as number)
            : statePreimage(
                p[1] as string,
                p[2] as number,
                p[3] as string,
                p[4] as number,
                c.reported_relays as never,
              )
      expect(again, c.name).toEqual(p)
      expect(core.canonical(p)).toBe(c.canonical)
      expect(core.toHex(core.utf8(c.canonical as string))).toBe(c.canonical_hex)
      expect(core.toHex(core.preimageDigest(p))).toBe(c.sha256)
      const key = core.signingKeyFromSeed(core.fromHex(c.seed_hex as string, 32))
      expect(key.address).toBe(c.address)
      expect(core.signPreimage(key, p)).toBe(c.sig)
      expect(core.verifyPreimage(c.address as string, p, c.sig as string)).toBe(true)
      if (c.reported_hash !== undefined)
        expect(reportedHash(c.reported_relays as never)).toBe(c.reported_hash)
      if (tag === AGENT_TAGS.bind) expect(p[5]).toBe(bindNonce((c.device_code ?? c.code) as string))
    }
    expect(reportedHash([])).toBe(core.sha256hex('[]'))
    // The four vectors the instance's contract pins (test/fixtures/agent-contract-vectors.json, copied as it is).
    for (const c of CONTRACT.bind_nonce as { secret: string; nonce: string }[])
      expect(bindNonce(c.secret)).toBe(c.nonce)
    for (const c of CONTRACT.reported_hash as { reported_relays: never; hash: string }[])
      expect(reportedHash(c.reported_relays)).toBe(c.hash)
    for (const c of V.reported_hash.cases as { reported_relays: never; reported_hash: string }[])
      expect(reportedHash(c.reported_relays)).toBe(c.reported_hash)
    for (const c of V.bind_nonce.cases as { secret: string; bind_nonce: string }[]) {
      expect(bindNonce(c.secret)).toBe(c.bind_nonce)
      expect(core.sha256hex(`bag-ent/bind-nonce/1\n${c.secret}`)).toBe(c.bind_nonce)
    }
  })

  it('each negative signature fails the strict rule, the small-order and S + L cases included', () => {
    const cases = V.negative.cases as Case[]
    expect(cases.filter((c) => c.name.includes('R the identity')).length).toBeGreaterThanOrEqual(4)
    for (const c of cases) {
      expect(
        core.verifyPreimage(c.address as string, c.preimage as core.CanonicalValue, c.sig as string),
        c.name,
      ).toBe(false)
    }
  })

  it('each field case is refused bad-request before any canonical form; a body that differs from its hash is caught', () => {
    for (const c of V.negative.fields as Case[]) {
      expect(
        () => build(c.kind as string, c.fields as unknown[], (c.reported_relays ?? []) as never),
        c.name,
      ).toThrow(/^bad-request: /)
    }
    for (const c of V.negative.state_body as Case[]) {
      expect(reportedHash(c.reported_relays as never)).not.toBe((c.preimage as string[])[5])
    }
    expect(() => bindPreimage('acme.example', 'ed25519:00', 'x', 'a', 1)).toThrow(/bad-request/)
    expect(() => statePreimage('x', 1, 'ab'.repeat(32), 1, [])).toThrow(/bad-request: agent_address/)
    const bad = [{ url: 'ftp://relay', last_subscribed_at: 1 }]
    expect(() => reportedHash(bad)).toThrow(/reported_relays/)
  })

  it('the generation table and the nonce window are the fake instance machine', () => {
    for (const c of V.generation.cases as Case[]) {
      expect(
        generationOutcome(c.G as number, c.grace_until as number, c.now as number, c.generation as number),
        c.name,
      ).toBe(c.outcome)
    }
    for (const c of V.nonce.cases as Case[])
      expect((c.now as number) - (c.seen_at as number) <= 600).toBe(c.refused === 'nonce-seen')
  })

  it('the three tags are disjoint from every SPEC tag and from each other', () => {
    const spec = V.collision.spec_tags as string[]
    expect(spec).toContain('ac/hop/1')
    expect(spec).toContain('ac/pair-open/1')
    const fresh = Object.values(AGENT_TAGS)
    expect(V.collision.new_tags).toEqual(fresh)
    expect(new Set(fresh).size).toBe(3)
    for (const t of fresh) {
      expect(t.startsWith('bag-ent/')).toBe(true)
      expect(spec).not.toContain(t)
    }
    expect(fresh.join()).not.toContain('bagent/')
    expect(layerNonce(seededRng('n'))).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('discovery: the override, no record for a reserved name, the record, then the stand-in', () => {
  const net = (
    status: number,
    body: string | null,
    txt: string[][] = [],
    seen: string[] = [],
  ): DiscoveryNet => ({
    txt: async (name) => {
      seen.push(`txt ${name}`)
      return txt
    },
    get: async (url, connect) => {
      seen.push(`get ${url} ${connect}`)
      return { status, body: body === null ? null : core.utf8(body) }
    },
    guard: { connectTo: async () => '192.0.2.34' },
  })

  it("under the test zone switch reads a mapped domain's record at its loopback origin, and takes a loopback instance", async () => {
    const seen: string[] = []
    const body = '{"v":1,"instance":"http://127.0.0.1:8790"}'
    const domain = 'acme.pilot.bag.dev'
    // Off: the record is fetched through the guard at the TXT origin, and a loopback instance in it is refused.
    await expect(discoverInstance(domain, {}, net(200, body, [], seen))).rejects.toThrow(/is not \{ "v": 1/)
    setTestZone({ file: '/unused', origins: new Map([[domain, 'http://127.0.0.1:8788']]) })
    try {
      expect(await discoverInstance(domain, {}, net(200, body, [], seen))).toBe('http://127.0.0.1:8790')
      await expect(discoverInstance('okok.pilot.bag.dev', {}, net(200, body))).rejects.toThrow(
        /is not \{ "v": 1/,
      )
    } finally {
      setTestZone(null)
    }
    expect(seen).toEqual([
      `txt _bag.${domain}`,
      `get https://${domain}/.well-known/bag/enterprise.json 192.0.2.34`,
      `txt _bag.${domain}`,
      `get http://${domain}:8788/.well-known/bag/enterprise.json 127.0.0.1`,
    ])
  })

  it('takes the record at the TXT origin through the guard, over the stand-in', async () => {
    const seen: string[] = []
    const txt = [[`v=ac1; key=${core.signingKeyFromSeed(new Uint8Array(32).fill(9)).address}; host=bag`]]
    const body = '{"v":1,"instance":"https://ent.acme.example.com"}'
    const env = { BAG_ENTERPRISE_URL: 'http://127.0.0.1:8788' }
    expect(await discoverInstance('acme.example.com', env, net(200, body, txt, seen))).toBe(
      'https://ent.acme.example.com',
    )
    expect(seen).toEqual([
      'txt _bag.acme.example.com',
      'get https://bag.acme.example.com/.well-known/bag/enterprise.json 192.0.2.34',
    ])
  })

  it('the override first, with no record fetched; a 404 falls to the stand-in; a reserved name asks for no record', async () => {
    const seen: string[] = []
    const env = { BAG_ENTERPRISE_INSTANCES: 'a.test=https://a.test, acme.example.com=http://localhost:8788/' }
    expect(await discoverInstance('acme.example.com', env, net(200, '{}', [], seen))).toBe(
      'http://localhost:8788',
    )
    expect(
      await discoverInstance(
        'acme.test',
        { BAG_ENTERPRISE_INSTANCES: 'acme.test=http://127.0.0.1:8788' },
        net(500, null, [], seen),
      ),
    ).toBe('http://127.0.0.1:8788')
    expect(
      await discoverInstance('b.example.net', { BAG_ENTERPRISE_URL: 'http://[::1]:9' }, net(404, null)),
    ).toBe('http://[::1]:9')
    for (const label of [
      'localhost',
      'test',
      'example',
      'invalid',
      'alt',
      'arpa',
      'internal',
      'local',
      'onion',
    ]) {
      expect(
        await discoverInstance(
          `acme.${label}`,
          { BAG_ENTERPRISE_URL: 'https://s.example' },
          net(500, null, [], seen),
        ),
      ).toBe('https://s.example')
      const none = await discoverInstance(`acme.${label}`, {}, net(500, null, [], seen)).catch(
        (x: EnterpriseError) => x,
      )
      expect((none as EnterpriseError).code).toBe('discovery_failed')
    }
    expect(seen).toEqual([])
  })

  it('a failed fetch, another status, a malformed record or a bad origin stops with discovery_failed', async () => {
    const env = { BAG_ENTERPRISE_URL: 'https://fallback.example' }
    const failing: DiscoveryNet = {
      ...net(200, null),
      guard: {
        connectTo: async () => {
          throw new GuardRefused({ range: 'loopback', detail: 'loopback' })
        },
      },
    }
    const bodies = [
      '{"v":2,"instance":"https://x.example"}',
      '{"v":1,"instance":"http://x.example"}',
      '{"v":1,"instance":"https://x.example/path"}',
      '{"v":1,"instance":"https://x.example","x":1}',
      'not json',
    ]
    const cases: [DiscoveryNet, string][] = [
      [failing, 'could not be fetched'],
      [net(500, null), 'answered 500'],
      ...bodies.map((b) => [net(200, b), 'is not'] as [DiscoveryNet, string]),
    ]
    for (const [n, said] of cases) {
      const e = await discoverInstance('acme.example.com', env, n).catch((x: unknown) => x)
      expect(e).toBeInstanceOf(EnterpriseError)
      expect((e as EnterpriseError).code).toBe('discovery_failed')
      expect((e as Error).message).toContain(said)
    }
    const none = await discoverInstance('acme.example.com', {}, net(404, null)).catch(
      (x: EnterpriseError) => x,
    )
    expect((none as EnterpriseError).message).toMatch(/^discovery_failed: no instance for acme.example.com/)
    const http = await discoverInstance(
      'acme.example.com',
      { BAG_ENTERPRISE_URL: 'http://ent.example' },
      net(404, null),
    ).catch((x: EnterpriseError) => x)
    expect((http as EnterpriseError).message).toContain(
      'BAG_ENTERPRISE_URL names no https or loopback origin',
    )
    expect(bareOrigin('not a url', true)).toBeNull()
    expect(bareOrigin('http://127.0.0.1:8788', false)).toBeNull()
  })
})

describe('the instance client', () => {
  const answer =
    (status: number, body: unknown): Fetch =>
    async () =>
      new Response(body === null ? null : JSON.stringify(body), { status })

  it('reads a refusal into its code, reason, server time and exit, and never prints the bearer token', async () => {
    const skew = answer(400, { error: 'clock_skew', error_description: 'ts is 400 s off', server_time: 42 })
    const e = (await call(skew, 'https://i.example', '/agent/refresh', {}).catch((x) => x)) as EnterpriseError
    expect([e.code, e.exit, e.message]).toEqual([
      'clock_skew',
      1,
      'clock_skew: /agent/refresh: ts is 400 s off; server time 42',
    ])
    const bind = answer(400, { error: 'invalid_grant', error_description: 'x', detail: 'bind-replay' })
    expect(
      ((await call(bind, 'https://i.example', '/agent/token', {}).catch((x) => x)) as EnterpriseError).reason,
    ).toBe('bind-replay')
    const exits = {
      agent_revoked: 3,
      stale_generation: 4,
      org_suspended: 4,
      authorization_pending: 4,
      access_denied: 1,
    }
    for (const [code, exit] of Object.entries(exits)) expect(new EnterpriseError(code, 'x').exit).toBe(exit)
    const junk = (await call(
      answer(502, null),
      'https://i.example',
      '/agent/me',
      null,
      'bagagt_secret',
    ).catch((x) => x)) as Error
    expect(junk.message).toBe('http-502: /agent/me: 502')
    const down: Fetch = async () => {
      throw new TypeError('connect ECONNREFUSED')
    }
    const off = (await call(down, 'https://i.example', '/agent/code', {}, 'bagagt_secret').catch(
      (x) => x,
    )) as EnterpriseError
    expect([off.code, off.message.includes('bagagt_secret')]).toEqual(['unreachable', false])
    expect(
      ((await call(undefined, 'https://i.example', '/agent/code', {}).catch((x) => x)) as EnterpriseError)
        .code,
    ).toBe('unreachable')
    expect(await call(answer(204, null), 'https://i.example', '/agent/state', {})).toBeNull()
  })
})
