import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { checkChainShape, verifyChain } from '@usebag/core'
import { generateEdgeKeys, HomeCustody } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { expiry } from '../src/commands/delegate.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('delegate')
afterAll(() => tmp.cleanup())
let n = 0

interface Home {
  readonly io: TestIo
  readonly dir: string
  readonly addresses: Record<string, string>
  delegate(...args: string[]): ReturnType<typeof cli>
  chain(file: string): ReturnType<typeof checkChainShape>
}

async function home(...names: string[]): Promise<Home> {
  const io = testIo(new MemoryRelay())
  const dir = join(tmp.dir, `home-${n++}`)
  const addresses: Record<string, string> = {}
  for (const name of names) addresses[name] = (await cli(io, 'keygen', name, '--dir', dir)).out[0] as string
  return {
    io,
    dir,
    addresses,
    delegate: (...args) => cli(io, 'delegate', ...args, '--dir', dir),
    chain: (file) => checkChainShape(JSON.parse(readFileSync(file, 'utf8'))),
  }
}

/** The hex of every private key in a home, to prove that no output holds one. */
function secrets(h: Home): string[] {
  return Object.keys(h.addresses).flatMap((name) => {
    const f = JSON.parse(readFileSync(join(h.dir, 'keys', `${name}.json`), 'utf8')) as Record<string, string>
    return [f.sign_seed as string, f.seal_priv as string]
  })
}

describe('delegate: one signed hop from an identity to an address, written as a chain file', () => {
  it('signs the hop with its caveats and expiry, writes the chain, and prints the subject and the effective caveats, never a key', async () => {
    const h = await home('alice', 'session')
    const { alice, session } = h.addresses as { alice: string; session: string }
    const out = join(h.dir, 'session.chain.json')
    const made = await h.delegate(
      '--from',
      'alice',
      '--to',
      session,
      '--caveat',
      'type=chat.v1',
      '--caveat',
      'repo=bag',
      '--exp',
      '+600',
      '--out',
      out,
    )
    expect(made).toEqual({
      code: 0,
      out: [session, `root ${alice} hops 1 exp ${T0 + 600} caveats ["type=chat.v1","repo=bag"]`],
      err: [],
    })
    const text = readFileSync(out, 'utf8')
    expect(text.endsWith(']\n') && text.split('\n')).toHaveLength(2)
    const chain = h.chain(out)
    expect(Object.keys(chain[0] as object)).toEqual(['iss', 'sub', 'caveats', 'exp', 'sig'])
    expect(verifyChain(chain, session, T0 + 600)).toEqual({
      root: alice,
      principal: alice,
      caveats: ['type=chat.v1', 'repo=bag'],
    })
    const printed = [...h.io.stdout, ...h.io.stderr, text].join('\n')
    expect(secrets(h).every((s) => !printed.includes(s))).toBe(true)
  })

  it('appends to a chain: the issuer must be its last subject, the expiry no later than its last, and not past', async () => {
    const h = await home('org', 'alice', 'bob', 'session')
    const { org, alice, session } = h.addresses as { org: string; alice: string; session: string }
    const first = join(h.dir, 'alice.chain.json')
    const both = join(h.dir, 'session.chain.json')
    const at = String(T0 + 3600)
    await h.delegate('--from', 'org', '--to', alice, '--caveat', 'type=coding.*', '--exp', at, '--out', first)
    const appended = await h.delegate(
      '--from',
      'alice',
      '--to',
      session,
      '--caveat',
      'repo=bag',
      '--exp',
      '+60',
      '--chain',
      first,
      '--out',
      both,
    )
    expect(appended.out).toEqual([
      session,
      `root ${org} hops 2 exp ${T0 + 60} caveats ["type=coding.*","repo=bag"]`,
    ])
    expect(verifyChain(h.chain(both), session, T0)).toMatchObject({ root: org, principal: alice })
    const wrong = await h.delegate(
      '--from',
      'bob',
      '--to',
      session,
      '--caveat',
      'repo=x',
      '--exp',
      '+60',
      '--chain',
      first,
      '--out',
      both,
    )
    expect(wrong.err).toEqual(["bag: chain-broken: hop 0's sub is not hop 1's iss"])
    const later = await h.delegate(
      '--from',
      'alice',
      '--to',
      session,
      '--caveat',
      'repo=x',
      '--exp',
      '+7200',
      '--chain',
      first,
      '--out',
      both,
    )
    expect(later.err).toEqual(['bag: exp-not-monotone: hop 1 expires after hop 0'])
    const past = await h.delegate(
      '--from',
      'alice',
      '--to',
      session,
      '--caveat',
      'repo=x',
      '--exp',
      String(T0 - 1),
      '--out',
      both,
    )
    expect(past.err).toEqual(['bag: hop-expired: hop 0 expired before ts'])
    expect(verifyChain(h.chain(both), session, T0).root).toBe(org)
  })

  it('refuses a subject that is not an address, an expiry it cannot read, and a chain file that is not a chain', async () => {
    const h = await home('alice')
    const out = join(h.dir, 'x.chain.json')
    const me = h.addresses.alice as string
    const run = async (...args: string[]) =>
      (await h.delegate('--from', 'alice', '--caveat', 'repo=x', ...args)).err[0]
    expect(await run('--to', 'bob', '--exp', '+60', '--out', out)).toBe('bag: bad-address: --to "bob"')
    expect(await run('--to', me, '--exp', 'soon', '--out', out)).toBe(
      'bag: usage: --exp is <unix seconds> or +<seconds>, not "soon"',
    )
    expect(await run('--to', me, '--exp', '+60')).toBe('bag: usage: --out is required')
    expect(await run('--to', me, '--exp', '+60', '--caveat', '', '--out', out)).toBe(
      'bag: bad-hop: hop 0 is not well-formed',
    )
    expect(await run('--to', me, '--exp', '+60', '--caveat', 'x'.repeat(257), '--out', out)).toBe(
      'bag: caveat-too-long: hop 0 has a caveat over 256 bytes',
    )
    writeFileSync(out, 'not json')
    expect(await run('--to', me, '--exp', '+60', '--chain', out, '--out', out)).toBe(
      `bag: bad-json: ${out} is not JSON`,
    )
    writeFileSync(out, '{"auth":[]}')
    expect(await run('--to', me, '--exp', '+60', '--chain', out, '--out', out)).toBe(
      'bag: bad-shape: auth is a list of hops',
    )
    expect(
      await run('--to', me, '--exp', '+60', '--chain', join(h.dir, 'missing.json'), '--out', out),
    ).toMatch(/^bag: ENOENT: /)
    expect(await run('--to', me, '--exp', '+60', '--out', join(h.dir, 'no', 'such', 'dir.json'))).toMatch(
      /^bag: ENOENT: /,
    )
    expect(await run('--to', me, '--exp', '+60', '--out', out, '--dir')).toMatch(/^bag: usage: /)
    expect(readFileSync(out, 'utf8')).toBe('{"auth":[]}')
  })
})

describe('delegate: at most 32 caveats of 256 bytes (the core), and never from an identity the agent holds', () => {
  it('takes 32 caveats of 256 bytes and refuses a 33rd and a 257th byte, by multi-byte characters too', async () => {
    const h = await home('alice', 'session')
    const to = h.addresses.session as string
    const run = async (caveats: string[]) => {
      const flags = caveats.flatMap((c) => ['--caveat', c])
      const out = join(h.dir, 'c.json')
      const ran = await h.delegate('--from', 'alice', '--to', to, ...flags, '--exp', '+60', '--out', out)
      return ran.err[0]
    }
    expect(await run(Array.from({ length: 32 }, (_, i) => `k${i}=v`))).toBeUndefined()
    expect(await run(['x'.repeat(256)])).toBeUndefined()
    expect(await run(['\u00e9'.repeat(128)])).toBeUndefined()
    expect(await run(Array.from({ length: 33 }, (_, i) => `k${i}=v`))).toBe(
      'bag: too-many-caveats: hop 0 has 33 caveats; the cap is 32',
    )
    expect(await run(['\u00e9'.repeat(128), '\u00e9'.repeat(129)])).toBe(
      'bag: caveat-too-long: hop 0 has a caveat over 256 bytes',
    )
  })

  it('refuses an identity the agent holds as not-authorized, with no chain written: the agent signs a session hop only', async () => {
    const h = await home('session')
    new HomeCustody(h.dir).agent.create('principal', generateEdgeKeys(h.io.rng))
    const out = join(h.dir, 'agent.chain.json')
    const refused = await h.delegate(
      '--from',
      'principal',
      '--to',
      h.addresses.session as string,
      '--caveat',
      'repo=x',
      '--exp',
      '+60',
      '--out',
      out,
    )
    expect([refused.code, refused.out, refused.err]).toEqual([
      1,
      [],
      ["bag: not-authorized: principal is held by the agent, which signs a session's hops only"],
    ])
    expect(existsSync(out)).toBe(false)
  })
})

describe('expiry: --exp as Unix seconds or +seconds from now', () => {
  it('reads both forms and refuses everything else', () => {
    expect([expiry('+1', 100), expiry('1800000000', 100), expiry('+86400', T0)]).toEqual([
      101,
      1_800_000_000,
      T0 + 86_400,
    ])
    for (const bad of ['', '+', '0', '+0', '-5', '1.5', '+1e3', ' 7', '07', '9007199254740993', 'never']) {
      expect(() => expiry(bad, T0), bad).toThrow(
        `usage: --exp is <unix seconds> or +<seconds>, not ${JSON.stringify(bad)}`,
      )
    }
  })
})
