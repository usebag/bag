import { readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { serializeRecord, signRecord } from '@usebag/core'
import { connectCodeOf, readSession } from '@usebag/enterprise-client'
import { FakeInstance } from '@usebag/enterprise-client/testing'
import { afterAll, describe, expect, it } from 'vitest'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// send and inbox after `bag connect`, with no flag the session knows: the relay, the sender, the chain and the trust
// root come from the live enterprise session. Run as command lines against the recorded fake of an instance on this
// machine (its relay on loopback, no DNS record for its domain) and the memory relay. Each step is its own test, so
// the reporter's per-test time is the command's product time.

const tmp = tempDir('send-inbox-session')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const RELAY = 'http://127.0.0.1:47713'
const SECRET = 'cli-test-secret-only-for-these-tests-000000'

interface World {
  readonly io: TestIo
  readonly fake: FakeInstance
  readonly relay: MemoryRelay
  readonly dir: string
}

/** A home connected to acme.example: the agent's records published at the organisation's one relay, RELAY. */
async function connected(label: string): Promise<World> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const fake = new FakeInstance({ domain: DOMAIN, origin: 'http://127.0.0.1:8788', now: () => io.time.now })
  ;(fake.relays as string[]).splice(0, 1, RELAY)
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  const net = { txt: async () => [], get: async () => ({ status: 404, body: null }) }
  Object.assign(io, {
    fetch: fake.fetch,
    enterpriseNet: { ...net, guard: { connectTo: async () => '127.0.0.1' } },
    enterpriseRelays: relay,
  })
  Object.assign(io.env, { BAG_ORG_CODE: code })
  // A root trusted by key that delegates keeps its record at its recipients' relays (spec/SPEC.md §9 item 5): the
  // organisation's, at its relay, where the receiver reads its revoked list.
  const org = { kind: 'address', key: fake.root.address, sealing_key: null, relays: [RELAY] } as const
  const record = {
    ...org,
    rotation_key: null,
    revoked: [],
    ttl: 86_400,
    iat: io.time.now,
    rotated_from: null,
  }
  await relay.publish(RELAY, serializeRecord(signRecord(fake.root, record)))
  const dir = join(tmp.dir, label)
  expect((await cli(io, 'connect', '--label', label, '--dir', dir)).out.at(-1)).toMatch(
    `Connected as ${label}`,
  )
  return { io, fake, relay, dir }
}

describe('send and inbox with the defaults of a live enterprise session', () => {
  let w: World
  let agent: string
  let root: string
  let sent: string

  it('connects (the setup of the next tests)', async () => {
    w = await connected('build-box')
    const s = readSession(w.dir)
    ;[agent, root] = [s?.agent_address as string, s?.org.root as string]
    expect(s?.org.relays).toEqual([RELAY])
    // The organisation's own root as GET /agent/trust grants it: a domain root, which has no DNS record here.
    expect(Object.keys(JSON.parse(readFileSync(join(w.dir, 'trust.json'), 'utf8')).roots)).toEqual([
      `domain:${DOMAIN}`,
    ])
    expect((await cli(w.io, 'name', 'add', 'peer', agent, '--dir', w.dir)).code).toBe(0)
  })

  it('bag send --to <name> --type <type> --body <json>: signed by the session key under the chain, at the relay', async () => {
    const r = await cli(w.io, 'send', '--to', 'peer', '--type', 'note', '--body', '{"hi":1}', '--dir', w.dir)
    expect(r.err).toEqual([])
    expect(r).toMatchObject({ code: 0, out: [expect.any(String), `published ${RELAY} tries=1`] })
    sent = r.out[0] as string
    const env = JSON.parse(new TextDecoder().decode(w.relay.envelopes.get(sent)))
    const s = readSession(w.dir)
    expect([env.from, env.to, env.auth.map((h: { iss: string }) => h.iss)]).toEqual([
      s?.session_address,
      [agent],
      [root, agent],
    ])
  })

  it("bag inbox --once: the agent's mailbox at every relay, trusting the organisation's root address", async () => {
    const r = await cli(w.io, 'inbox', '--once', '--dir', w.dir)
    const from = readSession(w.dir)?.session_address
    expect(r).toEqual({ code: 0, out: [`accept ${sent} ${from} ${root} note {"hi":1}`], err: [] })
    expect(w.io.wellKnown.size + w.io.txt.size).toBe(0)
  })

  it('--trust-root <the session domain> reads as the root address: no DNS, the message accepted', async () => {
    const again = await cli(w.io, 'send', '--to', agent, '--type', 'note', '--body', '2', '--dir', w.dir)
    const r = await cli(w.io, 'inbox', '--once', '--trust-root', DOMAIN, '--dir', w.dir)
    expect(r.out).toEqual([expect.stringMatching(new RegExp(`^accept ${again.out[0]} .* ${root} note 2$`))])
  })

  it('--type defaults to chat.v1; a --type given wins', async () => {
    const plain = await cli(w.io, 'send', '--to', agent, '--body', '{"n":1}', '--dir', w.dir)
    const typed = await cli(
      w.io,
      'send',
      '--to',
      agent,
      '--type',
      'task.v2',
      '--body',
      '{"n":2}',
      '--dir',
      w.dir,
    )
    expect([plain.code, typed.code]).toEqual([0, 0])
    const r = await cli(w.io, 'inbox', '--once', '--dir', w.dir)
    expect(r.out).toEqual([
      expect.stringMatching(new RegExp(`^accept ${plain.out[0]} .* chat\\.v1 \\{"n":1\\}$`)),
      expect.stringMatching(new RegExp(`^accept ${typed.out[0]} .* task\\.v2 \\{"n":2\\}$`)),
    ])
  })

  it('--body @- reads the JSON on stdin and --body @<path> a regular file, each at most the envelope cap', async () => {
    const text = 'it\'s "quoted" $(not run) `here`'
    Object.assign(w.io, { readAll: async () => JSON.stringify({ text }) })
    const piped = await cli(w.io, 'send', '--to', agent, '--body', '@-', '--dir', w.dir)
    const file = join(w.dir, 'body.json')
    writeFileSync(file, '{"from":"file"}')
    const filed = await cli(w.io, 'send', '--to', agent, '--body', `@${file}`, '--dir', w.dir)
    expect([piped.code, filed.code]).toEqual([0, 0])
    const r = await cli(w.io, 'inbox', '--once', '--dir', w.dir)
    expect(r.out).toHaveLength(2)
    expect(r.out[0]).toMatch(new RegExp(`^accept ${piped.out[0]} .* chat\\.v1 `))
    expect(r.out[0]?.endsWith(` ${JSON.stringify({ text })}`)).toBe(true)
    expect(r.out[1]).toMatch(new RegExp(`^accept ${filed.out[0]} .* chat\\.v1 \\{"from":"file"\\}$`))
    // Over the cap, on stdin or in a file; a symbolic link; text that is not JSON.
    Object.assign(w.io, { readAll: async () => null })
    const big = await cli(w.io, 'send', '--to', agent, '--body', '@-', '--dir', w.dir)
    expect(big.err[0]).toBe('bag: body-too-large: --body @-: over 65536 bytes, the envelope cap')
    const large = join(w.dir, 'large.json')
    writeFileSync(large, JSON.stringify({ t: 'x'.repeat(65_536) }))
    expect((await cli(w.io, 'send', '--to', agent, '--body', `@${large}`, '--dir', w.dir)).err[0]).toMatch(
      /^bag: body-too-large: /,
    )
    const link = join(w.dir, 'link.json')
    symlinkSync(file, link)
    expect((await cli(w.io, 'send', '--to', agent, '--body', `@${link}`, '--dir', w.dir)).err[0]).toMatch(
      /^bag: ELOOP: /,
    )
    Object.assign(w.io, { readAll: async () => 'not json' })
    expect((await cli(w.io, 'send', '--to', agent, '--body', '@-', '--dir', w.dir)).err[0]).toBe(
      'bag: usage: --body is not JSON',
    )
  })

  it('explicit flags win: another --as needs its own --relay; a --relay given is the one used', async () => {
    const send = (...more: string[]) =>
      cli(w.io, 'send', '--to', agent, '--type', 'n', '--body', '1', '--dir', w.dir, ...more)
    expect((await send('--as', 'other')).err[0]).toBe('bag: usage: --relay is required')
    // The recipient's relay, on loopback, is not the --relay given, so the private-address guard refuses it.
    const elsewhere = await send('--relay', 'http://127.0.0.1:1')
    expect([elsewhere.code, elsewhere.err[0]]).toEqual([1, expect.stringMatching(/^bag: resolve-failed: /)])
    w.relay.published.splice(0)
    expect((await send('--relay', 'http://127.0.0.1:1', '--allow-private-relays')).code).toBe(0)
    expect(w.relay.published).toEqual([RELAY])
  })

  it("--to <label>: a name the book lacks is the organisation's agent of that label, from its directory", async () => {
    const asked: string[] = []
    const fake = w.io.fetch as (url: string, init: RequestInit) => Promise<Response>
    Object.assign(w.io, {
      fetch: async (url: string, init: RequestInit) => {
        if (!url.endsWith('/api/v1/agent/directory')) return fake(url, init)
        asked.push(new Headers(init.headers).get('authorization')?.split(' ')[0] ?? '')
        const agents = [{ label: 'Peer-Box', address: agent, connectedAt: '2026-11-07T04:00:00Z' }]
        return Response.json({ agents, etag: 'e1' })
      },
    })
    const r = await cli(w.io, 'send', '--to', 'peer-box', '--type', 'note', '--body', '3', '--dir', w.dir)
    expect([r.code, r.out[1], asked]).toEqual([0, `published ${RELAY} tries=1`, ['Bearer']])
    expect(JSON.parse(new TextDecoder().decode(w.relay.envelopes.get(r.out[0] as string))).to).toEqual([
      agent,
    ])
    // A label the directory lacks is the name book's miss, as before.
    const none = await cli(w.io, 'send', '--to', 'nobody', '--type', 'note', '--body', '3', '--dir', w.dir)
    expect(none.err[0]).toMatch(/^bag: name-unknown: no name "nobody" in /)
  })

  it('a session that is not live fills in nothing, and the usage line says why', async () => {
    w.io.time.now += 30 * 86_400
    const r = await cli(w.io, 'inbox', '--once', '--dir', w.dir)
    expect(r.code).toBe(1)
    expect(r.err[0]).toMatch(
      /^bag: usage: --as is required \(the enterprise session of acme\.example is .*: bag status\)$/,
    )
  })
})

describe('send and inbox with two organisations in the home', () => {
  const RELAY2 = 'http://127.0.0.1:47714'
  let w: World
  let acmeAgent: string
  let walkAgent: string

  it('connects acme.example, then walk2.example (the setup of the next tests)', async () => {
    w = await connected('two-orgs')
    acmeAgent = readSession(w.dir, DOMAIN)?.agent_address as string
    const other = new FakeInstance({
      domain: 'walk2.example',
      origin: 'http://127.0.0.1:8789',
      now: () => w.io.time.now,
    })
    ;(other.relays as string[]).splice(0, 1, RELAY2)
    const code = connectCodeOf({ instance: other.origin, domain: other.domain }, SECRET)
    other.consoleCodes.add(code)
    const fetch = w.io.fetch as (u: string, i: RequestInit) => Promise<Response>
    Object.assign(w.io, {
      fetch: (u: string, i: RequestInit) => (u.startsWith(other.origin) ? other.fetch(u, i) : fetch(u, i)),
    })
    Object.assign(w.io.env, { BAG_ORG_CODE: code })
    expect((await cli(w.io, 'connect', '--dir', w.dir)).code).toBe(0)
    walkAgent = readSession(w.dir, 'walk2.example')?.agent_address as string
    expect(walkAgent).not.toBe(acmeAgent)
  })

  it('send with no --org: the most recently connected, named on stderr with the other', async () => {
    const r = await cli(w.io, 'send', '--to', walkAgent, '--type', 'note', '--body', '1', '--dir', w.dir)
    expect([r.code, r.out[1], r.err]).toEqual([
      0,
      `published ${RELAY2} tries=1`,
      ['bag: using walk2.example, the most recently connected; also signed in to acme.example (--org)'],
    ])
  })

  it('inbox --once with no --org reads that organisation, named on stderr', async () => {
    const r = await cli(w.io, 'inbox', '--once', '--dir', w.dir)
    expect(r.out).toEqual([
      expect.stringMatching(/^accept [0-9a-f]{64} ed25519:[0-9a-f]{64} ed25519:[0-9a-f]{64} note 1$/),
    ])
    expect(r.err).toEqual([
      'bag: using walk2.example, the most recently connected; also signed in to acme.example (--org)',
    ])
  })

  it("send and inbox --once --org acme.example: that organisation's sender, relay and mailbox, no line", async () => {
    const sent = await cli(
      w.io,
      'send',
      '--org',
      DOMAIN,
      '--to',
      acmeAgent,
      '--type',
      'note',
      '--body',
      '2',
      '--dir',
      w.dir,
    )
    expect([sent.code, sent.out[1], sent.err]).toEqual([0, `published ${RELAY} tries=1`, []])
    const r = await cli(w.io, 'inbox', '--once', '--org', DOMAIN, '--dir', w.dir)
    expect([r.out, r.err]).toEqual([
      [expect.stringMatching(new RegExp(`^accept ${sent.out[0]} .* note 2$`))],
      [],
    ])
  })
})
