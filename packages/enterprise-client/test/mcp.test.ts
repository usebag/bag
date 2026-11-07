import { mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterAll, describe, expect, it } from 'vitest'
import { connectCodeOf } from '../src/connect-code.ts'
import { createMcpServer, MCP_TOOLS, serveMcp } from '../src/mcp.ts'
import { type EnterprisePorts, VERSION } from '../src/ports.ts'
import { readSession } from '../src/session.ts'
import { FakeInstance } from './support/fake-instance.ts'
import { FakeRelay } from './support/fake-relay.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// The MCP server through an MCP client (the SDK's own, over its in-memory transport) against the recorded fake
// instance: the three tools and no other, connect through the real flow, status's public facts, a bad code's reason, and
// no secret in any tool result (the code, its secret part, the token, a key seed).

const tmp = tempDir('mcp')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const SECRET = 'connect-test-secret-only-for-these-tests-00'
let n = 0
const ROUND_TRIP = /^Connected as acme-example-1; relay round trip \d+ ms$/

async function setup(guard: () => Promise<string | null> = async () => '192.0.2.10') {
  const time = { now: T0 }
  const fake = new FakeInstance({ domain: DOMAIN, now: () => time.now })
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  const home = join(tmp.dir, `home-${n++}`)
  const ports: EnterprisePorts = {
    env: {},
    clock: { now: () => time.now },
    rng: seededRng(`mcp-${n}`),
    fetch: fake.fetch,
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => guard() },
    },
    sleep: async () => {},
    relays: new FakeRelay(),
  }
  const [a, b] = InMemoryTransport.createLinkedPair()
  await createMcpServer(ports, home).connect(a)
  const client = new Client({ name: 'test', version: '0' })
  await client.connect(b)
  const said: string[] = []
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as {
      content: { type: string; text: string }[]
      isError?: boolean
    }
    const text = r.content.map((c) => c.text).join('\n')
    said.push(text)
    return { text, isError: r.isError === true }
  }
  return { fake, code, home, client, call, said, ports, time }
}

function secrets(w: Awaited<ReturnType<typeof setup>>): string[] {
  const keys = join(w.home, 'keys')
  const seeds = readdirSync(keys).map(
    (f) => JSON.parse(readFileSync(join(keys, f), 'utf8')).sign_seed as string,
  )
  return [w.code, SECRET, w.fake.row().token, ...seeds]
}

describe('the MCP server', () => {
  it('offers connect, sign_in and status, and nothing else', async () => {
    const w = await setup()
    const { tools } = await w.client.listTools()
    expect(tools.map((t) => t.name)).toEqual(['connect', 'sign_in', 'status'])
    expect(tools[1]?.inputSchema.required).toEqual(['domain', 'instance'])
    expect(tools[0]?.inputSchema.required).toEqual(['code'])
    expect(MCP_TOOLS).toHaveLength(3)
  })

  it('connect takes the pasted code and answers the public lines; status the session; no secret in any result', async () => {
    const w = await setup()
    const before = await w.call('status')
    expect(before).toEqual({
      text: 'signed-out: not signed in: bag sign-in <domain>',
      isError: true,
    })
    const r = await w.call('connect', { code: `  ${w.code}\n` })
    expect(r.isError).toBe(false)
    expect(r.text.split('\n')).toEqual([expect.stringMatching(ROUND_TRIP)])
    expect(w.fake.calls[0]?.path).toBe('/agent/redeem')
    expect(w.fake.calls[0]?.body?.code).toBe(w.code)
    expect(readSession(w.home)?.instance).toBe('https://ent.example.test')
    const s = await w.call('status')
    expect(s.isError).toBe(false)
    expect(s.text.split('\n')[0]).toMatch(/^signed-in acme\.example agent ed25519:[0-9a-f]{64} state live$/)
    expect(s.text.split('\n').at(-1)).toMatch(ROUND_TRIP)
    const again = await w.call('connect', { code: w.code })
    expect(again.text.split('\n')).toEqual([expect.stringMatching(ROUND_TRIP)])
    for (const text of w.said) for (const secret of secrets(w)) expect(text).not.toContain(secret)
  })

  it("a bad code answers its reason, never the code; a refused one the instance's word; no code is usage", async () => {
    const w = await setup()
    const cut = w.code.slice(0, -1)
    const bad = await w.call('connect', { code: cut })
    expect(bad).toEqual({
      text: 'usage: this is not a connect code from the console: it is cut short or changed',
      isError: true,
    })
    expect(bad.text).not.toContain(cut.slice(-20))
    expect(await w.call('connect', { code: '' })).toEqual({
      text: 'usage: no code: paste the code from the console',
      isError: true,
    })
    w.fake.consoleCodes.clear()
    const used = await w.call('connect', { code: w.code })
    expect(used.isError).toBe(true)
    expect(used.text).toMatch(/^invalid_grant: /)
    expect(used.text).not.toContain(w.code)
    expect(used.text).not.toContain(SECRET)
    expect(w.fake.calls.every((c) => c.path === '/agent/redeem')).toBe(true)
  })

  it('sign_in: the approval link and fingerprint, waiting until a person approves, then Connected as <label>', async () => {
    const w = await setup()
    const args = { domain: 'acme.example', instance: 'https://ent.example.test' }
    const first = await w.call('sign_in', args)
    expect(first.isError).toBe(false)
    expect(first.text.split('\n')).toEqual([
      'Signing in to acme.example at https://ent.example.test',
      'open https://id.example.test/auth/agent and enter the code BCDF-GGG0',
      expect.stringMatching(
        /^fingerprint [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} \(the agent's key, as that page shows it\)$/,
      ),
      'approve only a code you started yourself',
      'Waiting for a person to approve it; ask again to see the state',
    ])
    const pending = join(w.home, 'orgs', 'acme.example', 'enterprise', 'pending.json')
    const deviceCode = JSON.parse(readFileSync(pending, 'utf8')).device_code as string
    const still = await w.call('sign_in', args)
    expect(still.text.split('\n').at(-1)).toBe(
      'Waiting for a person to approve it; ask again to see the state',
    )
    w.fake.approve('BCDF-GGG0')
    // The instance's label for the agent, not its key name: the grant's label is the one said.
    w.fake.byUser('BCDF-GGG0').label = 'acme-example-3'
    const done = await w.call('sign_in', args)
    expect(done.isError).toBe(false)
    expect(done.text.split('\n').at(-1)).toBe('Connected as acme-example-3')
    expect(w.fake.calls.map((c) => c.path)).toContain('/agent/code')
    expect((await w.call('status')).text.split('\n')[0]).toMatch(/state live$/)
    for (const text of w.said)
      for (const secret of [deviceCode, w.fake.row().token, ...secrets(w).slice(2)])
        expect(text).not.toContain(secret)
  })

  it('sign_in: refused when the person denies; a bad instance or domain is usage; the guard stops before any call', async () => {
    const w = await setup()
    const args = { domain: 'acme.example', instance: 'https://ent.example.test' }
    await w.call('sign_in', args)
    w.fake.deny('BCDF-GGG0')
    const refused = await w.call('sign_in', args)
    expect(refused.isError).toBe(true)
    expect(refused.text.split('\n').at(-1)).toMatch(/^access_denied: /)
    for (const [domain, instance, why] of [
      ['acme.example', 'http://ent.example.test', /^usage: the instance is the console origin/],
      ['acme.example', 'https://ent.example.test/path', /^usage: the instance is the console origin/],
      ['Not A Domain', 'https://ent.example.test', /^usage: the domain is/],
    ] as const) {
      const r = await w.call('sign_in', { domain, instance })
      expect([r.isError, r.text], instance).toEqual([true, expect.stringMatching(why)])
    }
    const { GuardRefused } = await import('@usebag/edge')
    const g = await setup(async () => {
      throw new GuardRefused({ range: 'private', detail: 'resolves to a private address' })
    })
    const r = await g.call('sign_in', args)
    expect([r.isError, r.text]).toEqual([true, expect.stringMatching(/^resolve-failed: https:\/\/ent/)])
    expect(g.fake.calls).toEqual([])
  })

  it("sign_in: approved before the organisation's signer signs; a session no longer live says so", async () => {
    const w = await setup()
    const args = { domain: 'acme.example', instance: 'https://ent.example.test' }
    w.fake.signer = false
    await w.call('sign_in', args)
    w.fake.approve('BCDF-GGG0')
    const approved = await w.call('sign_in', args)
    expect([approved.isError, approved.text.split('\n').at(-1)]).toEqual([
      false,
      "Approved; waiting for the organisation's signer: ask again in a minute",
    ])
    w.fake.signer = true
    w.fake.row().state = 'frozen'
    w.time.now += 13 * 3600
    expect((await w.call('status')).text).toContain('state frozen (agent_frozen)')
    const frozen = await w.call('sign_in', args)
    expect([frozen.isError, frozen.text.split('\n').at(-1)]).toEqual([
      false,
      'Not connected: the session is frozen (agent_frozen)',
    ])
    for (const text of w.said)
      for (const secret of [w.fake.row().token, ...secrets(w).slice(2)]) expect(text).not.toContain(secret)
  })

  it('sign_in: a pending file that is not one is refused, and its scrub reads nothing from it', async () => {
    const w = await setup()
    mkdirSync(join(w.home, 'enterprise'), { recursive: true, mode: 0o700 })
    writeFileSync(join(w.home, 'enterprise', 'pending.json'), '{', { mode: 0o600 })
    const r = await w.call('sign_in', { domain: 'acme.example', instance: 'https://ent.example.test' })
    expect(r.isError).toBe(true)
    expect(r.text.split('\n').at(-1)).toMatch(/^session-invalid: /)
    expect(w.fake.calls).toEqual([])
  })

  it("names itself bag at this client's version, and refuses a tool it does not have", async () => {
    const w = await setup()
    expect(w.client.getServerVersion()).toEqual({ name: 'bag', version: VERSION })
    expect(await w.call('verify', {})).toEqual({ text: 'usage: no tool "verify"', isError: true })
  })

  it('a failure with no code of its own is said as error: <message>', async () => {
    const w = await setup()
    // The enterprise directory a symbolic link: secureHome leaves it, and the first write refuses it.
    const elsewhere = `${w.home}-elsewhere`
    mkdirSync(elsewhere, { recursive: true, mode: 0o700 })
    mkdirSync(w.home, { recursive: true, mode: 0o700 })
    symlinkSync(elsewhere, join(w.home, 'enterprise'))
    const r = await w.call('connect', { code: w.code })
    expect(r.isError).toBe(true)
    expect(r.text.split('\n').at(-1)).toMatch(/^error: enterprise: .* is not a directory$/)
    expect(r.text).not.toContain(w.code)
    expect(r.text).not.toContain(SECRET)
  })

  it('serves the tools over a transport until it closes', async () => {
    const w = await setup()
    const [a, b] = InMemoryTransport.createLinkedPair()
    const served = serveMcp(w.ports, w.home, a)
    const client = new Client({ name: 'test', version: '0' })
    await client.connect(b)
    expect((await client.listTools()).tools.map((t) => t.name)).toEqual(['connect', 'sign_in', 'status'])
    await client.close()
    await expect(served).resolves.toBeUndefined()
  })
})
