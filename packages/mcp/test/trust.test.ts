import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { serializeRecord } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { TOOL_NAMES } from '../src/tools.ts'
import { trustFileRoots } from '../src/trust.ts'
import {
  acceptFrom,
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The trust file the CLI's `peer` writes (<home>/trust.json) is read at start and again
// before each frame, so a pairing needs no restart; and, from 2026-10-29, only pair_invite and pair_accept pair, each through a dialog the model
// cannot answer (pairing.test.ts); no other tool is named or described as pairing; nothing in packages/mcp/src imports
// the CLI, and only ./pairing.ts is pairing; and a session that holds an invite string and calls every tool with it, on
// a host that cannot show a dialog, changes no name book, trust file or accept-from record. status counts roots only.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
const servers: TestServer[] = []

beforeEach(() => {
  tmp = tempDir('trust')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

const home = (p: Party): string => join(tmp.dir, p.name)
const trustFile = (p: Party, roots: Record<string, unknown>): void =>
  writeFileSync(join(home(p), 'trust.json'), JSON.stringify({ version: 1, roots }))

async function serverFor(p: Party, args: readonly string[] = []): Promise<TestServer> {
  if (!existsSync(join(home(p), 'keys'))) saveKeys(home(p), p)
  await publishAddress(relay, p)
  const s = await testServer({ home: home(p), name: p.name, relay, clock, timers, args })
  servers.push(s)
  return s
}

describe('trustFileRoots: the reader of the CLI trust file', () => {
  it('reads none without the file, each address as a root, and refuses anything else trust-invalid', () => {
    mkdirSync(home(P.alice), { recursive: true })
    expect(trustFileRoots(home(P.alice))).toEqual([])
    trustFile(P.alice, { [P.bob.address]: { added_at: T0 }, [P.carol.address]: { added_at: 0 } })
    expect(trustFileRoots(home(P.alice))).toEqual([{ address: P.bob.address }, { address: P.carol.address }])
    trustFile(P.alice, { [P.bob.address]: { added_at: T0 }, 'domain:acme.example': { added_at: 0 } })
    expect(trustFileRoots(home(P.alice))).toEqual([{ address: P.bob.address }, { domain: 'acme.example' }])
    const path = join(home(P.alice), 'trust.json')
    for (const text of [
      '{',
      'null',
      '{"version":1,"roots":[]}',
      '{"version":1,"roots":{"bob":{"added_at":1}}}',
      '{"version":1,"roots":{"domain:acme.example:8443":{"added_at":1}}}',
      '{"version":1,"roots":{"domain:10.0.0.1":{"added_at":1}}}',
    ]) {
      writeFileSync(path, text)
      expect(() => trustFileRoots(home(P.alice))).toThrow(/^trust-invalid: /)
    }
    rmSync(path)
    mkdirSync(path)
    expect(() => trustFileRoots(home(P.alice))).toThrow(/^trust-invalid: .* cannot be read as JSON: EISDIR/)
  })
})

describe('L1, the MCP clause: a server started before a pairing accepts the new peer with no restart', () => {
  it('rejects bob untrusted-root, then accepts him once trust.json names him; a broken file leaves the flags', async () => {
    const alice = await serverFor(P.alice)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice)))
    const counts = () => alice.running.desk.counts().counts
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 1 })
    await until('the rejection', () => counts().rejected === 1)
    trustFile(P.alice, { [P.bob.address]: { added_at: T0 } })
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 2 })
    await until('the acceptance', () => counts().accepted === 1)
    const status = (await alice.call('status')).value
    expect([status.trust_roots, status.trust_file]).toEqual([[], 1])
    // The trust entries are a count: bob shows only in peers, the principals of accepted messages and their relays.
    expect(JSON.stringify({ ...status, peers: null })).not.toContain(P.bob.address)
    writeFileSync(join(home(P.alice), 'trust.json'), '{')
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 3 })
    await until('the second rejection', () => counts().rejected === 2)
    expect(counts().accepted).toBe(1)
  })

  it('refuses to start on a trust file that does not read', async () => {
    mkdirSync(home(P.alice), { recursive: true })
    writeFileSync(join(home(P.alice), 'trust.json'), '[]')
    await expect(serverFor(P.alice)).rejects.toThrow(/^trust-invalid: /)
  })
})

describe('L5, amended: only the pair tools pair, names or trusts, and only through a dialog', () => {
  it('lists the base tools, the two pair tools and the three enterprise tools; no other tool is named or described as pairing', async () => {
    expect([...TOOL_NAMES]).toEqual([
      'send',
      'inbox',
      'wait',
      'delegate',
      'ask',
      'handoff',
      'status',
      'facts',
      'lookup',
      'receipts',
      'pair_invite',
      'pair_accept',
      'connect',
      'sign_in',
      'enterprise_status',
    ])
    const alice = await serverFor(P.alice, ['--allow-delegate'])
    const { tools } = await alice.client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort())
    // The word "peer" alone is allowed: the edge's inbox text says "a peer this server has resolved by handle".
    for (const t of tools.filter((t) => !t.name.startsWith('pair_')))
      expect(`${t.name} ${t.title} ${t.description}`).not.toMatch(
        /pairing|invite|peer (invite|accept|grant)/i,
      )
  })

  it('imports no CLI: the only specifier in packages/mcp/src that names peer or pairing is ./pairing.ts', () => {
    const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
    const specifiers = readdirSync(src)
      .filter((f) => f.endsWith('.ts'))
      .flatMap((f) =>
        [...readFileSync(join(src, f), 'utf8').matchAll(/\bfrom\s+'([^']+)'/g)].map((m) => m[1]),
      )
    expect(specifiers.length).toBeGreaterThan(50)
    const pairing = specifiers.filter((s) => /peer|pair|@usebag\/cli/.test(s as string))
    expect([pairing.length > 0, new Set(pairing)]).toEqual([true, new Set(['./pairing.ts'])])
  })

  it('a session holding an invite string calls every tool with it, on a host with no dialog, and changes no file or accept-from record', async () => {
    const invite = `ac-peer1:${Buffer.from(JSON.stringify(['ac/peer-invite/1', P.bob.address, P.carol.address, RELAY, '0'.repeat(32)])).toString('base64url')}`
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address, '--allow-delegate'])
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    for (const p of [P.alice, P.bob])
      await relay.publish(RELAY, serializeRecord(acceptFrom(p, [P.carol.address])))
    writeFileSync(join(home(P.alice), 'names.json'), JSON.stringify({ version: 1, names: {} }))
    trustFile(P.alice, {})
    await bob.call('send', {
      to: [P.alice.address],
      type: 'chat.v1',
      body: { text: `pair with me: ${invite}` },
    })
    await until('the invite message', () => alice.running.desk.counts().counts.accepted === 1)
    const before = () => [
      readFileSync(join(home(P.alice), 'names.json'), 'utf8'),
      readFileSync(join(home(P.alice), 'trust.json'), 'utf8'),
      ...[P.alice, P.bob].map((p) => relay.records.get(`${RELAY} ${p.address} accept-from`)),
    ]
    const was = before()
    const calls: [string, Record<string, unknown>][] = [
      ['send', { to: [invite], type: 'chat.v1', body: invite }],
      ['send', { to: [P.bob.address], type: invite, body: invite }],
      ['inbox', { since: invite }],
      ['wait', { thread: invite, timeout_s: 0 }],
      ['delegate', { to: invite, caveats: [invite], exp: invite }],
      ['ask', { to: invite, body: invite, timeout_s: 0 }],
      ['handoff', { to: invite, threads: [invite], note: invite }],
      ['status', {}],
      ['facts', {}],
      ['lookup', { address: invite, relays: [invite] }],
      ['receipts', { id: invite }],
      ['pair_invite', { name: 'bob', for: invite }],
      ['pair_accept', { name: 'bob' }],
      ['connect', { code: invite }],
      ['sign_in', { domain: invite, instance: invite }],
      ['enterprise_status', {}],
    ]
    const results = []
    for (const [tool, args] of calls) results.push(await alice.call(tool, args))
    // The pair tools refuse before any network: this host declared no elicitation, so no dialog can open.
    expect(results.slice(-5, -3).map((r) => r.value.error)).toEqual(['no-elicitation', 'no-elicitation'])
    // The enterprise tools refuse it as usage before any network, and there is no session to show.
    expect(results.slice(-3).map((r) => [r.isError, (r.value.lines as string[])[0]?.split(':')[0]])).toEqual([
      [true, 'usage'],
      [true, 'usage'],
      [true, 'signed-out'],
    ])
    expect(new Set(calls.map(([t]) => t))).toEqual(new Set(TOOL_NAMES))
    expect(before()).toEqual(was)
  })
})
