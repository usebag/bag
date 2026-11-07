import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { GuardRefused } from '@usebag/edge'
import { connectCodeOf, type EnterprisePorts } from '@usebag/enterprise-client'
import { FakeInstance } from '@usebag/enterprise-client/testing'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { TOOL_NAMES } from '../src/tools.ts'
import {
  FakeClock,
  ManualTimers,
  type Outcome,
  P,
  publishAddress,
  saveKeys,
  type TestServer,
  tempDir,
  testServer,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The enterprise tools of the identity server (connect, sign_in and enterprise_status) through an SDK client against
// the enterprise client's recorded fake instance: listed beside the eleven, the library's flow at the server's home,
// {exit, lines} as text and structured content, a tool error where the standalone server answers one, and no secret
// in any result or log line (the code, its secret part, the device code, the token, a key seed).

const DOMAIN = 'acme.example'
const ROUND_TRIP = /^Connected as acme-example-1; relay round trip \d+ ms$/
const SECRET = 'mcp-test-secret-only-for-these-tests-'.padEnd(43, '0')
const WAITING = 'Waiting for a person to approve it; ask again to see the state'

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
const open: TestServer[] = []
const stdout = watchStdout()

beforeEach(() => {
  stdout.start()
  tmp = tempDir('enterprise-tools')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
})

afterEach(async () => {
  for (const s of open.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

/** alice's server at her home, its enterprise tools on the fake instance; `guard` answers the private-address guard. */
async function setup(guard: () => Promise<string | null> = async () => '192.0.2.10') {
  const fake = new FakeInstance({ domain: DOMAIN, now: () => clock.now() })
  const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
  fake.consoleCodes.add(code)
  const home = join(tmp.dir, 'alice')
  saveKeys(home, P.alice)
  await publishAddress(relay, P.alice)
  const enterprise: Partial<EnterprisePorts> = {
    fetch: fake.fetch,
    net: {
      txt: async () => [],
      get: async () => ({ status: 404, body: null }),
      guard: { connectTo: async () => guard() },
    },
    sleep: async () => {},
    // The organisation's relays, in memory, apart from the identity's: connect's records and round trip, status's probe.
    relays: new MemoryRelay(),
  }
  const server = await testServer({
    home,
    name: 'alice',
    relay,
    clock,
    timers,
    args: ['--allow-delegate'],
    enterprise,
  })
  open.push(server)
  const said: string[] = []
  const call = async (tool: string, args: Record<string, unknown> = {}): Promise<Outcome> => {
    const out = await server.call(tool, args)
    said.push((out.result.content[0] as { text: string }).text, JSON.stringify(out.result.structuredContent))
    return out
  }
  return { fake, code, home, server, call, said }
}

type World = Awaited<ReturnType<typeof setup>>

/** Every secret this home and the fake hold now: the code, its secret part, the device code, the token, each seed. */
function secrets(w: World): string[] {
  const out = [w.code, SECRET, ...P.alice.secrets]
  const pending = join(w.home, 'enterprise', 'pending.json')
  if (existsSync(pending)) out.push(JSON.parse(readFileSync(pending, 'utf8')).device_code as string)
  if (w.fake.rows.size > 0) out.push(w.fake.row().token)
  const keys = join(w.home, 'keys')
  for (const f of readdirSync(keys)) {
    const seed = (JSON.parse(readFileSync(join(keys, f), 'utf8')) as { sign_seed?: unknown }).sign_seed
    if (typeof seed === 'string') out.push(seed)
  }
  // A row's token before the instance issues one is empty: nothing to look for.
  return out.filter((s) => s !== '')
}

/** No result's text or structured content, and no log line, holds a secret. */
function clean(w: World, more: readonly string[] = []): void {
  const logs = JSON.stringify(w.server.log.lines)
  for (const secret of [...secrets(w), ...more]) {
    for (const text of w.said) expect(text).not.toContain(secret)
    expect(logs).not.toContain(secret)
  }
}

/** The outcome as {isError, exit, lines}, its structured content checked equal to its text's JSON. */
function shown(out: Outcome): { isError: boolean; exit: unknown; lines: string[] } {
  expect(out.result.structuredContent).toEqual(out.value)
  expect(Object.keys(out.value).sort()).toEqual(['exit', 'lines'])
  return { isError: out.isError, exit: out.value.exit, lines: out.value.lines as string[] }
}

const ARGS = { domain: DOMAIN, instance: 'https://ent.example.test' }

describe('the enterprise tools of the identity server', () => {
  it('lists connect, sign_in and enterprise_status beside the eleven: the full set, with their shapes', async () => {
    const w = await setup()
    const { tools } = await w.server.client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort())
    expect(TOOL_NAMES).toHaveLength(14)
    const tool = (name: string) => tools.find((t) => t.name === name)
    expect(tool('connect')?.inputSchema.required).toEqual(['code'])
    expect(tool('sign_in')?.inputSchema.required).toEqual(['domain', 'instance'])
    expect(Object.keys(tool('enterprise_status')?.inputSchema.properties ?? {})).toEqual(['org'])
    expect(tool('enterprise_status')?.inputSchema.required ?? []).toEqual([])
    expect(tool('connect')?.annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true })
    expect(tool('sign_in')?.annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true })
    expect(tool('enterprise_status')?.annotations).toMatchObject({ readOnlyHint: true })
    expect(tool('connect')?.description).toContain('exactly as the person pasted it: it is used once')
    expect(tool('connect')?.description).toContain('never carries the code, a token or a key')
    expect(tool('sign_in')?.description).toContain('never carries the device code, a token or a key')
    expect(tool('enterprise_status')?.description).toContain('never carries a code, a token or a key')
    expect(w.server.client.getInstructions()).toContain(
      'enterprise_status shows that session; never ask for or repeat a code, a token or a key.',
    )
  })

  it('connect: a bad code is a tool error with the reason, free of the code; no code is usage; nothing is called', async () => {
    const w = await setup()
    const cut = w.code.slice(0, -1)
    expect(shown(await w.call('connect', { code: cut }))).toEqual({
      isError: true,
      exit: 2,
      lines: ['usage: this is not a connect code from the console: it is cut short or changed'],
    })
    expect(shown(await w.call('connect', { code: ' \n' }))).toEqual({
      isError: true,
      exit: 2,
      lines: ['usage: no code: paste the code from the console'],
    })
    // A used code: the instance refuses it, and the answer is still free of it.
    w.fake.consoleCodes.clear()
    const used = shown(await w.call('connect', { code: w.code }))
    expect([used.isError, used.lines]).toEqual([true, [expect.stringMatching(/^invalid_grant: /)]])
    expect(w.fake.calls.map((c) => c.path)).toEqual(['/agent/redeem'])
    clean(w, [cut, cut.slice(cut.lastIndexOf('.') + 1)])
  })

  it('connect: the pasted code connects through the library at the home; status before and after; no secret', async () => {
    const w = await setup()
    expect(shown(await w.call('enterprise_status'))).toEqual({
      isError: true,
      exit: 3,
      lines: ['signed-out: not signed in: bag sign-in <domain>'],
    })
    const r = shown(await w.call('connect', { code: `  ${w.code}\n` }))
    expect(r).toEqual({
      isError: false,
      exit: 0,
      lines: [expect.stringMatching(ROUND_TRIP)],
    })
    expect(w.fake.calls[0]?.path).toBe('/agent/redeem')
    expect(w.fake.calls[0]?.body?.code).toBe(w.code)
    expect(existsSync(join(w.home, 'orgs', DOMAIN, 'enterprise', 'session.json'))).toBe(true)
    expect(w.fake.row().token.length).toBeGreaterThan(8)
    const s = shown(await w.call('enterprise_status'))
    expect([s.isError, s.exit]).toEqual([false, 0])
    expect(s.lines[0]).toMatch(/^signed-in acme\.example agent ed25519:[0-9a-f]{64} state live$/)
    expect(s.lines.at(-1)).toMatch(ROUND_TRIP)
    // org names the organisation: the same session; one this home does not hold is signed-out.
    expect(shown(await w.call('enterprise_status', { org: DOMAIN })).lines.at(-1)).toMatch(ROUND_TRIP)
    const none = shown(await w.call('enterprise_status', { org: 'other.example' }))
    expect([none.isError, none.lines]).toEqual([
      true,
      ['signed-out: not signed in to other.example: one of acme.example'],
    ])
    // Connected already: the same code again redeems nothing and says the session.
    const again = shown(await w.call('connect', { code: w.code }))
    expect([again.isError, again.lines]).toEqual([false, [expect.stringMatching(ROUND_TRIP)]])
    expect(w.fake.calls.filter((c) => c.path === '/agent/redeem')).toHaveLength(1)
    clean(w)
    const tool = w.server.log.lines.filter((l) => l.event === 'tool').map((l) => l.fields)
    expect(tool.slice(0, 3)).toEqual([
      { tool: 'enterprise_status', ok: false, code: 'signed-out' },
      { tool: 'connect', ok: true },
      { tool: 'enterprise_status', ok: true },
    ])
  })

  it("connect: approved before the organisation's signer signs is exit 4, not a tool error", async () => {
    const w = await setup()
    w.fake.signer = false
    const r = shown(await w.call('connect', { code: w.code }))
    expect([r.isError, r.exit, r.lines.at(-1)]).toEqual([
      false,
      4,
      "Waiting for the organisation's signer: run bag status in a minute",
    ])
    clean(w)
  })

  it('sign_in: the link, the user code and the fingerprint; waiting, then connected once approved; never the device code or the token', async () => {
    const w = await setup()
    const first = shown(await w.call('sign_in', ARGS))
    expect(first).toEqual({
      isError: false,
      exit: 4,
      lines: [
        `Signing in to ${DOMAIN} at https://ent.example.test`,
        'open https://id.example.test/auth/agent and enter the code BCDF-GGG0',
        expect.stringMatching(
          /^fingerprint [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} \(the agent's key, as that page shows it\)$/,
        ),
        'approve only a code you started yourself',
        WAITING,
      ],
    })
    const pending = join(w.home, 'orgs', DOMAIN, 'enterprise', 'pending.json')
    const deviceCode = JSON.parse(readFileSync(pending, 'utf8')).device_code as string
    expect(shown(await w.call('sign_in', ARGS)).lines.at(-1)).toBe(WAITING)
    const waiting = shown(await w.call('enterprise_status'))
    expect([waiting.isError, waiting.exit, waiting.lines[0]]).toEqual([
      false,
      4,
      'waiting acme.example: a person is to approve the code BCDF-GGG0',
    ])
    w.fake.approve('BCDF-GGG0')
    const done = shown(await w.call('sign_in', ARGS))
    expect([done.isError, done.exit, done.lines.at(-1)]).toEqual([false, 0, 'Connected as acme-example'])
    expect(w.fake.calls.map((c) => c.path)).toContain('/agent/code')
    expect(shown(await w.call('enterprise_status')).lines[0]).toMatch(/state live$/)
    clean(w, [deviceCode])
  })

  it('sign_in: a denied code is a tool error with the instance word; a bad instance or domain is usage', async () => {
    const w = await setup()
    await w.call('sign_in', ARGS)
    w.fake.deny('BCDF-GGG0')
    const refused = shown(await w.call('sign_in', ARGS))
    expect([refused.isError, refused.lines.at(-1)]).toEqual([true, expect.stringMatching(/^access_denied: /)])
    const bad = shown(await w.call('sign_in', { domain: DOMAIN, instance: 'http://ent.example.test' }))
    expect([bad.isError, bad.exit, bad.lines.at(-1)]).toEqual([
      true,
      2,
      expect.stringMatching(/^usage: the instance is the console origin/),
    ])
    clean(w)
  })

  it('a console on a private address is refused before any call, for sign_in and for connect', async () => {
    const w = await setup(async () => {
      throw new GuardRefused({ range: 'private', detail: 'resolves to a private address' })
    })
    const signIn = shown(await w.call('sign_in', ARGS))
    expect([signIn.isError, signIn.lines.at(-1)]).toEqual([
      true,
      expect.stringMatching(/^resolve-failed: https:\/\/ent/),
    ])
    const connect = shown(await w.call('connect', { code: w.code }))
    expect(connect.isError).toBe(true)
    expect(connect.lines.at(-1)).toMatch(/^resolve-failed: /)
    expect(w.fake.calls).toEqual([])
    clean(w)
  })
})
