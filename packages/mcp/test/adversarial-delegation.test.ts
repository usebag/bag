import { writeFileSync } from 'node:fs'
import { type Hop, verifyChain } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  saveKeys,
  sessionChain,
  T0,
  type TestServer,
  tempDir,
  testServer,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// A session's delegate tool (packages/mcp/src/tools.ts lines 415 to 453). Without
// --allow-session-delegation it is `usage`, naming the session key (line 420); with it, the hop is appended to the
// session's own chain (lines 431 to 441), so the chain's append-only rules carry its caveats and expiry over: a caveat
// is only ever added (all must hold), an expiry past the chain's is exp-not-monotone (core chain rule 7), and a chain
// argument that does not start with the session's own hops, byte for byte, is `usage` (line 432). The session is
// org -> jane (type=chat.*, a day) -> session (no caveat, an hour), in process on the memory relay.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let session: TestServer | null = null
const stdout = watchStdout()

async function sessionServer(args: readonly string[] = []): Promise<TestServer> {
  await session?.close()
  const chainFile = `${tmp.dir}/chain.json`
  writeFileSync(chainFile, `${JSON.stringify(sessionChain())}\n`)
  session = await testServer({
    home: tmp.dir,
    name: 'session',
    relay,
    clock,
    timers,
    args: [
      '--auth',
      chainFile,
      '--mailbox',
      P.jane.address,
      '--trust-root',
      P.bob.address,
      '--allow-delegate',
      ...args,
    ],
    pid: 1,
  })
  return session
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('adversarial-delegation')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.org, P.jane, P.bob]) await publishAddress(relay, p)
  saveKeys(tmp.dir, P.session, { signing: P.session.keys.signing, sealing: P.jane.keys.sealing })
})

afterEach(async () => {
  await session?.close()
  session = null
  tmp.cleanup()
  stdout.check()
})

describe('delegation from a session', () => {
  it('without --allow-session-delegation: usage naming the session key, for every form of the call, and no hop', async () => {
    const s = await sessionServer()
    const calls: Record<string, unknown>[] = [
      { to: P.carol.address, caveats: ['repo=x'], exp: '+60' },
      { to: P.carol.address, caveats: ['type=chat.v1'], exp: T0 + 60 },
      { to: P.carol.address, caveats: ['repo=x'], exp: '+60', chain: sessionChain() },
      { to: P.alice.address, caveats: ['repo=x'], exp: '+1' },
    ]
    for (const args of calls) {
      const out = await s.call('delegate', args)
      expect(out.isError).toBe(true)
      expect(out.value.error).toBe('usage')
      expect(out.value.detail).toContain(`this server runs as a session: its key ${P.session.address}`)
      expect(out.value.detail).toContain('--allow-session-delegation')
      expect(out.value.chain).toBeUndefined()
    }
    console.log(
      `MEASURE (off): ${calls.length} of ${calls.length} delegate calls -> usage naming ${P.session.address.slice(0, 16)}..., 0 hops signed`,
    )
  })

  it('with it: the caveats carry over and the expiry cannot pass the chain; a doctored own chain is refused', async () => {
    const s = await sessionServer(['--allow-session-delegation'])
    const own = sessionChain()
    // V1: the lawful delegation, inside the chain's expiry, adding a caveat.
    const lawful = await s.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect(lawful.value).toMatchObject({
      hops: 3,
      exp: T0 + 60,
      caveats: ['type=chat.*', 'repo=x'],
      root: P.org.address,
    })
    expect((lawful.value.chain as Hop[]).slice(0, 2)).toEqual(own)
    // Widen the caveats: none at all, or a broader type. The chain's caveat stays and every caveat must hold.
    const none = await s.call('delegate', { to: P.carol.address, caveats: [], exp: '+60' })
    const broader = await s.call('delegate', { to: P.carol.address, caveats: ['type=*'], exp: '+60' })
    expect([none.isError, String(none.value.text)]).toEqual([
      true,
      expect.stringContaining('delegate needs at least one caveat; [] is refused'),
    ])
    expect(broader.value.caveats).toEqual(['type=chat.*', 'type=*'])
    for (const out of [broader]) {
      expect(verifyChain(out.value.chain as Hop[], P.carol.address, T0).caveats[0]).toBe('type=chat.*')
    }
    // Extend the expiry: the chain's earliest is ts + 3,600. Equal is the limit; one second past is refused.
    const results: string[] = []
    const atLimit = await s.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: T0 + 3600 })
    expect(atLimit.value).toMatchObject({ hops: 3, exp: T0 + 3600 })
    for (const [exp, code] of [
      [T0 + 3601, 'exp-not-monotone'],
      [T0 + 86_400, 'usage'],
      ['+3601', 'exp-not-monotone'],
      ['+999999999', 'usage'],
    ] as const) {
      const out = await s.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp })
      expect([out.isError, out.value.error], String(exp)).toEqual([true, code])
      results.push(`exp ${String(exp)}: ${code}`)
    }
    // An expiry that is no safe integer: refused too, by the hop's shape check (signHop, core chain rule 2).
    const huge = await s.call('delegate', {
      to: P.carol.address,
      caveats: ['repo=x'],
      exp: '+9999999999999999999',
    })
    expect([huge.isError, huge.value.error]).toEqual([true, 'usage'])
    results.push(`exp +9999999999999999999: ${String(huge.value.error)}`)
    // A doctored own chain: the session hop's caveats edited (its sig kept), or the org hop's caveat stripped; and a
    // chain that is someone else's. Each is usage before any signature (sameHop, line 432).
    const edited = [own[0] as Hop, { ...(own[1] as Hop), caveats: ['type=*'] }]
    const stripped = [{ ...(own[0] as Hop), caveats: [] }, own[1] as Hop]
    const foreign = [own[0] as Hop]
    for (const [what, chain] of [
      ['session hop caveats edited', edited],
      ['org hop caveat stripped', stripped],
      ['a chain without the session hop', foreign],
    ] as const) {
      const out = await s.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60', chain })
      expect(out.value, what).toEqual({
        error: 'usage',
        detail:
          "a session delegates only under its own chain: chain must start with the hops of the server's --auth",
      })
      results.push(`${what}: usage`)
    }
    // The own chain followed by a hop to someone else, then this session's hop: refused by the chain rules.
    const detour = await s.call('delegate', {
      to: P.carol.address,
      caveats: ['repo=x'],
      exp: '+60',
      chain: [...own, (lawful.value.chain as Hop[])[2]],
    })
    expect([detour.isError, detour.value.error]).toEqual([true, 'chain-broken'])
    results.push(`own chain + a hop to carol, then the session's hop: ${String(detour.value.error)}`)
    console.log(
      `MEASURE (on): 0 widened; caveats [] refused by the schema; [type=*] -> [type=chat.*, type=*]; exp ts + 3,600 allowed, past 8 hours usage\n  ${results.join('\n  ')}`,
    )
  })
})
