import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { HOP_TAG, type Hop, signHop, verifyPreimage } from '@usebag/core'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { type AgentHome, agentHome, CAVEAT, loggedIn, publishRecord, RELAY } from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The device grant in the cli:
// `ac grant --device <petname>` on P's machine prints the hop P -> D as a chain of one hop, carried to D by hand;
// `ac login --device <file>` on D holds D's own key, answers for P, ends by the hop's exp, reads no record of P's and
// signs only; D's `ac logout` signs nothing and names each session still live, with the step that revokes D.

const tmp = tempDir('device-grant')
afterAll(() => tmp.cleanup())
// A test that fails with a window open leaves no agent behind: the signal ends it as a terminal's hangup would.
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
// Short names: a Unix socket path holds about 100 bytes.
const dir = (): string => join(tmp.dir, `d${n++}`)
const DAY = 86_400
const iso = (t: number): string => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')

/** Names `address` as `name` in the name book of `h` (what ac peer leaves there). */
async function pair(h: AgentHome, name: string, address: string): Promise<void> {
  expect((await cli(testIo(new MemoryRelay()), 'name', 'add', name, address, '--dir', h.dir)).code).toBe(0)
}

/** A chain file of the hops given, in the home of `h`. */
function chainFile(h: AgentHome, hops: readonly Hop[]): string {
  const file = join(h.dir, `hop${n++}.json`)
  writeFileSync(file, JSON.stringify(hops))
  return file
}

describe('ac grant --device (S1, S3): the hop P -> D, printed for the hand', () => {
  it('prints the hop on a y, signed by P to the paired key; declined without one; 31 days refused', async () => {
    const relay = new MemoryRelay()
    const p = agentHome(dir())
    publishRecord(relay, p)
    const D = generateEdgeKeys(systemRng).signing.address
    await pair(p, 'laptop', D)
    const login = await loggedIn(relay, p)
    const io = testIo(relay)
    const grant = (...more: string[]) => cli(io, 'grant', '--as', 'jane', '--dir', p.dir, ...more)
    login.io.lines.push('y')
    const g = await grant('--device', 'laptop', '--exp', `+${DAY}`)
    expect(g.code).toBe(0)
    expect(g.err[0]).toMatch(/^request [0-9a-f]{8}: /)
    const [hop, ...more] = JSON.parse(g.out[0] as string) as Hop[]
    expect(more).toEqual([])
    expect(hop).toMatchObject({ iss: p.address, sub: D, caveats: [], exp: T0 + DAY })
    const h = hop as Hop
    expect(verifyPreimage(p.address, [HOP_TAG, h.iss, h.sub, h.caveats, h.exp], h.sig)).toBe(true)
    expect(login.io.stderr).toContain(`device grant to ${D}`)
    expect(login.io.stderr).toContain('caveats unrestricted')
    login.io.lines.push('n')
    expect((await grant('--device', D, '--exp', `+${DAY}`)).err.at(-1)).toBe(
      'bag: declined: no y at the agent',
    )
    expect((await grant('--device', 'laptop', '--exp', `+${31 * DAY}`)).err.at(-1)).toBe(
      'bag: exp-not-monotone: the agent refused',
    )
    expect((await grant('--device', 'desktop', '--exp', '+60')).err.at(-1)).toMatch(/^bag: name-unknown: /)
    const both = await grant('--device', 'laptop', '--session', D, '--caveat', CAVEAT, '--exp', '+60')
    expect(both.err[0]).toBe('bag: usage: --session or --device is required')
    expect((await grant('--device', 'laptop', '--exp', '+60', '--chain', 'x.json')).err[0]).toBe(
      'bag: usage: --chain goes with --session',
    )
    expect((await grant('--session', D, '--exp', '+60')).err[0]).toBe('bag: usage: --caveat is required')
    // The device hop is in no dated map, so P's logout revokes nothing and D stays out of `revoked`.
    expect(await cli(io, 'logout', '--as', 'jane', '--dir', p.dir)).toEqual({
      code: 0,
      out: ['logout: nothing to revoke'],
      err: [],
    })
    expect((await login.ran).code).toBe(0)
  })
})

describe('ac login --device (S2): D holds its own key and answers for P', () => {
  /** P's home and D's (D's agent identity `jane` over D's own key file), P paired in D's book as `p`. */
  async function homes() {
    const p = agentHome(dir())
    const d = agentHome(dir())
    await pair(d, 'p', p.address)
    // A relay whose record fetches fail: a device login that asked for one of P's records would fail.
    const relay = new MemoryRelay()
    relay.failRecordFetch.set(RELAY, new Error('a device login fetched a record'))
    return { p, d, relay }
  }

  it("opens a window bounded by the hop's exp, fetches no record of P's, and grants under D", async () => {
    const { p, d, relay } = await homes()
    const device = signHop(p.keys.signing, d.address, [], T0 + 600)
    const file = chainFile(d, [device])
    const login = await loggedIn(relay, d, '--device', file)
    const sock = join(d.dir, 'agent.sock')
    expect(login.io.stdout).toEqual([`login ${d.address} for ${p.address} until ${iso(T0 + 600)} on ${sock}`])
    expect(relay.records.size).toBe(0)
    const io = testIo(relay)
    const S = generateEdgeKeys(systemRng).signing.address
    const grant = (exp: string, chainAt = file) =>
      cli(
        io,
        'grant',
        '--as',
        'jane',
        '--session',
        S,
        '--caveat',
        CAVEAT,
        '--exp',
        exp,
        '--chain',
        chainAt,
        '--dir',
        d.dir,
      )
    login.io.lines.push('y')
    const g = await grant('+300')
    expect(g.code).toBe(0)
    const chain = JSON.parse(g.out[0] as string) as Hop[]
    expect(chain).toHaveLength(2)
    expect(chain[0]).toEqual(device)
    expect(chain[1]).toMatchObject({ iss: d.address, sub: S, caveats: [CAVEAT], exp: T0 + 300 })
    // A --chain whose last hop is not to D: the grant is signed, but no broken chain is printed.
    login.io.lines.push('y')
    const elsewhere = chainFile(d, [
      signHop(p.keys.signing, generateEdgeKeys(systemRng).signing.address, [], T0 + 600),
    ])
    const broken = await grant('+200', elsewhere)
    expect([broken.code, broken.out]).toEqual([1, []])
    expect(broken.err.at(-1)).toMatch(/^bag: chain-broken: not one chain with --chain: /)
    // Past the device hop's exp the agent refuses before any prompt.
    expect((await grant('+700')).err.at(-1)).toBe('bag: exp-not-monotone: the agent refused')
    // D's logout signs nothing; it names the live session and the step that revokes D on P's machine.
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', d.dir)
    expect(out.code).toBe(0)
    expect(out.out).toEqual([
      expect.stringMatching(new RegExp(`^unrevoked ${S} until \\d{4}-\\d\\d-\\d\\dT`)),
    ])
    expect(out.err).toEqual([expect.stringContaining(`--revoke ${d.address}`)])
    expect(relay.published).toEqual([])
    expect(await login.ran).toMatchObject({ code: 0, out: [expect.any(String), `logout ${d.address}`] })
  })

  it('refuses a hop not from a principal in the book, not to D, not signed by P, or expired; no socket', async () => {
    const { p, d, relay } = await homes()
    const q = agentHome(dir())
    const cases: [Hop[], string][] = [
      [[signHop(q.keys.signing, d.address, [], T0 + 600)], 'not-authorized'],
      [[signHop(p.keys.signing, q.address, [], T0 + 600)], 'not-authorized'],
      [[{ ...signHop(q.keys.signing, d.address, [], T0 + 600), iss: p.address }], 'bad-hop-sig'],
      [[signHop(p.keys.signing, d.address, [], T0 - 1)], 'hop-expired'],
      [[], 'not-authorized'],
    ]
    for (const [hops, code] of cases) {
      const login = await loggedIn(relay, d, '--device', chainFile(d, hops))
      expect(login.io.stdout).toEqual([])
      expect(login.io.stderr.at(-1)).toMatch(new RegExp(`^bag: ${code}: `))
      expect((await login.ran).code).toBe(1)
      expect(existsSync(join(d.dir, 'agent.sock'))).toBe(false)
    }
  })
})
