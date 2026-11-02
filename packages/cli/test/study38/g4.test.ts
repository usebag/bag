import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { Hop } from '@usebag/core'
import { generateEdgeKeys, HomeCustody, systemRng } from '@usebag/edge'
import { AgentClient } from '@usebag/edge/agent'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { type AgentHome, CAVEAT, publishRecord, RELAY } from '../support/agent.ts'
import { T0, tempDir, testIo } from '../support/io.ts'
import { MemoryRelay } from '../support/relay.ts'
import { cli } from '../support/run.ts'
import { FakeSecurity } from '../support/security.ts'

// G4, one dialog (F3's one read): one `ac login` for a principal whose keys
// are one keychain item under `prompt` access, behind the fake /usr/bin/security that counts every call. The login reads
// the item once (both keys), no grant or renewal reads it again; three first grants are three `y` prompts on the agent's
// terminal and five renewals (silent `sign`s) are none. The live Keychain dialog and a real terminal are measured by hand:
// not run here.

const tmp = tempDir('study38-g4')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5))

describe('G4: one keychain read per login, three y prompts for three first grants, none for five renewals', () => {
  it('reads the item once under prompt access, prompts 3 times, renews 5 times silently', async () => {
    const relay = new MemoryRelay()
    const fake = new FakeSecurity()
    const dir = join(tmp.dir, 'home')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    // The principal: one keychain item (prompt access) holding both keys; the agent pointer `jane` names its address.
    const keys = generateEdgeKeys(systemRng)
    const custody = new HomeCustody(dir, { run: fake.run })
    custody.create('jane-keys', keys, { custody: 'keychain', access: 'prompt' })
    custody.agent.create('jane', keys)
    const home: AgentHome = { dir, keys, address: keys.signing.address }
    publishRecord(relay, home)
    const reads = (): number => fake.calls.filter((c) => c.args[0] === 'find-generic-password').length
    const before = reads()

    // ac login, on a terminal whose typed lines are counted: each ask of the agent's terminal is one prompt.
    const io = Object.assign(testIo(relay), { security: fake.run })
    io.tty = true
    let asked = 0
    io.readLine = async () => {
      asked++
      return io.lines.shift() ?? null
    }
    const ran = cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', dir)
    while (!io.stdout.some((l) => l.startsWith('login ')) && !io.stderr.some((l) => l.startsWith('bag:'))) {
      await tick()
    }
    expect(io.stdout.some((l) => l.startsWith('login '))).toBe(true)
    const afterLogin = reads()

    // Three first grants (`ac grant`, one y each) for three sessions.
    const sessions = [0, 1, 2].map(() => generateEdgeKeys(systemRng).signing)
    const chains: Hop[][] = []
    const afterGrant: number[] = []
    for (const s of sessions) {
      io.lines.push('y')
      const g = await cli(
        testIo(relay),
        'grant',
        '--as',
        'jane',
        '--session',
        s.address,
        '--caveat',
        CAVEAT,
        '--exp',
        '+3600',
        '--dir',
        dir,
      )
      expect(g.code).toBe(0)
      chains.push(JSON.parse(g.out[0] as string) as Hop[])
      afterGrant.push(reads())
    }
    const promptsForGrants = asked

    // Five renewals: a `sign` of the session's own subject, the same caveats, an exp past its first grant's, inside the window.
    const path = join(dir, 'agent.sock')
    const renewals = [0, 0, 1, 1, 2]
    for (const [i, which] of renewals.entries()) {
      const s = sessions[which]
      const chain = chains[which]
      if (s === undefined || chain === undefined) throw new Error('a session is missing')
      const client = new AgentClient(path, { key: s, chain })
      const hop = await client.sign(s.address, [CAVEAT], T0 + 7200 + i)
      client.close()
      expect(hop).toMatchObject({ sub: s.address, caveats: [CAVEAT], exp: T0 + 7200 + i })
    }
    const afterRenewals = reads()
    const promptLines = io.stderr.filter((l) => l === 'sign this grant? type y to sign').length
    const renewedLines = io.stderr.filter((l) => l.startsWith('renewed the grant of ')).length
    const promptsTotal = asked

    measure(
      'G4',
      'keychain reads',
      `before login ${before}, after login ${afterLogin}, after each of 3 grants ${afterGrant.join(', ')}, after 5 renewals ${afterRenewals}; item reads per login ${afterLogin - before}`,
    )
    measure(
      'G4',
      'y prompts',
      `terminal asks ${promptsForGrants} for 3 first grants (${promptLines} prompt lines printed), ${promptsTotal - promptsForGrants} for 5 renewals (${renewedLines} silent 'renewed' lines printed)`,
    )
    measure(
      'G4',
      'live dialog',
      'not run: the live Keychain dialog count and a real terminal y are measured by hand',
    )

    const out = await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', dir)
    expect(out.code).toBe(0)
    expect((await ran).code).toBe(0)

    expect(afterLogin - before).toBe(1)
    expect(afterGrant).toEqual([1, 1, 1].map((n) => before + n))
    expect(afterRenewals).toBe(before + 1)
    expect(promptsForGrants).toBe(3)
    expect(promptLines).toBe(3)
    expect(promptsTotal).toBe(3)
    expect(renewedLines).toBe(5)
  })
})

/** One MEASURE line, as the run records it. */
function measure(line: string, arm: string, text: string): void {
  console.log(`MEASURE ${line}(${arm}): ${text}`)
}
