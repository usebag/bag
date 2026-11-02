import { join } from 'node:path'
import { HomeCustody } from '@usebag/edge'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { agentHome, CAVEAT, loggedIn, publishRecord } from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// ac grant: a uid-only request for a session's first grant, which the agent signs only
// after a y on its own terminal; the refusals of the command, of the person and of the agent.

const tmp = tempDir('grant')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
const dir = (): string => join(tmp.dir, `h${n++}`)
const S = `ed25519:${'ab'.repeat(32)}`

describe('ac grant', () => {
  it('refuses an exp that is not unix seconds or +seconds, an identity of another custody, and no agent', async () => {
    const h = agentHome(dir())
    const io = testIo(new MemoryRelay())
    const grant = (as: string, exp: string) =>
      cli(io, 'grant', '--as', as, '--session', S, '--caveat', CAVEAT, `--exp=${exp}`, '--dir', h.dir)
    for (const exp of ['soon', '+0', '0', '-5', '1.5', '+99999999999999999']) {
      expect((await grant('jane', exp)).err[0]).toBe(
        `bag: usage: --exp is unix seconds or +seconds, not ${JSON.stringify(exp)}`,
      )
    }
    expect((await grant('jane-keys', '+60')).err[0]).toMatch(/^bag: usage: jane-keys is a file/)
    expect((await grant('jane', '+60')).err[0]).toBe(
      `bag: agent-locked: no agent listens at ${join(h.dir, 'agent.sock')}: run ac login`,
    )
  })

  it('is declined without a y, refused past the window, and refused for an agent of another identity', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const bob = agentHome(dir(), 'bob')
    new HomeCustody(h.dir).agent.create('bob', bob.keys)
    const login = await loggedIn(relay, h, '--window', '600')
    const io = testIo(relay)
    const grant = (as: string, exp: string) =>
      cli(io, 'grant', '--as', as, '--session', S, '--caveat', CAVEAT, `--exp=${exp}`, '--dir', h.dir)
    login.io.lines.push('Y', 'yes', 'n')
    for (let i = 0; i < 3; i++) {
      expect((await grant('jane', '+60')).err.at(-1)).toBe('bag: declined: no y at the agent')
    }
    expect((await grant('jane', String(T0 + 601))).err.at(-1)).toBe(
      'bag: exp-not-monotone: the agent refused',
    )
    login.io.lines.push('y')
    expect((await grant('bob', '+60')).err.at(-1)).toBe(
      `bag: bad-hop: the agent here signed another hop than the one asked (${h.address}'s)`,
    )
    expect((await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await login.ran).code).toBe(0)
  })
})
