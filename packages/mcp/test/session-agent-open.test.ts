import { createHash } from 'node:crypto'
import { existsSync, lstatSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { generateEdgeKeys, HomeCustody } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config.ts'
import { openAgentUnit, type SessionStart } from '../src/session.ts'
import { P } from './support/fixtures.ts'
import { seededRng } from './support/ports.ts'
import { type AgentHome, agentHome, CAVEAT } from './support/sessions.ts'

// openAgentUnit: the bag service's opening of an agent-custody identity (decision 92, the gap svc-core's wiring found:
// a window bound to an agent-custody identity bound but could not act). It is the --session form for the service: a
// session key of its own, the agent's hop to it after one y at the agent, the principal's mailbox.

let h: AgentHome
let opened: SessionStart | null = null

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
})

afterEach(async () => {
  opened?.close()
  opened = null
  await h.agent.close()
  h.tmp.cleanup()
})

const base = () => {
  // a session config as svc-core's unit has one: openAgentUnit replaces its session with the label's
  const c = parseConfig(
    [
      '--session',
      'placeholder',
      '--principal',
      'jane',
      '--grant-caveat',
      CAVEAT,
      '--dir',
      h.tmp.dir,
      '--relay',
      'http://127.0.0.1:1',
    ],
    {},
  )
  if (c === 'help') throw new Error('unexpected help')
  return c
}

/** Every file under `root` (relative path to a content hash; a socket as "socket"). */
function filesOf(root: string): Map<string, string> {
  const m = new Map<string, string>()
  const walk = (d: string): void => {
    for (const e of readdirSync(d)) {
      const p = join(d, e)
      const st = lstatSync(p)
      if (st.isDirectory()) walk(p)
      else
        m.set(
          relative(root, p),
          st.isSocket() ? 'socket' : createHash('sha256').update(readFileSync(p)).digest('hex'),
        )
    }
  }
  walk(root)
  return m
}

const deps = () => ({
  clock: h.clock,
  rng: seededRng('agent-open'),
  timers: h.timers,
  pid: 4,
  alive: () => true,
})

describe('openAgentUnit: an agent-custody identity opened for the bag service', () => {
  it('opens at the principal mailbox under the agent hop to a session key of its own', async () => {
    opened = openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())
    h.type('y')
    await opened.granted
    expect(opened.config.as).toBe('jane.service')
    expect(opened.config.mailbox).toBe(P.jane.address)
    const key = new HomeCustody(h.tmp.dir).files.entry('jane.service').address
    expect(key).not.toBe(P.jane.address)
    const [hop] = JSON.parse(readFileSync(opened.config.auth as string, 'utf8')) as {
      sub?: string
      caveats?: string[]
    }[]
    expect(hop?.sub).toBe(key)
    expect(hop?.caveats).toEqual([CAVEAT])
    expect(h.codes()).toHaveLength(1)
    // the mark that proves the file the service's own session key, for its start-up sweep; the key reader ignores it
    const file = JSON.parse(readFileSync(join(h.tmp.dir, 'keys', 'jane.service.json'), 'utf8')) as Record<
      string,
      unknown
    >
    expect([file.kind, file.principal]).toEqual(['session-key', 'jane'])
    expect(new HomeCustody(h.tmp.dir).keys('jane.service').signing.address).toBe(key)
    opened.close()
    opened = null
    expect(existsSync(join(h.tmp.dir, 'keys', 'jane.service.json'))).toBe(false)
  })

  it('refuses a real identity named jane.service before it asks the agent, and leaves its key file as it was', () => {
    const custody = new HomeCustody(h.tmp.dir)
    custody.create('jane.service', generateEdgeKeys(seededRng('foreign')), { custody: 'file' })
    const file = join(h.tmp.dir, 'keys', 'jane.service.json')
    const before = readFileSync(file, 'utf8')
    expect(() => openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())).toThrow(
      /exists: keys\/jane\.service\.json exists and is not the bag service's session key for jane/,
    )
    expect(h.codes()).toHaveLength(0)
    expect(readFileSync(file, 'utf8')).toBe(before)
    // the lock was released: the same refusal again, not busy
    expect(() => openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())).toThrow(/^exists:/)
  })

  it('refuses a session key marked for another principal', () => {
    const custody = new HomeCustody(h.tmp.dir)
    custody.create('jane.service', generateEdgeKeys(seededRng('other')), { custody: 'file' })
    const file = join(h.tmp.dir, 'keys', 'jane.service.json')
    const key = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    writeFileSync(file, JSON.stringify({ ...key, kind: 'session-key', principal: 'build' }), { mode: 0o600 })
    expect(() => openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())).toThrow(/^exists:/)
    expect(h.codes()).toHaveLength(0)
  })

  it('adopts its own marked session key for this principal', async () => {
    const custody = new HomeCustody(h.tmp.dir)
    const made = custody.create('jane.service', generateEdgeKeys(seededRng('left')), {
      custody: 'file',
    }).address
    const file = join(h.tmp.dir, 'keys', 'jane.service.json')
    const key = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    writeFileSync(file, JSON.stringify({ ...key, kind: 'session-key', principal: 'jane' }), { mode: 0o600 })
    opened = openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())
    h.type('y')
    await opened.granted
    const [hop] = JSON.parse(readFileSync(opened.config.auth as string, 'utf8')) as { sub?: string }[]
    expect(hop?.sub).toBe(made)
    expect(h.codes()).toHaveLength(1)
  })

  // The ruling of 2026-11-12 16:04 UTC: ac login does not lend an identity the bag service serves, because the two never
  // write the same file. The unit writes only under <name>.service; the agent (ac login, here the fake agent in the same
  // home) writes the principal's paths, its audit among them (cli login.test.ts pins that half). A unit write outside
  // <name>.service, or into a path of the principal, breaks the ruling.
  it('writes only under jane.service: its key with the mark, its grant and its lock; the agent only its audit', async () => {
    const before = filesOf(h.tmp.dir)
    opened = openAgentUnit(base(), 'jane', { caveats: [CAVEAT] }, deps())
    h.type('y')
    await opened.granted
    const after = filesOf(h.tmp.dir)
    const written = [...after].filter(([p, v]) => before.get(p) !== v).map(([p]) => p)
    const unit = written.filter((p) => /^state\/jane\.service\//.test(p) || p === 'keys/jane.service.json')
    expect(unit.sort()).toEqual([
      'keys/jane.service.json',
      'state/jane.service/grant.json',
      'state/jane.service/mcp.lock',
    ])
    // Everything else is the agent's: its audit, a principal path, never the unit's.
    expect(written.filter((p) => !unit.includes(p))).toEqual(['agent-audit.jsonl'])
    // Nothing of the principal's own state, records or key is touched by the unit.
    expect(written.filter((p) => /^(state\/jane\/|records\/|keys\/jane\.json$|agent\/)/.test(p))).toEqual([])
    expect([...before.keys()].filter((p) => !after.has(p))).toEqual([])
  })

  it('refuses an empty caveat list before it asks the agent', () => {
    expect(() => openAgentUnit(base(), 'jane', { caveats: [] }, deps())).toThrow(/caveat list/)
    expect(h.codes()).toHaveLength(0)
  })

  it('refuses a label that is not an agent-custody identity', () => {
    expect(() => openAgentUnit(base(), 'nobody', { caveats: [CAVEAT] }, deps())).toThrow()
    expect(h.codes()).toHaveLength(0)
  })
})
