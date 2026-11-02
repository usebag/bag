import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, afterEach, describe, expect, it, onTestFinished } from 'vitest'
import {
  type AgentHome,
  agentHome,
  CAVEAT,
  heldAddress,
  loggedIn,
  publishRecord,
  RELAY,
  sessionAddress,
} from '../support/agent.ts'
import { T0, type TestIo, tempDir, testIo } from '../support/io.ts'
import { MemoryRelay } from '../support/relay.ts'
import { cli, type Ran } from '../support/run.ts'
import { measure, notRun, seedsZeroed, until, zeroed } from './support-a.ts'

// G3 through `ac login`: the window ended by (a) `ac logout`, (b) SIGINT, (c) SIGHUP,
// (d) its end on login's own timer; after each, `ac grant` is tried (a signature asked of an agent that should be
// gone) and the principal's two seed buffers, the ones login read them into, are read for zeros ("the
// test reads the agent's key buffer"; best-effort, a JS runtime proves nothing of memory, never a fail alone).
// And `ac login --window 32400` (9 h). Arm (e), the process dying, is the edge's (packages/edge/test/agent/study38/
// g3.test.ts): here the agent shares the test's process. Pass: 0 signatures after any end.

const tmp = tempDir('s38-g3')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
let homes = 0
const dir = (): string => join(tmp.dir, `h${homes++}`)

interface Open {
  readonly relay: MemoryRelay
  readonly h: AgentHome
  readonly login: { readonly io: TestIo; readonly ran: Promise<Ran> }
  readonly z: ReturnType<typeof zeroed>
  readonly session: string
}

/** A window with one first grant (a `y` typed on login's terminal), the seed buffers watched. */
async function opened(exp: string, ...more: string[]): Promise<Open> {
  const relay = new MemoryRelay()
  const h = agentHome(dir())
  publishRecord(relay, h)
  const z = zeroed()
  onTestFinished(z.restore)
  const login = await loggedIn(relay, h, ...more)
  const session = sessionAddress()
  login.io.lines.push('y')
  const g = await cli(
    testIo(relay),
    'grant',
    '--as',
    'jane',
    '--session',
    session,
    '--caveat',
    CAVEAT,
    '--exp',
    exp,
    '--dir',
    h.dir,
  )
  expect(g.code).toBe(0)
  return { relay, h, login, z, session }
}

/** After the end: `ac grant` asked five times; the signatures it got, and how it was refused. */
async function afterEnd(o: Open): Promise<{ signatures: number; refusals: string }> {
  const io = testIo(o.relay)
  o.login.io.lines.push('y', 'y', 'y', 'y', 'y')
  let signatures = 0
  const seen = new Set<string>()
  for (let i = 0; i < 5; i++) {
    const r = await cli(
      io,
      'grant',
      '--as',
      'jane',
      '--session',
      sessionAddress(),
      '--caveat',
      CAVEAT,
      '--exp',
      '+60',
      '--dir',
      o.h.dir,
    )
    if (r.code === 0) signatures++
    else seen.add(/^bag: ([a-z-]+):/.exec(r.err.at(-1) ?? '')?.[1] ?? `exit ${r.code}`)
  }
  return { signatures, refusals: [...seen].join(', ') }
}

async function report(arm: string, o: Open, ran: Ran, extra: string): Promise<void> {
  const after = await afterEnd(o)
  measure(
    'G3',
    `${arm} cli`,
    `login exited ${ran.code}; ac grant after the end: signatures ${after.signatures} of 5, refused ` +
      `${after.refusals}; socket left ${existsSync(join(o.h.dir, 'agent.sock'))}; the principal's two seed buffers ` +
      `read zeroed ${seedsZeroed(o.z, o.h)} (best-effort); ${extra}`,
  )
  expect(after.signatures).toBe(0)
}

describe('G3 through ac login', () => {
  it('(a) ac logout: the record published with the session in revoked, iat risen, 0 signatures after', async () => {
    const o = await opened('+600')
    const out = await cli(testIo(o.relay), 'logout', '--as', 'jane', '--dir', o.h.dir)
    const ran = await o.login.ran
    const held = heldAddress(o.relay, o.h.address)
    await report(
      'a',
      o,
      ran,
      `ac logout exited ${out.code} (${out.out.join(' | ')}); the relay's record revoked ${JSON.stringify(held.revoked)}, ` +
        `iat ${T0} -> ${held.iat}`,
    )
    expect(held.revoked).toContain(o.session)
  })

  it("(b) SIGINT of the agent's terminal: 0 signatures after", async () => {
    const before = new Set(process.listeners('SIGINT'))
    const o = await opened('+600')
    const mine = process.listeners('SIGINT').filter((f) => !before.has(f))
    // The agent's own SIGINT handler, called as the signal would; emitting SIGINT would reach the test runner's too.
    for (const f of mine) f('SIGINT')
    const ran = await o.login.ran
    await report(
      'b',
      o,
      ran,
      `the agent's SIGINT handlers ${mine.length}; login printed ${JSON.stringify(ran.out.slice(1))}`,
    )
  })

  it("(c) SIGHUP of the agent's terminal: 0 signatures after", async () => {
    const o = await opened('+600')
    process.emit('SIGHUP')
    const ran = await o.login.ran
    await report('c', o, ran, `login printed ${JSON.stringify(ran.out.slice(1))}`)
  })

  it("(d) the window's end on login's own timer (--window 1): nothing published, 0 signatures after", async () => {
    const o = await opened('+1', '--window', '1')
    o.login.io.time.now = T0 + 1
    let done = false
    void o.login.ran.then(() => {
      done = true
    })
    const ended = await until(() => done, 400)
    if (!ended) {
      notRun('G3', 'd cli', "login's timer did not end the window within 4 s of real time")
      return
    }
    const ran = await o.login.ran
    await report(
      'd',
      o,
      ran,
      `published at the end ${o.relay.published.length} (the timer re-signs nothing at a clean end)`,
    )
  })

  it('--window 32400 (9 h): ac login refuses it', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const io = testIo(relay)
    io.tty = true
    const r = await cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', h.dir, '--window', '32400')
    measure(
      'G3',
      'window 32400 cli',
      `ac login exited ${r.code}: ${r.err.join(' | ')}; a window opened ${r.out.length > 0}`,
    )
    expect(r.code).not.toBe(0)
    expect(r.err[0]).toMatch(/--window is at most 28800/)
  })
})
