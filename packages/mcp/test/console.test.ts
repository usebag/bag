import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { PeerRequest } from '@usebag/edge'
import { type Fetch, PAIRINGS_PATH, type PairingCommand, writeJson } from '@usebag/enterprise-client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CONSOLE_POLL_MS, type ConsoleDeps, consolePass, type Pairer, pollConsole } from '../src/console.ts'
import { addTrust } from '../src/trust.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
  P,
  publishAddress,
  saveKeys,
  T0,
  tempDir,
  testServer,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The console's pairings in the MCP server (decision 38c, console.ts): a faked instance holds the commands and takes
// the events, a stubbed invite stands for the edge's ceremony. A pair runs once and is written to the name book and
// the trust file; an unpair of a kept link takes the root out; no live session, or an identity this server does not
// hold, makes no call; a failing pass is one log line and the next pass runs; the stop (and the server's close) ends
// the interval.

const DOMAIN = 'acme.example'
const ORIGIN = 'https://bag.acme.example'
const ID = '3f2c9a1e-0b7d-4e55-9a61-2c4d8e0f1a2b'
const PEER = P.bob.address

let tmp: ReturnType<typeof tempDir>
let log: MemoryLog
const stdout = watchStdout()

beforeEach(() => {
  stdout.start()
  tmp = tempDir('console')
  log = new MemoryLog()
})

afterEach(() => {
  vi.useRealTimers()
  tmp.cleanup()
  stdout.check()
})

/** A home whose profile holds a session of `state` for the identity alice (none when `state` is null). */
function home(state: string | null = 'live'): string {
  const h = join(tmp.dir, `home-${Math.random().toString(16).slice(2)}`)
  const dir = join(h, 'orgs', DOMAIN, 'enterprise')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (state === null) return h
  const session = {
    v: 1,
    domain: DOMAIN,
    instance: ORIGIN,
    name: 'alice',
    access_token: 'console-test-bearer',
    state,
    org: { domain: DOMAIN, root: P.org.address, relays: [] },
  }
  writeJson(join(dir, 'session.json'), session)
  return h
}

/** The instance: GET answers the commands, every POST is an event taken (204). */
function instance(commands: PairingCommand[]) {
  const events: { id: string; body: Record<string, unknown> }[] = []
  let gets = 0
  const fetch: Fetch = async (url, init) => {
    if (url === `${ORIGIN}${PAIRINGS_PATH}` && init.method === 'GET') {
      gets++
      return new Response(JSON.stringify({ pairings: commands, etag: `p${gets}` }))
    }
    events.push({ id: url.slice(`${ORIGIN}${PAIRINGS_PATH}/`.length), body: JSON.parse(String(init.body)) })
    return new Response(null, { status: 204 })
  }
  return { fetch, events, gets: () => gets }
}

const pair = (more: Partial<PairingCommand> = {}): PairingCommand => ({
  id: ID,
  action: 'pair',
  termDays: null,
  outsideAddress: PEER,
  name: 'bob',
  expiresAt: T0 + 600,
  spoken: '123456',
  ...more,
})

/** A stubbed ceremony: it opens, then asks with PEER's request and the code it was read. */
function pairer() {
  let runs = 0
  const p: Pairer = {
    invite: async (o) => {
      runs++
      o.opened('472-tulip-orbit-cedar', T0 + o.ttl)
      if (!(await o.ask({ from: PEER, code: '123456' } as PeerRequest))) throw new Error('declined')
      return PEER
    },
    busy: () => false,
  }
  return { p, runs: () => runs }
}

function deps(h: string, fetch: Fetch, p: Pairer | null): ConsoleDeps {
  const clock = new FakeClock()
  return { home: h, fetch, clock, log, pairer: () => p, sleep: async () => {} }
}

const trust = (h: string): string[] => {
  try {
    return Object.keys(JSON.parse(readFileSync(join(h, 'trust.json'), 'utf8')).roots)
  } catch {
    return []
  }
}

describe('consolePass', () => {
  it('runs a pair once: code, request, paired posted; the peer named and trusted', async () => {
    const h = home()
    const at = instance([pair()])
    const c = pairer()
    await consolePass(deps(h, at.fetch, c.p))
    await consolePass(deps(h, at.fetch, c.p))
    expect(c.runs()).toBe(1)
    expect(at.events.map((e) => [e.id, e.body.event])).toEqual([
      [ID, 'code_shown'],
      [ID, 'request'],
      [ID, 'paired'],
    ])
    expect(at.events[2]?.body.peerAddress).toBe(PEER)
    expect(JSON.parse(readFileSync(join(h, 'names.json'), 'utf8')).names.bob.address).toBe(PEER)
    expect(trust(h)).toEqual([PEER])
  })

  it('an unpair of a kept link takes its root out of the trust file and posts unpaired', async () => {
    const h = home()
    addTrust(h, PEER, T0)
    const link = { id: ID, peer: PEER, name: 'bob', paired_at: T0, until: null }
    writeJson(join(h, 'orgs', DOMAIN, 'enterprise', 'pairings.json'), { v: 1, links: [link], done: [] })
    const at = instance([pair({ action: 'unpair', spoken: null })])
    const c = pairer()
    await consolePass(deps(h, at.fetch, c.p))
    expect(trust(h)).toEqual([])
    expect(at.events).toEqual([{ id: ID, body: { event: 'unpaired' } }])
    expect(c.runs()).toBe(0)
    expect(log.lines.map((l) => l.event)).toEqual(['console-unpaired'])
  })

  it('runs the enterprise tick after a pass that ended a link or ran a pairing, and not after one that changed nothing', async () => {
    const h = home()
    addTrust(h, PEER, T0)
    const link = { id: ID, peer: PEER, name: 'bob', paired_at: T0, until: null }
    writeJson(join(h, 'orgs', DOMAIN, 'enterprise', 'pairings.json'), { v: 1, links: [link], done: [] })
    let ticks = 0
    const republish = async () => {
      ticks++
    }
    const pass = (commands: PairingCommand[]) =>
      consolePass({ ...deps(h, instance(commands).fetch, pairer().p), republish })
    await pass([pair({ action: 'unpair', spoken: null })])
    expect([ticks, trust(h)]).toEqual([1, []])
    await pass([])
    expect(ticks).toBe(1)
    const other = '7d1e0c2b-4a5f-4b6e-8c7d-9e0f1a2b3c4d'
    await pass([pair({ id: other })])
    expect([ticks, trust(h)]).toEqual([2, [PEER]])
    await pass([pair({ id: other })])
    expect(ticks).toBe(2)
  })

  it('makes no call with no session, a session not live, or an identity this server does not hold', async () => {
    const at = instance([pair()])
    const c = pairer()
    await consolePass(deps(home(null), at.fetch, c.p))
    await consolePass(deps(home('frozen'), at.fetch, c.p))
    await consolePass(deps(home(), at.fetch, null))
    expect([at.gets(), at.events.length, c.runs()]).toEqual([0, 0, 0])
  })

  it('leaves a pair for a later pass while a pair tool runs one', async () => {
    const h = home()
    const at = instance([pair()])
    const c = pairer()
    let busy = true
    const p: Pairer = { invite: c.p.invite, busy: () => busy }
    await consolePass(deps(h, at.fetch, p))
    expect(c.runs()).toBe(0)
    busy = false
    await consolePass(deps(h, at.fetch, p))
    expect(c.runs()).toBe(1)
  })
})

describe('pollConsole', () => {
  it('a failing pass is one log line, and the next pass runs', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const h = home()
    const at = instance([])
    const session = join(h, 'orgs', DOMAIN, 'enterprise', 'session.json')
    const good = readFileSync(session, 'utf8')
    writeJson(session, { v: 2 })
    const stop = pollConsole(deps(h, at.fetch, pairer().p))
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS)
    expect(log.lines).toEqual([
      { level: 'warn', event: 'console-pairings', fields: { code: 'session-invalid' } },
    ])
    expect(at.gets()).toBe(0)
    writeJson(session, JSON.parse(good))
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS)
    expect(at.gets()).toBe(1)
    stop()
  })

  it('the stop ends the interval', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const at = instance([])
    const stop = pollConsole(deps(home(), at.fetch, pairer().p))
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS)
    expect(at.gets()).toBe(1)
    stop()
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS * 4)
    expect(at.gets()).toBe(1)
  })

  it("the server polls its home's live session for its own identity, and its close stops that", async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const h = home()
    const relay = new MemoryRelay()
    saveKeys(h, P.alice)
    await publishAddress(relay, P.alice)
    const at = instance([])
    const server = await testServer({
      home: h,
      name: 'alice',
      relay,
      clock: new FakeClock(),
      timers: new ManualTimers(),
      enterprise: { fetch: at.fetch },
    })
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS)
    expect(at.gets()).toBe(1)
    await server.close()
    await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS * 4)
    expect(at.gets()).toBe(1)
  })
})
