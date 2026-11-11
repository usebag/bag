import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { HOST_FACTS_FILE, STALE_SECONDS } from '../src/facts.ts'
import { heldNote, REPORT_RULE, SUB_SESSION_NOTE } from '../src/tools.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  type TestServer,
  tempDir,
  testServer,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The facts tool and status's host fields over fixture host-facts.json files, on a server of one.

let tmp: ReturnType<typeof tempDir>
let clock: FakeClock
let alice: TestServer
let relay: MemoryRelay
const stdout = watchStdout()
const at = (s: number): string => new Date(s * 1000).toISOString()

/** Writes alice's host-facts.json, 0600, beside her doorbell. */
function hostFacts(value: Record<string, unknown>): void {
  const dir = join(tmp.dir, 'alice', 'state', 'alice')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const path = join(dir, HOST_FACTS_FILE)
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
  chmodSync(path, 0o600)
}

const omp = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  v: 1,
  host: 'omp',
  updated_at: at(clock.now() - 12),
  host_version: '18.17.0',
  host_pid: process.ppid,
  session_id: 'omp-session-1',
  main_session: true,
  model: 'deepinfra/deepseek-ai/DeepSeek-V4.1-Flash-1017',
  cost_usd: 1.25,
  context_percent: 41,
  context_tokens: 82_000,
  ...o,
})

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('facts-tool')
  clock = new FakeClock()
  relay = new MemoryRelay()
  saveKeys(`${tmp.dir}/alice`, P.alice)
  await publishAddress(relay, P.alice)
  alice = await testServer({
    home: `${tmp.dir}/alice`,
    name: 'alice',
    relay,
    clock,
    timers: new ManualTimers(),
    args: ['--trust-root', P.bob.address],
  })
})

afterEach(async () => {
  await alice.close()
  tmp.cleanup()
  stdout.check()
})

describe('facts', () => {
  it("returns the identity, each host figure with its age, main_session and the bag side, from the doorbell's directory", async () => {
    hostFacts(omp({ fields_at: { model: at(clock.now() - 300) } }))
    clock.t += 3
    const { value, isError } = await alice.call('facts')
    expect(isError).toBeFalsy()
    expect(Object.keys(value)[0]).toBe('identity')
    expect(value).toMatchObject({
      identity: { label: 'alice', address: P.alice.address, mailbox: P.alice.address },
      main_session: true,
      host_facts: {
        state: 'fresh',
        host: 'omp',
        host_version: '18.17.0',
        session_id: 'omp-session-1',
        age_s: 15,
        own_host: true,
        model: { value: 'deepinfra/deepseek-ai/DeepSeek-V4.1-Flash-1017', age_s: 303 },
        cost_usd: { value: 1.25, age_s: 15 },
        context_percent: { value: 41, age_s: 15 },
        context_tokens: { value: 82_000, age_s: 15 },
        not_provided: [],
        invalid: [],
      },
      bag: { relays: [RELAY], pid: process.pid, uptime_s: 3 },
      report_rule: REPORT_RULE,
    })
    const bag = value.bag as { doorbell_path: string }
    expect((value.host_facts as { path: string }).path).toBe(
      join(dirname(bag.doorbell_path), HOST_FACTS_FILE),
    )
    expect(value).not.toHaveProperty('sub_session')
  })

  it('says first, before anything else, that a spawned sub-session is not the agent of this identity', async () => {
    hostFacts(omp({ main_session: false, host_pid: 1 }))
    const { value } = await alice.call('facts')
    expect(Object.keys(value)[0]).toBe('sub_session')
    expect(value).toMatchObject({ sub_session: SUB_SESSION_NOTE, main_session: false })
    expect((value.host_facts as { detail: string }).detail).toContain('host_pid 1 is not this server')
  })

  it('names the figures a host does not provide, and never fills them', async () => {
    hostFacts({ v: 1, host: 'claude-code', updated_at: at(clock.now()), model: 'claude-opus-5-5' })
    const { value } = await alice.call('facts')
    expect(value).toMatchObject({
      main_session: null,
      host_facts: {
        model: { value: 'claude-opus-5-5' },
        cost_usd: { value: null, note: 'not provided by claude-code' },
        context_percent: { value: null, note: 'not provided by claude-code' },
        own_host: null,
      },
    })
  })

  it('answers a missing, a malformed and a stale file in its result, never as a tool error', async () => {
    const missing = await alice.call('facts')
    expect(missing.isError).toBeFalsy()
    expect(missing.value).toMatchObject({ main_session: null, host_facts: { state: 'missing' } })
    hostFacts({ v: 1, host: 'omp' })
    expect((await alice.call('facts')).value).toMatchObject({
      host_facts: { state: 'malformed', detail: expect.stringContaining('updated_at') },
    })
    hostFacts(omp({ updated_at: at(clock.now() - STALE_SECONDS - 60) }))
    expect((await alice.call('facts')).value).toMatchObject({
      host_facts: { state: 'stale', cost_usd: { value: 1.25 } },
    })
  })

  it('refuses an as that names no identity of this server', async () => {
    const { value, isError } = await alice.call('facts', { as: 'bob' })
    expect([isError, value.error]).toEqual([true, 'unknown-identity'])
  })
})

describe('status', () => {
  it("carries the host's model, main_session and the host facts' state", async () => {
    expect((await alice.call('status')).value).toMatchObject({
      model: null,
      main_session: null,
      host_facts: 'missing',
    })
    hostFacts(omp({ main_session: false }))
    expect((await alice.call('status')).value).toMatchObject({
      model: 'deepinfra/deepseek-ai/DeepSeek-V4.1-Flash-1017',
      main_session: false,
      host_facts: 'fresh',
    })
  })
})

describe('a held server: another session holds the identity', () => {
  const holdersModel = 'holders-own/model-that-must-not-appear'

  /** A second server of alice (pid 4343) in alice's home, while the first (pid 4242) lives and holds her lock. */
  async function second(): Promise<TestServer> {
    hostFacts(omp({ model: holdersModel }))
    return testServer({
      home: `${tmp.dir}/alice`,
      name: 'alice',
      relay,
      clock,
      timers: new ManualTimers(),
      pid: 4343,
      alive: (p) => p === 4242,
      args: ['--trust-root', P.bob.address],
    })
  }

  const heldShape = (): Record<string, unknown> => ({
    held: true,
    held_by: {
      pid: 4242,
      started_at: expect.any(String),
      cwd: process.cwd(),
      host: 'other',
      path: join(tmp.dir, 'alice', 'state', 'alice', 'mcp.lock'),
    },
    note: 'This session does not speak for alice; the session with pid 4242 (other) holds it.',
    message: expect.stringMatching(/^bag: the identity alice is held by another session \(pid 4242, /),
    pid: process.pid,
    started_at: at(clock.now() - 5),
    uptime_s: 5,
    held_since: null,
    held_from_start: true,
    host_facts: null,
    host_facts_state: 'held',
  })

  it("facts answers who holds it and this server's own process, and never reads the holder's host-facts.json", async () => {
    const held = await second()
    try {
      // The holder reads its own file: the fixture is readable, so its absence below is the held answer's doing.
      expect(JSON.stringify((await alice.call('facts')).value)).toContain(holdersModel)
      clock.t += 5
      const { value, isError } = await held.call('facts')
      expect(isError).toBeFalsy()
      expect(value).toEqual(heldShape())
      expect(JSON.stringify(value)).not.toContain(holdersModel)
    } finally {
      await held.close()
    }
  })

  it("status answers the same held fields, the note and its own uptime, without the holder's model", async () => {
    const held = await second()
    try {
      clock.t += 5
      const { value, isError } = await held.call('status')
      expect(isError).toBeFalsy()
      expect(value).toEqual(heldShape())
      expect(JSON.stringify(value)).not.toContain(holdersModel)
      // Every other tool still answers the held error.
      expect((await held.call('inbox')).value).toMatchObject({ error: 'busy' })
    } finally {
      await held.close()
    }
  })

  it('names the holder without a host when its lock has none', () => {
    const e = { holder: { pid: 7 } } as Parameters<typeof heldNote>[1]
    expect(heldNote('bob', e)).toBe('This session does not speak for bob; the session with pid 7 holds it.')
  })
})
