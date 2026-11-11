import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ElicitRequestSchema, type ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { generateSealingKey, serializeRecord, signRecord, toHex } from '@usebag/core'
import { KeyEpochStore, type RelayClient, RelayError, type Rng, setTelemetry, systemRng } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_MAX_TOOL_SECONDS,
  DEFAULT_PROGRESS_SECONDS,
  parseServerConfig,
  type ServerConfig,
} from '../src/config.ts'
import type { Desk } from '../src/desk.ts'
import { HeldError, type Opened } from '../src/open.ts'
import {
  type ProcessIo,
  REOPEN_MS,
  START_SPREAD_S,
  serve,
  startIdentities,
  type Unit,
} from '../src/server.ts'
import type { SubscriptionView } from '../src/subscriptions.ts'
import {
  acceptFrom,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { gatedRelay, MemoryRelay } from './support/relay.ts'
import { frames, StreamClientTransport } from './support/streams.ts'

// The multi-identity server: one MCP
// server over an --identities file, on the memory relay, beside a peer, bob, on a server of his own. The identities are
// personal (alice's key) and research (carol's), and side (jane's) where a third is needed. The rng draws every 4-byte
// jitter at its top (u just under 1), so the start waits and the keep-alive offset are known.

type Json = Record<string, unknown>
type RunningMany = Awaited<ReturnType<typeof startIdentities>>

const NA = 'not-authorized'
/** startDelayMs at u = (2^32 - 1) / 2^32. */
const SPREAD = Math.floor(0.999_999_999 * START_SPREAD_S * 1000)
const OWN = 'research is another identity of this server: never send to or pair with it'
const BODY = 'the body names another identity of this server: nothing was sent'

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let bob: TestServer
let files = 0
const open: { close(): Promise<void> }[] = []
const stdout = watchStdout()

/** A seeded rng whose 4-byte draws (the jitters) are all 0xff. */
function high(label: string): Rng {
  const base = seededRng(label)
  return { bytes: (n) => (n === 4 ? new Uint8Array(4).fill(0xff) : base.bytes(n)) }
}

/** An identity of the file, with its own home holding the party's key. */
function id(label: string, p: Party, more: Json = {}): Json {
  const home = join(tmp.dir, label)
  saveKeys(home, p)
  return { label, key: p.name, home, relays: [RELAY], trust_roots: [P.bob.address], ...more }
}

const two = (more: Json = {}): Json[] => [id('personal', P.alice, more), id('research', P.carol, more)]
const gone = (label: string): Json => ({ label, key: 'nobody', home: join(tmp.dir, label), relays: [RELAY] })

/** An identities file, 0600. */
function fileOf(identities: Json[], def?: string): string {
  const file = join(tmp.dir, `identities-${files++}.json`)
  const doc = { version: 1, ...(def === undefined ? {} : { default: def }), identities }
  writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
  return file
}

const configOf = (identities: Json[], args: string[] = [], def?: string): ServerConfig =>
  parseServerConfig(['--identities', fileOf(identities, def), ...args], {}) as ServerConfig

interface Many {
  readonly running: RunningMany
  readonly client: Client
  readonly log: MemoryLog
  readonly dialogs: string[]
  /** pair_invite's address questions, answered empty, kept apart from dialogs. */
  readonly questions: string[]
  call(tool: string, args?: Json): Promise<{ isError: boolean; value: Json }>
  unit(label: string): Unit
  close(): Promise<void>
}

interface Options {
  readonly args?: string[]
  readonly def?: string
  readonly alive?: (pid: number) => boolean
  readonly relayFor?: (label: string) => RelayClient
  /** Leaves the non-default identities waiting for their network start. */
  readonly waiting?: boolean
  /** The person's answers to the first dialogs, in order; every later dialog is cancelled. */
  readonly person?: ((message: string) => ElicitResult)[]
  /** The process's environment (default none: no HOME, so the machine's telemetry is off). */
  readonly env?: Readonly<Record<string, string>>
}

/** Starts the server, connects a client whose person answers as o.person says and, unless waiting, starts every network. */
async function many(identities: Json[], o: Options = {}): Promise<Many> {
  const log = new MemoryLog()
  const running = await startIdentities(configOf(identities, o.args, o.def), {
    clock,
    rng: high('many'),
    relayFor: (c) => o.relayFor?.(c.label) ?? relay,
    records: fakeRecords(new Map()),
    timers,
    pid: 4242,
    alive: o.alive ?? (() => false),
    log,
    resubscribeDelayMs: () => 0,
    pairPollMs: 2,
    ...(o.env === undefined ? {} : { env: o.env }),
  })
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  await running.mcp.connect(serverSide)
  const client = new Client(
    { name: 'multi-test', version: '0.0.0' },
    { capabilities: { elicitation: { form: {} } } },
  )
  const dialogs: string[] = []
  const questions: string[] = []
  client.setRequestHandler(ElicitRequestSchema, async (r) => {
    // pair_invite's address question, left empty: first contact.
    if (
      'requestedSchema' in r.params &&
      Object.keys(r.params.requestedSchema.properties).join() === 'address'
    ) {
      questions.push(r.params.message)
      return { action: 'accept', content: {} }
    }
    dialogs.push(r.params.message)
    return o.person?.shift()?.(r.params.message) ?? { action: 'cancel' }
  })
  await client.connect(clientSide)
  const m: Many = {
    running,
    client,
    log,
    dialogs,
    questions,
    async call(tool, args = {}) {
      const r = await client.callTool({ name: tool, arguments: args })
      const text = (r.content as { text: string }[])[0]?.text ?? '{}'
      return { isError: r.isError === true, value: JSON.parse(text) as Json }
    },
    unit: (label) => running.units.get(label) as Unit,
    async close() {
      await client.close()
      await running.stop()
    },
  }
  open.push(m)
  if (o.waiting !== true) {
    timers.fire((ms) => ms === SPREAD)
    await running.ready
  }
  return m
}

const accepted = (u: Unit): number => (u.desk as Desk).counts().counts.accepted
const lockOf = (label: string, p: Party): string => join(tmp.dir, label, 'state', p.name, 'mcp.lock')
const iso = (s: number): string => new Date(s * 1000).toISOString()
/** The mailboxes subscribed at the relay, but bob's. */
const mailboxes = (): string[] => [...relay.subs].map((s) => s.mailbox).filter((b) => b !== P.bob.address)

/** A server whose research identity another live server (pid 999) holds until `free()`. */
async function heldResearch(): Promise<{ m: Many; free(): void }> {
  let held = true
  const ids = two()
  mkdirSync(join(tmp.dir, 'research', 'state', 'carol'), { recursive: true })
  writeFileSync(lockOf('research', P.carol), JSON.stringify({ pid: 999 }))
  const m = await many(ids, { alive: (pid) => held && pid === 999 })
  return {
    m,
    free: () => {
      held = false
    },
  }
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('multi')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.alice, P.bob, P.carol, P.jane]) await publishAddress(relay, p)
  const home = join(tmp.dir, 'bob')
  saveKeys(home, P.bob)
  const trust = [P.alice, P.carol, P.jane].flatMap((p) => ['--trust-root', p.address])
  bob = await testServer({ home, name: 'bob', relay, clock, timers: new ManualTimers(), args: trust })
})

afterEach(async () => {
  // Past every invitation's end, so that a pairing's loops end before the servers stop (as pairing.test.ts).
  clock.t += 10_000
  await new Promise((r) => setTimeout(r, 30))
  for (const s of open.splice(0)) await s.close()
  await bob.close()
  tmp.cleanup()
  stdout.check()
})

describe('the tools of several identities', () => {
  it('lists the same names for one identity and for three, each identity tool taking as; delegate when one allows it', async () => {
    const one = (await bob.client.listTools()).tools
    const m = await many([...two(), id('side', P.jane, { allow_delegate: true })])
    const three = (await m.client.listTools()).tools
    expect(three.map((t) => t.name).sort()).toEqual([...one.map((t) => t.name), 'delegate'].sort())
    // The enterprise tools are home-level (the default identity's home): they take no as.
    const enterprise = ['connect', 'sign_in', 'enterprise_status']
    for (const t of three.filter((t) => !enterprise.includes(t.name)))
      expect(Object.keys(t.inputSchema.properties ?? {})).toContain('as')
    expect(three.filter((t) => enterprise.includes(t.name))).toHaveLength(3)
    expect(m.client.getInstructions()).toContain('Act only as the identity your user names')
    const hop = { to: P.bob.address, caveats: ['type=chat.*'], exp: '+60' }
    expect((await m.call('delegate', { as: 'personal', ...hop })).value).toMatchObject({ error: 'usage' })
    const granted = (await m.call('delegate', { as: 'side', ...hop })).value
    expect((granted.chain as Json[])[0]).toMatchObject({ iss: P.jane.address, sub: P.bob.address })
  })

  it('sends as personal from alice and as research from carol; an act without as is as-required, an unknown label unknown-identity', async () => {
    const m = await many(two())
    expect(await m.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })).toEqual({
      isError: true,
      value: {
        error: 'as-required',
        detail: 'send acts as one identity of several: pass as (the labels are personal, research)',
      },
    })
    expect((await m.call('lookup', { as: 'nobody', address: P.bob.address })).value).toEqual({
      error: 'unknown-identity',
      detail: 'as "nobody" names no identity of this server; the labels are personal, research',
    })
    await m.call('send', { as: 'personal', to: [P.bob.address], type: 'chat.v1', body: 1 })
    await m.call('send', { as: 'research', to: [P.bob.address], type: 'chat.v1', body: 2 })
    await until('bob has both', () => bob.running.desk.counts().counts.accepted === 2)
    const got = (await bob.call('inbox')).value.messages as { from: string; body: number }[]
    expect(got.map((g) => [g.body, g.from]).sort()).toEqual([
      [1, P.alice.address],
      [2, P.carol.address],
    ])
  })

  it('a server of one takes as naming its one identity, and refuses any other as unknown-identity', async () => {
    expect((await bob.call('status', { as: 'bob' })).value).toMatchObject({ address: P.bob.address })
    expect((await bob.call('status', { as: 'research' })).value).toEqual({
      error: 'unknown-identity',
      detail: 'as "research": this server holds one identity; omit as',
    })
  })

  it('reads take the default; inbox messages carry as; status without as is the summary, with as the full shape and label', async () => {
    const m = await many(two(), { def: 'research' })
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'to research' })
    await until('research has it', () => accepted(m.unit('research')) === 1)
    expect((await m.call('status')).value).toEqual({
      default: 'research',
      identities: [
        {
          label: 'personal',
          address: P.alice.address,
          state: 'running',
          code: null,
          relays: [RELAY],
          subscriptions: [expect.objectContaining({ relay: RELAY, state: 'subscribed' })],
          unread: 0,
          keep_alive_next_at: null,
          keep_alive_last: null,
          telemetry: { on: false, reason: 'no-file', choice: null },
        },
        expect.objectContaining({ label: 'research', address: P.carol.address, state: 'running', unread: 1 }),
      ],
      max_tool_seconds: DEFAULT_MAX_TOOL_SECONDS,
      progress_seconds: DEFAULT_PROGRESS_SECONDS,
      started_at: iso(T0),
      uptime_s: 0,
    })
    expect((await m.call('inbox')).value.messages).toMatchObject([{ body: 'to research', as: 'research' }])
    expect((await m.call('inbox', { as: 'personal' })).value.messages).toEqual([])
    expect((await m.call('status', { as: 'personal' })).value).toMatchObject({
      label: 'personal',
      address: P.alice.address,
      default_handler: 'queue',
    })
  })

  it("shows the machine's one telemetry switch (HOME/.bag) for every identity, in the summary and with as", async () => {
    const HOME = join(tmp.dir, 'machine')
    const m = await many(two(), { env: { HOME } })
    setTelemetry(join(HOME, '.bag'), 'on', systemRng)
    const on = { on: true, reason: 'file', choice: 'on' }
    const rows = ((await m.call('status')).value.identities as Json[]).map((r) => [r.label, r.telemetry])
    expect(rows).toEqual([
      ['personal', on],
      ['research', on],
    ])
    // An identity's home holds no switch of its own: a choice written there is not read.
    setTelemetry(join(tmp.dir, 'research'), 'off', systemRng)
    expect((await m.call('status', { as: 'research' })).value.telemetry).toEqual(on)
  })

  it('status tells an identity the relay never admitted from one it did, with the last error, as and without as', async () => {
    const full = gatedRelay(relay, 'close')
    const m = await many(two(), { relayFor: (label) => (label === 'research' ? full.client : relay) })
    await until('the closes', () => full.dials() >= 3)
    const { identities } = (await m.call('status')).value as {
      identities: { subscriptions: SubscriptionView[] }[]
    }
    const [personal, research] = identities.map((i) => i.subscriptions)
    const refused = {
      relay: RELAY,
      state: 'retrying',
      refusals: 0,
      last_code: 'unreachable',
      last_at: iso(T0),
    }
    expect(research).toEqual([refused])
    expect(personal).toEqual([
      { relay: RELAY, state: 'subscribed', refusals: 0, last_code: null, last_at: null },
    ])
    expect((await m.call('status', { as: 'research' })).value.subscriptions).toEqual([refused])
  })

  it("wait as personal is not woken by research's message; its token carries the label, and resume alone acts as it", async () => {
    const m = await many(two())
    const waiting = m.call('wait', { as: 'personal', timeout_s: 1 })
    let settled = false
    void waiting.then(() => {
      settled = true
    })
    await until('the wait is pending', () => timers.live().includes(1000))
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'not for personal' })
    await until('research has it', () => accepted(m.unit('research')) === 1)
    expect(settled).toBe(false)
    timers.fire((ms) => ms === 1000)
    expect((await waiting).value).toEqual({
      timed_out: true,
      pending: false,
      resume: `personal:r1.0.${T0 + 1}.any`,
    })
    await m.call('inbox', { as: 'research' })
    const token = (await m.call('wait', { as: 'research', timeout_s: 0 })).value.resume as string
    expect(token).toMatch(/^research:r1\.\d+\./)
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'later' })
    await until('research has the second', () => accepted(m.unit('research')) === 2)
    const resumed = await m.call('wait', { resume: token, timeout_s: 0 })
    expect(resumed.value.message).toMatchObject({ body: 'later', as: 'research' })
    expect((await m.call('wait', { as: 'personal', resume: token })).value).toEqual({
      error: 'usage',
      detail: "this resume token is research's, not personal's: pass resume alone",
    })
    const bare = token.slice('research:'.length)
    expect((await m.call('wait', { resume: bare })).value).toMatchObject({ error: 'usage' })
  })
})

describe('the guards: nothing that links two identities is sent', () => {
  it('to-own-identity: a send, ask, handoff, lookup or pairing addressed to another identity of this server', async () => {
    const m = await many(two())
    const before = relay.published.length
    const own = { error: 'to-own-identity', detail: OWN }
    const as = 'personal'
    const to = P.carol.address
    expect((await m.call('send', { as, to: [to], type: 'chat.v1', body: 1 })).value).toEqual(own)
    expect((await m.call('ask', { as, to, body: 1 })).value).toEqual(own)
    expect((await m.call('handoff', { as, to, threads: ['a'.repeat(64)] })).value).toEqual(own)
    expect((await m.call('lookup', { as, address: to })).value).toEqual(own)
    expect((await m.call('pair_invite', { as, name: 'carol', for: to })).value).toEqual(own)
    expect((await m.call('pair_accept', { as, name: 'carol', for: to })).value).toEqual(own)
    expect(relay.published.length).toBe(before)
  })

  it("body-names-other-identity: either form of another identity's address, in a body, a type or caveats; the detail names neither", async () => {
    const m = await many(two({ allow_delegate: true }))
    const hex = P.carol.address.slice('ed25519:'.length)
    const send = { as: 'personal', to: [P.bob.address], type: 'chat.v1' }
    const refused = { error: 'body-names-other-identity', detail: BODY }
    for (const body of [{ note: `ask ${P.carol.address}` }, `x${hex}y`])
      expect((await m.call('send', { ...send, body })).value).toEqual(refused)
    expect((await m.call('send', { ...send, type: `chat.${hex}`, body: 1 })).value).toEqual(refused)
    const hop = { as: 'personal', to: P.bob.address, caveats: [`repo=${hex}`], exp: '+60' }
    expect((await m.call('delegate', hop)).value).toEqual(refused)
    const asked = await m.call('ask', { as: 'personal', to: P.bob.address, body: hex, timeout_s: 0 })
    expect(asked.value).toEqual(refused)
    // Its own address and a peer's pass.
    const fine = { note: `${P.alice.address} and ${P.bob.address}` }
    expect((await m.call('send', { ...send, body: fine })).isError).toBe(false)
  })

  it("thread-of-other-identity: a reply or handoff as personal on research's thread, its message left unread; as research it goes", async () => {
    const m = await many(two())
    const sent = (await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'q' })).value
    await until('research has it', () => accepted(m.unit('research')) === 1)
    const thread = { id: (sent.thread as { id: string }).id, prev: [sent.id] }
    const reply = { to: [P.bob.address], type: 'chat.v1', body: 'a', thread }
    expect((await m.call('send', { as: 'personal', ...reply })).value).toEqual({
      error: 'thread-of-other-identity',
      detail: "that thread is research's: answer it as research",
    })
    const handoff = { as: 'personal', to: P.bob.address, threads: [thread.id] }
    expect((await m.call('handoff', handoff)).value).toMatchObject({ error: 'thread-of-other-identity' })
    // The probe reads research's store only: its message is still unread.
    expect((m.unit('research').desk as Desk).counts().counts.unread).toBe(1)
    expect((await m.call('send', { as: 'research', ...reply })).isError).toBe(false)
  })

  it('sees an identity that failed to open (busy) by its key, read without the lock: to it or naming it is refused', async () => {
    const { m } = await heldResearch()
    expect([m.unit('research').state, m.unit('research').address]).toEqual(['failed', P.carol.address])
    const before = relay.published.length
    const send = { as: 'personal', type: 'chat.v1' }
    expect((await m.call('send', { ...send, to: [P.carol.address], body: 1 })).value).toEqual({
      error: 'to-own-identity',
      detail: OWN,
    })
    const hex = P.carol.address.slice('ed25519:'.length)
    expect((await m.call('send', { ...send, to: [P.bob.address], body: hex })).value).toEqual({
      error: 'body-names-other-identity',
      detail: BODY,
    })
    expect(relay.published.length).toBe(before)
  })

  it('cannot see an identity whose key cannot be read (the documented residual): a send to its address goes', async () => {
    const ids = [id('personal', P.alice), { ...gone('research'), key: 'carol' }]
    const m = await many(ids)
    expect([m.unit('research').state, m.unit('research').address]).toEqual(['failed', null])
    const r = await m.call('send', { as: 'personal', to: [P.carol.address], type: 'chat.v1', body: 1 })
    expect(r.isError).toBe(false)
  })

  it('a thread both identities hold (one envelope to both) is answered as either', async () => {
    const m = await many(two())
    const sent = (
      await bob.call('send', { to: [P.alice.address, P.carol.address], type: 'chat.v1', body: 'q' })
    ).value
    await until('both have it', () => accepted(m.unit('personal')) + accepted(m.unit('research')) === 2)
    const thread = { id: (sent.thread as { id: string }).id, prev: [sent.id] }
    const reply = { to: [P.bob.address], type: 'chat.v1', body: 'a', thread }
    expect((await m.call('send', { as: 'personal', ...reply })).isError).toBe(false)
    expect((await m.call('send', { as: 'research', ...reply })).isError).toBe(false)
  })

  it("a sibling's inbox row whose content is not JSON is no thread: the guard reads past it", async () => {
    const m = await many(two())
    const { store } = m.unit('research').opened as Opened
    const row = store.inboxAdd('http://other.test', P.carol.address, 1, new TextEncoder().encode('x'), 0)
    store.inboxPut(row, { state: 'rejected', reason: 'bad-json', content: 'not json' }, 0)
    const handoff = { as: 'personal', to: P.bob.address, threads: ['b'.repeat(64)] }
    expect((await m.call('handoff', handoff)).isError).toBe(false)
  })
})

describe('read receipts per identity', () => {
  it('the receipts tool takes as, like any tool of one identity, and reads that identity alone', async () => {
    const m = await many(two())
    const id = 'a'.repeat(64)
    const { store } = m.unit('research').opened as Opened
    store.receiptAdd(id, P.bob.address, 5)
    expect((await m.call('receipts', { id })).value).toMatchObject({ error: 'as-required' })
    expect((await m.call('receipts', { as: 'research', id })).value).toEqual({
      id,
      receipts: [{ reader: P.bob.address, at: 5 }],
    })
    expect((await m.call('receipts', { as: 'personal', id })).value).toEqual({ id, receipts: [] })
  })
})

describe('pairing per identity', () => {
  it("one live pairing per server, across identities, so a sibling's invite meets busy; its token carries the label", async () => {
    const m = await many(two())
    const invite = await m.call('pair_invite', { as: 'personal', name: 'bob' })
    expect(invite.value.resume).toMatch(/^personal:[0-9a-f]{32}$/)
    expect((await m.call('pair_accept', { as: 'research', name: 'alice' })).value).toMatchObject({
      error: 'busy',
    })
  })

  it("the first dialog line names the identity that pairs, within the dialog's 60 characters", async () => {
    const m = await many(two())
    const r = await m.call('pair_accept', { as: 'research', name: 'bob' })
    expect(r.value).toMatchObject({ error: 'cancelled' })
    expect(m.dialogs.map((d) => d.split('\n')[0])).toEqual(["As research: paste your peer's code."])
  })

  it("pair_invite's first question says it makes a code, naming the identity; 60 characters with a 32-character label", async () => {
    const m = await many(two())
    await m.call('pair_invite', { as: 'personal', name: 'bob' })
    expect(m.questions.map((q) => q.split('\n')[0])).toEqual(['As personal: make a code for a peer.'])
    expect(`As ${'a'.repeat(32)}: make a code for a peer.`.length).toBeLessThanOrEqual(60)
  })

  it('both digit dialogs name the identity too: the acceptor reading out, the inviter typing', async () => {
    const inviter = await many(two(), { person: [() => ({ action: 'decline' })] })
    const invited = await inviter.call('pair_invite', { as: 'personal', name: 'jane' })
    const invite = invited.value.invite as string
    const confirm = { action: 'accept', content: { confirm: true } } as const
    const acceptor = await many([id('laptop', P.jane)], {
      person: [() => ({ action: 'accept', content: { invite } }), () => confirm],
    })
    await acceptor.call('pair_accept', { as: 'laptop', name: 'alice' })
    const out = await inviter.call('pair_invite', { resume: invited.value.resume })
    expect(out.value).toMatchObject({ error: 'declined' })
    const line = acceptor.dialogs[1]?.split('\n')[0] as string
    expect(line).toMatch(/^As laptop, check digits: \d{3} \d{3}$/)
    expect(inviter.dialogs.map((d) => d.split('\n')[0])).toEqual(['As personal: type the six digits.'])
    const digits = line.slice(-7)
    for (const d of [digits, digits.replace(' ', '')]) expect(inviter.dialogs.join('\n')).not.toContain(d)
  })
})

describe('push and resource, per label', () => {
  it('the channel notice names the label; one inbox resource per identity, updated only for its own', async () => {
    const m = await many(two(), { args: ['--push', 'channel', '--push', 'resource'] })
    const seen: { method: string; params?: unknown }[] = []
    m.client.fallbackNotificationHandler = async (n) => {
      seen.push({ method: n.method, params: n.params })
    }
    const uris = (await m.client.listResources()).resources.map((r) => r.uri)
    expect(uris).toEqual(['bag://inbox/personal', 'bag://inbox/research'])
    await m.client.subscribeResource({ uri: 'bag://inbox/research' })
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 1 })
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 2 })
    await until('both delivered', () => accepted(m.unit('personal')) + accepted(m.unit('research')) === 2)
    await m.client.ping()
    const channel = seen
      .filter((s) => s.method === 'notifications/claude/channel')
      .map((s) => (s.params as { content: string }).content)
    expect(channel).toHaveLength(2)
    expect(channel.some((c) => c.includes(`from ${P.bob.address} to personal, type chat.v1`))).toBe(true)
    expect(channel.some((c) => c.includes(`from ${P.bob.address} to research, type chat.v1`))).toBe(true)
    expect(seen.filter((s) => s.method === 'notifications/resources/updated')).toEqual([
      { method: 'notifications/resources/updated', params: { uri: 'bag://inbox/research' } },
    ])
  })
})

describe('failure isolation', () => {
  it('one key missing: the server starts, that identity is failed with its code and retried, the others work', async () => {
    const m = await many([...two(), gone('gone')])
    expect(((await m.call('status')).value.identities as Json[])[2]).toMatchObject({
      label: 'gone',
      address: null,
      state: 'failed',
      code: 'ENOENT',
    })
    expect((await m.call('status', { as: 'gone' })).value).toMatchObject({ error: 'ENOENT' })
    expect(timers.live()).toEqual([REOPEN_MS])
    const sent = await m.call('send', { as: 'personal', to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect(sent.isError).toBe(false)
    expect(m.log.lines.filter((l) => l.event === 'start' && l.level === 'error')).toEqual([
      { level: 'error', event: 'start', fields: expect.objectContaining({ code: 'ENOENT', label: 'gone' }) },
    ])
  })

  it('every identity missing: no server, the first code and each label in the detail, nothing left to retry', async () => {
    const deps = {
      clock,
      rng: high('none'),
      relayFor: () => relay,
      timers,
      pid: 4242,
      alive: () => false,
      log: new MemoryLog(),
    }
    await expect(startIdentities(configOf([gone('a'), gone('b')]), deps)).rejects.toMatchObject({
      code: 'ENOENT',
      message: expect.stringContaining('no identity could be opened (a ENOENT, b ENOENT)'),
    })
    expect(timers.live()).toEqual([])
  })

  it('busy while another server holds an identity, then opened at the retry, started after its spread, subscriptions reset', async () => {
    const { m, free } = await heldResearch()
    expect(m.unit('research').state).toBe('failed')
    expect((await m.call('inbox', { as: 'research' })).value).toMatchObject({ error: 'busy' })
    free()
    timers.fire((ms) => ms === REOPEN_MS)
    // Opened again at once, but a non-default identity subscribes only after a new start wait (the seeded 0xff draw).
    expect([m.unit('research').state, timers.live()]).toEqual(['starting', [SPREAD]])
    await new Promise((r) => setTimeout(r, 20))
    expect(mailboxes()).toEqual([P.alice.address])
    timers.fire((ms) => ms === SPREAD)
    await until('research runs', () => m.unit('research').state === 'running')
    expect(m.unit('research').subscriptions.list()).toMatchObject([{ state: 'subscribed', refusals: 0 }])
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'after the retry' })
    await until('research has it', () => accepted(m.unit('research')) === 1)
  })

  it('held: status and facts as that identity say who holds it; held_since is null from the start, the time once it had the identity', async () => {
    const { m, free } = await heldResearch()
    const fromStart = (await m.call('facts', { as: 'research' })).value
    expect(fromStart).toMatchObject({
      held: true,
      held_by: { pid: 999, path: lockOf('research', P.carol) },
      note: 'This session does not speak for carol; the session with pid 999 holds it.',
      held_since: null,
      held_from_start: true,
      host_facts: null,
      host_facts_state: 'held',
    })
    expect((await m.call('status', { as: 'research' })).value).toMatchObject({
      held: true,
      held_from_start: true,
    })
    free()
    timers.fire((ms) => ms === REOPEN_MS)
    timers.fire((ms) => ms === SPREAD)
    await until('research runs', () => m.unit('research').state === 'running')
    // It had the identity; another session takes it (as a reopening after a failure would find it).
    const u = m.unit('research')
    await u.shut()
    u.opened = null
    clock.t += 7
    u.failure = new RelayError(null, 0, null, 'down')
    u.failure = new HeldError('carol', { pid: 998 }, lockOf('research', P.carol))
    clock.t += 3
    u.failure = new HeldError('carol', { pid: 998 }, lockOf('research', P.carol))
    expect((await m.call('facts', { as: 'research' })).value).toMatchObject({
      held: true,
      held_by: { pid: 998 },
      held_since: iso(clock.now() - 3),
      held_from_start: false,
    })
    u.failure = null
    expect(u.heldSince).toBeNull()
  })

  it('a stopped server opens nothing again: the reopen timer of a failed identity is cancelled at stop', async () => {
    const { m, free } = await heldResearch()
    expect(timers.live()).toEqual([REOPEN_MS])
    open.splice(open.indexOf(m), 1)
    await m.close()
    free()
    expect(timers.live()).toEqual([])
    timers.fire()
    await new Promise((r) => setTimeout(r, 20))
    expect(JSON.parse(readFileSync(lockOf('research', P.carol), 'utf8'))).toEqual({ pid: 999 })
    expect(mailboxes()).toEqual([])
  })

  it("one identity's relay refusing three times: its wait returns refused, the other's gets its message", async () => {
    const m = await many(two())
    relay.refuse(RELAY, P.alice.address, NA, NA, NA)
    await until('personal refused', () => m.unit('personal').subscriptions.refused() !== null)
    expect((await m.call('wait', { as: 'personal', timeout_s: 5 })).value).toMatchObject({
      timed_out: false,
      pending: false,
      resume: expect.stringMatching(/^personal:/),
      mailbox: `refused: ${NA}`,
    })
    const waiting = m.call('wait', { as: 'research', timeout_s: 5 })
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'still here' })
    expect((await waiting).value.message).toMatchObject({ body: 'still here', as: 'research' })
  })

  it("a throw in one identity's accepted is logged with its label; the other keeps receiving", async () => {
    const m = await many(two())
    ;(m.unit('personal').desk as Desk).take = () => {
      throw new Error('cannot read the row')
    }
    await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 1 })
    await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 2 })
    await until('the notice error', () => m.log.lines.some((l) => l.event === 'notice'))
    expect(m.log.lines.find((l) => l.event === 'notice')?.fields).toMatchObject({
      label: 'personal',
      code: 'internal',
    })
    await until('research has it', () => accepted(m.unit('research')) === 1)
  })

  it("a stop where one identity's edge stop throws releases every lock", async () => {
    const m = await many(two())
    const locks = (): boolean[] => [
      existsSync(lockOf('personal', P.alice)),
      existsSync(lockOf('research', P.carol)),
    ]
    expect(locks()).toEqual([true, true])
    const { edge } = m.unit('personal').opened as Opened
    const stop = edge.stop.bind(edge)
    edge.stop = async () => {
      await stop()
      throw new Error('the stop failed')
    }
    open.splice(open.indexOf(m), 1)
    await m.close()
    expect(locks()).toEqual([false, false])
  })
})

describe('timing and separation', () => {
  it('opens every identity before any subscribes; the default at once, the others after startDelayMs', async () => {
    const labels = ['personal', 'research', 'side']
    const locks = (): boolean[] =>
      labels.map((l, i) => existsSync(lockOf(l, [P.alice, P.carol, P.jane][i] as Party)))
    const wire: Record<string, string[]> = {}
    const order: string[] = []
    // Each identity's own client: it records every call's arguments, and the locks held at each subscribe.
    const spy = (label: string): RelayClient => {
      const calls: string[] = []
      wire[label] = calls
      const text = (a: unknown): string =>
        a instanceof Uint8Array ? new TextDecoder().decode(a) : String(JSON.stringify(a))
      return new Proxy(relay, {
        get: (t, k) => {
          const v = Reflect.get(t, k) as unknown
          if (
            typeof v !== 'function' ||
            !['publish', 'fetch', 'fetchRecord', 'subscribe'].includes(String(k))
          )
            return v
          return (...args: unknown[]) => {
            calls.push(args.map(text).join(' '))
            if (k === 'subscribe') order.push(`${label} ${locks().join()}`)
            return (v as (...a: unknown[]) => unknown).apply(t, args)
          }
        },
      })
    }
    const m = await many([...two(), id('side', P.jane)], { def: 'research', waiting: true, relayFor: spy })
    expect(Object.keys(wire)).toEqual(labels)
    await until('research subscribed', () => mailboxes().length === 1)
    // The first subscription came after every identity had taken its lock.
    expect(order).toEqual(['research true,true,true'])
    expect([timers.live(), m.unit('personal').state]).toEqual([[SPREAD, SPREAD], 'starting'])
    timers.fire((ms) => ms === SPREAD)
    await m.running.ready
    // A shared relay holds one subscription per mailbox, each made by its identity's own client.
    expect(mailboxes().sort()).toEqual([P.alice.address, P.carol.address, P.jane.address].sort())
    await m.call('send', { as: 'personal', to: [P.bob.address], type: 'chat.v1', body: 'x' })
    // Nothing personal's client sent or asked for (envelopes, records, subscriptions, hops) names research or a label.
    const bytes = wire.personal?.join('\n') ?? ''
    expect(bytes).toContain(P.alice.address)
    expect(bytes).not.toMatch(new RegExp(`${P.carol.address.slice(8)}|research|personal`))
  })

  it('keeps a record alive with its own offset in [0, ttl / 10) after half the ttl', async () => {
    const ids = [id('personal', P.alice, { keep_alive_records: true }), id('research', P.carol)]
    const epochs = new KeyEpochStore(join(tmp.dir, 'personal', 'key-records'))
    const key = generateSealingKey((n) => new Uint8Array(n).fill(0x42))
    epochs.put(P.alice.address, 1, key, T0, T0 + 86_400)
    epochs.markPublished(P.alice.address, 1)
    const record = signRecord(P.alice.keys.signing, {
      kind: 'address',
      key: P.alice.address,
      sealing_key: toHex(P.alice.keys.sealing.publicKey),
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 600,
      iat: T0,
      rotated_from: null,
    })
    await relay.publish(RELAY, serializeRecord(record))
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice)))
    const m = await many(ids)
    await until('the first cycle', () => m.unit('personal').records?.status().last !== null)
    // u just under 1: 300 + floor(u × 600 / 10) = 359 (a server of one: 300, keepalive.test.ts).
    expect(m.unit('personal').records?.status().next_at).toBe(iso(T0 + 359))
  })

  it("status without as gives each identity's last keep-alive, with the code of its failure", async () => {
    const ids = [id('personal', P.alice, { keep_alive_records: true }), id('research', P.carol)]
    relay.failRecords = new RelayError(null, 0, null, 'connection refused')
    const m = await many(ids)
    await until('the first cycle', () => m.unit('personal').records?.status().last !== null)
    relay.failRecords = null
    const { identities } = (await m.call('status')).value as { identities: Json[] }
    expect(identities.map((i) => i.keep_alive_last)).toEqual([
      { at: iso(T0), outcome: 'unreachable', published: 0, failed: 0, code: 'unreachable' },
      null,
    ])
  })
})

describe('serve with --identities', () => {
  type TestIo = ProcessIo & {
    readonly stdin: PassThrough
    readonly stdout: PassThrough
    readonly out: Buffer[]
    readonly err: string[]
  }

  function io(argv: string[], seen: unknown[], env: ProcessIo['env'] = {}): TestIo {
    const stdin = new PassThrough()
    const pipe = new PassThrough()
    const out: Buffer[] = []
    pipe.on('data', (c: Buffer) => out.push(c))
    const err: string[] = []
    const quiet = { log: () => {}, info: () => {}, debug: () => {}, warn: () => {}, error: () => {} }
    return {
      argv,
      env,
      stdin,
      stdout: pipe,
      stderr: { write: (t: string) => err.push(t) },
      clock,
      rng: seededRng('serve'),
      relay: (d) => {
        seen.push(d)
        return relay
      },
      records: fakeRecords(new Map()),
      timers,
      pid: 4242,
      alive: () => false,
      signals: new EventEmitter() as unknown as ProcessIo['signals'],
      console: quiet,
      out,
      err,
    }
  }

  it('makes one relay client per identity, each with its own jittered reconnect wait, passes the environment, and writes only frames', async () => {
    const seen: unknown[] = []
    const HOME = join(tmp.dir, 'machine')
    const t = io(['--identities', fileOf(two())], seen, { DO_NOT_TRACK: '1', HOME })
    setTelemetry(join(HOME, '.bag'), 'on', systemRng)
    const done = serve(t)
    const client = new Client({ name: 'in-process', version: '0.0.0' })
    await client.connect(new StreamClientTransport(t.stdin, t.stdout))
    expect((await client.listTools()).tools).toHaveLength(14)
    // The process's DO_NOT_TRACK reaches the machine's switch: a person's yes stays off under it.
    const status = await client.callTool({ name: 'status', arguments: { as: 'research' } })
    expect(JSON.parse((status.content as { text: string }[])[0]?.text ?? '{}').telemetry).toEqual({
      on: false,
      reason: 'DO_NOT_TRACK',
      choice: 'on',
    })
    await client.close()
    expect(await done).toBe(0)
    expect(seen).toHaveLength(2)
    for (const d of seen as ((attempt: number) => number)[]) {
      expect(d(0)).toBeGreaterThanOrEqual(125)
      expect(d(0)).toBeLessThan(375)
      expect(d(30)).toBeLessThanOrEqual(30_000)
    }
    expect(frames(Buffer.concat(t.out)).bad).toEqual([])
  })

  it('makes the one client of a server of one without a reconnect wait of its own', async () => {
    const seen: unknown[] = []
    saveKeys(join(tmp.dir, 'personal'), P.alice)
    const t = io(['--as', 'alice', '--dir', join(tmp.dir, 'personal'), '--relay', RELAY], seen)
    const done = serve(t)
    await until('started', () => t.err.join('').includes('"event":"start"'))
    t.stdin.end()
    expect(await done).toBe(0)
    expect(seen).toEqual([undefined])
  })

  it('exits 1 when no identity can be opened', async () => {
    expect(await serve(io(['--identities', fileOf([gone('a')])], []))).toBe(1)
  })
})
