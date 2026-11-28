import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ElicitRequestSchema, type ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import {
  type AddressRecord,
  buildEnvelope,
  newThread,
  parseEnvelope,
  parseRecord,
  SUITE,
  signHop,
} from '@usebag/core'
import {
  type EdgeKeys,
  HomeCustody,
  INVITE_PREFIX,
  keepAddressCopy,
  LOCAL_RELAY,
  readInvite,
} from '@usebag/edge'
import { fetchTripwire, relayTripwire } from '@usebag/edge/test-support'
import { type HomeIo, keepFirstRecordsLocal, readRemoved, recordRemoved } from '@usebag/home'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LINK_ASK_MS, MAX_ASK_MS } from '../src/ask.ts'
import { pairingsOfTable, type ServiceConnection } from '../src/binding.ts'
import { parseConfig, parseServerConfig, type ServerConfig } from '../src/config.ts'
import { dropLocalPair, localPeersPath, localWordPath, spoolDir, wordRefusal } from '../src/local.ts'
import {
  BRIDGE_SHOW,
  BUSY,
  BUSY_HERE,
  CLOSING,
  FAST_ANSWER_MS,
  HIDE_WORDS,
  LINK_AGAIN,
  LINK_DIGITS,
  makingLine,
  OLD_EXTENSION,
  type Pairings,
  SHOW_EVERY_S,
} from '../src/pairing.ts'
import { type Running, startServer } from '../src/server.ts'
import { CONSENT_BRIDGE, Service, type ServiceDeps } from '../src/service.ts'
import { DIALOG_META, SUBAGENT_META } from '../src/socket.ts'
import type { Peer } from '../src/socket-owner.ts'
import { HOME_NOTE, HOME_OFF, LOCAL_ASK_DAYS, LOCAL_HELD_MAX, OTHERS_NOTE, SHORT_NOTE } from '../src/tools.ts'
import { SETTLE_MS } from '../src/wake-router.ts'
import {
  addressRecord,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  RELAY,
  saveKeys,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { party } from './support/ports.ts'
import { MemoryRelay } from './support/relay.ts'

// Delivery between identities of one home in the bag service (spec/SPEC.md 9.2), over its socket as a
// host reaches it: with the home word off every guard answers as before; on, a local pair is one dialog that writes
// only the service's table, and mail between the pair goes through the recipient's own receive path with no relay
// request (M1 to M6). personal is alice's key, research carol's, in one home; bob is a wire peer.

type Json = Record<string, unknown>

let home: string
let relay: MemoryRelay
let log: MemoryLog
const live: Service[] = []
const sockets: Socket[] = []
/** The labels start lists with relays [] (on this machine only), and the tripwire every one of them gets. */
let localOnly: readonly string[] = []
let wire = relayTripwire()
/** The record source (DNS, well-known, a relay's record) of every start with an identity on this machine only. */
let lookups = fetchTripwire()

beforeEach(() => {
  home = mkdtempSync('/tmp/bsl-')
  relay = new MemoryRelay()
  log = new MemoryLog()
  localOnly = []
  wire = relayTripwire()
  lookups = fetchTripwire()
})
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const s of live.splice(0)) await s.drain()
  rmSync(home, { recursive: true, force: true })
})

const OWN = 'is another identity of this server: never send to or pair with it'

/** The home word, as the CLI writes it. */
function word(on: boolean): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  writeFileSync(localWordPath(home), JSON.stringify({ version: 1, local_delivery: on ? 'on' : 'off' }), {
    mode: 0o600,
  })
}

/** The home word on with `label` hidden, as a dialog's hide writes it. */
function hide(label: string): void {
  const body = { version: 2, local_delivery: 'on', hidden: [label] }
  writeFileSync(localWordPath(home), JSON.stringify(body), { mode: 0o600 })
}

/** The changes after a request that stop it: the word off, the recipient hidden, the sender hidden. */
const CHANGES: [string, () => void][] = [
  ['the word turned off', () => word(false)],
  ['the recipient hidden', () => hide('research')],
  ['the sender hidden', () => hide('personal')],
]

/**
 * The person's pace on the service's monotonic clock: a scripted window's answer is the person's only when it comes
 * after FAST_ANSWER_MS (0.4.4: any faster answer is unseen), so window() moves this skew 300 ms just before it sends an
 * accept. A decline or a cancel it sends stays instant: these tests use them for a host's own answer, which is unseen.
 */
const pace = { skew: 0 }

async function start(
  more: Partial<ServiceDeps> = {},
  entry: Json = {},
  keychain: Party[] = [],
  agent: Party[] = [],
  others: [string, Party][] = [],
  prep: () => void = () => {},
): Promise<Service> {
  const ids: [string, Party][] = [['personal', P.alice], ['research', P.carol], ...others]
  for (const [label, p] of ids) {
    if (agent.includes(p)) new HomeCustody(home).agent.create(p.name, p.keys)
    else if (keychain.includes(p)) {
      mkdirSync(join(home, 'keychain'), { recursive: true, mode: 0o700 })
      // A keychain pointer as KeychainCustody writes it; the item itself is never read (openKeys stands in).
      const pointer = {
        suite: SUITE,
        custody: 'keychain',
        access: 'prompt',
        address: p.address,
        keychain: null,
      }
      writeFileSync(join(home, 'keychain', `${p.name}.json`), JSON.stringify(pointer), {
        mode: 0o600,
      })
    } else saveKeys(home, p)
    // The home's own copy of each address record, as onboard keeps it: where a local seal reads the sealing key. An
    // identity on this machine only has the first records identity_create keeps instead (epoch 1, unpublished).
    if (!localOnly.includes(label)) keepAddressCopy(home, p.name, addressRecord(p))
    else
      keepFirstRecordsLocal(
        { clock: new FakeClock(), rng: seededRng(label) } as unknown as HomeIo,
        home,
        p.name,
        p.keys,
      )
  }
  const identities = ids.map(([label, p]) => ({
    label,
    key: p.name,
    home,
    relays: localOnly.includes(label) ? [] : [RELAY],
    trust_roots: [P.bob.address],
    ...entry,
  }))
  const file = join(home, 'identities.json')
  writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
  const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
  const deps: ServiceDeps = {
    clock: new FakeClock(),
    rng: seededRng('service-local'),
    relayFor: (c) => (c.relays.length === 0 ? wire : relay),
    records: localOnly.length > 0 ? () => lookups : fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4243,
    alive: () => false,
    // The registering extension is the omp it names (socket-owner.ts peerIs answers match); a test changes it.
    peer: async () => 'match',
    log,
    resubscribeDelayMs: () => 0,
    helloMs: 300,
    drainCallsMs: 200,
    returnWaitMs: 300,
    mono: () => performance.now() + pace.skew,
    ...more,
  }
  prep() // the test's last change to the home before the service starts
  const s = await Service.start(config, home, deps)
  live.push(s)
  await s.opening
  return s
}

interface Line {
  request(method: string, params?: Json): Promise<Json>
  next(pick: (m: Json) => boolean): Promise<Json>
  /** How many messages that `pick` takes have arrived and not been taken by next. */
  count(pick: (m: Json) => boolean): number
  send(m: Json): void
  /** Several messages in one write, so the service reads them in one go. */
  sendAll(ms: Json[]): void
  /** The dialogs this window was shown, by message. */
  readonly dialogs: string[]
}

/** A window bound to `label`; `hello` replaces members of its hello (an omp window: no elicitation, the bridge). */
async function window(
  s: Service,
  label: string,
  answer: boolean | null | 'never' | 'decline' | 'decline-late' | 'empty' | 'cancel-late' | Json = true,
  hello: Json = {},
): Promise<Line> {
  const line = await connected(s, label, hello)
  expect((await line.request('service/use', { label, via: 'typed' })).result).toMatchObject({ bound: true })
  // The person: every confirm dialog answered `answer` (null cancels it; 'never' leaves it to the test).
  if (answer === 'never') return line
  void (async () => {
    for (;;) {
      const req = await line.next((m) => m.method === 'elicitation/create')
      const params = req.params as Json
      line.dialogs.push(String(params.message))
      const handle = (params._meta as Json)[DIALOG_META]
      const result =
        answer === null || answer === 'cancel-late'
          ? { action: 'cancel' }
          : answer === 'decline' || answer === 'decline-late'
            ? { action: 'decline' }
            : answer === 'empty'
              ? { action: 'accept', content: {} }
              : typeof answer === 'object'
                ? { action: 'accept', content: answer }
                : { action: 'accept', content: { confirm: answer } }
      // 'cancel-late': the person saw the dialog and closed it, at a person's pace.
      // 'decline-late': a host's own decline that came after FAST_ANSWER_MS (a loaded machine, 2026-11-23).
      if (result.action === 'accept' || answer === 'cancel-late' || answer === 'decline-late')
        pace.skew += 300
      line.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } })
    }
  })().catch(() => {})
  return line
}

/** A connection past its hello at cwd /w/<label>, bound to nothing. */
async function connected(s: Service, label: string, hello: Json = {}): Promise<Line> {
  const socket = createConnection(s.paths.sock)
  sockets.push(socket)
  await new Promise<void>((r) => socket.once('connect', () => r()))
  const seen: Json[] = []
  const waiters: { pick: (m: Json) => boolean; resolve: (m: Json) => void }[] = []
  let buf = ''
  socket.on('data', (b: Buffer) => {
    buf += b.toString()
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const m = JSON.parse(buf.slice(0, i)) as Json
      buf = buf.slice(i + 1)
      const w = waiters.findIndex((x) => x.pick(m))
      if (w >= 0) waiters.splice(w, 1)[0]?.resolve(m)
      else seen.push(m)
    }
  })
  let id = 100
  const line: Line = {
    dialogs: [],
    count: (pick) => seen.filter(pick).length,
    send: (m) => socket.write(`${JSON.stringify(m)}\n`),
    sendAll: (ms) => socket.write(ms.map((m) => `${JSON.stringify(m)}\n`).join('')),
    next: (pick) => {
      const i = seen.findIndex(pick)
      if (i >= 0) return Promise.resolve(seen.splice(i, 1)[0] as Json)
      return new Promise((resolve) => waiters.push({ pick, resolve }))
    },
    async request(method, params = {}) {
      const n = ++id
      line.send({ jsonrpc: '2.0', id: n, method, params })
      return line.next((m) => m.id === n)
    },
  }
  const said = await line.request('service/hello', {
    contract: 1,
    token: s.token.toString('hex'),
    host: 'claude-code',
    cwd: `/w/${label}`,
    client_capabilities: { elicitation: { form: {} } },
    input_hook: true,
    ...hello,
  })
  expect(said.result, JSON.stringify(said)).toBeDefined()
  // 0.4.2: no hello reply names a bridge folder.
  expect((said.result as Json).bridge_dir).toBeUndefined()
  return line
}

/** An allowed pair of personal and research in the record, as the service writes it (before it starts). */
function allowedRow(): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const row = {
    a: 'personal',
    b: 'research',
    a_addr: P.alice.address,
    b_addr: P.carol.address,
    added_at: 1,
    state: 'allowed',
  }
  writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
}

/** The Allow of personal and research: a's request, then the dialog at b's next call (b's person says yes). */
async function allow(a: Line, b: Line): Promise<void> {
  expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
  await call(b, 'status')
}

async function call(l: Line, name: string, args: Json = {}): Promise<Json> {
  const r = await l.request('tools/call', { name, arguments: args })
  const result = r.result as { content?: { text: string }[] } | undefined
  if (result === undefined) throw new Error(JSON.stringify(r))
  return JSON.parse(result.content?.[0]?.text ?? '{}') as Json
}

async function until(test: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** Every envelope id the relay was asked to take. */
const onRelay = (): string[] => [...relay.envelopes.keys()]

const chat = (to: string[], text = 'hi'): Json => ({ as: undefined, to, type: 'chat.v1', body: { text } })

describe('the home word off (M5)', () => {
  it('every guard answers as today: a send, an ask, a handoff and a pair_invite to an own identity are to-own-identity', async () => {
    word(false)
    const s = await start()
    const a = await window(s, 'personal')
    for (const [tool, args] of [
      ['send', chat([P.carol.address])],
      ['ask', { to: P.carol.address, body: 'q', timeout_s: 0 }],
      ['handoff', { to: P.carol.address, threads: ['a'.repeat(64)] }],
      ['pair_invite', { name: 'research', for: P.carol.address }],
    ] as const) {
      expect([tool, await call(a, tool, args)]).toEqual([
        tool,
        { error: 'to-own-identity', detail: `research ${OWN}`, as: 'personal' },
      ])
    }
    expect(a.dialogs).toEqual([])
    expect(await call(a, 'status')).toMatchObject({ local_delivery: 'off', local_peers: [] })
    // A word that is not on is off, and a table entry alone does nothing while the word is off.
    word(false)
    writeFileSync(
      localPeersPath(home),
      JSON.stringify({
        version: 1,
        pairs: [
          {
            a: 'personal',
            b: 'research',
            a_addr: P.alice.address,
            b_addr: P.carol.address,
            added_at: 1,
            state: 'allowed',
          },
        ],
      }),
    )
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ error: 'to-own-identity' })
    expect(onRelay()).toEqual([])
  })

  it('delegate and lookup of an own identity are refused with the word off, as with it on (M3, M4)', async () => {
    word(false)
    const s = await start({}, { allow_delegate: true })
    const a = await window(s, 'personal')
    expect(
      await call(a, 'delegate', { to: P.carol.address, caveats: ['type=chat.*'], exp: '+60' }),
    ).toMatchObject({ error: 'to-own-identity' })
    expect(await call(a, 'lookup', { address: P.carol.address })).toMatchObject({ error: 'to-own-identity' })
    expect(a.dialogs).toEqual([])
    expect(onRelay()).toEqual([])
  })
})

describe('a local send to an identity with no key in this home', () => {
  it('answers resolve-failed with the fix: a rotation of that identity, named by its key name and its label', async () => {
    word(true)
    const s = await start()
    // research (carol) holds no epoch key and its address record copy is gone: nothing to seal to.
    rmSync(join(home, 'records', 'carol.address.json'), { force: true })
    const a = await window(s, 'personal')
    const refused = await call(a, 'send', chat([P.carol.address]))
    expect(refused).toMatchObject({
      error: 'resolve-failed',
      detail:
        'research has no key record and no address record copy in this home, so a local send has nothing to seal to: ' +
        `run \`bag keys rotate carol --relay ${RELAY}\` once for research, then send again`,
    })
    expect(String(refused.detail)).not.toContain('<') // a command a person pastes holds no placeholder
  })
})

describe('an identity on this machine only (relays []): local mail, and no relay call before its promotion', () => {
  const HERE = 'research is on this machine only: give it relays with identity_relays, then send again'
  const ASK =
    'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, never ' +
    'go to a relay, and reach each agent as mail from your own identity. No refuses it for 24 hours and returns the ' +
    'waiting mail to its sender as declined; closing this question leaves it waiting.'

  it('opens with no subscription and no keeper; a first send asks the Allow once, delivers, no rotate', async () => {
    word(true)
    localOnly = ['research']
    const s = await start()
    const u = s.unit('research')
    expect(u?.config).toMatchObject({ relays: [], rendezvous: null })
    expect([u?.records, u?.subscriptions.list()]).toEqual([null, []])
    const a = await window(s, 'personal')
    expect(((await call(a, 'status')).home as Json).identities).toEqual([
      expect.objectContaining({ label: 'research', relays: [], reach: 'this machine only' }),
    ])
    const one = await call(a, 'send', chat([P.carol.address], 'one'))
    expect(one).toMatchObject({ delivery: 'local', pairing: 'requested' })
    const b = await window(s, 'research')
    expect(await call(b, 'status')).toMatchObject({
      relays: [],
      reach: 'this machine only',
      subscriptions: [],
    })
    expect(b.dialogs).toEqual([ASK])
    // Sealed to epoch 1, which identity_create keeps unpublished: no resolve-failed asking for a rotation.
    expect(((await call(b, 'wait', { timeout_s: 1 })).message as Json).id).toBe(one.id)
    expect(await call(b, 'send', chat([P.alice.address], 'back'))).toMatchObject({ delivery: 'local' })
    // A local ask's resume goes on with it: no no-relays for a call that only waits.
    const asked = await call(b, 'ask', { to: P.alice.address, body: 'q', timeout_s: 0 })
    expect(asked).toMatchObject({
      timed_out: true,
      resume: expect.any(String),
      question: { delivery: 'local' },
    })
    const again = await call(b, 'ask', { resume: asked.resume, timeout_s: 0 })
    expect([again.error, again.timed_out]).toEqual([undefined, true])
    expect(b.dialogs).toEqual([ASK])
    expect(log.lines.some((l) => JSON.stringify(l).includes('keys rotate'))).toBe(false)
    expect([wire.calls, lookups.calls, onRelay()]).toEqual([[], [], []])
  })

  it('refuses every wire tool no-relays before any dialog, key read or relay call, the console ones too', async () => {
    word(true)
    localOnly = ['research']
    const s = await start({}, { allow_delegate: true })
    const b = await window(s, 'research')
    for (const [tool, args] of [
      ['send', chat([P.bob.address])],
      ['ask', { to: P.bob.address, body: 'q', timeout_s: 0 }],
      ['handoff', { to: P.bob.address, threads: ['a'.repeat(64)] }],
      ['delegate', { to: P.bob.address, caveats: ['type=chat.*'], exp: '+60' }],
      ['lookup', { address: P.bob.address }],
      ['pair_invite', { name: 'bob' }],
      ['pair_accept', { name: 'bob' }],
      ['keep_alive', { word: 'on' }],
    ] as const)
      expect([tool, await call(b, tool, args)]).toEqual([
        tool,
        { error: 'no-relays', detail: HERE, as: 'research' },
      ])
    expect(b.dialogs).toEqual([])
    // The console's pairing (Pairings.consoleInvite) passes no guard: its key read refuses it first.
    expect(await call(b, 'pair_cancel')).toMatchObject({ cancelled: false })
    const p = pairingsOfTable(s.table)[0] as Pairings
    const epochs = s.unit('research')?.opened?.epochs
    const rotate = epochs ? vi.spyOn(epochs, 'rotate') : null
    await expect(
      p.consoleInvite({ ttl: 600, opened: () => {}, ask: async () => false }),
    ).rejects.toMatchObject({
      code: 'no-relays',
    })
    const seen = [wire.calls, lookups.calls, onRelay(), relay.rendezvous.size, rotate?.mock.calls ?? []]
    expect(seen).toEqual([[], [], [], 0, []])
  })

  it("an own agent's chained local mail to it is refused before policy; its sender reads the fix", async () => {
    word(true)
    localOnly = ['research']
    allowedRow()
    const rng = seededRng('chained')
    // personal's agent key, under personal's hop: its root is personal, which research's allowed pair trusts locally.
    const env = buildEnvelope({
      from: P.session.keys.signing,
      to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
      auth: [signHop(P.alice.keys.signing, P.session.address, [], T0 + 3600)],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text: 'chained' },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
    // Spooled before the start, as a send to research while it was closed leaves it: drained at its open.
    const s = await start({}, {}, [], [], [], () => {
      mkdirSync(spoolDir(home, 'carol'), { recursive: true, mode: 0o700 })
      writeFileSync(join(spoolDir(home, 'carol'), `${env.envelope.id}.env`), env.bytes, { mode: 0o600 })
    })
    const a = await window(s, 'personal')
    await until(() => readdirSync(spoolDir(home, 'carol')).filter((f) => f.endsWith('.env')).length === 0)
    // No unit signs as the agent key, so the report goes to the chain's root (auth[0].iss): personal, which reads it.
    expect([...s.units.values()].map((u) => u.address)).not.toContain(P.session.address)
    expect(await call(a, 'status', { id: env.envelope.id })).toMatchObject({
      delivery: 'local',
      status: HERE,
      reason: 'no-relays',
    })
    // no-relays is the mapping of the edge's policy-refused for a chained row at a receiver with relays [] (refusalOf).
    const spool = log.lines.filter((l) => l.event === 'local-spool' && l.fields.label === 'research')
    expect(spool.map((l) => l.fields.code)).toEqual(['no-relays'])
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })

  it('a chained local row refused for another reason (untrusted-root) reaches its sender as that reason', async () => {
    word(true)
    localOnly = ['research']
    allowedRow()
    const rng = seededRng('chained-other')
    // personal's own key under a root research does not trust locally: refused before the local-only rule is reached.
    const env = buildEnvelope({
      from: P.alice.keys.signing,
      to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
      auth: [signHop(P.org.keys.signing, P.alice.address, [], T0 + 3600)],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text: 'other root' },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
    const s = await start({}, {}, [], [], [], () => {
      mkdirSync(spoolDir(home, 'carol'), { recursive: true, mode: 0o700 })
      writeFileSync(join(spoolDir(home, 'carol'), `${env.envelope.id}.env`), env.bytes, { mode: 0o600 })
    })
    const a = await window(s, 'personal')
    await until(() => readdirSync(spoolDir(home, 'carol')).filter((f) => f.endsWith('.env')).length === 0)
    const told = await call(a, 'status', { id: env.envelope.id })
    expect(told).toMatchObject({ delivery: 'local', reason: 'untrusted-root' })
    expect(told.status).not.toBe(HERE)
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })

  it('refuses a lookup of its own address no-relays, relays hint or not: no relay or record is read', async () => {
    word(true)
    localOnly = ['research']
    const s = await start()
    const b = await window(s, 'research')
    for (const args of [{ address: P.carol.address }, { address: P.carol.address, relays: [RELAY] }])
      expect(await call(b, 'lookup', args)).toEqual({ error: 'no-relays', detail: HERE, as: 'research' })
    expect([wire.calls, lookups.calls, onRelay()]).toEqual([[], [], []])
  })

  it('with no key record to seal to, the fix is its promotion, never a keys rotate that would publish it', async () => {
    word(true)
    localOnly = ['research']
    const s = await start()
    rmSync(join(home, 'key-records'), { recursive: true, force: true })
    rmSync(join(home, 'records', 'carol.address.json'), { force: true })
    const a = await window(s, 'personal')
    const refused = await call(a, 'send', chat([P.carol.address]))
    expect(refused).toMatchObject({ error: 'resolve-failed' })
    expect(String(refused.detail)).toContain('give research relays with identity_relays, which publishes it')
    expect(String(refused.detail)).not.toContain('keys rotate')
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })
})

describe("discovery: status's home (spec/SPEC.md 9.2 item 1)", () => {
  it('lists the other identities that take part, with address, relays and open; none with the word off', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const st = await call(a, 'status')
    expect(st.home).toEqual({
      local_delivery: 'on',
      local: 'on',
      identities: [
        { label: 'research', address: P.carol.address, relays: [RELAY], open: true, pair: 'none' },
      ],
      note: HOME_NOTE,
    })
    expect(a.dialogs).toEqual([])
    expect(onRelay()).toEqual([])
    word(false)
    expect((await call(a, 'status')).home).toMatchObject({
      local_delivery: 'off',
      local: 'off',
      identities: [],
      note: HOME_OFF,
    })
  })

  it('says on (default) while no run/local.json exists', async () => {
    const s = await start()
    const a = await window(s, 'personal')
    const st = await call(a, 'status')
    expect(st.home).toMatchObject({ local_delivery: 'on (default)', local: 'on' })
    // The top-level word says the same as home; once the file exists, plain on.
    expect(st.local_delivery).toBe('on (default)')
    word(true)
    expect((await call(a, 'status')).local_delivery).toBe('on')
  })

  it("a change to the word file is audited in every identity's log, shown once to each window (C1)", async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const b = await window(s, 'research')
    expect(await call(a, 'status')).not.toHaveProperty('notice')
    writeFileSync(
      localWordPath(home),
      JSON.stringify({ version: 2, local_delivery: 'on', hidden: ['research'] }),
      {
        mode: 0o600,
      },
    )
    const said = [
      expect.stringMatching(/^local delivery on this machine changed: hidden research at \d\d:\d\d UTC$/),
    ]
    // On the next result of any tool, once per window (b's is a refusal).
    expect((await call(a, 'inbox')).notice).toEqual(said)
    expect(await call(a, 'inbox')).not.toHaveProperty('notice')
    const refused = await call(b, 'send', chat([P.alice.address]))
    expect([refused.error, refused.notice]).toEqual(['to-own-identity', said])
    for (const name of ['alice', 'carol']) {
      const lines = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8').split('\n')
      expect(lines.filter((l) => l.includes('"policy"') && l.includes('hidden research'))).toHaveLength(1)
    }
  })

  it('never lists an agent identity, and shows an agent identity none of the others', async () => {
    word(true)
    const s = await start({}, {}, [], [P.carol])
    const a = await window(s, 'personal')
    expect((await call(a, 'status')).home).toMatchObject({ local: 'on', identities: [] })
  })
})

describe("the local pair on first touch: the message waits for the person's Allow (spec/SPEC.md 9.2 item 1)", () => {
  const ASK =
    'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, never ' +
    'go to a relay, and reach each agent as mail from your own identity. No refuses it for 24 hours and returns the ' +
    'waiting mail to its sender as declined; closing this question leaves it waiting.'
  const held = (): string[] => {
    const dir = join(spoolDir(home, 'carol'), 'held')
    return existsSync(dir) ? readdirSync(dir).sort() : []
  }
  const pairs = (): Json[] => JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]

  it("holds a first touch, asks research's window in the labels' words, and a Yes delivers in order", async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const before = readdirSync(home).sort()
    const one = await call(a, 'send', chat([P.carol.address], 'one'))
    expect(one).toMatchObject({ delivery: 'local', pairing: 'requested', as: 'personal' })
    expect(String(one.note)).toContain("research's window will ask your person")
    const two = await call(a, 'send', chat([P.carol.address], 'two'))
    expect(held()).toEqual([`${one.id}.env`, `${two.id}.env`].sort())
    expect(await call(a, 'status', { id: one.id })).toMatchObject({ status: 'waiting for research to allow' })
    expect(pairs()).toMatchObject([
      { a: 'personal', b: 'research', state: 'requested', held: [one.id, two.id] },
    ])
    expect(a.dialogs).toEqual([])
    // research's window: its next tool call opens the dialog, in the words of the two labels and none of the message.
    const b = await window(s, 'research')
    await call(b, 'status')
    expect(b.dialogs).toEqual([ASK])
    const got = [
      (await call(b, 'wait', { timeout_s: 1 })).message,
      (await call(b, 'wait', { timeout_s: 1 })).message,
    ]
    expect(got.map((m) => (m as Json).id)).toEqual([one.id, two.id])
    expect(held()).toEqual([])
    expect(pairs()).toEqual([
      {
        a: 'personal',
        b: 'research',
        a_addr: P.alice.address,
        b_addr: P.carol.address,
        added_at: expect.any(Number),
        state: 'allowed',
      },
    ])
    expect((await call(a, 'status', { id: one.id })).status).toBe('delivered locally')
    expect((await call(a, 'inbox')).notice).toBeUndefined()
    // The way back needs no dialog: allowed both ways.
    expect(await call(b, 'send', chat([P.alice.address], 'back'))).toMatchObject({
      delivery: 'local',
      spooled: false,
    })
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ note: 'already allowed' })
    expect(readdirSync(home).sort()).toEqual(before)
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
    expect(onRelay()).toEqual([])
    expect(relay.rendezvous.size).toBe(0)
  })

  it('a Yes stays allowed when a held message fails: failed-local with its code, the rest delivered (F1)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const ids: string[] = []
    for (const text of ['one', 'two', 'three'])
      ids.push(String((await call(a, 'send', chat([P.carol.address], text))).id))
    // The second held envelope's signature broken: research's receive path refuses it at the Yes.
    const file = join(spoolDir(home, 'carol'), 'held', `${ids[1]}.env`)
    const env = JSON.parse(readFileSync(file, 'utf8')) as Json
    const sig = String(env.sig)
    writeFileSync(
      file,
      JSON.stringify({ ...env, sig: `${sig.slice(0, -1)}${sig.endsWith('0') ? '1' : '0'}` }),
    )
    const b = await window(s, 'research')
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(b.dialogs).toHaveLength(1)
    expect(pairs()[0]).toMatchObject({ state: 'allowed' })
    expect(held()).toEqual([])
    const got = [
      (await call(b, 'wait', { timeout_s: 1 })).message,
      (await call(b, 'wait', { timeout_s: 1 })).message,
    ]
    expect(got.map((m) => (m as Json).id)).toEqual([ids[0], ids[2]])
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
    const failed = audit.filter((l) => l.includes('failed-local') && l.includes(String(ids[1])))
    expect(failed).toHaveLength(1)
    // The audit line's detail is a JSON string: the refusal's code is its reason (the line's own reason stays ok).
    const detail = JSON.parse(String((JSON.parse(failed[0] as string) as Json).detail)) as Json
    expect(detail).toEqual({ relay: 'local:', delivery: 'failed-local', reason: 'bad-sig', to: 'research' })
    // No re-ask: research's next call shows no dialog.
    await call(b, 'status')
    expect(b.dialogs).toHaveLength(1)
  })

  it('a corrupt held file is set aside as .failed and the rest delivered after a Yes', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const one = await call(a, 'send', chat([P.carol.address], 'one'))
    const two = await call(a, 'send', chat([P.carol.address], 'two'))
    writeFileSync(join(spoolDir(home, 'carol'), 'held', `${one.id}.env`), 'not an envelope')
    const b = await window(s, 'research')
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(pairs()[0]).toMatchObject({ state: 'allowed' })
    expect(held()).toEqual([`${one.id}.env.failed`])
    expect(((await call(b, 'wait', { timeout_s: 1 })).message as Json).id).toBe(two.id)
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    // No sender line for it: its sender cannot be read from a file that does not parse.
    const lines = audit.split('\n').filter((l) => l.includes('failed-local') && l.includes(String(one.id)))
    expect(lines).toEqual([])
  })

  it(`holds at most ${LOCAL_HELD_MAX}; past that local-pair-pending, and pair_invite while asked too`, async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    for (let i = 0; i < LOCAL_HELD_MAX; i++)
      expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ pairing: 'requested' })
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ error: 'local-pair-pending' })
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({
      error: 'local-pair-pending',
    })
    expect(held()).toHaveLength(LOCAL_HELD_MAX)
  })

  it('a No drops the held mail (declined for the sender) and refuses for 24 h; then a touch asks again', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    const one = await call(a, 'send', chat([P.carol.address]))
    const b = await window(s, 'research', 'decline-late')
    await call(b, 'status')
    expect(held()).toEqual([])
    expect((await call(a, 'status', { id: one.id })).status).toBe('not delivered: your person declined')
    const refused = await call(a, 'send', chat([P.carol.address]))
    expect(refused.error).toBe('local-declined')
    expect(String(refused.detail)).toContain('research declined messages from personal until')
    clock.t += 86_400
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ pairing: 'requested' })
  })

  for (const [what, change] of CHANGES)
    it(`with ${what} a request is not asked; it waits, asked once undone (BUG 1)`, async () => {
      word(true)
      const s = await start()
      const a = await window(s, 'personal')
      await call(a, 'send', chat([P.carol.address]))
      change()
      const b = await window(s, 'research')
      expect(await call(b, 'status')).not.toHaveProperty('error')
      expect(b.dialogs).toEqual([])
      expect(pairs()).toMatchObject([{ state: 'requested' }])
      expect(held()).toHaveLength(1)
      word(true)
      await call(b, 'status')
      expect(b.dialogs).toHaveLength(1)
      expect(pairs()[0]).toMatchObject({ state: 'allowed' })
      expect(held()).toEqual([])
    })

  it('a re-ask in cooling asks the sender first, at most one per 10 minutes and 3 per cooling', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    const no = await window(s, 'research', 'decline-late')
    await call(no, 'status')
    // The sender's own dialog first; its Yes puts the request back in research's speaking window.
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    expect(a.dialogs.at(-1)).toMatch(
      /^Ask research again to allow messages from personal\? You declined at \d\d:\d\d\.$/,
    )
    await call(no, 'status')
    expect(no.dialogs).toHaveLength(2)
    // Within 10 minutes: refused with the wait, and no dialog on either side.
    const soon = await call(a, 'pair_invite', { for: P.carol.address })
    expect([soon.error, a.dialogs.length]).toEqual(['local-declined', 1])
    for (let i = 0; i < 2; i++) {
      clock.t += 600
      await call(a, 'pair_invite', { for: P.carol.address })
      await call(no, 'status')
    }
    // Three re-asks this cooling: refused until it ends.
    clock.t += 600
    const past = await call(a, 'pair_invite', { for: P.carol.address })
    expect([past.error, a.dialogs.length]).toEqual(['local-declined', 3])
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(audit.split('\n').filter((l) => l.includes('re-ask personal to research: yes'))).toHaveLength(3)
  })

  const isRing = (m: Json): boolean => m.method === 'service/ring'

  it("a first touch rings research's speaking window (requests 1), the other quietly, and no other label", async () => {
    word(true)
    const timers = new ManualTimers()
    const s = await start({ timers })
    const a = await window(s, 'personal')
    const quiet = await window(s, 'research')
    const b = await window(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    timers.fire((ms) => ms === SETTLE_MS)
    const rung = (await b.next(isRing)).params
    expect(rung).toMatchObject({ as: 'research', unread: 0, requests: 1, speaking: true })
    expect((await quiet.next(isRing)).params).toMatchObject({ requests: 1, speaking: false })
    await call(a, 'status')
    expect([a.count(isRing), b.count(isRing), quiet.count(isRing)]).toEqual([0, 0, 0])
    // The dialog at the speaking window's next tool call, never the other's.
    await call(b, 'status')
    expect([b.dialogs.length, quiet.dialogs.length]).toEqual([1, 0])
  })

  it("a re-ask's Yes rings research's speaking window again (requests 1), and not the sender's", async () => {
    word(true)
    const [clock, timers] = [new FakeClock(), new ManualTimers()]
    const s = await start({ clock, timers })
    const a = await window(s, 'personal')
    const no = await window(s, 'research', 'decline-late')
    await call(a, 'pair_invite', { for: P.carol.address })
    timers.fire((ms) => ms === SETTLE_MS)
    await no.next(isRing)
    await call(no, 'status')
    expect(no.dialogs).toHaveLength(1)
    // The sender's own Yes to ask again puts the request back: research is rung once more.
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    timers.fire((ms) => ms === SETTLE_MS)
    const rung = (await no.next(isRing)).params
    expect(rung).toMatchObject({ as: 'research', unread: 0, requests: 1, speaking: true })
    expect(a.count(isRing)).toBe(0)
    await call(no, 'status')
    expect(no.dialogs).toHaveLength(2)
  })

  it('the re-ask dialog names the time of the No, not the time of the re-ask (item i)', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    const no = await window(s, 'research', 'decline-late')
    const declinedAt = new Date(clock.now() * 1000).toISOString().slice(11, 16)
    await call(no, 'status')
    clock.t += 1800
    const reAskAt = new Date(clock.now() * 1000).toISOString().slice(11, 16)
    expect(reAskAt).not.toBe(declinedAt)
    await call(a, 'pair_invite', { for: P.carol.address })
    expect(a.dialogs.at(-1)).toBe(
      `Ask research again to allow messages from personal? You declined at ${declinedAt}.`,
    )
  })

  it('a re-ask by the decliner rings the window that will be asked (row.b), not the other side', async () => {
    word(true)
    const [clock, timers] = [new FakeClock(), new ManualTimers()]
    const s = await start({ clock, timers })
    const a = await window(s, 'personal')
    const r = await window(s, 'research', 'decline-late')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    await call(r, 'status')
    expect(pairs()).toMatchObject([{ a: 'personal', b: 'research', state: 'declined' }])
    timers.fire((ms) => ms === SETTLE_MS)
    const isRing = (m: Json): boolean => m.method === 'service/ring'
    while (r.count(isRing) > 0) await r.next(isRing)
    // research, which said No, asks again from its own window (its own Yes there, as a re-ask is).
    const yes = await window(s, 'research')
    expect(await call(yes, 'pair_invite', { for: P.alice.address })).toMatchObject({ pairing: 'requested' })
    timers.fire((ms) => ms === SETTLE_MS)
    const rung = (await yes.next(isRing)).params
    expect(rung).toMatchObject({ as: 'research', requests: 1, speaking: true })
    await call(a, 'status')
    expect(a.count(isRing)).toBe(0)
  })

  it('a re-ask answered at once (a decline or a cancel faster than a person) is no-elicitation, never declined (q2, 0.4.4)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    await call(await window(s, 'research', 'decline-late'), 'status')
    expect(pairs()).toMatchObject([{ state: 'declined', reasks: [] }])
    for (const answer of ['decline', null] as const) {
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.carol.address })
      expect(r.error).toBe('no-elicitation')
      // No answer is no re-ask: none counted, still declined.
      expect(pairs()).toMatchObject([{ state: 'declined', reasks: [] }])
    }
    // Closed by the person after they saw it (a cancel at a person's pace, or a timeout): cancelled, nothing changed.
    const late = await window(s, 'personal', 'cancel-late')
    const r = await call(late, 'pair_invite', { for: P.carol.address })
    expect([r.error, r.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
    expect(pairs()).toMatchObject([{ state: 'declined', reasks: [] }])
  })

  it("a decline slower than FAST_ANSWER_MS is the person's No on a local form: the pair declined (q2)", async () => {
    word(true)
    let t = 0
    // Every dialog answered 300 ms after it opened, on the monotonic clock: as slow as a person.
    const s = await start({ mono: () => (t += 300) })
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const b = await window(s, 'research', 'decline')
    await call(b, 'status')
    expect(pairs()).toMatchObject([{ state: 'declined' }])
    expect(held()).toEqual([])
  })

  it("a refused re-ask is audited in the sender's log with its bound, once per pair per 10 minutes (item m)", async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    const ask = () => call(a, 'pair_invite', { for: P.carol.address })
    expect(await ask()).toMatchObject({ pairing: 'requested' })
    const no = await window(s, 'research', 'decline-late')
    await call(no, 'status')
    const lines = (name: string) =>
      readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
        .split('\n')
        .filter((l) => l.includes('re-ask personal to research refused'))
    // Within 10 minutes of a re-ask: refused, one line naming that bound however often the model calls.
    expect(await ask()).toMatchObject({ pairing: 'requested' })
    await call(no, 'status')
    for (let i = 0; i < 3; i++) expect((await ask()).error).toBe('local-declined')
    expect(lines('alice')).toHaveLength(1)
    expect(lines('alice')[0]).toContain('at most one re-ask in 10 minutes')
    // Three re-asks used: refused for the cooling; a line again only 10 minutes after the last one.
    for (let i = 0; i < 2; i++) {
      clock.t += 600
      expect(await ask()).toMatchObject({ pairing: 'requested' })
      await call(no, 'status')
    }
    for (let i = 0; i < 3; i++) expect((await ask()).error).toBe('local-declined')
    expect(lines('alice')).toHaveLength(2)
    expect(lines('alice')[1]).toContain('at most 3 re-asks in a cooling')
    clock.t += 300
    expect((await ask()).error).toBe('local-declined')
    expect(lines('alice')).toHaveLength(2)
    clock.t += 300
    expect((await ask()).error).toBe('local-declined')
    expect(lines('alice')).toHaveLength(3)
    // In the sender's log only.
    expect(lines('carol')).toEqual([])
  })

  it('a request no one answers expires after 7 days: the held mail is not delivered, no answer', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    const one = await call(a, 'send', chat([P.carol.address]))
    clock.t += LOCAL_ASK_DAYS * 86_400
    expect((await call(a, 'status', { id: one.id })).status).toBe('not delivered: no answer')
    expect(held()).toEqual([])
    expect(existsSync(localPeersPath(home)) ? pairs() : []).toEqual([])
  })

  it('asks only in the speaking window; another window of research sees the state, never the dialog', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const quiet = await window(s, 'research')
    const speaking = await window(s, 'research')
    expect((await call(quiet, 'status')).home).toMatchObject({
      identities: [{ label: 'personal', pair: 'requested' }],
    })
    expect(quiet.dialogs).toEqual([])
    await call(speaking, 'status')
    expect(speaking.dialogs).toEqual([ASK])
  })

  it('an allowed row the service did not write goes back to requested, audited in every log, told (C1)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await window(s, 'research')
    await call(a, 'status')
    const forged = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
    }
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [forged] }), { mode: 0o600 })
    const sent = await call(a, 'send', chat([P.carol.address]))
    expect(sent).toMatchObject({ pairing: 'requested' })
    expect(sent.notice).toEqual(['a local pair on this machine changed outside bag'])
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(audit.split('\n').filter((l) => l.includes('changed outside bag'))).toHaveLength(1)
    }
  })

  for (const forged of ['allowed', 'declined'] as const)
    it(`a ${forged} row the service did not write goes back to requested, held cleared (r1), audited, told (item k)`, async () => {
      word(true)
      const s = await start()
      const a = await window(s, 'personal')
      // research's person closes every dialog unanswered: the request stays requested (L1).
      const b = await window(s, 'research', null)
      const one = await call(a, 'send', chat([P.carol.address]))
      await call(b, 'inbox')
      // Someone else rewrites the service's requested row with an explicit state; mode and fields otherwise right.
      const [row] = pairs()
      const until = 1_900_000_000 // past the fake clock's now: a cooling still running
      const body = { ...row, state: forged, ...(forged === 'declined' ? { until } : {}) }
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [body] }), { mode: 0o600 })
      const sent = await call(a, 'send', chat([P.carol.address]))
      expect(sent).toMatchObject({ delivery: 'local', pairing: 'requested' })
      expect(sent.notice).toContain('a local pair on this machine changed outside bag')
      // Reset with no held mail (r1): only the send after the reset is held by it.
      expect(pairs()).toMatchObject([{ state: 'requested', held: [sent.id] }])
      void one
      expect((await call(b, 'inbox')).notice).toContain('a local pair on this machine changed outside bag')
      for (const name of ['alice', 'carol']) {
        const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
        expect(audit.split('\n').filter((l) => l.includes('changed outside bag'))).toHaveLength(1)
      }
    })

  for (const how of ['0644', 'a symlink'] as const)
    it(`a table refused as ${how} reads as no pairs, audited in every log and told once in each window (item l)`, async () => {
      word(true)
      const s = await start()
      const a = await window(s, 'personal')
      const b = await window(s, 'research', null)
      await call(a, 'send', chat([P.carol.address]))
      await call(b, 'inbox')
      const file = localPeersPath(home)
      if (how === '0644') chmodSync(file, 0o644)
      else {
        renameSync(file, join(home, 'run', 'elsewhere.json'))
        symlinkSync(join(home, 'run', 'elsewhere.json'), file)
      }
      const told =
        'local pairs on this machine refused: run/local-peers.json is not a 0600 regular file of this user; to use ' +
        `them again: chmod 600 ${file}, or put a regular file of yours there in place of a link`
      const st = await call(a, 'status')
      expect(st.notice).toContain(told)
      expect(((st.home as Json).identities as Json[])[0]).toMatchObject({ label: 'research', pair: 'none' })
      expect((await call(b, 'inbox')).notice).toContain(told)
      expect((await call(a, 'status')).notice).toBeUndefined()
      for (const name of ['alice', 'carol']) {
        const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
        expect(audit.split('\n').filter((l) => l.includes('local pairs refused'))).toHaveLength(1)
      }
    })

  it('a refused table is never written over: a send is refused, the file and the held mail untouched (item n 24)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const b = await window(s, 'research', null)
    const one = await call(a, 'send', chat([P.carol.address]))
    await call(b, 'inbox')
    const file = localPeersPath(home)
    chmodSync(file, 0o644)
    const bytes = readFileSync(file)
    const before = held()
    expect(before).toEqual([`${one.id}.env`])
    const r = await call(a, 'send', chat([P.carol.address]))
    expect(r.error).toBe('to-own-identity')
    expect(String(r.detail)).toContain('the local pair table is refused: run/local-peers.json is not a 0600')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ error: 'to-own-identity' })
    await call(b, 'inbox')
    expect(readFileSync(file).equals(bytes)).toBe(true)
    expect(statSync(file).mode & 0o777).toBe(0o644)
    expect(held()).toEqual(before)
    expect(onRelay()).toEqual([])
    // Mode fixed: the same table reads again, the request still waiting with its held message.
    chmodSync(file, 0o600)
    expect(pairs()).toMatchObject([{ state: 'requested', held: [one.id] }])
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ pairing: 'requested' })
  })

  it('a start table that does not parse, then an outside change: every row unknown, nothing throws (item n EXTRA)', async () => {
    word(true)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), 'not a table', { mode: 0o600 })
    const timers = new ManualTimers()
    const s = await start({ timers })
    const a = await window(s, 'personal')
    const b = await window(s, 'research', null)
    await call(a, 'status')
    // Someone writes an allowed row over the unreadable table.
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
    }
    const table = { version: 1, pairs: [{ ...row, state: 'allowed' }] }
    writeFileSync(localPeersPath(home), JSON.stringify(table), { mode: 0o600 })
    const st = await call(a, 'status')
    expect(st).not.toHaveProperty('error')
    expect(st.notice).toContain('a local pair on this machine changed outside bag')
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    const sent = await call(a, 'send', chat([P.carol.address]))
    expect(sent).toMatchObject({ delivery: 'local', pairing: 'requested' })
    timers.fire((ms) => ms === SETTLE_MS)
    expect((await b.next((m) => m.method === 'service/ring')).params).toMatchObject({
      as: 'research',
      requests: 1,
    })
    expect(await call(b, 'inbox')).not.toHaveProperty('error')
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(audit).toContain('the table read at start does not parse')
    expect(audit).toContain('a local pair on this machine changed outside bag')
  })

  it('a table refused between the read and the rewrite: #pairs returns the rows read, nothing throws (item o)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await window(s, 'research', null)
    const one = await call(a, 'send', chat([P.carol.address]))
    const file = localPeersPath(home)
    // A forged allowed row written outside; its reconcile audits "changed outside bag" just before its rewrite, and
    // that audit line is where this test turns the table to 0644: the mode changes between the check and the write.
    const [row] = pairs()
    writeFileSync(file, JSON.stringify({ version: 1, pairs: [{ ...row, state: 'allowed' }] }), {
      mode: 0o600,
    })
    const edge = s.units.get('personal')?.opened?.edge as unknown as {
      audit: { record: (e: Json) => unknown }
    }
    const audit = edge.audit
    const record = audit.record.bind(audit)
    audit.record = (e: Json) => {
      if (JSON.stringify(e.detail).includes('changed outside bag')) chmodSync(file, 0o644)
      return record(e)
    }
    const bytes = readFileSync(file)
    const st = await call(a, 'status')
    expect(st).not.toHaveProperty('error')
    expect(st.notice).toContain('a local pair on this machine changed outside bag')
    // Not written over (still the outside bytes, 0644); the failed write logged; the later reads in the same call see
    // the table refused, and say so.
    expect(readFileSync(file).equals(bytes)).toBe(true)
    expect(statSync(file).mode & 0o777).toBe(0o644)
    expect(log.lines.some((l) => l.event === 'local-pairs-not-written')).toBe(true)
    expect(String(st.notice)).toContain('local pairs on this machine refused')
    // From now on the table is refused: a send answers the refusal, and the held mail is still there.
    const sent = await call(a, 'send', chat([P.carol.address]))
    expect(sent.error).toBe('to-own-identity')
    expect(held()).toEqual([`${one.id}.env`])
  })

  it('a CLI unpair of one pair keeps another allowed in the running service: no reset, no re-ask (q3)', async () => {
    word(true)
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    const r = await window(s, 'research')
    const l = await window(s, 'lab')
    await call(a, 'send', chat([P.carol.address]))
    await call(r, 'status')
    await call(a, 'send', chat([P.jane.address]))
    await call(l, 'status')
    expect(pairs().map((x) => x.state)).toEqual(['allowed', 'allowed'])
    // bag unpair research --as personal, as packages/cli/src/commands/local.ts dropLocalPairs writes it: the table
    // parsed, the one row left out, the rest written back as read.
    const file = localPeersPath(home)
    const table = JSON.parse(readFileSync(file, 'utf8')) as { version: number; pairs: Json[] }
    const rest = table.pairs.filter((x) => x.b !== 'research')
    writeFileSync(file, `${JSON.stringify({ version: 1, pairs: rest })}\n`, { mode: 0o600 })
    const st = await call(a, 'status')
    expect(((st.home as Json).identities as Json[]).map((i) => [i.label, i.pair])).toEqual([
      ['research', 'none'],
      ['lab', 'allowed'],
    ])
    expect(pairs()).toMatchObject([{ b: 'lab', state: 'allowed' }])
    expect(await call(a, 'send', chat([P.jane.address]))).toMatchObject({ delivery: 'local', spooled: false })
    expect([a.dialogs.length, l.dialogs.length]).toEqual([0, 1])
  })

  it('after a restart each window is shown its allowed pairs at its first result', async () => {
    word(true)
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
      state: 'allowed',
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
    const s = await start()
    const a = await window(s, 'personal')
    expect((await call(a, 'inbox')).notice).toEqual(['local pairs allowed for personal: research'])
    expect(await call(a, 'inbox')).not.toHaveProperty('notice')
    expect((await call(a, 'status')).home).toMatchObject({
      identities: [{ label: 'research', pair: 'allowed' }],
    })
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(audit).toContain('local pairs read: 1')
  })

  it('a dialog closed without an answer is no answer: the pair stays requested and is asked again (L1)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const closed = await window(s, 'research', null)
    await call(closed, 'status')
    expect(closed.dialogs).toHaveLength(1)
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    const yes = await window(s, 'research')
    await call(yes, 'status')
    expect(yes.dialogs).toHaveLength(1)
    expect(pairs()).toMatchObject([{ a: 'personal', b: 'research' }])
    expect(pairs()[0]).toMatchObject({ state: 'allowed' })
  })

  it("the Allow ended by bag's own bound is no answer: still requested, the mail still held, a late Yes does nothing", async () => {
    word(true)
    const timers = new ManualTimers()
    const s = await start({ timers })
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const b = await window(s, 'research', 'never')
    b.send({ jsonrpc: '2.0', id: 9002, method: 'tools/call', params: { name: 'status', arguments: {} } })
    const asked = await b.next((m) => m.method === 'elicitation/create')
    await vi.waitFor(() => expect(timers.live()).toContain(MAX_ASK_MS))
    timers.fire((ms) => ms === MAX_ASK_MS)
    const withdrawn = await b.next((m) => m.method === 'notifications/cancelled')
    expect(withdrawn.params).toMatchObject({ requestId: asked.id })
    expect(JSON.stringify(await b.next((m) => m.id === 9002))).not.toContain('no-elicitation')
    const handle = ((asked.params as Json)._meta as Json)[DIALOG_META]
    const late = { action: 'accept', content: { confirm: true }, _meta: { [DIALOG_META]: handle } }
    b.send({ jsonrpc: '2.0', id: asked.id, result: late })
    await vi.waitFor(() => expect(log.lines.some((x) => x.event === 'dialog-unknown')).toBe(true))
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    expect(pairs()[0]?.held).toHaveLength(1)
  })

  it('a host that gives up on the dialog and cancels the call is no answer: still requested (L1)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    // A host's own dialog timeout reaches the service as the call's cancel: the elicitation is withdrawn, unanswered.
    const b = await window(s, 'research', 'never')
    b.send({ jsonrpc: '2.0', id: 9001, method: 'tools/call', params: { name: 'status', arguments: {} } })
    const asked = await b.next((m) => m.method === 'elicitation/create')
    const cancel = { requestId: 9001, reason: 'timeout' }
    b.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: cancel })
    const withdrawn = await b.next((m) => m.method === 'notifications/cancelled')
    expect(withdrawn.params).toMatchObject({ requestId: asked.id })
    await new Promise((r) => setTimeout(r, 20))
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    const yes = await window(s, 'research')
    await call(yes, 'status')
    expect(yes.dialogs).toHaveLength(1)
    expect(pairs()[0]).toMatchObject({ state: 'allowed' })
  })

  it("a host's instant decline (under FAST_ANSWER_MS) is no answer, never a No: still requested (9a)", async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    // codex exec declines a form in under a millisecond: no person saw it.
    const auto = await window(s, 'research', 'decline')
    expect(await call(auto, 'status')).not.toHaveProperty('error')
    expect(auto.dialogs).toHaveLength(1)
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    expect(held()).toHaveLength(1)
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ pairing: 'requested' })
  })

  it.each(['claude-vscode', 'claude-desktop'])(
    "on %s a host's decline after FAST_ANSWER_MS is no answer, never a No: still requested, the mail held",
    async (surface) => {
      word(true)
      const s = await start()
      const a = await window(s, 'personal')
      await call(a, 'send', chat([P.carol.address]))
      const late = await window(s, 'research', 'decline-late', { shim: { surface } })
      expect(await call(late, 'status')).not.toHaveProperty('error')
      expect(late.dialogs).toHaveLength(1)
      expect(pairs()).toMatchObject([{ state: 'requested' }])
      expect(held()).toHaveLength(1)
      // The service log's line names the surface it read from the window's hello.
      const line = log.lines.filter((l) => l.event === 'consent-dialog').at(-1)
      expect(line?.fields).toMatchObject({ act: 'local-pair', code: 'no-elicitation', surface })
    },
  )

  it("on the terminal (cli) a host's decline after FAST_ANSWER_MS is still the person's No: declined", async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const late = await window(s, 'research', 'decline-late', { shim: { surface: 'cli' } })
    expect(await call(late, 'status')).not.toHaveProperty('error')
    expect(pairs()).toMatchObject([{ state: 'declined' }])
  })

  // The question card (design 2026-11-24, section 7): the local Allow answered by a card, read by pairing.ts cardSaid.
  it.each(['claude-vscode', 'claude-desktop'])(
    "on %s the card's No declines the pair and returns the held mail as declined; no answer leaves it requested",
    async (surface) => {
      word(true)
      const s = await start()
      const a = await window(s, 'personal')
      await call(a, 'send', chat([P.carol.address]))
      for (const bag_card of ['dismissed', 'idle', 'other', 'maybe']) {
        const w = await window(
          s,
          'research',
          { confirm: true, bag_card, bag_open_ms: 4000 },
          { shim: { surface } },
        )
        expect(await call(w, 'status')).not.toHaveProperty('error')
        expect([bag_card, w.dialogs.length, pairs()]).toMatchObject([bag_card, 1, [{ state: 'requested' }]])
        expect(held()).toHaveLength(1)
      }
      const no = await window(
        s,
        'research',
        { confirm: false, bag_card: 'no', bag_open_ms: 4000 },
        { shim: { surface } },
      )
      await call(no, 'status')
      expect(pairs()).toMatchObject([{ state: 'declined' }])
      expect(held()).toEqual([])
    },
  )

  it("a card's Yes allows the pair; on the terminal (cli) a marker is refused as no answer", async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    for (const bag_card of ['no', 'yes']) {
      const w = await window(
        s,
        'research',
        { confirm: bag_card === 'yes', bag_card, bag_open_ms: 4000 },
        { shim: { surface: 'cli' } },
      )
      await call(w, 'status')
      expect(pairs()).toMatchObject([{ state: 'requested' }])
    }
    const yes = await window(
      s,
      'research',
      { confirm: true, bag_card: 'yes', bag_open_ms: 4000 },
      { shim: { surface: 'claude-vscode' } },
    )
    await call(yes, 'status')
    expect(pairs()).toMatchObject([{ state: 'allowed' }])
  })

  it('an accept with false (an untouched switch) is no answer on cli and with no surface: still requested, the mail held', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    for (const hello of [{ shim: { surface: 'cli' } }, {}]) {
      const w = await window(s, 'research', false, hello)
      expect(await call(w, 'status')).not.toHaveProperty('error')
      expect([w.dialogs.length, pairs(), held().length]).toMatchObject([1, [{ state: 'requested' }], 1])
    }
  })

  // The pace of a local Allow left unanswered, as it is today (pinned, no new cap): askPending asks once per tool call of
  // the speaking window, never between calls and never twice in one call; askPerson's local-pair ask is limit false.
  it('no answer on the local Allow is asked again only at the next tool call, once per call', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const w = await window(
      s,
      'research',
      { bag_card: 'dismissed', bag_open_ms: 4000 },
      { shim: { surface: 'claude-vscode' } },
    )
    for (let i = 1; i <= 3; i++) {
      await call(w, 'status')
      await new Promise((r) => setTimeout(r, 50))
      expect(w.dialogs).toHaveLength(i)
    }
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    expect(held()).toHaveLength(1)
  })

  it('an accept with no boolean in it is no answer, not a No: still requested (r5)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    await call(a, 'send', chat([P.carol.address]))
    const b = await window(s, 'research', 'empty')
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(b.dialogs).toHaveLength(1)
    expect(pairs()).toMatchObject([{ state: 'requested' }])
    expect(held()).toHaveLength(1)
  })

  it('an expiry returns the reconciled rows it wrote: the other pair stays allowed in the same call (r5)', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock }, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    const l = await window(s, 'lab')
    await call(a, 'send', chat([P.jane.address]))
    await call(l, 'status')
    const r = await window(s, 'research', null)
    await call(a, 'send', chat([P.carol.address]))
    await call(r, 'status')
    clock.t += LOCAL_ASK_DAYS * 86_400
    const st = await call(a, 'status')
    expect(((st.home as Json).identities as Json[]).map((i) => [i.label, i.pair])).toEqual([
      ['research', 'none'],
      ['lab', 'allowed'],
    ])
    expect(pairs()).toEqual([expect.objectContaining({ b: 'lab', state: 'allowed' })])
    expect(held()).toEqual([])
  })

  it('a planted request naming an agent identity is never asked: no Allow dialog, nothing written allowed (u4)', async () => {
    word(true)
    const s = await start({}, {}, [], [P.carol])
    const a = await window(s, 'personal')
    await call(a, 'status')
    const row = {
      a: 'research',
      b: 'personal',
      a_addr: P.carol.address,
      b_addr: P.alice.address,
      added_at: T0,
    }
    const planted = { version: 1, pairs: [{ ...row, state: 'requested', at: T0, held: [] }] }
    writeFileSync(localPeersPath(home), JSON.stringify(planted), { mode: 0o600 })
    await call(a, 'status')
    await call(a, 'inbox')
    expect(a.dialogs).toEqual([])
    expect(pairs().every((r) => r.state !== 'allowed')).toBe(true)
  })

  it('a planted request naming an agent identity does not ring; a pairable one does (v5)', async () => {
    word(true)
    const timers = new ManualTimers()
    const s = await start({ timers }, {}, [], [P.carol], [['lab', P.jane]])
    const a = await window(s, 'personal')
    await call(a, 'status')
    const isRing = (m: Json): boolean => m.method === 'service/ring'
    // research is an agent identity: its planted request to personal is neither asked nor rung.
    const row = {
      a: 'research',
      b: 'personal',
      a_addr: P.carol.address,
      b_addr: P.alice.address,
      added_at: T0,
    }
    const planted = { version: 1, pairs: [{ ...row, state: 'requested', at: T0, held: [] }] }
    writeFileSync(localPeersPath(home), JSON.stringify(planted), { mode: 0o600 })
    await call(a, 'status')
    s.router.arrived('personal')
    timers.fire((ms) => ms === SETTLE_MS)
    await call(a, 'status')
    expect(a.count(isRing)).toBe(0)
    // Inverse: lab's first touch of personal, between two pairable identities, rings personal's window.
    const l = await window(s, 'lab')
    await call(l, 'send', chat([P.alice.address]))
    timers.fire((ms) => ms === SETTLE_MS)
    expect((await a.next(isRing)).params).toMatchObject({ as: 'personal', requests: 1 })
  })

  it('an agent identity is never a local peer: pair_invite for it is to-own-identity, with no dialog', async () => {
    word(true)
    const s = await start({}, {}, [], [P.carol])
    const a = await window(s, 'personal')
    const r = await call(a, 'pair_invite', { for: P.carol.address })
    expect(r, JSON.stringify(r)).toMatchObject({ error: 'to-own-identity' })
    expect(a.dialogs).toEqual([])
    expect(existsSync(localPeersPath(home))).toBe(false)
  })
})

/**
 * A wire peer on its own stdio server and home, on the same memory relay, whose host shows form dialogs: `person`
 * answers them in order (pair_invite's address question is answered empty). For the omp pairing tests over the link.
 */
async function peer(party: Party) {
  const dir = mkdtempSync('/tmp/bslp-')
  peers.push(dir)
  saveKeys(dir, party)
  const config = parseConfig(['--as', party.name, '--dir', dir, '--relay', RELAY], {})
  if (config === 'help') throw new Error('unexpected help')
  let t = 0
  const running: Running = await startServer(config, {
    clock: new FakeClock(),
    rng: seededRng(`peer-${party.name}`),
    relay,
    records: fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4244,
    alive: () => false,
    log: new MemoryLog(),
    resubscribeDelayMs: () => 0,
    pairPollMs: 2,
    mono: () => (t += 1000),
  })
  stops.push(() => running.stop())
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  await running.mcp.connect(serverSide)
  const client = new Client(
    { name: 'peer', version: '0.0.0' },
    { capabilities: { elicitation: { form: {} } } },
  )
  const dialogs: string[] = []
  const person: ((message: string) => ElicitResult)[] = []
  client.setRequestHandler(ElicitRequestSchema, async (r) => {
    const props = Object.keys(
      (r.params as { requestedSchema?: { properties?: object } }).requestedSchema?.properties ?? {},
    )
    if (props.join() === 'address') return { action: 'accept', content: {} }
    dialogs.push(r.params.message)
    return (person.shift() ?? (() => ({ action: 'cancel' }) as ElicitResult))(r.params.message)
  })
  await client.connect(clientSide)
  stops.push(() => client.close())
  const call = async (name: string, args: Json): Promise<Json> => {
    const result = await client.callTool({ name, arguments: args })
    return JSON.parse((result.content as { text: string }[])[0]?.text as string) as Json
  }
  return { dir, dialogs, person, call }
}
const peers: string[] = []
const stops: (() => Promise<void>)[] = []
afterEach(async () => {
  await new Promise((r) => setTimeout(r, 20))
  for (const s of stops.splice(0).reverse()) await s().catch(() => {})
  for (const d of peers.splice(0)) rmSync(d, { recursive: true, force: true })
})
const digitsIn = (message: string | undefined): string =>
  /[Cc]heck digits: (\d{3} \d{3})/.exec(message ?? '')?.[1] as string

describe("omp's Allow over its extension's registered link, never a file (item 7, C2)", () => {
  const WORDS =
    'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, never ' +
    'go to a relay, and reach each agent as mail from your own identity. No refuses it for 24 hours and returns the ' +
    'waiting mail to its sender as declined; closing this question leaves it waiting.'
  const PID = 777_001
  /** An omp window of omp process `pid`: no elicitation, the bridge capability naming that pid (the shim's). */
  const omp = (s: Service, label: string, pid = PID) =>
    window(s, label, true, {
      host: 'omp',
      client_capabilities: { experimental: { [CONSENT_BRIDGE]: { pid } } },
    })
  /** The extension's own connection: a hello, then consent-register for `pid`; the asks it receives, kept. */
  async function link(s: Service, pid = PID, secret?: string, more: Json = {}) {
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((r) => socket.once('connect', () => r()))
    const seen: Json[] = []
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        seen.push(JSON.parse(buf.slice(0, i)) as Json)
        buf = buf.slice(i + 1)
      }
    })
    let n = 0
    const request = async (method: string, params: Json): Promise<Json> => {
      const id = ++n
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
      await until(() => seen.some((m) => m.id === id))
      return seen.find((m) => m.id === id) as Json
    }
    await request('service/hello', { contract: 1, token: s.token.toString('hex'), host: 'omp', cwd: '/w' })
    const reg = await request('service/consent-register', {
      pid,
      ...(secret === undefined ? {} : { secret }),
      ...more,
    })
    const asks = () => seen.filter((m) => m.method === 'service/consent-ask').map((m) => m.params as Json)
    const withdraws = () =>
      seen.filter((m) => m.method === 'service/consent-withdraw').map((m) => m.params as Json)
    return { socket, reg, request, asks, withdraws, seen }
  }
  const pairState = (): unknown =>
    (JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[])[0]?.state

  it("asks research's omp window over the link in the service's words; only its Yes allows, no file", async () => {
    word(true)
    const s = await start()
    const l = await link(s)
    expect(typeof (l.reg.result as Json).secret).toBe('string')
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    const sent = await call(a, 'send', chat([P.carol.address]))
    const done = call(b, 'status')
    await until(() => l.asks().length === 1)
    expect(l.asks()[0]).toMatchObject({ title: 'Yes: allow personal and research', message: WORDS })
    // No bridge folder is made (0.4.2), and an answer on another connection changes nothing.
    const shim = join(home, 'run', 'shim')
    expect(existsSync(shim) ? readdirSync(shim).filter((f) => f.endsWith('.consent')) : []).toEqual([])
    const other = await link(s, PID + 1)
    const forged = await other.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true })
    expect((forged.error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(pairState()).toBe('requested')
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true })
    await done
    expect(pairState()).toBe('allowed')
    expect((await call(a, 'status', { id: sent.id })).status).toBe('delivered locally')
  })

  it("a link's No declines the pair", async () => {
    word(true)
    const s = await start()
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    const done = call(b, 'status')
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: false })
    await done
    expect(pairState()).toBe('declined')
  })

  it('an aborted or timed-out omp confirm (accepted null, or no boolean) is no answer: requested', async () => {
    word(true)
    const s = await start()
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    for (const [i, accepted] of [null, undefined, 'no'].entries()) {
      const done = call(b, 'status')
      await until(() => l.asks().length === i + 1)
      await l.request('service/consent-answer', { id: l.asks()[i]?.id, accepted })
      expect(await done).not.toHaveProperty('error')
      expect(pairState()).toBe('requested')
    }
    const done = call(b, 'status')
    await until(() => l.asks().length === 4)
    await l.request('service/consent-answer', { id: l.asks()[3]?.id, accepted: true })
    await done
    expect(pairState()).toBe('allowed')
  })

  it('a link that closes before an answer is no answer: the pair stays requested and is asked again (L1)', async () => {
    word(true)
    const s = await start({ alive: (pid) => pid === PID })
    const l = await link(s)
    const secret = String((l.reg.result as Json).secret)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    const done = call(b, 'status')
    await until(() => l.asks().length === 1)
    l.socket.destroy()
    await done
    expect(pairState()).toBe('requested')
    const again = await link(s, PID, secret)
    const asked = call(b, 'status')
    await until(() => again.asks().length === 1)
    await again.request('service/consent-answer', { id: again.asks()[0]?.id, accepted: true })
    await asked
    expect(pairState()).toBe('allowed')
  })

  it('a link that does not answer in time is no answer: the pair stays requested and is asked again (L1)', async () => {
    word(true)
    const timers = new ManualTimers()
    const s = await start({ timers })
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    const done = call(b, 'status')
    await until(() => l.asks().length === 1)
    // Under omp's 30 s limit on the tool call that carries it (item j): 25 s less the call's time so far, for a 0.4.1
    // extension that told no call_ms; then withdrawn, the confirm dismissed.
    expect(LINK_ASK_MS).toBe(25_000)
    const ms = Number(l.asks()[0]?.ms)
    expect(ms).toBeLessThanOrEqual(LINK_ASK_MS)
    expect(ms).toBeGreaterThan(LINK_ASK_MS - 2000)
    timers.fire((t) => t === ms)
    await done
    await until(() => l.withdraws().length === 1)
    expect(l.withdraws()).toEqual([{ id: l.asks()[0]?.id }])
    expect(pairState()).toBe('requested')
    // A late answer for the withdrawn ask is refused and changes nothing.
    const late = await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: false })
    expect((late.error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(pairState()).toBe('requested')
    // The next call opens a fresh ask, the first gone.
    const again = call(b, 'status')
    await until(() => l.asks().length === 2)
    expect(l.asks()[1]?.id).not.toBe(l.asks()[0]?.id)
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true })
    await again
    expect(pairState()).toBe('allowed')
  })

  it('an ask whose tool call is cancelled is withdrawn; a No after it is refused, still requested (item j)', async () => {
    word(true)
    const s = await start()
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    b.send({ jsonrpc: '2.0', id: 9003, method: 'tools/call', params: { name: 'status', arguments: {} } })
    await until(() => l.asks().length === 1)
    const cancel = { requestId: 9003, reason: 'omp ended the call at 30 s' }
    b.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: cancel })
    await until(() => l.withdraws().length === 1)
    expect(l.withdraws()).toEqual([{ id: l.asks()[0]?.id }])
    // The person's Escape on the dismissed confirm, arriving late: refused, and no 24 h decline.
    const late = await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: false })
    expect((late.error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(pairState()).toBe('requested')
    expect(readdirSync(join(spoolDir(home, 'carol'), 'held'))).toHaveLength(1)
  })

  it('a new ask on a link withdraws the open one first: no confirm stacks behind a stale one (item j)', async () => {
    word(true)
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    const c = await omp(s, 'lab')
    await call(a, 'send', chat([P.carol.address]))
    await call(a, 'send', chat([P.jane.address]))
    const first = call(b, 'status')
    await until(() => l.asks().length === 1)
    const second = call(c, 'status')
    await until(() => l.asks().length === 2)
    expect(l.withdraws()).toEqual([{ id: l.asks()[0]?.id }])
    await first
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true })
    await second
    const rows = JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]
    expect(rows.find((r) => r.b === 'research')).toMatchObject({ state: 'requested' })
    expect(rows.find((r) => r.b === 'lab')).toMatchObject({ state: 'allowed' })
  })

  for (const [what, change] of CHANGES)
    it(`a Yes after ${what} writes no allowed row; the call succeeds, the mail waits`, async () => {
      word(true)
      const s = await start()
      const l = await link(s)
      const a = await window(s, 'personal')
      const b = await omp(s, 'research')
      await call(a, 'send', chat([P.carol.address]))
      const done = call(b, 'status')
      await until(() => l.asks().length === 1)
      change()
      await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true })
      expect(await done).not.toHaveProperty('error')
      expect(pairState()).toBe('requested')
      expect(readdirSync(join(spoolDir(home, 'carol'), 'held'))).toHaveLength(1)
    })

  it("while one of a sender's requests is asked, its request to another identity is still asked there", async () => {
    word(true)
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const l = await link(s)
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    const c = await window(s, 'lab')
    await call(a, 'send', chat([P.carol.address]))
    await call(a, 'send', chat([P.jane.address]))
    const done = call(b, 'status')
    await until(() => l.asks().length === 1)
    // research's dialog is open (personal to research); lab's own request from personal is asked at lab's call.
    await call(c, 'status')
    expect(c.dialogs).toHaveLength(1)
    const row = (to: string) =>
      (JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]).find((r) => r.b === to)
    expect(row('lab')).toMatchObject({ state: 'allowed' })
    expect(row('research')).toMatchObject({ state: 'requested' })
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true })
    await done
    expect(row('research')).toMatchObject({ state: 'allowed' })
  })

  /** The service's side of the omp window `label`'s connection, for the consent port (askPerson's seam). */
  const connOf = (s: Service): ServiceConnection =>
    [...s.connections].find((c) => {
      const exp = c.capabilities.raw.experimental as Json | undefined
      return exp !== undefined && CONSENT_BRIDGE in exp
    }) as ServiceConnection

  it('0.4.2 register: kinds and call_ms; a text ask carries max and placeholder, and its checked text answers', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    await omp(s, 'personal')
    const asked = s.local.consent(connOf(s), {
      kind: 'text',
      title: 'bag: paste',
      message: 'm',
      placeholder: 'invite or code',
      max: 512,
    })
    expect(asked).not.toBeNull()
    await until(() => l.asks().length === 1)
    // call_ms 130000: the cap is 120 s (clamp(call_ms - 10 s, 15 s, 120 s)).
    expect(l.asks()[0]).toMatchObject({ kind: 'text', ms: 120_000, max: 512, placeholder: 'invite or code' })
    await l.request('service/consent-answer', {
      id: l.asks()[0]?.id,
      accepted: true,
      text: '  472-tulip-orbit-cedar ',
    })
    expect(await asked).toEqual({ accepted: true, text: '472-tulip-orbit-cedar' })
  })

  it('a text answer over max, with a line break, or not a string is no answer', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['text'], call_ms: 20_000 })
    await omp(s, 'personal')
    for (const [i, text] of ['x'.repeat(17), 'a\nb', 7, ''].entries()) {
      const asked = s.local.consent(connOf(s), { kind: 'text', title: 't', message: 'm', max: 16 })
      await until(() => l.asks().length === i + 1)
      // call_ms 20000: the cap is 15 s.
      expect(l.asks()[i]?.ms).toBe(15_000)
      await l.request('service/consent-answer', { id: l.asks()[i]?.id, accepted: true, text })
      expect(await asked).toEqual({ accepted: null })
    }
  })

  it('only an ask the service made with fold folds a line break; an answer cannot ask for it (the paste)', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['text'], call_ms: 20_000 })
    await omp(s, 'personal')
    const folded = s.local.consent(connOf(s), { kind: 'text', title: 't', message: 'm', max: 64, fold: true })
    await until(() => l.asks().length === 1)
    // The fold is the service's record of the ask: it is never sent to the extension.
    expect(l.asks()[0]).not.toHaveProperty('fold')
    await l.request('service/consent-answer', {
      id: l.asks()[0]?.id,
      accepted: true,
      text: 'line one\nline two\r\n',
    })
    expect(await folded).toEqual({ accepted: true, text: 'line one line two' })
    // An ask made without fold stays no answer on an inner break, whatever the answer carries.
    const plain = s.local.consent(connOf(s), { kind: 'text', title: 't', message: 'm', max: 64 })
    await until(() => l.asks().length === 2)
    await l.request('service/consent-answer', {
      id: l.asks()[1]?.id,
      accepted: true,
      text: '123\n456',
      fold: true,
    })
    expect(await plain).toEqual({ accepted: null })
  })

  it('a kind the link did not register is null: a 0.4.1 extension gets no text and no show', async () => {
    const s = await start()
    await link(s)
    await omp(s, 'personal')
    expect(s.local.consent(connOf(s), { kind: 'text', title: 't', message: 'm' })).toBeNull()
    expect(s.local.consent(connOf(s), { kind: 'show', title: 't', message: 'm', ms: 1000 })).toBeNull()
  })

  it('a show stands beside a question and is withdrawn by its signal; with under 15 s of the call left, no ask', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['text', 'show'], call_ms: 30_000 })
    await omp(s, 'personal')
    const stop = new AbortController()
    const shown = s.local.consent(
      connOf(s),
      { kind: 'show', title: 'bag: pairing', message: 'code', lines: ['code', 'x'], ms: 600_000 },
      stop.signal,
    )
    await until(() => l.asks().length === 1)
    expect(l.asks()[0]).toMatchObject({ kind: 'show', lines: ['code', 'x'], ms: 600_000 })
    const q = s.local.consent(connOf(s), { kind: 'confirm', title: 't', message: 'm', elapsedMs: 0 })
    await until(() => l.asks().length === 2)
    expect(l.withdraws()).toEqual([])
    stop.abort()
    await until(() => l.withdraws().length === 1)
    expect(l.withdraws()).toEqual([{ id: l.asks()[0]?.id }])
    expect(await shown).toEqual({ accepted: null })
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true })
    expect(await q).toEqual({ accepted: true })
    // 30 s call, 11 s gone: 14 s left before the 5 s margin is under 15 s, so it is not sent.
    const late = s.local.consent(connOf(s), { kind: 'confirm', title: 't', message: 'm', elapsedMs: 11_000 })
    expect(await late).toEqual({ accepted: null, sent: false })
    expect(l.asks()).toHaveLength(2)
  })

  it('pair_accept in an omp window asks the paste as text over the link; no answer is not a No; pair_cancel withdraws it', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    expect(l.asks()[0]).toMatchObject({ kind: 'text', placeholder: 'invite or code', max: 512 })
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    const asked = await first
    expect(asked).toMatchObject({ requested: false, asked: true, note: LINK_AGAIN })
    // The resume asks the paste again; a paste with a control character fails the one text check: no answer, never
    // inviteOf. (A line break in the paste is folded since the wrapped-widget fix, and inviteOf judges the result.)
    const again = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2)
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true, text: 'a\u0007b' })
    const twice = await again
    expect(twice).toMatchObject({ asked: true, note: LINK_AGAIN })
    // A third ask, open while the person cancels in this window: withdrawn at once, and nothing written. Each answer
    // carries the next token: a token serves one call.
    const third = call(b, 'pair_accept', { resume: twice.resume })
    await until(() => l.asks().length === 3)
    expect(await call(b, 'pair_cancel', {})).toEqual({ cancelled: true, was: 'accept', as: 'personal' })
    await until(() => l.withdraws().some((w) => w.id === l.asks()[2]?.id))
    expect((await third).error).toBeDefined()
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
  })

  it('an omp paste left unanswered at the first call and three resumes is asked each time, never rate-limited', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    let token = ''
    for (let i = 0; i < 4; i++) {
      const asked = call(b, 'pair_accept', i === 0 ? { name: 'bob' } : { resume: token })
      await until(() => l.asks().length === i + 1)
      await l.request('service/consent-answer', { id: l.asks()[i]?.id, accepted: null })
      const r = await asked
      expect(r).toMatchObject({ requested: false, asked: true, note: LINK_AGAIN })
      token = String(r.resume)
    }
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'accept' })
  })

  it('pair_invite in an omp window shows the code over the link, never in the result; pair_cancel clears the widget', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const invited = await call(b, 'pair_invite', { name: 'bob' })
    expect(invited).toMatchObject({ invite_open: true, note: BRIDGE_SHOW })
    expect(invited.code ?? invited.invite).toBeUndefined()
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    await until(() => shows().length === 2)
    const shown = shows()[1] as Json
    const code = String((shown.lines as string[])[1]).trim()
    expect(code.length).toBeGreaterThan(5)
    // The code alone on its line: no words of the heading around it.
    expect(code).not.toMatch(/\s/)
    expect(JSON.stringify(invited)).not.toContain(code)
    // The placeholder show was replaced (withdrawn); the code's show stands until the pairing ends, then goes at once.
    expect(l.withdraws().map((w) => w.id)).toContain(shows()[0]?.id)
    expect(l.withdraws().map((w) => w.id)).not.toContain(shown.id)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'invite' })
    await until(() => l.withdraws().some((w) => w.id === shown.id))
  })

  /** personal's audit lines of one event, each its decision and its detail's fields. */
  const audited = (event: string): Json[] =>
    readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
      .split('\n')
      .filter((x) => x !== '')
      .map((x) => JSON.parse(x) as Json)
      .filter((x) => x.event === event)
      .map((x) => ({ decision: x.decision, ...(JSON.parse(String(x.detail ?? '{}')) as Json) }))
  /** A tools/call on window `w` sent raw, with its own id, so the test can cancel it as omp does at its timeout. */
  const raw = (w: Line, id: number, name: string, args: Json): void =>
    w.send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })
  const cancelCall = (w: Line, id: number): void =>
    w.send({
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: { requestId: id, reason: 'omp ended the call at 30 s' },
    })
  /** A record's fields, or null when the bytes are not one (an envelope). */
  const recordOf = (bytes: Uint8Array): Json | null => {
    try {
      return JSON.parse(new TextDecoder().decode(bytes)) as Json
    } catch {
      return null
    }
  }

  it('a first pair_accept cancelled by the client while the paste stands ends its pairing: withdrawn, nothing written, asked afresh', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    raw(b, 9101, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    cancelCall(b, 9101)
    await until(() => l.withdraws().some((w) => w.id === l.asks()[0]?.id))
    const consent = () => audited('policy').filter((d) => d.step === 'consent')
    await until(() => audited('pair').length > 0 && consent().length > 0)
    expect(audited('pair')).toEqual([
      {
        decision: 'reject',
        step: 'decline',
        code: 'cancelled',
        reason: 'client-abort',
        window: 'omp /w/personal',
      },
    ])
    expect(consent()).toEqual([
      {
        decision: 'queue',
        step: 'consent',
        act: 'pair-accept-code',
        kind: 'text',
        host: 'omp',
        said: 'none',
      },
    ])
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
    // The window's next first call is not busy: it asks the paste again, and no answer keeps that pairing.
    const next = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 2)
    expect(l.asks()[1]).toMatchObject({ kind: 'text', placeholder: 'invite or code' })
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: null })
    expect(await next).toMatchObject({ requested: false, asked: true, note: LINK_AGAIN })
    // The cancelled call got no answer, as the protocol has it.
    expect(b.count((m) => m.id === 9101)).toBe(0)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'accept' })
  })

  it('the same once the paste is answered, while the edge reads the invitation: the digits never show, nothing is sent', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const code = String(invited.code ?? invited.invite)
    // Hold the acceptor's reads at the relay once the paste is answered, so the cancel lands inside the edge's step.
    const fetch = relay.fetchRecord.bind(relay)
    const held = Promise.withResolvers<void>()
    let holding = false
    let reached = false
    relay.fetchRecord = async (url, address, kind) => {
      if (holding) {
        reached = true
        await held.promise
      }
      return fetch(url, address, kind)
    }
    raw(b, 9102, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    holding = true
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true, text: code })
    await until(() => reached)
    cancelCall(b, 9102)
    await new Promise((r) => setTimeout(r, 20))
    holding = false
    held.resolve()
    await until(() => audited('pair').length === 1)
    expect(audited('pair')).toEqual([
      {
        decision: 'reject',
        step: 'decline',
        code: 'cancelled',
        reason: 'client-abort',
        window: 'omp /w/personal',
      },
    ])
    expect(l.asks()).toHaveLength(1)
    if (code.startsWith(INVITE_PREFIX)) expect(relay.box(RELAY, readInvite(code).i)).toEqual([])
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
    expect(b.count((m) => m.id === 9102)).toBe(0)
    const next = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 2)
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: null })
    expect(await next).toMatchObject({ requested: false, asked: true, note: LINK_AGAIN })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'accept' })
  }, 30_000)

  it('a first pair_invite cancelled by the client clears the widget at the abort itself; the invitation is withdrawn, and pair_invite starts again', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // Hold the invitation's accept-from at the relay: its address record went out, the call is still open.
    const publish = relay.publish.bind(relay)
    const held = Promise.withResolvers<void>()
    let i = ''
    relay.publish = async (url, bytes) => {
      const r = recordOf(bytes)
      if (i === '' && r?.kind === 'accept-from' && r.owner !== P.alice.address) {
        i = String(r.owner)
        await held.promise
      }
      return publish(url, bytes)
    }
    raw(b, 9103, 'pair_invite', { name: 'bob' })
    await until(() => i !== '')
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    // The making show was sent before the edge began; its frame reaches the link over the socket, which can come after
    // the in-memory relay is held under a loaded machine: waited for, never assumed.
    await until(() => shows().length === 1)
    expect(shows()).toHaveLength(1)
    cancelCall(b, 9103)
    // Withdrawn while the edge is still held: at the abort, not when the call's body settles.
    await until(() => l.withdraws().some((w) => w.id === shows()[0]?.id))
    // A pair_cancel while that end winds down ends nothing twice: one audit line.
    expect(await call(b, 'pair_cancel', {})).toEqual({ cancelled: false, as: 'personal' })
    // A new start in this window meanwhile is told to try again soon, naming neither resume nor pair_cancel.
    const closing = await call(b, 'pair_invite', { name: 'jane' })
    expect(closing).toEqual({ error: 'busy', detail: CLOSING, as: 'personal' })
    expect(String(closing.detail)).not.toContain('pair_cancel')
    held.resolve()
    await until(() => audited('pair').some((d) => d.code === 'cancelled'))
    expect(audited('pair').filter((d) => d.decision === 'reject')).toEqual([
      {
        decision: 'reject',
        step: 'refuse',
        code: 'cancelled',
        reason: 'client-abort',
        window: 'omp /w/personal',
      },
    ])
    // The code was never shown, and I's newest address record names no sealing key: nothing can reach it.
    expect(shows()).toHaveLength(1)
    await until(() => {
      const bytes = relay.records.get(`${RELAY} ${i} address`)
      return bytes !== undefined && (parseRecord(bytes) as AddressRecord).sealing_key === null
    })
    expect(b.count((m) => m.id === 9103)).toBe(0)
    relay.publish = publish
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({
      invite_open: true,
      note: BRIDGE_SHOW,
    })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'invite' })
  }, 30_000)

  it('a first pair_accept cancelled before its first await resolves still ends the pairing it started: client-abort, nothing asked', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // The call and its cancel in one write: the signal is aborted before the body's first await can resolve.
    b.sendAll([
      {
        jsonrpc: '2.0',
        id: 9108,
        method: 'tools/call',
        params: { name: 'pair_accept', arguments: { name: 'bob' } },
      },
      { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 9108, reason: 'at once' } },
    ])
    await until(() => audited('pair').length > 0)
    expect(audited('pair')).toEqual([
      {
        decision: 'reject',
        step: 'decline',
        code: 'cancelled',
        reason: 'client-abort',
        window: 'omp /w/personal',
      },
    ])
    expect(l.asks()).toEqual([])
    const next = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    expect(await next).toMatchObject({ asked: true, note: LINK_AGAIN })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  })

  const CLIENT_ABORT = {
    decision: 'reject',
    step: 'refuse',
    code: 'cancelled',
    reason: 'client-abort',
    window: 'omp /w/personal',
  }
  /**
   * The widget's shows on link `l` in the order it read them, each with whether a withdraw for it came after it. A show
   * asked after its pairing ended is never withdrawn (the end withdrew the one it had), so withdrawn: false catches it.
   */
  const widget = (l: { seen: Json[] }): { message: unknown; withdrawn: boolean }[] =>
    l.seen.flatMap((m, i) => {
      const p = m.params as Json
      if (m.method !== 'service/consent-ask' || p.kind !== 'show') return []
      const after = l.seen.slice(i + 1)
      const withdrawn = after.some(
        (w) => w.method === 'service/consent-withdraw' && (w.params as Json).id === p.id,
      )
      return [{ message: p.message, withdrawn }]
    })
  /** Once the edge's run of the cancelled pairing has ended, a round trip on the link: every message before it is read. */
  const settled = async (l: { request(m: string, p: Json): Promise<Json> }): Promise<void> => {
    await until(() => log.lines.some((x) => x.event === 'pair-ended'), 10_000)
    await l.request('service/consent-answer', { id: 'none', accepted: null })
  }

  it('a first pair_invite cancelled in the same write as its call ends the pairing at once: client-abort, no invitation, its widget withdrawn', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // The call and its cancel in one write: the SDK aborts the call's signal before the body runs.
    b.sendAll([
      {
        jsonrpc: '2.0',
        id: 9109,
        method: 'tools/call',
        params: { name: 'pair_invite', arguments: { name: 'bob' } },
      },
      { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 9109, reason: 'at once' } },
    ])
    await until(() => audited('pair').some((d) => d.code === 'cancelled'), 10_000)
    await settled(l)
    // The end alone: no invitation was opened for a call already cancelled.
    expect(audited('pair')).toEqual([CLIENT_ABORT])
    // Only the placeholder was shown, never a code, and it was withdrawn.
    expect(widget(l)).toEqual([{ message: makingLine('bob'), withdrawn: true }])
    expect(b.count((m) => m.id === 9109)).toBe(0)
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  }, 30_000)

  it('a first pair_invite cancelled once its widget is up ends the pairing it started: client-abort, every show withdrawn', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // The invitation's accept-from held, so the call is still open when its cancel arrives.
    const publish = relay.publish.bind(relay)
    const held = Promise.withResolvers<void>()
    relay.publish = async (url, bytes) => {
      const r = recordOf(bytes)
      if (r?.kind === 'accept-from' && r.owner !== P.alice.address) await held.promise
      return publish(url, bytes)
    }
    raw(b, 9111, 'pair_invite', { name: 'bob' })
    await until(() => l.asks().some((q) => q.kind === 'show'))
    cancelCall(b, 9111)
    // The cancel ended the pairing (its show withdrawn); then the held edge goes on and sees it.
    await until(() => l.withdraws().length > 0)
    relay.publish = publish
    held.resolve()
    await until(() => audited('pair').some((d) => d.code === 'cancelled'), 10_000)
    await settled(l)
    expect(audited('pair').filter((d) => d.decision === 'reject')).toEqual([CLIENT_ABORT])
    const shown = widget(l)
    expect(shown.length).toBeGreaterThan(0)
    expect(shown.filter((x) => !x.withdrawn)).toEqual([])
    expect(b.count((m) => m.id === 9111)).toBe(0)
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  }, 30_000)

  it('the closing answer is bounded by the 30 s wait: an edge that never ends is let go, and the next start opens', async () => {
    const timers = new ManualTimers()
    const s = await start({ pairPollMs: 2, timers })
    await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const publish = relay.publish.bind(relay)
    const held = Promise.withResolvers<void>()
    let i = ''
    relay.publish = async (url, bytes) => {
      const r = recordOf(bytes)
      if (i === '' && r?.kind === 'accept-from' && r.owner !== P.alice.address) {
        i = String(r.owner)
        await held.promise
      }
      return publish(url, bytes)
    }
    raw(b, 9110, 'pair_invite', { name: 'bob' })
    await until(() => i !== '')
    cancelCall(b, 9110)
    await until(() => timers.live().includes(30_000))
    expect(await call(b, 'pair_invite', { name: 'bob' })).toEqual({
      error: 'busy',
      detail: CLOSING,
      as: 'personal',
    })
    // The edge is still held: the wait's 30 s run out, the pairing is let go and audited, and a start opens.
    timers.fire((ms) => ms === 30_000)
    await until(() => audited('pair').some((d) => d.code === 'cancelled'))
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({
      invite_open: true,
      note: BRIDGE_SHOW,
    })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
    held.resolve()
  }, 30_000)

  it('a resume cancelled in the same write as its call ends at once: it holds no wait for max_tool_seconds', async () => {
    const timers = new ManualTimers()
    const s = await start({ pairPollMs: 2, timers })
    await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const invited = await call(b, 'pair_invite', { name: 'bob' })
    const before = timers.live()
    b.sendAll([
      {
        jsonrpc: '2.0',
        id: 9301,
        method: 'tools/call',
        params: { name: 'pair_invite', arguments: { resume: invited.resume } },
      },
      { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 9301, reason: 'at once' } },
    ])
    // The cancelled resume spent the token (so it ran); its window's timer and its progress are gone with it.
    expect(await call(b, 'pair_invite', { resume: invited.resume })).toMatchObject({ error: 'usage' })
    expect(timers.live()).toEqual(before)
    expect(b.count((m) => m.id === 9301)).toBe(0)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  }, 30_000)

  it('a token dies at once on cancel: a resume while the cancel winds down is refused, and busy says it is closing', async () => {
    const s = await start({ pairPollMs: 2 })
    await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const invited = await call(b, 'pair_invite', { name: 'bob' })
    // Hold every publish from here: the edge's withdrawal of the invitation, so pair_cancel waits on it.
    const publish = relay.publish.bind(relay)
    const held = Promise.withResolvers<void>()
    let reached = false
    relay.publish = async (url, bytes) => {
      reached = true
      await held.promise
      return publish(url, bytes)
    }
    const cancelling = call(b, 'pair_cancel', {})
    await until(() => reached)
    expect(await call(b, 'pair_invite', { resume: invited.resume })).toMatchObject({ error: 'usage' })
    expect(await call(b, 'pair_invite', { name: 'bob' })).toEqual({
      error: 'busy',
      detail: CLOSING,
      as: 'personal',
    })
    held.resolve()
    relay.publish = publish
    expect(await cancelling).toEqual({ cancelled: true, was: 'invite', as: 'personal' })
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ invite_open: true })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  }, 30_000)

  it('a paste left to its expiry is reported by the token once, then it dies; the window starts again at once', async () => {
    const timers = new ManualTimers()
    const s = await start({ timers })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    const asked = await first
    expect(asked).toMatchObject({ asked: true, note: LINK_AGAIN })
    // The invitation's longest life passes with no paste.
    timers.fire((ms) => ms === 600_000)
    await until(() => audited('pair').length > 0)
    expect(audited('pair')).toEqual([{ decision: 'reject', step: 'decline', code: 'invite-expired' }])
    expect(await call(b, 'pair_accept', { resume: asked.resume })).toMatchObject({ error: 'invite-expired' })
    expect(await call(b, 'pair_accept', { resume: asked.resume })).toMatchObject({ error: 'usage' })
    // Not busy and not closing: the next start asks the paste.
    const next = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 2)
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: null })
    expect(await next).toMatchObject({ asked: true, note: LINK_AGAIN })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  })

  it("a paste expiring under a resume's open question answers invite-expired there, once; then the token dies", async () => {
    const timers = new ManualTimers()
    const s = await start({ timers })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    const asked = await first
    const resumed = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2)
    // The invitation's longest life passes while that paste question is open: withdrawn, and the call says why.
    timers.fire((ms) => ms === 600_000)
    expect(await resumed).toMatchObject({ error: 'invite-expired', as: 'personal' })
    expect(l.withdraws().map((w) => w.id)).toContain(l.asks()[1]?.id)
    expect(audited('pair')).toEqual([{ decision: 'reject', step: 'decline', code: 'invite-expired' }])
    // Reported once: the token that call spent is dead, and no answer carried another.
    expect(await call(b, 'pair_accept', { resume: asked.resume })).toMatchObject({ error: 'usage' })
    const next = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 3)
    await l.request('service/consent-answer', { id: l.asks()[2]?.id, accepted: null })
    expect(await next).toMatchObject({ asked: true, note: LINK_AGAIN })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
    expect(audited('pair')).toHaveLength(2)
  })

  it('an expired paste nobody resumes never strands the window: the next start is neither busy nor closing', async () => {
    const timers = new ManualTimers()
    const s = await start({ timers })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    await first
    timers.fire((ms) => ms === 600_000)
    await until(() => audited('pair').length > 0)
    const next = call(b, 'pair_invite', { name: 'bob' })
    expect(await next).toMatchObject({ invite_open: true, note: BRIDGE_SHOW })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'invite' })
  })

  it("a cancelled first call that started no pairing (the visibility dialog) never ends another window's pairing", async () => {
    word(true)
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const a = await window(s, 'personal', 'never')
    const b = await omp(s, 'personal')
    raw(a, 9107, 'pair_invite', { for: P.alice.address })
    await a.next((m) => m.method === 'elicitation/create')
    const started = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    cancelCall(a, 9107)
    await new Promise((r) => setTimeout(r, 30))
    expect(l.withdraws()).toEqual([])
    expect(audited('pair')).toEqual([])
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    expect(await started).toMatchObject({ asked: true, note: LINK_AGAIN })
    expect(await call(b, 'pair_cancel', {})).toEqual({ cancelled: true, was: 'accept', as: 'personal' })
  })

  it("a resume cancelled by the client keeps the inviter's held request; busy in the window gives a fresh token, which asks the six again", async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const a = await omp(s, 'personal')
    const other = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await call(a, 'pair_invite', { name: 'bob' })
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    await until(() => shows().length === 2)
    const code = String(((shows()[1] as Json).lines as string[])[1]).trim()
    let digits = ''
    bob.person.push(() => ({ action: 'accept', content: { invite: code } }))
    bob.person.push((m) => {
      digits = digitsIn(m)
      return { action: 'accept', content: { confirm: true } }
    })
    const accepted = await bob.call('pair_accept', { name: 'alice' })
    const texts = () => l.asks().filter((q) => q.kind === 'text')
    raw(a, 9104, 'pair_invite', { resume: invited.resume })
    await until(() => texts().length === 1, 10_000)
    cancelCall(a, 9104)
    await until(() => l.withdraws().some((w) => w.id === texts()[0]?.id))
    await new Promise((r) => setTimeout(r, 20))
    // Not ended: no pair reject. The token that call spent is dead, and its answer, with the next one, was dropped.
    expect(audited('pair').filter((d) => d.decision === 'reject')).toEqual([])
    expect(await call(a, 'pair_invite', { resume: invited.resume })).toMatchObject({ error: 'usage' })
    // Another window of the identity is told it runs elsewhere, with no token.
    const elsewhere = await call(other, 'pair_invite', { name: 'jane' })
    expect(elsewhere).toEqual({
      error: 'busy',
      detail: `${BUSY} (it runs in the omp window at /w/personal)`,
      as: 'personal',
    })
    const busy = await call(a, 'pair_invite', { name: 'jane' })
    expect(busy).toEqual({
      error: 'busy',
      detail: BUSY_HERE('pair_invite'),
      resume: busy.resume,
      as: 'personal',
    })
    expect(await call(other, 'pair_invite', { resume: busy.resume })).toMatchObject({ error: 'usage' })
    const third = call(a, 'pair_invite', { resume: busy.resume })
    await until(() => texts().length === 2, 10_000)
    await l.request('service/consent-answer', { id: texts()[1]?.id, accepted: true, text: digits })
    expect(await third).toMatchObject({ paired: true, peer: P.bob.address, name: 'bob' })
    expect(await bob.call('pair_accept', { resume: accepted.resume })).toMatchObject({ paired: true })
    // The token is dead once its pairing has ended and answered.
    expect(await call(a, 'pair_invite', { resume: busy.resume })).toMatchObject({ error: 'usage' })
    // No token reaches the service log or the audit, not even a 7-character prefix of one.
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    for (const t of [invited.resume, busy.resume]) {
      // The answer's token begins with the identity's label; the token itself follows it.
      const token = String(t).split(':').at(-1) as string
      expect(token).toMatch(/^[0-9a-f]{32}$/)
      expect(log.text()).not.toContain(token.slice(0, 7))
      expect(audit).not.toContain(token.slice(0, 7))
    }
  }, 30_000)

  it("an acceptor's digits confirm cancelled by the client stays held; the fresh token from busy asks it again", async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', {
      id: l.asks()[0]?.id,
      accepted: true,
      text: String(invited.code ?? invited.invite),
    })
    const asked = await first
    expect(asked).toMatchObject({ note: LINK_DIGITS })
    raw(b, 9105, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2, 10_000)
    cancelCall(b, 9105)
    await until(() => l.withdraws().some((w) => w.id === l.asks()[1]?.id))
    const busy = await call(b, 'pair_accept', { name: 'bob' })
    expect(busy).toMatchObject({ error: 'busy', detail: BUSY_HERE('pair_accept') })
    const no = call(b, 'pair_accept', { resume: busy.resume })
    await until(() => l.asks().length === 3, 10_000)
    expect(l.asks()[2]).toMatchObject({ title: 'bag: read these check digits to your peer' })
    await l.request('service/consent-answer', { id: l.asks()[2]?.id, accepted: false })
    expect(await no).toMatchObject({ error: 'declined' })
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
  }, 30_000)

  it("the service log names each link ask's cap and how it ended, never its words, its answer or a code", async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const ev = (e: string): Json[] => log.lines.filter((x) => x.event === e).map((x) => x.fields as Json)
    expect(ev('consent-link')).toEqual([{ pid: PID, kinds: ['confirm', 'text', 'show'], call_ms: 130_000 }])
    // An answered ask (no answer is still an answer from the link), then a client abort under the cap.
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: null })
    const asked = await first
    raw(b, 9106, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2)
    cancelCall(b, 9106)
    await until(() => ev('link-end').length === 2)
    // A third ask ended by pair_cancel, whose why the pairing's abort carries.
    const busy = await call(b, 'pair_accept', { name: 'bob' })
    const third = call(b, 'pair_accept', { resume: busy.resume })
    await until(() => l.asks().length === 3)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
    await third
    await until(() => ev('link-end').length === 3)
    const ids = l.asks().map((q) => q.id)
    const asks = ev('link-ask')
    expect(asks.map((x) => [x.id, x.act, x.kind])).toEqual(ids.map((id) => [id, 'pair-accept-code', 'text']))
    for (const x of asks) expect([typeof x.cap_ms, typeof x.elapsed_ms]).toEqual(['number', 'number'])
    const ends = ev('link-end')
    expect(ends.map((x) => [x.id, x.act, x.kind, x.end])).toEqual([
      [ids[0], 'pair-accept-code', 'text', 'answered'],
      [ids[1], 'pair-accept-code', 'text', 'client-abort'],
      [ids[2], 'pair-accept-code', 'text', 'cancel'],
    ])
    for (const x of ends) expect(typeof x.open_ms).toBe('number')
    // The abort came long before the cap: the link's call_ms is named beside it, for a mis-told one.
    expect(ends[1]).toMatchObject({ mismatch: 'call-ms', call_ms: 130_000 })
    expect(ends[0]).not.toHaveProperty('mismatch')
    expect(ends[2]).not.toHaveProperty('mismatch')
    const text = log.text()
    for (const words of [l.asks()[0]?.title, l.asks()[0]?.message, 'invite or code'])
      expect(text).not.toContain(String(words))
  })

  it('a first call past 6 starts in 600 s from one window is rate-limited and starts nothing; another window still starts', async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // Each start asks the paste once, gets no answer (not a No, so the answered bound is not reached) and is cancelled.
    for (let n = 0; n < 6; n++) {
      const started = call(b, 'pair_accept', { name: 'bob' })
      await until(() => l.asks().length === n + 1)
      await l.request('service/consent-answer', { id: l.asks()[n]?.id, accepted: null })
      expect(await started).toMatchObject({ asked: true, note: LINK_AGAIN })
      expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true })
    }
    const seventh = await call(b, 'pair_accept', { name: 'bob' })
    expect(seventh).toMatchObject({ error: 'rate-limited', as: 'personal' })
    expect(String(seventh.detail)).toMatch(/^6 pairings were started here lately: start again in \d+ s$/)
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ error: 'rate-limited' })
    expect(l.asks()).toHaveLength(6)
    expect(audited('pair')).toHaveLength(6)
    // The bound is per window: another window of the identity starts.
    const c = await omp(s, 'personal')
    const fresh = call(c, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 7)
    await l.request('service/consent-answer', { id: l.asks()[6]?.id, accepted: null })
    expect(await fresh).toMatchObject({ asked: true, note: LINK_AGAIN })
    expect(await call(c, 'pair_cancel', {})).toMatchObject({ cancelled: true })
  })

  it('a 0.4.1 link (no kinds registered) cannot pair: no-elicitation, the old-extension words, nothing shown', async () => {
    const s = await start()
    const l = await link(s)
    const b = await omp(s, 'personal')
    expect(await call(b, 'pair_accept', { name: 'bob' })).toMatchObject({ error: 'no-elicitation' })
    expect(await call(b, 'pair_invite', { name: 'bob' })).toMatchObject({ error: 'no-elicitation' })
    expect(l.asks()).toEqual([])
  })

  it('an omp inviter pairs over the link: a wrong typed six counts a try, no answer and a line break are asked again, the right six pair', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const a = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await call(a, 'pair_invite', { name: 'bob' })
    expect(invited).toMatchObject({ invite_open: true, note: BRIDGE_SHOW })
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    await until(() => shows().length === 2)
    const code = String(((shows()[1] as Json).lines as string[])[1]).trim()
    // bob pastes the code and confirms the digits he reads out; his request reaches the omp window's held ask.
    let digits = ''
    bob.person.push(() => ({ action: 'accept', content: { invite: code } }))
    bob.person.push((m) => {
      digits = digitsIn(m)
      return { action: 'accept', content: { confirm: true } }
    })
    const accepted = await bob.call('pair_accept', { name: 'alice' })
    expect(accepted).toMatchObject({ requested: true })
    const texts = () => l.asks().filter((q) => q.kind === 'text')
    const answer = async (i: number, body: Json) => {
      await until(() => texts().length === i + 1, 10_000)
      await l.request('service/consent-answer', { id: texts()[i]?.id, ...body })
    }
    // A wrong six: one try spent, asked again in the same call with the tries left (the address on its own line).
    const first = call(a, 'pair_invite', { resume: invited.resume })
    await answer(0, { accepted: true, text: '000 000' })
    await until(() => texts().length === 2, 10_000)
    expect(String(texts()[1]?.message)).toContain('No match. Tries left: 2.')
    expect(String(texts()[1]?.message).split('\n')).toHaveLength(3)
    // No answer: not a try, and the call answers pending with the request held.
    await answer(1, { accepted: null })
    const once = await first
    expect(once).toMatchObject({ pending: true, note: LINK_AGAIN })
    // A line break inside the answer fails the link's one text check: no answer again, never a try. (Whitespace at
    // either end is trimmed first, as for every text answer.)
    const second = call(a, 'pair_invite', { resume: once.resume })
    await answer(2, { accepted: true, text: `${digits.slice(0, 3)}\n${digits.slice(4)}` })
    const twice = await second
    expect(twice).toMatchObject({ pending: true, note: LINK_AGAIN })
    // The right six, at the next resume: paired both sides.
    const third = call(a, 'pair_invite', { resume: twice.resume })
    await answer(3, { accepted: true, text: digits })
    expect(await third).toMatchObject({ paired: true, peer: P.bob.address, name: 'bob' })
    expect(String(texts()[3]?.message)).toContain('No match. Tries left: 2.')
    expect(await bob.call('pair_accept', { resume: accepted.resume })).toMatchObject({
      paired: true,
      name: 'alice',
    })
    // The code's widget went at the pairing's end.
    await until(() => l.withdraws().some((w) => w.id === shows()[1]?.id))
  }, 30_000)

  it('an omp inviter whose person types three wrong sixes ends digits-mismatch, nothing written', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const a = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await call(a, 'pair_invite', { name: 'bob' })
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    await until(() => shows().length === 2)
    const code = String(((shows()[1] as Json).lines as string[])[1]).trim()
    bob.person.push(() => ({ action: 'accept', content: { invite: code } }))
    bob.person.push(() => ({ action: 'accept', content: { confirm: true } }))
    await bob.call('pair_accept', { name: 'alice' })
    const texts = () => l.asks().filter((q) => q.kind === 'text')
    const end = call(a, 'pair_invite', { resume: invited.resume })
    for (let i = 0; i < 3; i++) {
      await until(() => texts().length === i + 1, 10_000)
      await l.request('service/consent-answer', { id: texts()[i]?.id, accepted: true, text: '000000' })
    }
    expect(await end).toMatchObject({ error: 'digits-mismatch' })
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
  }, 30_000)

  it('an omp acceptor pastes the code over the link, then confirms the check digits in the next call: paired', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const code = String(invited.code ?? invited.invite)
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    expect(l.asks()[0]).toMatchObject({ kind: 'text' })
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true, text: code })
    const asked = await first
    expect(asked).toMatchObject({ requested: false, asked: true, note: LINK_DIGITS })
    // The next call asks the check digits' Yes; bob's person types what was read out.
    const done = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2, 10_000)
    const digits = digitsIn(String(l.asks()[1]?.message))
    expect(digits).toMatch(/^\d{3} \d{3}$/)
    expect(l.asks()[1]).toMatchObject({ title: 'bag: read these check digits to your peer' })
    bob.person.push(() => ({ action: 'accept', content: { digits } }))
    const inviter = bob.call('pair_invite', { resume: invited.resume })
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true })
    expect(await inviter).toMatchObject({ paired: true, name: 'alice' })
    expect(await done).toMatchObject({ paired: true, peer: P.bob.address, name: 'bob' })
  }, 30_000)

  // The pairing's own end withdraws its open link question (the merged signal of pairing.ts #within): a withdraw is no
  // answer there, never unseen, so each call answers the cancel's own refusal, never no-elicitation.
  const CANCELLED = {
    error: 'cancelled',
    detail: 'your user cancelled this pairing (pair_cancel): nothing was written',
  }
  const unseenLines = (): string =>
    log
      .text()
      .split('\n')
      .filter((x) => x.includes('no-elicitation'))
      .join('\n')

  it("pair_cancel at once under omp's paste, its check digits and its code's show: each call answers the cancel, never no-elicitation", async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    // The paste, at the first call.
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'accept' })
    expect(await first).toMatchObject(CANCELLED)
    // The check digits, at the resume after the paste.
    const bob = await peer(P.bob)
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const accepting = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 2)
    const code = String(invited.code ?? invited.invite)
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true, text: code })
    const asked = await accepting
    const digits = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 3, 10_000)
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'accept' })
    expect(await digits).toMatchObject(CANCELLED)
    await until(() => l.withdraws().some((w) => w.id === l.asks()[2]?.id))
    // The code's show, under the inviter's waiting resume.
    const opened = await call(b, 'pair_invite', { name: 'carol' })
    const shows = () => l.asks().filter((q) => q.kind === 'show')
    await until(() => shows().length === 2)
    const waiting = call(b, 'pair_invite', { resume: opened.resume })
    expect(await call(b, 'pair_cancel', {})).toMatchObject({ cancelled: true, was: 'invite' })
    expect(await waiting).toMatchObject(CANCELLED)
    await until(() => l.withdraws().some((w) => w.id === shows()[1]?.id))
    expect(unseenLines()).toBe('')
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
    // The window is still bound: a cancel leaves no refusal memory and binds nothing anew.
    expect(await call(b, 'status', {})).toMatchObject({ as: 'personal' })
  }, 30_000)

  it("the window's close at once under omp's paste ends the pairing as a close: audited once, nothing written, no no-elicitation", async () => {
    const s = await start()
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const socket = sockets.at(-1) as Socket
    raw(b, 9201, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    socket.destroy()
    await until(() => l.withdraws().some((w) => w.id === l.asks()[0]?.id))
    await until(() => audited('pair').length > 0)
    expect(audited('pair')).toEqual([
      { decision: 'reject', step: 'decline', code: 'cancelled', reason: 'close', window: 'omp /w/personal' },
    ])
    expect(unseenLines()).toBe('')
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
  })

  it('an omp acceptor pastes a code copied from a wrapped widget, with a line break at each wrap: it still pairs', async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const bob = await peer(P.bob)
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const code = String(invited.code ?? invited.invite)
    // As omp's widget wraps it: an invite string at columns 60 and 120, a code after each of its hyphens.
    const wrapped = code.startsWith(INVITE_PREFIX)
      ? `${code.slice(0, 60)}\n${code.slice(60, 120)}\r\n${code.slice(120)}`
      : code.replaceAll('-', '-\n')
    expect(wrapped).toContain('\n')
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true, text: wrapped })
    const asked = await first
    expect(asked).toMatchObject({ requested: false, asked: true, note: LINK_DIGITS })
    const done = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 2, 10_000)
    const digits = digitsIn(String(l.asks()[1]?.message))
    bob.person.push(() => ({ action: 'accept', content: { digits } }))
    const inviter = bob.call('pair_invite', { resume: invited.resume })
    await l.request('service/consent-answer', { id: l.asks()[1]?.id, accepted: true })
    expect(await inviter).toMatchObject({ paired: true, name: 'alice' })
    expect(await done).toMatchObject({ paired: true, peer: P.bob.address, name: 'bob' })
  }, 30_000)

  it("an omp acceptor's No at the check digits declines; a pasted text that is no code is bad-code, nothing sent", async () => {
    const s = await start({ pairPollMs: 2 })
    const l = await link(s, PID, undefined, { kinds: ['confirm', 'text', 'show'], call_ms: 130_000 })
    const b = await omp(s, 'personal')
    const bob = await peer(P.bob)
    // A printable paste that is neither a code nor an invite string: the edge's strict parse, the second guard.
    const bad = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 1)
    await l.request('service/consent-answer', { id: l.asks()[0]?.id, accepted: true, text: 'hello there' })
    expect(await bad).toMatchObject({ error: 'bad-code' })
    const invited = await bob.call('pair_invite', { name: 'alice' })
    const first = call(b, 'pair_accept', { name: 'bob' })
    await until(() => l.asks().length === 2)
    await l.request('service/consent-answer', {
      id: l.asks()[1]?.id,
      accepted: true,
      text: String(invited.code ?? invited.invite),
    })
    const asked = await first
    // No answer to the digits first: pending; then the person's No declines.
    const again = call(b, 'pair_accept', { resume: asked.resume })
    await until(() => l.asks().length === 3, 10_000)
    await l.request('service/consent-answer', { id: l.asks()[2]?.id, accepted: null })
    const pending = await again
    expect(pending).toMatchObject({ pending: true, note: LINK_AGAIN })
    const no = call(b, 'pair_accept', { resume: pending.resume })
    await until(() => l.asks().length === 4, 10_000)
    await l.request('service/consent-answer', { id: l.asks()[3]?.id, accepted: false })
    expect(await no).toMatchObject({ error: 'declined' })
    for (const f of ['trust.json', 'names.json']) expect(existsSync(join(home, f))).toBe(false)
  }, 30_000)

  it('with no link the window is not asked; a first registration after its hello from a non-omp peer is refused (L2)', async () => {
    word(true)
    // The late registration's connection is not omp PID's own: refused by the peer check, with its line, not L2's.
    const s = await start({ peer: async () => 'other' })
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(pairState()).toBe('requested')
    expect(OLD_EXTENSION).toContain('bag host install omp --user again and restarts omp')
    const late = await link(s)
    expect((late.reg.error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(late.asks()).toEqual([])
    const audit = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8')
    // The audit line holds the policy text as an escaped JSON string, so a line's end reads \" in the file.
    expect(audit).toContain(`consent registration refused for omp ${PID}: peer is not omp ${PID}\\"`)
    expect(audit).not.toContain(`consent registration refused for omp ${PID}\\"`)
  })

  it('a first registration after its hello is taken when the peer is omp itself (L2 lifted for a verified peer)', async () => {
    word(true)
    const asked: number[] = []
    const s = await start({
      peer: async (_socket, pid) => {
        asked.push(pid)
        return 'match'
      },
    })
    await omp(s, 'research')
    const late = await link(s)
    expect(typeof (late.reg.result as Json).secret).toBe('string')
    expect(asked).toEqual([PID])
    expect(existsSync(join(s.paths.dir, `consent-${PID}.json`))).toBe(true)
    const linked = log.lines.filter((x) => x.event === 'consent-link').map((x) => x.fields as Json)
    expect(linked).toEqual([{ pid: PID, kinds: ['confirm'], call_ms: null, late: true }])
  })

  it("at start, a dead omp's consent hash is removed and a live one's kept (L3)", async () => {
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    for (const pid of [PID, PID + 9])
      writeFileSync(join(home, 'run', `consent-${pid}.json`), '{"hash":"x"}', { mode: 0o600 })
    await start({ alive: (pid) => pid === PID })
    expect(readdirSync(join(home, 'run')).filter((f) => f.startsWith('consent-'))).toEqual([
      `consent-${PID}.json`,
    ])
  })

  it('the first registration wins; a re-registration then needs the secret while the pid lives', async () => {
    const s = await start({ alive: (pid) => pid === PID })
    const first = await link(s)
    const secret = String((first.reg.result as Json).secret)
    expect(secret).toMatch(/^[0-9a-f]{64}$/)
    expect(statSync(join(s.paths.dir, `consent-${PID}.json`)).mode & 0o777).toBe(0o600)
    expect(readFileSync(join(s.paths.dir, `consent-${PID}.json`), 'utf8')).not.toContain(secret)
    const second = await link(s)
    expect((second.reg.error as Json).data).toMatchObject({ code: 'not-authorized' })
    first.socket.destroy()
    await new Promise((r) => setTimeout(r, 20))
    const thief = await link(s)
    expect((thief.reg.error as Json).data).toMatchObject({ code: 'not-authorized' })
    const back = await link(s, PID, secret)
    expect(back.reg.result).toEqual({})
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(
      audit.split('\n').filter((x) => x.includes(`consent registration refused for omp ${PID}`)),
    ).toHaveLength(2)
  })
})

describe('the peer check on a consent registration: only omp itself registers for its pid', () => {
  const PID = 777_002
  /** A connection after its hello, whose register requests go out without waiting; answers and the close, kept. */
  async function raw(s: Service) {
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((r) => socket.once('connect', () => r()))
    const seen: Json[] = []
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        seen.push(JSON.parse(buf.slice(0, i)) as Json)
        buf = buf.slice(i + 1)
      }
    })
    const send = (id: number, method: string, params: Json) =>
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    const answer = async (id: number): Promise<Json> => {
      await until(() => seen.some((m) => m.id === id))
      return seen.find((m) => m.id === id) as Json
    }
    send(0, 'service/hello', { contract: 1, token: s.token.toString('hex'), host: 'omp', cwd: '/w' })
    await answer(0)
    const register = (id: number, pid = PID) => send(id, 'service/consent-register', { pid })
    return { socket, register, answer }
  }
  const audit = () => readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
  const file = (s: Service) => join(s.paths.dir, `consent-${PID}.json`)
  /** A fake lookup that answers only when the test releases it. */
  function held() {
    const waiting: ((p: Peer) => void)[] = []
    return { waiting, peer: () => new Promise<Peer>((r) => waiting.push(r)) }
  }

  for (const [peer, line] of [
    ['other', `peer is not omp ${PID}`],
    ['unavailable', 'peer lookup unavailable'],
  ] as const)
    it(`a peer lookup that answers ${peer} is refused, writes no secret file, and the connection is closed`, async () => {
      const s = await start({ peer: async () => peer })
      const c = await raw(s)
      c.register(1)
      expect(((await c.answer(1)).error as Json).data).toMatchObject({ code: 'not-authorized' })
      await until(() => c.socket.destroyed)
      expect(existsSync(file(s))).toBe(false)
      expect(audit()).toContain(`consent registration refused for omp ${PID}: ${line}\\"`)
    })

  it('a lookup with no answer in its limit is refused as timed out, and the connection is closed', async () => {
    const h = held()
    const s = await start({ peer: h.peer, peerMs: 50 })
    const c = await raw(s)
    c.register(1)
    expect(((await c.answer(1)).error as Json).data).toMatchObject({ code: 'not-authorized' })
    await until(() => c.socket.destroyed)
    expect(existsSync(file(s))).toBe(false)
    expect(audit()).toContain(`consent registration refused for omp ${PID}: peer lookup timed out\\"`)
    // An answer after the limit changes nothing: still no link and no file.
    for (const r of h.waiting) r('match')
    await new Promise((r) => setTimeout(r, 20))
    expect(existsSync(file(s))).toBe(false)
  })

  it('a lookup past its limit frees its slot at the limit: four stuck lookups do not make the next four busy', async () => {
    const h = held()
    const s = await start({ peer: h.peer, peerMs: 50 })
    const first = await Promise.all([1, 2, 3, 4].map(() => raw(s)))
    for (const [i, c] of first.entries()) c.register(1, PID + i)
    for (const c of first)
      expect(((await c.answer(1)).error as Json).data).toMatchObject({ code: 'not-authorized' })
    // None of the four lookups has answered, yet their slots are free: four more each get a lookup, none busy.
    const next = await Promise.all([1, 2, 3, 4].map(() => raw(s)))
    for (const [i, c] of next.entries()) c.register(1, PID + 10 + i)
    for (const c of next)
      expect(((await c.answer(1)).error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(h.waiting).toHaveLength(8)
    expect(audit()).not.toContain('too many peer lookups')
    for (const r of h.waiting) r('match')
  })

  it('a lookup that throws at once is unavailable and frees its slot', async () => {
    let calls = 0
    const s = await start({
      peer: () => {
        calls++
        throw new Error('no lookup')
      },
    })
    for (const i of [1, 2, 3, 4, 5]) {
      const c = await raw(s)
      c.register(1, PID + i)
      expect(((await c.answer(1)).error as Json).data).toMatchObject({ code: 'not-authorized' })
    }
    expect(calls).toBe(5)
    expect(audit()).toContain(`consent registration refused for omp ${PID + 5}: peer lookup unavailable\\"`)
  })

  it('a match is taken: the lookup is asked for this connection and pid, and the secret is answered', async () => {
    const asked: [unknown, number][] = []
    const s = await start({
      alive: (pid) => pid === PID,
      peer: async (socket, pid) => {
        asked.push([socket, pid])
        return 'match'
      },
    })
    const c = await raw(s)
    c.register(1)
    expect(((await c.answer(1)).result as Json).secret).toMatch(/^[0-9a-f]{64}$/)
    expect(asked.map(([, pid]) => pid)).toEqual([PID])
    expect(asked[0]?.[0]).toBeDefined()
    expect(existsSync(file(s))).toBe(true)
    expect(c.socket.destroyed).toBe(false)
  })

  it('more lookups than the cap are refused busy: three per connection, four in the whole service', async () => {
    const h = held()
    const s = await start({ peer: h.peer })
    const one = await raw(s)
    for (const id of [1, 2, 3, 4]) one.register(id, PID + id)
    expect(((await one.answer(4)).error as Json).data).toMatchObject({ code: 'busy' })
    await until(() => h.waiting.length === 3)
    const two = await raw(s)
    two.register(1, PID + 10)
    two.register(2, PID + 11)
    expect(((await two.answer(2)).error as Json).data).toMatchObject({ code: 'busy' })
    expect(h.waiting).toHaveLength(4)
    expect(audit()).toContain(`consent registration refused for omp ${PID + 4}: too many peer lookups\\"`)
    for (const r of h.waiting) r('other')
  })
})

describe('a refused run/local.json fails closed: delivery off, each bound window only its own', () => {
  const short = (a: string): string => `${a.slice(0, 16)}\u2026${a.slice(-4)}`
  const labels = (v: Json): unknown[] => (v.identities as Json[]).map((i) => [i.label, i.address])
  /** research hidden, local delivery on, 0600; personal and lab allowed both ways. */
  async function three(): Promise<{ s: Service; a: Line; l: Line }> {
    word(true)
    hide('research')
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    const l = await window(s, 'lab')
    await call(a, 'send', chat([P.jane.address]))
    await call(l, 'status')
    const table = JSON.parse(readFileSync(localPeersPath(home), 'utf8')) as { pairs: Json[] }
    expect(table.pairs).toMatchObject([{ b: 'lab', state: 'allowed' }])
    return { s, a, l }
  }

  for (const how of ['0644', 'a symlink', 'a file that does not read'] as const)
    it(`refused as ${how}: identities lists only its own, home none with the fix, nothing delivered; fixed, all as before`, async () => {
      const { s, a, l } = await three()
      const file = localWordPath(home)
      const body = readFileSync(file)
      if (how === '0644') chmodSync(file, 0o644)
      else if (how === 'a symlink') {
        renameSync(file, join(home, 'run', 'elsewhere.json'))
        symlinkSync(join(home, 'run', 'elsewhere.json'), file)
      } else writeFileSync(file, '{not json', { mode: 0o600 })
      const line = wordRefusal(home) as string
      expect(line).toContain(file)
      if (how === '0644')
        expect(line).toBe(
          `run/local.json is not private to you (mode 0644): bag keeps local delivery off, and a window acting as an identity sees none of the others, until it is 0600: chmod 600 ${file}, then read \`bag status --home\` (hidden and local pairs) before you rely on it`,
        )
      const ids = await call(a, 'identities')
      expect(labels(ids)).toEqual([['personal', P.alice.address]])
      for (const x of ['research', '"lab"', short(P.carol.address), short(P.jane.address)])
        expect(JSON.stringify(ids)).not.toContain(x)
      const st = await call(a, 'status')
      expect(st.home).toMatchObject({ local_delivery: 'off', local: 'off', identities: [], note: line })
      expect(st.notice).toContain(`local delivery on this machine refused: ${line}`)
      expect(JSON.stringify(st.notice)).not.toMatch(/shown research|word off/)
      expect((await call(a, 'status')).notice).toBeUndefined()
      // Nothing goes locally, to the hidden one or between the two that were allowed; nothing reaches a relay.
      for (const to of [P.carol.address, P.jane.address])
        expect(await call(a, 'send', chat([to]))).toMatchObject({ error: 'to-own-identity' })
      expect(onRelay()).toEqual([])
      // An unbound window is unchanged: every identity, short.
      expect(labels(await call(await connected(s, 'loose'), 'identities'))).toEqual([
        ['personal', short(P.alice.address)],
        ['research', short(P.carol.address)],
        ['lab', short(P.jane.address)],
      ])
      // Fixed: the word reads again; research is hidden, lab is listed short and reached locally.
      if (how === 'a symlink') rmSync(file)
      writeFileSync(file, body, { mode: 0o600 })
      chmodSync(file, 0o600)
      expect(wordRefusal(home)).toBeNull()
      expect(labels(await call(a, 'identities'))).toEqual([
        ['personal', P.alice.address],
        ['lab', short(P.jane.address)],
      ])
      expect(((await call(a, 'status')).home as Json).identities).toMatchObject([{ label: 'lab' }])
      expect(await call(a, 'send', chat([P.jane.address]))).toMatchObject({ delivery: 'local' })
      expect(await call(l, 'inbox')).toBeDefined()
      expect(log.lines.filter((x) => x.event === 'local-word')).toHaveLength(1)
    })

  it('every writer refuses while it is refused, before any question: the bytes and the mode unchanged', async () => {
    word(true)
    hide('research')
    const s = await start()
    const a = await window(s, 'personal')
    const r = await window(s, 'research')
    const file = localWordPath(home)
    chmodSync(file, 0o644)
    const bytes = readFileSync(file)
    const line = wordRefusal(home) as string
    const calls: [Line, string, Json][] = [
      [a, 'pair_invite', { for: P.alice.address }], // the hide dialog
      [r, 'pair_invite', { for: P.carol.address }], // the show dialog
      ...(['on', 'off'] as const).map((w): [Line, string, Json] => [a, 'local_delivery', { word: w }]),
      [a, 'local_delivery', { word: 'hide', name: 'personal' }],
      [a, 'local_delivery', { word: 'show', name: 'research' }],
    ]
    for (const [w, tool, args] of calls) {
      const v = await call(w, tool, args)
      expect([tool, args, v.error, v.detail]).toEqual([
        tool,
        args,
        'unsafe-path',
        `${line}; nothing was changed`,
      ])
      expect(readFileSync(file).equals(bytes)).toBe(true)
      expect(statSync(file).mode & 0o777).toBe(0o644)
    }
    expect([a.dialogs, r.dialogs]).toEqual([[], []])
    expect(() => s.local.setHidden('personal', true)).toThrow(`unsafe-path: ${line}; nothing was changed`)
    expect(readFileSync(file).equals(bytes)).toBe(true)
  })

  it('a missing file is not refused: the default holds, nothing hidden', async () => {
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    expect(wordRefusal(home)).toBeNull()
    expect(labels(await call(a, 'identities'))).toEqual([
      ['personal', P.alice.address],
      ['research', short(P.carol.address)],
      ['lab', short(P.jane.address)],
    ])
    expect((await call(a, 'status')).home).toMatchObject({ local_delivery: 'on (default)', note: HOME_NOTE })
  })
})

describe('hidden: an identity kept apart (spec/SPEC.md 9.2 item 1)', () => {
  it('identities: a window bound to another identity is never shown a hidden one, by the typed word or the dialog', async () => {
    word(true)
    hide('personal')
    const s = await start()
    const short = (a: string): string => `${a.slice(0, 16)}\u2026${a.slice(-4)}`
    const typed = await window(s, 'research')
    // A window bound by the dialog's Yes: the use tool's dialog answered in the window.
    const asked = await connected(s, 'research')
    const using = call(asked, 'use', { name: 'research' })
    const req = await asked.next((m) => m.method === 'elicitation/create')
    // The binding table reads the real clock (performance.now): the person answers at a person's pace.
    await new Promise((r) => setTimeout(r, FAST_ANSWER_MS + 50))
    const handle = ((req.params as Json)._meta as Json)[DIALOG_META]
    const content = { bind: true }
    asked.send({
      jsonrpc: '2.0',
      id: req.id,
      result: { action: 'accept', content, _meta: { [DIALOG_META]: handle } },
    })
    expect(await using).toMatchObject({ bound: true, as: 'research', granted: 'dialog' })
    for (const w of [typed, asked]) {
      const r = await call(w, 'identities')
      expect(r).toEqual({
        identities: [{ label: 'research', address: P.carol.address }],
        full: false,
        note: OTHERS_NOTE,
        as: 'research',
      })
      for (const x of ['personal', P.alice.address, short(P.alice.address)])
        expect(JSON.stringify(r)).not.toContain(x)
    }
    // The hidden identity's own window sees itself in full and none of the others.
    const own = await window(s, 'personal')
    expect(await call(own, 'identities')).toEqual({
      identities: [{ label: 'personal', address: P.alice.address }],
      full: false,
      note: OTHERS_NOTE,
      as: 'personal',
    })
    // A window bound to no identity is as before: both, short.
    const loose = await connected(s, 'loose')
    expect(await call(loose, 'identities')).toEqual({
      identities: [
        { label: 'personal', address: short(P.alice.address) },
        { label: 'research', address: short(P.carol.address) },
      ],
      full: false,
      note: SHORT_NOTE,
      as: null,
    })
  })

  it('service/sees answers what the identities tool lists to the window: a hidden one is as a label no identity has', async () => {
    word(true)
    hide('personal')
    const s = await start()
    const sees = async (l: Line, label: string) => (await l.request('service/sees', { label })).result
    const other = await window(s, 'research')
    for (const label of ['personal', 'nosuch']) expect(await sees(other, label)).toEqual({ sees: false })
    expect(await sees(other, 'research')).toEqual({ sees: true })
    // The hidden identity's own window sees itself alone; a window bound to none sees both, as identities lists them.
    const own = await window(s, 'personal')
    expect([await sees(own, 'personal'), await sees(own, 'research')]).toEqual([
      { sees: true },
      { sees: false },
    ])
    const loose = await connected(s, 'loose')
    expect([await sees(loose, 'personal'), await sees(loose, 'research')]).toEqual([
      { sees: true },
      { sees: true },
    ])
    // Read-only: nothing bound, nothing asked; a bad ask is usage.
    expect(own.dialogs).toEqual([])
    expect((await loose.request('service/sees', {})).error).toMatchObject({ data: { code: 'usage' } })
    expect((await call(loose, 'identities')).as).toBeNull()
  })

  it("hides by its window's dialog, then refuses both ways and lists it to none; shows by a Yes", async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const a = await window(s, 'personal')
    const b = await window(s, 'research')
    await allow(a, b)
    const hid = await call(a, 'pair_invite', { for: P.alice.address })
    expect(hid).toMatchObject({ local: true, hidden: true, as: 'personal' })
    expect(a.dialogs.at(-1)).toBe(HIDE_WORDS('personal'))
    expect(HIDE_WORDS('personal')).toBe('Keep personal apart from your other identities on this machine?')
    expect(JSON.parse(readFileSync(localWordPath(home), 'utf8'))).toMatchObject({ hidden: ['personal'] })
    for (const [l, to] of [
      [a, P.carol.address],
      [b, P.alice.address],
    ] as const) {
      const r = await call(l, 'send', chat([to]))
      expect(r).toMatchObject({ error: 'to-own-identity' })
      expect(String(r.detail)).toMatch(/^hidden: personal is kept apart/)
    }
    expect((await call(b, 'status')).home).toMatchObject({ identities: [] })
    expect((await call(a, 'status')).home).toMatchObject({ local: 'off', identities: [] })
    expect(onRelay()).toEqual([])
    const shown = await call(a, 'pair_invite', { for: P.alice.address })
    expect(shown).toMatchObject({ hidden: false })
    expect(a.dialogs.at(-1)).toBe('Let personal reach your other identities on this machine?')
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ delivery: 'local' })
    // The direction is the state's, never the model's: visible now, so the same call offers hide again.
    await call(a, 'pair_invite', { for: P.alice.address })
    expect(a.dialogs.at(-1)).toBe(HIDE_WORDS('personal'))
    // A second show dialog within 10 minutes is refused busy, with no dialog; after them it asks.
    const asked = a.dialogs.length
    const again = await call(a, 'pair_invite', { for: P.alice.address })
    expect([again.error, a.dialogs.length]).toEqual(['busy', asked])
    clock.t += SHOW_EVERY_S
    expect(await call(a, 'pair_invite', { for: P.alice.address })).toMatchObject({ hidden: false })
  })

  it('hide and show answered at once (a decline or a cancel faster than a person) are no-elicitation, never declined (q2, 0.4.4)', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const fileWord = () => JSON.parse(readFileSync(localWordPath(home), 'utf8')) as Json
    for (const answer of ['decline', null] as const) {
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.alice.address })
      expect(r.error).toBe('no-elicitation')
      expect(fileWord()).toEqual({ version: 1, local_delivery: 'on' })
    }
    // A hide closed by the person after they saw it: cancelled, the word unchanged.
    const hideLate = await window(s, 'personal', 'cancel-late')
    const h = await call(hideLate, 'pair_invite', { for: P.alice.address })
    expect([h.error, h.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
    expect(fileWord()).toEqual({ version: 1, local_delivery: 'on' })
    // Hidden by a Yes; then a show with no answer is cancelled too, and personal stays hidden.
    expect(await call(await window(s, 'personal'), 'pair_invite', { for: P.alice.address })).toMatchObject({
      hidden: true,
    })
    for (const answer of ['decline', null] as const) {
      clock.t += SHOW_EVERY_S
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.alice.address })
      expect(r.error).toBe('no-elicitation')
      expect(fileWord()).toMatchObject({ hidden: ['personal'] })
    }
    // A show closed by the person after they saw it: cancelled, personal stays hidden.
    clock.t += SHOW_EVERY_S
    const showLate = await window(s, 'personal', 'cancel-late')
    const v = await call(showLate, 'pair_invite', { for: P.alice.address })
    expect([v.error, v.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
    expect(fileWord()).toMatchObject({ hidden: ['personal'] })
  })

  it('a No changes nothing', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal', 'decline-late')
    expect(await call(a, 'pair_invite', { for: P.alice.address })).toMatchObject({ error: 'declined' })
    expect(JSON.parse(readFileSync(localWordPath(home), 'utf8'))).toEqual({
      version: 1,
      local_delivery: 'on',
    })
  })
})

describe("each window sees only its own identity's notices and pairs (item h)", () => {
  /** personal and lab allowed by lab's Yes: the change "lab allowed personal; 1 messages delivered" is personal's. */
  async function three() {
    word(true)
    const s = await start({}, {}, [], [], [['lab', P.jane]])
    const pa = await window(s, 'personal')
    const lab = await window(s, 'lab')
    expect(await call(pa, 'send', chat([P.jane.address]))).toMatchObject({ pairing: 'requested' })
    await call(lab, 'status')
    expect(lab.dialogs).toHaveLength(1)
    return { s, pa, lab }
  }
  const PERSONAL = 'lab allowed personal; 1 messages delivered'

  it("research's window sending to personal sees none of personal's notices; personal's does", async () => {
    const { s, pa } = await three()
    const rw = await window(s, 'research')
    const out = await call(rw, 'send', chat([P.alice.address]))
    expect(out).toMatchObject({ pairing: 'requested', as: 'research' })
    expect(out.notice).toBeUndefined()
    expect((await call(rw, 'status')).notice).toBeUndefined()
    // Not consumed by research's window: personal's speaking window still sees its own, once.
    expect((await call(pa, 'status')).notice).toEqual([PERSONAL])
    expect((await call(pa, 'status')).notice).toBeUndefined()
  })

  it('two windows of different identities see only their own pairs and notices, on status and a send', async () => {
    const { s, pa } = await three()
    const rw = await window(s, 'research')
    const pairsOf = (st: Json) =>
      Object.fromEntries(((st.home as Json).identities as Json[]).map((i) => [i.label, i.pair]))
    const rs = await call(rw, 'status')
    expect([pairsOf(rs), rs.notice]).toEqual([{ personal: 'none', lab: 'none' }, undefined])
    const ps = await call(pa, 'status')
    expect([pairsOf(ps), ps.notice]).toEqual([{ research: 'none', lab: 'allowed' }, [PERSONAL]])
    // On a send result: personal's local send to lab carries no notice now (shown once), research's none of personal's.
    expect(await call(pa, 'send', chat([P.jane.address]))).toMatchObject({ delivery: 'local' })
    const sent = await call(rw, 'send', chat([P.alice.address]))
    expect(sent.notice).toBeUndefined()
    // personal's next call asks it (its window says Yes): now allowed, in personal's view.
    expect(pairsOf(await call(pa, 'status'))).toEqual({ research: 'allowed', lab: 'allowed' })
    expect(pa.dialogs).toHaveLength(1)
  })
})

describe('local mail (M2, M3, M4)', () => {
  async function paired(more: Partial<ServiceDeps> = {}, entry: Json = {}) {
    word(true)
    const s = await start(more, entry)
    const a = await window(s, 'personal')
    const b = await window(s, 'research')
    await allow(a, b)
    return { s, a, b }
  }

  it("a read receipt between own identities goes back locally, by the reader's setting only (item 8)", async () => {
    const base = seededRng('receipts')
    const rng = { bytes: (n: number) => (n === 4 ? new Uint8Array(4) : base.bytes(n)) }
    // research answers personal's receipt requests (receipts_to); personal answers none.
    const { s, a, b } = await paired({ rng }, { receipts_to: [P.alice.address] })
    const sent = await call(a, 'send', { ...chat([P.carol.address]), body: { text: 'r?' }, receipt: true })
    expect(sent).toMatchObject({ delivery: 'local' })
    expect(((await call(b, 'wait', { timeout_s: 1 })).message as Json).body).toMatchObject({
      'ac.receipt': true,
    })
    await until(() => (s.unit('personal')?.opened?.edge.receipts(String(sent.id)).length ?? 0) === 1)
    expect(await call(a, 'receipts', { id: sent.id })).toMatchObject({
      receipts: [{ reader: P.carol.address }],
    })
    // The other way, personal's setting names no one: research gets none.
    const back = await call(b, 'send', { ...chat([P.alice.address]), body: { text: 'r?' }, receipt: true })
    await call(a, 'wait', { timeout_s: 1 })
    await new Promise((r) => setTimeout(r, 50))
    expect(await call(b, 'receipts', { id: back.id })).toMatchObject({ receipts: [] })
    expect(onRelay()).toEqual([])
  })

  it('a wait cancelled in the same write as its call takes nothing: the message stays unread, and the next wait returns it', async () => {
    const { a, b } = await paired()
    const sent = await call(a, 'send', chat([P.carol.address], 'kept'))
    b.sendAll([
      {
        jsonrpc: '2.0',
        id: 9201,
        method: 'tools/call',
        params: { name: 'wait', arguments: { timeout_s: 1 } },
      },
      { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 9201, reason: 'at once' } },
    ])
    // timeout_s 0 answers at once: the message, or null when the cancelled wait took it.
    expect(((await call(b, 'wait', { timeout_s: 0 })).message as Json | null)?.id).toBe(sent.id)
    expect(b.count((m) => m.id === 9201)).toBe(0)
  })

  it('never refuses a local send for rate: 210 sends from one identity inside one minute are all delivered', async () => {
    // The injected clock stands still, so every send falls inside one minute and one day: past the old 20 a minute
    // and 200 a day (removed 2026-11-23), none is refused and no rate-limit line is audited.
    const clock = new FakeClock()
    const { a } = await paired({ clock })
    const start = clock.now()
    const sent: Json[] = []
    for (let i = 0; i < 210; i++) sent.push(await call(a, 'send', chat([P.carol.address])))
    expect(clock.now() - start).toBeLessThan(60)
    expect(sent.filter((r) => r.delivery !== 'local' || r.error !== undefined)).toEqual([])
    expect(new Set(sent.map((r) => r.id)).size).toBe(210)
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
    expect(audit.filter((l) => l.includes('rate-limit'))).toEqual([])
    expect(audit.filter((l) => l.includes('delivered-local'))).toHaveLength(210)
    expect(onRelay()).toEqual([])
  }, 60_000)

  it('goes both ways through the recipient receive path, via local, with no relay request for any envelope id', async () => {
    const arrived: string[] = []
    const { s, a, b } = await paired({ mail: { arrived: (label) => void arrived.push(label) } })
    arrived.splice(0) // the request's ring
    const sent = await call(a, 'send', chat([P.carol.address], 'one'))
    expect(sent).toMatchObject({ delivery: 'local', spooled: false, as: 'personal' })
    expect(sent.targets).toBeUndefined()
    const got = (await call(b, 'wait', { timeout_s: 1 })).message as Json
    expect(got).toMatchObject({
      id: sent.id,
      from: P.alice.address,
      via: 'local',
      relay: 'local:',
      as: 'research',
      // Labelled as from an own identity (tools.ts from_own_note).
      from_own: 'personal',
      from_own_note: 'from your own identity personal on this machine',
    })
    expect(got.trust).toMatchObject({ root: P.alice.address, verified: true })
    expect(arrived).toEqual(['research'])
    // The reply, by the message's reply field, goes local too and reaches personal.
    const reply = got.reply as { to: string[]; thread: Json }
    const back = await call(b, 'send', { to: reply.to, type: 'chat.v1', body: 'two', thread: reply.thread })
    expect(back).toMatchObject({ delivery: 'local' })
    expect(((await call(a, 'wait', { timeout_s: 1 })).message as Json).id).toBe(back.id)
    // ask waits on its thread for the answer the other side sends locally.
    const asking = call(a, 'ask', { to: P.carol.address, body: 'q?', timeout_s: 2 })
    const q = (await call(b, 'wait', { timeout_s: 2 })).message as Json
    const qr = q.reply as { to: string[]; thread: Json }
    await call(b, 'send', { to: qr.to, type: 'answer.v1', body: 'a!', thread: qr.thread })
    const answered = await asking
    expect(answered).toMatchObject({
      answer: { body: 'a!', via: 'local', from_own: 'research' },
      question: { delivery: 'local' },
    })
    expect(((await call(a, 'inbox')).messages as Json[]).map((m) => m.from_own)).toContain('research')
    // handoff goes local, as a local message.
    const h = await call(a, 'handoff', { to: P.carol.address, threads: [(got.thread as Json).id as string] })
    expect(h).toMatchObject({ delivery: 'local', handed_off: [(got.thread as Json).id] })
    for (const id of [sent.id, back.id, h.id]) expect(onRelay()).not.toContain(id)
    // status with the id: delivered locally, as the send said; an id it never sent is unknown.
    expect(await call(a, 'status', { id: sent.id })).toMatchObject({
      id: sent.id,
      delivery: 'local',
      status: 'delivered locally',
      spooled: false,
      as: 'personal',
    })
    expect(await call(b, 'status', { id: back.id })).toMatchObject({
      delivery: 'local',
      status: 'delivered locally',
    })
    expect(await call(a, 'status', { id: 'f'.repeat(64) })).toMatchObject({
      delivery: 'relay',
      status: 'unknown',
      targets: [],
    })
    expect(onRelay()).toEqual([])
    // One unseal per delivered message on the recipient side.
    const audit = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8')
    expect(
      audit.split('\n').filter((l) => l.includes('"unseal"') && l.includes(String(sent.id))),
    ).toHaveLength(1)
    const senderAudit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(senderAudit).toContain('delivered-local')
    void s
  })

  it('refuses a mixed local and wire send to-own-identity, and delegate to an own identity (M3, M4)', async () => {
    const { a } = await paired({}, { allow_delegate: true })
    expect(await call(a, 'send', chat([P.carol.address, P.bob.address]))).toMatchObject({
      error: 'to-own-identity',
    })
    expect(
      await call(a, 'delegate', { to: P.carol.address, caveats: ['type=chat.*'], exp: '+60' }),
    ).toMatchObject({ error: 'to-own-identity' })
    expect(await call(a, 'lookup', { address: P.carol.address })).toMatchObject({ error: 'to-own-identity' })
    expect(onRelay()).toEqual([])
  })

  it('an envelope from personal arriving over a relay is judged by the wire roots alone: untrusted-root (M2)', async () => {
    const { s } = await paired()
    const alice = s.unit('personal')?.opened?.edge
    const research = s.unit('research')?.opened?.edge
    if (alice === undefined || research === undefined) throw new Error('not open')
    const { bytes } = alice.seal({ type: 'chat.v1', body: 'over the wire' }, [
      { address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey },
    ])
    const row = await research.receive(RELAY, 77, bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
  })

  it('after the pair is dropped (unpair, identity remove), the next send asks again and nothing is left', async () => {
    const { a } = await paired()
    // The table as bag unpair or identity remove leaves it (packages/cli/src/commands/local.ts dropLocalPairs).
    expect(dropLocalPair(home, P.alice.address, P.carol.address)).toBe(true)
    expect(JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs).toEqual([])
    // The next touch asks again (spec/SPEC.md 9.2 item 5): held, nothing delivered.
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ pairing: 'requested' })
  })
})

describe('the spool (M6)', () => {
  it('a send to a Keychain identity not open raises no open and no dialog; its first bind delivers it and empties the spool', async () => {
    word(true)
    allowedRow()
    const reads: string[] = []
    const byName = new Map<string, EdgeKeys>([
      ['alice', P.alice.keys],
      ['carol', P.carol.keys],
    ])
    const s = await start(
      {
        openKeys: async (_h, name) => {
          reads.push(name)
          const keys = byName.get(name) as EdgeKeys
          return { custody: 'keychain', address: keys.signing.address, keys }
        },
      },
      {},
      [P.carol],
    )
    const a = await window(s, 'personal')
    expect(s.unit('research')?.opened).toBeNull()
    const sent = await call(a, 'send', chat([P.carol.address], 'while closed'))
    expect(sent).toMatchObject({ delivery: 'local', spooled: true })
    expect(reads).not.toContain('carol')
    expect(a.dialogs).toHaveLength(0) // the pair was allowed before; none at the send
    expect(s.unit('research')?.opened).toBeNull()
    const files = readdirSync(spoolDir(home, 'carol'))
    expect(files).toEqual([`${sent.id}.env`])
    expect(statSync(join(spoolDir(home, 'carol'), files[0] as string)).mode & 0o777).toBe(0o600)
    expect(parseEnvelope(readFileSync(join(spoolDir(home, 'carol'), files[0] as string))).id).toBe(sent.id)
    // The person binds research: one read, then the spool is delivered once.
    const b = await window(s, 'research')
    await until(() => s.unit('research')?.opened !== null)
    expect(reads.filter((n) => n === 'carol')).toEqual(['carol'])
    expect(((await call(b, 'wait', { timeout_s: 1 })).message as Json).id).toBe(sent.id)
    await until(() => readdirSync(spoolDir(home, 'carol')).length === 0)
    expect(onRelay()).toEqual([])
  })

  it('a spooled envelope the policy refuses at the open (the pair dropped since) is logged with its code and deleted', async () => {
    word(true)
    allowedRow()
    const keys = (name: string): EdgeKeys => (name === 'alice' ? P.alice.keys : P.carol.keys)
    const s = await start(
      {
        openKeys: async (_h, name) => ({
          custody: 'keychain',
          address: keys(name).signing.address,
          keys: keys(name),
        }),
      },
      {},
      [P.carol],
    )
    const a = await window(s, 'personal')
    const sent = await call(a, 'send', chat([P.carol.address], 'then unpaired'))
    expect(sent).toMatchObject({ delivery: 'local', spooled: true })
    // The pair dropped before research opens; its spool kept (unpair drops the pair only).
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [] }))
    await window(s, 'research')
    await until(() => readdirSync(spoolDir(home, 'carol')).length === 0)
    expect(
      log.lines.some(
        (x) =>
          x.event === 'local-spool' && x.fields.label === 'research' && x.fields.code === 'untrusted-root',
      ),
    ).toBe(true)
    // C3: the sender is told, in its audit, and status(id) says so.
    expect(await call(a, 'status', { id: sent.id })).toMatchObject({
      delivery: 'local',
      status: 'not delivered locally: research could not open it (untrusted-root)',
      reason: 'untrusted-root',
    })
  })

  for (const end of ['Yes', 'No', 'expiry'] as const)
    it(`a forged row's held ids touch no file outside held/, nor another pair's mail, at its ${end} (r1)`, async () => {
      word(true)
      const clock = new FakeClock()
      const s = await start({ clock }, {}, [], [], [['lab', P.jane]])
      const a = await window(s, 'personal')
      // A real held message of another pair, personal to lab, in lab's spool.
      const real = await call(a, 'send', chat([P.jane.address], 'real'))
      const realFile = join(spoolDir(home, 'jane'), 'held', `${real.id}.env`)
      const realBytes = readFileSync(realFile)
      // Outside every spool: a file and a directory the traversal ids point at.
      writeFileSync(join(home, 'victim.env'), 'keep me')
      mkdirSync(join(home, 'dirvictim.env'))
      const forged = {
        a: 'personal',
        b: 'research',
        a_addr: P.alice.address,
        b_addr: P.carol.address,
        added_at: 1,
        state: 'requested',
        at: clock.now(),
        held: ['../../../../victim', '../../../../dirvictim', real.id],
      }
      const table = JSON.parse(readFileSync(localPeersPath(home), 'utf8')) as { pairs: Json[] }
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [...table.pairs, forged] }), {
        mode: 0o600,
      })
      const before = readdirSync(home).sort()
      if (end === 'expiry') {
        clock.t += LOCAL_ASK_DAYS * 86_400
        expect(await call(a, 'status')).not.toHaveProperty('error')
      } else {
        const b = await window(s, 'research', end === 'Yes')
        expect(await call(b, 'status')).not.toHaveProperty('error')
      }
      const research = (JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]).find(
        (r) => r.b === 'research',
      )
      if (end !== 'expiry') expect(research?.held ?? []).toEqual([])
      expect(readFileSync(join(home, 'victim.env'), 'utf8')).toBe('keep me')
      expect(statSync(join(home, 'dirvictim.env')).isDirectory()).toBe(true)
      expect(readdirSync(home).sort()).toEqual(before)
      if (end !== 'expiry') {
        // The other pair's held message is intact, and its own Yes still delivers it.
        expect(readFileSync(realFile).equals(realBytes)).toBe(true)
        const l = await window(s, 'lab')
        await call(l, 'status')
        expect(((await call(l, 'wait', { timeout_s: 1 })).message as Json).id).toBe(real.id)
      }
    })

  it("a table refused before start: each identity's log gets the refusal line as it opens (r2)", async () => {
    word(true)
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [] }), { mode: 0o644 })
    chmodSync(localPeersPath(home), 0o644)
    await start()
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(audit.split('\n').filter((l) => l.includes('local pairs refused'))).toHaveLength(1)
    }
  })

  /** An envelope from personal (alice) to research (carol), as a held first touch is. */
  const fromPersonal = (text: string) => {
    const rng = seededRng(`held-${text}`)
    return buildEnvelope({
      from: P.alice.keys.signing,
      to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
  }

  it('an expiry first seen at start drops the held mail, fails it to the sender, audited at each open (s1)', async () => {
    word(true)
    const envs = [fromPersonal('one'), fromPersonal('two')]
    const heldDir = join(spoolDir(home, 'carol'), 'held')
    mkdirSync(heldDir, { recursive: true, mode: 0o700 })
    for (const e of envs) writeFileSync(join(heldDir, `${e.envelope.id}.env`), e.bytes, { mode: 0o600 })
    // A request asked 8 days before this start, never answered (the service was stopped meanwhile).
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: T0 - 8 * 86_400,
      state: 'requested',
      at: T0 - 8 * 86_400,
      held: envs.map((e) => e.envelope.id),
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
    await start()
    expect(readdirSync(heldDir)).toEqual([])
    expect(JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs).toEqual([])
    const audit = (name: string) => readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8').split('\n')
    for (const e of envs) {
      const lines = audit('alice').filter((l) => l.includes('failed-local') && l.includes(e.envelope.id))
      expect(lines).toHaveLength(1)
      expect(lines[0]).toContain('no answer')
    }
    for (const name of ['alice', 'carol'])
      expect(audit(name).filter((l) => l.includes('local pairs read: 0'))).toHaveLength(1)
  })

  it("a held id that is not an envelope id in the start table is audited in each identity's log as it opens (s1)", async () => {
    word(true)
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: T0,
      state: 'requested',
      at: T0,
      held: ['../../../../x'],
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
    await start()
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(
        audit.split('\n').filter((l) => l.includes('held mail that is not an envelope id')),
      ).toHaveLength(1)
    }
  })

  it("a row naming an outside address under a real label is reset, and a Yes trusts only the identity's own (s2)", async () => {
    word(true)
    // At start, so the baseline itself carries it: personal's label with an outside address, already allowed. The
    // outside party is jane, whom no identity trusts on the wire (bob is every identity's trust root in start()).
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.jane.address,
      b_addr: P.carol.address,
      added_at: 1,
      state: 'allowed',
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
    const s = await start()
    const table = () => JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]
    expect(table()).toMatchObject([
      { a_addr: P.alice.address, b_addr: P.carol.address, state: 'requested', held: [] },
    ])
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(audit).toContain("a local pair named an address that is not its identity's")
    }
    // research's person says Yes to "personal": the pair is allowed with personal's own address only.
    const b = await window(s, 'research')
    await call(b, 'status')
    expect(b.dialogs).toHaveLength(1)
    expect(table()).toMatchObject([{ a_addr: P.alice.address, state: 'allowed' }])
    const sign = (from: Party, text: string) => {
      const rng = seededRng(`s2-${text}`)
      return buildEnvelope({
        from: from.keys.signing,
        to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
        auth: [],
        type: 'chat.v1',
        thread: newThread((n) => rng.bytes(n)),
        body: { text },
        ts: T0,
        rng: (n) => rng.bytes(n),
      }).bytes
    }
    const edge = s.unit('research')?.opened?.edge
    if (edge === undefined) throw new Error('research is not open')
    const outside = await edge.receive(LOCAL_RELAY, 1000, sign(P.jane, 'outside'))
    expect([outside.state, outside.reason]).toEqual(['rejected', 'untrusted-root'])
    const own = await edge.receive(LOCAL_RELAY, 1001, sign(P.alice, 'own'))
    expect(own.state).not.toBe('rejected')
  })

  for (const how of [
    'a custody move stopped partway (EEXIST)',
    'a Keychain pointer that does not read',
  ] as const)
    it(`a configured identity whose address cannot be read keeps its row, unasked and untrusted: ${how} (t2)`, async () => {
      word(true)
      const row = {
        a: 'personal',
        b: 'research',
        a_addr: P.alice.address,
        b_addr: P.carol.address,
        added_at: 1,
        state: 'allowed',
      }
      mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
      const before = readFileSync(localPeersPath(home))
      const keychain = how.startsWith('a Keychain') ? [P.carol] : []
      const prep = (): void => {
        mkdirSync(join(home, 'keychain'), { recursive: true, mode: 0o700 })
        const pointer = join(home, 'keychain', `${P.carol.name}.json`)
        // EEXIST: a pointer beside carol's key file; else carol's own pointer made unreadable.
        if (keychain.length === 0)
          writeFileSync(
            pointer,
            JSON.stringify({ suite: SUITE, custody: 'keychain', address: P.carol.address }),
            {
              mode: 0o600,
            },
          )
        else writeFileSync(pointer, 'not a pointer', { mode: 0o600 })
      }
      const s = await start({}, {}, keychain, [], [], prep)
      const a = await window(s, 'personal')
      const st = await call(a, 'status')
      expect(st).not.toHaveProperty('error')
      // Not dropped, not rewritten: the table's bytes as they were.
      expect(readFileSync(localPeersPath(home)).equals(before)).toBe(true)
      expect(((st.home as Json).identities as Json[]).map((i) => i.label)).not.toContain('research')
      expect(a.dialogs).toEqual([])
      const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
      expect(
        audit.filter((l) => l.includes('local pairs of research: its address cannot be read now')),
      ).toHaveLength(1)
      expect(audit.filter((l) => l.includes('dropped'))).toEqual([])
      // Untrusted meanwhile: an envelope signed by carol at personal's LOCAL_RELAY is refused.
      const rng = seededRng('t2')
      const env = buildEnvelope({
        from: P.carol.keys.signing,
        to: [{ address: P.alice.address, sealingKey: P.alice.keys.sealing.publicKey }],
        auth: [],
        type: 'chat.v1',
        thread: newThread((n) => rng.bytes(n)),
        body: { text: 'unread' },
        ts: T0,
        rng: (n) => rng.bytes(n),
      })
      const edge = s.unit('personal')?.opened?.edge
      if (edge === undefined) throw new Error('personal is not open')
      const got = await edge.receive(LOCAL_RELAY, 1000, env.bytes)
      expect([got.state, got.reason]).toEqual(['rejected', 'untrusted-root'])
    })

  it("the start's audit lines reach an identity's log once a run: a lend and a return repeat none of them (t3)", async () => {
    word(true)
    allowedRow()
    const s = await start()
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((r) => socket.once('connect', () => r()))
    const seen: Json[] = []
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        seen.push(JSON.parse(buf.slice(0, i)) as Json)
        buf = buf.slice(i + 1)
      }
    })
    let n = 0
    const request = async (method: string, params: Json): Promise<Json> => {
      const id = ++n
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
      await until(() => seen.some((m) => m.id === id))
      return seen.find((m) => m.id === id) as Json
    }
    await request('service/hello', { contract: 1, token: s.token.toString('hex'), host: 'cli', cwd: '/w' })
    expect((await request('service/lend', { label: 'personal', verb: 'pair' })).result).toMatchObject({
      lent: true,
    })
    expect((await request('service/return', { label: 'personal' })).result).toMatchObject({ returned: true })
    await until(() => s.unit('personal')?.opened != null)
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
    expect(audit.filter((l) => l.includes('local pairs read: 1'))).toHaveLength(1)
  })

  it('an identity added at runtime (the identities reread) keeps its pairs: no drop (t2)', async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const s = await start({ reread })
    // lab joins the home while the service runs: its key, its address copy, its entry in identities.json.
    saveKeys(home, P.jane)
    keepAddressCopy(home, P.jane.name, addressRecord(P.jane))
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
    const lab = { ...(doc.identities[0] as Json), label: 'lab', key: P.jane.name }
    writeFileSync(file, JSON.stringify({ version: 1, identities: [...doc.identities, lab] }), { mode: 0o600 })
    const a = await window(s, 'personal')
    const l = await window(s, 'lab')
    expect(await call(a, 'send', chat([P.jane.address]))).toMatchObject({ pairing: 'requested' })
    await call(l, 'status')
    expect(l.dialogs).toHaveLength(1)
    // A later read keeps the pair: allowed, and no drop line in any log.
    expect(((await call(a, 'status')).home as Json).identities).toEqual(
      expect.arrayContaining([expect.objectContaining({ label: 'lab', pair: 'allowed' })]),
    )
    expect(JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs).toMatchObject([
      { a: 'personal', b: 'lab', state: 'allowed' },
    ])
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(audit).not.toContain('no identity of this home')
  })

  it('bag identity remove beside the service: the return of the lent identity fails its held mail to the senders (C2)', async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const s = await start({ reread }, {}, [], [], [['lab', P.jane]])
    const r = await window(s, 'research', null)
    const waiting = await call(r, 'send', chat([P.jane.address], 'held for lab'))
    expect(waiting).toMatchObject({ pairing: 'requested' })
    const labHeld = join(spoolDir(home, 'jane'), 'held')
    expect(readdirSync(labHeld)).toEqual([`${waiting.id}.env`])
    // And lab's own first touch of personal, held in personal's spool (the other side's): its sender is the one removed.
    // No personal window yet, and no answer from lab's: both requests stay held, unasked.
    const l = await window(s, 'lab', null)
    const fromLab = await call(l, 'send', chat([P.alice.address], 'held for personal'))
    expect(fromLab).toMatchObject({ pairing: 'requested' })
    const aliceHeld = join(spoolDir(home, 'alice'), 'held')
    expect(readdirSync(aliceHeld)).toEqual([`${fromLab.id}.env`])
    expect((await l.request('service/unbind', {})).result).toBeDefined()
    // The CLI's connection, as bag identity remove makes it (packages/cli/src/service.ts leaseFor).
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((done) => socket.once('connect', () => done()))
    const seen: Json[] = []
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        seen.push(JSON.parse(buf.slice(0, i)) as Json)
        buf = buf.slice(i + 1)
      }
    })
    let n = 0
    const request = async (method: string, params: Json): Promise<Json> => {
      const id = ++n
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
      await until(() => seen.some((m) => m.id === id))
      return seen.find((m) => m.id === id) as Json
    }
    await request('service/hello', { contract: 1, token: s.token.toString('hex'), host: 'cli', cwd: '/w' })
    expect((await request('service/lend', { label: 'lab', verb: 'identity-remove' })).result).toMatchObject({
      lent: true,
    })
    // N1: while lab is lent for its remove, a personal window that would say Yes is not asked about lab's request, so
    // no Yes delivers the held mail of the identity being removed.
    const p = await window(s, 'personal')
    await call(p, 'status')
    expect(p.dialogs).toEqual([])
    expect(readdirSync(aliceHeld)).toEqual([`${fromLab.id}.env`])
    // What bag identity remove does to the home while lab is lent (packages/cli/src/commands/identity.ts): lab leaves
    // identities.json, its held mail moves to the sender's held/ (state/jane leaves the home), the rows are left for
    // the service, and its key and state move out.
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
    writeFileSync(
      file,
      JSON.stringify({ version: 1, identities: doc.identities.filter((x) => x.label !== 'lab') }),
      {
        mode: 0o600,
      },
    )
    const carolHeld = join(spoolDir(home, 'carol'), 'held')
    mkdirSync(carolHeld, { recursive: true, mode: 0o700 })
    renameSync(join(labHeld, `${waiting.id}.env`), join(carolHeld, `${waiting.id}.env`))
    const left = mkdtempSync(join(home, '..', 'bsl-left-'))
    renameSync(join(home, 'keys', 'jane.json'), join(left, 'jane.json'))
    renameSync(join(home, 'state', 'jane'), join(left, 'jane'))
    const back = await request('service/return', { label: 'lab' })
    expect(back.result).toMatchObject({ returned: true, removed: true })
    // At the return, before its answer: lab's rows leave and its held mail is failed to research, then deleted.
    expect(JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs).toEqual([])
    expect(readdirSync(carolHeld)).toEqual([])
    // lab's own held mail in personal's spool is dropped with its row; its sender is gone, so no one is told.
    expect(readdirSync(aliceHeld)).toEqual([])
    const alice = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8')
    expect(alice.split('\n').filter((x) => x.includes('failed-local'))).toEqual([])
    const carol = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8').split('\n')
    const failed = carol.filter((x) => x.includes('failed-local') && x.includes(String(waiting.id)))
    expect(failed).toHaveLength(1)
    expect(failed[0]).toContain('identity removed')
    expect(await call(r, 'status', { id: waiting.id })).toMatchObject({
      delivery: 'local',
      reason: 'identity removed',
    })
  })

  it('a return while the identities file does not read records no removal: pairs and held mail kept (F2)', async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const s = await start({ reread }, {}, [], [], [['lab', P.jane]])
    const r = await window(s, 'research', null)
    const waiting = await call(r, 'send', chat([P.jane.address], 'held for lab'))
    expect(waiting).toMatchObject({ pairing: 'requested' })
    const labHeld = join(spoolDir(home, 'jane'), 'held')
    const socket = createConnection(s.paths.sock)
    sockets.push(socket)
    await new Promise<void>((done) => socket.once('connect', () => done()))
    const seen: Json[] = []
    let buf = ''
    socket.on('data', (b: Buffer) => {
      buf += b.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        seen.push(JSON.parse(buf.slice(0, i)) as Json)
        buf = buf.slice(i + 1)
      }
    })
    let n = 0
    const request = async (method: string, params: Json): Promise<Json> => {
      const id = ++n
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
      await until(() => seen.some((m) => m.id === id))
      return seen.find((m) => m.id === id) as Json
    }
    await request('service/hello', { contract: 1, token: s.token.toString('hex'), host: 'cli', cwd: '/w' })
    expect((await request('service/lend', { label: 'lab', verb: 'keys-rotate' })).result).toMatchObject({
      lent: true,
    })
    // lab is still listed and its key is in place, but the file does not read now (group-readable): the reread throws.
    const rows = readFileSync(localPeersPath(home), 'utf8')
    chmodSync(file, 0o644)
    try {
      expect((await request('service/return', { label: 'lab' })).result).toMatchObject({ removed: true })
    } finally {
      chmodSync(file, 0o600)
    }
    // No removal recorded: the row and its held mail stay, and no sender is told.
    expect(readFileSync(localPeersPath(home), 'utf8')).toBe(rows)
    expect(readdirSync(labHeld)).toEqual([`${waiting.id}.env`])
    const carol = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8').split('\n')
    expect(carol.filter((x) => x.includes('failed-local'))).toEqual([])
  })

  it('an identity removed at runtime loses its pairs and fails its held mail; re-added, it starts with none (u1)', async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const clock = new FakeClock()
    const s = await start({ reread, clock }, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    const r = await window(s, 'research', null)
    const l = await window(s, 'lab')
    // personal and lab allowed by lab's Yes; research's first touch of lab held, unanswered.
    await call(a, 'send', chat([P.jane.address]))
    await call(l, 'status')
    // Inverse of the stale-notice filter: a window open during the change is told it, once.
    expect((await call(a, 'inbox')).notice).toContain('lab allowed personal; 1 messages delivered')
    const waiting = await call(r, 'send', chat([P.jane.address], 'held for lab'))
    expect(waiting).toMatchObject({ pairing: 'requested' })
    const labHeld = join(spoolDir(home, 'jane'), 'held')
    expect(readdirSync(labHeld)).toEqual([`${waiting.id}.env`])
    const table = () => JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]
    expect(table().map((x) => [x.a, x.b, x.state])).toEqual([
      ['personal', 'lab', 'allowed'],
      ['research', 'lab', 'requested'],
    ])
    // No window bound to lab at its remove, so #dropGone takes its unit in the same reread (v3).
    expect((await l.request('service/unbind', {})).result).toBeDefined()
    // lab leaves identities.json; the next reread (any service request) removes it.
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
    const without = doc.identities.filter((x) => x.label !== 'lab')
    writeFileSync(file, JSON.stringify({ version: 1, identities: without }), { mode: 0o600 })
    await a.request('service/identities', {})
    expect(table()).toEqual([])
    expect(readdirSync(labHeld)).toEqual([])
    const carol = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8').split('\n')
    expect(carol.filter((x) => x.includes('failed-local') && x.includes(String(waiting.id)))).toHaveLength(1)
    expect(await call(a, 'status')).toMatchObject({ local_peers: [] })
    const fresh = await window(s, 'personal')
    expect((await call(fresh, 'inbox')).notice ?? []).not.toEqual(
      expect.arrayContaining([expect.stringContaining('lab')]),
    )
    // lab's unit is gone (no window held it), so the re-add below makes a new unit (#addUnit), not the gone-unit path.
    expect(s.unit('lab')).toBeNull()
    // Inverse: lab re-added later in the run is the home's again, with no pairs; a row of it that survived on disk
    // (written back outside) is dropped as foreign; its old held mail is not delivered; a first touch asks again.
    clock.t += 1
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    await a.request('service/identities', {})
    const old = {
      a: 'personal',
      b: 'lab',
      a_addr: P.alice.address,
      b_addr: P.jane.address,
      added_at: T0,
      state: 'allowed',
    }
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [old] }), { mode: 0o600 })
    expect(await call(a, 'status')).toMatchObject({ local_peers: [] })
    expect(table()).toEqual([])
    const again = await call(a, 'send', chat([P.jane.address], 'again'))
    expect(again).toMatchObject({ delivery: 'local', pairing: 'requested' })
    expect(table()).toMatchObject([{ a: 'personal', b: 'lab', state: 'requested', held: [again.id] }])
    // C3: a window opened after the re-add is not told lab's notices from before its removal (its old pairs are gone).
    const reborn = await window(s, 'personal')
    const told = ((await call(reborn, 'inbox')).notice as string[] | undefined) ?? []
    expect(told.some((x) => x.includes('lab allowed personal'))).toBe(false)
    // Inverse: a change naming lab made after its re-add is told to a later window, once.
    hide('lab')
    const after = await window(s, 'personal')
    const now = ((await call(after, 'inbox')).notice as string[] | undefined) ?? []
    expect(now.filter((x) => x.includes('hidden lab'))).toHaveLength(1)
    expect(
      (((await call(after, 'inbox')).notice as string[] | undefined) ?? []).some((x) =>
        x.includes('hidden lab'),
      ),
    ).toBe(false)
  })

  it('a hide notice of an identity removed since is not told to a later window; a present one is, once (v1)', async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const s = await start({ reread }, {}, [], [], [['lab', P.jane]])
    const a = await window(s, 'personal')
    await call(a, 'status')
    hide('lab')
    // Inverse: lab still present, personal's open window is told the hide once.
    const told = (await call(a, 'status')).notice as string[] | undefined
    expect(told?.some((x) => x.includes('hidden lab'))).toBe(true)
    expect(
      ((await call(a, 'status')).notice as string[] | undefined)?.some((x) => x.includes('hidden lab')),
    ).not.toBe(true)
    // lab removed (no window bound to it): a window opened after is not told "hidden lab".
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
    writeFileSync(
      file,
      JSON.stringify({ version: 1, identities: doc.identities.filter((x) => x.label !== 'lab') }),
      {
        mode: 0o600,
      },
    )
    await a.request('service/identities', {})
    const later = await window(s, 'personal')
    const first = ((await call(later, 'inbox')).notice as string[] | undefined) ?? []
    expect(first.some((x) => x.includes('hidden lab'))).toBe(false)
  })

  for (const how of ['refused at the remove', 'never opened'] as const)
    it(`a removed identity's held mail is failed once the table reads, its unit gone: ${how} (v2, v3)`, async () => {
      word(true)
      const file = join(home, 'identities.json')
      const reread = () =>
        (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
      // never opened: lab a Keychain identity no window ever binds, so it is never opened.
      const keychain = how === 'never opened' ? [P.jane] : []
      const s = await start({ reread }, {}, keychain, [], [['lab', P.jane]])
      if (how === 'never opened') expect(s.unit('lab')?.opened).toBeNull()
      const r = await window(s, 'research', null)
      const waiting = await call(r, 'send', chat([P.jane.address], 'held for lab'))
      expect(waiting).toMatchObject({ pairing: 'requested' })
      const labHeld = join(spoolDir(home, 'jane'), 'held')
      expect(readdirSync(labHeld)).toEqual([`${waiting.id}.env`])
      const peers = localPeersPath(home)
      if (how === 'refused at the remove') chmodSync(peers, 0o644)
      const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
      writeFileSync(
        file,
        JSON.stringify({ version: 1, identities: doc.identities.filter((x) => x.label !== 'lab') }),
        {
          mode: 0o600,
        },
      )
      await r.request('service/identities', {})
      expect(s.unit('lab')).toBeNull()
      if (how === 'refused at the remove') {
        // Refused: nothing written or dropped yet; the held file waits.
        expect(readdirSync(labHeld)).toEqual([`${waiting.id}.env`])
        chmodSync(peers, 0o600)
        await call(r, 'status')
      }
      expect(readdirSync(labHeld)).toEqual([])
      expect(JSON.parse(readFileSync(peers, 'utf8')).pairs).toEqual([])
      const carol = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8').split('\n')
      const failed = carol.filter((x) => x.includes('failed-local') && x.includes(String(waiting.id)))
      expect(failed).toHaveLength(1)
      expect(failed[0]).toContain('identity removed')
    })

  it('a planted row with a made-up label is dropped from the table, audited, and asks no one (s2)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const b = await window(s, 'research')
    const planted = {
      a: 'ghost',
      b: 'research',
      a_addr: P.jane.address,
      b_addr: P.carol.address,
      added_at: 1,
      state: 'requested',
      at: T0,
      held: [],
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [planted] }), { mode: 0o600 })
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(b.dialogs).toEqual([])
    expect(JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs).toEqual([])
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(audit).toContain('a local pair named a label that is no identity of this home: 1 dropped')
    }
    void a
  })

  it('a table forged between start and the first call is reset: the baseline is read at start (q1)', async () => {
    word(true)
    const s = await start()
    // After start, before any tool call: an allowed row the service never wrote.
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    const forged = { version: 1, pairs: [{ ...row, state: 'allowed' }] }
    writeFileSync(localPeersPath(home), JSON.stringify(forged), { mode: 0o600 })
    const a = await window(s, 'personal')
    const sent = await call(a, 'send', chat([P.carol.address]))
    expect(sent).toMatchObject({ delivery: 'local', pairing: 'requested' })
    expect(sent.notice).toContain('a local pair on this machine changed outside bag')
    expect(await call(a, 'status')).toMatchObject({ local_peers: [] })
  })

  it('a spooled envelope from a forged allowed pair is refused at the open: the receiver reads the reconciled table (q1)', async () => {
    word(true)
    const keys = (name: string): EdgeKeys => (name === 'alice' ? P.alice.keys : P.carol.keys)
    const s = await start(
      {
        openKeys: async (_h, name) => ({
          custody: 'keychain',
          address: keys(name).signing.address,
          keys: keys(name),
        }),
      },
      {},
      [P.carol],
    )
    expect(s.unit('research')?.opened).toBeNull()
    // Forged after start: an allowed row on disk, and an envelope from personal waiting in research's spool.
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
    }
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    const forged = { version: 1, pairs: [{ ...row, state: 'allowed' }] }
    writeFileSync(localPeersPath(home), JSON.stringify(forged), { mode: 0o600 })
    const rng = seededRng('forged-spool')
    const env = buildEnvelope({
      from: P.alice.keys.signing,
      to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text: 'forged pair' },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
    mkdirSync(spoolDir(home, 'carol'), { recursive: true, mode: 0o700 })
    writeFileSync(join(spoolDir(home, 'carol'), `${env.envelope.id}.env`), env.bytes, { mode: 0o600 })
    // research opens at its bind: the spool drains through its receive path, whose local roots come from the
    // service's reconciled view (the forged row reset to requested), never the disk.
    await window(s, 'research')
    await until(() => readdirSync(spoolDir(home, 'carol')).filter((f) => f.endsWith('.env')).length === 0)
    expect(
      log.lines.some(
        (x) =>
          x.event === 'local-spool' && x.fields.label === 'research' && x.fields.code === 'untrusted-root',
      ),
    ).toBe(true)
    expect((JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[])[0]).toMatchObject({
      state: 'requested',
    })
  })

  it('a spooled envelope that does not unseal at the open is kept (.failed) and logged, never dropped', async () => {
    word(true)
    allowedRow()
    const keys = (name: string): EdgeKeys => (name === 'alice' ? P.alice.keys : P.carol.keys)
    const s = await start(
      {
        openKeys: async (_h, name) => ({
          custody: 'keychain',
          address: keys(name).signing.address,
          keys: keys(name),
        }),
      },
      {},
      [P.carol],
    )
    const a = await window(s, 'personal')
    // An envelope sealed to a key research does not hold (it rotated since), spooled as a send to it closed leaves it.
    const alice = s.unit('personal')?.opened?.edge
    if (alice === undefined) throw new Error('not open')
    const { id, bytes } = alice.seal({ type: 'chat.v1', body: 'stale key' }, [
      { address: P.carol.address, sealingKey: P.bob.keys.sealing.publicKey },
    ])
    mkdirSync(spoolDir(home, 'carol'), { recursive: true })
    writeFileSync(join(spoolDir(home, 'carol'), `${id}.env`), bytes)
    await window(s, 'research')
    await until(() => readdirSync(spoolDir(home, 'carol')).includes(`${id}.env.failed`))
    expect(log.lines.some((x) => x.event === 'local-spool' && x.fields.code === 'open-failed')).toBe(true)
    expect(await call(a, 'status', { id })).toMatchObject({
      status: 'not delivered locally: research could not open it (open-failed)',
    })
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
    expect(audit.filter((l) => l.includes('failed-local') && l.includes(id))).toHaveLength(1)
  })
})

describe("a removed identity's held mail is failed naming the side it was held for (#dropRemoved)", () => {
  /** An envelope from research (carol) to lab (jane), as research's touch of a pair lab asked for is held. */
  const forLab = (text: string) => {
    const rng = seededRng(`for-lab-${text}`)
    return buildEnvelope({
      from: P.carol.keys.signing,
      to: [{ address: P.jane.address, sealingKey: P.jane.keys.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
  }

  it("lab removed while it is the row's a: each held message is failed naming the side it was for, both ways", async () => {
    word(true)
    const file = join(home, 'identities.json')
    const reread = () =>
      (parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig).identities
    const env = forLab('held')
    // And lab's own message to research, from the row's a, waiting in research's held/.
    const rng = seededRng('from-lab')
    const fromLab = buildEnvelope({
      from: P.jane.keys.signing,
      to: [{ address: P.carol.address, sealingKey: P.carol.keys.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text: 'from lab' },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
    // lab asked research first (lab is the row's a); research's message to lab waits in lab's held/.
    const row = {
      a: 'lab',
      b: 'research',
      a_addr: P.jane.address,
      b_addr: P.carol.address,
      added_at: 1,
      state: 'requested',
      at: T0,
      held: [env.envelope.id, fromLab.envelope.id],
    }
    const s = await start({ reread }, {}, [], [], [['lab', P.jane]], () => {
      const held = join(spoolDir(home, 'jane'), 'held')
      mkdirSync(held, { recursive: true, mode: 0o700 })
      writeFileSync(join(held, `${env.envelope.id}.env`), env.bytes, { mode: 0o600 })
      const carolHeld = join(spoolDir(home, 'carol'), 'held')
      mkdirSync(carolHeld, { recursive: true, mode: 0o700 })
      writeFileSync(join(carolHeld, `${fromLab.envelope.id}.env`), fromLab.bytes, { mode: 0o600 })
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
    })
    const r = await window(s, 'research', null)
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { version: number; identities: Json[] }
    const without = doc.identities.filter((x) => x.label !== 'lab')
    writeFileSync(file, JSON.stringify({ version: 1, identities: without }), { mode: 0o600 })
    await r.request('service/identities', {})
    expect(readdirSync(join(spoolDir(home, 'jane'), 'held'))).toEqual([])
    const lines = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8')
      .split('\n')
      .filter((x) => x.includes('failed-local') && x.includes(env.envelope.id))
    expect(lines).toHaveLength(1)
    const detail = JSON.parse(String((JSON.parse(lines[0] as string) as Json).detail)) as Json
    // The side it was held for, lab: never the row's b (research, the sender's own side), as main had it.
    expect(detail).toMatchObject({ delivery: 'failed-local', reason: 'identity removed', to: 'lab' })
    // The other way, from the row's a: lab's message to research is failed in lab's own audit, naming research.
    expect(readdirSync(join(spoolDir(home, 'carol'), 'held'))).toEqual([])
    const fromA = readFileSync(join(home, 'state', 'jane', 'audit.jsonl'), 'utf8')
      .split('\n')
      .filter((x) => x.includes('failed-local') && x.includes(fromLab.envelope.id))
    expect(fromA).toHaveLength(1)
    expect(JSON.parse(String((JSON.parse(fromA[0] as string) as Json).detail))).toMatchObject({
      reason: 'identity removed',
      to: 'research',
    })
  })
})

describe('run/removed.json: a served remove whose service stopped before the give-back', () => {
  /** An envelope from `from` to `to`, by party. */
  const mail = (from: Party, to: Party, text: string) => {
    const rng = seededRng(`recorded-${text}`)
    return buildEnvelope({
      from: from.keys.signing,
      to: [{ address: to.address, sealingKey: to.keys.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
  }
  /** Holds `env` in the held/ of key name `name`. */
  const holdIn = (name: string, env: { envelope: { id: string }; bytes: Uint8Array }): string => {
    const dir = join(spoolDir(home, name), 'held')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    writeFileSync(join(dir, `${env.envelope.id}.env`), env.bytes, { mode: 0o600 })
    return join(dir, `${env.envelope.id}.env`)
  }
  const rowOf = (a: string, b: string, aAddr: string, bAddr: string, id: string) => ({
    a,
    b,
    a_addr: aAddr,
    b_addr: bAddr,
    added_at: 1,
    state: 'requested',
    at: T0,
    held: [id],
  })
  const failedIn = (name: string, id: string): Json[] => {
    const file = join(home, 'state', name, 'audit.jsonl')
    if (!existsSync(file)) return []
    return readFileSync(file, 'utf8')
      .split('\n')
      .filter((x) => x.includes('failed-local') && x.includes(id))
      .map((x) => JSON.parse(String((JSON.parse(x) as Json).detail)) as Json)
  }
  const table = () => JSON.parse(readFileSync(localPeersPath(home), 'utf8')).pairs as Json[]

  it("a fresh start fails the removed identity's held mail to each sender's audit, then the record goes", async () => {
    word(true)
    // What a served identity remove of lab left: lab out of identities.json and its key moved, research's mail to it
    // moved into research's held/ (state/jane left the home), the row kept for the give-back, and the record.
    const env = mail(P.carol, P.jane, 'to lab')
    const file = holdIn('carol', env)
    const s = await start({}, {}, [], [], [], () => {
      const row = rowOf('research', 'lab', P.carol.address, P.jane.address, env.envelope.id)
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
      recordRemoved(home, { label: 'lab', key: 'jane', address: P.jane.address, at: T0 })
    })
    void s
    expect(existsSync(file)).toBe(false)
    expect(table()).toEqual([])
    await until(() => failedIn('carol', env.envelope.id).length === 1)
    expect(failedIn('carol', env.envelope.id)).toEqual([
      { relay: LOCAL_RELAY, delivery: 'failed-local', reason: 'identity removed', to: 'lab' },
    ])
    expect(readRemoved(home)).toEqual([])
  })

  it("a sender that is neither side of the row's addresses is not guessed: a policy line names the file, the spool's label is used", async () => {
    word(true)
    const env = mail(P.carol, P.jane, 'reset')
    const file = holdIn('carol', env)
    const s = await start({}, {}, [], [], [], () => {
      // The row's b address is not research's (a reset row): carol, the sender, is neither side's address.
      const row = rowOf('research', 'lab', P.bob.address, P.jane.address, env.envelope.id)
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
      recordRemoved(home, { label: 'lab', key: 'jane', address: P.jane.address, at: T0 })
    })
    void s
    expect(existsSync(file)).toBe(false)
    await until(() => failedIn('carol', env.envelope.id).length === 1)
    // research's spool held it: research is the label, never a guess between the row's two sides.
    expect(failedIn('carol', env.envelope.id)).toEqual([
      { relay: LOCAL_RELAY, delivery: 'failed-local', reason: 'identity removed', to: 'research' },
    ])
    const policy = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8')
      .split('\n')
      .filter((x) => x.includes('is from neither side of its pair'))
    expect(policy).toHaveLength(1)
    expect(policy[0]).toContain(`${env.envelope.id}.env`)
  })

  for (const [what, spoil] of [
    [
      'a symlinked removed.json',
      () => {
        const real = join(mkdtempSync(join(home, '..', 'bsl-real-')), 'removed.json')
        renameSync(join(home, 'run', 'removed.json'), real)
        symlinkSync(real, join(home, 'run', 'removed.json'))
      },
    ],
    ['a 0644 removed.json', () => chmodSync(join(home, 'run', 'removed.json'), 0o644)],
    [
      'a directory in its place',
      () => {
        rmSync(join(home, 'run', 'removed.json'))
        mkdirSync(join(home, 'run', 'removed.json'))
      },
    ],
  ] as [string, () => void][])
    it(`${what} is read as no entries at the start: a policy line, nothing failed, the held mail kept`, async () => {
      word(true)
      const env = mail(P.carol, P.jane, `refused-${what}`)
      const file = holdIn('carol', env)
      const s = await start({}, {}, [], [], [], () => {
        const row = rowOf('research', 'lab', P.carol.address, P.jane.address, env.envelope.id)
        writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
        recordRemoved(home, { label: 'lab', key: 'jane', address: P.jane.address, at: T0 })
        spoil()
      })
      void s
      await until(() =>
        readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8').includes('removed record refused'),
      )
      expect(existsSync(file)).toBe(true)
      expect(failedIn('carol', env.envelope.id)).toEqual([])
    })

  it('re-added with the same key: nothing is failed, the record goes, and the held mail is delivered at the Allow', async () => {
    word(true)
    const env = mail(P.carol, P.jane, 'kept')
    const file = holdIn('jane', env)
    const s = await start({}, {}, [], [], [['lab', P.jane]], () => {
      const row = rowOf('research', 'lab', P.carol.address, P.jane.address, env.envelope.id)
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: [row] }), { mode: 0o600 })
      recordRemoved(home, { label: 'lab', key: 'jane', address: P.jane.address, at: T0 })
    })
    expect(readRemoved(home)).toEqual([])
    expect(existsSync(file)).toBe(true)
    expect(table()).toMatchObject([{ a: 'research', b: 'lab', state: 'requested', held: [env.envelope.id] }])
    const l = await window(s, 'lab')
    await call(l, 'status')
    await until(() => table()[0]?.state === 'allowed')
    await until(() => !existsSync(file))
    expect(failedIn('carol', env.envelope.id)).toEqual([])
  })

  it('re-added with a new key: the old held mail is failed, the new identity keeps its own', async () => {
    word(true)
    const jade = party('jade', 0x17)
    const old = mail(P.carol, P.jane, 'old')
    const fresh = mail(P.alice, jade, 'new')
    const oldFile = holdIn('carol', old)
    const s = await start({}, {}, [], [], [['lab', jade]], () => {
      const freshFile = holdIn('jade', fresh)
      void freshFile
      const rows = [
        rowOf('research', 'lab', P.carol.address, P.jane.address, old.envelope.id),
        rowOf('personal', 'lab', P.alice.address, jade.address, fresh.envelope.id),
      ]
      writeFileSync(localPeersPath(home), JSON.stringify({ version: 1, pairs: rows }), { mode: 0o600 })
      recordRemoved(home, { label: 'lab', key: 'jane', address: P.jane.address, at: T0 })
    })
    void s
    expect(existsSync(oldFile)).toBe(false)
    await until(() => failedIn('carol', old.envelope.id).length === 1)
    expect(failedIn('carol', old.envelope.id)[0]).toMatchObject({ reason: 'identity removed', to: 'lab' })
    expect(existsSync(join(spoolDir(home, 'jade'), 'held', `${fresh.envelope.id}.env`))).toBe(true)
    expect(table()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ a: 'personal', b: 'lab', b_addr: jade.address, held: [fresh.envelope.id] }),
      ]),
    )
    expect(failedIn('alice', fresh.envelope.id)).toEqual([])
    expect(readRemoved(home)).toEqual([])
  })
})

describe("a Codex sub-agent's connection never speaks for the identity it binds", () => {
  // A Codex sub-agent's shim is a second connection of the same window: its calls carry the window's sessionId with a
  // threadId of its own (a window's two ids are equal), and a current shim adds bag.dev/subagent true. The service
  // marks such a connection at its first call, before the call runs, and never clears the mark; the wake router never
  // lets a marked connection speak, so mail still wakes the window the person types in.
  const isRing = (m: Json): boolean => m.method === 'service/ring'
  const S = '01a1dcf8-4bfd-7000-8000-000000000001'
  const T = '01a1dcf9-51b4-7000-8000-000000000002'
  const SUB = { sessionId: S, threadId: T, [SUBAGENT_META]: true }
  const OLD_SHIM = { sessionId: S, threadId: T }
  const WINDOW = { sessionId: S, threadId: S }

  async function callWith(l: Line, name: string, args: Json, meta?: Json): Promise<Json> {
    const params = meta === undefined ? { name, arguments: args } : { name, arguments: args, _meta: meta }
    const r = await l.request('tools/call', params)
    const result = r.result as { content?: { text: string }[] } | undefined
    if (result === undefined) throw new Error(JSON.stringify(r))
    return JSON.parse(result.content?.[0]?.text ?? '{}') as Json
  }

  /** A Codex sub-agent's connection at /w/sub, bound to `label` by its own use call (the person's Yes), `meta` on it. */
  async function subagent(s: Service, label: string, meta: Json): Promise<Line> {
    const l = await connected(s, 'sub', { host: 'codex', input_hook: false })
    const use = callWith(l, 'use', { name: label }, meta)
    const req = await l.next((m) => m.method === 'elicitation/create')
    const handle = ((req.params as Json)._meta as Json)[DIALOG_META]
    const result = { action: 'accept', content: { bind: true }, _meta: { [DIALOG_META]: handle } }
    // The bind dialog's clock is the service's real one: the person answers after FAST_ANSWER_MS (0.4.4).
    await new Promise((r) => setTimeout(r, 300))
    l.send({ jsonrpc: '2.0', id: req.id, result })
    expect(await use).toMatchObject({ bound: true, as: label, granted: 'dialog' })
    return l
  }

  const connAt = (s: Service, cwd: string) => [...s.connections].find((c) => c.cwd === cwd)

  /** personal and research allowed; personal's window, then research's Codex window, typed into, bound first. */
  async function setup(): Promise<{ s: Service; timers: ManualTimers; a: Line; main: Line }> {
    word(true)
    allowedRow()
    const timers = new ManualTimers()
    const s = await start({ timers })
    const a = await window(s, 'personal')
    const main = await window(s, 'research', true, { host: 'codex' })
    expect(await callWith(main, 'status', {}, WINDOW)).toMatchObject({ as: 'research' })
    return { s, timers, a, main }
  }

  /** One local message from personal to research, rung after the settle wait. */
  async function mail(a: Line, timers: ManualTimers): Promise<void> {
    expect(await call(a, 'send', chat([P.carol.address]))).toMatchObject({ delivery: 'local' })
    timers.fire((ms) => ms === SETTLE_MS)
  }

  it("a sub-agent bound last and alive: the mail rings the window's own connection, the sub-agent's quietly", async () => {
    const { s, timers, a, main } = await setup()
    const sub = await subagent(s, 'research', SUB)
    expect(connAt(s, '/w/sub')?.subagent).toBe(true)
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ as: 'research', unread: 1, speaking: true })
    expect((await sub.next(isRing)).params).toMatchObject({ as: 'research', unread: 1, speaking: false })
    // Its later calls change nothing: the next mail rings the same way.
    await callWith(sub, 'status', {}, SUB)
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ speaking: true })
    expect((await sub.next(isRing)).params).toMatchObject({ speaking: false })
    expect(connAt(s, '/w/research')?.subagent).toBe(false)
  })

  it('a sub-agent connection that says hello and never calls gets no ring and no wake, and is not marked', async () => {
    const { s, timers, a, main } = await setup()
    const sub = await connected(s, 'sub', { host: 'codex', input_hook: false })
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ as: 'research', speaking: true })
    // A ping is no tool call; its answer comes after anything the ring wrote to this connection.
    expect((await sub.request('ping')).result).toEqual({})
    expect(sub.count(isRing)).toBe(0)
    expect(connAt(s, '/w/sub')?.subagent).toBe(false)
  })

  it("a later call that looks like the window's (bag.dev/subagent false, equal ids, or no _meta) never clears the mark", async () => {
    const { s, timers, a, main } = await setup()
    const sub = await subagent(s, 'research', SUB)
    await callWith(sub, 'status', {}, { ...WINDOW, [SUBAGENT_META]: false })
    expect(connAt(s, '/w/sub')?.subagent).toBe(true)
    await callWith(sub, 'status', {})
    expect(connAt(s, '/w/sub')?.subagent).toBe(true)
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ speaking: true })
    expect((await sub.next(isRing)).params).toMatchObject({ speaking: false })
  })

  it('a first call that is the use bind, with differing ids, is marked before the bind applies', async () => {
    const { s, timers, a, main } = await setup()
    const own = connAt(s, '/w/research')?.handle
    const sub = await subagent(s, 'research', OLD_SHIM)
    // The bind made this connection a seat of research, yet the window still speaks: the mark came first.
    expect(connAt(s, '/w/sub')?.subagent).toBe(true)
    expect(own).toBeDefined()
    expect(s.router.speaking('research')).toBe(own)
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ as: 'research', unread: 1, speaking: true })
    expect((await sub.next(isRing)).params).toMatchObject({ as: 'research', unread: 1, speaking: false })
  })

  it('a 0.4.1 shim sends no field: differing sessionId and threadId mark its connection at the bind', async () => {
    const { s, timers, a, main } = await setup()
    const sub = await subagent(s, 'research', OLD_SHIM)
    expect(connAt(s, '/w/sub')?.subagent).toBe(true)
    await mail(a, timers)
    expect((await main.next(isRing)).params).toMatchObject({ speaking: true })
    expect((await sub.next(isRing)).params).toMatchObject({ speaking: false })
  })

  it("the window's own connection is never marked: equal ids, no _meta, and differing ids on a host that is not Codex", async () => {
    const { s, timers, a, main } = await setup()
    await callWith(main, 'status', {}, WINDOW)
    await callWith(main, 'status', {})
    expect(connAt(s, '/w/research')?.subagent).toBe(false)
    // The inference is Codex's ids only: another host's differing ids are no sign of a sub-agent.
    const other = await window(s, 'research', true, { host: 'claude-code', cwd: '/w/other' })
    await callWith(other, 'status', {}, OLD_SHIM)
    expect(connAt(s, '/w/other')?.subagent).toBe(false)
    await mail(a, timers)
    expect((await other.next(isRing)).params).toMatchObject({ speaking: true })
    expect((await main.next(isRing)).params).toMatchObject({ speaking: false })
  })
})
