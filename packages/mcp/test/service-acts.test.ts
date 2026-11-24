import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { type AcceptFromRecord, parseRecord, serializeRecord } from '@usebag/core'
import {
  keepAddressCopy,
  type RelayClient,
  RelayError,
  readAuditLines,
  SqliteStore,
  setKeepAlive,
  verifyAuditLog,
} from '@usebag/edge'
import { fetchTripwire, recordingRelay, relayTripwire } from '@usebag/edge/test-support'
import {
  CLI_AUDIT,
  type HomeIo,
  identityRelays,
  installClaude,
  keepFirstRecordsLocal,
  migrate,
  readRemoved,
} from '@usebag/home'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { tableFor } from '../src/binding.ts'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { localWordPath } from '../src/local.ts'
import { shortAddress } from '../src/pairing.ts'
import { rereadOf, Service, type ServiceDeps } from '../src/service.ts'
import { DIALOG_META } from '../src/socket.ts'
import {
  ACT_QUESTIONS,
  CREATE_TOO_LONG,
  FOLDER_NOT_SHOWN,
  OTHER_FOLDER,
  RECORDS_KEPT,
  RECORDS_NONE,
  RELAY_NOT_PLAIN,
  WIRE_PLACEHOLDER,
  WIRE_TAKES_NO_LABEL,
} from '../src/tools.ts'
import {
  acceptFrom,
  addressRecord,
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
  type TestServer,
  testServer,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The acts on the home as tools of the bag service (tools.ts, service.ts quiet): the person's Yes in the window first,
// then the identity held quiet only while the act re-checks and writes, and given back as a lend's return gives it
// back, also when the act throws; while the question is open its unit keeps receiving mail. The home is a folder of
// its own under /tmp (its socket fits sun_path), so what identity remove moves beside it stays in the test's folder.

type Json = Record<string, unknown>

let root: string
let home: string
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let log: MemoryLog
const live: Service[] = []
const sockets: Socket[] = []
const others: TestServer[] = []
/** The labels the file lists with relays [] (on this machine only), and the tripwire every one of them gets. */
let localOnly: readonly string[] = []
let wire = relayTripwire()
/** The record source of a start that lists or makes an identity on this machine only (`here`, or localOnly). */
let lookups = fetchTripwire()
let here = false
/** Set at a promotion's Yes: from then on an identity with relays [] gets this relay, not the tripwire. */
let promoted: RelayClient | null = null

beforeEach(() => {
  localOnly = []
  wire = relayTripwire()
  lookups = fetchTripwire()
  here = false
  promoted = null
  root = mkdtempSync('/tmp/bsa-')
  home = join(root, 'h')
  mkdirSync(home, { mode: 0o700 })
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  log = new MemoryLog()
})
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const o of others.splice(0)) await o.close()
  for (const s of live.splice(0)) await s.drain()
  rmSync(root, { recursive: true, force: true })
})

/** The service's own file, <home>/identities.json, as the CLI writes it: each label with its party's key. */
function identitiesFile(ids: readonly [string, Party][]): string {
  const file = join(home, 'identities.json')
  const identities = ids.map(([label, p]) => {
    saveKeys(home, p)
    const here = localOnly.includes(label)
    if (here)
      keepFirstRecordsLocal({ clock, rng: seededRng(label) } as unknown as HomeIo, home, p.name, p.keys)
    return { label, key: p.name, home, relays: here ? [] : [RELAY], trust_roots: [P.bob.address] }
  })
  writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
  return file
}

async function start(ids: readonly [string, Party][], more: Partial<ServiceDeps> = {}): Promise<Service> {
  const file = identitiesFile(ids)
  const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
  const s = await Service.start(config, home, {
    clock,
    rng: seededRng('acts'),
    relayFor: (c) => (c.relays.length === 0 ? (promoted ?? wire) : relay),
    records: here || localOnly.length > 0 ? () => lookups : fakeRecords(new Map()),
    timers,
    pid: 4242,
    alive: () => false,
    // The registering extension is the omp it names (socket-owner.ts peerIs answers match); a test changes it.
    peer: async () => 'match',
    log,
    resubscribeDelayMs: () => 0,
    helloMs: 300,
    drainCallsMs: 200,
    returnWaitMs: 300,
    reread: rereadOf(file, config, home),
    ...more,
  })
  live.push(s)
  await s.opening
  return s
}

/** A line client of the socket: requests by id, and the frames nobody waited for kept for next. */
interface Line {
  send(m: Json): void
  next(pick: (m: Json) => boolean): Promise<Json>
  request(method: string, params?: Json): Promise<Json>
}

async function connect(s: Service, hello: Json): Promise<Line> {
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
    send: (m) => socket.write(`${JSON.stringify(m)}\n`),
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
  const r = await line.request('service/hello', {
    contract: 1,
    token: s.token.toString('hex'),
    host: 'claude-code',
    cwd: '/tmp/work',
    client_capabilities: { elicitation: { form: {} } },
    input_hook: true,
    ...hello,
  })
  expect(r.result, JSON.stringify(r)).toBeDefined()
  return line
}

/** A window bound to `label` by the person's typed word. */
async function bound(s: Service, label: string, cwd = '/tmp/work'): Promise<Line> {
  const l = await connect(s, { cwd })
  const r = await l.request('service/use', { label, via: 'typed' })
  expect(r.result, JSON.stringify(r)).toMatchObject({ bound: true, as: label })
  return l
}

/** A tool call's answer: its structured value. */
async function call(l: Line, name: string, args: Json = {}): Promise<Json> {
  const r = await l.request('tools/call', { name, arguments: args })
  const result = r.result as { content?: { text: string }[] } | undefined
  if (result === undefined) throw new Error(JSON.stringify(r))
  return JSON.parse(result.content?.[0]?.text ?? '{}') as Json
}

/**
 * A person's pace (0.4.4): an answer sooner than FAST_ANSWER_MS after its dialog went out is unseen, and the service's
 * dialog clocks are the real one here, so a scripted answer is sent this long after the dialog arrived.
 */
const PERSON_MS = 300
const atPersonPace = (): Promise<void> => new Promise((r) => setTimeout(r, PERSON_MS))

/** The next dialog of window `l`: its message, and how to answer it (Yes, or no answer). */
async function dialog(l: Line): Promise<{ message: string; answer(yes: boolean): void }> {
  const req = await l.next((m) => m.method === 'elicitation/create')
  const params = req.params as Json
  const handle = (params._meta as Json)[DIALOG_META]
  return {
    message: String(params.message),
    answer: (yes) => {
      const result = yes ? { action: 'accept', content: { confirm: true } } : { action: 'cancel' }
      void atPersonPace().then(() =>
        l.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } }),
      )
    },
  }
}

async function until(test: () => boolean, ms = 5000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** bob, outside the home, sending to alice through the same memory relay. */
async function bobOutside(): Promise<TestServer> {
  const dir = join(root, 'bob')
  saveKeys(dir, P.bob)
  await publishAddress(relay, P.alice)
  await publishAddress(relay, P.bob)
  const bob = await testServer({
    home: dir,
    name: 'bob',
    relay,
    clock,
    timers,
    args: ['--trust-root', P.alice.address],
  })
  others.push(bob)
  return bob
}

/** The roots of alice's newest accept-from at the relay, and its iat. */
const acceptAt = (p: Party): AcceptFromRecord =>
  parseRecord(relay.records.get(`${RELAY} ${p.address} accept-from`) as Uint8Array) as AcceptFromRecord

/** An audit line's event, decision and parsed detail. */
const eventOf = (l: string): { event: string; decision: string; detail: unknown } => {
  const v = JSON.parse(l) as { event: string; decision: string; detail: string | null }
  return { event: v.event, decision: v.decision, detail: v.detail === null ? null : JSON.parse(v.detail) }
}

const accepted = (s: Service, label: string): number => s.unit(label)?.desk?.counts().counts.accepted ?? -1

describe('quiet: the service holds an identity quiet for an act, and gives it back as a lend returns', () => {
  it('a second quiet or a CLI lend answers busy while it holds; its end reopens the unit, also after a throw', async () => {
    const s = await start([['personal', P.alice]])
    const end = await s.quiet('personal', 'unpair')
    expect(s.unit('personal')?.opened).toBeNull()
    expect(s.lent('personal')).toBe('unpair')
    await expect(s.quiet('personal', 'identity-relays')).rejects.toMatchObject({ code: 'busy' })
    const cli = await connect(s, { host: 'cli', input_hook: false })
    const lend = await cli.request('service/lend', { label: 'personal', verb: 'pair' })
    expect(((lend.error as Json).data as Json).code).toBe('busy')
    expect(JSON.stringify(lend)).toContain('is held for unpair in a window')
    // A bind answers busy too, naming the act, never the window.
    const win = await connect(s, {})
    const use = await win.request('service/use', { label: 'personal', via: 'typed' })
    expect(JSON.stringify(use)).toContain('lent to an act in a window (unpair)')
    // The CLI cannot return what it did not lend.
    expect(((await cli.request('service/return', { label: 'personal' })).error as Json).data).toMatchObject({
      code: 'usage',
    })
    await end()
    await end()
    expect(s.unit('personal')?.opened).not.toBeNull()
    expect(s.lent('personal')).toBeNull()
    // quiesce runs the act under quiet; an act that throws is given back all the same.
    await expect(
      s.quiesce('personal', async () => {
        expect(s.unit('personal')?.opened).toBeNull()
        throw new Error('the act failed')
      }),
    ).rejects.toThrow('the act failed')
    expect(s.unit('personal')?.opened).not.toBeNull()
    expect((await cli.request('service/lend', { label: 'personal', verb: 'pair' })).result).toMatchObject({
      lent: true,
    })
  })

  it('with alone, refuses an identity a window is bound to', async () => {
    const s = await start([
      ['personal', P.alice],
      ['research', P.carol],
    ])
    await bound(s, 'research')
    await expect(s.quiet('research', 'identity-remove', true)).rejects.toMatchObject({ code: 'busy' })
    expect(s.unit('research')?.opened).not.toBeNull()
  })
})

describe('unpair through the tool', () => {
  it('while its dialog is open the unit receives mail; after the Yes the record leaves the root, and a keep-alive tick keeps it out', async () => {
    const s = await start([['personal', P.alice]])
    setKeepAlive(home, 'personal', true)
    const bob = await bobOutside()
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice, [P.bob.address])))
    const w = await bound(s, 'personal')
    const pending = call(w, 'unpair', { root: P.bob.address })
    const d = await dialog(w)
    expect(d.message).toBe(ACT_QUESTIONS.unpair('personal', P.bob.address).message)
    // Not quiet while the person decides: the unit is open, and mail sent now arrives.
    expect(s.unit('personal')?.opened).not.toBeNull()
    const before = accepted(s, 'personal')
    expect((await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'hi' })).isError).toBe(
      false,
    )
    await until(() => accepted(s, 'personal') === before + 1)
    d.answer(true)
    const r = await pending
    expect(r.lines).toContain(
      `last root: the accept-from of ${P.alice.address} now names only ${P.alice.address}, its owner`,
    )
    expect(r).toMatchObject({ as: 'personal' })
    expect(acceptAt(P.alice).roots).toEqual([P.alice.address])
    // Given back: open again, and not lent.
    await until(() => s.unit('personal')?.opened !== null && s.lent('personal') === null)
    const after = acceptAt(P.alice).iat
    // One keep-alive tick past the record's re-sign point: what it signs is the record as it is now.
    clock.t += 80_000
    for (let i = 0; i < 100 && acceptAt(P.alice).iat <= after; i++) {
      timers.fire()
      await new Promise((x) => setTimeout(x, 10))
    }
    expect(acceptAt(P.alice).roots).toEqual([P.alice.address])
    expect(acceptAt(P.alice).iat).toBeGreaterThan(after)
  })

  it('a dialog not answered changes nothing and never held the identity quiet', async () => {
    const s = await start([['personal', P.alice]])
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice, [P.bob.address])))
    const w = await bound(s, 'personal')
    const pending = call(w, 'unpair', { root: P.bob.address })
    ;(await dialog(w)).answer(false)
    expect(await pending).toMatchObject({ error: 'cancelled', as: 'personal' })
    expect(acceptAt(P.alice).roots).toEqual([P.bob.address])
    expect(log.lines.some((l) => l.event === 'quiet')).toBe(false)
    expect(s.unit('personal')?.opened).not.toBeNull()
  })
})

describe('identity_remove through the tool', () => {
  // The service's pid is this process's, as in a real service: the units' mcp.lock files name a live process, so the
  // act's held check sees them, and only the service's own lease or quiet of the label lets it through.
  const ids: [string, Party][] = [
    ['personal', P.alice],
    ['research', P.carol],
  ]

  it('removes another identity after the Yes: its files move, the service drops it; never itself, never one a window uses', async () => {
    const s = await start(ids, { pid: process.pid })
    const w = await bound(s, 'personal')
    expect(await call(w, 'identity_remove', { name: 'personal' })).toMatchObject({
      error: 'usage',
      as: 'personal',
    })
    expect(await call(w, 'identity_remove', { name: 'nobody' })).toMatchObject({
      error: 'unknown-identity',
      as: 'personal',
    })
    // Another window uses research: its unit's lock is that unit's, not a quiet's, so the act refuses held, before
    // any question.
    const other = await bound(s, 'research', '/tmp/other')
    expect(await call(w, 'identity_remove', { name: 'research' })).toMatchObject({
      error: 'held',
      as: 'personal',
    })
    expect(s.unit('research')?.opened).not.toBeNull()
    expect(log.lines.some((l) => l.event === 'quiet')).toBe(false)
    sockets.at(-1)?.destroy()
    void other
    await until(() => s.connections.size === 1)
    const pending = call(w, 'identity_remove', { name: 'research' })
    const d = await dialog(w)
    // No held mail: the N = 0 form.
    expect(d.message).toBe(
      [
        'Remove research from this machine?',
        `Address: ${shortAddress(P.carol.address)}`,
        'Its files move to a folder; its relays are told.',
      ].join('\n'),
    )
    expect(d.message).toBe(ACT_QUESTIONS.remove('research', P.carol.address, 0).message)
    // Nothing is held quiet while the person decides: neither the window's own identity nor the one removed.
    expect(s.unit('personal')?.opened).not.toBeNull()
    expect(s.unit('research')?.opened).not.toBeNull()
    expect(s.lent('research')).toBeNull()
    d.answer(true)
    const r = await pending
    expect(r.lines).toEqual(expect.arrayContaining([expect.stringMatching(/^removed carol ed25519:/)]))
    expect(r).toMatchObject({ as: 'personal' })
    await until(() => s.unit('research') === null)
    const left = JSON.parse(readFileSync(join(home, 'identities.json'), 'utf8')) as { identities: Json[] }
    expect(left.identities.map((i) => i.label)).toEqual(['personal'])
    expect(existsSync(join(home, 'keys', 'carol.json'))).toBe(false)
    expect(s.lent('research')).toBeNull()
    expect(log.lines.filter((l) => l.event === 'quiet').map((l) => l.fields.label)).toEqual(['research'])
    // The record of the served remove was written, and deleted at the give-back once its held mail was failed.
    expect(readRemoved(home)).toEqual([])
  })

  it('while its dialog is open the identity removed keeps receiving mail; no answer changes nothing', async () => {
    const s = await start(ids, { pid: process.pid })
    const bob = await bobOutside()
    await publishAddress(relay, P.carol)
    const w = await bound(s, 'personal')
    const pending = call(w, 'identity_remove', { name: 'research' })
    const d = await dialog(w)
    const before = accepted(s, 'research')
    expect((await bob.call('send', { to: [P.carol.address], type: 'chat.v1', body: 'hi' })).isError).toBe(
      false,
    )
    await until(() => accepted(s, 'research') === before + 1)
    d.answer(false)
    expect(await pending).toMatchObject({ error: 'cancelled', as: 'personal' })
    expect(existsSync(join(home, 'keys', 'carol.json'))).toBe(true)
    expect(log.lines.some((l) => l.event === 'quiet')).toBe(false)
    expect(s.unit('research')?.opened).not.toBeNull()
    expect(readRemoved(home)).toEqual([])
  })

  it('removes an identity on this machine only: its dialog says no relay is told, and none is called', async () => {
    localOnly = ['research']
    const s = await start(ids, { pid: process.pid })
    const w = await bound(s, 'personal')
    const pending = call(w, 'identity_remove', { name: 'research' })
    const d = await dialog(w)
    expect(d.message).toBe(
      [
        'Remove research from this machine?',
        `Address: ${shortAddress(P.carol.address)}`,
        'Its files move to a folder; no relay is told.',
      ].join('\n'),
    )
    expect(ACT_QUESTIONS.remove('research', P.carol.address, 0, true).title).toBe('Yes: remove research')
    d.answer(true)
    expect((await pending).lines).toEqual(
      expect.arrayContaining([expect.stringMatching(/^removed carol ed25519:/)]),
    )
    await until(() => s.unit('research') === null)
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })

  it("a window bound to the identity refuses held before any question: its lock is that unit's, not a quiet's", async () => {
    const s = await start(ids, { pid: process.pid })
    const w = await bound(s, 'personal')
    const other = await bound(s, 'research', '/tmp/other')
    expect(await call(w, 'identity_remove', { name: 'research' })).toMatchObject({
      error: 'held',
      as: 'personal',
    })
    // Answered with no dialog: a question would have waited for this window's person.
    expect(s.unit('research')?.opened).not.toBeNull()
    void other
  })

  it('an identity no window is bound to passes to the question, its own unit open while it is asked', async () => {
    const s = await start(ids, { pid: process.pid })
    const w = await bound(s, 'personal')
    const pending = call(w, 'identity_remove', { name: 'research' })
    const d = await dialog(w)
    expect(d.message.split('\n')[0]).toBe('Remove research from this machine?')
    expect(s.unit('research')?.opened).not.toBeNull()
    d.answer(false)
    expect(await pending).toMatchObject({ error: 'cancelled', as: 'personal' })
  })

  it('another live process holding the identity refuses held before any question', async () => {
    // research's lock is held by another live process (this test's own pid, the service's being 4242), as a command
    // line that took it would: the service cannot open it, and the lock is no lease or quiet of the service's.
    mkdirSync(join(home, 'state', 'carol'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'state', 'carol', 'mcp.lock'), JSON.stringify({ pid: process.pid }))
    const s = await start(ids, { alive: (pid) => pid === process.pid })
    expect(s.unit('research')?.opened).toBeNull()
    const w = await bound(s, 'personal')
    expect(await call(w, 'identity_remove', { name: 'research' })).toMatchObject({
      error: 'held',
      as: 'personal',
    })
    expect(existsSync(join(home, 'keys', 'carol.json'))).toBe(true)
    expect(log.lines.some((l) => l.event === 'quiet')).toBe(false)
  })

  it('a window that binds the identity during the dialog makes the Yes busy: nothing moves', async () => {
    const s = await start(ids, { pid: process.pid })
    const w = await bound(s, 'personal')
    const pending = call(w, 'identity_remove', { name: 'research' })
    const d = await dialog(w)
    await bound(s, 'research', '/tmp/late')
    d.answer(true)
    expect(await pending).toMatchObject({ error: 'busy', as: 'personal' })
    expect(existsSync(join(home, 'keys', 'carol.json'))).toBe(true)
    expect(s.unit('research')?.opened).not.toBeNull()
    expect(s.lent('research')).toBeNull()
  })
})

describe('identity_relays through the tool', () => {
  it("asks with the old and the new list, holds the identity quiet only after the Yes, and writes the service's file", async () => {
    const s = await start([['personal', P.alice]])
    const w = await bound(s, 'personal')
    const next = 'http://relay2.test'
    const pending = call(w, 'identity_relays', { relays: [`${next}/`] })
    const d = await dialog(w)
    const file = join(home, 'identities.json')
    expect(d.message).toBe(['Set the relays of personal to:', 'http://relay2.test'].join('\n'))
    expect(s.lent('personal')).toBeNull()
    d.answer(true)
    const r = await pending
    expect(r).toMatchObject({ as: 'personal' })
    expect((r.lines as string[])[0]).toBe(`relays personal ${next}`)
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { identities: { relays: string[] }[] }
    expect(doc.identities[0]?.relays).toEqual([next])
    expect(
      log.lines.filter((l) => l.event === 'quiet' || l.event === 'quiet-end').map((l) => l.event),
    ).toEqual(['quiet', 'quiet-end'])
    await until(() => s.unit('personal')?.opened !== null && s.lent('personal') === null)
  })
})

describe('identity_relays on an identity on this machine only: its promotion', () => {
  it('asks to publish it, naming each relay and what one sees; no relay call until the Yes', async () => {
    localOnly = ['personal']
    const s = await start([['personal', P.alice]])
    const w = await bound(s, 'personal')
    // A second on from the records kept at its making: a copy of an equal iat is refused (keepAddressCopy).
    clock.t += 1
    const pending = call(w, 'identity_relays', { relays: [RELAY] })
    const d = await dialog(w)
    expect(d.message).toBe(
      ['Publish personal at these relays?', RELAY, 'Each relay sees when mail arrives for it.'].join('\n'),
    )
    expect(ACT_QUESTIONS.relays('personal', [RELAY], true)?.title).toBe('Yes: publish personal')
    const at = [...relay.records.keys()].filter((k) => k.includes(P.alice.address))
    expect([wire.calls, lookups.calls, at]).toEqual([[], [], []])
    const rec = recordingRelay(relay)
    promoted = rec
    d.answer(true)
    const r = await pending
    expect(r.lines).toEqual(expect.arrayContaining([`published address ${P.alice.address} ${RELAY}`]))
    // In order: epoch 1's key record, an address record naming the new relays, then the accept-from.
    const published: readonly { kind: string; address: string; relays: readonly string[] | null }[] =
      rec.published
    expect(published.map((p) => [p.kind, p.address, p.relays])).toEqual([
      ['key', P.alice.address, null],
      ['address', P.alice.address, [RELAY]],
      ['accept-from', P.alice.address, null],
    ])
    expect(wire.calls).toEqual([])
  })
})

describe('the relays a give-back finds in the file: taken at the reopen, with no restart', () => {
  const RELAY2 = 'http://relay2.test'
  /** The unit's relay client: the tripwire until the Yes, then the recorder (looked up at each call, not at start). */
  const via = new Proxy({} as RelayClient, {
    get: (_t, k) => {
      const c = (promoted ?? wire) as unknown as Record<string | symbol, unknown>
      const f = c[k]
      return typeof f === 'function' ? f.bind(c) : f
    },
  })
  const deps: Partial<ServiceDeps> = {
    relayFor: () => via,
    records: (client) => (promoted === null ? lookups : fakeRecords(new Map())(client)),
  }
  /** A recording relay over the memory relay; mail (no kind) goes past its record parse, its relay kept in `mail`. */
  function recorder(): { rec: ReturnType<typeof recordingRelay>; mail: string[]; client: RelayClient } {
    const rec = recordingRelay(relay)
    const mail: string[] = []
    const publish: RelayClient['publish'] = (url, bytes) => {
      if ((JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }).kind !== undefined)
        return rec.publish(url, bytes)
      mail.push(url)
      return relay.publish(url, bytes)
    }
    return { rec, mail, client: { ...rec, publish } }
  }
  /** bob off this machine, at RELAY, taking mail from anyone: his records put there directly, by no identity's call. */
  async function bobAtRelay(): Promise<void> {
    await publishAddress(relay, P.bob)
    await relay.publish(RELAY, serializeRecord(acceptFrom(P.bob)))
  }
  /** The checks of a promoted identity in the same service lifetime: send, publish order, status, keeper, subscribe. */
  async function live(s: Service, w: Line, r: ReturnType<typeof recorder>): Promise<void> {
    await until(() => s.unit('personal')?.state === 'running' && s.lent('personal') === null)
    expect(r.rec.calls).toContainEqual({ method: 'subscribe', url: RELAY })
    const sent = await call(w, 'send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(sent.error, JSON.stringify(sent)).toBeUndefined()
    expect(r.mail).toEqual([RELAY])
    expect(r.rec.published.map((p) => [p.kind, p.address, p.relays])).toEqual([
      ['key', P.alice.address, null],
      ['address', P.alice.address, [RELAY]],
      ['accept-from', P.alice.address, null],
    ])
    const line = (s.unit('personal') as NonNullable<ReturnType<Service['unit']>>).summary()
    expect(line.relays).toEqual([RELAY])
    expect(line).not.toHaveProperty('reach')
    expect(JSON.stringify(await call(w, 'status'))).not.toContain('this machine only')
    // A keeper exists: its next time is set (an ISO time; null with no keeper, as for relays []).
    await until(() => typeof s.unit('personal')?.summary().keep_alive_next_at === 'string')
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  }

  it('a promotion by identity_relays: the reopened unit sends, subscribes and keeps its records', async () => {
    localOnly = ['personal']
    const s = await start([['personal', P.alice]], deps)
    await bobAtRelay()
    const w = await bound(s, 'personal')
    clock.t += 1
    const pending = call(w, 'identity_relays', { relays: [RELAY] })
    const d = await dialog(w)
    expect([wire.calls, lookups.calls]).toEqual([[], []])
    const r = recorder()
    promoted = r.client
    d.answer(true)
    expect((await pending).error).toBeUndefined()
    await live(s, w, r)
  })

  it('a promotion by the CLI, through a lend and its return: the same', async () => {
    localOnly = ['personal']
    const s = await start([['personal', P.alice]], deps)
    await bobAtRelay()
    const cli = await connect(s, { host: 'cli', input_hook: false })
    expect(
      (await cli.request('service/lend', { label: 'personal', verb: 'identity-relays' })).result,
    ).toBeDefined()
    expect([wire.calls, lookups.calls]).toEqual([[], []])
    const r = recorder()
    promoted = r.client
    clock.t += 1
    const io = {
      say: () => {},
      warn: () => {},
      ask: async () => true,
      clock,
      rng: seededRng('cli'),
      env: { HOME: root },
      relay: () => r.client,
    } as unknown as HomeIo
    await identityRelays(io, home, 'personal', [RELAY])
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({ open: true })
    await live(s, await bound(s, 'personal'), r)
  })

  it('a published identity given other relays takes them at the reopen', async () => {
    const r = recorder()
    promoted = r.client
    const s = await start([['personal', P.alice]], deps)
    const w = await bound(s, 'personal')
    const pending = call(w, 'identity_relays', { relays: [RELAY2] })
    ;(await dialog(w)).answer(true)
    expect((await pending).error).toBeUndefined()
    await until(() => s.unit('personal')?.state === 'running' && s.lent('personal') === null)
    const u = s.unit('personal') as NonNullable<ReturnType<Service['unit']>>
    expect([u.config.relays, u.config.rendezvous]).toEqual([[RELAY2], RELAY2])
    expect(u.summary().relays).toEqual([RELAY2])
    expect((u.summary().subscriptions as { relay: string }[]).map((x) => x.relay)).toEqual([RELAY2])
    await until(() => r.rec.calls.some((c) => c.method === 'subscribe' && c.url === RELAY2))
  })

  it('an entry changed while its label is open and listed: a reread leaves it, its next return takes it', async () => {
    const r = recorder()
    promoted = r.client
    const s = await start([['personal', P.alice]], deps)
    const file = join(home, 'identities.json')
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { identities: { relays: string[] }[] }
    ;(doc.identities[0] as { relays: string[] }).relays = [RELAY2]
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    // A hello re-reads the file (#refresh): an open label is not read again there.
    const cli = await connect(s, { host: 'cli', input_hook: false })
    expect(s.unit('personal')?.config.relays).toEqual([RELAY])
    expect((await cli.request('service/lend', { label: 'personal', verb: 'pair' })).result).toBeDefined()
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({ open: true })
    await until(() => s.unit('personal')?.state === 'running')
    expect(s.unit('personal')?.summary().relays).toEqual([RELAY2])
    await until(() => r.rec.calls.some((c) => c.method === 'subscribe' && c.url === RELAY2))
  })

  it('a give-back of an unchanged identity reopens with its config as it was', async () => {
    const s = await start([['personal', P.alice]], deps)
    const before = s.unit('personal')?.config
    const cli = await connect(s, { host: 'cli', input_hook: false })
    expect((await cli.request('service/lend', { label: 'personal', verb: 'pair' })).result).toBeDefined()
    expect((await cli.request('service/return', { label: 'personal' })).result).toMatchObject({ open: true })
    expect(s.unit('personal')?.config).toBe(before)
  })
})

describe('identity_create through the tool, in a window bound to no identity', () => {
  /** The identities file's labels and relays now. */
  const listed = (): [unknown, unknown][] =>
    (
      JSON.parse(readFileSync(join(home, 'identities.json'), 'utf8')) as { identities: Json[] }
    ).identities.map((i) => [i.label, i.relays])
  const relays = ['https://relay-one.example.com/', 'http://relay.test:8080/r']

  it('T4: the question shows the label and every relay whole; a No or no answer writes nothing', async () => {
    const s = await start([['personal', P.alice]])
    const w = await connect(s, {})
    // An explicit No in the dialog: declined, nothing written.
    const no = call(w, 'identity_create', { label: 'jane', relays })
    const req = await w.next((m) => m.method === 'elicitation/create')
    const params = req.params as Json
    expect(params.message).toBe(
      ['Make jane and publish it to these relays?', 'relay-one.example.com, http://relay.test:8080/r'].join(
        '\n',
      ),
    )
    expect(params.message).toBe(
      ACT_QUESTIONS.create('jane', ['relay-one.example.com', 'http://relay.test:8080/r'])?.message,
    )
    const handle = (params._meta as Json)[DIALOG_META]
    await atPersonPace()
    w.send({
      jsonrpc: '2.0',
      id: req.id,
      result: { action: 'decline', _meta: { [DIALOG_META]: handle } },
    })
    expect(await no).toMatchObject({ error: 'declined', as: null })
    // No answer: cancelled, nothing written.
    const none = call(w, 'identity_create', { label: 'jane', relays })
    ;(await dialog(w)).answer(false)
    expect(await none).toMatchObject({ error: 'cancelled', as: null })
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(false)
    expect(listed()).toEqual([['personal', [RELAY]]])
    expect(s.unit('jane')).toBeNull()
    // The Yes makes it, with the relays as given (each checked), in a key file.
    const made = call(w, 'identity_create', { label: 'jane', relays })
    ;(await dialog(w)).answer(true)
    expect(await made).toMatchObject({
      lines: expect.arrayContaining([expect.stringMatching(/^ed25519:/)]),
      as: null,
    })
    expect(listed()).toEqual([
      ['personal', [RELAY]],
      ['jane', ['https://relay-one.example.com', 'http://relay.test:8080/r']],
    ])
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
  })

  it('T5: a bad label or relay refuses before any question, as does a label the home holds', async () => {
    const s = await start([['personal', P.alice]])
    const w = await connect(s, {})
    const refused: [Json, string][] = [
      [{ label: 'Jane', relays }, 'usage'],
      [{ label: 'jane.service', relays }, 'usage'],
      [{ label: `j${'a'.repeat(32)}`, relays }, 'usage'],
      [{ label: 'jane\nYes', relays }, 'usage'],
      [{ label: 'personal', relays }, 'exists'],
      [{ label: 'alice', relays }, 'exists'],
      [{ label: 'jane', relays: ['ftp://relay.test'] }, 'usage'],
      [{ label: 'jane', relays: ['not a url'] }, 'usage'],
    ]
    for (const [args, code] of refused)
      expect([args, await call(w, 'identity_create', args)]).toMatchObject([args, { error: code, as: null }])
    expect(
      await call(w, 'identity_create', { label: 'jane', relays: ['https://u@relay.test'] }),
    ).toMatchObject({
      error: 'usage',
      detail: RELAY_NOT_PLAIN,
    })
    const long = (n: number) => `https://relay-${n}-${'x'.repeat(30)}.example.com`
    expect(
      await call(w, 'identity_create', { label: 'jane', relays: [long(1), long(2), long(3)] }),
    ).toMatchObject({ error: 'usage', detail: CREATE_TOO_LONG })
    // Every refusal came back with no dialog sent: the next one this window sees is the next ask's.
    const asked = call(w, 'identity_create', { label: 'jane', relays })
    const d = await dialog(w)
    expect(d.message).toContain('Make jane and publish it to these relays?')
    d.answer(false)
    await asked
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(false)
  })

  it('with relays [] it makes one here only: a 32-letter label fits, its records are kept, no relay call', async () => {
    here = true
    const s = await start([['personal', P.alice]])
    const w = await connect(s, {})
    const name = 'j'.repeat(32)
    const made = call(w, 'identity_create', { label: name, relays: [] })
    const d = await dialog(w)
    const lines = [
      `Make ${name} on this machine only?`,
      'Nothing is published; it can talk to your other',
      'identities here, and you can give it relays later.',
    ]
    expect(d.message).toBe(lines.join('\n'))
    expect(lines.every((l) => l.length <= 60)).toBe(true)
    d.answer(true)
    const r = await made
    const address = (r.lines as string[])[0] as string
    expect(r.lines).toEqual([
      address,
      ...['key', 'address', 'accept-from'].map((k) => `kept ${k} ${address}`),
    ])
    expect(listed()).toEqual([
      ['personal', [RELAY]],
      [name, []],
    ])
    await until(() => s.unit(name)?.state === 'running')
    expect([s.unit(name)?.records, s.unit(name)?.subscriptions.list()]).toEqual([null, []])
    expect([...relay.records.keys()].some((k) => k.includes(address))).toBe(false)
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })

  it('with relays [] and local delivery off, its result says how to turn it on', async () => {
    mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(localWordPath(home), JSON.stringify({ version: 1, local_delivery: 'off' }), { mode: 0o600 })
    here = true
    const s = await start([['personal', P.alice]])
    const w = await connect(s, {})
    const made = call(w, 'identity_create', { label: 'kim', relays: [] })
    ;(await dialog(w)).answer(true)
    expect(((await made).lines as string[]).at(-1)).toBe(
      'local delivery is off on this machine: bag local-delivery on',
    )
    expect([wire.calls, lookups.calls]).toEqual([[], []])
  })

  it('after the Yes it publishes the first records to each named relay, one line each; nothing reaches a relay before it', async () => {
    const R2 = 'http://relay2.test'
    let answered = false
    // Once the service has started, a record publish or read before the person's Yes throws: no network before it.
    let armed = false
    const guarded = new Proxy(relay, {
      get(target, key, receiver) {
        const v = Reflect.get(target, key, receiver) as unknown
        if (armed && !answered && (key === 'publish' || key === 'fetchRecord'))
          return () => Promise.reject(new Error(`${String(key)} before the Yes`))
        return typeof v === 'function' ? v.bind(target) : v
      },
    })
    const s = await start([['personal', P.alice]], { relayFor: () => guarded })
    armed = true
    const w = await connect(s, {})
    const made = call(w, 'identity_create', { label: 'jane', relays: [RELAY, R2] })
    const d = await dialog(w)
    expect(
      [...relay.records.keys()].some((k) => k.includes(' accept-from') && !k.includes(P.alice.address)),
    ).toBe(false)
    answered = true
    d.answer(true)
    const r = await made
    const address = (r.lines as string[])[0] as string
    expect(r.lines).toEqual([
      address,
      ...['key', 'address', 'accept-from'].flatMap((k) =>
        [RELAY, R2].map((u) => `published ${k} ${address} ${u}`),
      ),
    ])
    for (const url of [RELAY, R2])
      for (const kind of ['key', 'address', 'accept-from'])
        expect([url, kind, relay.records.has(`${url} ${address} ${kind}`)]).toEqual([url, kind, true])
    // The home's copy is written as onboard writes it, which host_wire reads.
    expect(existsSync(join(home, 'records', 'jane.address.json'))).toBe(true)
    // The same trace as the command line's act in cli-audit.jsonl, anchored, and it verifies: one policy line per
    // address and accept-from publish per relay, and the rotation line.
    const state = join(home, 'state', 'jane')
    const audit = readAuditLines(join(state, CLI_AUDIT))
    const publish = (record: string, url: string) => ({
      event: 'policy',
      decision: 'accept',
      detail: { step: 'publish', record, relay: url, outcome: 'ok' },
    })
    expect(audit.map(eventOf)).toEqual([
      publish('address', RELAY),
      publish('address', R2),
      { event: 'rotate', decision: 'accept', detail: expect.objectContaining({ subject: `key:${address}` }) },
      publish('accept-from', RELAY),
      publish('accept-from', R2),
    ])
    const store = new SqliteStore(join(state, 'edge.sqlite'), { lock: false })
    const anchor = store.auditAnchorGet(CLI_AUDIT)
    store.close()
    expect(verifyAuditLog(audit, anchor)).toMatchObject({ ok: true })
    expect(s.unit('jane')).not.toBeNull()
  })

  it('a relay that refuses its records is a failed line; none taking them refuses with its code, and the identity stays', async () => {
    const R2 = 'http://relay2.test'
    const s = await start([['personal', P.alice]])
    const w = await connect(s, {})
    relay.failRecordPublish.set(R2, new RelayError('publish-failed', 500, null, 'refused'))
    const made = call(w, 'identity_create', { label: 'jane', relays: [RELAY, R2] })
    ;(await dialog(w)).answer(true)
    const r = await made
    const address = (r.lines as string[])[0] as string
    expect(r.lines).toContain(`failed address ${address} ${R2} publish-failed`)
    expect(r.lines).toContain(`published address ${address} ${RELAY}`)
    // Each publish is audited, the failed one with its code.
    const lines = readAuditLines(join(home, 'state', 'jane', CLI_AUDIT))
      .map(eventOf)
      .filter((l) => l.event === 'policy')
    expect(lines).toEqual(
      [
        ['address', RELAY, 'ok'],
        ['address', R2, 'publish-failed'],
        ['accept-from', RELAY, 'ok'],
        ['accept-from', R2, 'publish-failed'],
      ].map(([record, url, outcome]) => ({
        event: 'policy',
        decision: outcome === 'ok' ? 'accept' : 'reject',
        detail: { step: 'publish', record, relay: url, outcome },
      })),
    )
    relay.failRecordPublish.set(RELAY, new RelayError('publish-failed', 500, null, 'refused'))
    const none = call(w, 'identity_create', { label: 'kim', relays: [RELAY, R2] })
    ;(await dialog(w)).answer(true)
    const refused = await none
    expect(refused).toMatchObject({ error: 'publish-failed', as: null })
    expect(String(refused.detail)).toContain('kim is made, but no relay took its key and address record')
    // Kept, as onboard keeps it: its key, its service entry, and served at once.
    expect(existsSync(join(home, 'keys', 'kim.json'))).toBe(true)
    expect(s.unit('kim')).not.toBeNull()
  })

  it('T6: the new identity is neither bound nor wired: the window stays unbound and its folder untouched', async () => {
    const s = await start([['personal', P.alice]])
    const folder = join(root, 'work')
    mkdirSync(folder)
    const w = await connect(s, { cwd: folder })
    const made = call(w, 'identity_create', { label: 'jane', relays })
    ;(await dialog(w)).answer(true)
    await made
    await until(() => s.unit('jane') !== null)
    const conn = [...s.connections].at(-1)
    expect(conn === undefined ? null : tableFor(home)?.state(conn)).toBe('unbound')
    expect(await call(w, 'status')).toMatchObject({ bound: false, as: null })
    expect(readdirSync(folder)).toEqual([])
    expect(existsSync(join(home, 'install'))).toBe(false)
    // A file key, never the keychain: no dialog on this machine's screen.
    expect(existsSync(join(home, 'keychain', 'jane.json'))).toBe(false)
  })
})

describe("telemetry in a bound window: the machine's setting, in every window", () => {
  it('on asks the person in the bound window; off and status ask nothing, and off answers while on is asked', async () => {
    const machine = join(root, 'machine')
    const s = await start([['personal', P.alice]], { env: { HOME: machine } })
    const w = await bound(s, 'personal')
    expect(await call(w, 'telemetry', { word: 'status' })).toEqual({
      lines: ['telemetry off reason=no-file choice=none id=none spool=0 sent=none'],
      as: 'personal',
    })
    const on = call(w, 'telemetry', { word: 'on' })
    const d = await dialog(w)
    expect(d.message).toBe(ACT_QUESTIONS.telemetryOn.message)
    expect(await call(w, 'telemetry', { word: 'off' })).toEqual({
      lines: ['telemetry off reason=file choice=off id=none spool=0 sent=none'],
      as: 'personal',
    })
    d.answer(true)
    const lines = (await on).lines as string[]
    expect(lines[0]).toMatch(/^telemetry on reason=file choice=on id=set spool=/)
    expect(JSON.stringify(lines)).not.toMatch(/[0-9a-f]{32}/)
    expect(await call(w, 'identity_create', { label: 'jane', relays: [RELAY] })).toMatchObject({
      error: 'not-authorized',
      as: 'personal',
    })
  })
})

describe("host_wire and unwire: a proposal for the window's own folder, for the identity the person types or this window made", () => {
  const ids: [string, Party][] = [
    ['personal', P.alice],
    ['work', P.carol],
  ]
  /** A project folder of this test, made. */
  const project = (name = 'proj'): string => {
    const dir = join(root, name)
    mkdirSync(dir, { recursive: true })
    return dir
  }
  /** The next dialog of `l`, and how to answer it: a typed text, a confirm, or no answer (null). */
  async function next(l: Line): Promise<{ params: Json; answer(content: Json | null): void }> {
    const req = await l.next((m) => m.method === 'elicitation/create')
    const params = req.params as Json
    const handle = (params._meta as Json)[DIALOG_META]
    return {
      params,
      answer: (content) => {
        const result = content === null ? { action: 'cancel' } : { action: 'accept', content }
        void atPersonPace().then(() =>
          l.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } }),
        )
      },
    }
  }
  const field = (params: Json): Json => {
    const props = (params.requestedSchema as Json).properties as Json
    return props
  }
  const proposals = (): Json[] =>
    existsSync(join(home, 'proposals.json'))
      ? (JSON.parse(readFileSync(join(home, 'proposals.json'), 'utf8')).proposals as Json[])
      : []
  /** The folder's host files, as they are: none of them is written by a wire. */
  const hostFiles = (dir: string): (string | null)[] =>
    ['.mcp.json', join('.omp', 'mcp.json'), join('.claude', 'settings.json')].map((f) =>
      existsSync(join(dir, f)) ? readFileSync(join(dir, f), 'utf8') : null,
    )
  /** What the bind dialog of a window in `cwd` presets: the table's proposal. */
  const preset = (s: Service, cwd: string, host = 'claude-code'): string | null =>
    s.table.propose({ cwd, host } as never)
  /** A proposals.json of these rows, 0600, as host migrate writes it. */
  const planted = (rows: Json[]): void =>
    writeFileSync(join(home, 'proposals.json'), JSON.stringify({ version: 1, proposals: rows }), {
      mode: 0o600,
    })

  it('T7, T7b, T7c: the identity is the typed label, never the argument; the wire writes a proposal and no host file', async () => {
    const s = await start(ids)
    const dir = project()
    const w = await connect(s, { cwd: dir })
    // A label argument is refused for wire, before any question: the model never names the identity (M1).
    expect(await call(w, 'host_wire', { host: 'claude-code', label: 'personal' })).toMatchObject({
      error: 'usage',
      detail: WIRE_TAKES_NO_LABEL,
      as: null,
    })
    // A typed label that is no identity of the home refuses, and nothing is proposed (M15).
    const nobody = call(w, 'host_wire', { host: 'claude-code' })
    const first = await next(w)
    expect(Object.keys(field(first.params))).toEqual(['text'])
    expect(field(first.params).text).toEqual({
      type: 'string',
      title: ACT_QUESTIONS.wireTyped('claude-code', dir).title,
    })
    expect(JSON.stringify(first.params)).not.toContain('personal')
    // A typed canary that is no identity: the refusal names the check, never the typed text, in no result and no log.
    first.answer({ text: 'zq-canary-7341' })
    const refused = await nobody
    expect(refused).toMatchObject({ error: 'unknown-identity', as: null })
    expect(JSON.stringify(refused)).not.toContain('zq-canary-7341')
    expect(JSON.stringify(log.lines)).not.toContain('zq-canary-7341')
    for (const l of readdirSync(join(home, 'state'))) {
      const audit = join(home, 'state', l, 'audit.jsonl')
      if (existsSync(audit)) expect(readFileSync(audit, 'utf8')).not.toContain('zq-canary-7341')
    }
    expect(proposals()).toEqual([])
    // The person typing "work": a row of proposals.json, 0600, and the result says its records were not published.
    const typed = call(w, 'host_wire', { host: 'claude-code', action: 'wire' })
    const second = await next(w)
    expect(second.params.message).toBe(ACT_QUESTIONS.wireTyped('claude-code', dir).message)
    second.answer({ text: 'work' })
    expect(await typed).toEqual({
      lines: [`wrote ${join(home, 'proposals.json')}: work proposed in ${dir}`, RECORDS_NONE],
      as: null,
    })
    expect(RECORDS_NONE).toBe(
      'this identity has published no records yet, so no peer can reach it: `bag onboard` in a terminal publishes them',
    )
    expect(proposals()).toEqual([
      {
        folder: dir,
        host: 'claude-code',
        label: 'work',
        from: 'host_wire',
        stamp: expect.stringMatching(/^\d{8}T\d{6}Z$/),
      },
    ])
    expect(statSync(join(home, 'proposals.json')).mode & 0o777).toBe(0o600)
    // With the home's copy of its address record, the line says the service keeps them; omp has its own row.
    keepAddressCopy(home, 'carol', addressRecord(P.carol))
    const omp = call(w, 'host_wire', { host: 'omp' })
    ;(await next(w)).answer({ text: 'work' })
    expect(((await omp).lines as string[]).at(-1)).toBe(RECORDS_KEPT)
    expect(RECORDS_KEPT).toBe("the identity's records at its relays are kept by the bag service as it runs")
    expect(proposals().map((r) => r.host)).toEqual(['claude-code', 'omp'])
    // No per-folder entry: no .mcp.json, no .omp/mcp.json, no .claude/settings.json; the service still holds work.
    expect(hostFiles(dir)).toEqual([null, null, null])
    expect(s.unit('work')?.opened).not.toBeNull()
    expect(WIRE_PLACEHOLDER).toBe('the label of the identity')
    // And host migrate finds nothing in the folder to move.
    const said: string[] = []
    const io = {
      say: (l: string) => said.push(l),
      warn: (l: string) => said.push(l),
      ask: async () => false,
      clock,
      env: { HOME: project('user') },
    }
    const build = { packaged: false, version: '0', cli: 'c', mcp: 'm', omp: 'o', shim: 's' }
    await migrate(io as never, {
      home,
      given: [dir],
      sandbox: false,
      build,
      proc: { node: 'n', execPath: 'n', pid: 1, uid: process.getuid?.() },
    })
    expect(said.at(-1)).toBe('nothing to migrate: no per-folder bag entry of this home was found')
  })

  it("T7: an identity this window made is offered by name for a Yes; T8: only the window's own folder; T10: no scope argument", async () => {
    const s = await start(ids)
    const dir = project()
    const w = await connect(s, { cwd: dir })
    const made = call(w, 'identity_create', { label: 'jane', relays: [RELAY] })
    ;(await dialog(w)).answer(true)
    await made
    await until(() => {
      const u = s.unit('jane')
      return u !== null && u.opened !== null
    })
    expect(await call(w, 'host_wire', { host: 'omp', folder: join(root, 'other') })).toMatchObject({
      error: 'usage',
      detail: OTHER_FOLDER,
    })
    const wire = call(w, 'host_wire', { host: 'omp', folder: dir })
    const d = await next(w)
    expect(Object.keys(field(d.params))).toEqual(['confirm'])
    expect(d.params.message).toBe(ACT_QUESTIONS.wire('omp', dir, 'jane').message)
    d.answer({ confirm: true })
    expect(await wire).toMatchObject({ as: null })
    expect(proposals()).toMatchObject([{ folder: dir, host: 'omp', label: 'jane' }])
    expect(hostFiles(dir)).toEqual([null, null, null])
    const listed = (
      (await w.request('tools/list')).result as { tools: { name: string; inputSchema: Json }[] }
    ).tools
    const props = (t: string) =>
      Object.keys((listed.find((x) => x.name === t)?.inputSchema.properties as Json) ?? {})
    expect(props('host_wire')).toEqual(['host', 'folder', 'action', 'label'])
    expect(listed.some((t) => t.name === 'unwire')).toBe(false)
  })

  it('T9: the question says every new window in the folder will propose the label, the folder whole; one that does not fit refuses', async () => {
    const s = await start(ids)
    const dir = project()
    const w = await connect(s, { cwd: dir })
    const wire = call(w, 'host_wire', { host: 'claude-code' })
    const d = await next(w)
    d.answer({ text: 'work' })
    await wire
    expect(ACT_QUESTIONS.wire('claude-code', dir, 'work').message.split('\n')).toEqual([
      'Every new window in',
      dir,
      'will propose work.',
    ])
    expect(ACT_QUESTIONS.wireTyped('claude-code', dir).message.split('\n')).toEqual([
      'Every new window in',
      dir,
      'will propose the identity you type here.',
    ])
    // Two long folders that share their first 60 characters: neither is cut, so both refuse before any question.
    const long = `/${'p'.repeat(60)}`
    for (const f of [`${long}/a`, `${long}/b`]) {
      const v = await connect(s, { cwd: f })
      expect(await call(v, 'host_wire', { host: 'claude-code' })).toMatchObject({
        error: 'usage',
        detail: FOLDER_NOT_SHOWN,
      })
    }
  })

  it('the proposal presets the bind dialog of a new window in that exact folder, never in a folder under it, and opens no dialog itself', async () => {
    const s = await start(ids)
    const dir = project()
    const sub = project(join('proj', 'sub'))
    const w = await connect(s, { cwd: dir })
    const wire = call(w, 'host_wire', { host: 'omp' })
    ;(await next(w)).answer({ text: 'work' })
    await wire
    // Keyed by the folder alone: every host's window there is preset, live at once; one in proj/sub is not.
    expect(preset(s, dir)).toBe('work')
    expect(preset(s, dir, 'codex')).toBe('work')
    expect(preset(s, sub)).toBeNull()
    // A new window in the folder is unbound, and nothing asks it: its status answers with no dialog.
    const v = await connect(s, { cwd: dir })
    let asked = false
    const first = v.next((m) => m.method === 'elicitation/create')
    void first.then(() => {
      asked = true
    })
    expect(await call(v, 'status')).toMatchObject({ as: null })
    await new Promise((r) => setTimeout(r, 100))
    expect(asked).toBe(false)
    // Asked to bind with no label, its dialog (the first it sees) presets work; the person still chooses.
    const use = call(v, 'use', {})
    const req = await first
    const params = req.params as Json
    expect(field(params).identity).toMatchObject({ default: 'work' })
    const handle = (params._meta as Json)[DIALOG_META]
    v.send({ jsonrpc: '2.0', id: req.id, result: { action: 'cancel', _meta: { [DIALOG_META]: handle } } })
    expect((await use).error).toBeDefined()
    expect(await call(v, 'status')).toMatchObject({ as: null })
    // The service still holds work, and binds it in a window by the typed word.
    expect(s.unit('work')?.opened).not.toBeNull()
    await bound(s, 'work', dir)
  })

  it("T11: action unwire asks, may take its label, removes the folder's proposal and an earlier bag's own entries only (M12, M17)", async () => {
    const s = await start(ids)
    const dir = project()
    const w = await connect(s, { cwd: dir })
    const wire = call(w, 'host_wire', { host: 'claude-code' })
    ;(await next(w)).answer({ text: 'work' })
    await wire
    // An earlier bag's per-folder server in the folder, beside another server and another hook of the person's.
    const work = { label: 'carol', home, relays: [RELAY] }
    const mains = { cli: '/p/bag.js', mcp: '/p/bag-mcp.js', omp: '/p/bag-omp-wake.js', copied: null }
    installClaude(
      { node: '/n/node', execPath: '/n/node', pid: 1, uid: process.getuid?.() },
      mains,
      dir,
      work,
      [],
    )
    const mcpFile = join(dir, '.mcp.json')
    const doc = JSON.parse(readFileSync(mcpFile, 'utf8')) as { mcpServers: Json }
    doc.mcpServers.other = { command: 'other' }
    writeFileSync(mcpFile, JSON.stringify(doc))
    const settingsFile = join(dir, '.claude', 'settings.json')
    const settings = JSON.parse(readFileSync(settingsFile, 'utf8')) as { hooks: Record<string, unknown[]> }
    settings.hooks.Stop?.push({ hooks: [{ type: 'command', command: 'echo mine' }] })
    writeFileSync(settingsFile, JSON.stringify(settings))
    expect(
      await call(w, 'host_wire', { host: 'claude-code', action: 'unwire', label: 'personal' }),
    ).toMatchObject({
      error: 'not-found',
    })
    const no = call(w, 'host_wire', { host: 'claude-code', action: 'unwire', label: 'work' })
    const d = await next(w)
    expect(d.params.message).toBe(ACT_QUESTIONS.unwire('claude-code', dir, 'work').message)
    d.answer(null)
    expect(await no).toMatchObject({ error: 'cancelled' })
    expect(proposals()).toHaveLength(1)
    const yes = call(w, 'host_wire', { host: 'claude-code', action: 'unwire' })
    ;(await next(w)).answer({ confirm: true })
    expect(((await yes).lines as string[])[0]).toBe(
      `wrote ${join(home, 'proposals.json')}: no proposal in ${dir} for claude-code`,
    )
    expect(proposals()).toEqual([])
    expect(preset(s, dir)).toBeNull()
    const after = JSON.parse(readFileSync(mcpFile, 'utf8')) as { mcpServers: Json }
    expect(Object.keys(after.mcpServers)).toEqual(['other'])
    const hooks = JSON.stringify(JSON.parse(readFileSync(settingsFile, 'utf8')))
    expect(hooks).toContain('echo mine')
    expect(hooks).not.toContain('wake-hook')
    // A proposal alone unwires too; nothing proposed and no server is not-found.
    const again = call(w, 'host_wire', { host: 'claude-code' })
    ;(await next(w)).answer({ text: 'work' })
    await again
    const only = call(w, 'host_wire', { host: 'claude-code', action: 'unwire' })
    ;(await next(w)).answer({ confirm: true })
    expect(await only).toMatchObject({
      lines: [`wrote ${join(home, 'proposals.json')}: no proposal in ${dir} for claude-code`],
    })
    expect(await call(w, 'host_wire', { host: 'claude-code', action: 'unwire' })).toMatchObject({
      error: 'not-found',
    })
  })

  it('T12: over the omp link, the text ask and the confirm: the typed label proposes, the argument never does', async () => {
    const s = await start(ids)
    const dir = project()
    const ext = await connect(s, { host: 'omp', input_hook: false, client_capabilities: {} })
    expect(
      (await ext.request('service/consent-register', { pid: 778, kinds: ['text'] })).result,
    ).toBeDefined()
    const w = await connect(s, {
      host: 'omp',
      cwd: dir,
      client_capabilities: { experimental: { 'bag.dev/consent-bridge': { pid: 778 } } },
    })
    const ask = async (answer: Json): Promise<Json> => {
      const q = (await ext.next((m) => m.method === 'service/consent-ask')).params as Json
      await ext.request('service/consent-answer', { id: q.id, ...answer })
      return q
    }
    // On the link path too, a label argument is refused before any question (M10).
    expect(await call(w, 'host_wire', { host: 'omp', label: 'personal' })).toMatchObject({
      error: 'usage',
      detail: WIRE_TAKES_NO_LABEL,
    })
    const wire = call(w, 'host_wire', { host: 'omp' })
    const q = await ask({ accepted: true, text: 'work' })
    expect(q).toMatchObject({
      kind: 'text',
      ...ACT_QUESTIONS.wireTyped('omp', dir),
      placeholder: WIRE_PLACEHOLDER,
    })
    expect(JSON.stringify(q)).not.toContain('personal')
    expect(await wire).toMatchObject({ as: null })
    expect(proposals()).toMatchObject([{ folder: dir, host: 'omp', label: 'work' }])
    expect(hostFiles(dir)).toEqual([null, null, null])
    const unwire = call(w, 'host_wire', { host: 'omp', action: 'unwire' })
    expect(await ask({ accepted: true })).toMatchObject(ACT_QUESTIONS.unwire('omp', dir, 'work'))
    expect(await unwire).toMatchObject({ as: null })
    expect(proposals()).toEqual([])
  })

  it("the made-here reader: a label removed and made again elsewhere is not this window's, so the person types", async () => {
    const s = await start(ids, { pid: process.pid })
    const dir = project()
    const a = await connect(s, { cwd: dir })
    const made = call(a, 'identity_create', { label: 'jane', relays: [RELAY] })
    ;(await dialog(a)).answer(true)
    await made
    // personal's window removes jane; another window makes jane again, with another key.
    const p = await bound(s, 'personal', project('p'))
    const removed = call(p, 'identity_remove', { name: 'jane' })
    ;(await dialog(p)).answer(true)
    expect(await removed).toMatchObject({ as: 'personal' })
    await until(() => s.unit('jane') === null)
    const b = await connect(s, { cwd: project('b') })
    const again = call(b, 'identity_create', { label: 'jane', relays: [RELAY] })
    ;(await dialog(b)).answer(true)
    await again
    await until(() => {
      const u = s.unit('jane')
      return u !== null && u.opened !== null
    })

    // In a, the label alone would match; its pair does not: the dialog asks the person to type.
    const wire = call(a, 'host_wire', { host: 'claude-code' })
    const d = await next(a)
    expect(Object.keys(field(d.params))).toEqual(['text'])
    d.answer(null)
    expect(await wire).toMatchObject({ error: 'cancelled' })
    // No answer proposes nothing; nor does an explicit No to the typed label's question.
    expect(proposals()).toEqual([])
    const no = call(a, 'host_wire', { host: 'claude-code' })
    const asked = await a.next((m) => m.method === 'elicitation/create')
    const handle = ((asked.params as Json)._meta as Json)[DIALOG_META]
    await new Promise((r) => setTimeout(r, 300))
    a.send({ jsonrpc: '2.0', id: asked.id, result: { action: 'decline', _meta: { [DIALOG_META]: handle } } })
    expect(await no).toMatchObject({ error: 'declined' })
    expect(proposals()).toEqual([])
    expect(hostFiles(dir)).toEqual([null, null, null])
  })

  it("host migrate's proposals are read at start; a row naming no identity is left out and logged once", async () => {
    const dir = project()
    const gone = project('gone')
    planted([
      { folder: dir, host: 'claude-code', label: 'work', from: 'migrate', stamp: '20261112T124500Z' },
      { folder: project('x'), host: 'omp', label: 'nobody', from: 'migrate', stamp: '20261112T124500Z' },
      { folder: 'relative/dir', host: 'omp', label: 'work', from: 'migrate', stamp: '20261112T124500Z' },
      { folder: gone, host: 'omp', label: 'personal', from: 'migrate', stamp: '20261112T124500Z' },
    ])
    rmSync(gone, { recursive: true })
    const s = await start(ids)
    expect(preset(s, dir)).toBe('work')
    expect(preset(s, join(root, 'x'))).toBeNull()
    expect(preset(s, 'relative/dir')).toBeNull()
    // A row whose folder is gone stays in the file and marks nothing, even once the folder is there again.
    expect(preset(s, gone)).toBeNull()
    await connect(s, { cwd: dir })
    await connect(s, { cwd: dir })
    expect(log.lines.filter((l) => l.event === 'proposal-not-an-identity')).toEqual([
      { level: 'warn', event: 'proposal-not-an-identity', fields: { label: 'nobody' } },
    ])
    expect(proposals()).toHaveLength(4)
  })

  it('a refused proposals.json (0644, or a link) writes one policy line and loads nothing; wire and unwire refuse it', async () => {
    const dir = project()
    const row = {
      folder: dir,
      host: 'claude-code',
      label: 'work',
      from: 'migrate',
      stamp: '20261112T124500Z',
    }
    planted([row])
    chmodSync(join(home, 'proposals.json'), 0o644)
    const s = await start(ids)
    expect(preset(s, dir)).toBeNull()
    const w = await connect(s, { cwd: dir })
    await connect(s, { cwd: dir })
    const why = 'folder proposals refused, none read: proposals.json is not a 0600 regular file of this user'
    for (const name of ['alice', 'carol']) {
      const audit = readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
      expect(audit.split('\n').filter((l) => l.includes(why))).toHaveLength(1)
    }
    expect(await call(w, 'host_wire', { host: 'claude-code' })).toMatchObject({ error: 'unsafe-path' })
    expect(await call(w, 'host_wire', { host: 'claude-code', action: 'unwire' })).toMatchObject({
      error: 'unsafe-path',
    })
    // A link to a 0600 file of the right rows is refused all the same.
    const real = join(root, 'elsewhere.json')
    writeFileSync(real, JSON.stringify({ version: 1, proposals: [row] }), { mode: 0o600 })
    rmSync(join(home, 'proposals.json'))
    symlinkSync(real, join(home, 'proposals.json'))
    await connect(s, { cwd: dir })
    expect(preset(s, dir)).toBeNull()
    // Put right, the next window's hello reads it.
    rmSync(join(home, 'proposals.json'))
    planted([row])
    await connect(s, { cwd: dir })
    expect(preset(s, dir)).toBe('work')
  })

  it("propose's custody check stays: a lent or removed label presets nothing", async () => {
    const dir = project()
    planted([{ folder: dir, host: 'claude-code', label: 'work', from: 'migrate', stamp: '20261112T124500Z' }])
    const s = await start(ids)
    expect(preset(s, dir)).toBe('work')
    const cli = await connect(s, { host: 'cli', input_hook: false })
    expect((await cli.request('service/lend', { label: 'work', verb: 'pair' })).result).toMatchObject({
      lent: true,
    })
    expect(preset(s, dir)).toBeNull()
    expect((await cli.request('service/return', { label: 'work' })).result).toBeDefined()
    await until(() => preset(s, dir) === 'work')
    // work taken out of the identities file: the next hello's reread drops it, and nothing is preset.
    const file = join(home, 'identities.json')
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { identities: Json[] }
    doc.identities = doc.identities.filter((e) => e.label !== 'work')
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    await connect(s, { cwd: dir })
    await until(() => preset(s, dir) === null)
  })
})
