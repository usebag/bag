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
import { buildEnvelope, newThread, parseEnvelope, SUITE } from '@usebag/core'
import { type EdgeKeys, HomeCustody, keepAddressCopy, LOCAL_RELAY } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseServerConfig, type ServerConfig } from '../src/config.ts'
import { dropLocalPair, localPeersPath, localWordPath, spoolDir } from '../src/local.ts'
import { HIDE_WORDS, OLD_EXTENSION, SHOW_EVERY_S } from '../src/pairing.ts'
import { CONSENT_BRIDGE, LINK_ASK_S, Service, type ServiceDeps } from '../src/service.ts'
import { DIALOG_META } from '../src/socket.ts'
import {
  HOME_NOTE,
  HOME_OFF,
  LOCAL_ASK_DAYS,
  LOCAL_HELD_MAX,
  LOCAL_PER_DAY,
  LOCAL_PER_MINUTE,
} from '../src/tools.ts'
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
import { MemoryRelay } from './support/relay.ts'

// Delivery between identities of one home in the bag service (spec/SPEC.md 9.2, decision 98), over its socket as a
// host reaches it: with the home word off every guard answers as before; on, a local pair is one dialog that writes
// only the service's table, and mail between the pair goes through the recipient's own receive path with no relay
// request (M1 to M6). personal is alice's key, research carol's, in one home; bob is a wire peer.

type Json = Record<string, unknown>

let home: string
let relay: MemoryRelay
let log: MemoryLog
const live: Service[] = []
const sockets: Socket[] = []

beforeEach(() => {
  home = mkdtempSync('/tmp/bsl-')
  relay = new MemoryRelay()
  log = new MemoryLog()
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

async function start(
  more: Partial<ServiceDeps> = {},
  entry: Json = {},
  keychain: Party[] = [],
  agent: Party[] = [],
  others: [string, Party][] = [],
  prep: () => void = () => {},
): Promise<Service> {
  const ids: [string, Party][] = [['personal', P.alice], ['research', P.carol], ...others]
  for (const [, p] of ids) {
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
    // The home's own copy of each address record, as onboard keeps it: where a local seal reads the sealing key.
    keepAddressCopy(home, p.name, addressRecord(p))
  }
  const identities = ids.map(([label, p]) => ({
    label,
    key: p.name,
    home,
    relays: [RELAY],
    trust_roots: [P.bob.address],
    ...entry,
  }))
  const file = join(home, 'identities.json')
  writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
  const config = parseServerConfig(['--service', '--dir', home, '--identities', file], {}) as ServerConfig
  const deps: ServiceDeps = {
    clock: new FakeClock(),
    rng: seededRng('service-local'),
    relayFor: () => relay,
    records: fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4243,
    alive: () => false,
    log,
    resubscribeDelayMs: () => 0,
    helloMs: 300,
    drainCallsMs: 200,
    returnWaitMs: 300,
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
  /** The dialogs this window was shown, by message. */
  readonly dialogs: string[]
  /** The consent bridge folder the hello returned (an omp window), else undefined. */
  bridge?: string
}

/** A window bound to `label`; `hello` replaces members of its hello (an omp window: no elicitation, the bridge). */
async function window(
  s: Service,
  label: string,
  answer: boolean | null | 'never' | 'decline' | 'empty' = true,
  hello: Json = {},
): Promise<Line> {
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
  const dir = (said.result as Json).bridge_dir
  if (typeof dir === 'string') line.bridge = dir
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
        answer === null
          ? { action: 'cancel' }
          : answer === 'decline'
            ? { action: 'decline' }
            : answer === 'empty'
              ? { action: 'accept', content: {} }
              : { action: 'accept', content: { confirm: answer } }
      line.send({ jsonrpc: '2.0', id: req.id, result: { ...result, _meta: { [DIALOG_META]: handle } } })
    }
  })().catch(() => {})
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

describe("discovery: status's home (decision 103)", () => {
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
    // The top-level word says the same as home (falsifier GAP 3); once the file exists, plain on.
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

describe('the local pair on first touch (decision 104)', () => {
  const ASK =
    'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, never ' +
    'go to a relay, and reach each agent as mail from your own identity.'
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

  it('a corrupt held file is set aside as .failed and the rest delivered after a Yes (falsifier 21)', async () => {
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
    const b = await window(s, 'research', false)
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
    const no = await window(s, 'research', false)
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
    const no = await window(s, 'research', false)
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
    const no = await window(s, 'research', false)
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

  it('a re-ask by the decliner rings the window that will be asked (row.b), not the other side (falsifier 18)', async () => {
    word(true)
    const [clock, timers] = [new FakeClock(), new ManualTimers()]
    const s = await start({ clock, timers })
    const a = await window(s, 'personal')
    const r = await window(s, 'research', false)
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

  it('a re-ask with no answer (a fast decline, or a timeout or cancel) is cancelled, never declined (q2)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    expect(await call(a, 'pair_invite', { for: P.carol.address })).toMatchObject({ pairing: 'requested' })
    await call(await window(s, 'research', false), 'status')
    expect(pairs()).toMatchObject([{ state: 'declined', reasks: [] }])
    for (const answer of ['decline', null] as const) {
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.carol.address })
      expect([r.error, r.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
      // No answer is no re-ask: none counted, still declined.
      expect(pairs()).toMatchObject([{ state: 'declined', reasks: [] }])
    }
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
    const no = await window(s, 'research', false)
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

describe("omp's Allow over its extension's registered link, never a file (item 7, C2)", () => {
  const WORDS =
    'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, never ' +
    'go to a relay, and reach each agent as mail from your own identity.'
  const PID = 777_001
  /** An omp window of omp process `pid`: no elicitation, the bridge capability naming that pid (the shim's). */
  const omp = (s: Service, label: string, pid = PID) =>
    window(s, label, true, {
      host: 'omp',
      client_capabilities: { experimental: { [CONSENT_BRIDGE]: { pid } } },
    })
  /** The extension's own connection: a hello, then consent-register for `pid`; the asks it receives, kept. */
  async function link(s: Service, pid = PID, secret?: string) {
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
    })
    const asks = () => seen.filter((m) => m.method === 'service/consent-ask').map((m) => m.params as Json)
    const withdraws = () =>
      seen.filter((m) => m.method === 'service/consent-withdraw').map((m) => m.params as Json)
    return { socket, reg, request, asks, withdraws }
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
    // An answer file in the window's bridge folder, or an answer on another connection, changes nothing.
    const dir = b.bridge as string
    writeFileSync(join(dir, `${l.asks()[0]?.id}.answer.json`), JSON.stringify({ accepted: true }))
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
    // Under omp's 30 s limit on the tool call that carries it (item j): 25 s, then withdrawn, the confirm dismissed.
    expect(LINK_ASK_S).toBe(25)
    expect(l.asks()[0]?.ms).toBe(LINK_ASK_S * 1000)
    timers.fire((ms) => ms === LINK_ASK_S * 1000)
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

  it('with no link the window is not asked; a first registration after its hello is refused (L2)', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal')
    const b = await omp(s, 'research')
    await call(a, 'send', chat([P.carol.address]))
    expect(await call(b, 'status')).not.toHaveProperty('error')
    expect(pairState()).toBe('requested')
    expect(OLD_EXTENSION).toContain('bag host install omp again and restarts omp')
    const late = await link(s)
    expect((late.reg.error as Json).data).toMatchObject({ code: 'not-authorized' })
    expect(late.asks()).toEqual([])
    const audit = readFileSync(join(home, 'state', 'carol', 'audit.jsonl'), 'utf8')
    expect(audit).toContain(`consent registration refused for omp ${PID}`)
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

describe('hidden: an identity kept apart (decision 103, section 3)', () => {
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

  it('hide and show with no answer (a fast decline, or a timeout or cancel) are cancelled, never declined (q2)', async () => {
    word(true)
    const clock = new FakeClock()
    const s = await start({ clock })
    const fileWord = () => JSON.parse(readFileSync(localWordPath(home), 'utf8')) as Json
    for (const answer of ['decline', null] as const) {
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.alice.address })
      expect([r.error, r.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
      expect(fileWord()).toEqual({ version: 1, local_delivery: 'on' })
    }
    // Hidden by a Yes; then a show with no answer is cancelled too, and personal stays hidden.
    expect(await call(await window(s, 'personal'), 'pair_invite', { for: P.alice.address })).toMatchObject({
      hidden: true,
    })
    for (const answer of ['decline', null] as const) {
      clock.t += SHOW_EVERY_S
      const w = await window(s, 'personal', answer)
      const r = await call(w, 'pair_invite', { for: P.alice.address })
      expect([r.error, r.detail]).toEqual(['cancelled', 'the dialog was not answered: nothing was changed'])
      expect(fileWord()).toMatchObject({ hidden: ['personal'] })
    }
  })

  it('a No changes nothing', async () => {
    word(true)
    const s = await start()
    const a = await window(s, 'personal', false)
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

  it('limits a sender to 20 local sends a minute and 200 a day, audited (S5)', async () => {
    const clock = new FakeClock()
    const { a } = await paired({ clock })
    const rate = async (): Promise<Json> => call(a, 'send', chat([P.carol.address]))
    for (let i = 0; i < LOCAL_PER_MINUTE; i++) expect(await rate()).toMatchObject({ delivery: 'local' })
    const over = await rate()
    expect([over.error, String(over.detail).startsWith('rate: at most 20 local sends a minute')]).toEqual([
      'to-own-identity',
      true,
    ])
    const audit = readFileSync(join(home, 'state', 'alice', 'audit.jsonl'), 'utf8').split('\n')
    expect(audit.filter((l) => l.includes('"rate-limit"') && l.includes('minute'))).toHaveLength(1)
    clock.t += 60
    expect(await rate()).toMatchObject({ delivery: 'local' })
    // 21 counted so far; spread out, the day's 200 is the next bound.
    for (let i = 21; i < LOCAL_PER_DAY; i++) {
      clock.t += 4
      expect(await rate()).toMatchObject({ delivery: 'local' })
    }
    clock.t += 4
    expect(String((await rate()).detail)).toContain('200 a day')
    clock.t += 86_400
    expect(await rate()).toMatchObject({ delivery: 'local' })
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
      // Labelled as from an own identity (decision 103, item 5).
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
    // The next touch asks again (decision 104): held, nothing delivered.
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
