import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { decodeAddress, openGroupKey, toHex } from '@usebag/core'
import { GroupKeyStore, inviteText as invited, KeyEpochStore } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { NO_RECOVERY } from '../src/commands/keygen.ts'
import { loadKeys } from '../src/home.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli, type Ran } from './support/run.ts'

// The lost device, the in-process lines assigned to this file: L4, the
// hand acts from "device lost" to "the new identity receives a message from each former peer", counted on the
// documented sequence (the pairing and group sections of packages/cli/README.md) by running it through the
// CLI's commands, and L6's half that this file can see (every audit log the recovery touched verifies, the
// four kinds of step that write no audit line write none, and `peer` writes only its epoch's `rotate` line,
// no key material in any output or file). Homes on an
// in-process relay (support/network.ts, which refuses as spec/SPEC.md §8.2 does), the terminal's answers and
// the clock injected through the test io, as peer.test.ts and group.test.ts do. `peer invite` and `peer
// accept` need a terminal on stdin (no-tty otherwise), so the pairing arm of L4 is measured here and only
// here; the end-to-end scenario 46 runs the group arm on the release relay (46d). The "built" halves of L4
// (the devices-as-a-group, a `device` grant) and L5, L7, L8 are not built, so no test exists for them
// ("not run until built").
//
// The count: what counts is each bag command typed, each thing
// carried from one person or device to another (an invite string, an address), each code comparison and each
// confirmation; `mkdir`, `date` and an optional command are not counted (L4). The ledger below
// records each act as the test performs it, a counted command must exit 0 (a refused step repeated would be a
// second act and moves the count), the confirmations are the prompts the commands asked (the io's `asked`),
// and the code comparison is made on the two printed codes.
//
// Forward secrecy (since 2026-10-29): `peer invite` and `peer accept` carry the side's
// current key record, publishing epoch 1 first when the side holds none (cli/src/epochs.ts currentKey), so a pairing
// leaves the side's address record with no sealing key, its key record at the relay, and one `rotate` audit line in
// its home. None of that is a hand act: the counts below are unchanged.

const tmp = tempDir('lost-device')
afterAll(() => tmp.cleanup())
const R = 'http://127.0.0.1:1'
const P = '--allow-private-relays'
let n = 0

interface Party {
  readonly io: TestIo
  readonly dir: string
  readonly name: string
  address: string
}

/** Runs a command in a party's home: --dir unless it takes none, the private-relay flag where it does. */
function go(p: Party, ...argv: string[]): Promise<Ran> {
  const verb = argv[0]
  const dir = verb === 'publish' || verb === 'audit' ? [] : ['--dir', p.dir]
  const priv = verb === 'send' || verb === 'inbox' || verb === 'group' ? [P] : []
  return cli(p.io, ...argv, ...dir, ...priv)
}

type Kind = 'command' | 'carry' | 'compare' | 'confirm'

/** The hand acts of one recovery, in the order they were made. */
class Ledger {
  readonly acts: [Kind, string][] = []

  add(kind: Kind, what: string): void {
    this.acts.push([kind, what])
  }

  carry<T>(what: string, value: T): T {
    this.add('carry', what)
    return value
  }

  /** A counted command; it must exit 0 with nothing on stderr. */
  async act(p: Party, what: string, ...argv: string[]): Promise<Ran> {
    this.add('command', what)
    const ran = await go(p, ...argv)
    expect([what, ran.code, quiet(ran.err)]).toEqual([what, 0, []])
    return ran
  }

  count(kind: Kind): number {
    return this.acts.filter(([k]) => k === kind).length
  }
}

/** A step's stderr but keygen's one line (a keygen identity has no recovery copy, said, not an error). */
const quiet = (err: readonly string[]): string[] => err.filter((l) => l !== NO_RECOVERY)

/** A command that is part of the setup, or of a control: run, and required to succeed. */
async function step(p: Party, hand: Ledger | undefined, what: string, ...argv: string[]): Promise<Ran> {
  if (hand !== undefined) return hand.act(p, what, ...argv)
  const ran = await go(p, ...argv)
  expect([what, ran.code, quiet(ran.err)]).toEqual([what, 0, []])
  return ran
}

/** The parties of one run on one in-process relay, their clocks kept together. */
class Rig {
  readonly net = new Network()
  readonly all: Party[] = []
  now = T0

  async party(name: string, hand?: Ledger): Promise<Party> {
    const io = testIo(this.net)
    io.tty = true
    io.time.now = this.now
    const p: Party = { io, dir: join(tmp.dir, `${name}-${n++}`), name, address: '' }
    p.address = (await step(p, hand, 'keygen', 'keygen', name)).out[0] as string
    this.all.push(p)
    return p
  }

  /** Moves every party's clock on: a relay refuses a record not newer than the one it holds. */
  tick(seconds = 10): void {
    this.now += seconds
    for (const p of this.all) p.io.time.now = this.now
  }
}

const publishAddress = async (p: Party, hand?: Ledger): Promise<void> => {
  const file = join(p.dir, `${p.name}.address.json`)
  await step(
    p,
    hand,
    'record address',
    'record',
    'address',
    p.name,
    '--relay',
    R,
    '--sealing-key',
    '--out',
    file,
  )
  await step(p, hand, 'publish', 'publish', R, file)
}

const publishAccept = async (p: Party, roots: readonly string[], hand?: Ledger): Promise<void> => {
  const file = join(p.dir, `${p.name}.accept-from.json`)
  const root = roots.flatMap((r) => ['--root', r])
  const size = ['--max-bytes', '65536', '--ttl', '604800']
  await step(p, hand, 'record accept-from', 'record', 'accept-from', p.name, ...root, ...size, '--out', file)
  await step(p, hand, 'publish', 'publish', R, file)
}

/** The invite string the inviter printed at or after stdout line `from` (an inviter pairs twice). */
async function printed(p: Party, from: number): Promise<string> {
  const end = Date.now() + 5000
  const line = (): string | undefined => p.io.stdout.slice(from).find((l) => l.startsWith('invite '))
  while (line() === undefined) {
    if (Date.now() > end) throw new Error('timed out waiting for the invite')
    await new Promise((r) => setTimeout(r, 5))
  }
  return (line() as string).slice('invite '.length)
}

/**
 * One pairing: `inviter` invites and calls the acceptor `as`, `acceptor` accepts and calls the inviter
 * `called`. With a ledger, the acts of L4's sequence are recorded: the two commands, the string
 * carried, the six digits compared, and one confirmation per prompt the commands asked.
 * Note of 2026-10-30: the inviter asks no y, and its typed digits are counted in that y's place.
 */
async function pair(
  inviter: Party,
  as: string,
  acceptor: Party,
  called: string,
  hand?: Ledger,
): Promise<void> {
  acceptor.io.answers.push(true)
  // The inviter's person types what the acceptor's person reads out: its screen never shows the digits.
  const { readLine } = inviter.io
  const shown = (): string | undefined =>
    acceptor.io.stdout.findLast((l) => l.startsWith('check digits '))?.slice('check digits '.length)
  inviter.io.readLine = async () => shown() ?? null
  const asked = (): number => inviter.io.asked.length + acceptor.io.asked.length
  const start = asked()
  hand?.add('command', 'peer invite')
  hand?.add('command', 'peer accept')
  const mark = inviter.io.stdout.length
  const inviting = go(inviter, 'peer', 'invite', '--as', inviter.name, '--relay', R, '--name', as)
  const text =
    hand === undefined
      ? await printed(inviter, mark)
      : hand.carry('the invite string', await printed(inviter, mark))
  const accepting = go(
    acceptor,
    'peer',
    'accept',
    '--as',
    acceptor.name,
    '--relay',
    R,
    '--name',
    called,
    text,
  )
  const [a, b] = await Promise.all([inviting, accepting])
  inviter.io.readLine = readLine
  expect([a.code, a.err, b.code, b.err]).toEqual([0, [], 0, []])
  expect(shown()).toMatch(/^\d{3} \d{3}$/)
  expect(a.out.join('\n')).not.toContain(shown())
  hand?.add('compare', 'the six digits read out')
  for (let i = start; i < asked(); i++) hand?.add('confirm', 'y')
  hand?.add('confirm', 'the six digits typed')
}

/** The ids of the chat messages a run printed as accepted, sorted (accepted group keys print too). */
const chatIds = (lines: readonly string[]): string[] =>
  lines
    .filter((l) => l.startsWith('accept ') && l.includes(' chat.v1 '))
    .map((l) => l.split(' ')[1] as string)
    .sort()

const auditLogs = (home: string): string[] => {
  const state = join(home, 'state')
  if (!existsSync(state)) return []
  return readdirSync(state)
    .flatMap((name) => ['audit.jsonl', 'cli-audit.jsonl'].map((f) => join(state, name, f)))
    .filter((f) => existsSync(f))
}

/** An audit log's events as `<event> <decision>`, as the file holds them now. */
const eventsOf = (file: string): string[] =>
  readFileSync(file, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as { event: string; decision: string })
    .map((l) => `${l.event} ${l.decision}`)

const groupDir = (home: string, name: string, group: string): string =>
  join(home, 'groups', name, toHex(decodeAddress(group)))

/** The hand acts the sequence takes for k former peers and g groups (L4). */
const formula = (k: number, g: 0 | 1, names: 'old' | 'new'): number => {
  const perPeer = names === 'old' ? 8 : 7
  if (g === 0) return 2 + perPeer * k
  return k === 0 ? 3 + 7 * g : 1 + perPeer * k + 7 * g
}

/** What the setup before the loss leaves: the lost `dev`, its former peers, and the group's admin. */
interface Before {
  readonly rig: Rig
  readonly dev: Party
  readonly peers: Party[]
  readonly admin: Party | null
}

/**
 * Before the loss, uncounted: `dev` is paired with each of k peers (it calls them peer1.., they call it
 * `dev`); with a group, `team` (admin and group in one home) has `dev` and the first peer as members, each
 * member's accept-from record admitting the group.
 */
async function before(k: number, g: 0 | 1): Promise<Before> {
  const rig = new Rig()
  const dev = await rig.party('dev')
  const peers: Party[] = []
  for (let i = 1; i <= k; i++) peers.push(await rig.party(`peer${i}`))
  const admin = g === 1 ? await rig.party('team') : null
  const cold = g === 1 ? await rig.party('cold') : null
  await publishAddress(dev)
  if (admin !== null) await publishAccept(dev, [admin.address])
  const first = peers[0]
  if (admin !== null && first !== undefined) {
    await publishAddress(first)
    await publishAccept(first, [admin.address])
  }
  for (const p of peers) {
    rig.tick()
    await pair(dev, p.name, p, 'dev')
  }
  if (admin !== null && cold !== null) {
    await step(
      admin,
      undefined,
      'group create',
      'group',
      'create',
      'team',
      '--relay',
      R,
      '--rotation-key',
      cold.address,
    )
    await step(admin, undefined, 'group add', 'group', 'add', 'team', dev.address)
    if (first !== undefined) await step(admin, undefined, 'group add', 'group', 'add', 'team', first.address)
  }
  return { rig, dev, peers, admin }
}

interface Recovered {
  readonly hand: Ledger
  readonly dev2: Party
  readonly read: Ran
  readonly ids: string[]
  readonly post: string | null
  readonly heldByDev2: string[]
  readonly auditBefore: { readonly dev2: string[]; readonly peers: string[][] }
  /** Each of those logs' events when it was listed, before the party's first send or inbox. */
  readonly auditEvents: ReadonlyMap<string, string[]>
}

/**
 * From "device lost" to "dev2 receives one message from each former peer", in the documented order. After the
 * loss no step uses dev's keys (V3): dev appears only as an address, in the admin's `group remove`.
 * `controls` adds one refusal that shows a named step is needed (the `name forget`); it is not an act of
 * the sequence.
 */
async function recover(b: Before, names: 'old' | 'new', controls = false): Promise<Recovered> {
  const { rig, dev, peers, admin } = b
  const hand = new Ledger()
  const called = names === 'old' ? 'dev' : 'dev-new'
  rig.tick()
  const dev2 = await rig.party('dev2', hand)
  const team = admin === null ? null : hand.carry('the group address to dev2', admin.address)
  // k = 0: pairing is what publishes dev2's address record, which `group add` resolves; with no peer it is
  // two steps.
  if (peers.length === 0 && admin !== null) await publishAddress(dev2, hand)
  const auditBeforePeers: string[][] = []
  const auditEvents = new Map<string, string[]>()
  const listed = (dir: string): string[] => {
    const files = auditLogs(dir)
    for (const f of files) auditEvents.set(f, eventsOf(f))
    return files
  }
  for (const peer of peers) {
    rig.tick()
    if (names === 'old') {
      if (controls && peer === peers[0]) {
        // The name is pinned to dev's old address: without `name forget` the acceptor refuses before sending
        // anything.
        const decoy = invited({ inviter: dev2.address, i: dev.address, relay: R, secret: '00'.repeat(16) })
        const refused = await go(
          peer,
          'peer',
          'accept',
          '--as',
          peer.name,
          '--relay',
          R,
          '--name',
          'dev',
          decoy,
        )
        expect([refused.code, refused.err[0]]).toEqual([1, expect.stringMatching(/^bag: name-exists: /)])
      }
      await hand.act(peer, 'name forget', 'name', 'forget', 'dev')
    }
    await pair(dev2, peer.name, peer, called, hand)
  }
  if (admin !== null && team !== null) {
    rig.tick()
    // The member's accept-from, re-signed with the group's root and the peers pairing added, then published,
    // before the add.
    await publishAccept(dev2, [team, ...peers.map((p) => p.address)], hand)
    const mine = hand.carry("dev2's address to the admin", dev2.address)
    await hand.act(admin, 'group add', 'group', 'add', 'team', mine)
    await hand.act(admin, 'group remove', 'group', 'remove', 'team', dev.address)
  }
  const ids: string[] = []
  for (const peer of peers) {
    auditBeforePeers.push(listed(peer.dir))
    const body = JSON.stringify({ from: peer.name })
    const argv = [
      'send',
      '--as',
      peer.name,
      '--to',
      called,
      '--relay',
      R,
      '--type',
      'chat.v1',
      '--body',
      body,
    ]
    ids.push((await hand.act(peer, 'send', ...argv)).out[0] as string)
  }
  // Not an act of the sequence: the admin posts to its own group, to see that dev2 reads the group's mail.
  let post: string | null = null
  if (admin !== null && team !== null) {
    const body = '{"n":1}'
    const sent = await step(
      admin,
      undefined,
      'send',
      'send',
      '--as',
      'team',
      '--to',
      team,
      '--relay',
      R,
      '--type',
      'chat.v1',
      '--body',
      body,
    )
    post = sent.out[0] as string
  }
  const auditBefore = { dev2: listed(dev2.dir), peers: auditBeforePeers }
  const group = team === null ? [] : ['--group', team]
  const what = team === null ? 'inbox --once' : 'inbox --group'
  const read = await hand.act(dev2, what, 'inbox', '--as', 'dev2', '--relay', R, ...group, '--once')
  const held =
    team === null ? [] : readdirSync(groupDir(dev2.dir, 'dev2', team)).filter((f) => /^g\d+\.json$/.test(f))
  return { hand, dev2, read, ids, post, heldByDev2: held.sort(), auditBefore, auditEvents }
}

const breakdown = (h: Ledger): string => {
  const [c, y, m, f] = [h.count('command'), h.count('carry'), h.count('compare'), h.count('confirm')]
  return `${c} commands, ${y} carried, ${m} compared, ${f} confirmed`
}

describe('L4 and L6: the lost device, the hand acts of the recovery', () => {
  // The k = 2, g = 1 run, built once and shared by the first test and L6: L6 does not depend on test order.
  let shared: Promise<{ b: Before; r: Recovered }> | undefined
  const main = (): Promise<{ b: Before; r: Recovered }> => {
    shared ??= (async () => {
      const b = await before(2, 1)
      return { b, r: await recover(b, 'old', true) }
    })()
    return shared
  }

  it('L4: k = 2 peers and g = 1 group: 24 acts, 2 messages and the group read by dev2', async () => {
    const { b, r } = await main()
    const lines = r.read.out
    // L4: the sequence completed for k = 2, g = 1: each peer's message and the group's post are accepted, no
    // refusal.
    expect(chatIds(lines)).toEqual([...r.ids, r.post as string].sort())
    expect(lines.filter((l) => l.startsWith('reject '))).toEqual([])
    // L4: dev2 holds generation 1 (the add) and 2 (the remove) of the group.
    expect(r.heldByDev2).toEqual(['g1.json', 'g2.json'])
    // L4: every act counted: 1 + 8k + 7g = 24, range 24 to 26 (a refused step repeated).
    expect(r.hand.acts.length).toBe(formula(2, 1, 'old'))
    expect(r.hand.acts.length).toBe(24)
    // L4: the parts of the count (per peer: name forget, invite, carried, accept, compared, y, y, send = 8).
    // Note of 2026-10-30: the compare is now the acceptor's read-out, and
    // the inviter's y is the digits typed, one act for one, so the count stands.
    expect([
      r.hand.count('command'),
      r.hand.count('carry'),
      r.hand.count('compare'),
      r.hand.count('confirm'),
    ]).toEqual([14, 4, 2, 4])
    const accepted = `${chatIds(lines).length} of ${r.ids.length + 1} (2 peers, 1 group post)`
    console.log(
      [
        `MEASURE L4: k=2 g=1 ${r.hand.acts.length} hand acts (${breakdown(r.hand)});`,
        `formula 1 + 8k + 7g = 24, range 24 to 26; dev2 accepted ${accepted}, 0 refused,`,
        `generations held ${r.heldByDev2.join(',')}`,
      ].join(' '),
    )
    // The groups seam: dev2, under forward secrecy since its pairing, keeps each generation it accepted at rest
    // under keys/ (outside L6's scan), and after its epoch keys are deleted past their horizon it still reads the
    // group's mail with them. Not an act: a control after the count.
    const admin = b.admin as Party
    const kept = join(r.dev2.dir, 'keys', 'groups', 'dev2', toHex(decodeAddress(admin.address)))
    expect(readdirSync(kept).sort()).toEqual(['g1.key', 'g2.key'])
    const epochs = new KeyEpochStore(join(r.dev2.dir, 'key-records'))
    expect(epochs.epochs(r.dev2.address).length).toBeGreaterThan(0)
    epochs.prune(r.dev2.address, r.dev2.io.time.now + 30 * 86_400, 0, 0)
    expect(epochs.epochs(r.dev2.address)).toEqual([])
    const posted = await step(
      admin,
      undefined,
      'send',
      ...[
        'send',
        '--as',
        'team',
        '--to',
        admin.address,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        '{"n":9}',
      ],
    )
    const after = await step(
      r.dev2,
      undefined,
      'inbox --group',
      ...['inbox', '--as', 'dev2', '--relay', R, '--group', admin.address, '--once'],
    )
    expect(chatIds(after.out)).toContain(posted.out[0])
    console.log('MEASURE groups seam: dev2 read the group after its epoch keys were deleted')
  }, 60_000)

  it('L4: a new --name for the identity needs no name forget: 7 per peer, 22 for k = 2, g = 1', async () => {
    const b = await before(2, 1)
    const r = await recover(b, 'new')
    // L4: "(7; 6 with a new --name, no name forget)": the peer count drops by one act each.
    expect(r.hand.acts.length).toBe(formula(2, 1, 'new'))
    expect(r.hand.acts.length).toBe(22)
    expect(chatIds(r.read.out)).toEqual([...r.ids, r.post as string].sort())
    console.log(
      [
        `MEASURE L4: k=2 g=1 new names ${r.hand.acts.length} hand acts (${breakdown(r.hand)});`,
        'formula 1 + 7k + 7g = 22',
      ].join(' '),
    )
  }, 60_000)

  it('L4: k = 1 peer, no group: 2 + 8k = 10 acts, the live arm (L4-live) count', async () => {
    const b = await before(1, 0)
    const r = await recover(b, 'old')
    // L4-live: "10 hand acts by the sequence (2 + 8k, k = 1, g = 0), range 10 to 12".
    expect(r.hand.acts.length).toBe(formula(1, 0, 'old'))
    expect(r.hand.acts.length).toBe(10)
    expect(chatIds(r.read.out)).toEqual(r.ids)
    console.log(
      `MEASURE L4: k=1 g=0 ${r.hand.acts.length} hand acts (${breakdown(r.hand)}); formula 2 + 8k = 10`,
    )
  }, 60_000)

  it('L4: k = 0, g = 1: no pairing published the address record, so 3 + 7g = 10', async () => {
    const b = await before(0, 1)
    const r = await recover(b, 'old')
    // L4: "at k = 0 the sequence adds `record address` and `publish` and is 3 + 7g, outside this line".
    expect(r.hand.acts.length).toBe(formula(0, 1, 'old'))
    expect(r.hand.acts.length).toBe(10)
    expect(chatIds(r.read.out)).toEqual([r.post as string])
    console.log(
      `MEASURE L4: k=0 g=1 ${r.hand.acts.length} hand acts (${breakdown(r.hand)}); formula 3 + 7g = 10`,
    )
  }, 60_000)

  it('L4: an add before the member admits the group is refused root-not-accepted', async () => {
    // L4: "(before the add, else the admin's `group add` is refused `root-not-accepted` at the member's
    // relay)": the member's accept-from names someone else, as pairing leaves it, and the admin's add is
    // refused.
    const rig = new Rig()
    const [admin, cold, dev2, other] = [
      await rig.party('team'),
      await rig.party('cold'),
      await rig.party('dev2'),
      await rig.party('other'),
    ]
    await step(
      admin,
      undefined,
      'group create',
      'group',
      'create',
      'team',
      '--relay',
      R,
      '--rotation-key',
      cold.address,
    )
    await publishAddress(dev2)
    await publishAccept(dev2, [other.address])
    const refused = await go(admin, 'group', 'add', 'team', dev2.address)
    expect([refused.code, refused.err[0]]).toEqual([1, expect.stringMatching(/^bag: root-not-accepted: /)])
    console.log(
      [
        'MEASURE L4: group add before the member admits the group: refused root-not-accepted (exit 1),',
        'so the re-signed accept-from and its publish come first',
      ].join(' '),
    )
  }, 60_000)

  it('L6: every audit log verifies, four kinds of step leave none and peer only its rotate line, no key material', async () => {
    const { b, r } = await main()
    const admin = b.admin as Party
    // L6: the four kinds of step keygen, record, publish and name write no audit line; `peer` writes only the
    // `rotate` line of the epoch it published. dev2 ran keygen, record, publish and peer, and each peer ran
    // peer and name, so each holds one log, of that one line, until its first send or inbox.
    const rotation = (p: Party): string => join(p.dir, 'state', p.name, 'cli-audit.jsonl')
    expect(r.auditBefore.dev2).toEqual([rotation(r.dev2)])
    expect(r.auditBefore.peers).toEqual(b.peers.map((p) => [rotation(p)]))
    for (const file of [...r.auditBefore.dev2, ...r.auditBefore.peers.flat()]) {
      expect(r.auditEvents.get(file), file).toEqual(['rotate accept'])
    }
    // L6: every log a recovery step touched prints `ok <n> lines` under `audit verify`.
    const logs = b.rig.all.flatMap((p) => auditLogs(p.dir).map((f) => [p, f] as const))
    expect(logs.length).toBeGreaterThanOrEqual(4)
    let lines = 0
    for (const [p, f] of logs) {
      const verified = await cli(p.io, 'audit', 'verify', f)
      expect([verified.code, verified.out[0]]).toEqual([0, expect.stringMatching(/^ok \d+ lines$/)])
      lines += Number(/^ok (\d+) lines$/.exec(verified.out[0] as string)?.[1])
    }
    // L6: the admin's log holds one `rotate accept` line per group step, naming the action, generation and
    // member.
    const steps = readFileSync(join(admin.dir, 'state', 'team', 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { event: string; decision: string; detail?: string })
      .filter((l) => l.event === 'rotate' && l.decision === 'accept')
      .map((l) => JSON.parse(l.detail as string) as { action: string; generation: number; member: string })
    expect(steps.map((s) => [s.action, s.generation, s.member])).toEqual([
      ['add', 1, b.dev.address],
      ['add', 1, (b.peers[0] as Party).address],
      ['add', 1, r.dev2.address],
      ['remove', 2, b.dev.address],
    ])
    // L6: no seed and no generation key, in any form, in any output line or file (the key files hold them by
    // design).
    const seeds: Buffer[] = []
    for (const p of b.rig.all) {
      const keys = loadKeys(p.io, p.dir, p.name)
      seeds.push(Buffer.from(keys.signing.exportSeed()), Buffer.from(keys.sealing.exportSeed()))
    }
    const keys = loadKeys(admin.io, admin.dir, 'team')
    const store = new GroupKeyStore(join(admin.dir, 'groups', 'team'))
    for (const g of [1, 2]) {
      const opened = openGroupKey(
        store.body(admin.address, g),
        { address: admin.address, key: keys.sealing },
        b.rig.now,
      )
      seeds.push(Buffer.from(opened.key.exportSeed()))
    }
    const forms = (seed: Buffer): Buffer[] =>
      [seed.toString('hex'), seed.toString('base64'), seed.toString('base64url')].map((t) => Buffer.from(t))
    const hits = (bytes: Buffer): number =>
      seeds.flatMap((s) => [s, ...forms(s)]).filter((needle) => bytes.includes(needle)).length
    const files = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.name === 'keys' ? [] : e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)],
      )
    const scanned = b.rig.all.flatMap((p) => files(p.dir))
    const output = Buffer.from(b.rig.all.flatMap((p) => [...p.io.stdout, ...p.io.stderr]).join('\n'))
    const found = hits(output) + scanned.reduce((total, f) => total + hits(readFileSync(f)), 0)
    expect(found).toBe(0)
    // L6: the control, a planted seed, is found once.
    const control = join(tmp.dir, 'control.txt')
    writeFileSync(control, `x ${(seeds[0] as Buffer).toString('hex')} y`)
    expect(hits(readFileSync(control))).toBe(1)
    const outputLines = b.rig.all.reduce((t, p) => t + p.io.stdout.length + p.io.stderr.length, 0)
    console.log(
      [
        `MEASURE L6: ${logs.length} audit logs ok (${lines} lines);`,
        `the admin's steps ${steps.map((s) => s.action).join(', ')};`,
        'one log, a rotate line, before the first send or inbox for dev2 and 2 peers (keygen, record, publish, name',
        `write none; peer writes the epoch's); 0 of ${seeds.length} seeds in ${outputLines} output lines and ${scanned.length} files;`,
        'control 1',
      ].join(' '),
    )
  }, 60_000)
})
