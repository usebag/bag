import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import {
  type AddressRecord,
  buildEnvelope,
  countersignRotation,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  decodeAddress,
  fromHex,
  HOP_TAG,
  type Hop,
  type KeyRecord,
  newThread,
  openGroupKey,
  openSealed,
  parseEnvelope,
  parseRecord,
  serializeRecord,
  signFetchAuth,
  toHex,
  verifyChain,
  verifyRotation,
} from '@usebag/core'
import {
  createHttpRelay,
  FsKeyStore,
  GroupKeyStore,
  newSeeds,
  parseAuditLine,
  RelayError,
  readAuditLines,
  readSheet,
  SHEET_LINES,
  SqliteStore,
  seedKeys,
  sheetLines,
  verifyAuditLog,
} from '@usebag/edge'
import { AgentClient } from '@usebag/edge/agent'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  CLI_MAIN,
  type CliRun,
  cliProcess,
  extraRelay,
  homeSecrets,
  nodeAt,
  now,
  party,
  REPO,
  rawPublish,
  relayEvents,
  sleep,
  startRelay,
  until,
  untilSecond,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'
import { exited, lineOf, type Terminal, terminal } from '../terminal.ts'

// e2e scenario 46 ("the lost device"). The cases are 46a to 46j, and L1 to L8 label the lines they check. These
// are the end-to-end fixtures of those lines, on the release relay, through the CLI in child
// processes where a person would type a command and through the edge library where a line needs a key or a
// clock the CLI does not give:
//
//   46a  L1   identity continuity by a countersigned rotation: (a), (c) and (d). (b) is scenario 14, as is.
//   46b  L2   group history on a re-add, in both orders, and the lost member's hop refused `revoked`.
//   46c  L3   undelivered mail within the retention, on a relay with a short ttl and a 1 s sweep.
//   46d  L4   the group arm of the recovery on a real relay (k = 0, g = 1), its hand acts counted. The
//             pairing arm needs a terminal on stdin (`peer` refuses `no-tty` otherwise), so it is counted
//             in-process in packages/cli/test/lost-device.test.ts, where L4's count is.
//   46e  L5x  the stand-in on today's commands, three tests. They are PREDICTIONS TO BE FALSIFIED, reported
//             beside the lines with no rule: a red is a falsified prediction, not a defect.
//   46f  L6   the audit trail of the CLI's steps and the planted controls of the secret count.
//
//   46g, 46h  the device grant and groups in the agent (described where they are).
//   46i  L7   restore in place from the sheet, 46j  L8  the two refusals.
//
// Every case ends with L6's secret count: any seed or generation key, in the forms hex, upper hex, base64,
// base64url and raw, in any file of the scenario's directory outside the key files, in any output, argument
// or environment. L3-live and L4-live are sittings of a person at a real device; L5 (built) is not built, so no
// test exists for it. L7 and L8 are 46i and 46j. After the loss no step uses dev's keys, except the
// controls each case names.

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

/** One CLI process that must exit 0 with nothing on stderr. */
async function ok(...args: string[]): Promise<CliRun> {
  const ran = await cli(...args)
  const what = args.slice(0, 3).join(' ')
  expect([what, ran.code, ran.err]).toEqual([what, 0, []])
  return ran
}

/** Makes identities in a home; their addresses, in order. */
async function keygen(home: string, ...names: string[]): Promise<string[]> {
  const made = await Promise.all(names.map((name) => ok('keygen', name, '--dir', home)))
  return made.map((m) => m.out[0] as string)
}
const one = async (home: string, name: string): Promise<string> => (await keygen(home, name))[0] as string

/** `name`'s address record (with its sealing key) and its accept-from record for `roots`, at `relay`. */
async function onboard(
  home: string,
  name: string,
  relay: string,
  roots: readonly string[],
  ...more: string[]
): Promise<void> {
  const address = join(home, `${name}.address.json`)
  const accept = join(home, `${name}.accept-from.json`)
  const dir = ['--dir', home]
  await ok('record', 'address', name, '--relay', relay, '--sealing-key', ...more, '--out', address, ...dir)
  await ok('publish', relay, address)
  const root = roots.flatMap((r) => ['--root', r])
  await ok(
    'record',
    'accept-from',
    name,
    ...root,
    '--max-bytes',
    '65536',
    '--ttl',
    '604800',
    '--out',
    accept,
    ...dir,
  )
  await ok('publish', relay, accept)
}

const chatIds = (lines: readonly string[]): string[] =>
  lines
    .filter((l) => l.startsWith('accept ') && l.includes(' chat.v1 '))
    .map((l) => l.split(' ')[1] as string)
    .sort()

const groupDir = (home: string, name: string, group: string): string =>
  join(home, 'groups', name, toHex(decodeAddress(group)))

const auditLogs = (home: string): string[] => {
  const state = join(home, 'state')
  if (!existsSync(state)) return []
  return readdirSync(state)
    .map((name) => join(state, name, 'audit.jsonl'))
    .filter((f) => existsSync(f))
    .sort()
}

/** L6: every audit log of these homes prints `ok <n> lines`; the number of logs and of lines. */
async function verifyLogs(homes: readonly string[]): Promise<[number, number]> {
  let logs = 0
  let lines = 0
  for (const home of homes) {
    for (const log of auditLogs(home)) {
      const verified = await ok('audit', 'verify', log)
      expect(verified.out[0]).toMatch(/^ok \d+ lines$/)
      logs++
      lines += Number(/^ok (\d+) lines$/.exec(verified.out[0] as string)?.[1])
    }
  }
  return [logs, lines]
}

/** The "event decision reason" of each line of a CLI audit log for an envelope id. */
/** The error code of a refused CLI run: its first stderr line, `bag: <code>: ...`. */
const why = (r: CliRun): string | undefined => r.err[0]?.split(':')[1]?.trim()

const stepsOf = (log: string, id: string): string[] =>
  readAuditLines(log)
    .map(parseAuditLine)
    .filter((l) => l.id === id)
    .map((l) => `${l.event} ${l.decision} ${l.reason}`)

// --- L6: no secret in any form, anywhere
// ---------------------------------------------------------------------------

const forms = (hex: string): Buffer[] => {
  const raw = Buffer.from(hex, 'hex')
  const text = [hex, hex.toUpperCase(), raw.toString('base64'), raw.toString('base64url')]
  return [raw, ...text.map((t) => Buffer.from(t))]
}

/** Every regular file under a directory, the key files (a `keys` directory) left out: seeds by design. */
function filesUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return e.name === 'keys' ? [] : filesUnder(join(dir, e.name))
    return e.isFile() ? [join(dir, e.name)] : []
  })
}

/** How many times any form of any secret occurs in the byte strings: a count, never the secret. */
function occurrences(haystacks: readonly Buffer[], secrets: readonly string[]): number {
  let total = 0
  for (const bytes of haystacks) {
    for (const needle of secrets.flatMap(forms)) {
      for (let i = bytes.indexOf(needle); i >= 0; i = bytes.indexOf(needle, i + 1)) total++
    }
  }
  return total
}

/** [occurrences in the scenario's files, occurrences in the CLI output, argv and environment]. */
function leaks(w: World, secrets: readonly string[]): [number, number] {
  const files = filesUnder(w.dir).map((f) => readFileSync(f))
  const ambient = [outputs.join('\n'), process.argv.join(' '), Object.values(process.env).join('\n')]
  return [
    occurrences(files, secrets),
    occurrences(
      ambient.map((t) => Buffer.from(t)),
      secrets,
    ),
  ]
}

/** The seeds of a group's generations 1..count, from the admin's own copies in its home. */
function generationSeeds(home: string, name: string, group: string, count: number): string[] {
  const keys = new FsKeyStore(join(home, 'keys')).load(name)
  const store = new GroupKeyStore(join(home, 'groups', name))
  return Array.from({ length: count }, (_, i) => {
    const body = store.body(group, i + 1)
    return toHex(openGroupKey(body, { address: group, key: keys.sealing }, now()).key.exportSeed())
  })
}

/** L6's count for a case, asserted 0 and 0 and printed. */
function noSecrets(label: string, w: World, secrets: readonly string[]): void {
  const [inFiles, inOutput] = leaks(w, secrets)
  expect([inFiles, inOutput]).toEqual([0, 0])
  const files = filesUnder(w.dir).length
  const scanned = `${secrets.length} secrets, ${files} files, ${outputs.length} CLI outputs`
  console.log(
    `MEASURE L6 ${label}: ${scanned}; occurrences ${inFiles} in files and ${inOutput} in output, argv, env`,
  )
}

/**
 * Lapses the key record of `address` that an edge's store caches (when it holds one), as 300 s passing would: the
 * resolver caches a key record at most that long (the forward-secrecy ruling), and a CLI child runs on the system
 * clock, which a test cannot move.
 */
function lapseKeyCache(file: string, address: string): void {
  if (!existsSync(file)) return
  const store = new SqliteStore(file)
  try {
    const subject = `address:${address}`
    const bytes = store.cacheGet(subject, 'key', 0)
    if (bytes !== null) store.cachePut(subject, 'key', bytes, 0)
  } finally {
    store.close()
  }
}

/** 46i's measured hand acts and groups, and the messages to dev it read, for the registered lines' own cases. */
let measured43g: { acts: number; groups: number; read: number; sent: number } | null = null
describe('e2e scenario 46: the lost device', () => {
  // L1: (a) and (c) with the key surviving, (d) with it gone. (b) is scenario 14.
  it('(46a, L1) rotation: countersigned 200, bare and third-key 422, rotation key, no follow', async () => {
    outputs.length = 0
    const w = await world('s46a')
    const second = await extraRelay(w, 'relay-2', [])
    const [R1, R2] = [w.url, second.url]
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const names = ['dev', 'dev2', 'dev3', 'solo', 'solo2', 'bob', 'bob2']
    const addresses = await keygen(home, ...names)
    const [dev, dev2, bob, bob2] = [0, 1, 5, 6].map((n) => addresses[n] as string) as [
      string,
      string,
      string,
      string,
    ]
    const k = party('rotation-key')
    const third = party('third-key')

    // dev's record names k as its rotation key (at onboarding) and is held at R1 only; solo's names none, at
    // R1.
    const devFile = join(home, 'dev.address.json')
    const rotationKey = ['--rotation-key', k.address]
    await ok(
      'record',
      'address',
      'dev',
      '--relay',
      R1,
      '--sealing-key',
      ...rotationKey,
      '--out',
      devFile,
      ...dir,
    )
    await ok('publish', R1, devFile)
    const soloFile = join(home, 'solo.address.json')
    await ok('record', 'address', 'solo', '--relay', R1, '--sealing-key', '--out', soloFile, ...dir)
    await ok('publish', R1, soloFile)
    const devRecord = parseRecord(readFileSync(devFile)) as AddressRecord
    const soloRecord = parseRecord(readFileSync(soloFile)) as AddressRecord

    /** `record address <to> --rotated-from <from>` as the CLI writes it: countersigned by `from`'s key. */
    const rotation = async (to: string, from: string): Promise<{ file: string; record: AddressRecord }> => {
      const file = join(home, `${to}.rotation.json`)
      const relays = ['--relay', R1, '--relay', R2]
      await ok(
        'record',
        'address',
        to,
        ...relays,
        '--sealing-key',
        '--rotated-from',
        from,
        '--out',
        file,
        ...dir,
      )
      return { file, record: parseRecord(readFileSync(file)) as AddressRecord }
    }
    const outcome = async (url: string, r: AddressRecord): Promise<[number, string | undefined]> => {
      const published = await rawPublish(url, serializeRecord(r))
      return [published.status, (published.body as { error?: string }).error]
    }

    // L1 (a), key survives: dev2's record rotated from dev. Bare (rotation_sig null) and countersigned by a
    // third key: 422 bad-rotation at both relays (four refusals); countersigned by dev: 200 at R1, which
    // holds dev's record, and at R2, which does not.
    const made = await rotation('dev2', 'dev')
    expect([made.record.rotated_from, made.record.rotation_sig === null]).toEqual([dev, false])
    const bare: AddressRecord = { ...made.record, rotation_sig: null }
    const byThird = countersignRotation(third.signing, made.record)
    const refusals = [
      await outcome(R1, bare),
      await outcome(R2, bare),
      await outcome(R1, byThird),
      await outcome(R2, byThird),
    ]
    expect(refusals).toEqual(Array(4).fill([422, 'bad-rotation']))
    expect((await ok('publish', R1, made.file)).out).toEqual([`ok address ${dev2}`])
    expect((await ok('publish', R2, made.file)).out).toEqual([`ok address ${dev2}`])

    // L1 (d), key gone: dev3's rotation countersigned by k (the core's countersignRotation: the CLI names a
    // rotation key but cannot countersign with one). It passes the core's verifyRotation against dev's
    // record and is 200 at R1, which holds that record, and 422 bad-rotation at R2, which does not (SPEC
    // §7.3).
    const viaKey = await rotation('dev3', 'dev')
    const byK = countersignRotation(k.signing, viaKey.record)
    expect(devRecord.rotation_key).toBe(k.address)
    expect(() => verifyRotation(devRecord, byK)).not.toThrow()
    const keyed = [await outcome(R1, byK), await outcome(R2, byK)]
    expect(keyed).toEqual([
      [200, undefined],
      [422, 'bad-rotation'],
    ])
    // L1 (d), no rotation_key: no countersigner and no continuity. k's countersignature of solo's rotation
    // fails the core's verifyRotation and the relay that holds solo's record.
    const viaSolo = await rotation('solo2', 'solo')
    const soloByK = countersignRotation(k.signing, viaSolo.record)
    expect(soloRecord.rotation_key).toBeNull()
    expect(() => verifyRotation(soloRecord, soloByK)).toThrow(/bad-rotation/)
    const none = await outcome(R1, soloByK)
    expect(none).toEqual([422, 'bad-rotation'])

    // L1 (c), measured, the not-built half: bob trusts dev by address (his accept-from names dev). After (a),
    // dev2 sends to bob: the relay answers 403 root-not-accepted, and bob's inbox accepts 0 of 1. With bob2,
    // whose accept-from is ["*"], the relay takes the message and bob2's edge refuses untrusted-root: 0 of 1
    // accepted; the control, dev itself to bob2, is accepted.
    await onboard(home, 'bob', R1, [dev])
    await onboard(home, 'bob2', R1, ['*'])
    const send = (as: string, to: string, n: number): Promise<CliRun> =>
      cli('send', '--as', as, '--to', to, '--relay', R1, '--type', 'chat.v1', '--body', `{"n":${n}}`, ...dir)
    const toBob = await send('dev2', bob, 1)
    expect([toBob.code, toBob.err[0]]).toEqual([1, expect.stringMatching(/^bag: root-not-accepted: /)])
    const bobSees = await ok('inbox', '--as', 'bob', '--relay', R1, '--once', '--trust-root', dev, ...dir)
    expect(bobSees.out).toEqual([])
    const toBob2 = await send('dev2', bob2, 2)
    expect([toBob2.code, toBob2.err]).toEqual([0, []])
    const fromDev = await send('dev', bob2, 3)
    expect([fromDev.code, fromDev.err]).toEqual([0, []])
    const bob2Sees = await ok('inbox', '--as', 'bob2', '--relay', R1, '--once', '--trust-root', dev, ...dir)
    expect([...bob2Sees.out].sort()).toEqual(
      [
        `reject ${toBob2.out[0]} untrusted-root`,
        `accept ${fromDev.out[0]} ${dev} ${dev} chat.v1 {"n":3}`,
      ].sort(),
    )

    const refused = bob2Sees.out.find((l) => l.startsWith('reject'))?.split(' ')[2]
    console.log(
      [
        `MEASURE L1: (a) countersigned by dev: 200 at R1 (holds dev's record) and 200 at R2 (holds none);`,
        `bare and third-key: ${refusals.map((r) => r.join(' ')).join(', ')};`,
        `(c) dev2 to bob (accept-from [dev]): exit ${toBob.code} ${why(toBob)}, bob accepted`,
        `${bobSees.out.length} of 1; dev2 to bob2 (accept-from *): the relay took it, bob2's edge`,
        `${refused}, 0 of 1 accepted, the control dev to bob2 accepted;`,
        `(d) rotation key k: ${keyed.map((r) => r.join(' ')).join(' / ')} (old record held / not held),`,
        `no rotation_key: ${none.join(' ')}`,
      ].join(' '),
    )
    await verifyLogs([home])
    noSecrets('46a', w, [...homeSecrets(home, names), ...k.secrets, ...third.secrets])
  }, 180_000)

  // L2: add then remove hands dev2 generations 2 and 3, remove then add hands it 3 alone; the lost hop is
  // revoked.
  it('(46b, L2) a re-add hands over the current generation only; dev2 opens nothing earlier', async () => {
    outputs.length = 0
    const w = await world('s46b')
    const R = w.url
    const homes = ['admin', 'bob', 'dev', 'dev2', 'senders'].map((d) => join(w.dir, d))
    const [adm, hb, hd, hd2, hs] = homes as [string, string, string, string, string]
    const [teamA, teamB, cold] = (await keygen(adm, 'team-a', 'team-b', 'cold')) as [string, string, string]
    const [bob, dev, dev2] = await Promise.all([one(hb, 'bob'), one(hd, 'dev'), one(hd2, 'dev2')])
    const senders = await keygen(hs, 's1', 's2', 's3', 's4')
    const trust = senders.flatMap((s) => ['--trust-root', s])
    // The members admit both groups; the groups admit the four senders, one per post (a sender caches the
    // group's record for its ttl, so each sender posts once to each group).
    for (const [home, name] of [
      [hb, 'bob'],
      [hd, 'dev'],
      [hd2, 'dev2'],
    ] as const) {
      await onboard(home, name, R, [teamA, teamB])
    }
    const roots = senders.flatMap((s) => ['--root', s])
    for (const team of ['team-a', 'team-b']) {
      const made = await ok(
        'group',
        'create',
        team,
        '--relay',
        R,
        '--rotation-key',
        cold,
        ...roots,
        '--dir',
        adm,
      )
      expect(made.out[0]).toMatch(/ generation 1$/)
    }
    const admin = (...args: string[]): Promise<CliRun> => ok('group', ...args, '--dir', adm)
    const post = async (sender: number, group: string, n: number): Promise<string> => {
      const as = ['--as', `s${sender}`, '--to', group, '--relay', R]
      const sent = await ok('send', ...as, '--type', 'chat.v1', '--body', `{"n":${n}}`, '--dir', hs)
      return sent.out[0] as string
    }

    /** The shared history, the loss, the re-add in `order`, two posts after, and dev2's read. */
    const lose = async (name: string, group: string, order: 'add-remove' | 'remove-add') => {
      await admin('add', name, bob)
      await admin('add', name, dev)
      const m1 = await post(1, group, 1) // sealed to generation 1 (n-1)
      await admin('rotate', name)
      const m2 = await post(2, group, 2) // sealed to generation 2 (n); dev's device is lost from here
      let m3: string
      let m4: string
      if (order === 'add-remove') {
        await admin('add', name, dev2)
        m3 = await post(3, group, 3)
        await admin('remove', name, dev)
        m4 = await post(4, group, 4)
      } else {
        await admin('remove', name, dev)
        m3 = await post(3, group, 3)
        await admin('add', name, dev2)
        m4 = await post(4, group, 4)
      }
      const inbox = ['inbox', '--as', 'dev2', '--relay', R, '--group', group, '--once']
      const read = await ok(...inbox, ...trust, '--dir', hd2)
      const generations = read.out
        .filter((l) => l.startsWith('group-key '))
        .map((l) => Number(/ generation (\d+) /.exec(l)?.[1]))
        .sort()
      const held = readdirSync(groupDir(hd2, 'dev2', group)).filter((f) => /^g\d+\.json$/.test(f))
      const failed = read.out.filter((l) => l.startsWith('reject ')).sort()
      // The control, the lost member's hop after the remove: refused `revoked` at subscribe.
      const lost = await cli(
        'inbox',
        '--as',
        'dev',
        '--relay',
        R,
        '--group',
        group,
        '--once',
        ...trust,
        '--dir',
        hd,
      )
      return { m: [m1, m2, m3, m4], read, generations, held: held.sort(), failed, lost }
    }

    // (i) add then remove: dev2 is handed generation 2 by the add and 3 by the remove.
    const i = await lose('team-a', teamA, 'add-remove')
    const [i1, i2, i3, i4] = i.m as [string, string, string, string]
    expect(i.generations).toEqual([2, 3])
    expect(i.held).toEqual(['g2.json', 'g3.json'])
    expect(chatIds(i.read.out)).toEqual([i2, i3, i4].sort())
    expect(i.failed).toEqual([`reject ${i1} open-failed`])
    expect([i.lost.code, i.lost.err[0]]).toEqual([1, expect.stringMatching(/^bag: revoked: /)])

    // (ii) remove then add: dev2 is handed generation 3 by the add, the only one it holds.
    const ii = await lose('team-b', teamB, 'remove-add')
    const [j1, j2, j3, j4] = ii.m as [string, string, string, string]
    expect(ii.generations).toEqual([3])
    expect(ii.held).toEqual(['g3.json'])
    expect(chatIds(ii.read.out)).toEqual([j3, j4].sort())
    expect(ii.failed).toEqual([`reject ${j1} open-failed`, `reject ${j2} open-failed`].sort())
    expect([ii.lost.code, ii.lost.err[0]]).toEqual([1, expect.stringMatching(/^bag: revoked: /)])

    // L6: the admin's log holds one `rotate accept` line per step, naming the action, generation and member.
    const stepsOfAdmin = (name: string) =>
      readAuditLines(join(adm, 'state', name, 'audit.jsonl'))
        .map(parseAuditLine)
        .filter((l) => l.event === 'rotate' && l.decision === 'accept')
        .map(
          (l) =>
            JSON.parse(l.detail as string) as { action: string; generation: number; member: string | null },
        )
        .map((s) => [s.action, s.generation, s.member])
    expect(stepsOfAdmin('team-a')).toEqual([
      ['add', 1, bob],
      ['add', 1, dev],
      ['rotate', 2, null],
      ['add', 2, dev2],
      ['remove', 3, dev],
    ])
    expect(stepsOfAdmin('team-b')).toEqual([
      ['add', 1, bob],
      ['add', 1, dev],
      ['rotate', 2, null],
      ['remove', 3, dev],
      ['add', 3, dev2],
    ])
    // L6: bob's home ran keygen, record and publish only: no edge was opened there, so no audit line exists.
    expect(auditLogs(hb)).toEqual([])
    const [logs, lines] = await verifyLogs([adm, hs, hd, hd2])
    console.log(
      [
        `MEASURE L2: (i) add then remove: dev2 handed generations ${i.generations.join(',')}, opened`,
        `${chatIds(i.read.out).length} of 3 posts sealed to a held generation and ${i.failed.length} of 1`,
        'earlier post failed open-failed;',
        `(ii) remove then add: handed ${ii.generations.join(',')}, opened`,
        `${chatIds(ii.read.out).length} of 2`,
        `and ${ii.failed.length} of 2 earlier posts failed open-failed; dev's hop after the remove:`,
        `${why(i.lost)} and ${why(ii.lost)}; ${logs} audit logs ok (${lines} lines)`,
      ].join(' '),
    )
    const secrets = [
      ...homeSecrets(adm, ['team-a', 'team-b', 'cold']),
      ...homeSecrets(hb, ['bob']),
      ...homeSecrets(hd, ['dev']),
      ...homeSecrets(hd2, ['dev2']),
      ...homeSecrets(hs, ['s1', 's2', 's3', 's4']),
      ...generationSeeds(adm, 'team-a', teamA, 3),
      ...generationSeeds(adm, 'team-b', teamB, 3),
    ]
    noSecrets('46b', w, secrets)
  }, 240_000)

  // L3: the mail waiting for the lost key stays until its ttl; dev2 reads 0 of it; bob can read again what
  // he got.
  it('(46c, L3) undelivered mail stays until its ttl and the new key reads none of it', async () => {
    outputs.length = 0
    const TTL = 10
    const w = await world('s46c')
    const dir = join(w.dir, 'short-relay')
    mkdirSync(dir)
    // The retention is the relay's ttl: 10 s, and its sweep runs every second (--sweep-interval 1), not every
    // 60 s.
    const relay = await withSpawnedRelays(() =>
      startRelay(dir, { ttl: TTL, skew: 2 }, ['--sweep-interval', '1']),
    )
    onTestFinished(async () => {
      await relay.stop()
    })
    const url = relay.url
    const [dev, dev2, bob] = [party('dev'), party('dev2'), party('bob')]
    const D = nodeAt(w, 'dev', url, { keys: dev.keys })
    const B = nodeAt(w, 'bob', url, { keys: bob.keys, roots: [{ address: dev.address }] })
    const E = nodeAt(w, 'dev2', url, { keys: dev2.keys })
    await D.edge.publishRecord(addressRecord(dev, { relays: [url] }))
    await D.edge.publishRecord(acceptFrom(dev, [bob.address]))
    await B.edge.publishRecord(addressRecord(bob, { relays: [url] }))
    await B.edge.publishRecord(acceptFrom(bob, [dev.address]))
    B.edge.setDefault(B.handler('bob'))
    await B.edge.start()

    // The thread before the loss: dev sends bob r = 2 messages, which bob receives and opens.
    for (const n of [1, 2]) {
      await D.edge.send({ to: [bob.address], type: 'chat.v1', body: { from: 'dev', n } })
    }
    await until('bob to take the 2 messages of dev', () => B.store.inboxList(['acked']).length === 2)

    // m = 2 sent by bob to dev before the loss, then the loss (dev2's record is published; bob has not
    // learned of it), then m' = 2 more. From here dev's keys are used by the control reads only.
    const t0 = now()
    const sentTo = async (n: number): Promise<string> => {
      const sent = await B.edge.send({ to: [dev.address], type: 'chat.v1', body: { n } })
      expect(sent.targets.map((x) => x.state)).toEqual(['published'])
      return sent.id
    }
    const ids = [await sentTo(1), await sentTo(2)]
    await E.edge.publishRecord(addressRecord(dev2, { relays: [url] }))
    ids.push(await sentTo(3), await sentTo(4))
    const bytes = ids.map((id) => B.store.outboxGet(id)?.bytes as Uint8Array)

    // Inside the retention: the control, a fetch by dev's key, is 200 with the exact bytes.
    const controls: Uint8Array[] = []
    for (const id of ids) controls.push(await D.edge.fetch(url, id))
    expect(controls).toEqual(bytes)
    // dev2's fetch of each: 403 not-authorized.
    const fetches: string[] = []
    for (const id of ids) {
      const e = await E.edge.fetch(url, id).then(
        () => null,
        (x: unknown) => x,
      )
      expect(e).toBeInstanceOf(RelayError)
      fetches.push(`${(e as RelayError).status} ${(e as RelayError).code}`)
    }
    expect(fetches).toEqual(Array(4).fill('403 not-authorized'))
    // Given the bytes, dev2's edge refuses each at its verify step: not-recipient.
    const verdicts: string[] = []
    for (const [i, b] of bytes.entries()) {
      const row = await E.edge.receiver.receive(url, i + 1, b)
      verdicts.push(`${row.state} ${row.reason}`)
    }
    expect(verdicts).toEqual(Array(4).fill('rejected not-recipient'))
    // The core: as dev2's own address, no wrap (not-recipient); dev's wrap with dev2's sealing key, open-
    // failed.
    const code = (f: () => unknown): string => {
      try {
        f()
        return 'opened'
      } catch (e) {
        return (e as { code?: string }).code ?? String(e)
      }
    }
    const envelopes = bytes.map((b) => parseEnvelope(b))
    const asDev2 = envelopes.map((e) =>
      code(() => openSealed(e, { address: dev2.address, key: dev2.sealing })),
    )
    const dev2sKey = envelopes.map((e) =>
      code(() => openSealed(e, { address: dev.address, key: dev2.sealing })),
    )
    expect([asDev2, dev2sKey]).toEqual([Array(4).fill('not-recipient'), Array(4).fill('open-failed')])
    // The precondition of the control: every read above was inside the first row's retention.
    expect(now()).toBeLessThan(t0 + TTL)

    // After the sweep: the control's fetch is 404 not-found for each (SPEC §8.3), its answer for an id not
    // held.
    const answer = (id: string): Promise<string> =>
      D.edge.fetch(url, id).then(
        () => '200',
        (e: unknown) => (e instanceof RelayError ? `${e.status} ${e.code}` : String(e)),
      )
    const end = Date.now() + 30_000
    let gone: string[] = []
    for (;;) {
      gone = await Promise.all(ids.map(answer))
      if (gone.every((g) => g === '404 not-found') || Date.now() > end) break
      await sleep(250)
    }
    expect(gone).toEqual(Array(4).fill('404 not-found'))
    const goneAfter = now() - t0

    // What bob can send again: the r = 2 messages he received are held as opened content; of the s = 4 he
    // sent, none is readable by him (he is not in `to`: his outbox keeps the exact bytes sealed to dev), so 0
    // of 4.
    const received = B.store.inboxList(['acked'])
    const readable = received.filter(
      (r) => (JSON.parse(r.content as string) as { body: { from?: string } }).body.from === 'dev',
    )
    const ownCopy = envelopes.map((e) =>
      code(() => openSealed(e, { address: bob.address, key: bob.sealing })),
    )
    expect([received.length, readable.length]).toEqual([2, 2])
    expect(ownCopy).toEqual(Array(4).fill('not-recipient'))

    // L6: the audit logs verify, dev2's edge has its four refusals, and no seed is in any file or output.
    for (const n of [D, B, E]) {
      await n.close()
      expect(verifyAuditLog(readAuditLines(n.auditPath))).toEqual({ ok: true, lines: n.audit().length })
    }
    expect(E.steps().filter((s) => s === 'verify reject not-recipient')).toHaveLength(4)
    // L3: 0 of m + m' readable by the new key, each outcome counted under its condition.
    const readableByNew = ids.filter(
      (_, i) =>
        fetches[i] !== '403 not-authorized' ||
        verdicts[i] !== 'rejected not-recipient' ||
        asDev2[i] === 'opened' ||
        dev2sKey[i] === 'opened',
    ).length
    expect(readableByNew).toBe(0)
    const sentReadable = ownCopy.filter((c) => c === 'opened').length
    console.log(
      [
        `MEASURE L3: relay ttl ${TTL} s, sweep 1 s; m = 2 before the loss and m' = 2 after:`,
        `dev's fetch 200 x4 inside the retention (exact bytes), 404 not-found x4 ${goneAfter} s after the`,
        `first send; dev2's fetch ${fetches[0]} x4, its edge ${verdicts[0]} x4, the core as dev2`,
        `${asDev2[0]} x4, dev's wrap with dev2's key ${dev2sKey[0]} x4: ${readableByNew} of ${ids.length}`,
        `readable by the new key; bob can read again ${readable.length} of ${received.length} received`,
        `and ${sentReadable} of ${ids.length} sent`,
      ].join(' '),
    )
    noSecrets('46c', w, [...dev.secrets, ...dev2.secrets, ...bob.secrets])
  }, 120_000)

  // L4: the group arm on a real relay, k = 0 and g = 1: 3 + 7g = 10 hand acts.
  it('(46d, L4) the group arm of the recovery, counted: 10 hand acts at k = 0, g = 1', async () => {
    outputs.length = 0
    const w = await world('s46d')
    const R = w.url
    const homes = ['admin', 'bob', 'dev', 'dev2'].map((d) => join(w.dir, d))
    const [adm, hb, hd, hd2] = homes as [string, string, string, string]
    const [team, cold] = (await keygen(adm, 'team', 'cold')) as [string, string]
    const [bob, dev] = await Promise.all([one(hb, 'bob'), one(hd, 'dev')])
    // Before the loss, uncounted: bob and dev are members, each admitting the group, and bob holds generation
    // 1.
    await onboard(hb, 'bob', R, [team])
    await onboard(hd, 'dev', R, [team])
    await ok('group', 'create', 'team', '--relay', R, '--rotation-key', cold, '--dir', adm)
    for (const member of [bob, dev]) await ok('group', 'add', 'team', member, '--dir', adm)
    const read = (home: string, as: string): Promise<CliRun> =>
      ok('inbox', '--as', as, '--relay', R, '--group', team, '--once', '--dir', home)
    await read(hb, 'bob')

    // The recovery: device lost, no step uses dev's keys; `dev` appears as an address in the admin's `group
    // remove`. At k = 0 pairing publishes nothing, so dev2's address record is two steps of the sequence (3 +
    // 7g).
    const acts: string[] = []
    const act = async (what: string, ...args: string[]): Promise<CliRun> => {
      acts.push(`command ${what}`)
      return ok(...args)
    }
    const carry = <T>(what: string, value: T): T => {
      acts.push(`carry ${what}`)
      return value
    }
    const started = Date.now()
    const dev2 = (await act('keygen', 'keygen', 'dev2', '--dir', hd2)).out[0] as string
    const groupAtDev2 = carry('the group address to dev2', team)
    const addr = join(hd2, 'dev2.address.json')
    const accept = join(hd2, 'dev2.accept-from.json')
    await act(
      'record address',
      'record',
      'address',
      'dev2',
      '--relay',
      R,
      '--sealing-key',
      '--out',
      addr,
      '--dir',
      hd2,
    )
    await act('publish', 'publish', R, addr)
    const size = ['--max-bytes', '65536', '--ttl', '604800']
    const signed = [
      'record',
      'accept-from',
      'dev2',
      '--root',
      groupAtDev2,
      ...size,
      '--out',
      accept,
      '--dir',
      hd2,
    ]
    await act('record accept-from', ...signed)
    await act('publish', 'publish', R, accept)
    const dev2AtAdmin = carry("dev2's address to the admin", dev2)
    await act('group add', 'group', 'add', 'team', dev2AtAdmin, '--dir', adm)
    await act('group remove', 'group', 'remove', 'team', dev, '--dir', adm)
    // Not an act of the sequence: bob, a member, posts to the group under his hop, and reads generation 2.
    const post = (
      await ok(
        'send',
        '--as',
        'bob',
        '--to',
        team,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        '{"n":1}',
        '--dir',
        hb,
      )
    ).out[0] as string
    await read(hb, 'bob')
    const got = await act(
      'inbox --group',
      'inbox',
      '--as',
      'dev2',
      '--relay',
      R,
      '--group',
      groupAtDev2,
      '--once',
      '--dir',
      hd2,
    )
    const wall = Date.now() - started

    // L4: 3 + 7g = 10 for g = 1 and k = 0 (range 10 to 12: a refused step repeated); every command exited 0.
    expect(acts.length).toBe(10)
    expect(acts.filter((a) => a.startsWith('command ')).length).toBe(8)
    expect(acts.filter((a) => a.startsWith('carry ')).length).toBe(2)
    // L4: dev2 completed the arm: it holds generations 1 (the add) and 2 (the remove) and reads bob's post.
    expect(
      readdirSync(groupDir(hd2, 'dev2', team))
        .filter((f) => /^g\d+\.json$/.test(f))
        .sort(),
    ).toEqual(['g1.json', 'g2.json'])
    expect(got.out).toContain(`accept ${post} ${bob} ${team} chat.v1 {"n":1}`)
    expect(chatIds(got.out)).toEqual([post])
    expect(got.out.filter((l) => l.startsWith('reject '))).toEqual([])

    // L6: the logs verify, dev2 has none before its inbox (keygen, record, publish write none), no key
    // material.
    const [logs, lines] = await verifyLogs([adm, hb, hd2])
    expect(logs).toBe(3)
    const commands = acts.filter((a) => a.startsWith('command ')).length
    console.log(
      [
        `MEASURE L4: k=0 g=1 on the release relay: ${acts.length} hand acts (${commands} commands,`,
        `${acts.length - commands} carried); formula 3 + 7g = 10, range 10 to 12; dev2 holds generations 1,2`,
        `and read bob's post; wall time ${wall} ms from keygen to the read (process start-up included, no`,
        `rule: the human steps take longer); ${logs} audit logs ok (${lines} lines)`,
      ].join(' '),
    )
    const secrets = [
      ...homeSecrets(adm, ['team', 'cold']),
      ...homeSecrets(hb, ['bob']),
      ...homeSecrets(hd, ['dev']),
      ...homeSecrets(hd2, ['dev2']),
      ...generationSeeds(adm, 'team', team, 2),
    ]
    noSecrets('46d', w, secrets)
  }, 180_000)

  // L5x (reported beside the lines, with no rule): the identity made as a group, d1's key lost.
  // Three PREDICTIONS to be falsified, one test each; a red here is a falsified prediction, reported as one,
  // not a defect of the build. The stand-in: `dev` is a group whose key is the admin's, on d1; d2 is a
  // member.

  // Prediction 1 (0.85), a prediction to be falsified: reachability lasts the record's ttl, not seven days.
  it('(46e-1, L5x) prediction: the group identity is unreachable once its record lapses', async () => {
    outputs.length = 0
    const TTL = 30
    const w = await world('s46e1')
    const R = w.url
    const homes = ['d1', 'd2', 'peers'].map((d) => join(w.dir, d))
    const [h1, h2, hp] = homes as [string, string, string]
    const [dev, cold] = (await keygen(h1, 'dev', 'cold')) as [string, string]
    const d2 = await one(h2, 'd2')
    const [pa, pc] = (await keygen(hp, 'peer-a', 'peer-c')) as [string, string]
    await onboard(h2, 'd2', R, [dev])
    const ttl = ['--ttl', String(TTL)]
    const root = ['--root', pa, '--root', pc]
    const create = ['group', 'create', 'dev', '--relay', R, '--rotation-key', cold, ...ttl, ...root]
    const created = await ok(...create, '--dir', h1)
    const iat = Number(/ iat (\d+) /.exec(created.out[1] as string)?.[1])
    await ok('group', 'add', 'dev', d2, '--dir', h1)
    const say = (as: string, n: number): Promise<CliRun> =>
      cli(
        'send',
        '--as',
        as,
        '--to',
        dev,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        `{"n":${n}}`,
        '--dir',
        hp,
      )
    const posted = (await say('peer-a', 1)).out[0] as string
    const inbox = ['inbox', '--as', 'd2', '--relay', R, '--group', dev, '--once', '--trust-root', pa]

    // While the record lives (30 s here; GROUP_RECORD_TTL is 3,600 s by default, 86,400 s at most), d2's
    // `inbox --group` opens the mail to dev; after it, a peer's CLI send fails resolve-failed (exit 1) and so
    // does d2's `inbox --group`.
    const during = await ok(...inbox, '--dir', h2)
    expect(chatIds(during.out)).toEqual([posted])
    expect(now()).toBeLessThan(iat + TTL)
    await untilSecond(iat + TTL + 1)
    const late = await say('peer-c', 2)
    expect([late.code, late.err[0]]).toEqual([1, expect.stringMatching(/^bag: resolve-failed: /)])
    const lapsed = await cli(...inbox, '--dir', h2)
    expect([lapsed.code, lapsed.err[0]]).toEqual([1, expect.stringMatching(/^bag: resolve-failed: /)])
    console.log(
      [
        `MEASURE L5x (1): record ttl ${TTL} s: d2 opened ${chatIds(during.out).length} of 1 post while it`,
        `lived; after it, the peer's send exit ${late.code} ${why(late)} and d2's inbox exit ${lapsed.code}`,
        `${why(lapsed)}`,
      ].join(' '),
    )
    const secrets = [
      ...homeSecrets(h1, ['dev', 'cold']),
      ...homeSecrets(h2, ['d2']),
      ...homeSecrets(hp, ['peer-a', 'peer-c']),
      ...generationSeeds(h1, 'dev', dev, 1),
    ]
    await verifyLogs([h1, h2, hp])
    noSecrets('46e-1', w, secrets)
  }, 120_000)

  // Prediction 2 (0.90), a prediction to be falsified: d2 cannot write as dev to a peer.
  it('(46e-2, L5x) prediction: a device writes as itself, a hand-attached hop meets relay', async () => {
    outputs.length = 0
    const w = await world('s46e2')
    const R = w.url
    const homes = ['d1', 'd2', 'peers'].map((d) => join(w.dir, d))
    const [h1, h2, hp] = homes as [string, string, string]
    const [dev, cold] = (await keygen(h1, 'dev', 'cold')) as [string, string]
    const d2 = await one(h2, 'd2')
    const made = await keygen(hp, 'peer-a', 'peer-b', 'peer-c', 'peer-d', 'peer-e')
    const [pa, pb, pc, pd, pe] = made as [string, string, string, string, string]
    // A former peer's accept-from names the identity (pairing). peer-a's names d2 too; peer-c's names d2
    // alone.
    await onboard(h2, 'd2', R, [dev])
    await onboard(hp, 'peer-a', R, [dev, d2])
    await onboard(hp, 'peer-b', R, [dev])
    await onboard(hp, 'peer-c', R, [d2])
    await onboard(hp, 'peer-d', R, [dev])
    await onboard(hp, 'peer-e', R, [dev])
    await ok('group', 'create', 'dev', '--relay', R, '--rotation-key', cold, '--dir', h1)
    await ok('group', 'add', 'dev', d2, '--dir', h1)
    await ok('inbox', '--as', 'd2', '--relay', R, '--group', dev, '--once', '--dir', h2)
    const send = (to: string, n: number, ...more: string[]): Promise<CliRun> =>
      cli(
        'send',
        '--as',
        'd2',
        '--to',
        to,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        `{"n":${n}}`,
        ...more,
      )

    // `send --as d2 --to <peer>` goes out under d2's own root: the hop is attached only when the one --to is
    // the group. peer-a, whose accept-from names d2, reads d2, not dev; peer-b, whose accept-from names dev
    // only, is refused root-not-accepted by its relay.
    const toA = await send(pa, 1, '--dir', h2)
    expect([toA.code, toA.err]).toEqual([0, []])
    const readA = await ok('inbox', '--as', 'peer-a', '--relay', R, '--once', '--trust-root', d2, '--dir', hp)
    expect(readA.out).toEqual([`accept ${toA.out[0]} ${d2} ${d2} chat.v1 {"n":1}`])
    const toB = await send(pb, 2, '--dir', h2)
    expect([toB.code, toB.err[0]]).toEqual([1, expect.stringMatching(/^bag: root-not-accepted: /)])

    // With the membership hop attached by hand (`--auth`): the relay evaluates no caveat, so it publishes
    // unless the peer's accept-from refuses the root dev (peer-c's names d2 alone: 403 root-not-accepted).
    // Past the relay, a peer running a plain `inbox` has no groups evaluator: unknown-caveat; a peer that is
    // not a member and runs `inbox --group dev` holds the evaluator and the caveat fails (`to` is not exactly
    // the group): caveat-failed, and the run then exits 1 with ENOENT, since it holds no membership hop of
    // dev.
    const hop = new GroupKeyStore(join(h2, 'groups', 'd2')).body(dev, 1).hop
    const chain = join(h2, 'dev.chain.json')
    writeFileSync(chain, `${JSON.stringify([hop])}\n`)
    const viaHop = (to: string, n: number): Promise<CliRun> => send(to, n, '--auth', chain, '--dir', h2)
    const toC = await viaHop(pc, 3)
    expect([toC.code, toC.err[0]]).toEqual([1, expect.stringMatching(/^bag: root-not-accepted: /)])
    const toD = await viaHop(pd, 4)
    const toE = await viaHop(pe, 5)
    expect([toD.code, toD.err, toE.code, toE.err]).toEqual([0, [], 0, []])
    const plain = await ok(
      'inbox',
      '--as',
      'peer-d',
      '--relay',
      R,
      '--once',
      '--trust-root',
      dev,
      '--dir',
      hp,
    )
    expect(plain.out).toEqual([`reject ${toD.out[0]} unknown-caveat`])
    const member = ['inbox', '--as', 'peer-e', '--relay', R, '--group', dev, '--once', '--trust-root', dev]
    const asGroup = await cli(...member, '--dir', hp)
    expect(asGroup.out).toEqual([`reject ${toE.out[0]} caveat-failed`])
    expect([asGroup.code, asGroup.err[0]]).toEqual([
      1,
      expect.stringMatching(/^bag: ENOENT: groups: no membership hop of .* is held$/),
    ])
    const root = readA.out[0]?.split(' ')[3] === d2 ? 'd2' : 'dev'
    console.log(
      [
        `MEASURE L5x (2): d2 to peer-a (accept-from names d2) read as root ${root};`,
        `d2 to peer-b (names dev only): exit ${toB.code} ${why(toB)}; with the hop by hand: peer-c (names d2`,
        `alone) exit ${toC.code} ${why(toC)}, peer-d plain inbox ${plain.out[0]?.split(' ')[2]},`,
        'peer-e inbox',
        `--group ${asGroup.out[0]?.split(' ')[2]} then exit ${asGroup.code} ${why(asGroup)}`,
      ].join(' '),
    )
    const secrets = [
      ...homeSecrets(h1, ['dev', 'cold']),
      ...homeSecrets(h2, ['d2']),
      ...homeSecrets(hp, ['peer-a', 'peer-b', 'peer-c', 'peer-d', 'peer-e']),
      ...generationSeeds(h1, 'dev', dev, 1),
    ]
    await verifyLogs([h1, h2, hp])
    noSecrets('46e-2', w, secrets)
  }, 180_000)

  // Prediction 3 (0.90), a prediction to be falsified: membership ends with the hop.
  it('(46e-3, L5x) prediction: membership ends with the hop, hop-expired past its exp', async () => {
    outputs.length = 0
    const w = await world('s46e3')
    const R = w.url
    const homes = ['d1', 'd2'].map((d) => join(w.dir, d))
    const [h1, h2] = homes as [string, string]
    const [dev, cold] = (await keygen(h1, 'dev', 'cold')) as [string, string]
    const d2 = await one(h2, 'd2')
    await onboard(h2, 'd2', R, [dev])
    await ok('group', 'create', 'dev', '--relay', R, '--rotation-key', cold, '--dir', h1)
    // No hop is renewed without the admin's key. The hop's exp is 15 s after the add here (604,800 s by
    // default).
    const added = await ok('group', 'add', 'dev', d2, '--exp', '+15', '--dir', h1)
    const exp = Number(/ exp (\d+)$/.exec(added.out[0] as string)?.[1])
    const inbox = ['inbox', '--as', 'd2', '--relay', R, '--group', dev, '--once', '--dir', h2]
    expect((await ok(...inbox)).code).toBe(0)
    expect(now()).toBeLessThan(exp)
    await untilSecond(exp + 1)
    const expired = await cli(...inbox)
    expect([expired.code, expired.err[0]]).toEqual([1, expect.stringMatching(/^bag: hop-expired: /)])
    console.log(
      [
        'MEASURE L5x (3): hop exp +15 s: d2 inbox --group before it exit 0, after it exit',
        `${expired.code} ${why(expired)}`,
      ].join(' '),
    )
    const secrets = [
      ...homeSecrets(h1, ['dev', 'cold']),
      ...homeSecrets(h2, ['d2']),
      ...generationSeeds(h1, 'dev', dev, 1),
    ]
    await verifyLogs([h1, h2])
    noSecrets('46e-3', w, secrets)
  }, 120_000)

  // L6: the CLI steps that write no audit line write none, the edge steps leave theirs, the controls are
  // found.
  it('(46f, L6) audit trail of the CLI steps and the planted controls of the secret count', async () => {
    outputs.length = 0
    const w = await world('s46f')
    const R = w.url
    const home = join(w.dir, 'home')
    const dir = ['--dir', home]
    const [alice, bob, carol] = (await keygen(home, 'alice', 'bob', 'carol')) as [string, string, string]
    await onboard(home, 'bob', R, [alice, carol])
    await ok('name', 'add', 'bob', bob, ...dir)
    // keygen, record, publish and name left no audit line (`peer` is counted in packages/cli/test/lost-
    // device.test.ts, which can give it a terminal).
    expect(auditLogs(home)).toEqual([])
    const send = (as: string, n: number): Promise<CliRun> =>
      ok('send', '--as', as, '--to', bob, '--relay', R, '--type', 'chat.v1', '--body', `{"n":${n}}`, ...dir)
    const [fromAlice, fromCarol] = [
      (await send('alice', 1)).out[0] as string,
      (await send('carol', 2)).out[0] as string,
    ]
    const read = await ok('inbox', '--as', 'bob', '--relay', R, '--once', '--trust-root', alice, ...dir)
    expect([...read.out].sort()).toEqual(
      [`accept ${fromAlice} ${alice} ${alice} chat.v1 {"n":1}`, `reject ${fromCarol} untrusted-root`].sort(),
    )
    // The edge steps leave their lines: verify, policy, dedup, unseal, policy and route per receipt, and the
    // refusal's `reject untrusted-root`; the sender's `publish`.
    const log = (name: string): string => join(home, 'state', name, 'audit.jsonl')
    expect(auditLogs(home).map((f) => basename(dirname(f)))).toEqual(['alice', 'bob', 'carol'])
    expect(stepsOf(log('bob'), fromAlice)).toEqual([
      'verify accept ok',
      'policy accept ok',
      'dedup accept ok',
      'unseal accept ok',
      'policy accept ok',
      'route route ok',
    ])
    expect(stepsOf(log('bob'), fromCarol)).toEqual(['verify accept ok', 'policy reject untrusted-root'])
    expect(stepsOf(log('alice'), fromAlice)).toEqual(['publish accept ok'])
    const [logs, lines] = await verifyLogs([home])
    expect(logs).toBe(3)

    // The count of secrets: 0 in files, output, argv and environment; and the planted controls, a file with a
    // seed and a line with a seed in another form, each counted once.
    const secrets = homeSecrets(home, ['alice', 'bob', 'carol'])
    const [inFiles, inOutput] = leaks(w, secrets)
    expect([inFiles, inOutput]).toEqual([0, 0])
    const scanned = filesUnder(w.dir).length
    const planted = join(w.dir, 'planted.txt')
    writeFileSync(planted, `key=${secrets[0]}\n`)
    const plantedLine = `seed ${Buffer.from(secrets[2] as string, 'hex').toString('base64url')}`
    const controls = [
      occurrences([readFileSync(planted)], secrets),
      occurrences([Buffer.from(plantedLine)], secrets),
    ]
    expect(controls).toEqual([1, 1])
    console.log(
      [
        'MEASURE L6 46f: keygen, record, publish and name wrote 0 audit lines; send and inbox wrote logs for',
        `alice, bob and carol, ${logs} logs ok (${lines} lines); bob's receipt: verify, policy, dedup,`,
        'unseal, policy, route; the refusal: verify, policy reject untrusted-root;',
        `${secrets.length} secrets, ${scanned} files: occurrences ${inFiles} in files and ${inOutput} in`,
        `output; controls ${controls.join(' and ')}`,
      ].join(' '),
    )
  }, 120_000)

  // --- 46g, 46h: the device grant and
  // groups in the agent, through the CLI in child processes on a real relay. `ac login`, which asks each first grant
  // on its own terminal, runs on a pseudo-terminal (../terminal.ts, scenario 41's pattern) and the test types the
  // `y`; the session's agent calls (`open`, `sign`) go through the edge library's AgentClient on the agent's socket,
  // since no CLI command makes them. A Unix socket path holds about 100 bytes, so the homes have one-letter names.
  //
  //   46g  the device: P grants D a hop (`ac grant --device`), D logs in with it, D grants a session S, S sends
  //        through the relay under [P -> D, D -> S] and the reader accepts; D opens nothing of P's; D's logout
  //        signs nothing and prints the unrevoked lines and the revoke step; P's `record address --revoke D`
  //        cuts D's new mail.
  //   46h  groups in the agent: P holds a generation of a group, `ac login` replays it, a session under
  //        [G -> P, P -> S] opens a message sealed to the group; a group-rooted sign is not-authorized; the
  //        agent's audit has the open line with the generation.

  /** Random bytes for a message built here (the core's Rng). */
  const fresh = (n: number): Uint8Array => new Uint8Array(randomBytes(n))

  /** The questions the agent has put on its terminal so far: each ends "type y to sign". */
  const asked = (t: Terminal): number => t.err().split('type y to sign').length - 1

  /** Types `y` at the agent's terminal once its `n`-th question is shown. */
  async function sign(t: Terminal, n: number): Promise<void> {
    await until(`question ${n} at the agent`, () => asked(t) >= n, 30_000)
    t.type('y')
  }

  /** The address record of `address` the relay serves, parsed. */
  async function served(url: string, address: string): Promise<AddressRecord> {
    const res = await fetch(`${url}/v0/fetch/record/${address}/address`)
    expect(res.status).toBe(200)
    return parseRecord(new Uint8Array(await res.arrayBuffer())) as AddressRecord
  }

  /** The key record of `address` the relay serves (forward secrecy: the address record of a logged-in identity names no sealing key). */
  async function servedKey(url: string, address: string): Promise<KeyRecord> {
    const res = await fetch(`${url}/v0/fetch/record/${address}/key`)
    expect(res.status).toBe(200)
    return parseRecord(new Uint8Array(await res.arrayBuffer())) as KeyRecord
  }

  /**
   * P's login window and the epoch it publishes first: the identity was made with a sealing key in its address
   * record, so login publishes epoch 1, a key record and the address record re-signed with none. The re-sign is at the
   * clock's second and the relay takes it only when later than the stored record's, so the window opens in a later second.
   */
  async function loginAt(home: string, name: string, relay: string, address: string): Promise<Terminal> {
    await untilSecond((await served(relay, address)).iat + 1)
    const t = terminal(['login', '--as', name, '--relay', relay, '--dir', home], outputs)
    const opened = await lineOf(t, 'login ')
    expect(opened.startsWith(`login ${address} until `)).toBe(true)
    await lineOf(t, `published address ${address} `)
    expect(t.out().filter((l) => l.startsWith('published '))).toEqual([
      `published key ${address} ${relay}`,
      `published address ${address} ${relay}`,
    ])
    return t
  }

  /** The lines of a home's agent audit log (detail parsed), and `audit verify` printing `ok <n> lines` for it. */
  interface AgentLine {
    readonly event: string
    readonly decision: string
    readonly reason: string
    readonly id: string | null
    readonly from: string | null
    readonly root: string | null
    readonly detail: Record<string, unknown> | null
  }
  async function agentLog(home: string): Promise<AgentLine[]> {
    const file = join(home, 'agent-audit.jsonl')
    const verified = await ok('audit', 'verify', file)
    expect(verified.out[0]).toMatch(/^ok \d+ lines$/)
    return readFileSync(file, 'utf8')
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => {
        const line = JSON.parse(l) as AgentLine & { detail: string | null }
        return { ...line, detail: line.detail === null ? null : JSON.parse(line.detail) }
      })
  }

  /** The socket path of a home's agent, checked to fit a Unix socket (104 bytes on macOS, 108 on Linux). */
  function socketOf(home: string): string {
    const sock = join(home, 'agent.sock')
    expect(sock.length, `the socket path ${sock} must fit a Unix socket (under 104 bytes)`).toBeLessThan(104)
    return sock
  }

  it('(46g, device) P grants D a hop; D grants S; the reader accepts [P -> D, D -> S]; D opens nothing; revoking D cuts it', async () => {
    outputs.length = 0
    const w = await world('s46g')
    const R = w.url
    const homes = ['p', 'd', 'r'].map((d) => join(w.dir, d))
    const [hp, hd, hr] = homes as [string, string, string]
    for (const h of homes) mkdirSync(h, { recursive: true, mode: 0o700 })
    // P: the key file pk and the agent identity p over it; D: the key file dk, the agent identity dev over it, and
    // the session key s on the device; the reader names P as the one root it accepts.
    const P = await one(hp, 'pk')
    const [D, S] = (await keygen(hd, 'dk', 's')) as [string, string]
    const reader = await one(hr, 'reader')
    await onboard(hp, 'pk', R, [P])
    await onboard(hr, 'reader', R, [P])
    expect((await ok('keygen', 'p', '--custody', 'agent', '--principal', 'pk', '--dir', hp)).out).toEqual([P])
    expect((await ok('keygen', 'dev', '--custody', 'agent', '--principal', 'dk', '--dir', hd)).out).toEqual([
      D,
    ])
    // What `ac peer` leaves in each name book (the pairing is scenario 41's): P knows D as laptop, D knows P.
    await ok('name', 'add', 'laptop', D, '--dir', hp)
    await ok('name', 'add', 'p', P, '--dir', hd)
    const published = (): string[] =>
      relayEvents(w.relay)
        .filter((e) => e.event === 'publish-record')
        .map((e) => `${e.kind} ${e.signer}`)

    // P's window; `ac grant --device laptop` (S1): the agent shows the grant and signs on the one y typed there. The
    // hop is P -> D, no caveat, exp 3600 s on (bound: the 30 days of DEVICE_MAX; the CLI reads its clock between
    // t0 and t1).
    const p = await loginAt(hp, 'p', R, P)
    const pOpen = p.out().find((l) => l.startsWith('login ')) as string
    expect(pOpen.endsWith(` on ${socketOf(hp)}`)).toBe(true)
    const t0 = now()
    const deviceGrant = cli('grant', '--as', 'p', '--device', 'laptop', '--exp', '+3600', '--dir', hp)
    await sign(p, 1)
    const granted = await deviceGrant
    const t1 = now()
    expect([granted.code, granted.err.length]).toEqual([0, 1])
    expect(granted.err[0]).toMatch(/^request [0-9a-f]{8}: /)
    const device = JSON.parse(granted.out[0] as string) as Hop[]
    expect(device).toHaveLength(1)
    expect(device[0]).toMatchObject({ iss: P, sub: D, caveats: [] })
    const deviceExp = (device[0] as Hop).exp
    expect([deviceExp - 3600 >= t0, deviceExp - 3600 <= t1]).toEqual([true, true])
    expect(p.err()).toContain(`device grant to ${D}`)
    expect(p.err()).toContain('caveats unrestricted')
    expect(asked(p)).toBe(1)

    // The device hop is in no dated map, so P's logout signs nothing and D stays out of
    // `revoked` (bound: 0 entries in the record the relay serves).
    const pOut = await ok('logout', '--as', 'p', '--dir', hp)
    expect(pOut.out).toEqual(['logout: nothing to revoke'])
    expect(await exited(p, 'P login')).toBe(0)
    expect(p.out().at(-1)).toBe(`logout ${P}`)
    const beforeRevoke = await served(R, P)
    expect(beforeRevoke.revoked).toEqual([])
    const pLog = await agentLog(hp)
    expect(pLog.map((l) => [l.event, l.decision, l.reason, l.root])).toEqual([['device', 'accept', 'ok', P]])
    expect(pLog[0]?.detail).toMatchObject({ tag: HOP_TAG, sub: D, exp: deviceExp, caveats: 0 })

    // D's window (S2): the hop carried by hand; the window answers for P and reads no record of P's (bound: 0 records
    // published while D's window is open).
    const hopFile = join(hd, 'laptop.hop.json')
    writeFileSync(hopFile, `${granted.out[0]}\n`)
    const d = terminal(['login', '--as', 'dev', '--device', hopFile, '--dir', hd], outputs)
    const dOpen = await lineOf(d, 'login ')
    expect(dOpen.startsWith(`login ${D} for ${P} until `)).toBe(true)
    expect(dOpen.endsWith(` on ${socketOf(hd)}`)).toBe(true)
    // The setup: two records each of pk and the reader, and P's epoch 1 at login (a key record and the address record).
    await until('the setup publishes logged', () => !w.relay.spawned || published().length >= 6)
    const publishedAtLogin = published().length

    // D grants S under D (`--chain` puts the device hop first): [P -> D, D -> S], which verifies to root P.
    const sessionGrant = cli(
      ...['grant', '--as', 'dev', '--session', S, '--caveat', 'type=chat.v1', '--exp', '+600'],
      ...['--chain', hopFile, '--dir', hd],
    )
    await sign(d, 1)
    const grantedS = await sessionGrant
    expect([grantedS.code, grantedS.err.length]).toEqual([0, 1])
    const chain = JSON.parse(grantedS.out[0] as string) as Hop[]
    expect(chain).toHaveLength(2)
    expect(chain[0]).toEqual(device[0])
    expect(chain[1]).toMatchObject({ iss: D, sub: S, caveats: ['type=chat.v1'] })
    expect(verifyChain(chain, S, now())).toMatchObject({ root: P })
    const chainFile = join(hd, 's.chain.json')
    writeFileSync(chainFile, `${grantedS.out[0]}\n`)

    // S signs and sends through the relay; the reader, trusting P, accepts: from S, root P (bound: 1 of 1 accepted).
    const send = (n: number): Promise<CliRun> =>
      cli(
        ...['send', '--as', 's', '--to', reader, '--relay', R, '--type', 'chat.v1', '--body', `{"n":${n}}`],
        ...['--auth', chainFile, '--dir', hd],
      )
    const inbox = (): Promise<CliRun> =>
      ok(
        'inbox',
        '--as',
        'reader',
        '--relay',
        R,
        '--once',
        '--trust-root',
        P,
        '--honor',
        'coding',
        '--dir',
        hr,
      )
    const m1 = await send(1)
    expect([m1.code, m1.err, m1.out[1]]).toEqual([0, [], `published ${R} tries=1`])
    expect((await inbox()).out).toEqual([`accept ${m1.out[0]} ${S} ${P} chat.v1 {"n":1}`])

    // The device opens nothing: S under D's window asks to open a message sealed to P and is not-authorized
    // (bound: 0 accepted `open` lines in D's agent audit, the one refusal audited as a reject).
    const writer = party('writer')
    const pKey = await servedKey(R, P)
    expect((await served(R, P)).sealing_key).toBeNull()
    const mail = buildEnvelope({
      from: writer.signing,
      to: [{ address: P, sealingKey: fromHex(pKey.sealing_key, 32) }],
      auth: [],
      type: 'chat.v1',
      thread: newThread(fresh),
      body: { n: 9 },
      ts: now(),
      rng: fresh,
    })
    const sKeys = new FsKeyStore(join(hd, 'keys')).load('s')
    const session = new AgentClient(socketOf(hd), { key: sKeys.signing, chain })
    try {
      const text = new TextDecoder().decode(mail.bytes)
      await expect(session.open(P, mail.envelope.id, text)).rejects.toMatchObject({ code: 'not-authorized' })
    } finally {
      session.close()
    }

    // D's logout: nothing is signed, the one live session is named with `exp + TTL + skew`, and the revoke
    // step for P's machine is printed (bound: 1 unrevoked line, its instant exactly the hop's exp + 604800 + 300).
    const dOut = await cli('logout', '--as', 'dev', '--dir', hd)
    expect(dOut.code).toBe(0)
    expect(dOut.out).toEqual([
      expect.stringMatching(new RegExp(`^unrevoked ${S} until \\d{4}-\\d\\d-\\d\\dT`)),
    ])
    expect(dOut.err).toEqual([expect.stringContaining(`--revoke ${D}`)])
    const until1 = Date.parse(/ until (\S+)$/.exec(dOut.out[0] as string)?.[1] as string) / 1000
    expect(until1).toBe((chain[1] as Hop).exp + DEFAULT_TTL + DEFAULT_SKEW)
    expect(await exited(d, 'D login')).toBe(0)
    expect(d.out().at(-1)).toBe(`logout ${D}`)
    await sleep(300)
    expect(published().length).toBe(publishedAtLogin)
    const dLog = await agentLog(hd)
    expect(dLog.map((l) => [l.event, l.decision, l.reason, l.root, l.from])).toEqual([
      ['sign', 'accept', 'ok', P, null],
      ['open', 'reject', 'not-authorized', P, S],
    ])

    // The gap the revoke step closes: D has logged out and P's record still lists nobody, so S's chain still
    // passes (bound: accepted until D is revoked, at most the hop's exp + TTL + skew).
    const m2 = await send(2)
    expect([m2.code, m2.err]).toEqual([0, []])
    expect((await inbox()).out).toEqual([`accept ${m2.out[0]} ${S} ${P} chat.v1 {"n":2}`])

    // P's machine: `record address pk --revoke D`, which the built path allows after P's logout. The relay now keeps D
    // in P's revoked list, so a new send under a chain through D is 403 revoked and reaches no one (bound: 1 of 1
    // refused, 0 accepted).
    await sleep(1100)
    const revoked = join(hp, 'pk.revoked.address.json')
    await ok(
      'record',
      'address',
      'pk',
      '--relay',
      R,
      '--sealing-key',
      '--revoke',
      D,
      '--out',
      revoked,
      '--dir',
      hp,
    )
    expect((await ok('publish', R, revoked)).out).toEqual([`ok address ${P}`])
    expect((await served(R, P)).revoked).toEqual([D])
    const m3 = await send(3)
    expect([m3.code, m3.out[1], m3.err[0]]).toEqual([
      1,
      `failed ${R} tries=1 reason=revoked`,
      expect.stringMatching(/^bag: revoked: /),
    ])
    expect((await inbox()).out).toEqual([])

    console.log(
      [
        `MEASURE 46g: P's device hop exp = request + 3600 s (read within ${t1 - t0} s of the request, bound 30 days),`,
        `P's logout left`,
        `${beforeRevoke.revoked.length} entries in revoked, D's window published ${published().length - publishedAtLogin}`,
        `records; chain length ${chain.length} accepted 2 of 2 (before and after D's logout);`,
        `D open at P's mailbox not-authorized with ${dLog.filter((l) => l.event === 'open' && l.decision === 'accept').length} accepted open lines;`,
        `unrevoked lines 1, instant exp + ${DEFAULT_TTL} + ${DEFAULT_SKEW}; after the revoke step the send is`,
        `${m3.out[1]?.split('reason=')[1]} (exit ${m3.code}) and the reader accepted 0 of 1`,
      ].join(' '),
    )
    await verifyLogs([hp, hd, hr])
    noSecrets('46g', w, [
      ...homeSecrets(hp, ['pk']),
      ...homeSecrets(hd, ['dk', 's']),
      ...homeSecrets(hr, ['reader']),
      ...writer.secrets,
    ])
  }, 240_000)

  it('(46h, groups in the agent) P holds a generation; login replays it; a session under [G -> P, P -> S] opens group mail', async () => {
    outputs.length = 0
    const w = await world('s46h')
    const R = w.url
    const homes = ['a', 'p', 's'].map((d) => join(w.dir, d))
    const [ha, hp, hs] = homes as [string, string, string]
    for (const h of homes) mkdirSync(h, { recursive: true, mode: 0o700 })
    // The admin makes the group (generation 1) and admits P; P admits the group's root at its mailbox, reads its
    // membership as the key file pk (the pointer p is made after, as a member's `keygen --custody agent` is now
    // allowed); one sender, s1, is admitted by the group.
    const [team, cold] = (await keygen(ha, 'team', 'cold')) as [string, string]
    const P = await one(hp, 'pk')
    const s1 = await one(hs, 's1')
    await onboard(hp, 'pk', R, [team])
    const made = await ok(
      'group',
      'create',
      'team',
      '--relay',
      R,
      '--rotation-key',
      cold,
      '--root',
      s1,
      '--dir',
      ha,
    )
    expect(made.out[0]).toMatch(/ generation 1$/)
    await ok('group', 'add', 'team', P, '--dir', ha)
    await ok('inbox', '--as', 'pk', '--relay', R, '--group', team, '--once', '--dir', hp)
    const store = new GroupKeyStore(join(hp, 'groups', 'pk'))
    expect(store.generations(team)).toEqual([1])
    const body = store.body(team, 1)
    const membership = body.hop as Hop
    expect(membership).toMatchObject({ iss: team, sub: P })

    // The inverse of the agent's group refusal (agent-groups.test.ts): the pointer for a member is made, exit 0, and the login
    // window opens with the stored body replayed (bound: 0 "not held" lines and no `agent-groups` on stderr).
    const pointer = await ok('keygen', 'p', '--custody', 'agent', '--principal', 'pk', '--dir', hp)
    expect(pointer.out).toEqual([P])
    const p = await loginAt(hp, 'p', R, P)
    expect([p.err().includes('not held'), p.err().includes('agent-groups')]).toEqual([false, false])

    // A session S: P grants it [P -> S] on one y; with the membership hop it holds [G -> P, P -> S].
    const S = party('session')
    const other = party('other')
    const grantS = cli(
      ...[
        'grant',
        '--as',
        'p',
        '--session',
        S.address,
        '--caveat',
        'type=chat.v1',
        '--exp',
        '+600',
        '--dir',
        hp,
      ],
    )
    await sign(p, 1)
    const granted = await grantS
    expect([granted.code, granted.err.length]).toEqual([0, 1])
    const hop = JSON.parse(granted.out[0] as string) as Hop[]
    expect(hop).toHaveLength(1)
    const chain = [membership, ...hop]
    expect(verifyChain(chain, S.address, now())).toMatchObject({ root: team })

    // A message sealed to the group, sent by s1 through the relay, fetched by S under its chain (the relay admits a
    // chain from a party of the envelope), and opened by the agent with the generation it replayed.
    const sent = await ok(
      ...['send', '--as', 's1', '--to', team, '--relay', R, '--type', 'chat.v1', '--body', '{"n":1}'],
      ...['--dir', hs],
    )
    const id = sent.out[0] as string
    const ts = now()
    const proof = { signer: S.address, ts, sig: signFetchAuth(S.signing, id, ts, R), auth: chain }
    const text = new TextDecoder().decode(await createHttpRelay().fetch(R, id, proof))
    const sock = socketOf(hp)
    const open = new AgentClient(sock, { key: S.signing, chain })
    const signer = new AgentClient(sock, { key: S.signing, chain })
    const own = new AgentClient(sock, { key: S.signing, chain: hop })
    try {
      const content = await open.open(team, id, text)
      expect(content).toMatchObject({ type: 'chat.v1', body: { n: 1 } })
      // A group-rooted session asking to sign is not-authorized (bound: 1 accepted sign line, the grant, and 1
      // rejected); and P's own chain is no group session: the group's mailbox is not-authorized under it.
      const exp = now() + 60
      await expect(signer.sign(other.address, ['type=chat.v1'], exp)).rejects.toMatchObject({
        code: 'not-authorized',
      })
      await expect(own.open(team, id, text)).rejects.toMatchObject({ code: 'not-authorized' })
    } finally {
      open.close()
      signer.close()
      own.close()
    }

    // P's logout revokes S (the one session subject granted) and the window ends.
    const out = await ok('logout', '--as', 'p', '--dir', hp)
    expect(out.out).toEqual([expect.stringMatching(new RegExp(`^published address ${P} iat \\d+ ${R}$`))])
    expect(await exited(p, 'P login')).toBe(0)
    expect(p.out().at(-1)).toBe(`logout ${P}`)

    // The agent's audit: the replay (one rotate line, the generation taken, no key), the grant (one sign line) and
    // the open with the generation (bound: exactly 1 accepted open line, detail {mailbox, rule, generation}; the two
    // refusals above are audited as rejects, which the agent writes once a request's signature has verified).
    const log = await agentLog(hp)
    const lines = (event: string): AgentLine[] => log.filter((l) => l.event === event)
    expect(lines('rotate').map((l) => [l.decision, l.reason])).toEqual([['accept', 'ok']])
    expect(lines('rotate')[0]?.detail).toMatchObject({ group: team, generation: 1, hop_exp: membership.exp })
    expect(lines('sign').map((l) => [l.decision, l.reason, l.from, l.root])).toEqual([
      ['accept', 'ok', null, P],
      ['reject', 'not-authorized', S.address, P],
    ])
    const opened = lines('open').filter((l) => l.decision === 'accept')
    expect(opened).toHaveLength(1)
    expect(opened[0]).toMatchObject({ reason: 'ok', id, from: S.address, root: P })
    expect(opened[0]?.detail).toEqual({ mailbox: team, rule: 'root', generation: 1 })
    expect(lines('open').map((l) => [l.decision, l.reason, l.detail?.mailbox])).toEqual([
      ['accept', 'ok', team],
      ['reject', 'not-authorized', team],
    ])

    console.log(
      [
        `MEASURE 46h: P's store held generations ${store.generations(team).join(',')}; login replayed it`,
        `(${lines('rotate').length} rotate line, 0 not-held lines); a session under a chain of ${chain.length} hops`,
        `rooted at the group opened the message (type ${'chat.v1'}); a group-rooted sign and P's own chain at G's`,
        `mailbox: not-authorized, not-authorized; the agent's audit: ${opened.length} accepted open line with generation`,
        `${opened[0]?.detail?.generation}, ${lines('sign').length} sign lines (1 accepted), ${log.length} lines in all, chain verified`,
      ].join(' '),
    )
    await verifyLogs([ha, hp, hs])
    noSecrets('46h', w, [
      ...homeSecrets(ha, ['team', 'cold']),
      ...homeSecrets(hp, ['pk']),
      ...homeSecrets(hs, ['s1']),
      ...S.secrets,
      ...other.secrets,
      ...generationSeeds(ha, 'team', team, 1),
    ])
  }, 240_000)

  // --- 46i, 46j (personal recovery; L7 and L8): `ac init`, `ac restore`
  // and `ac init --accept-loss`, through the CLI in child processes on a real relay.
  //
  //   46i  (L7)  restore in place: `ac init` prints the sheet, the device is lost, `ac restore` on a new home
  //                  from the sheet's four lines; the address is unchanged, the mail that waited is read, a group
  //                  member is re-added by its admin. At most 5 + g hand acts, 0 peer acts. Two of these lines are
  //                  asserted in their own case below: the bound (4 + g, plus the republish confirm) and the mail
  //                  read, 1 of 2 (forward secrecy: the mail that waited through the loss was sealed to an epoch
  //                  key only the lost device held).
  //   46j  (L8)  the two refusals: `ac init` with a wrong or absent checksum is `single-copy` with nothing stored
  //                  or published; `ac init --accept-loss` with a wrong or missing phrase is refused, the exact
  //                  phrase is accepted, and its audit line verifies.
  //
  // THE TERMINAL. `ac init` prints the sheet only when stdin AND stdout are terminals (Io.isTty, Io.outIsTty).
  // ../terminal.ts gives the child a terminal on stdin only (its stdout is a pipe), so `ac init` on it refuses
  // `no-tty` by design (46j asserts that). The sheet is therefore driven through a pseudo-terminal both ways: the
  // helper `sheeted` below is terminal.ts's pattern with the child's stdout on the same pty, the real command
  // unchanged, nothing faked. What the sheet prints is what the person sees: the test reads the four lines from that
  // screen, and the screen is the one place a seed may appear. Everything else the child prints (its stderr, and its
  // stdout with the two seed lines taken out) goes to `outputs`, where L6 counts. `ac restore` needs stdin alone
  // (it reads the sheet with the echo off, `stty -echo`, which works on the pty and is refused `no-tty` on a pipe),
  // so it runs on terminal.ts as is, with a pipe for stdout.

  /** terminal.ts's pty script with the child's stdout on the pty too; the master's output is the screen. */
  const SHEET_PTY = `
import os, pty, select, signal, subprocess, sys
master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave)
signal.signal(signal.SIGTERM, lambda *_: child.terminate())

def put(data):
    while data:
        data = data[os.write(1, data):]

fds = [0, master]
while child.poll() is None:
    for fd in select.select(fds, [], [], 0.05)[0]:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b''
        if fd == 0 and data:
            os.write(master, data)
        elif fd == master and data:
            put(data)
        elif not data:
            fds.remove(fd)
# The child has exited: what it wrote last is still in the master. This process keeps the slave open, so the master
# never reports a hangup; read until nothing comes for a moment.
while select.select([master], [], [], 0.3)[0]:
    try:
        data = os.read(master, 4096)
    except OSError:
        break
    if not data:
        break
    put(data)
code = child.returncode
sys.exit(code if code >= 0 else 128 - code)
`

  /** A CLI process with stdin and stdout on one terminal: the screen is what a person at it sees. */
  interface Sheeted extends Terminal {
    /** The screen: what the child wrote to its stdout, line by line (the terminal's carriage returns dropped). */
    screen(): string[]
    /** Text typed at the terminal as it is, with no newline (the end-of-file character is `\x04`). */
    raw(text: string): void
  }

  /** The two lines a seed is printed on; they are on the screen and nowhere else. */
  const SEED_LINE = /^(signing|rotation) [0-9a-f]{64}$/

  function sheeted(args: readonly string[], seen: string[]): Sheeted {
    const env: NodeJS.ProcessEnv = { ...process.env }
    delete env.AC_HOME
    const child = spawn('python3', ['-I', '-c', SHEET_PTY, process.execPath, CLI_MAIN, ...args], {
      cwd: REPO,
      env,
    })
    let out = ''
    let err = ''
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString()
    })
    child.stderr.on('data', (d: Buffer) => {
      err += d.toString()
    })
    child.stdin.on('error', () => {})
    const screen = (): string[] =>
      out
        .replaceAll('\r', '')
        .split('\n')
        .filter((l) => l !== '')
    const exit = new Promise<number>((resolve) => {
      child.on('error', (e) => {
        err += String(e)
        resolve(-1)
      })
      child.on('close', (code, signal) => {
        // The seed lines are the sheet itself; the rest of what the child printed is counted by L6.
        seen.push(
          screen()
            .filter((l) => !SEED_LINE.test(l))
            .join('\n'),
          err,
        )
        resolve(code ?? (signal === null ? -1 : 128))
      })
    })
    onTestFinished(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
    })
    return {
      out: screen,
      screen,
      err: () => err,
      type: (line) => child.stdin.write(`${line}\n`),
      raw: (text) => child.stdin.write(text),
      exit,
    }
  }

  /** The sheet's four lines on the screen, or null while they are not all there. */
  function sheetAt(screen: readonly string[]): string[] | null {
    const i = screen.findIndex((l) => l.startsWith('signing '))
    const sheet = i < 0 ? [] : screen.slice(i, i + SHEET_LINES)
    return sheet.length === SHEET_LINES && /^[0-9a-f]{8}$/.test(sheet[SHEET_LINES - 1] as string)
      ? sheet
      : null
  }

  /** What a person reads off the sheet: its lines, its checksum, the address its seeds make, and the seeds in hex. */
  interface Printed {
    readonly lines: string[]
    readonly checksum: string
    readonly address: string
    readonly secrets: string[]
  }

  /** Waits for the sheet and the checksum prompt, and reads the sheet as `ac restore` would. */
  async function printed(t: Sheeted): Promise<Printed> {
    await until(
      'the sheet on the terminal',
      () => sheetAt(t.screen()) !== null && t.err().includes('type the last line of the sheet'),
      30_000,
    )
    const lines = sheetAt(t.screen()) as string[]
    const read = readSheet(lines)
    if (typeof read === 'string') throw new Error(`the sheet on the terminal does not read: ${read}`)
    const { seeds } = read
    return {
      lines,
      checksum: lines[SHEET_LINES - 1] as string,
      address: seedKeys(seeds, new Uint8Array(32)).keys.signing.address,
      secrets: [seeds.sign, seeds.rotation].map(toHex),
    }
  }

  /** Waits until the child has written `text` to its stderr (its prompts are there). */
  const prompted = (t: Terminal, text: string): Promise<void> =>
    until(`"${text}" at the terminal`, () => t.err().includes(text), 30_000)

  /** Every regular file under a directory, keys and all, as relative names: a refused command leaves none. */
  const everyFile = (dir: string): string[] =>
    existsSync(dir)
      ? readdirSync(dir, { recursive: true })
          .map(String)
          .filter((n) => statSync(join(dir, n)).isFile())
          .sort()
      : []

  /** The address records the spawned relay has logged so far, `<kind> <signer>` (none when it is not spawned). */
  const logged = (w: World): string[] =>
    relayEvents(w.relay)
      .filter((e) => e.event === 'publish-record')
      .map((e) => `${e.kind} ${e.signer}`)

  /** The status the relay answers for the address record of `address`. */
  async function recordStatus(url: string, address: string): Promise<number> {
    const res = await fetch(`${url}/v0/fetch/record/${address}/address`)
    await res.arrayBuffer()
    return res.status
  }

  /** The lines of a CLI audit log, parsed (the detail as a JSON string, or null). */
  const auditLinesOf = (log: string) =>
    readAuditLines(log)
      .map(parseAuditLine)
      .map((l) => ({
        event: l.event,
        decision: l.decision,
        reason: l.reason,
        detail: l.detail === null ? null : (JSON.parse(l.detail) as Record<string, unknown>),
      }))

  const LOSS_PHRASE = 'I accept losing this identity'

  it('(46i) restore in place: the sheet, a new home, the same address; at most 5 + g hand acts, 0 peer acts', async () => {
    outputs.length = 0
    const w = await world('s46i')
    const R = w.url
    const homes = ['old', 'new', 'adm', 'peers', 'lone'].map((d) => join(w.dir, d))
    const [hold, hnew, adm, hp, hlone] = homes as [string, string, string, string, string]
    for (const h of homes) mkdirSync(h, { recursive: true, mode: 0o700 })
    const [team, cold] = (await keygen(adm, 'team', 'cold')) as [string, string]
    const [bob, carol] = (await keygen(hp, 'bob', 'carol')) as [string, string]
    const groups = 1

    // Before the loss, uncounted. dev is made by `ac init` on a terminal: the sheet is printed, its checksum typed
    // back, the identity and its rotation key stored, the address record published.
    const init = sheeted(['init', 'dev', '--relay', R, '--dir', hold], outputs)
    const sheet = await printed(init)
    init.type(sheet.checksum)
    expect(await exited(init, 'ac init dev')).toBe(0)
    const dev = sheet.address
    expect(init.screen()).toEqual(
      expect.arrayContaining([
        `published address ${dev} ${R}`,
        `published key ${dev} ${R}`,
        'recovery: printed sheet confirmed',
      ]),
    )
    // The sheet is printed once: each seed is on the screen exactly once.
    expect(occurrences([Buffer.from(init.screen().join('\n'))], sheet.secrets)).toBe(2)
    // dev reads mail from bob, carol and the group (the sheet's relay is the one relay here); both peers read dev.
    const accept = join(hold, 'dev.accept-from.json')
    const size = ['--max-bytes', '65536', '--ttl', '604800']
    const roots = [bob, carol, team].flatMap((r) => ['--root', r])
    await ok('record', 'accept-from', 'dev', ...roots, ...size, '--out', accept, '--dir', hold)
    await ok('publish', R, accept)
    await onboard(hp, 'bob', R, [dev])
    await onboard(hp, 'carol', R, [dev])
    await ok('group', 'create', 'team', '--relay', R, '--rotation-key', cold, '--dir', adm)
    await ok('group', 'add', 'team', dev, '--dir', adm)
    await ok('inbox', '--as', 'dev', '--relay', R, '--group', team, '--once', '--dir', hold)
    expect(new GroupKeyStore(join(hold, 'groups', 'dev')).generations(team)).toEqual([1])
    const before = await served(R, dev)
    expect(before.rotation_key).toMatch(/^ed25519:/)
    const recordsAtLoss = logged(w).length

    // THE LOSS. From here no step uses dev's keys or the old home. The peers' commands are the checks (their sends
    // are the messages whose first receipt is timed, as bob's post in 46d), kept apart from the acts.
    const acts: string[] = []
    const peerCommands: string[] = []
    const send = async (from: string, home: string, to: string, n: number): Promise<string> => {
      peerCommands.push(`send ${from}`)
      const body = `{"n":${n}}`
      const sent = await ok(
        ...['send', '--as', from, '--to', to, '--relay', R, '--type', 'chat.v1'],
        '--body',
        body,
        '--dir',
        home,
      )
      expect(sent.out[1]).toBe(`published ${R} tries=1`)
      return sent.out[0] as string
    }
    // bob writes while dev is gone: his message waits at the relay (the retention is seven days), sealed to the epoch
    // key the lost device held. The restore recovers the identity, not that key (restore recovers the identity, not past mail).
    const fromBob = await send('bob', hp, dev, 1)

    // 1 act: `ac restore dev` on the new device; 1 act: the sheet carried to it (its four lines typed, echo off);
    // 1 act: the checksum typed once more, to keep the sheet as the second copy.
    acts.push('command ac restore dev')
    const restore = terminal(['restore', 'dev', '--dir', hnew], outputs)
    await prompted(restore, `type the ${SHEET_LINES} lines of the sheet`)
    acts.push('carry the sheet')
    for (const line of sheet.lines) restore.type(line)
    // Restore cannot prove it holds the newest record, so it asks before it republishes. 1 act: the y.
    await prompted(restore, 'publish the address record anyway?')
    acts.push('confirm the republish')
    restore.type('y')
    await prompted(restore, 'type the last line of the sheet once more')
    acts.push('confirm the checksum again')
    restore.type(sheet.checksum)
    expect(await exited(restore, 'ac restore dev')).toBe(0)
    // A record is held at the relay; the warning names the un-revoke risk, and the one republish is the same keys, later.
    expect(restore.out()).toEqual([
      `published address ${dev} ${R}`,
      `published key ${dev} ${R}`,
      'restored dev',
      'recovery: printed sheet confirmed',
      `next: ac keygen dev-agent --custody agent --principal dev, then ac login --as dev-agent --relay ${R}`,
    ])
    expect(restore.err()).toContain('confirming may UN-REVOKE a key you revoked before')
    expect(restore.err()).not.toContain('no relay named holds a record')
    const after = await served(R, dev)
    expect([after.key, after.sealing_key, after.rotation_key, after.relays, after.revoked]).toEqual([
      dev,
      null,
      before.rotation_key,
      before.relays,
      before.revoked,
    ])
    expect(after.iat).toBeGreaterThan(before.iat)

    // Time passes, as a loss and a restore take: every peer's cached key record of dev (300 s at most, the forward-secrecy
    // ruling) lapses, so the next send and the admin's re-add resolve dev's new epoch. Not an act.
    for (const [home, name] of [
      [adm, 'team'],
      [hp, 'bob'],
      [hp, 'carol'],
    ] as const) {
      lapseKeyCache(join(home, 'state', name, 'edge.sqlite'), dev)
    }
    // carol writes after the restore, to the address she has always had.
    const fromCarol = await send('carol', hp, dev, 2)
    // 1 act per group: the group's admin re-adds dev (a renewal: the current generation, sent again).
    acts.push('command group add (the admin of team)')
    await ok('group', 'add', 'team', dev, '--dir', adm)
    // 1 act: the receive. `inbox --group` reads the identity's own mailbox first (the waiting mail, the generation),
    // then the group's.
    acts.push('command inbox --group')
    const got = await ok(
      ...['inbox', '--as', 'dev', '--relay', R, '--group', team, '--once'],
      ...['--trust-root', bob, '--trust-root', carol, '--dir', hnew],
    )
    // Measured for the registered line's own case: the messages to dev that dev read, of the two sent.
    const read = [fromBob, fromCarol].filter((id) => chatIds(got.out).includes(id)).length
    expect(chatIds(got.out)).toEqual([fromCarol])
    // The generation arrives from the admin's renewal (a key sent before the loss and left unacked would show as a
    // second line, with the same generation and the same key).
    const keyLines = got.out.filter((l) => l.startsWith('group-key '))
    expect(keyLines.length).toBeGreaterThan(0)
    for (const l of keyLines) expect(l).toMatch(new RegExp(`^group-key ${team} generation 1 `))
    expect(got.out).toContain(`accept ${fromCarol} ${carol} ${carol} chat.v1 {"n":2}`)
    // Forward secrecy: the mail that waited through the loss opens with no key the new device holds.
    expect(got.out.filter((l) => l.startsWith('reject '))).toEqual([`reject ${fromBob} open-failed`])
    expect(new GroupKeyStore(join(hnew, 'groups', 'dev')).generations(team)).toEqual([1])

    // The bound, 5 + g acts at most (4 + g plus the republish confirm), is asserted in its own case
    // below. Not acts: the peers' sends and the controls below.
    measured43g = { acts: acts.length, groups, read, sent: 2 }
    // Peer acts: none. Each peer ran its one send, nothing else to recover dev; the relay logged no record from
    // either peer, and two new records in all, dev's own: the address record with no sealing key, and epoch 1's key
    // record.
    expect(peerCommands).toEqual(['send bob', 'send carol'])

    // Controls, not acts: the restored dev writes as dev, and bob, whose accept-from names dev, reads it with no
    // pairing, no name forget, no new pin.
    const toBob = await ok(
      ...['send', '--as', 'dev', '--to', bob, '--relay', R, '--type', 'chat.v1', '--body', '{"n":3}'],
      ...['--dir', hnew],
    )
    peerCommands.push('inbox bob')
    const atBob = await ok('inbox', '--as', 'bob', '--relay', R, '--once', '--trust-root', dev, '--dir', hp)
    expect(atBob.out).toEqual([`accept ${toBob.out[0]} ${dev} ${dev} chat.v1 {"n":3}`])
    let newRecords = 0
    if (w.relay.spawned) {
      await until("dev's republish in the relay log", () => logged(w).length > recordsAtLoss)
      await sleep(300)
      const newer = logged(w).slice(recordsAtLoss)
      expect(newer.filter((r) => r.endsWith(` ${bob}`) || r.endsWith(` ${carol}`))).toEqual([])
      expect(newer.filter((r) => r.endsWith(` ${dev}`))).toEqual([`address ${dev}`, `key ${dev}`])
      newRecords = newer.length
    }

    // The new home: both keys (the identity and its rotation key), the state `sheet`, `keys list` showing it, and the
    // restore line first in the identity's audit log.
    // keys/ holds the identity, its rotation key, and groups/: the generation dev accepted, kept at rest.
    expect(readdirSync(join(hnew, 'keys')).sort()).toEqual(['dev.json', 'dev.rotation.json', 'groups'])
    const state = JSON.parse(readFileSync(join(hnew, `recovery-state.${dev}.json`), 'utf8'))
    expect(state).toEqual({ v: 1, copy: 'sheet', confirmed_at: expect.any(Number), stale_since: null })
    const listed = await ok('keys', 'list', '--dir', hnew)
    const line = listed.out.find((l) => l.startsWith('dev '))
    expect([line?.split(' ')[1], line]).toEqual([dev, expect.stringMatching(/ copy=sheet$/)])
    // A restore audits as every command outside an edge does, in the file of its own (the last-mile rulings, section 5).
    const log = join(hnew, 'state', 'dev', 'cli-audit.jsonl')
    expect(auditLinesOf(log)[0]).toEqual({
      event: 'restore',
      decision: 'accept',
      reason: 'ok',
      detail: { copy: 'sheet' },
    })
    // The new home's edge has run since (inbox, above): it started beside that file, and verify reads the two as a set.
    const verifiedSet = await ok('audit', 'verify', join(hnew, 'state', 'dev', 'audit.jsonl'))
    expect(verifiedSet.out.at(-1)).toMatch(/^cli-audit\.jsonl: ok \d+ lines$/)

    // With no record at any relay the restore asks, and publishes anew only on a y. The sheet here is made in the
    // test from the edge's own functions (a fresh identity never published), typed at `ac restore` as any sheet.
    const lone = newSeeds({ bytes: fresh })
    const loneLines = sheetLines(lone, R)
    const loneAddress = seedKeys(lone, new Uint8Array(32)).keys.signing.address
    const loneSecrets = [lone.sign, lone.rotation].map(toHex)
    const loneRun = async (answer: string, last: boolean): Promise<Terminal> => {
      const t = terminal(['restore', 'lone', '--dir', hlone], outputs)
      await prompted(t, `type the ${SHEET_LINES} lines of the sheet`)
      for (const l of loneLines) t.type(l)
      await prompted(t, 'publish the address record anyway?')
      t.type(answer)
      if (last) {
        await prompted(t, 'type the last line of the sheet once more')
        t.type(loneLines[SHEET_LINES - 1] as string)
      }
      return t
    }
    const declined = await loneRun('n', false)
    expect(await exited(declined, 'ac restore lone (n)')).toBe(1)
    expect(declined.err()).toContain('no relay named holds a record of')
    expect(declined.err()).toMatch(/bag: declined: /) // after the [y/N] prompt, on its line
    expect([everyFile(hlone), await recordStatus(R, loneAddress)]).toEqual([[], 404])
    const anew = await loneRun('y', true)
    expect(await exited(anew, 'ac restore lone (y)')).toBe(0)
    expect(anew.out()).toEqual([
      `published address ${loneAddress} ${R}`,
      `published key ${loneAddress} ${R}`,
      'restored lone (no record was held: published anew)',
      'recovery: printed sheet confirmed',
      `next: ac keygen lone-agent --custody agent --principal lone, then ac login --as lone-agent --relay ${R}`,
    ])
    expect(await recordStatus(R, loneAddress)).toBe(200)

    console.log(
      [
        `MEASURE 46i: restore in place took ${acts.length} hand acts (${acts.join('; ')}), registered bound 5 + g = ${5 + groups}`,
        '(4 + g plus the republish confirm)',
        `for g = ${groups}; peer acts 0 (the peers ran ${peerCommands.length} commands, all send or inbox, as checks;`,
        `${newRecords} new records in the relay log, dev's own address record and epoch 1's key record, none from a peer); the address is unchanged,`,
        `no sealing key in the record and the rotation key the same, iat later; dev read ${read} of 2 messages`,
        "(registered: 1 of 2; bob's mail during the loss rejects open-failed, carol's later mail accepted: forward",
        `secrecy: a restore recovers the identity, not past mail) and generation 1 of the group; the sheet was on the screen once (2 of 2 seeds once);`,
        'with no record held restore asked and n stored and published nothing (404, 0 files), y published anew (200)',
      ].join(' '),
    )
    await verifyLogs([hold, hnew, adm, hp, hlone])
    noSecrets('46i', w, [
      ...sheet.secrets,
      ...loneSecrets,
      ...homeSecrets(hold, ['dev', 'dev.rotation']),
      ...homeSecrets(hnew, ['dev', 'dev.rotation']),
      ...homeSecrets(hlone, ['lone', 'lone.rotation']),
      ...homeSecrets(adm, ['team', 'cold']),
      ...homeSecrets(hp, ['bob', 'carol']),
      ...generationSeeds(adm, 'team', team, 1),
    ])
  }, 240_000)

  // The bound: at most 5 + g hand acts, 4 + g plus the republish confirm (decided 2026-10-28: restore cannot prove
  // it holds the newest record, so it asks a y before any republish). 46i measures 6 acts for g = 1.
  it('(46i bound) restore in place in at most 5 + g hand acts', () => {
    expect(measured43g).not.toBeNull()
    const m = measured43g as { acts: number; groups: number }
    expect(m.acts).toBeLessThanOrEqual(5 + m.groups)
  })

  // The read line: 1 of 2 messages to dev, one sent during the loss and one after. Under forward secrecy
  // (decided 2026-10-28: a restore recovers the identity, not past mail) bob's mail during the loss was sealed to an epoch key only the lost device held and
  // rejects open-failed, and carol's mail after is read. 46i itself asserts that behaviour.
  it('(46i read) the mail sent after the restore is read, 1 of 2', () => {
    expect(measured43g).not.toBeNull()
    const m = measured43g as { read: number; sent: number }
    expect([m.read, m.sent]).toEqual([1, 2])
  })
  it('(46j, 43h) the two refusals: a bad or absent checksum and a bad or missing phrase store and publish nothing', async () => {
    outputs.length = 0
    const w = await world('s46j')
    const R = w.url
    const homes = ['sheet', 'loss', 'plain'].map((d) => join(w.dir, d))
    const [hs, hl, hn] = homes as [string, string, string]
    for (const h of homes) mkdirSync(h, { recursive: true, mode: 0o700 })
    const secrets: string[] = []
    const single = /^bag: single-copy: .*nothing was stored or published$/m

    // `ac init` on a terminal, the sheet printed, and the checksum answered wrongly (one character changed), with an
    // empty line, and with the end of input (control-D). Each is `single-copy`, exit 1, nothing stored or published:
    // no file in the home, a 404 at the relay for the address the printed seeds make.
    const refused = async (what: string, answer: (t: Sheeted, sheet: Printed) => void): Promise<void> => {
      const t = sheeted(['init', 'alice', '--relay', R, '--dir', hs], outputs)
      const sheet = await printed(t)
      secrets.push(...sheet.secrets)
      answer(t, sheet)
      expect([what, await exited(t, what)]).toEqual([what, 1])
      expect([what, single.test(t.err())]).toEqual([what, true])
      expect(t.screen().filter((l) => l.startsWith('published ') || l.startsWith('recovery:'))).toEqual([])
      expect(occurrences([Buffer.from(t.screen().join('\n'))], sheet.secrets)).toBe(2)
      expect([what, everyFile(hs), await recordStatus(R, sheet.address)]).toEqual([what, [], 404])
    }
    await refused('wrong checksum', (t, s) =>
      t.type(s.checksum.replace(/.$/, (c) => (c === '0' ? '1' : '0'))),
    )
    await refused('empty answer', (t) => t.type(''))
    await refused('no answer (end of input)', (t) => t.raw('\x04'))
    expect(logged(w)).toEqual([])

    // The same home takes the right checksum: the refusals were the checksum and nothing else (the control).
    const control = sheeted(['init', 'alice', '--relay', R, '--dir', hs], outputs)
    const sheet = await printed(control)
    secrets.push(...sheet.secrets)
    control.type(sheet.checksum)
    expect(await exited(control, 'ac init alice')).toBe(0)
    expect(control.screen()).toEqual(
      expect.arrayContaining([
        `published address ${sheet.address} ${R}`,
        `published key ${sheet.address} ${R}`,
        'recovery: printed sheet confirmed',
      ]),
    )
    expect((await served(R, sheet.address)).key).toBe(sheet.address)
    expect(JSON.parse(readFileSync(join(hs, `recovery-state.${sheet.address}.json`), 'utf8'))).toMatchObject({
      copy: 'sheet',
      stale_since: null,
    })

    // Without the terminals: stdin a pipe is `no-tty` for the sheet and for --accept-loss, and stdin a terminal with
    // stdout a pipe is `no-tty` and prints no sheet. Nothing is stored.
    for (const more of [[], ['--accept-loss']]) {
      const piped = await cli('init', 'nobody', '--relay', R, ...more, '--dir', hn)
      expect([more, piped.code, why(piped), piped.out]).toEqual([more, 1, 'no-tty', []])
    }
    const outPiped = terminal(['init', 'nobody', '--relay', R, '--dir', hn], outputs)
    expect(await exited(outPiped, 'ac init with stdout a pipe')).toBe(1)
    expect([outPiped.out(), outPiped.err()]).toEqual([[], expect.stringMatching(/^bag: no-tty: /)])
    expect(everyFile(hn)).toEqual([])

    // `--accept-loss`: no sheet. A wrong phrase, an empty line, a phrase in the wrong case and the end of input are
    // refused `single-copy`, exit 1, nothing stored. stdout may be a pipe here (no sheet is printed).
    const loss = async (answer: (t: Terminal) => void): Promise<Terminal> => {
      const t = terminal(['init', 'bob', '--relay', R, '--accept-loss', '--dir', hl], outputs)
      await prompted(t, `type exactly: ${LOSS_PHRASE}`)
      answer(t)
      return t
    }
    const phrases: [string, (t: Terminal) => void][] = [
      ['a shorter phrase', (t) => t.type('I accept losing this')],
      ['an empty line', (t) => t.type('')],
      ['the phrase in lower case', (t) => t.type(LOSS_PHRASE.toLowerCase())],
      ['the phrase with a space after', (t) => t.type(`${LOSS_PHRASE} `)],
      ['the end of input', (t) => t.type('\x04')],
    ]
    for (const [what, answer] of phrases) {
      const t = await loss(answer)
      expect([what, await exited(t, what)]).toEqual([what, 1])
      expect([what, single.test(t.err()), t.out(), everyFile(hl)]).toEqual([what, true, [], []])
    }
    // alice's own two records from the control (the address record and epoch 1's key record) are all the relay has
    // logged: nothing from a refusal.
    await until("alice's records in the relay log", () => !w.relay.spawned || logged(w).length >= 2)
    expect(logged(w).length).toBe(w.relay.spawned ? 2 : 0)

    // The exact phrase is accepted: exit 0, the identity and its rotation key stored, the record published, the
    // state `none`, `keys list` showing it, and one audit line that verifies and holds no key.
    const exact = await loss((t) => t.type(LOSS_PHRASE))
    expect(await exited(exact, 'the exact phrase')).toBe(0)
    const bobAddress = exact.out()[0]?.split(' ')[2] as string
    expect(exact.out()).toEqual([
      `published address ${bobAddress} ${R}`,
      `published key ${bobAddress} ${R}`,
      'recovery: none (accepted at ac init)',
    ])
    expect((await served(R, bobAddress)).key).toBe(bobAddress)
    expect(readdirSync(join(hl, 'keys')).sort()).toEqual(['bob.json', 'bob.rotation.json'])
    expect(JSON.parse(readFileSync(join(hl, `recovery-state.${bobAddress}.json`), 'utf8'))).toEqual({
      v: 1,
      copy: 'none',
      confirmed_at: null,
      stale_since: null,
    })
    const listed = await ok('keys', 'list', '--dir', hl)
    expect(listed.out.find((l) => l.startsWith('bob '))).toMatch(/ copy=none$/)
    const log = join(hl, 'state', 'bob', 'cli-audit.jsonl')
    const verified = await ok('audit', 'verify', log)
    expect(verified.out).toEqual(['ok 2 lines'])
    expect(auditLinesOf(log)).toEqual([
      { event: 'onboard', decision: 'accept', reason: 'ok', detail: { copy: 'none' } },
      {
        event: 'rotate',
        decision: 'accept',
        reason: 'ok',
        detail: {
          subject: `key:${bobAddress}`,
          epoch: 1,
          sealing_key: expect.stringMatching(/^[0-9a-f]{64}$/),
          exp: expect.any(Number),
          resigned: false,
          republished: false,
          deleted: [],
        },
      },
    ])

    console.log(
      [
        'MEASURE 46j (43h): ac init with a wrong checksum, an empty answer and no answer: 3 of 3',
        'exit 1 single-copy, 0 files in the home, 404 at the relay for the printed seeds, 0 records logged;',
        'the right checksum then published (control); stdin a pipe: no-tty x2 (the sheet and --accept-loss),',
        'stdout a pipe: no-tty and no sheet; --accept-loss with 5 bad answers (short, empty, lower case,',
        'trailing space, end of input): 5 of 5 exit 1 single-copy, 0 files; the exact phrase: exit 0, state none,',
        'copy=none in keys list, 2 audit lines (onboard accept copy none, then rotate accept for epoch 1) that ac audit verify reads as "ok 2 lines"',
      ].join(' '),
    )
    await verifyLogs([hs, hl, hn])
    noSecrets('46j', w, [
      ...secrets,
      ...homeSecrets(hs, ['alice', 'alice.rotation']),
      ...homeSecrets(hl, ['bob', 'bob.rotation']),
    ])
  }, 240_000)
})
