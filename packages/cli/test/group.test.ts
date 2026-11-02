import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AddressRecord,
  decodeAddress,
  MEMBERSHIP_SECONDS,
  openGroupKey,
  parseEnvelope,
  parseRecord,
  toHex,
} from '@usebag/core'
import { GroupKeyStore, KeyEpochStore } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { loadKeys } from '../src/home.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli, type Ran } from './support/run.ts'

// Lines L1 to L6 for the group commands: the admin's home, two
// members' homes and an outsiders' home, each its own --dir, on two in-process relays by URL (support/network.ts,
// which refuses a root a mailbox's accept-from does not list, 403 root-not-accepted): G, the group's, and M, the
// members'. The steps build on each other, in order, as a person would run them. L7 is the gate's.

const tmp = tempDir('group')
afterAll(() => tmp.cleanup())
const [G, M] = ['http://127.0.0.1:1', 'http://127.0.0.1:2']
const P = '--allow-private-relays'

const net = new Network()
// Members share the group's mailbox at G: each run reads it from its start, and its own store skips what it handled.
net.at(G).replay = true
const io = testIo(net)
const dirs = { admin: '', bob: '', carol: '', out: '', cold: '' }
const who = { team: '', bob: '', carol: '', alice: '', dave: '', cold: '', solo: '' }

const run = (dir: string, ...argv: string[]): Promise<Ran> => cli(io, ...argv, '--dir', dir, P)
const admin = (...argv: string[]): Promise<Ran> => run(dirs.admin, 'group', ...argv)
const groupInbox = (as: 'bob' | 'carol', ...more: string[]): Promise<Ran> =>
  run(dirs[as], 'inbox', '--as', as, '--relay', M, '--group', 'team', '--once', ...more)
const post = (dir: string, as: string, to: string, body: string, ...more: string[]): Promise<Ran> =>
  run(dir, 'send', '--as', as, '--to', to, '--relay', G, '--type', 'chat.v1', '--body', body, ...more)
const short = (a: string): string => `${a.slice(0, 'ed25519:'.length + 8)}…`
const record = (url: string, signer: string, kind: string) =>
  parseRecord(net.record(url, signer, kind) as string)
const groupDir = (dir: string, name: string): string =>
  join(dir, 'groups', name, toHex(decodeAddress(who.team)))

/** A member: an identity in its own home with its address record and an accept-from record admitting the group. */
async function member(name: 'bob' | 'carol'): Promise<void> {
  const dir = dirs[name]
  for (const [kind, ...more] of [
    ['address', '--relay', M, '--sealing-key'],
    ['accept-from', '--root', who.team, '--root', who.alice, '--max-bytes', '65536', '--ttl', '604800'],
  ] as const) {
    const file = join(dir, `${name}.${kind}.json`)
    await cli(io, 'record', kind, name, ...more, '--out', file, '--dir', dir)
    await cli(io, 'publish', M, file)
  }
  await cli(io, 'name', 'add', 'team', who.team, '--dir', dir)
  await cli(io, 'name', 'add', name, who[name], '--dir', dirs.admin)
}

describe('the group commands, an admin and two members on two relays', () => {
  it('setup: five homes, the identities and the members records', async () => {
    for (const k of Object.keys(dirs) as (keyof typeof dirs)[]) dirs[k] = join(tmp.dir, k)
    const keygen = async (name: string, dir: string) =>
      (await cli(io, 'keygen', name, '--dir', dir)).out[0] as string
    who.team = await keygen('team', dirs.admin)
    who.solo = await keygen('solo', dirs.admin)
    who.cold = await keygen('cold', dirs.cold)
    who.bob = await keygen('bob', dirs.bob)
    who.carol = await keygen('carol', dirs.carol)
    who.alice = await keygen('alice', dirs.out)
    who.dave = await keygen('dave', dirs.out)
    expect(Object.values(who).every((a) => a.startsWith('ed25519:'))).toBe(true)
  })

  it('L1: create prints the address, generation 1 and each publish; the records and the store follow', async () => {
    const before = await admin('add', 'team', who.bob)
    expect(before.err[0]).toBe(`bag: ENOENT: groups: no admin state of ${who.team} is kept here`)
    const missing = await admin('create', 'team', '--relay', G)
    expect(missing.err[0]).toBe('bag: usage: --rotation-key is required')
    expect((await admin()).err[0]).toBe('bag: usage: group create|add|remove|rotate|keep <name> ...')
    const roots = ['--root', who.alice, '--root', who.dave]
    const made = await admin('create', 'team', '--relay', G, '--rotation-key', who.cold, ...roots)
    expect(made.code).toBe(0)
    expect(made.out).toEqual([
      `group ${who.team} generation 1`,
      `published address ${who.team} iat ${T0} ${G}`,
      `published accept-from ${who.team} iat ${T0} ${G}`,
    ])
    const address = record(G, who.team, 'address') as AddressRecord
    expect(address.rotation_key).toBe(who.cold)
    expect(address.ttl).toBe(3600)
    expect((record(G, who.team, 'accept-from') as AcceptFromRecord).roots).toEqual([
      who.team,
      who.alice,
      who.dave,
    ])
    const dir = groupDir(dirs.admin, 'team')
    expect(readdirSync(dir).sort()).toEqual(['g1.json', 'state.json'])
    expect([statSync(dir).mode & 0o777, statSync(join(dir, 'g1.json')).mode & 0o777]).toEqual([0o700, 0o600])
    const again = await admin('create', 'team', '--relay', G, '--rotation-key', who.cold)
    expect(again.err[0]).toBe(`bag: EEXIST: groups: ${who.team} is kept here already`)
    // The record's numbers as options: a second group, solo, on both relays.
    const numbers = ['--ttl', '7200', '--max-bytes', '9000', '--retention', '600']
    const solo = await admin(
      'create',
      'solo',
      '--relay',
      G,
      '--relay',
      M,
      '--rotation-key',
      who.cold,
      ...numbers,
    )
    expect(solo.out.slice(1)).toEqual([
      `published address ${who.solo} iat ${T0} ${G}`,
      `published address ${who.solo} iat ${T0} ${M}`,
      `published accept-from ${who.solo} iat ${T0} ${G}`,
      `published accept-from ${who.solo} iat ${T0} ${M}`,
    ])
    expect((record(M, who.solo, 'address') as AddressRecord).ttl).toBe(7200)
    const accept = record(M, who.solo, 'accept-from') as AcceptFromRecord
    expect([accept.max_bytes, accept.ttl]).toEqual([9000, 600])
    console.log(`MEASURE groups L1: ${made.out.length} lines printed; files ${readdirSync(dir).join(', ')}`)
  })

  it('L2: add carries generation 1 to each member on the other relay, again renews, remove sends generation 2', async () => {
    await member('bob')
    await member('carol')
    const bob = await admin('add', 'team', 'bob', '--relay-hint', M)
    expect(bob.code).toBe(0)
    expect(bob.out[0]).toBe(`added ${who.bob} exp ${T0 + MEMBERSHIP_SECONDS}`)
    expect(bob.out[1]).toMatch(/^[0-9a-f]{64}$/)
    expect(bob.out[2]).toBe(`published ${M} tries=1`)
    const got = await groupInbox('bob')
    expect(got.code).toBe(0)
    expect(got.out).toContain(`group-key team (${short(who.team)}) generation 1 new`)
    expect(existsSync(join(groupDir(dirs.bob, 'bob'), 'g1.json'))).toBe(true)
    expect((await admin('add', 'team', who.carol, '--relay-hint', M)).code).toBe(0)
    expect((await groupInbox('carol')).out).toContain(`group-key team (${short(who.team)}) generation 1 new`)
    const fromTeam = (): number =>
      [...net.at(M).envelopes.values()].filter((b) => parseEnvelope(b).from === who.team).length
    expect(fromTeam()).toBe(2)
    io.time.now += 10
    const renewed = await admin('add', 'team', 'bob', '--exp', `${T0 + MEMBERSHIP_SECONDS + 3_600}`)
    expect(renewed.out[0]).toBe(`added ${who.bob} exp ${T0 + MEMBERSHIP_SECONDS + 3_600}`)
    expect((await groupInbox('bob')).out).toContain(
      `group-key team (${short(who.team)}) generation 1 renewed`,
    )
    console.log(
      `MEASURE groups L2: 2 group-key.v1 envelopes for 2 members and 1 generation; ${fromTeam()} after the renewal`,
    )
  })

  it('L5: a member posts to the group under its hop; the other reads it, the root named by its book', async () => {
    const sent = await post(dirs.carol, 'carol', 'team', '{"n":1}')
    expect(sent.code).toBe(0)
    const env = parseEnvelope(net.at(G).envelopes.get(sent.out[0] as string) as Uint8Array)
    expect(env.to).toEqual([who.team])
    expect(env.auth.map((h) => [h.iss, h.sub, h.caveats])).toEqual([
      [who.team, who.carol, [`group=${who.team}`]],
    ])
    const read = await groupInbox('bob')
    const line = `accept ${env.id} ${who.carol} team (${short(who.team)}) chat.v1 {"n":1}`
    expect(read.out).toContain(line)
    // The admin posts to its own group as the group's root, under no hop.
    const own = await post(dirs.admin, 'team', who.team, '{"n":0}')
    expect(parseEnvelope(net.at(G).envelopes.get(own.out[0] as string) as Uint8Array).auth).toEqual([])
    // A --to of two recipients never takes the hop: carol's own root is refused at the group's mailbox.
    const two = await post(dirs.carol, 'carol', 'team', '{}', '--to', who.bob, '--relay', M)
    expect(two.err[0]).toMatch(/^bag: root-not-accepted: /)
    // A run of the member's own mailbox reads other mail as before, beside the group's keys.
    expect((await post(dirs.out, 'alice', who.bob, '{"direct":1}', '--relay', M)).code).toBe(0)
    const direct = await groupInbox('bob', '--trust-root', who.alice)
    expect(direct.out.filter((l) => l.includes('{"direct":1}'))).toHaveLength(1)
    expect(
      (await run(dirs.bob, 'inbox', '--as', 'bob', '--relay', M, '--group', 'team', '--quarantined')).err[0],
    ).toBe('bag: usage: --group: no release, drop, --quarantined')
    console.log(
      `MEASURE groups L5: to ${env.to.length} address, ${env.auth.length} hop; bob printed "${line}"`,
    )
  })

  it('L3: after remove, the removed member refuses the next post open-failed; rotate reaches the rest', async () => {
    const removed = await admin('remove', 'team', 'carol')
    expect(removed.out).toEqual([`generation 2 sent 1 record iat ${io.time.now}`])
    expect((await groupInbox('bob')).out).toContain(`group-key team (${short(who.team)}) generation 2 new`)
    expect((await groupInbox('carol')).out.filter((l) => l.startsWith('group-key'))).toEqual([])
    // alice has never read the group's record, so her cache is older than its ttl: she seals to generation 2.
    const sent = await post(dirs.out, 'alice', who.team, '{"n":2}')
    const id = sent.out[0] as string
    const bob = await groupInbox('bob', '--trust-root', who.alice)
    expect(bob.out).toContain(`accept ${id} ${who.alice} ${who.alice} chat.v1 {"n":2}`)
    const carol = await groupInbox('carol', '--trust-root', who.alice)
    expect(carol.out).toContain(`reject ${id} open-failed`)
    io.time.now += 10
    const rotated = await admin('rotate', 'team')
    expect(rotated.out).toEqual([`generation 3 sent 1 record iat ${io.time.now}`])
    expect((await groupInbox('bob')).out).toContain(`group-key team (${short(who.team)}) generation 3 new`)
    const g3 = new GroupKeyStore(join(dirs.bob, 'groups', 'bob')).body(who.team, 3).sealing_key
    expect((record(G, who.team, 'address') as AddressRecord).sealing_key).toBe(g3)
    const third = (await post(dirs.out, 'dave', who.team, '{"n":3}')).out[0] as string
    expect((await groupInbox('bob', '--trust-root', who.dave)).out).toContain(
      `accept ${third} ${who.dave} ${who.dave} chat.v1 {"n":3}`,
    )
    expect((await groupInbox('carol', '--trust-root', who.dave)).out).toContain(`reject ${third} open-failed`)
    expect((await admin('remove', 'team', 'carol')).err[0]).toBe(
      `bag: ENOENT: groups: ${who.carol} is not a member of ${who.team}`,
    )
    console.log('MEASURE groups L3: carol open-failed on 2 of 2 posts after her removal; bob accepted 2 of 2')
  })

  it('L4: keep re-signs the record now, at the members relays too, and on its loop until the stop signal', async () => {
    // An hour on, every copy of the record has lapsed: a member on another relay cannot find the group's mailbox.
    io.time.now += 4000
    const lapsed = await groupInbox('bob')
    expect(lapsed.err[0]).toMatch(/^bag: resolve-failed: .* \(record-expired\)$/)
    const once = await admin('keep', 'team', '--once')
    expect(once.out).toEqual([
      `published address ${who.team} iat ${io.time.now} ${G}`,
      `published address ${who.team} iat ${io.time.now} ${M}`,
    ])
    expect((record(M, who.team, 'address') as AddressRecord).iat).toBe(io.time.now)
    expect((await groupInbox('bob')).code).toBe(0)
    const kept = record(G, who.team, 'address') as AddressRecord
    expect(kept.iat).toBe(io.time.now)
    expect(kept.sealing_key).toBe(
      new GroupKeyStore(join(dirs.bob, 'groups', 'bob')).body(who.team, 3).sealing_key,
    )
    expect((await admin('keep', 'team', '--every', '3600')).err[0]).toBe(
      "bag: usage: --every 3600 is not below the record's ttl, 3600 s",
    )
    // The loop on an io of its own, whose stop signal this test aborts.
    const loopIo: TestIo = testIo(net)
    loopIo.time.now = io.time.now + 10
    const looping = cli(loopIo, 'group', 'keep', 'team', '--every', '1', '--dir', dirs.admin, P)
    const end = Date.now() + 10_000
    while (loopIo.stdout.filter((l) => l.startsWith('next ')).length < 2 && Date.now() < end) {
      await new Promise((r) => setTimeout(r, 20))
    }
    loopIo.stop.abort()
    const ran = await looping
    expect(ran.code).toBe(0)
    const t = loopIo.time.now
    expect(ran.out).toEqual([
      `published address ${who.team} iat ${t} ${G}`,
      `published address ${who.team} iat ${t} ${M}`,
      `next ${t + 1}`,
      `published address ${who.team} iat ${t + 1} ${G}`,
      `published address ${who.team} iat ${t + 1} ${M}`,
      `next ${t + 2}`,
    ])
    console.log(
      `MEASURE groups L4: after 4,000 s bob's run "${lapsed.err[0]}"; keep --once ${once.out.length} lines (G and M), then bob's run 0; the loop ${ran.out.length} lines, then 0 on the signal`,
    )
  })

  it('L6: the audit logs verify, the admin names each step, and no generation key is in any output or file', async () => {
    const log = join(dirs.admin, 'state', 'team', 'audit.jsonl')
    const verified = await cli(io, 'audit', 'verify', log)
    expect(verified.code).toBe(0)
    expect(verified.out[0]).toMatch(/^ok \d+ lines$/)
    const steps = readFileSync(log, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { event: string; decision: string; detail?: string })
      .filter((l) => l.event === 'rotate' && l.decision === 'accept')
      .map(
        (l) =>
          JSON.parse(l.detail as string) as { action: string; generation: number; member: string | null },
      )
    expect(steps.map((s) => [s.action, s.generation, s.member])).toEqual([
      ['add', 1, who.bob],
      ['add', 1, who.carol],
      ['add', 1, who.bob],
      ['remove', 2, who.carol],
      ['rotate', 3, null],
    ])
    for (const m of ['bob', 'carol'] as const) {
      expect((await cli(io, 'audit', 'verify', join(dirs[m], 'state', m, 'audit.jsonl'))).code).toBe(0)
    }
    // The seeds of the three generations, from the admin's own copies, opened with the group's identity key.
    const keys = loadKeys(io, dirs.admin, 'team')
    const store = new GroupKeyStore(join(dirs.admin, 'groups', 'team'))
    const seeds = [1, 2, 3].map((n) =>
      Buffer.from(
        openGroupKey(
          store.body(who.team, n),
          { address: who.team, key: keys.sealing },
          io.time.now,
        ).key.exportSeed(),
      ),
    )
    const forms = (seed: Buffer): Buffer[] =>
      [seed.toString('hex'), seed.toString('base64'), seed.toString('base64url')].map((t) => Buffer.from(t))
    const files = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.name === 'keys' ? [] : e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)],
      )
    const scanned = Object.values(dirs).flatMap(files)
    const hits = (bytes: Buffer): number =>
      seeds.flatMap((s) => [s, ...forms(s)]).filter((needle) => bytes.includes(needle)).length
    const output = Buffer.from([...io.stdout, ...io.stderr].join('\n'))
    const found = hits(output) + scanned.reduce((n, f) => n + hits(readFileSync(f)), 0)
    expect(found).toBe(0)
    const control = join(tmp.dir, 'control.txt')
    writeFileSync(control, `x ${(seeds[0] as Buffer).toString('hex')} y`)
    expect(hits(readFileSync(control))).toBe(1)
    console.log(
      `MEASURE groups L6: audit ok; steps ${steps.map((s) => s.action).join(', ')}; 0 of ${seeds.length} seeds in ${io.stdout.length + io.stderr.length} output lines and ${scanned.length} files; control 1`,
    )
  })

  it('forward secrecy (the groups seam): a member reads a generation it holds after the epoch key that delivered it is deleted', async () => {
    // bob moves to forward secrecy: an epoch, its key record, and his address record re-signed with no sealing key.
    const moved = await cli(io, 'keys', 'rotate', 'bob', '--relay', M, '--dir', dirs.bob)
    expect([moved.code, moved.out[0]]).toEqual([0, `published key ${who.bob} ${M}`])
    // An hour on (past every cached record of the group's), the admin rotates: generation 4 is sealed to bob's key
    // record, which his resolver prefers, and bob accepts it with his epoch key.
    io.time.now += 3601
    expect((await admin('rotate', 'team')).code).toBe(0)
    expect((await groupInbox('bob')).out).toContain(`group-key team (${short(who.team)}) generation 4 new`)
    // The opened generation key is kept at rest under keys/ (outside L6's scan), 0600, beside bob's own seed.
    const kept = join(dirs.bob, 'keys', 'groups', 'bob', toHex(decodeAddress(who.team)), 'g4.key')
    expect(statSync(kept).mode & 0o777).toBe(0o600)
    // bob's epoch keys are deleted past their horizon: none is held, and no key of his opens generation 4's wrap.
    const epochs = new KeyEpochStore(join(dirs.bob, 'key-records'))
    epochs.prune(who.bob, io.time.now + 30 * 86_400, 0, 0)
    expect(epochs.epochs(who.bob)).toEqual([])
    // dave posts to the group under generation 4; bob reads it with the kept key.
    const id = (await post(dirs.out, 'dave', who.team, '{"n":4}')).out[0] as string
    expect((await groupInbox('bob', '--trust-root', who.dave)).out).toContain(
      `accept ${id} ${who.dave} ${who.dave} chat.v1 {"n":4}`,
    )
    console.log('MEASURE groups seam: bob read a generation-4 post after his epoch keys were deleted')
  })
})
