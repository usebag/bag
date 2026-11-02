import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_SKEW,
  DEFAULT_TTL,
  generateSealingKey,
  newThread,
  type OpenerLike,
  openSealed,
  parseRecord,
  sealTo,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import {
  type EdgeKeys,
  generateEdgeKeys,
  HomeCustody,
  INCOMPLETE_REVOCATION,
  RelayError,
  systemRng,
} from '@usebag/edge'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { groupStore } from '../src/commands/group.ts'
import { epochStore, receivingKeys } from '../src/home.ts'
import { instant } from '../src/names.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { FakeSecurity, forms, occurrences } from './support/security.ts'

// L4: keys list prints each identity's name, address, custody and created time (an ISO 8601 UTC instant to
// the second), never key material, and reads no keychain, so it raises no dialog. As a process its stderr is clean:
// main.ts drops Node's SQLite ExperimentalWarning (src/warnings.ts).

const tmp = tempDir('keys')
afterAll(() => tmp.cleanup())
let n = 0
const LINE =
  /^[a-z0-9][a-z0-9._-]{0,63} ed25519:[0-9a-f]{64} (file|keychain|agent) (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ|-)$/
const MAIN = fileURLToPath(new URL('../src/main.ts', import.meta.url))

describe('keys list (L4)', () => {
  it('lists file and keychain identities by name, with the addresses keygen printed, and no key material', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const dir = join(tmp.dir, `home-${n++}`)
    const made = new Map<string, string>()
    const start = Math.floor(Date.now() / 1000)
    for (const [name, custody] of [
      ['zoe', 'file'],
      ['bob', 'keychain'],
      ['amy', 'file'],
      ['dan', 'keychain'],
    ] as const) {
      const r = await cli(io, 'keygen', name, '--custody', custody, '--dir', dir)
      expect(r.code).toBe(0)
      made.set(name, r.out[0] as string)
    }
    const end = Math.floor(Date.now() / 1000)
    const calls = fake.calls.length
    const listed = await cli(io, 'keys', 'list', '--dir', dir)
    expect(fake.calls.length).toBe(calls)
    expect(listed.code).toBe(0)
    expect(listed.err).toEqual([])
    expect(listed.out).toHaveLength(4)
    for (const line of listed.out) expect(line).toMatch(LINE)
    expect(listed.out.map((l) => l.split(' ').slice(0, 3))).toEqual([
      ['amy', made.get('amy'), 'file'],
      ['bob', made.get('bob'), 'keychain'],
      ['dan', made.get('dan'), 'keychain'],
      ['zoe', made.get('zoe'), 'file'],
    ])
    for (const line of listed.out) {
      const created = Date.parse(line.split(' ')[3] as string) / 1000
      expect(Number.isInteger(created)).toBe(true)
      expect(created).toBeGreaterThanOrEqual(start - 5)
      expect(created).toBeLessThanOrEqual(end + 5)
    }
    const fileSeeds = ['amy', 'zoe'].flatMap((name) => {
      const f = JSON.parse(readFileSync(join(dir, 'keys', `${name}.json`), 'utf8')) as Record<string, string>
      return [Buffer.from(f.sign_seed as string, 'hex'), Buffer.from(f.seal_priv as string, 'hex')]
    })
    const needles = [...fileSeeds, ...fake.seeds()].flatMap(forms)
    expect(needles.length).toBe(8 * 6)
    expect(occurrences(listed.out.join('\n'), needles)).toBe(0)
    console.log(
      `MEASURE L4: keys list printed ${listed.out.length} lines, ${fake.calls.length - calls} security calls, 0 seeds`,
    )
  })

  it('lists an identity the agent holds as custody agent from its pointer: no agent asked, no keychain called, no seed', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const dir = join(tmp.dir, `home-${n++}`)
    const amy = (await cli(io, 'keygen', 'amy', '--dir', dir)).out[0]
    const held = generateEdgeKeys(io.rng)
    new HomeCustody(dir).agent.create('zed', held)
    const listed = await cli(io, 'keys', 'list', '--dir', dir)
    expect([listed.code, listed.err]).toEqual([0, []])
    for (const line of listed.out) expect(line).toMatch(LINE)
    expect(listed.out.map((l) => l.split(' ').slice(0, 3))).toEqual([
      ['amy', amy, 'file'],
      ['zed', held.signing.address, 'agent'],
    ])
    const needles = [held.signing.exportSeed(), held.sealing.exportSeed()].flatMap(forms)
    const pointer = readFileSync(join(dir, 'agent', 'zed.json'), 'utf8')
    expect([fake.calls.length, occurrences(`${listed.out.join('\n')}\n${pointer}`, needles)]).toEqual([0, 0])
  })

  it('prints the address of an identity the agent holds, and refuses to open or sign as it: not-authorized', async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, `home-${n++}`)
    const held = generateEdgeKeys(io.rng)
    new HomeCustody(dir).agent.create('zed', held)
    expect((await cli(io, 'address', 'zed', '--dir', dir)).out).toEqual([held.signing.address])
    const relay = 'http://127.0.0.1:9'
    const refused = await cli(io, 'inbox', '--as', 'zed', '--relay', relay, '--once', '--dir', dir)
    expect([refused.code, refused.out, refused.err]).toEqual([
      1,
      [],
      ["bag: not-authorized: zed is held by the agent, which signs a session's hops only"],
    ])
  })

  it('prints the created time in Unix seconds as an ISO 8601 UTC instant, and - for one its custody does not know (a custody may not)', async () => {
    const address = `ed25519:${'ab'.repeat(32)}`
    const spy = vi.spyOn(HomeCustody.prototype, 'list').mockReturnValueOnce([
      { name: 'w', address, custody: 'file', created: 1_792_941_104 },
      { name: 'x', address, custody: 'keychain', created: null },
      { name: 'y', address, custody: 'file', created: 0 },
    ])
    expect((await cli(testIo(new MemoryRelay()), 'keys', 'list', '--dir', tmp.dir)).out).toEqual([
      `w ${address} file 2026-10-25T15:11:44Z`,
      `x ${address} keychain -`,
      `y ${address} file 1970-01-01T00:00:00Z`,
    ])
    spy.mockRestore()
  })

  it('as a process, prints its lines with a clean stderr: no SQLite ExperimentalWarning', async () => {
    const dir = join(tmp.dir, `home-${n++}`)
    const made = await cli(testIo(new MemoryRelay()), 'keygen', 'amy', '--dir', dir)
    expect(made.code).toBe(0)
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: tmp.dir }
    delete env.AC_HOME
    delete env.NODE_OPTIONS
    const ran = await new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
      execFile(
        process.execPath,
        [MAIN, 'keys', 'list', '--dir', dir],
        { env, timeout: 30_000 },
        (e, stdout, stderr) => done({ code: e === null ? 0 : Number(e.code), stdout, stderr }),
      )
    })
    expect(ran).toMatchObject({ code: 0, stderr: '' })
    expect(ran.stdout).toMatch(
      new RegExp(`^amy ${made.out[0]} file \\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ\\n$`),
    )
    console.log(`MEASURE keys list as a process: exit ${ran.code}, stderr ${ran.stderr.length} bytes`)
  })

  it('prints nothing for a home with no identity, and refuses another verb', async () => {
    const io = testIo(new MemoryRelay())
    expect(await cli(io, 'keys', 'list', '--dir', join(tmp.dir, `home-${n++}`))).toEqual({
      code: 0,
      out: [],
      err: [],
    })
    const bad = await cli(io, 'keys', 'show')
    expect([bad.code, bad.err[0]]).toEqual([
      1,
      'bag: usage: keys list [--dir <home>] | keys rotate <name> --relay <url>... [--dir <home>] | keys prune <name> [--dir <home>]',
    ])
  })
})

// keys rotate: the identity's next epoch now. A key record over a fresh sealing key, and the address record with
// no sealing key, re-signed when it still names one; the epoch's private key is kept in <home>/key-records.

const RELAY = 'http://127.0.0.1:9'
const R2 = 'http://127.0.0.1:10'
const DAY = 86_400
const ROTATION = generateEdgeKeys(systemRng).signing.address

/** A home with the key file `bob`, and bob's keys. */
async function bobHome(io: TestIo, dir: string): Promise<{ keys: EdgeKeys; address: string }> {
  const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  return { keys: new HomeCustody(dir).keys('bob'), address }
}

/** Puts bob's address record at the relay as the held one: a sealing key and revoked entry unless `o` says otherwise. */
function hold(
  relay: MemoryRelay,
  keys: EdgeKeys,
  o: { sealing?: boolean; relays?: string[]; revoked?: string[]; iat?: number } = {},
) {
  const record = signRecord(keys.signing, {
    kind: 'address',
    key: keys.signing.address,
    sealing_key: o.sealing === false ? null : toHex(keys.sealing.publicKey),
    relays: o.relays ?? [RELAY],
    rotation_key: ROTATION,
    revoked: o.revoked ?? [`ed25519:${'cd'.repeat(32)}`],
    ttl: 3600,
    iat: o.iat ?? T0,
    rotated_from: null,
  })
  relay.records.set(`${keys.signing.address} address`, serializeRecord(record))
  return record
}
const heldAt = (relay: MemoryRelay, address: string, kind: string) =>
  parseRecord(relay.records.get(`${address} ${kind}`) as Uint8Array)

describe('keys rotate with a relay down (spec/SPEC.md Appendix B 110)', () => {
  const held = (keys: EdgeKeys, address: string, revoked: string[]): Uint8Array =>
    serializeRecord(
      signRecord(keys.signing, {
        kind: 'address',
        key: address,
        sealing_key: toHex(new Uint8Array(32).fill(7)),
        relays: [RELAY, R2],
        rotation_key: null,
        revoked,
        ttl: 3600,
        iat: T0 - 1,
        rotated_from: null,
      }),
    )

  it('exits 0 and names the relay when nothing it lags on revokes', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { address, keys } = await bobHome(io, dir)
    await relay.publish(RELAY, held(keys, address, []))
    relay.failRecordPublish.set(R2, new RelayError(null, 0, null, 'no answer'))
    const r = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
    expect(r.code).toBe(0)
    expect(r.out).toContain(`failed key ${address} ${R2} unreachable`)
    expect(r.out.join('\n')).not.toContain('incomplete revocation')
    expect(r.out.at(-1)).toBe(`epoch 1 ${address} until ${instant(T0 + DAY)}`)
  })

  it('exits 3, written and not done, with a line per relay when the record carries a revoked list', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { address, keys } = await bobHome(io, dir)
    await relay.publish(RELAY, held(keys, address, [`ed25519:${'ab'.repeat(32)}`]))
    relay.failRecordPublish.set(R2, new RelayError(null, 0, null, 'no answer'))
    const r = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
    expect(r.code).toBe(3)
    expect(r.out).toContain(`incomplete revocation ${address} ${R2} unreachable: ${INCOMPLETE_REVOCATION}`)
  })
})

describe('keys rotate', () => {
  it('publishes the first epoch when no record is held: a fresh address record with no sealing key, then the key record', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { address } = await bobHome(io, dir)
    const r = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--relay', `${RELAY}/`, '--dir', dir)
    expect(r).toEqual({
      code: 0,
      out: [
        `published key ${address} ${RELAY}`,
        `published address ${address} ${RELAY}`,
        `epoch 1 ${address} until ${instant(T0 + DAY)}`,
      ],
      err: [],
    })
    expect(heldAt(relay, address, 'address')).toMatchObject({
      sealing_key: null,
      relays: [RELAY],
      revoked: [],
      iat: T0,
    })
    expect(heldAt(relay, address, 'key')).toMatchObject({ kind: 'key', key: address, iat: T0, exp: T0 + DAY })
    expect(epochStore(dir).epochs(address)).toEqual([1])
  })

  it('publishes the key record alone at the relays of a held record with no sealing key, which is kept as it is', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { keys, address } = await bobHome(io, dir)
    const record = hold(relay, keys, { sealing: false, relays: [RELAY, R2] })
    const before = relay.records.get(`${address} address`)
    io.time.now = T0 + 10
    // Only RELAY is named: the held record names R2 too, and the key record goes to both.
    const r = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
    expect(r).toEqual({
      code: 0,
      out: [
        `published key ${address} ${RELAY}`,
        `published key ${address} ${R2}`,
        `epoch 1 ${address} until ${instant(T0 + 10 + DAY)}`,
      ],
      err: [],
    })
    expect(relay.records.get(`${address} address`)).toBe(before)
    expect(record.sealing_key).toBeNull()
    expect(heldAt(relay, address, 'key')).toMatchObject({ iat: T0 + 10, exp: T0 + 10 + DAY })
  })

  it('re-signs a held record that names a sealing key with none, keeping its revoked entries and rotation key', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { keys, address } = await bobHome(io, dir)
    const held = hold(relay, keys)
    io.time.now = T0 + 10
    const r = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
    expect(r.out).toEqual([
      `published key ${address} ${RELAY}`,
      `published address ${address} ${RELAY}`,
      `epoch 1 ${address} until ${instant(T0 + 10 + DAY)}`,
    ])
    expect(heldAt(relay, address, 'address')).toMatchObject({
      sealing_key: null,
      revoked: held.revoked,
      rotation_key: held.rotation_key,
      relays: held.relays,
      ttl: held.ttl,
      iat: T0 + 10,
    })
  })

  it('refuses window-open while a login window holds a record that names a sealing key, and rotates one that names none', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, 'k') // short: a Unix socket path holds about 100 bytes
    const { keys, address } = await bobHome(io, dir)
    expect(
      (await cli(io, 'keygen', 'jane', '--custody', 'agent', '--principal', 'bob', '--dir', dir)).code,
    ).toBe(0)
    hold(relay, keys)
    const server = createServer((c) => c.on('error', () => undefined))
    await new Promise<void>((up) => server.listen(join(dir, 'agent.sock'), up))
    try {
      const published = relay.published.length
      const refused = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
      expect(refused).toEqual({
        code: 1,
        out: [],
        err: ['bag: window-open: a login window holds jane: run ac logout first'],
      })
      expect([relay.published.length, epochStore(dir).epochs(address)]).toEqual([published, []])
      // The record has no sealing key: the window's logout re-signs nothing that an epoch changes, so the epoch goes out.
      hold(relay, keys, { sealing: false, iat: T0 + 1 })
      const ok = await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
      expect(ok.out[0]).toBe(`published key ${address} ${RELAY}`)
      expect(ok.code).toBe(0)
    } finally {
      await new Promise<void>((down) => server.close(() => down()))
    }
  })

  it('names the epochs it deleted past their horizon, exp + the relay retention + the skew', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const { address } = await bobHome(io, dir)
    const rotate = () => cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)
    expect((await rotate()).out.at(-1)).toBe(`epoch 1 ${address} until ${instant(T0 + DAY)}`)
    io.time.now = T0 + 100
    const second = await rotate()
    expect(second.out).toEqual([
      `published key ${address} ${RELAY}`,
      `epoch 2 ${address} until ${instant(T0 + 100 + DAY)}`,
    ])
    // At the second epoch's horizon only the first is past its own; one second later the second is (deleted: > exp + retention + skew).
    const horizon = T0 + 100 + DAY + DEFAULT_TTL + DEFAULT_SKEW
    io.time.now = horizon
    const at = await rotate()
    // The address record has lapsed by now, so it is re-signed with the epoch; the next epoch finds it standing.
    expect(at.out).toEqual([
      `published key ${address} ${RELAY}`,
      `published address ${address} ${RELAY}`,
      `epoch 3 ${address} until ${instant(horizon + DAY)}`,
      'deleted epochs 1',
    ])
    io.time.now = horizon + 1
    const past = await rotate()
    expect(past.out).toEqual([
      `published key ${address} ${RELAY}`,
      `epoch 4 ${address} until ${instant(horizon + 1 + DAY)}`,
      'deleted epochs 2',
    ])
    expect(epochStore(dir).epochs(address)).toEqual([4, 3])
  })

  it('is a usage error without a name, without --relay, and with a name that is not an identity of the home', async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, `home-${n++}`)
    await bobHome(io, dir)
    const usage = /^bag: usage: /
    expect((await cli(io, 'keys', 'rotate', '--relay', RELAY, '--dir', dir)).err[0]).toMatch(usage)
    expect((await cli(io, 'keys', 'rotate', 'bob', '--dir', dir)).err[0]).toMatch(usage)
    expect((await cli(io, 'keys', 'rotate', 'nobody', '--relay', RELAY, '--dir', dir)).err[0]).toMatch(
      /^bag: ENOENT: /,
    )
  })
})

// keys prune: the long-term sealing key replaced by a fresh random seed once it opens
// nothing (epoch 1 deleted); the signing key, the address and the key text's form are kept.

const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))
const SECRET = { text: 'secret' }

/** Every file under `dir` by path, as bytes: a home before and after a step. */
function snapshot(dir: string, at = dir, into = new Map<string, string>()): Map<string, string> {
  for (const e of readdirSync(at, { withFileTypes: true })) {
    const path = join(at, e.name)
    if (e.isDirectory()) snapshot(dir, path, into)
    else into.set(path, readFileSync(path).toString('latin1'))
  }
  return into
}

/** What an opener does with a message sealed to `sealingKey` for `address`: its body, or the code it refused with. */
function tried(opener: OpenerLike, address: string, sealingKey: Uint8Array): unknown {
  const content = { type: 'chat.v1', thread: newThread(rng), body: SECRET }
  const m = {
    to: [address],
    from: address,
    sealed: sealTo([{ address, sealingKey }], address, content, rng),
    content,
  }
  try {
    return openSealed(m, { address, key: opener }).body
  } catch (e) {
    return (e as { code?: unknown }).code
  }
}

/** A home with bob in `custody` and bob's epoch 2 (no epoch 1: its horizon has passed), and what bob holds. */
async function prunable(io: TestIo, custody: 'file' | 'keychain') {
  const dir = join(tmp.dir, `home-${n++}`)
  const address = (await cli(io, 'keygen', 'bob', '--custody', custody, '--dir', dir)).out[0] as string
  const epoch = generateSealingKey(rng)
  epochStore(dir).put(address, 2, epoch, T0, T0 + DAY)
  return { dir, address, epoch }
}

const keyFile = (dir: string) =>
  JSON.parse(readFileSync(join(dir, 'keys', 'bob.json'), 'utf8')) as Record<string, string>

describe('keys prune', () => {
  it('replaces the sealing key of a key file: the signing key and address stay, the old seed is in no file, mode 0600', async () => {
    const io = testIo(new MemoryRelay())
    const { dir, address, epoch } = await prunable(io, 'file')
    const before = keyFile(dir)
    const old = new HomeCustody(dir).keys('bob').sealing.publicKey
    // A chain file that does not read, and one with no hop, root no identity: neither stops a prune.
    writeFileSync(join(dir, 'junk.chain.json'), 'nope')
    writeFileSync(join(dir, 'empty.chain.json'), '[]')
    utimesSync(join(dir, 'keys', 'bob.json'), 1_700_000_000, 1_700_000_000)
    const created = `bob ${address} file 2023-11-14T22:13:20Z`
    expect((await cli(io, 'keys', 'list', '--dir', dir)).out).toEqual([created])
    const r = await cli(io, 'keys', 'prune', 'bob', '--dir', dir)
    expect(r).toEqual({ code: 0, out: [`pruned ${address} long-term sealing key`], err: [] })
    expect((await cli(io, 'keys', 'list', '--dir', dir)).out).toEqual([created]) // the created time is kept
    const after = keyFile(dir)
    expect(Object.keys(after)).toEqual(['suite', 'sign_seed', 'seal_priv'])
    expect([after.suite, after.sign_seed]).toEqual([before.suite, before.sign_seed])
    expect(after.seal_priv).toMatch(/^[0-9a-f]{64}$/)
    expect(after.seal_priv).not.toBe(before.seal_priv)
    expect(statSync(join(dir, 'keys', 'bob.json')).mode & 0o777).toBe(0o600)
    expect(readdirSync(join(dir, 'keys'))).toEqual(['bob.json'])
    expect((await cli(io, 'keys', 'list', '--dir', dir)).out[0]).toMatch(new RegExp(`^bob ${address} file `))
    const everything = [...snapshot(dir).values()].join('\n')
    expect(occurrences(everything, forms(Buffer.from(before.seal_priv as string, 'hex')))).toBe(0)
    // Mail sealed to a held epoch still opens; one sealed to the old long-term key no longer does.
    const keys = new HomeCustody(dir).keys('bob')
    expect(tried(receivingKeys(dir, keys).sealing, address, epoch.publicKey)).toEqual(SECRET)
    expect(tried(keys.sealing, address, old)).toBe('open-failed')
    expect(tried(keys.sealing, address, keys.sealing.publicKey)).toEqual(SECRET)
    // The new long-term key is never tried by the receiving openers: changeover is false.
    expect(tried(receivingKeys(dir, keys).sealing, address, keys.sealing.publicKey)).toBe('open-failed')
    const log = readFileSync(join(dir, 'state', 'bob', 'cli-audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
    expect(log).toHaveLength(1)
    const line = JSON.parse(log[0] as string)
    expect([line.event, line.decision, line.from, JSON.parse(line.detail)]).toEqual([
      'rotate',
      'accept',
      address,
      { subject: `key:${address}`, action: 'prune-sealing' },
    ])
  })

  it('may be run again: it replaces the seed again (a design choice), and audits each', async () => {
    const io = testIo(new MemoryRelay())
    const { dir } = await prunable(io, 'file')
    expect((await cli(io, 'keys', 'prune', 'bob', '--dir', dir)).code).toBe(0)
    const first = keyFile(dir).seal_priv
    expect((await cli(io, 'keys', 'prune', 'bob', '--dir', dir)).code).toBe(0)
    expect(keyFile(dir).seal_priv).not.toBe(first)
    expect(
      readFileSync(join(dir, 'state', 'bob', 'cli-audit.jsonl'), 'utf8')
        .trim()
        .split('\n'),
    ).toHaveLength(2)
  })

  it('updates a keychain item through the runner, as one -U line: the pointer is untouched, the old seed is nowhere', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const { dir, address, epoch } = await prunable(io, 'keychain')
    const item = () =>
      JSON.parse(new TextDecoder().decode([...fake.items.values()][0])) as Record<string, string>
    const [before, pointer] = [item(), readFileSync(join(dir, 'keychain', 'bob.json'), 'utf8')]
    const r = await cli(io, 'keys', 'prune', 'bob', '--dir', dir)
    expect(r).toEqual({ code: 0, out: [`pruned ${address} long-term sealing key`], err: [] })
    // One -U update among the calls (the read-back of F2 comes after it).
    const updates = fake.calls.filter((c) => /^add-generic-password -U /.test(String(c.input)))
    expect(updates.map((c) => c.input)).toEqual([
      expect.stringMatching(/^add-generic-password -U -s bag:bob -a /),
    ])
    expect(fake.items.size).toBe(1)
    const after = item()
    expect([after.suite, after.sign_seed]).toEqual([before.suite, before.sign_seed])
    expect(after.seal_priv).not.toBe(before.seal_priv)
    expect(readFileSync(join(dir, 'keychain', 'bob.json'), 'utf8')).toBe(pointer)
    const everything = [...snapshot(dir).values()].join('\n')
    const needles = forms(Buffer.from(before.seal_priv as string, 'hex'))
    expect(
      occurrences(everything, needles) +
        occurrences(new TextDecoder().decode([...fake.items.values()][0]), needles),
    ).toBe(0)
    const keys = new HomeCustody(dir, { run: fake.run }).keys('bob')
    expect(toHex(keys.sealing.exportSeed())).toBe(after.seal_priv)
    expect(tried(receivingKeys(dir, keys).sealing, address, epoch.publicKey)).toEqual(SECRET)
  })

  it('refuses, before any write and with every file as it was: no epoch (an org holds none), epoch 1 held, a group admin, the agent, no identity', async () => {
    const io = testIo(new MemoryRelay())
    const refused = async (dir: string, name: string, ...err: string[]) => {
      const before = snapshot(dir)
      expect(await cli(io, 'keys', 'prune', name, '--dir', dir)).toEqual({ code: 1, out: [], err })
      expect(snapshot(dir)).toEqual(before)
    }
    const bare = join(tmp.dir, `home-${n++}`)
    await cli(io, 'keygen', 'bob', '--dir', bare)
    await refused(
      bare,
      'bob',
      'bag: no-forward-secrecy: bob holds no epoch: its long-term key opens all its mail',
    )
    const { dir, address } = await prunable(io, 'file')
    epochStore(dir).put(address, 1, generateSealingKey(rng), T0, T0 + DAY)
    await refused(
      dir,
      'bob',
      `bag: before-horizon: bob holds epoch 1, deleted by the first rotation after ${instant(T0 + DAY + DEFAULT_TTL + DEFAULT_SKEW)}`,
    )
    const admin = (await prunable(io, 'file')).dir
    const bob = new HomeCustody(admin).keys('bob').signing.address
    groupStore(admin, 'bob').saveState({
      group: bob,
      generation: 1,
      iat: T0,
      relays: [RELAY],
      ttl: 3600,
      rotationKey: ROTATION,
      members: [],
      revoked: [],
    })
    await refused(admin, 'bob', "bag: group-admin: bob is a group's admin: it opens its copies with that key")
    // An org is marked by the chain file onboard writes for its agent, <home>/<agent>.chain.json, root first: refused by
    // that root, whatever the org key's name, and though it holds epochs (keys rotate and peer mint them for any key).
    const org = (await prunable(io, 'file')).dir
    const chain = join(org, 'agent.chain.json')
    const to = `ed25519:${'ab'.repeat(32)}`
    expect(
      (await cli(io, 'delegate', '--from', 'bob', '--to', to, '--exp', '+3600', '--out', chain, '--dir', org))
        .code,
    ).toBe(0)
    await refused(org, 'bob', "bag: not-individual: bob is an org's key: its served record names it")
    new HomeCustody(dir).agent.create('zed', generateEdgeKeys(io.rng))
    await refused(dir, 'zed', 'bag: custody-unsupported: zed is held by the agent, which keeps its own keys')
    expect((await cli(io, 'keys', 'prune', 'nobody', '--dir', dir)).err[0]).toMatch(/^bag: ENOENT: /)
    expect((await cli(io, 'keys', 'prune', '--dir', dir)).err[0]).toMatch(/^bag: usage: /)
  })

  it('refuses window-open while an ac login window holds the identity, as keys rotate does', async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, 'p') // short: a Unix socket path holds about 100 bytes
    const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
    expect(
      (await cli(io, 'keygen', 'jane', '--custody', 'agent', '--principal', 'bob', '--dir', dir)).code,
    ).toBe(0)
    epochStore(dir).put(address, 2, generateSealingKey(rng), T0, T0 + DAY)
    const server = createServer((c) => c.on('error', () => undefined))
    await new Promise<void>((up) => server.listen(join(dir, 'agent.sock'), up))
    try {
      const before = keyFile(dir)
      expect(await cli(io, 'keys', 'prune', 'bob', '--dir', dir)).toEqual({
        code: 1,
        out: [],
        err: ['bag: window-open: a login window holds jane: run ac logout first'],
      })
      expect(keyFile(dir)).toEqual(before)
    } finally {
      await new Promise<void>((down) => server.close(() => down()))
    }
  })

  it('reads the item back and refuses prune-unverified when the update made a second item and the read gives the old one', async () => {
    const fake = new FakeSecurity()
    // An update that lands in another item (as -U does in a keychain other than the pointer's default).
    const aside: typeof fake.run = (args, input) => {
      const line = input === undefined ? '' : new TextDecoder().decode(input)
      if (args[0] !== '-i' || !line.includes(' -U ')) return fake.run(args, input)
      return fake.run(args, new TextEncoder().encode(line.replace('bag:bob', 'bag:elsewhere')))
    }
    const io = { ...testIo(new MemoryRelay()), security: aside }
    const { dir } = await prunable(io, 'keychain')
    const before = snapshot(dir)
    const r = await cli(io, 'keys', 'prune', 'bob', '--dir', dir)
    expect(r).toEqual({
      code: 1,
      out: [],
      err: ['bag: prune-unverified: the item of bob does not hold the new key: check the keychain'],
    })
    expect(fake.items.size).toBe(2)
    expect(snapshot(dir)).toEqual(before) // no audit line for a prune that did not take
  })
})
