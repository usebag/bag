import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AddressRecord,
  countersignRotation,
  type KeyRecord,
  MAX_ADDRESS_TTL,
  parseRecord,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import {
  generateEdgeKeys,
  readRecoveryState,
  readSheet,
  type Seeds,
  SHEET_LINES,
  seedKeys,
  systemRng,
  writeRecoveryState,
} from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { init, LOSS_PHRASE, restore } from '../src/commands/init.ts'
import { keygen, NO_RECOVERY } from '../src/commands/keygen.ts'
import { keys as keysCommand } from '../src/commands/keys.ts'
import { epochStore } from '../src/home.ts'
import { instant } from '../src/names.ts'
import { agentHome, loggedIn, publishRecord } from './support/agent.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// ac init and ac restore: the sheet and its checksum, --accept-loss,
// and the restore order. Nothing is stored or published before the person's act; restore makes no network call on a
// sheet that does not check.

const tmp = tempDir('init-restore')
afterAll(() => tmp.cleanup())
const R = 'http://127.0.0.1:1'
let n = 0
const home = (): string => join(tmp.dir, `h${n++}`)
/** A sealing seed for seedKeys: the sheet holds none (forward secrecy), and the tests read only the signing and rotation keys. */
const FRESH = new Uint8Array(32).fill(2)

/** A terminal io (stdin and stdout) on `net`, with the lines a person types. */
function term(net: Network, ...lines: string[]): TestIo {
  const io = testIo(net)
  io.tty = true
  io.outTty = true
  io.lines.push(...lines)
  return io
}
const code = (e: unknown): string => String((e as { code?: unknown }).code)
/** The audit lines of `name` in `dir`: event, decision and the parsed detail. */
const auditOf = (dir: string, name: string) =>
  readFileSync(join(dir, 'state', name, 'cli-audit.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as { event: string; decision: string; detail: string | null })
    .map((l) => ({
      event: l.event,
      decision: l.decision,
      detail: l.detail === null ? null : JSON.parse(l.detail),
    }))
/** What a home holds, as file names (none when the directory is not there). */
const files = (dir: string): string[] =>
  existsSync(dir) ? readdirSync(dir, { recursive: true }).map(String) : []
const held = (net: Network, address: string): AddressRecord =>
  parseRecord(net.record(R, address, 'address') as string) as AddressRecord
const heldKey = (net: Network, address: string): KeyRecord =>
  parseRecord(net.record(R, address, 'key') as string) as KeyRecord
/** A restore io whose clock reads after the init that made the sheet: a relay takes a key record only if it is newer. */
function later(io: TestIo, seconds = 60): TestIo {
  io.time.now = T0 + seconds
  return io
}

/** An ac init that prints the sheet and confirms it: its io, home, sheet lines and address. */
async function made(net: Network) {
  const dir = home()
  const io = term(net)
  // The checksum is typed after the sheet is printed: read it from stdout when the prompt asks.
  const readLine = io.readLine
  Object.assign(io, { readLine: async () => io.stdout[SHEET_LINES - 1] ?? (await readLine()) })
  expect(await init(['alice', '--relay', R, '--dir', dir], io)).toBe(0)
  const sheet = io.stdout.slice(0, SHEET_LINES)
  return { io, dir, sheet, address: io.stdout.at(-2)?.split(' ')[2] as string }
}

describe('ac init', () => {
  it('prints the sheet once, takes the checksum back, then stores, writes the state, publishes and audits', async () => {
    const net = new Network()
    const { io, dir, sheet, address } = await made(net)
    expect(readSheet(sheet)).toEqual({ seeds: expect.any(Object), relay: R })
    expect(io.stdout.slice(SHEET_LINES)).toEqual([
      `published address ${address} ${R}`,
      `published key ${address} ${R}`,
      'recovery: printed sheet confirmed',
    ])
    expect(['alice.json', 'alice.rotation.json'].map((f) => existsSync(join(dir, 'keys', f)))).toEqual([
      true,
      true,
    ])
    expect(readRecoveryState(dir, address)).toEqual({
      v: 1,
      copy: 'sheet',
      confirmed_at: T0,
      stale_since: null,
    })
    const r = held(net, address)
    // The address record names no sealing key; epoch 1's key record does, for a day, and its private key is kept.
    expect([r.sealing_key, r.rotation_key, r.relays, r.ttl]).toEqual([
      null,
      expect.stringMatching(/^ed25519:/),
      [R],
      MAX_ADDRESS_TTL,
    ])
    const key = heldKey(net, address)
    expect([key.kind, key.key, key.iat, key.exp - key.iat]).toEqual(['key', address, T0, 86_400])
    expect(key.sealing_key).toMatch(/^[0-9a-f]{64}$/)
    expect(epochStore(dir).epochs(address)).toEqual([1])
    expect(net.log).toEqual([`${R} address ${address}`, `${R} key ${address}`])
    expect(auditOf(dir, 'alice')).toEqual([
      { event: 'onboard', decision: 'accept', detail: { copy: 'sheet' } },
      {
        event: 'rotate',
        decision: 'accept',
        detail: {
          subject: `key:${address}`,
          epoch: 1,
          sealing_key: key.sealing_key,
          exp: key.exp,
          resigned: false,
          republished: false,
          deleted: [],
        },
      },
    ])
    const audit = readFileSync(join(dir, 'state', 'alice', 'cli-audit.jsonl'), 'utf8')
    for (const l of sheet.slice(0, 2)) expect(audit).not.toContain(l.split(' ')[1])
  })

  it('stores and publishes nothing on a wrong checksum, no answer, or a sheet that would go to a pipe', async () => {
    for (const answer of ['00000000', null]) {
      const net = new Network()
      const dir = home()
      const io = answer === null ? term(net) : term(net, answer)
      await expect(init(['alice', '--relay', R, '--dir', dir], io)).rejects.toMatchObject({
        code: 'single-copy',
      })
      expect([files(dir), net.log]).toEqual([[], []])
    }
    const net = new Network()
    const piped = term(net)
    piped.outTty = false
    await expect(init(['alice', '--relay', R, '--dir', home()], piped)).rejects.toMatchObject({
      code: 'no-tty',
    })
    expect(piped.stdout).toEqual([])
    const noTty = term(net)
    noTty.tty = false
    await expect(init(['alice', '--relay', R, '--dir', home()], noTty)).rejects.toMatchObject({
      code: 'no-tty',
    })
  })

  it('--accept-loss: no sheet, the exact phrase or nothing, then the state none', async () => {
    const net = new Network()
    const wrong = term(net, 'I accept losing this')
    const none = home()
    await expect(init(['bob', '--relay', R, '--accept-loss', '--dir', none], wrong)).rejects.toMatchObject({
      code: 'single-copy',
    })
    expect([files(none), wrong.stdout]).toEqual([[], []])
    const dir = home()
    const io = term(net, LOSS_PHRASE)
    io.outTty = false // no sheet is printed, so stdout may be a pipe
    expect(await init(['bob', '--relay', R, '--accept-loss', '--dir', dir], io)).toBe(0)
    const address = io.stdout[0]?.split(' ')[2] as string
    expect(io.stdout).toEqual([
      `published address ${address} ${R}`,
      `published key ${address} ${R}`,
      'recovery: none (accepted at ac init)',
    ])
    expect(readRecoveryState(dir, address)?.copy).toBe('none')
    expect(auditOf(dir, 'bob').map((l) => [l.event, l.decision])).toEqual([
      ['onboard', 'accept'],
      ['rotate', 'accept'],
    ])
    expect(auditOf(dir, 'bob')[0]).toEqual({ event: 'onboard', decision: 'accept', detail: { copy: 'none' } })
  })

  it('refuses a bad or long name, agent custody, a missing --relay and a bad one before it prints or reads anything', async () => {
    const net = new Network()
    const dir = home()
    for (const [args, want] of [
      [['Alice', '--relay', R], 'usage'],
      [['a'.repeat(56), '--relay', R], 'usage'],
      [['alice', '--relay', R, '--custody', 'agent'], 'usage'],
      [['alice'], 'usage'],
      [['alice', '--relay', 'htp://x'], 'usage'],
    ] as const) {
      const io = term(net)
      const e = await init([...args, '--dir', dir], io).catch((x) => x)
      expect([code(e) === 'undefined' ? 'usage' : code(e), io.stdout, io.stderr]).toEqual([want, [], []])
    }
    const io = term(net)
    await expect(restore(['alice', '--relay', 'htp://x', '--dir', dir], io)).rejects.toThrow()
    expect([io.stdout, io.stderr, files(dir), net.log]).toEqual([[], [], [], []])
  })

  it('says a publish that failed left the identity stored, and names the step that publishes it', async () => {
    const net = new Network()
    const dir = home()
    const io = term(net)
    const down = Object.assign(new Error('the relay is down'), { code: 'relay-unreachable' })
    Object.assign(io, { relay: () => ({ ...net, publish: async () => Promise.reject(down) }) })
    const readLine = io.readLine
    Object.assign(io, { readLine: async () => io.stdout[SHEET_LINES - 1] ?? (await readLine()) })
    const e = await init(['alice', '--relay', R, '--dir', dir], io).catch((x) => x)
    expect([code(e), (e as Error).message]).toEqual([
      'relay-unreachable',
      expect.stringMatching(
        /^relay-unreachable: alice is stored with its state, but .* did not take its address record; make and publish it: ac record address alice /,
      ),
    ])
    expect((e as Error).message).toMatch(
      new RegExp(
        `--relay ${R} --rotation-key ed25519:[0-9a-f]{64}, then ac publish, then ac keys rotate alice --relay ${R}$`,
      ),
    )
    expect(['alice.json', 'alice.rotation.json'].map((f) => existsSync(join(dir, 'keys', f)))).toEqual([
      true,
      true,
    ])
  })

  it('names publish-failed for a relay error without a code', async () => {
    const net = new Network()
    const io = term(net)
    Object.assign(io, {
      relay: () => ({ ...net, publish: async () => Promise.reject(new Error('no code')) }),
    })
    const readLine = io.readLine
    Object.assign(io, { readLine: async () => io.stdout[SHEET_LINES - 1] ?? (await readLine()) })
    expect(code(await init(['alice', '--relay', R, '--dir', home()], io).catch((x) => x))).toBe(
      'publish-failed',
    )
  })

  it('says a key record that was refused left the identity stored with its address record, and names ac keys rotate', async () => {
    const net = new Network()
    const dir = home()
    const io = term(net)
    const down = Object.assign(new Error('the relay is down'), { code: 'relay-unreachable' })
    const taken: string[] = []
    Object.assign(io, {
      relay: () => ({
        ...net,
        publish: async (url: string, bytes: Uint8Array) => {
          const kind = (JSON.parse(new TextDecoder().decode(bytes)) as { kind: string }).kind
          if (kind === 'key') throw down
          taken.push(kind)
          return net.publish(url, bytes)
        },
      }),
    })
    const readLine = io.readLine
    Object.assign(io, { readLine: async () => io.stdout[SHEET_LINES - 1] ?? (await readLine()) })
    const e = await init(['alice', '--relay', R, '--dir', dir], io).catch((x) => x)
    expect([code(e), taken]).toEqual(['relay-unreachable', ['address']])
    expect((e as Error).message).toBe(
      `relay-unreachable: alice is stored with its state, but relay-unreachable: ${R} did not take the key record of ${io.stdout.at(-1)?.split(' ')[2]}; publish it again: ac keys rotate alice --relay ${R}`,
    )
    expect(['alice.json', 'alice.rotation.json'].map((f) => existsSync(join(dir, 'keys', f)))).toEqual([
      true,
      true,
    ])
    expect(io.stdout.at(-1)).toMatch(/^published address ed25519:[0-9a-f]{64} http:\/\/127\.0\.0\.1:1$/)
  })

  it('wraps an epoch failure that carries no code as the code error', async () => {
    const net = new Network()
    const dir = home()
    const io = term(net)
    let armed = false
    Object.assign(io, {
      // The address record is published first; from then on the CSPRNG fails, as the epoch's key is made.
      rng: {
        bytes: (length: number) => {
          if (armed) throw new Error('the CSPRNG is down')
          return systemRng.bytes(length)
        },
      },
      relay: () => ({
        ...net,
        publish: async (url: string, bytes: Uint8Array) => {
          const sent = await net.publish(url, bytes)
          armed = true
          return sent
        },
      }),
    })
    const readLine = io.readLine
    Object.assign(io, { readLine: async () => io.stdout[SHEET_LINES - 1] ?? (await readLine()) })
    const e = await init(['alice', '--relay', R, '--dir', dir], io).catch((x) => x)
    expect([code(e), (e as Error).message]).toEqual([
      'error',
      'error: alice is stored with its state, but the CSPRNG is down',
    ])
  })

  it('keys list shows a stale copy, and a state file that does not read as unreadable', async () => {
    const net = new Network()
    const { dir, address } = await made(net)
    writeRecoveryState(dir, address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: T0 + 60 })
    const listed = testIo(net)
    expect(keysCommand(['list', '--dir', dir], listed)).toBe(0)
    expect(listed.stdout.find((l) => l.startsWith('alice '))).toMatch(
      new RegExp(` copy=sheet stale_since=${instant(T0 + 60)}$`),
    )
    writeFileSync(join(dir, `recovery-state.${address}.json`), '{')
    const broken = testIo(net)
    expect(keysCommand(['list', '--dir', dir], broken)).toBe(0)
    expect(broken.stdout.find((l) => l.startsWith('alice '))).toMatch(/ copy=unreadable$/)
  })

  it('reprints a held sheet on a terminal, and a confirmed reprint clears stale_since; a mismatch changes nothing', async () => {
    const net = new Network()
    const { dir, sheet, address } = await made(net)
    writeRecoveryState(dir, address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: T0 + 9 })
    const wrong = term(net, '00000000')
    await expect(init(['alice', '--reprint', '--relay', R, '--dir', dir], wrong)).rejects.toMatchObject({
      code: 'single-copy',
    })
    expect(readRecoveryState(dir, address)?.stale_since).toBe(T0 + 9)
    const io = term(net, sheet[3] as string)
    expect(await init(['alice', '--reprint', '--relay', R, '--dir', dir], io)).toBe(0)
    expect(io.stdout).toEqual([...sheet, 'recovery: printed sheet confirmed (reprinted)'])
    expect(readRecoveryState(dir, address)).toEqual({
      v: 1,
      copy: 'sheet',
      confirmed_at: T0,
      stale_since: null,
    })
    expect(auditOf(dir, 'alice').at(-1)).toEqual({
      event: 'onboard',
      decision: 'accept',
      detail: { copy: 'sheet', reprint: true },
    })
    const piped = term(net)
    piped.outTty = false
    await expect(init(['alice', '--reprint', '--relay', R, '--dir', dir], piped)).rejects.toMatchObject({
      code: 'no-tty',
    })
    await expect(init(['carol', '--reprint', '--relay', R, '--dir', dir], term(net))).rejects.toMatchObject({
      code: 'ENOENT',
    })
  })

  it('refuses a name a custody holds before it asks anything', async () => {
    const net = new Network()
    const dir = home()
    expect(keygen(['alice', '--dir', dir], testIo(net))).toBe(0)
    const io = term(net)
    await expect(init(['alice', '--relay', R, '--dir', dir], io)).rejects.toMatchObject({ code: 'EEXIST' })
    expect([net.log, io.stdout, io.stderr]).toEqual([[], [], []])
    await expect(restore(['alice', '--dir', dir], term(net))).rejects.toMatchObject({ code: 'EEXIST' })
    // A rotation key alone is an ac init or restore that did not finish: named as such.
    const half = home()
    expect(keygen(['bob.rotation', '--dir', half], testIo(net))).toBe(0)
    await expect(init(['bob', '--relay', R, '--dir', half], term(net))).rejects.toMatchObject({
      code: 'EEXIST',
      message: expect.stringContaining(
        'bob.rotation is held, but not bob: an ac init or restore did not finish',
      ),
    })
  })
})

describe('ac restore', () => {
  it('restores in place from the sheet: same keys, a later iat, the state sheet on a second checksum', async () => {
    const net = new Network()
    const { sheet, address } = await made(net)
    const before = held(net, address)
    const dir = home()
    const io = later(term(net, ...sheet, sheet[3] as string))
    io.answers.push(true) // the confirm before any republish
    expect(await restore(['alice', '--dir', dir], io)).toBe(0)
    expect(io.asked).toEqual(['publish the address record anyway?'])
    expect(io.stderr).toContainEqual(
      'publishing replaces it: confirming may UN-REVOKE a key you revoked before',
    )
    expect(io.stdout).toEqual([
      `published address ${address} ${R}`,
      `published key ${address} ${R}`,
      'restored alice',
      'recovery: printed sheet confirmed',
      `next: ac keygen alice-agent --custody agent --principal alice, then ac login --as alice-agent --relay ${R}`,
    ])
    const after = held(net, address)
    // The record names no sealing key before or after; the restore's own epoch 1 is a new key record.
    expect([before.sealing_key, after.sealing_key, after.rotation_key, after.iat > before.iat]).toEqual([
      null,
      null,
      before.rotation_key,
      true,
    ])
    const key = heldKey(net, address)
    expect([key.iat, key.exp - key.iat, epochStore(dir).epochs(address)]).toEqual([T0 + 60, 86_400, [1]])
    expect(readRecoveryState(dir, address)?.copy).toBe('sheet')
    expect(io.secrets).toBe(SHEET_LINES) // every line of the sheet read with the echo off (ruling 5)
    expect(auditOf(dir, 'alice').map((l) => [l.event, l.decision])).toEqual([
      ['restore', 'accept'],
      ['rotate', 'accept'],
    ])
    const listed = testIo(net)
    expect(keysCommand(['list', '--dir', dir], listed)).toBe(0)
    expect(listed.stdout.find((l) => l.startsWith('alice '))).toMatch(/ copy=sheet$/)
    const { keys, rotation } = seedKeys((readSheet(sheet) as { seeds: Seeds }).seeds, FRESH)
    const stored = readdirSync(join(dir, 'keys')).sort()
    expect([stored, keys.signing.address, after.rotation_key]).toEqual([
      ['alice.json', 'alice.rotation.json'],
      address,
      rotation.address,
    ])
  })

  it("reads past blank lines in a pasted sheet, asks --relay beside the sheet's, and needs a terminal", async () => {
    const net = new Network()
    const { sheet, address } = await made(net)
    const other = 'http://127.0.0.1:2'
    const io = later(term(net, '', sheet[0] as string, '', ...sheet.slice(1), '', 'no'))
    io.answers.push(true)
    expect(await restore(['alice', '--relay', other, '--dir', home()], io)).toBe(0)
    // The record's relays, where it was found: the address record, then epoch 1's key record.
    expect(net.log.slice(-2)).toEqual([`${R} address ${address}`, `${R} key ${address}`])
    const noTty = term(net, ...sheet)
    noTty.tty = false
    await expect(restore(['alice', '--dir', home()], noTty)).rejects.toMatchObject({ code: 'no-tty' })
  })

  it('publishes anew when no record is held, and keeps single-copy without the second checksum', async () => {
    const net = new Network()
    const { sheet, address } = await made(net)
    const fresh = new Network()
    const dir = home()
    // No source holds a record: the person is warned that a revocation cannot be seen, and must say y (ruling 3).
    const declined = term(fresh, ...sheet)
    const none = home()
    await expect(restore(['alice', '--dir', none], declined)).rejects.toMatchObject({ code: 'declined' })
    expect([files(none), fresh.log, declined.asked]).toEqual([[], [], ['publish the address record anyway?']])
    expect(declined.stderr).toContainEqual(expect.stringContaining('no relay named holds a record of'))
    const io = term(fresh, ...sheet, 'wrong')
    io.answers.push(true)
    expect(await restore(['alice', '--dir', dir], io)).toBe(0)
    expect(io.stdout.slice(0, 3)).toEqual([
      `published address ${address} ${R}`,
      `published key ${address} ${R}`,
      'restored alice (no record was held: published anew)',
    ])
    expect(readRecoveryState(dir, address)?.copy).toBe('single-copy')
    expect(fresh.log).toEqual([`${R} address ${address}`, `${R} key ${address}`])
  })

  it('stops on a record that revokes the address, keeps a rotated record as held, and keeps every revocation (rulings 2 and 3)', async () => {
    const R2 = 'http://127.0.0.1:2'
    const sign = (o: Partial<AddressRecord>, sheet: string[]) => {
      const { keys, rotation } = seedKeys((readSheet(sheet) as { seeds: Seeds }).seeds, FRESH)
      const r = signRecord(keys.signing, {
        kind: 'address',
        key: keys.signing.address,
        sealing_key: toHex(keys.sealing.publicKey),
        relays: [R],
        rotation_key: rotation.address,
        revoked: [],
        ttl: MAX_ADDRESS_TTL,
        iat: T0 + 5,
        rotated_from: null,
        ...o,
      })
      return r
    }
    // (a) revoked lists the address: stop, a reject line, nothing stored.
    const a = new Network()
    const { sheet, address } = await made(a)
    await a.publish(R, serializeRecord(sign({ revoked: [address] }, sheet)))
    const dirA = home()
    await expect(restore(['alice', '--dir', dirA], term(a, ...sheet))).rejects.toMatchObject({
      code: 'revoked',
    })
    expect([existsSync(join(dirA, 'keys')), auditOf(dirA, 'alice')]).toEqual([
      false,
      [{ event: 'restore', decision: 'reject', detail: { revoked: true } }],
    ])
    // (b) rotated_from set and the keys match: restored, the record left as held. A rotated record with no sealing key
    // takes the key record alone; one that still names a sealing key is refused bad-rotation, after the keys are
    // stored and before any epoch is.
    const b = new Network()
    const made2 = await made(b)
    const prev = generateEdgeKeys({ bytes: (l) => new Uint8Array(l).fill(5) })
    const rotated = countersignRotation(
      prev.signing,
      sign({ rotated_from: prev.signing.address, sealing_key: null }, made2.sheet),
    )
    await b.publish(R, serializeRecord(rotated))
    const logged = [...b.log]
    const dirB = home()
    const ioB = later(term(b, ...made2.sheet, made2.sheet[3] as string))
    expect(await restore(['alice', '--dir', dirB], ioB)).toBe(0)
    expect(ioB.stdout.slice(0, 2)).toEqual([
      `kept address ${made2.address} as held: it names rotated_from ${prev.signing.address}, which only that key signs again`,
      `published key ${made2.address} ${R}`,
    ])
    expect(b.log).toEqual([...logged, `${R} key ${made2.address}`])
    expect(held(b, made2.address)).toMatchObject({
      iat: T0 + 5,
      rotated_from: prev.signing.address,
      sealing_key: null,
    })
    expect(epochStore(dirB).epochs(made2.address)).toEqual([1])
    const b2 = new Network()
    const made2b = await made(b2)
    const prev2 = generateEdgeKeys({ bytes: (l) => new Uint8Array(l).fill(5) })
    await b2.publish(
      R,
      serializeRecord(
        countersignRotation(prev2.signing, sign({ rotated_from: prev2.signing.address }, made2b.sheet)),
      ),
    )
    const loggedB2 = [...b2.log]
    const dirB2 = home()
    const ioB2 = later(term(b2, ...made2b.sheet, made2b.sheet[3] as string))
    const refused = await restore(['alice', '--dir', dirB2], ioB2).catch((x) => x)
    expect([code(refused), (refused as Error).message]).toEqual([
      'bad-rotation',
      expect.stringMatching(/^bad-rotation: alice is stored with its state, but bad-rotation: /),
    ])
    expect(['alice.json', 'alice.rotation.json'].map((f) => existsSync(join(dirB2, 'keys', f)))).toEqual([
      true,
      true,
    ])
    expect([epochStore(dirB2).epochs(made2b.address), b2.log]).toEqual([[], loggedB2])
    // (c) two relays, one with a revocation of another key: the newest record wins, and the revocation is kept.
    const c = new Network()
    const made3 = await made(c)
    const other = generateEdgeKeys({ bytes: (l) => new Uint8Array(l).fill(6) }).signing.address
    await c.publish(R, serializeRecord(sign({ relays: [R, R2] }, made3.sheet)))
    await c.publish(R2, serializeRecord(sign({ relays: [R2], revoked: [other], iat: T0 + 3 }, made3.sheet)))
    // The clock reads between the init (T0) and the newest record found (T0 + 5): the republish takes that record's iat + 1.
    const ioC = term(c, ...made3.sheet, made3.sheet[3] as string)
    ioC.time.now = T0 + 3
    ioC.answers.push(true)
    expect(await restore(['alice', '--dir', home()], ioC)).toBe(0)
    // A found record and a declined confirm: nothing stored, nothing published.
    const logged3 = [...c.log]
    const no = home()
    await expect(restore(['alice', '--dir', no], term(c, ...made3.sheet))).rejects.toMatchObject({
      code: 'declined',
    })
    expect([files(no), c.log]).toEqual([[], logged3])
    for (const url of [R, R2]) {
      const r = parseRecord(c.record(url, made3.address, 'address') as string) as AddressRecord
      expect([url, r.revoked, r.relays, r.iat]).toEqual([url, [other], [R, R2], T0 + 6])
    }
  })

  it('makes no network call on a sheet that does not check, and stops on a record of other keys', async () => {
    const net = new Network()
    const { sheet, address } = await made(net)
    for (const lines of [sheet.slice(0, 3), [...sheet.slice(0, 3), '00000000']]) {
      const quiet = new Network()
      await expect(restore(['alice', '--dir', home()], term(quiet, ...lines))).rejects.toMatchObject({
        code: 'bad-sheet',
      })
      expect(quiet.relays.size).toBe(0)
    }
    // A rotation moved the rotation key: the record names another one, so the sheet is stale. The sealing key is
    // not compared: the sheet holds no sealing seed.
    const other = generateEdgeKeys({ bytes: (l) => new Uint8Array(l).fill(7) })
    const before = held(net, address)
    const { keys } = seedKeys((readSheet(sheet) as { seeds: Seeds }).seeds, FRESH)
    const rotated = signRecord(keys.signing, {
      kind: 'address',
      key: before.key,
      sealing_key: before.sealing_key,
      relays: before.relays,
      rotation_key: other.signing.address,
      revoked: [],
      ttl: before.ttl,
      iat: before.iat + 10,
      rotated_from: null,
    })
    await net.publish(R, serializeRecord(rotated))
    const dir = home()
    const logged = [...net.log]
    await expect(restore(['alice', '--dir', dir], term(net, ...sheet))).rejects.toMatchObject({
      code: 'stale-record',
      message: expect.stringContaining(`sheet stale since ${before.iat + 10}`),
    })
    expect([existsSync(join(dir, 'keys')), net.log]).toEqual([false, logged])
    expect(auditOf(dir, 'alice')).toEqual([
      { event: 'restore', decision: 'reject', detail: { stale_since: before.iat + 10 } },
    ])
    // A relay that answers another identity's record for the address is refused, nothing stored.
    const bob = generateEdgeKeys({ bytes: (l) => new Uint8Array(l).fill(8) })
    const bobs = signRecord(bob.signing, {
      ...rotated,
      key: bob.signing.address,
      sealing_key: null,
      iat: before.iat,
    })
    net.at(R).records.set(`${address} address`, serializeRecord(bobs))
    await expect(restore(['alice', '--dir', home()], term(net, ...sheet))).rejects.toMatchObject({
      code: 'bad-record',
    })
    expect(code(await restore(['alice', '--dir', dir], term(net)).catch((e) => e))).toBe('bad-sheet')
  })
})

describe('the state beside a keygen identity, and the stale line', () => {
  it('keygen says it keeps no recovery copy; a state with stale_since reads back for the login line', async () => {
    const net = new Network()
    const dir = home()
    const io = testIo(net)
    io.tty = true
    expect(keygen(['sess', '--dir', dir], io)).toBe(0)
    expect(io.stderr).toEqual([NO_RECOVERY])
    const script = testIo(net) // not a terminal: no notice
    expect(keygen(['sess2', '--dir', dir], script)).toBe(0)
    expect(script.stderr).toEqual([])
    const address = io.stdout[0] as string
    writeRecoveryState(dir, address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: T0 + 60 })
    expect(readRecoveryState(dir, address)?.stale_since).toBe(T0 + 60)
  })

  it('a rotation marks the copy stale on the old address and carries it to the new one, and runs by name', async () => {
    const net = new Network()
    const { dir, address } = await made(net)
    const io = testIo(net)
    const next = (await cli(io, 'keygen', 'alice2', '--dir', dir)).out[0] as string
    const out = join(dir, 'alice2.address.json')
    const r = await cli(
      io,
      'record',
      'address',
      'alice2',
      '--relay',
      R,
      '--rotated-from',
      'alice',
      '--out',
      out,
      '--dir',
      dir,
    )
    expect(r.code).toBe(0)
    for (const a of [address, next])
      expect(readRecoveryState(dir, a)).toMatchObject({ copy: 'sheet', stale_since: T0 })
    // Without a state for the old address, a rotation writes none.
    const plain = home()
    await cli(io, 'keygen', 'p1', '--dir', plain)
    await cli(io, 'keygen', 'p2', '--dir', plain)
    await cli(
      io,
      'record',
      'address',
      'p2',
      '--relay',
      R,
      '--rotated-from',
      'p1',
      '--out',
      join(plain, 'p2.json'),
      '--dir',
      plain,
    )
    expect(readdirSync(plain).filter((f) => f.startsWith('recovery-state'))).toEqual([])
    // The commands are registered: ac init and ac restore run by name.
    expect((await cli(term(net), 'restore', 'Bad')).code).not.toBe(0)
    expect((await cli(term(net), 'init', 'Bad', '--relay', R)).err[0]).toMatch(
      /^bag: usage: "Bad" is not a key name/,
    )
  })

  it('ac login prints recovery: stale since <time> while the state says so, and nothing without it', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(home())
    publishRecord(relay, h)
    writeRecoveryState(h.dir, h.address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: T0 - 60 })
    const login = await loggedIn(relay, h)
    expect(login.io.stdout.at(-1)).toBe(`recovery: stale since ${instant(T0 - 60)}`)
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await login.ran).code).toBe(0)
    // No stale_since: no line. A state file that does not read: one stderr line, and the login goes on.
    writeRecoveryState(h.dir, h.address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: null })
    const clean = await loggedIn(relay, h)
    expect(clean.io.stdout.some((l) => l.startsWith('recovery:'))).toBe(false)
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    await clean.ran
    writeFileSync(join(h.dir, `recovery-state.${h.address}.json`), '{"v":2}')
    const broken = await loggedIn(relay, h)
    expect(broken.io.stderr).toContainEqual(
      expect.stringMatching(/^login: bad-state: .* is not a recovery state of version 1$/),
    )
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await broken.ran).code).toBe(0)
  })
})
