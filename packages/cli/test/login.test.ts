import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  type Hop,
  parseRecord,
  SigningKey,
  sealingKeyFromSeed,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { afterAll, afterEach, describe, expect, it, onTestFinished, vi } from 'vitest'
import { epochStore } from '../src/home.ts'
import {
  type AgentHome,
  agentHome,
  CAVEAT,
  heldAddress,
  loggedIn,
  loggedInAt,
  publishRecord,
  RELAY,
  sessionAddress,
} from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// ac login: the window on a terminal, the first grant signed after one y typed
// there, and the window's end by ac logout or a signal, which publishes the re-signed address record.

const tmp = tempDir('login')
afterAll(() => tmp.cleanup())
// A test that fails with a window open leaves no agent behind: the signal ends it as a terminal's hangup would.
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
const dir = (): string => join(tmp.dir, `h${n++}`)
const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5))

/** Watches every 32-byte array overwritten with zeros: what it held before, and the array itself. */
function zeroed(): { readonly seen: Map<string, Uint8Array>; restore(): void } {
  const seen = new Map<string, Uint8Array>()
  const fill = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function (this: Uint8Array, v: number, start?: number, end?: number) {
    if (this.length === 32 && v === 0) seen.set(toHex(this), this)
    return fill.call(this, v, start, end)
  } as typeof fill
  return {
    seen,
    restore: () => {
      Uint8Array.prototype.fill = fill
    },
  }
}

/** Whether the window's end overwrote the principal's two seeds, the buffers login read them into. */
function seedsZeroed(z: ReturnType<typeof zeroed>, h: AgentHome): boolean {
  const own = [h.keys.signing.exportSeed(), h.keys.sealing.exportSeed()].map((s) => z.seen.get(toHex(s)))
  return own.every((b) => b?.every((x) => x === 0))
}

describe('ac login', () => {
  it('opens a window, signs a first grant after a y, and publishes the revocation at ac logout', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const z = zeroed()
    onTestFinished(z.restore)
    const login = await loggedIn(relay, h)
    const sock = join(h.dir, 'agent.sock')
    expect(login.io.stdout).toEqual([
      `login ${h.address} until 2027-01-15T16:00:00Z on ${sock}`,
      `published key ${h.address} ${RELAY}`,
      `published address ${h.address} ${RELAY}`,
    ])
    const io = testIo(relay)
    const S = sessionAddress()
    login.io.lines.push('y')
    const args = ['--session', S, '--caveat', CAVEAT, '--exp', '+600', '--dir', h.dir]
    const g = await cli(io, 'grant', '--as', 'jane', ...args)
    expect(g.code).toBe(0)
    const [hop] = JSON.parse(g.out[0] as string) as Hop[]
    expect(hop).toMatchObject({ iss: h.address, sub: S, caveats: [CAVEAT], exp: T0 + 600 })
    expect(g.err[0]).toMatch(/^request [0-9a-f]{8}: /)
    expect(login.io.stderr.join('\n')).toContain(S)
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    // The epoch at login re-signed the held record at T0 + 1 (one past its iat), so the logout's follows at T0 + 2.
    expect(out).toEqual({ code: 0, out: [`published address ${h.address} iat ${T0 + 2} ${RELAY}`], err: [] })
    expect(heldAddress(relay, h.address)).toMatchObject({ revoked: [S], iat: T0 + 2 })
    expect(await login.ran).toMatchObject({
      code: 0,
      out: [
        expect.any(String),
        `published key ${h.address} ${RELAY}`,
        `published address ${h.address} ${RELAY}`,
        `logout ${h.address}`,
      ],
    })
    expect(existsSync(join(h.dir, 'agent-audit.jsonl'))).toBe(true)
    expect(seedsZeroed(z, h)).toBe(true)
  })

  it('ends at a hangup: the live grant revoked, the record published by login itself', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const z = zeroed()
    onTestFinished(z.restore)
    const login = await loggedIn(relay, h, '--window', '60')
    expect(seedsZeroed(z, h)).toBe(false)
    expect(login.io.stdout[0]).toContain('until 2027-01-15T08:01:00Z')
    const S = sessionAddress()
    login.io.lines.push('y')
    const io = testIo(relay)
    const args = ['--session', S, '--caveat', CAVEAT, '--exp', String(T0 + 60), '--dir', h.dir]
    expect((await cli(io, 'grant', '--as', 'jane', ...args)).code).toBe(0)
    process.emit('SIGHUP')
    const ran = await login.ran
    expect(ran.code).toBe(0)
    expect(ran.out).toContain(`published address ${h.address} iat ${T0 + 2} ${RELAY}`)
    expect(heldAddress(relay, h.address).revoked).toEqual([S])
    expect(seedsZeroed(z, h)).toBe(true)
  })

  it('reports the subjects left out when the record cannot take them, and exits 1', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    const full = Array.from({ length: 1024 }, (_, i) => `ed25519:${i.toString(16).padStart(64, '0')}`)
    publishRecord(relay, h, { revoked: full })
    const login = await loggedIn(relay, h)
    const S = sessionAddress()
    login.io.lines.push('y')
    const io = testIo(relay)
    await cli(io, 'grant', '--as', 'jane', '--session', S, '--caveat', CAVEAT, '--exp', '+60', '--dir', h.dir)
    relay.published.length = 0
    process.emit('SIGHUP')
    const ran = await login.ran
    expect(ran.code).toBe(1)
    expect(ran.err.at(-1)).toMatch(/^bag: bad-record: revoke: too many revoked/)
    expect(relay.published).toEqual([])
  })

  it('takes the newest address record of the relays named and of the relays it names, and reports an empty one', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    const [B, C] = ['http://127.0.0.1:8', 'http://127.0.0.1:7']
    const X = sessionAddress()
    const old = serializeRecord(publishRecord(relay, h, { relays: [RELAY, B, C] }))
    const newer = serializeRecord(
      publishRecord(relay, h, { relays: [RELAY, B, C], iat: T0 + 5, revoked: [X] }),
    )
    relay.recordsAt.set(RELAY, new Map([[`${h.address} address`, old]]))
    relay.recordsAt.set(B, new Map([[`${h.address} address`, newer]]))
    relay.recordsAt.set(C, new Map())
    const login = await loggedIn(relay, h)
    expect(login.io.stderr).toEqual([`login: ${C} holds no address record of ${h.address}`])
    const S = sessionAddress()
    login.io.lines.push('y')
    const io = testIo(relay)
    await cli(io, 'grant', '--as', 'jane', '--session', S, '--caveat', CAVEAT, '--exp', '+60', '--dir', h.dir)
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    // The epoch at login re-signed the newest record (its relays and its revoked entry) one second past its iat, T0 + 6,
    // so the logout's record follows that one: iat T0 + 7, with X kept and S added, at all three relays.
    expect(out.out).toEqual([RELAY, B, C].map((u) => `published address ${h.address} iat ${T0 + 7} ${u}`))
    expect(heldAddress(relay, h.address)).toMatchObject({ revoked: [X, S], sealing_key: null })
    expect((await login.ran).code).toBe(0)
  })

  it('refuses a record that does not verify at a relay the newest record names', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    const B = 'http://127.0.0.1:8'
    const good = serializeRecord(publishRecord(relay, h, { relays: [RELAY, B] }))
    const other = agentHome(dir())
    const theirs = serializeRecord(publishRecord(relay, other, { iat: T0 + 5 }))
    relay.recordsAt.set(RELAY, new Map([[`${h.address} address`, good]]))
    relay.recordsAt.set(B, new Map([[`${h.address} address`, theirs]]))
    const io = testIo(relay)
    io.tty = true
    const r = await cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', h.dir)
    expect(r.err.at(-1)).toMatch(new RegExp(`^bag: bad-record: ${B} answered another record`))
    expect(existsSync(join(h.dir, 'agent.sock'))).toBe(false)
  })

  it('fails on any relay that fails, before it reads a seed, and leaves no socket', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    relay.failRecordFetch.set('http://127.0.0.1:8', new RelayError(null, 0, null, 'no answer'))
    const read = vi.spyOn(SigningKey.prototype, 'exportSeed')
    onTestFinished(() => read.mockRestore())
    const io = testIo(relay)
    io.tty = true
    const relays = ['--relay', RELAY, '--relay', 'http://127.0.0.1:8']
    const r = await cli(io, 'login', '--as', 'jane', ...relays, '--dir', h.dir)
    expect(r.code).toBe(1)
    expect(r.err.at(-1)).toBe('bag: unreachable: no response: no answer')
    expect(read).not.toHaveBeenCalled()
    expect(existsSync(join(h.dir, 'agent.sock'))).toBe(false)
  })

  it('answers window-open to a record address of the principal while it reads the records', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    let open: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      open = resolve
    })
    const fetch = relay.fetchRecord.bind(relay)
    relay.fetchRecord = async (url, address, kind) => {
      await gate
      return fetch(url, address, kind)
    }
    const io = testIo(relay)
    io.tty = true
    const ran = cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', h.dir)
    while (!existsSync(join(h.dir, 'agent.sock'))) await tick()
    const made = await cli(testIo(relay), 'record', 'address', 'jane-keys', '--relay', RELAY, '--dir', h.dir)
    expect(made.err[0]).toBe('bag: window-open: a login window holds jane: run ac logout first')
    open()
    while (!io.stdout.some((l) => l.startsWith('login '))) await tick()
    await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)
    expect((await ran).code).toBe(0)
  })

  it('releases a prompt still waiting for its answer when the window ends', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const login = await loggedIn(relay, h)
    let answer: (line: string | null) => void = () => {}
    let released = false
    login.io.readLine = () =>
      new Promise((resolve) => {
        answer = resolve
      })
    login.io.release = () => {
      released = true
      answer(null)
    }
    const io = testIo(relay)
    const S = sessionAddress()
    const args = ['--as', 'jane', '--session', S, '--caveat', CAVEAT, '--exp', '+60', '--dir', h.dir]
    const asked = cli(io, 'grant', ...args)
    while (!login.io.stderr.some((l) => l.startsWith('request '))) await tick()
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    expect(out.out).toEqual(['logout: nothing to revoke'])
    expect((await login.ran).code).toBe(0)
    expect(released).toBe(true)
    expect((await asked).err.at(-1)).toMatch(/^bag: agent-locked: /)
  })

  it('refuses no terminal, a window over 8 hours, an identity of another custody and a pointer with no seeds', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    const io = testIo(relay)
    const login = (...more: string[]) => cli(io, 'login', '--relay', RELAY, '--dir', h.dir, ...more)
    expect((await login('--as', 'jane')).err[0]).toMatch(/^bag: no-tty: /)
    io.tty = true
    expect((await login('--as', 'jane', '--window', '28801')).err[0]).toMatch(/^bag: usage: --window/)
    expect((await login('--as', 'jane-keys')).err[0]).toBe(
      'bag: usage: jane-keys is a file identity, not an agent identity',
    )
    const bare = agentHome(dir(), 'jane', false)
    publishRecord(relay, bare)
    const r = await cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', bare.dir)
    expect(r.err.at(-1)).toBe(`bag: ENOENT: no key file or keychain identity holds ${bare.address}`)
  })

  it('refuses no address record, a record of another key and a rotation record at the relays', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    const io = testIo(relay)
    io.tty = true
    const login = () => cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', h.dir)
    expect((await login()).err.at(-1)).toMatch(/^bag: not-found: no address record of /)
    const other = agentHome(dir())
    publishRecord(relay, other)
    relay.records.set(`${h.address} address`, relay.records.get(`${other.address} address`) as Uint8Array)
    expect((await login()).err[0]).toMatch(/^bag: bad-record: /)
    publishRecord(relay, h, { rotated_from: other.address }, other.keys.signing)
    expect((await login()).err[0]).toBe('bag: rotation: logout re-signs no rotation record')
  })
})

describe('ac login: a new epoch once the newest is 12 hours old', () => {
  const seal = sealingKeyFromSeed(new Uint8Array(32).fill(4))

  it('publishes the key record and the address record with no sealing key after the login line, and logout re-signs that record', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h, { revoked: [] })
    const login = await loggedIn(relay, h)
    expect(login.io.stdout).toEqual([
      `login ${h.address} until 2027-01-15T16:00:00Z on ${join(h.dir, 'agent.sock')}`,
      `published key ${h.address} ${RELAY}`,
      `published address ${h.address} ${RELAY}`,
    ])
    expect(login.io.stderr).toEqual([])
    expect(parseRecord(relay.records.get(`${h.address} key`) as Uint8Array)).toMatchObject({
      kind: 'key',
      key: h.address,
      iat: T0,
      exp: T0 + 86_400,
    })
    expect(heldAddress(relay, h.address).sealing_key).toBeNull()
    expect(epochStore(h.dir).epochs(h.address)).toEqual([1])
    const S = sessionAddress()
    login.io.lines.push('y')
    const io = testIo(relay)
    const args = ['--session', S, '--caveat', CAVEAT, '--exp', '+600', '--dir', h.dir]
    expect((await cli(io, 'grant', '--as', 'jane', ...args)).code).toBe(0)
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    expect(out.out).toEqual([`published address ${h.address} iat ${T0 + 2} ${RELAY}`])
    expect(heldAddress(relay, h.address)).toMatchObject({ revoked: [S], sealing_key: null, iat: T0 + 2 })
    expect((await login.ran).code).toBe(0)
  })

  it('publishes the key record alone when the record read names no sealing key, and keeps that record', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    // The record as an earlier login's epoch left it: no sealing key.
    const bare = signRecord(h.keys.signing, {
      kind: 'address',
      key: h.address,
      sealing_key: null,
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 3600,
      iat: T0,
      rotated_from: null,
    })
    relay.records.set(`${h.address} address`, serializeRecord(bare))
    const login = await loggedIn(relay, h)
    expect(login.io.stdout.slice(1)).toEqual([`published key ${h.address} ${RELAY}`])
    expect(epochStore(h.dir).epochs(h.address)).toEqual([1])
    expect(relay.records.get(`${h.address} address`)).toEqual(serializeRecord(bare))
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).out).toEqual([
      'logout: nothing to revoke',
    ])
    expect((await login.ran).code).toBe(0)
  })

  it('rotates nothing while the newest epoch is under 12 hours old, and again once it is exactly 12 hours old', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    epochStore(h.dir).put(h.address, 1, seal, T0 - 43_199, T0 + 43_201)
    epochStore(h.dir).markPublished(h.address, 1) // a published epoch (fs/edge 8c976aa4: put keeps it unpublished)
    const quiet = await loggedIn(relay, h)
    expect(quiet.io.stdout).toHaveLength(1)
    expect(relay.published).toEqual([])
    expect(epochStore(h.dir).epochs(h.address)).toEqual([1])
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await quiet.ran).code).toBe(0)
    // The same epoch one second later is 12 hours old: due.
    const due = await loggedInAt(relay, h, T0 + 1)
    expect(due.io.stdout.slice(1)).toEqual([
      `published key ${h.address} ${RELAY}`,
      `published address ${h.address} ${RELAY}`,
    ])
    expect(epochStore(h.dir).epochs(h.address)).toEqual([2, 1])
    expect((await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await due.ran).code).toBe(0)
  })

  it('opens the window when a relay refuses the epoch: one stderr line naming ac keys rotate, never a refusal', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(dir())
    publishRecord(relay, h)
    relay.failRecordPublish.set(RELAY, new RelayError('stale-record', 409, null, 'not newer'))
    const login = await loggedIn(relay, h)
    expect(login.io.stdout).toEqual([
      `login ${h.address} until 2027-01-15T16:00:00Z on ${join(h.dir, 'agent.sock')}`,
    ])
    expect(login.io.stderr).toEqual([
      `login: no new epoch: stale-record: ${RELAY} did not take the key record of ${h.address}; publish it again: ac keys rotate jane-keys --relay ${RELAY}; senders get resolve-failed once the newest key record lapses (ac keys rotate jane-keys --relay <url> publishes one)`,
    ])
    // The window is open: a first grant is signed, and the logout re-signs the record that was read, sealing key and all.
    const S = sessionAddress()
    login.io.lines.push('y')
    const io = testIo(relay)
    const args = ['--session', S, '--caveat', CAVEAT, '--exp', '+600', '--dir', h.dir]
    expect((await cli(io, 'grant', '--as', 'jane', ...args)).code).toBe(0)
    relay.failRecordPublish.clear()
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    expect(out.out).toEqual([`published address ${h.address} iat ${T0 + 1} ${RELAY}`])
    expect(heldAddress(relay, h.address)).toMatchObject({ revoked: [S] })
    expect(heldAddress(relay, h.address).sealing_key).not.toBeNull()
    expect((await login.ran).code).toBe(0)
  })
})
