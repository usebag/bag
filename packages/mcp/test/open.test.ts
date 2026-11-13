import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import {
  buildEnvelope,
  type Hop,
  isAcError,
  newThread,
  parseEnvelope,
  serializeRecord,
  signHop,
  toHex,
} from '@usebag/core'
import { keepAddressCopy, LOCAL_RELAY, RelayError } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { type Config, ConfigError, parseConfig } from '../src/config.ts'
import {
  acquireLock,
  HeldError,
  jitteredDelay,
  noteLockHost,
  type OpenDeps,
  observed,
  openIdentity,
  pidAlive,
  readLock,
  startDelayMs,
} from '../src/open.ts'
import {
  addressRecord,
  FakeClock,
  P,
  RELAY,
  saveKeys,
  seededRng,
  sessionChain,
  T0,
  tempDir,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

let tmp: ReturnType<typeof tempDir>

beforeEach(() => {
  tmp = tempDir('open')
})

afterEach(() => {
  tmp.cleanup()
})

function config(args: readonly string[]): Config {
  return parseConfig(['--relay', RELAY, '--dir', tmp.dir, ...args], {}) as Config
}

function deps(over: Partial<OpenDeps> = {}): OpenDeps {
  return {
    clock: new FakeClock(),
    rng: seededRng('open'),
    relay: new MemoryRelay(),
    accepted: () => {},
    onError: () => {},
    pid: 4242,
    alive: () => false,
    ...over,
  }
}

function writeChain(name: string, value: unknown): string {
  const file = join(tmp.dir, name)
  writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value)}\n`)
  return file
}

/** The code an opening fails with: the closed set's, the server's own, or an errno. */
function failure(fn: () => unknown): string {
  try {
    fn()
  } catch (e) {
    if (isAcError(e) || e instanceof ConfigError) return e.code
    return String((e as { code?: unknown }).code)
  }
  throw new Error('it opened')
}

describe('the lock file: one server per identity', () => {
  it('pidAlive is true for this process and for a process of another user, false for one that is gone', () => {
    expect(pidAlive(process.pid)).toBe(true)
    expect(pidAlive(1)).toBe(true)
    const gone = spawnSync(process.execPath, ['-e', '0']).pid as number
    expect(pidAlive(gone)).toBe(false)
  })

  it('takes a free lock with its pid, 0600, and the release removes it', () => {
    const path = join(tmp.dir, 'mcp.lock')
    const release = acquireLock(path, 7, () => true)
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({
      pid: 7,
      started_at: expect.any(String),
      cwd: process.cwd(),
      ppid: process.ppid,
    })
    expect(statSync(path).mode & 0o777).toBe(0o600)
    release()
    expect(existsSync(path)).toBe(false)
  })

  it('writes whether a server keeps its records alive beside the pid, and still reads the pid alone', () => {
    const path = join(tmp.dir, 'mcp.lock')
    for (const keepAlive of [true, false]) {
      const release = acquireLock(path, 7, () => true, keepAlive)
      expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ pid: 7, keep_alive: keepAlive })
      expect(failure(() => acquireLock(path, 8, () => true))).toBe('busy')
      release()
      expect(existsSync(path)).toBe(false)
    }
  })

  it('refuses with busy while a live process holds it, and takes over one left by a process that is gone', () => {
    const path = join(tmp.dir, 'mcp.lock')
    acquireLock(path, 7, () => true)
    expect(failure(() => acquireLock(path, 8, (pid) => pid === 7))).toBe('busy')
    const release = acquireLock(path, 8, () => false)
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ pid: 8 })
    writeFileSync(path, '{"pid":"eight"}')
    expect(acquireLock(path, 10, () => true)).toBeTypeOf('function')
    writeFileSync(path, 'not json')
    const third = acquireLock(path, 9, () => true)
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ pid: 9 })
    release()
    expect(existsSync(path)).toBe(true)
    third()
    expect(existsSync(path)).toBe(false)
  })

  it('names the holder in the refusal: pid, start time, host and folder, and reads a lock an older server wrote', () => {
    const path = join(tmp.dir, 'mcp.lock')
    writeFileSync(
      path,
      JSON.stringify({ pid: 7, started_at: '2026-11-11T12:00:00.000Z', cwd: '/work/a', host: 'omp' }),
    )
    expect(readLock(path)).toEqual({
      pid: 7,
      startedAt: '2026-11-11T12:00:00.000Z',
      cwd: '/work/a',
      host: 'omp',
    })
    try {
      acquireLock(path, 8, () => true)
      throw new Error('it opened')
    } catch (e) {
      expect(e).toBeInstanceOf(HeldError)
      expect((e as HeldError).message).toBe(
        'busy: bag: the identity ' +
          `${basename(tmp.dir)} is held by another session (pid 7, started 2026-11-11T12:00:00.000Z, omp) in /work/a; ` +
          'close that session or run bag in its own folder',
      )
    }
    writeFileSync(path, '{"pid":7,"keep_alive":true}')
    expect(readLock(path)).toEqual({ pid: 7 })
    writeFileSync(path, 'nope')
    expect(readLock(path)).toBeNull()
  })

  it('noteLockHost adds the host to its own lock only', () => {
    const path = join(tmp.dir, 'mcp.lock')
    acquireLock(path, 7, () => true)
    noteLockHost(path, 9, 'codex')
    expect(readLock(path)?.host).toBeUndefined()
    noteLockHost(path, 7, 'omp')
    expect(readLock(path)).toMatchObject({ pid: 7, host: 'omp' })
    noteLockHost(join(tmp.dir, 'none.lock'), 7, 'omp')
  })

  it('does not leave a half-written or temporary file, and takes a lock over only from a holder that is gone', () => {
    const path = join(tmp.dir, 'mcp.lock')
    const release = acquireLock(path, 7, () => true)
    expect(readdirSync(tmp.dir).filter((f) => f.includes('mcp.lock'))).toEqual(['mcp.lock'])
    release()
    // Two servers find the lock of a dead holder: the first takes it, the second is refused as held by the first.
    writeFileSync(path, '{"pid":5}')
    const first = acquireLock(path, 8, (p) => p === 8)
    expect(() => acquireLock(path, 9, (p) => p === 8)).toThrow(HeldError)
    expect(readLock(path)?.pid).toBe(8)
    first()
  })

  it('puts back a live lock that was swapped in while the stale one was moved aside', () => {
    const path = join(tmp.dir, 'mcp.lock')
    writeFileSync(path, '{"pid":5}')
    const swapping = (p: number): boolean => {
      if (p !== 5) return p === 6
      writeFileSync(path, '{"pid":6}') // another server takes it over between the check and the move
      return false
    }
    try {
      acquireLock(path, 9, swapping)
      throw new Error('it opened')
    } catch (e) {
      expect(e).toBeInstanceOf(HeldError)
      expect((e as HeldError).holder.pid).toBe(6)
    }
    expect(readLock(path)?.pid).toBe(6)
    expect(readdirSync(tmp.dir).filter((f) => f.includes('stale'))).toEqual([])
  })

  it('treats a lock whose pid another process now has as stale: that process started after the lock was written', () => {
    const path = join(tmp.dir, 'mcp.lock')
    // This process is alive and started long after 2000.
    writeFileSync(path, JSON.stringify({ pid: process.pid, started_at: '2000-01-01T00:00:00.000Z' }))
    const release = acquireLock(path, 8, () => true)
    expect(readLock(path)?.pid).toBe(8)
    release()
    // Written now, it is a live holder.
    writeFileSync(path, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }))
    expect(() => acquireLock(path, 8, () => true)).toThrow(HeldError)
    // A lock without started_at is judged by the file's time.
    writeFileSync(path, JSON.stringify({ pid: process.pid }))
    expect(() => acquireLock(path, 8, () => true)).toThrow(HeldError)
  })

  it('rethrows an error other than EEXIST: a state directory that does not exist', () => {
    expect(failure(() => acquireLock(join(tmp.dir, 'no', 'such', 'mcp.lock'), 8, () => false))).toBe('ENOENT')
  })
})

describe('observed: the relay client with arrivals reported and errors passed on', () => {
  it('passes publish, fetch, record lookups and acks through', async () => {
    const relay = new MemoryRelay()
    const client = observed(relay, { mailbox: 'mb' })
    expect(await client.fetchRecord(RELAY, P.bob.address, 'address')).toBeNull()
    await expect(
      client.fetch(RELAY, 'f'.repeat(64), { signer: '', ts: 0, sig: '', auth: [] }),
    ).rejects.toThrow('not-found')
    await expect(client.publish(RELAY, new TextEncoder().encode('{"kind":"x"}'))).rejects.toThrow()
    const sub = client.subscribe(RELAY, 'mb', P.bob.keys.signing, [], null)
    sub.ack(3)
    expect(relay.acks.get(`${RELAY} mb`)).toBe(3)
    const frames = sub[Symbol.asyncIterator]()
    sub.close()
    expect(await frames.next()).toEqual({ value: undefined, done: true })
    expect(relay.presented).toEqual([
      { call: 'fetch', hops: [] },
      { call: 'subscribe', hops: [] },
    ])
  })

  it('passes the pair rendezvous calls through when the client offers them, and leaves them absent when not', async () => {
    const relay = new MemoryRelay()
    const bare = observed(relay, { mailbox: 'mb' })
    expect([bare.pairOpen, bare.pairClaim]).toEqual([undefined, undefined])
    relay.offerRendezvous(() => 1000)
    const client = observed(relay, { mailbox: 'mb' })
    const open = { inviter: P.alice.address, invitation: P.bob.address, relays: [RELAY], ttl: 600, sig: '' }
    const nameplate = await client.pairOpen?.(RELAY, open)
    expect(nameplate).toBe('472')
    expect(await client.pairClaim?.(RELAY, '472')).toEqual({
      inviter: P.alice.address,
      invitation: P.bob.address,
      relays: [RELAY],
      exp: 1600,
    })
  })

  it("presents the edge's own hops at subscribe and fetch (a renewal is the edge's), and passes each frame error on", async () => {
    const relay = new MemoryRelay()
    const hops = sessionChain().slice(1)
    const errors: string[] = []
    const client = observed(relay, {
      mailbox: 'mb',
      onSubscriptionError: (url, e) => errors.push(`${url} ${(e as RelayError).code}`),
    })
    await expect(
      client.fetch(RELAY, 'f'.repeat(64), { signer: '', ts: 0, sig: '', auth: hops }),
    ).rejects.toThrow('not-found')
    const sub = client.subscribe(RELAY, 'mb', P.session.keys.signing, hops, null)
    expect(relay.presented.map((p) => p.hops)).toEqual([hops, hops])
    relay.failSubscribe = new RelayError('hop-expired', 0, null, 'the chain expired')
    await expect(sub[Symbol.asyncIterator]().next()).rejects.toThrow('hop-expired')
    expect(errors).toEqual([`${RELAY} hop-expired`])
    // Without an error hook the error still reaches the Receiver.
    const bare = observed(relay, { mailbox: 'mb' }).subscribe(RELAY, 'mb', P.bob.keys.signing, [], null)
    await expect(bare[Symbol.asyncIterator]().next()).rejects.toThrow('hop-expired')
    relay.failSubscribe = null
    sub.close()
    bare.close()
  })

  it("reports on the mailbox alone: a pairing's invitation, subscribed through this client, is no sign of it", async () => {
    const relay = new MemoryRelay()
    const seen: string[] = []
    const client = observed(relay, {
      mailbox: 'mb',
      onLink: (url, link) => seen.push(`link ${url} ${link.admitted}`),
      onArrival: (url) => seen.push(`arrival ${url}`),
      onSubscriptionError: (url) => seen.push(`error ${url}`),
      onFrame: () => seen.push('frame'),
    })
    relay.boxes.set(`${RELAY} invitation`, [{ cursor: 1, bytes: new Uint8Array(1) }])
    const invitation = client.subscribe(RELAY, 'invitation', P.bob.keys.signing, [], null)
    await invitation[Symbol.asyncIterator]().next()
    relay.failSubscribe = new RelayError('hop-expired', 0, null, 'the chain expired')
    await expect(invitation[Symbol.asyncIterator]().next()).rejects.toThrow('hop-expired')
    relay.failSubscribe = null
    invitation.close()
    expect(seen).toEqual([])
    relay.boxes.set(`${RELAY} mb`, [{ cursor: 1, bytes: new Uint8Array(1) }])
    const mailbox = client.subscribe(RELAY, 'mb', P.bob.keys.signing, [], null)
    await mailbox[Symbol.asyncIterator]().next()
    mailbox.close()
    expect(seen).toEqual([`link ${RELAY} true`, 'frame', `arrival ${RELAY}`])
  })
})

describe('openIdentity: keys, chain, lock, store, audit log and edge, as the CLI composes them', () => {
  it('opens a self-rooted principal: it signs and receives as itself, state in <home>/state/<name>/ (0700)', () => {
    saveKeys(tmp.dir, P.alice)
    const opened = openIdentity(config(['--as', 'alice']), deps())
    try {
      expect(opened.identity).toEqual({
        address: P.alice.address,
        mailbox: P.alice.address,
        principal: P.alice.address,
        root: P.alice.address,
      })
      expect([opened.edge.mailbox, opened.edge.auth]).toEqual([P.alice.address, []])
      expect(opened.stateDir).toBe(join(tmp.dir, 'state', 'alice'))
      expect(statSync(opened.stateDir).mode & 0o777).toBe(0o700)
      expect(existsSync(join(opened.stateDir, 'mcp.lock'))).toBe(true)
      expect(opened.signer.address).toBe(P.alice.address)
    } finally {
      opened.close()
    }
    expect(existsSync(join(tmp.dir, 'state', 'alice', 'mcp.lock'))).toBe(false)
  })

  it('with no bag service (stdio) a local: row is refused untrusted-root, even with an allowed pair on disk (r3)', async () => {
    saveKeys(tmp.dir, P.alice)
    keepAddressCopy(tmp.dir, P.carol.name, addressRecord(P.carol))
    // The word on and an allowed pair of alice and carol on disk: the raw table the old default trusted.
    mkdirSync(join(tmp.dir, 'run'), { recursive: true, mode: 0o700 })
    writeFileSync(join(tmp.dir, 'run', 'local.json'), '{"version":1,"local_delivery":"on"}', { mode: 0o600 })
    const row = {
      a: 'alice',
      b: 'carol',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 1,
      state: 'allowed',
    }
    writeFileSync(join(tmp.dir, 'run', 'local-peers.json'), JSON.stringify({ version: 1, pairs: [row] }), {
      mode: 0o600,
    })
    const opened = openIdentity(config(['--as', 'alice']), deps())
    try {
      const rng = seededRng('stdio-local')
      const env = buildEnvelope({
        from: P.carol.keys.signing,
        to: [{ address: P.alice.address, sealingKey: P.alice.keys.sealing.publicKey }],
        auth: [],
        type: 'chat.v1',
        thread: newThread((n) => rng.bytes(n)),
        body: { text: 'from carol' },
        ts: T0,
        rng: (n) => rng.bytes(n),
      })
      // recover() re-receives a stored local: row through this same receive path (receiver.ts localRoots).
      const r = await opened.edge.receive(LOCAL_RELAY, 1, env.bytes)
      expect([r.state, r.reason]).toEqual(['rejected', 'untrusted-root'])
    } finally {
      opened.close()
    }
  })

  it("keeps a --session server's waiting sends in memory, gone at close, and an identity's on disk", () => {
    saveKeys(tmp.dir, P.alice)
    const given = config(['--as', 'alice'])
    const session = { name: 'auto', principal: 'jane', caveats: [], exp: null }
    const opened = openIdentity({ ...given, session }, deps())
    opened.store.waitingAdd('{"body":"plaintext"}', '{}', T0)
    expect(opened.store.waitingList()).toHaveLength(1)
    opened.close()
    const identity = openIdentity(given, deps())
    expect(identity.store.waitingList()).toEqual([])
    identity.store.waitingAdd('{"body":"plaintext"}', '{}', T0)
    identity.close()
    const again = openIdentity(given, deps())
    expect(again.store.waitingList()).toHaveLength(1)
    again.close()
  })

  it("opens a session: it signs as the session key and receives at its principal's mailbox, under the chain", () => {
    saveKeys(tmp.dir, P.session, { signing: P.session.keys.signing, sealing: P.jane.keys.sealing })
    const chain = writeChain('chain.json', sessionChain())
    const opened = openIdentity(
      config(['--as', 'session', '--auth', chain, '--mailbox', P.jane.address, '--honor', 'coding']),
      deps(),
    )
    try {
      expect(opened.identity).toEqual({
        address: P.session.address,
        mailbox: P.jane.address,
        principal: P.jane.address,
        root: P.org.address,
      })
      expect([opened.edge.address, opened.edge.mailbox]).toEqual([P.session.address, P.jane.address])
      expect(opened.edge.auth).toEqual(sessionChain())
      expect(opened.sealingKey).toBe(toHex(P.jane.keys.sealing.publicKey))
    } finally {
      opened.close()
    }
  })

  it("takes a chain already read (--chain-cmd's) in place of the file, and refuses a --chain-cmd session without one", async () => {
    saveKeys(tmp.dir, P.session, { signing: P.session.keys.signing, sealing: P.jane.keys.sealing })
    const args = ['--as', 'session', '--chain-cmd', 'helper', '--mailbox', P.jane.address]
    expect(failure(() => openIdentity(config(args), deps()))).toBe('usage')
    const relay = new MemoryRelay()
    await relay.publish(RELAY, serializeRecord(addressRecord(P.bob)))
    const given = sessionChain()
    const opened = openIdentity(config(args), deps({ auth: given, relay }))
    try {
      expect(opened.edge.auth).toBe(given)
      // A renewal goes through the edge's renewChain: the next envelope carries it, and the array given is unchanged.
      const next = [
        given[0] as Hop,
        signHop(P.jane.keys.signing, P.session.address, ['type=chat.v1'], T0 + 7200),
      ]
      opened.edge.renewChain(next)
      const sent = await opened.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
      const bytes = relay.envelopes.get(`${RELAY} ${sent.id}`) as Uint8Array
      expect(parseEnvelope(bytes).auth).toEqual(next)
      expect([opened.edge.auth, given]).toEqual([next, sessionChain()])
      expect(opened.client).not.toBe(relay)
    } finally {
      opened.close()
    }
  })

  it("refuses a mailbox that is not the chain's principal, a chain to another key, and a chain expired now", () => {
    saveKeys(tmp.dir, P.session)
    const chain = writeChain('chain.json', sessionChain())
    expect(() =>
      openIdentity(config(['--as', 'session', '--auth', chain, '--mailbox', P.org.address]), deps()),
    ).toThrow("usage: --mailbox must be the chain's principal")
    saveKeys(tmp.dir, P.carol)
    expect(
      failure(() =>
        openIdentity(config(['--as', 'carol', '--auth', chain, '--mailbox', P.jane.address]), deps()),
      ),
    ).toBe('chain-not-to-sender')
    const late = deps({ clock: Object.assign(new FakeClock(), { t: T0 + 7200 }) })
    expect(
      failure(() =>
        openIdentity(config(['--as', 'session', '--auth', chain, '--mailbox', P.jane.address]), late),
      ),
    ).toBe('hop-expired')
    const widened = writeChain('wide.json', [
      signHop(P.org.keys.signing, P.jane.address, [], T0 + 60),
      signHop(P.jane.keys.signing, P.session.address, [], T0 + 120),
    ])
    expect(
      failure(() =>
        openIdentity(config(['--as', 'session', '--auth', widened, '--mailbox', P.jane.address]), deps()),
      ),
    ).toBe('exp-not-monotone')
    expect(existsSync(join(tmp.dir, 'state', 'session', 'mcp.lock'))).toBe(false)
  })

  it('refuses a key that does not exist, and an identity a live server holds', () => {
    expect(failure(() => openIdentity(config(['--as', 'nobody']), deps()))).toBe('ENOENT')
    saveKeys(tmp.dir, P.alice)
    const first = openIdentity(config(['--as', 'alice']), deps({ pid: 1 }))
    try {
      expect(failure(() => openIdentity(config(['--as', 'alice']), deps({ alive: () => true })))).toBe('busy')
    } finally {
      first.close()
    }
  })

  it("reads the keys through the home's custody: a name held by a key file and a keychain pointer both is EEXIST", () => {
    saveKeys(tmp.dir, P.alice)
    mkdirSync(join(tmp.dir, 'keychain'), { mode: 0o700 })
    writeFileSync(join(tmp.dir, 'keychain', 'alice.json'), '{}', { mode: 0o600 })
    expect(failure(() => openIdentity(config(['--as', 'alice']), deps()))).toBe('EEXIST')
    expect(existsSync(join(tmp.dir, 'state', 'alice'))).toBe(false)
  })

  it('releases the lock and the store when the audit log cannot be continued or the store cannot be opened', () => {
    saveKeys(tmp.dir, P.alice)
    const state = join(tmp.dir, 'state', 'alice')
    mkdirSync(state, { recursive: true, mode: 0o700 })
    writeFileSync(join(state, 'audit.jsonl'), 'not an audit line\n')
    expect(() => openIdentity(config(['--as', 'alice']), deps())).toThrow()
    expect(existsSync(join(state, 'mcp.lock'))).toBe(false)
    writeFileSync(join(state, 'audit.jsonl'), '')
    const again = openIdentity(config(['--as', 'alice']), deps())
    again.close()
    saveKeys(tmp.dir, P.bob)
    mkdirSync(join(tmp.dir, 'state', 'bob', 'edge.sqlite'), { recursive: true })
    expect(() => openIdentity(config(['--as', 'bob']), deps())).toThrow()
    expect(existsSync(join(tmp.dir, 'state', 'bob', 'mcp.lock'))).toBe(false)
  })
})

/** A random source whose every byte is `b`: 0x00 gives u = 0, 0xff gives u just under 1 (jitterOf). */
const bytesOf = (b: number) => ({ bytes: (n: number) => new Uint8Array(n).fill(b) })

describe('the jitters of an --identities server', () => {
  it('jitteredDelay: the edge 250 ms × 2^n, at most 30 s, times a factor in [0.5, 1.5), still at most 30 s', () => {
    const low = jitteredDelay(bytesOf(0x00))
    const high = jitteredDelay(bytesOf(0xff))
    expect([0, 1, 2, 6, 7, 20].map(low)).toEqual([125, 250, 500, 8000, 15_000, 15_000])
    expect([0, 1, 2, 6].map(high)).toEqual([374, 749, 1499, 23_999])
    // 2^7 × 250 is 32 s: capped at 30 s before the factor, and at 30 s after it.
    expect([7, 20].map(high)).toEqual([30_000, 30_000])
  })

  it("jitteredDelay draws a fresh factor at each attempt from the identity's own source", () => {
    let calls = 0
    const counting = {
      bytes: (n: number) => {
        calls++
        return new Uint8Array(n).fill(calls % 2 === 0 ? 0xff : 0x00)
      },
    }
    const delay = jitteredDelay(counting)
    expect([delay(3), delay(3), delay(3)]).toEqual([1000, 2999, 1000])
    expect(calls).toBe(3)
  })

  it("startDelayMs: uniform in [0, spread) seconds, and 0 for the default identity's spread of 0", () => {
    expect(startDelayMs(bytesOf(0x00), 20)).toBe(0)
    expect(startDelayMs(bytesOf(0xff), 20)).toBe(19_999)
    // 0x80808080 / 2^32 is 0.50196..., so 10,039 ms of 20 s.
    expect(startDelayMs(bytesOf(0x80), 20)).toBe(10_039)
    expect(startDelayMs(bytesOf(0xff), 0)).toBe(0)
  })
})
