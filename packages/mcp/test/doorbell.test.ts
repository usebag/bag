import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { doorbellPath, ring } from '../src/open.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  saveKeys,
  type TestServer,
  tempDir,
  testServer,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The doorbell: <home>/state/<name>/doorbell, empty, 0600 in the 0700 state directory,
// whose mtime moves at most once for each message the edge accepts (the edge's Receiver calls the server's writer
// inside Receiver.ack, when the edge acks the row), and never for a refusal. No test here polls with a real-time cap:
// the server's timers are manual, so a wait call returns only when a message arrives, and the relay hands bob's frames over in cursor order, so once
// wait returns a message, every frame sent before it has been handled. `ring` is wrapped to count its calls exactly.

const rung = vi.hoisted(() => ({ paths: [] as string[] }))
vi.mock('../src/open.ts', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/open.ts')>()
  return {
    ...original,
    ring: (path: string): void => {
      rung.paths.push(path)
      original.ring(path)
    },
  }
})

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
const servers: TestServer[] = []
const OLD = new Date('2020-01-01T00:00:00Z')

beforeEach(() => {
  tmp = tempDir('doorbell')
  relay = new MemoryRelay()
  rung.paths.length = 0
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

async function serverFor(p: Party, args: readonly string[], clock: FakeClock): Promise<TestServer> {
  saveKeys(tmp.dir, p)
  await publishAddress(relay, p)
  const pid = 4000 + servers.length
  const timers = new ManualTimers()
  const s = await testServer({ home: tmp.dir, name: p.name, relay, clock, timers, args, pid })
  servers.push(s)
  return s
}

const mode = (path: string): number => statSync(path).mode & 0o777

describe('doorbellPath and ring', () => {
  it('names <home>/state/<name>/doorbell as an absolute path, a relative home resolved', () => {
    expect(doorbellPath('/h', 'bob')).toBe('/h/state/bob/doorbell')
    expect(doorbellPath('rel/home', 'bob')).toBe(resolve('rel/home', 'state', 'bob', 'doorbell'))
  })

  it('makes the file empty, 0600, in a 0700 directory, and moves its mtime on a second ring, writing nothing', () => {
    const path = doorbellPath(tmp.dir, 'bob')
    ring(path)
    expect([mode(join(tmp.dir, 'state', 'bob')), mode(path), statSync(path).size]).toEqual([0o700, 0o600, 0])
    utimesSync(path, OLD, OLD)
    ring(path)
    expect(statSync(path).mtimeMs).toBeGreaterThan(OLD.getTime())
    expect(readFileSync(path, 'utf8')).toBe('')
  })

  it('refuses a symlink at the path (ELOOP) and leaves its target as it was', () => {
    const path = doorbellPath(tmp.dir, 'bob')
    mkdirSync(join(tmp.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
    const target = join(tmp.dir, 'target')
    writeFileSync(target, 'kept')
    utimesSync(target, OLD, OLD)
    symlinkSync(target, path)
    let code: unknown = null
    try {
      ring(path)
    } catch (e) {
      code = (e as { code?: unknown }).code
    }
    expect(code).toBe('ELOOP')
    expect([readFileSync(target, 'utf8'), statSync(target).mtimeMs]).toEqual(['kept', OLD.getTime()])
  })
})

describe('the server rings the doorbell for each accepted message, never for a refusal', () => {
  it('names the path in its start line and in status, rings once per delivery, and not for a refusal', async () => {
    const clock = new FakeClock()
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], clock)
    const alice = await serverFor(P.alice, [], clock)
    const carol = await serverFor(P.carol, [], clock)
    const path = join(tmp.dir, 'state', 'bob', 'doorbell')
    expect(bob.log.lines.find((l) => l.event === 'start')?.fields.doorbell_path).toBe(path)
    expect((await bob.call('status')).value.doorbell_path).toBe(path)
    expect(existsSync(path)).toBe(false)
    const rejected = (): number => bob.running.desk.counts().counts.rejected
    // carol's root is not trusted. Her message is handled before alice's, which follows it at the relay.
    await carol.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'refused' })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect((await bob.call('wait', {})).value).toMatchObject({ message: { body: 1 } })
    expect([rung.paths, rejected()]).toEqual([[path], 1])
    expect([mode(path), statSync(path).size]).toEqual([0o600, 0])
    utimesSync(path, OLD, OLD)
    await carol.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'refused again' })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 2 })
    expect((await bob.call('wait', {})).value).toMatchObject({ message: { body: 2 } })
    expect([rung.paths, rejected()]).toEqual([[path, path], 2])
    expect([statSync(path).mtimeMs > OLD.getTime(), statSync(path).size]).toEqual([true, 0])
  })

  it('logs a doorbell it cannot touch, and delivers the message all the same', async () => {
    const clock = new FakeClock()
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], clock)
    const alice = await serverFor(P.alice, [], clock)
    // A directory where the file belongs: opening it to write fails with EISDIR.
    mkdirSync(join(tmp.dir, 'state', 'bob', 'doorbell'))
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'still delivered' })
    // The ring comes just before the accepted call that hands the message to the desk, so the log line is there once
    // wait returns.
    expect((await bob.call('wait', {})).value).toMatchObject({ message: { body: 'still delivered' } })
    expect(bob.log.lines.find((l) => l.event === 'doorbell')).toMatchObject({
      level: 'error',
      fields: { code: 'EISDIR' },
    })
    expect(bob.running.desk.counts().counts.accepted).toBe(1)
  })

  it('refuses a FIFO at the path at once (ENXIO, no reader) instead of blocking, and delivers the message all the same', async () => {
    const path = doorbellPath(tmp.dir, 'bob')
    mkdirSync(join(tmp.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
    execFileSync('mkfifo', [path])
    expect(() => ring(path)).toThrow(expect.objectContaining({ code: 'ENXIO' }))
    const clock = new FakeClock()
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], clock)
    const alice = await serverFor(P.alice, [], clock)
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'past the fifo' })
    expect((await bob.call('wait', {})).value).toMatchObject({ message: { body: 'past the fifo' } })
    expect(bob.log.lines.find((l) => l.event === 'doorbell')).toMatchObject({
      level: 'error',
      fields: { code: 'ENXIO' },
    })
  })
})
