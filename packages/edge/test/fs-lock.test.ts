import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { afterAll, describe, expect, it } from 'vitest'
import {
  acquireLock,
  type LockFs,
  type LockHolder,
  nodeLockFs,
  pidAlive,
  processStart,
  START_TOLERANCE,
} from '../src/adapters/fs-lock.ts'
import { tempDir } from './support/fixtures.ts'

// The writer lock.

const tmp = tempDir('lock')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => {
  const dir = join(tmp.dir, `d${n++}`)
  mkdirSync(dir)
  return join(dir, 'audit.lock')
}
const holder = (path: string): LockHolder => JSON.parse(readFileSync(path, 'utf8')) as LockHolder
const code = (fn: () => unknown): string => {
  try {
    fn()
  } catch (e) {
    return String((e as { code?: unknown }).code)
  }
  return 'taken'
}
/** Another process, alive, with the start time it wrote. */
const live = { alive: () => true, startOf: () => 1_800_000_000 }

describe('acquireLock', () => {
  it('writes its pid, start and token in a 0600 file, leaves no temporary file, and the release removes it', () => {
    const path = fresh()
    const release = acquireLock(path, { pid: 4242, start: 1_800_000_000 })
    expect(holder(path)).toEqual({
      pid: 4242,
      start: 1_800_000_000,
      token: expect.stringMatching(/^[0-9a-f]{16}$/),
    })
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(readdirSync(join(path, '..'))).toEqual(['audit.lock'])
    release()
    expect(existsSync(path)).toBe(false)
    release()
    const mine = acquireLock(path)
    expect(holder(path)).toMatchObject({ pid: process.pid })
    expect(Math.abs(holder(path).start - (Date.now() / 1000 - process.uptime()))).toBeLessThan(2)
    // A release removes only its own lock.
    writeFileSync(path, JSON.stringify({ pid: 7, start: 1, token: 'other' }))
    mine()
    expect(holder(path).token).toBe('other')
  })

  it('refuses with busy while a live process holds the lock, whoever asks', () => {
    const path = fresh()
    acquireLock(path, { pid: 7, start: 1_800_000_000 })
    expect(() => acquireLock(path, { pid: 8, ...live })).toThrow(
      `busy: ${path} is held by the process with pid 7, started 2027-01-15T08:00:00.000Z`,
    )
    expect(code(() => acquireLock(path, { pid: 7, ...live }))).toBe('busy')
    // A start time that cannot be read counts as the holder's; one within the tolerance is the holder's.
    expect(code(() => acquireLock(path, { alive: () => true, startOf: () => null }))).toBe('busy')
    expect(
      code(() => acquireLock(path, { alive: () => true, startOf: () => 1_800_000_000 + START_TOLERANCE })),
    ).toBe('busy')
  })

  it('takes over a stale lock: its pid gone, its pid alive with another start time, or a file that names no holder', () => {
    const path = fresh()
    acquireLock(path, { pid: 7, start: 1_800_000_000 })
    acquireLock(path, { pid: 8, start: 1_800_000_100, alive: (pid) => pid !== 7 })
    expect(holder(path)).toMatchObject({ pid: 8 })
    acquireLock(path, {
      pid: 9,
      start: 1,
      alive: () => true,
      startOf: () => 1_800_000_100 + START_TOLERANCE + 1,
    })
    expect(holder(path)).toMatchObject({ pid: 9 })
    for (const junk of [
      '',
      'not json',
      'null',
      '{"pid":0,"start":1,"token":"t"}',
      '{"pid":5,"start":"x","token":"t"}',
    ]) {
      writeFileSync(path, junk)
      acquireLock(path, { pid: 10, ...live })
      expect(holder(path), junk).toMatchObject({ pid: 10 })
    }
    expect(readdirSync(join(path, '..'))).toEqual(['audit.lock'])
  })

  it('gives way when another writer takes a stale lock between its read and its move, and puts that lock back', () => {
    const path = fresh()
    acquireLock(path, { pid: 7, start: 1 })
    let intruder: LockHolder | null = null
    const alive = (pid: number): boolean => {
      // While this writer judges the lock stale, another one replaces it with its own, fresh lock.
      if (pid === 7) {
        writeFileSync(path, JSON.stringify({ pid: 99, start: 2, token: 'fresh' }))
        intruder = holder(path)
        return false
      }
      return true
    }
    expect(() => acquireLock(path, { pid: 8, start: 3, alive, startOf: () => 2 })).toThrow(
      'is held by the process with pid 99',
    )
    expect(holder(path)).toEqual(intruder)
    expect(readdirSync(join(path, '..'))).toEqual(['audit.lock'])
  })

  it('tries again when the lock goes away under it, and refuses after three tries', () => {
    const path = fresh()
    acquireLock(path, { pid: 7, start: 1 })
    // The stale lock vanishes between the read and the move: the next try takes the lock.
    const vanish = (pid: number): boolean => {
      if (pid === 7) nodeLockFs.unlink(path)
      return false
    }
    acquireLock(path, { pid: 8, start: 2, alive: vanish })
    expect(holder(path)).toMatchObject({ pid: 8 })
    // A lock that exists at every link and is gone at every read: three tries, then busy.
    let links = 0
    const flicker: LockFs = {
      ...nodeLockFs,
      link: () => {
        links++
        throw Object.assign(new Error('exists'), { code: 'EEXIST' })
      },
    }
    expect(() => acquireLock(fresh(), { fs: flicker })).toThrow('is held by another writer')
    expect(links).toBe(3)
  })

  it('throws any other file error as it is', () => {
    const dir = fresh()
    mkdirSync(dir)
    // The lock path is a directory: the link meets it (EEXIST) and the read fails (EISDIR).
    expect(code(() => acquireLock(dir, { ...live }))).toBe('EISDIR')
    expect(code(() => acquireLock(join(tmp.dir, 'no', 'such', 'audit.lock')))).toBe('ENOENT')
    const locked: LockFs = {
      ...nodeLockFs,
      rename: () => {
        throw Object.assign(new Error('denied'), { code: 'EACCES' })
      },
    }
    const path = fresh()
    acquireLock(path, { pid: 7, start: 1 })
    expect(code(() => acquireLock(path, { pid: 8, alive: () => false, fs: locked }))).toBe('EACCES')
  })
})

describe('pidAlive and processStart', () => {
  it('see this process, a process of another user, and not a process that is gone', async () => {
    const gone = spawnSync(process.execPath, ['-e', '0']).pid as number
    expect([pidAlive(process.pid), pidAlive(1), pidAlive(gone)]).toEqual([true, true, false])
    // Bracketed by two wall-clock reads around a child spawned now: no process.uptime (it leaves out system sleep),
    // so a sleep inside the worker's life cannot move the bound. ps reads whole seconds and Linux derives it from btime,
    // hence START_TOLERANCE each side, as production uses it.
    const before = Date.now() / 1000
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
    try {
      const childStart = processStart(child.pid as number) as number
      const after = Date.now() / 1000
      expect(childStart).toBeGreaterThanOrEqual(before - START_TOLERANCE)
      expect(childStart).toBeLessThanOrEqual(after + START_TOLERANCE)
    } finally {
      child.kill()
    }
    // This process: performance.timeOrigin is the wall clock at its start (the forks pool runs each file in its own
    // process), so no uptime is involved.
    expect(
      Math.abs((processStart(process.pid) as number) - performance.timeOrigin / 1000),
    ).toBeLessThanOrEqual(START_TOLERANCE)
    expect(processStart(gone)).toBeNull()
    expect(processStart(1, () => 'Sun Oct 25 01:52:10 2026\n')).toBe(
      Math.floor(Date.parse('Sun Oct 25 01:52:10 2026') / 1000),
    )
    expect(processStart(1, () => 'no date here')).toBeNull()
  })
})

describe('a second process', () => {
  const LOCK = resolve(import.meta.dirname, '../src/adapters/fs-lock.ts')

  /** A child node process that takes the lock at `path`, prints "held", and waits until it is killed. */
  async function holderProcess(path: string): Promise<ChildProcess> {
    const script = `import { acquireLock } from ${JSON.stringify(LOCK)}; acquireLock(process.argv[1]); process.stdout.write('held\\n'); setInterval(() => {}, 1000)`
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, path], {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    await new Promise<void>((done, fail) => {
      child.stdout?.on('data', (d: Buffer) => d.toString().includes('held') && done())
      child.once('exit', (c) => fail(new Error(`the holder exited with ${c}`)))
    })
    return child
  }

  it('refuses with busy while another process holds the lock, and takes it over once that process is gone', async () => {
    const path = fresh()
    const child = await holderProcess(path)
    try {
      expect(holder(path).pid).toBe(child.pid)
      expect(code(() => acquireLock(path))).toBe('busy')
    } finally {
      child.kill('SIGKILL')
      await new Promise((r) => child.once('exit', r))
    }
    // Killed, it released nothing: its pid is gone, so the lock is stale.
    expect(holder(path).pid).toBe(child.pid)
    const release = acquireLock(path)
    expect(holder(path).pid).toBe(process.pid)
    release()
  }, 20_000)
})
