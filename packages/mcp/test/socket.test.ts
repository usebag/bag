import { type ChildProcess, spawn } from 'node:child_process'
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  bindSocket,
  checkSocketPath,
  ensureRunDir,
  LineReader,
  runPaths,
  socketPathMax,
  takeServiceLock,
  tokenMatches,
} from '../src/socket.ts'

// The socket side of the bag service (docs/bag-service.md sections 2 to 4): the lock, the run directory, the path
// guard, the framing and the token. Homes are short directories under /tmp, so a socket path fits sun_path.

let dir: string
beforeEach(() => {
  dir = mkdtempSync('/tmp/bsk-')
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

/** A child node that takes the lock at `path` and prints got or busy, then holds it for `ms`. */
function holder(path: string, ms: number): { child: ChildProcess; said: Promise<string> } {
  const code = `
    const { DatabaseSync } = require('node:sqlite')
    const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 0 })
    try {
      db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE')
      db.exec('CREATE TABLE IF NOT EXISTS held(at INTEGER); COMMIT')
      process.stdout.write('got\\n')
    } catch { process.stdout.write('busy\\n'); process.exit(0) }
    setTimeout(() => {}, ${ms})`
  const child = spawn(process.execPath, ['--no-warnings', '-e', code], {
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  const said = new Promise<string>((resolve) => {
    child.stdout?.once('data', (b: Buffer) => resolve(b.toString().trim()))
  })
  return { child, said }
}

describe('the single-service lock', () => {
  it('is exclusive across processes, held for its life, and freed by the kernel when the holder is killed', async () => {
    const path = join(dir, 'service.lock')
    const lock = await takeServiceLock(path)
    expect(lstatSync(path).mode & 0o777).toBe(0o600)
    const other = holder(path, 0)
    expect(await other.said).toBe('busy')
    lock.release()
    const h = holder(path, 30_000)
    expect(await h.said).toBe('got')
    await expect(takeServiceLock(path, () => 'pid 7', 0)).rejects.toThrow(
      'busy: the bag service for this home already runs (pid 7)',
    )
    h.child.kill('SIGKILL')
    await new Promise((r) => h.child.once('exit', r))
    const again = await takeServiceLock(path, undefined, 0)
    again.release()
  })

  it('retries for about a second before it concludes busy, so a probe that holds it an instant never fails a start', async () => {
    const path = join(dir, 'service.lock')
    const brief = holder(path, 300)
    expect(await brief.said).toBe('got')
    const t = Date.now()
    const lock = await takeServiceLock(path, undefined, 1000)
    expect(Date.now() - t).toBeLessThan(1000)
    lock.release()
    const long = holder(path, 30_000)
    expect(await long.said).toBe('got')
    const t2 = Date.now()
    await expect(takeServiceLock(path, undefined, 1000)).rejects.toThrow('busy')
    expect(Date.now() - t2).toBeGreaterThanOrEqual(900)
    long.child.kill('SIGKILL')
  })
})

describe('the run directory', () => {
  it('is made 0700, and an existing one that is loose, a link or not a directory is refused unsafe-path', () => {
    const run = join(dir, 'run')
    ensureRunDir(run)
    expect(lstatSync(run).mode & 0o777).toBe(0o700)
    chmodSync(run, 0o755)
    expect(() => ensureRunDir(run)).toThrow('unsafe-path: ')
    expect(() => ensureRunDir(run)).toThrow('has mode 0755; it must be 0700')
    const real = join(dir, 'real')
    mkdirSync(real, { mode: 0o700 })
    symlinkSync(real, join(dir, 'link'))
    expect(() => ensureRunDir(join(dir, 'link'))).toThrow('is a link or not a directory')
    expect(() => ensureRunDir(run, 12345)).toThrow('belongs to another user')
  })
})

describe('the socket path guard', () => {
  it('allows 103 bytes on darwin and 107 on linux, counted in UTF-8, and says to shorten AC_HOME', () => {
    expect(socketPathMax('darwin')).toBe(103)
    expect(socketPathMax('linux')).toBe(107)
    const at = (n: number): string => `/${'a'.repeat(n - 1)}`
    expect(() => checkSocketPath(at(103), 'darwin')).not.toThrow()
    expect(() => checkSocketPath(at(104), 'darwin')).toThrow(
      'unsafe-path: the socket path is 104 bytes; this platform allows 103: set AC_HOME to a shorter home',
    )
    expect(() => checkSocketPath(at(107), 'linux')).not.toThrow()
    // 52 two-byte letters are 104 bytes though 53 characters.
    expect(() => checkSocketPath(`/${'é'.repeat(52)}`, 'darwin')).toThrow('105 bytes')
    expect(() => checkSocketPath('run/service.sock', 'darwin')).toThrow('not absolute')
    expect(runPaths('/h').sock).toBe('/h/run/service.sock')
  })
})

describe('the socket bind', () => {
  it('binds 0600 under umask 077, replaces a leftover socket, and refuses anything else at the path', async () => {
    const run = join(dir, 'run')
    ensureRunDir(run)
    const sock = join(run, 'service.sock')
    // A crashed service's socket: bound, then the server gone without unlinking it.
    const left = createServer()
    await new Promise<void>((r) => left.listen(sock, r))
    await new Promise<void>((r) => {
      ;(left as unknown as { _handle: { close(): void } })._handle.close()
      r()
    })
    const server = await bindSocket(sock, () => {})
    expect(lstatSync(sock).isSocket()).toBe(true)
    expect(lstatSync(sock).mode & 0o777).toBe(0o600)
    await new Promise<void>((r) => server.close(() => r()))
    writeFileSync(sock, 'not a socket')
    await expect(bindSocket(sock, () => {})).rejects.toThrow('unsafe-path: ')
  })
})

describe('the framing', () => {
  it('splits lines across chunks, skips blank ones, and ends a line over the limit', () => {
    const lines: string[] = []
    let long = 0
    const r = new LineReader(
      (l) => lines.push(l),
      () => long++,
      10,
    )
    r.push(Buffer.from('{"a"'))
    r.push(Buffer.from(':1}\n\n{"b":2}\n12345'))
    expect(lines).toEqual(['{"a":1}', '{"b":2}'])
    r.push(Buffer.from('678901'))
    expect(long).toBe(1)
    r.push(Buffer.from('\n{}\n'))
    expect(lines).toHaveLength(2)
    const exact = new LineReader(
      (l) => lines.push(l),
      () => long++,
      10,
    )
    exact.push(Buffer.from('1234567890\n'))
    expect(lines.at(-1)).toBe('1234567890')
  })
})

describe('the launch token', () => {
  it('matches only its own 64 hex characters', () => {
    const token = Buffer.alloc(32, 0xab)
    const hex = token.toString('hex')
    expect(tokenMatches(hex, token)).toBe(true)
    expect(tokenMatches(hex.toUpperCase(), token)).toBe(false)
    expect(tokenMatches(`${hex.slice(0, 63)}8`, token)).toBe(false)
    expect(tokenMatches(hex.slice(0, 62), token)).toBe(false)
    expect(tokenMatches(undefined, token)).toBe(false)
  })
})
