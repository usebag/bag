import { spawn } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  KEEP_ALIVE_LOCK_WAIT_MS,
  keepAliveChoice,
  markUsed,
  setKeepAlive,
  updateKeepAlive,
} from '../src/keep-alive-table.ts'
import { tempDir } from './support/fixtures.ts'

// The bag service's keep-alive table: one file for the home, written by the CLI (the person's word) and the service
// (the last close) through one locked read-modify-write, so neither writer loses the other's word.

const T0 = 1_800_000_000
const N = 120
const MODULE = pathToFileURL(join(import.meta.dirname, '..', 'src', 'keep-alive-table.ts')).href

let tmp: ReturnType<typeof tempDir>
beforeEach(() => {
  tmp = tempDir('keeptable')
})
afterEach(() => tmp.cleanup())

/** A child process that writes N entries as fast as it can: the person's word, or the service's last close. */
function writer(home: string, kind: 'word' | 'close'): Promise<number> {
  const script = `
    const m = await import(${JSON.stringify(MODULE)})
    const [home, kind] = process.argv.slice(-2)
    for (let i = 0; i < ${N}; i++) {
      if (kind === 'word') m.setKeepAlive(home, 'w' + i, i % 2 === 0)
      else await m.markUsed(home, 'c' + i, ${T0} + i)
    }`
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, home, kind], {
      stdio: 'inherit',
    })
    child.on('error', reject)
    child.on('exit', (code) => resolve(code ?? -1))
  })
}

describe('the keep-alive table', () => {
  it('keeps both words when two processes write it at once, and leaves no lock or temporary file', async () => {
    const home = tmp.dir
    expect(await Promise.all([writer(home, 'word'), writer(home, 'close')])).toEqual([0, 0])
    for (let i = 0; i < N; i++) {
      expect(keepAliveChoice(home, `w${i}`)).toEqual({ keep: i % 2 === 0, used_at: null })
      expect(keepAliveChoice(home, `c${i}`)).toEqual({ keep: null, used_at: T0 + i })
    }
    expect(existsSync(join(home, 'run', 'keep-alive.lock'))).toBe(false)
    expect(readFileSync(join(home, 'run', 'keep-alive.json'), 'utf8').endsWith('\n')).toBe(true)
    expect(statSync(join(home, 'run', 'keep-alive.json')).mode & 0o777).toBe(0o600)
  }, 60_000)

  it("keeps one identity's word and its close apart: the second writer re-reads the entry under the lock", async () => {
    setKeepAlive(tmp.dir, 'omp', false)
    await markUsed(tmp.dir, 'omp', T0)
    expect(keepAliveChoice(tmp.dir, 'omp')).toEqual({ keep: false, used_at: T0 })
  })

  it('waits for a live lock and answers busy past the wait; takes over a lock a crashed writer left', () => {
    setKeepAlive(tmp.dir, 'omp', true)
    const lock = join(tmp.dir, 'run', 'keep-alive.lock')
    writeFileSync(lock, '')
    const start = Date.now()
    expect(() => setKeepAlive(tmp.dir, 'omp', false)).toThrow('busy')
    expect(Date.now() - start).toBeGreaterThanOrEqual(KEEP_ALIVE_LOCK_WAIT_MS)
    expect(keepAliveChoice(tmp.dir, 'omp').keep).toBe(true)
    const old = (Date.now() - 60_000) / 1000
    utimesSync(lock, old, old)
    setKeepAlive(tmp.dir, 'omp', false)
    expect([keepAliveChoice(tmp.dir, 'omp').keep, existsSync(lock)]).toEqual([false, false])
  })

  it('lets a writer frozen past the takeover neither rename nor unlink: it starts again under the new holder', async () => {
    const lock = join(tmp.dir, 'run', 'keep-alive.lock')
    let froze = false
    const done = updateKeepAlive(
      tmp.dir,
      'omp',
      { keep: false },
      {
        beforeCommit: () => {
          if (froze) return
          froze = true
          // While this writer was frozen, its lock went stale and another writer took it over and holds it now.
          unlinkSync(lock)
          writeFileSync(lock, 'the taker')
        },
      },
    )
    await new Promise((r) => setTimeout(r, 50))
    expect([froze, readFileSync(lock, 'utf8'), keepAliveChoice(tmp.dir, 'omp').keep]).toEqual([
      true,
      'the taker',
      null,
    ])
    expect(readdirSync(join(tmp.dir, 'run')).filter((f) => f.endsWith('.tmp'))).toEqual([])
    unlinkSync(lock) // the taker releases
    await done
    expect([keepAliveChoice(tmp.dir, 'omp').keep, existsSync(lock)]).toEqual([false, false])
  })

  it('releases only its own lock: one taken over after its rename is left to the taker', async () => {
    const lock = join(tmp.dir, 'run', 'keep-alive.lock')
    await updateKeepAlive(
      tmp.dir,
      'omp',
      { keep: true },
      {
        beforeRelease: () => {
          unlinkSync(lock)
          writeFileSync(lock, 'the taker')
        },
      },
    )
    expect([keepAliveChoice(tmp.dir, 'omp').keep, readFileSync(lock, 'utf8')]).toEqual([true, 'the taker'])
  })

  it('waits on timers in the async writer, so the event loop runs while the lock is held, and rejects busy', async () => {
    mkdirSync(join(tmp.dir, 'run'), { recursive: true })
    writeFileSync(join(tmp.dir, 'run', 'keep-alive.lock'), 'held')
    let ticks = 0
    const tick = setInterval(() => ticks++, 20)
    await expect(markUsed(tmp.dir, 'omp', T0)).rejects.toThrow('busy')
    clearInterval(tick)
    expect(ticks).toBeGreaterThan(20)
  })
})
