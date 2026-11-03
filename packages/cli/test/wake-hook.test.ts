import { type ChildProcess, spawn } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  codexSessionName,
  resolveSessionName,
  SessionFileError,
  SessionNameError,
  type SessionNameOptions,
  writeSessionFile,
} from '@usebag/edge/agent'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { wakeHook } from '../src/commands/wake-hook.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// wake-hook (the doorbell): one file's mtime against the one it last reported, in wake-seen.
// The poll interval is the third argument of wakeHook, which the loop tests set to 5 ms; cli() runs at the real 1 s,
// which the runs that decide at the first look never wait for.

const tmp = tempDir('wake-hook')
afterAll(() => tmp.cleanup())
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
let n = 0

/** Polls `test` every 5 ms for up to 5 s; fails naming `what`. */
async function until(what: string, test: () => boolean): Promise<void> {
  for (const end = Date.now() + 5000; !test(); await sleep(5)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
  }
}

const MESSAGE = 'bag: a message was delivered to bob; read it with the inbox tool and report it'

interface World {
  readonly io: TestIo
  readonly dir: string
  readonly bell: string
  readonly seen: string
  /** Sets the doorbell's mtime, in seconds (fractional allowed), making the file when it is not there. */
  touch(seconds: number): number
}

/** A home with the identity bob, and helpers for his doorbell and wake-seen. */
async function world(): Promise<World> {
  const io = testIo(new MemoryRelay())
  const dir = join(tmp.dir, `home-${n++}`)
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  io.stdout.length = 0 // keygen prints the new address; the tests read only what wake-hook prints
  io.stderr.length = 0
  const bell = join(dir, 'state', 'bob', 'doorbell')
  return {
    io,
    dir,
    bell,
    seen: join(dir, 'state', 'bob', 'wake-seen'),
    touch(seconds) {
      mkdirSync(join(dir, 'state', 'bob'), { recursive: true })
      if (!existsSync(bell)) writeFileSync(bell, '')
      utimesSync(bell, seconds, seconds)
      return statSync(bell).mtimeMs
    },
  }
}

const text = (file: string): string => readFileSync(file, 'utf8')
const hook = (w: World, ...more: string[]) => cli(w.io, 'wake-hook', '--as', 'bob', '--dir', w.dir, ...more)

describe('wake-hook: the first run baselines, a changed doorbell fires once, the deadline is silent', () => {
  it('takes the current mtime as the baseline and fires nothing, with the doorbell there or not, and writes wake-seen 0600', async () => {
    const a = await world()
    expect(await hook(a, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(readFileSync(a.seen, 'utf8')).toBe('0\n')
    expect(statSync(a.seen).mode & 0o777).toBe(0o600)
    expect(statSync(join(a.dir, 'state', 'bob')).mode & 0o777).toBe(0o700)
    const b = await world()
    const ms = b.touch(1_700_000_001)
    expect(await hook(b, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(readFileSync(b.seen, 'utf8')).toBe(`${ms}\n`)
  })

  it('fires on a touched doorbell with the stderr line and exit code 2, stores the mtime, and does not fire on the same mtime again', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    const ms = w.touch(1_700_000_002)
    expect(await hook(w, '--max', '0')).toEqual({ code: 2, out: [], err: [MESSAGE] })
    expect(readFileSync(w.seen, 'utf8')).toBe(`${ms}\n`)
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
  })

  it('exits with --exit-code when it fires', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    w.touch(1_700_000_002)
    expect((await hook(w, '--max', '0', '--exit-code', '7')).code).toBe(7)
    w.touch(1_700_000_003)
    expect((await hook(w, '--max', '0', '--exit-code', '0')).code).toBe(0)
    expect(readFileSync(w.seen, 'utf8')).toBe(`${statSync(w.bell).mtimeMs}\n`)
  })

  it('keeps a fractional mtime as the number the OS gives, in wake-seen and in the --print line', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    const ms = w.touch(1_700_000_002.1234567)
    await hook(w, '--max', '0')
    expect(readFileSync(w.seen, 'utf8')).toBe(`${ms}\n`)
    expect(String(ms)).toMatch(/^1700000002\d{3}/)
    w.touch(1_700_000_003.7654321)
    const printed = wakeHook(['--as', 'bob', '--dir', w.dir, '--print'], w.io, 5)
    await until('the print line', () => w.io.stdout.length === 1)
    w.io.stop.abort()
    expect(await printed).toBe(0)
    expect(w.io.stdout).toEqual([`doorbell ${statSync(w.bell).mtimeMs}`])
  })

  it('reads a doorbell that is gone as 0, and takes a wake-seen that holds anything but a number for no baseline', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    rmSync(w.bell)
    expect(await hook(w, '--max', '0')).toEqual({ code: 2, out: [], err: [MESSAGE] })
    expect(readFileSync(w.seen, 'utf8')).toBe('0\n')
    const junk = await world()
    junk.touch(1_700_000_001)
    writeFileSync(junk.seen, 'not a number')
    expect(await hook(junk, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(readFileSync(junk.seen, 'utf8')).toBe(`${statSync(junk.bell).mtimeMs}\n`)
  })

  it('wakes at the deadline once per mail-free stretch: the first with the line and the code, the next silent until a ring, and a ring then a deadline wakes again', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const idle = join(w.dir, 'state', 'bob', 'wake-idle')
    const deadline = (...more: string[]) =>
      wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '1', ...more], w.io, 10)
    const t0 = Date.now()
    expect(await deadline()).toBe(2)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900)
    expect(w.io.stderr).toEqual(['bag: no message for bob in 1 s'])
    expect(statSync(idle).mode & 0o777).toBe(0o600)
    w.io.stderr.length = 0
    expect(await deadline('--exit-code', '5')).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    w.touch(1_700_000_002)
    expect(await deadline()).toBe(2)
    expect(w.io.stderr).toEqual([MESSAGE])
    expect(existsSync(idle)).toBe(false)
    w.io.stderr.length = 0
    expect(await deadline('--exit-code', '5')).toBe(5)
    expect(w.io.stderr).toEqual(['bag: no message for bob in 1 s'])
  }, 15_000)

  it('replaces a link at wake-idle instead of following it, and a marker that holds anything but 1 counts as none', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const idle = join(w.dir, 'state', 'bob', 'wake-idle')
    const victim = join(w.dir, 'victim')
    writeFileSync(victim, 'keep')
    mkdirSync(join(w.dir, 'state', 'bob'), { recursive: true })
    symlinkSync(victim, idle)
    const deadline = () => wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '1'], w.io, 10)
    expect(await deadline()).toBe(2)
    expect(text(victim)).toBe('keep')
    expect(lstatSync(idle).isSymbolicLink()).toBe(false)
    expect(text(idle)).toBe('1\n')
    writeFileSync(idle, 'junk')
    expect(await deadline()).toBe(2)
    expect(text(idle)).toBe('1\n')
  }, 15_000)

  it('--max 0 only looks once: it never wakes on silence and leaves no wake-idle marker; --print never does either', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    const printed = wakeHook(['--as', 'bob', '--dir', w.dir, '--print', '--max', '1'], w.io, 10)
    await sleep(1200)
    w.io.stop.abort()
    expect(await printed).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(readdirSync(join(w.dir, 'state', 'bob')).sort()).toEqual(['doorbell', 'wake-seen'])
  })

  it('sees a touch made while it waits', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const waiting = wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '30'], w.io, 5)
    await sleep(40)
    w.touch(1_700_000_002)
    expect(await waiting).toBe(2)
    expect(w.io.stderr).toEqual([MESSAGE])
  })

  it('stops at once with exit 0 on the stop signal', async () => {
    const w = await world()
    w.io.stop.abort()
    expect(await wakeHook(['--as', 'bob', '--dir', w.dir], w.io, 5)).toBe(0)
  })

  it('--print writes one doorbell line per change on stdout, never exits by itself, ignores --max, and stops on the signal', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const printed = wakeHook(['--as', 'bob', '--dir', w.dir, '--print', '--max', '0'], w.io, 5)
    await sleep(30)
    const first = w.touch(1_700_000_002)
    await until('the first line', () => w.io.stdout.length === 1)
    const second = w.touch(1_700_000_003)
    await until('the second line', () => w.io.stdout.length === 2)
    await sleep(30)
    w.io.stop.abort()
    expect(await printed).toBe(0)
    expect(w.io.stdout).toEqual([`doorbell ${first}`, `doorbell ${second}`])
    expect(w.io.stderr).toEqual([])
    expect(existsSync(w.seen)).toBe(false) // the baseline was kept in memory
  })

  it('--print leaves wake-seen and wake-idle as they are, so a hook after it still reports the ring it printed', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    const idle = join(w.dir, 'state', 'bob', 'wake-idle')
    writeFileSync(idle, '1\n', { mode: 0o600 })
    const [seenBefore, seenAt] = [text(w.seen), statSync(w.seen).mtimeMs]
    const printed = wakeHook(['--as', 'bob', '--dir', w.dir, '--print'], w.io, 5)
    const first = w.touch(1_700_000_002)
    await until('the first line', () => w.io.stdout.length === 1)
    const second = w.touch(1_700_000_003)
    await until('the second line', () => w.io.stdout.length === 2)
    w.io.stop.abort()
    expect(await printed).toBe(0)
    expect(w.io.stdout).toEqual([`doorbell ${first}`, `doorbell ${second}`])
    expect([text(w.seen), statSync(w.seen).mtimeMs, text(idle)]).toEqual([seenBefore, seenAt, '1\n'])
    const fresh = testIo(new MemoryRelay()) // w.io's stop signal is spent
    expect(await cli(fresh, 'wake-hook', '--as', 'bob', '--dir', w.dir, '--max', '0')).toEqual({
      code: 2,
      out: [],
      err: [MESSAGE],
    })
  })

  it('opens no edge and no store: the state directory holds the doorbell and wake-seen only', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    expect(readdirSync(join(w.dir, 'state', 'bob')).sort()).toEqual(['doorbell', 'wake-seen'])
  })

  it('refuses a missing --as, a bad --max or --exit-code, an unknown option, a missing home, and an identity the home lacks', async () => {
    const w = await world()
    const err = async (...a: string[]) => (await cli(w.io, 'wake-hook', ...a)).err[0]
    expect(await err('--dir', w.dir)).toBe('bag: usage: --as is required')
    expect(await err('--as', 'bob', '--dir', w.dir, '--max=-1')).toBe(
      'bag: usage: --max is a whole number from 0 to 2000000, not "-1"',
    )
    expect(await err('--as', 'bob', '--dir', w.dir, '--max', '2000001')).toContain('--max is a whole number')
    expect(await err('--as', 'bob', '--dir', w.dir, '--exit-code', '256')).toBe(
      'bag: usage: --exit-code is a whole number from 0 to 255, not "256"',
    )
    expect(await err('--as', 'bob', '--dir', w.dir, '--exit-code', 'x')).toContain(
      '--exit-code is a whole number',
    )
    expect(await err('--as', 'bob', '--dir', w.dir, '--bogus')).toContain('usage')
    expect(await err('--as', 'bob')).toBe('bag: usage: no home directory: pass --dir, or set AC_HOME or HOME')
    expect(await err('--as', 'nobody', '--dir', w.dir)).toMatch(/^bag: ENOENT: /)
    expect(await err('--as', '../keys', '--dir', w.dir)).toContain('a key name is 1 to 64')
    expect(existsSync(join(w.dir, 'state', 'nobody'))).toBe(false)
  })
})

describe('wake-hook --no-idle-wake: the deadline is silent, a ring still wakes (the Codex Stop hook)', () => {
  const idleOf = (w: World): string => join(w.dir, 'state', 'bob', 'wake-idle')
  const deadline = (w: World, ...more: string[]) =>
    wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '1', '--no-idle-wake', ...more], w.io, 10)

  it('at the deadline exits 0, silent, makes no wake-idle, and leaves one that is there as it is', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const t0 = Date.now()
    expect(await deadline(w)).toBe(0)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(existsSync(idleOf(w))).toBe(false)
    writeFileSync(idleOf(w), 'kept')
    expect(await deadline(w, '--exit-code', '5')).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(text(idleOf(w))).toBe('kept')
  }, 15_000)

  it('a ring during the wait still exits 2 with the line, and the lock is freed', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const waiting = wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '30', '--no-idle-wake'], w.io, 5)
    await sleep(40)
    w.touch(1_700_000_002)
    expect(await waiting).toBe(2)
    expect(w.io.stderr).toEqual([MESSAGE])
    expect(existsSync(join(w.dir, 'state', 'bob', 'wake-hook.lock'))).toBe(false)
  })

  it('a Stop after a continuation with no new ring waits and ends silent: the doorbell is the loop guard', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    w.touch(1_700_000_002)
    expect(await deadline(w)).toBe(2) // the ring continues the turn once
    w.io.stderr.length = 0
    expect(await deadline(w)).toBe(0) // the Stop that follows: no ring since, so the turn ends
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(existsSync(idleOf(w))).toBe(false)
  }, 15_000)

  it('beside --print changes nothing: it still prints a line per change and runs till the signal', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const printed = wakeHook(
      ['--as', 'bob', '--dir', w.dir, '--print', '--max', '1', '--no-idle-wake'],
      w.io,
      5,
    )
    await sleep(30)
    const ms = w.touch(1_700_000_002)
    await until('the print line', () => w.io.stdout.length === 1)
    await sleep(1100)
    w.io.stop.abort()
    expect(await printed).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[`doorbell ${ms}`], []])
  })
})

describe('wake-hook: one at a time per identity (wake-hook.lock), and wake-seen written whole', () => {
  const lockOf = (w: World): string => join(w.dir, 'state', 'bob', 'wake-hook.lock')
  const dead = 99_999_999

  it('a second hook finds the first one live and ends 0, silent, without touching wake-seen; the first still ends 0 on the signal and frees the lock', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const first = wakeHook(['--as', 'bob', '--dir', w.dir], w.io, 60_000)
    await until('the lock and the baseline', () => existsSync(lockOf(w)) && existsSync(w.seen))
    expect(text(lockOf(w))).toBe(`${process.pid}\n`)
    expect(statSync(lockOf(w)).mode & 0o777).toBe(0o600)
    const baseline = text(w.seen)
    w.touch(1_700_000_002)
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(text(w.seen)).toBe(baseline)
    expect(existsSync(lockOf(w))).toBe(true)
    w.io.stop.abort()
    expect(await first).toBe(0)
    expect(existsSync(lockOf(w))).toBe(false)
  })

  it('frees the lock when it fires and at the deadline, so the next hook takes it; --print takes none', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    expect((await hook(w, '--max', '0')).code).toBe(0)
    expect(existsSync(lockOf(w))).toBe(false)
    w.touch(1_700_000_002)
    expect((await hook(w, '--max', '0')).code).toBe(2)
    expect(existsSync(lockOf(w))).toBe(false)
    w.touch(1_700_000_003)
    expect((await hook(w, '--max', '0')).code).toBe(2)
    expect(readdirSync(join(w.dir, 'state', 'bob')).sort()).toEqual(['doorbell', 'wake-seen'])
    const printing = wakeHook(['--as', 'bob', '--dir', w.dir, '--print'], w.io, 60_000)
    await sleep(20)
    expect(existsSync(lockOf(w))).toBe(false)
    w.io.stop.abort()
    expect(await printing).toBe(0)
  })

  it('takes over a lock whose pid is dead, one that holds junk or 0, and one older than max + 60 s, even with a live pid', async () => {
    for (const held of [`${dead}\n`, 'junk', '0\n', `${process.pid}\n`]) {
      const w = await world()
      w.touch(1_700_000_001)
      writeFileSync(lockOf(w), held)
      if (held === `${process.pid}\n`) utimesSync(lockOf(w), 1_700_000_000, 1_700_000_000)
      expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
      expect(text(w.seen)).toBe(`${statSync(w.bell).mtimeMs}\n`)
      expect(existsSync(lockOf(w))).toBe(false)
    }
  })

  it('takes over a lock whose live pid is no wake-hook (pid 1, which refuses a signal EPERM) as stale', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    writeFileSync(lockOf(w), '1\n')
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(text(w.seen)).toBe(`${statSync(w.bell).mtimeMs}\n`)
    expect(existsSync(lockOf(w))).toBe(false)
  })

  // Child processes, each killed after its test. A fake holder runs `node -e <script> <word> <lock>`: on SIGTERM it
  // removes the lock while it holds its pid, as wake-hook's release does, and exits 0; otherwise it idles.
  const kids: ChildProcess[] = []
  afterEach(() => {
    for (const k of kids.splice(0)) if (k.exitCode === null && k.signalCode === null) k.kill('SIGKILL')
  })
  const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')
  const HOLD =
    "const fs = process.getBuiltinModule('node:fs'); const f = process.argv[2]; process.on('SIGTERM', () => { " +
    "try { if (fs.readFileSync(f, 'utf8').trim() === String(process.pid)) fs.rmSync(f) } catch {} process.exit(0) }); " +
    "setInterval(() => {}, 1000); process.stdout.write('ready\\n')"
  type Kid = {
    readonly proc: ChildProcess
    readonly ended: Promise<{ code: number | null; at: number }>
    out: string
  }
  function kid(args: readonly string[]): Kid {
    const env: NodeJS.ProcessEnv = { ...process.env }
    delete env.AC_HOME
    const proc = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
    kids.push(proc)
    const k: Kid = {
      proc,
      out: '',
      ended: new Promise((done) => proc.on('exit', (code) => done({ code, at: Date.now() }))),
    }
    proc.stdout?.on('data', (d) => (k.out += d))
    proc.stderr?.on('data', (d) => (k.out += d))
    return k
  }
  /** A fake holder whose argv has `word`, holding the lock of w once it is ready. */
  async function holder(w: World, word: string): Promise<Kid> {
    const k = kid(['-e', HOLD, word, lockOf(w)])
    await until('the holder ready', () => k.out === 'ready\n')
    writeFileSync(lockOf(w), `${k.proc.pid}\n`, { mode: 0o600 })
    return k
  }
  const running = (k: Kid): boolean => k.proc.exitCode === null && k.proc.signalCode === null

  it('takes the lock over from a live wake-hook: SIGTERM ends it within 1 s, the lock holds this pid, a ring is 2', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    const old = await holder(w, 'wake-hook')
    const start = Date.now()
    const waiting = wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '30'], w.io, 5)
    const { code, at } = await old.ended
    expect([code, at - start < 1000]).toEqual([0, true])
    await until('the lock is this pid', () => existsSync(lockOf(w)) && text(lockOf(w)) === `${process.pid}\n`)
    expect(Date.now() - start).toBeLessThan(1000)
    w.touch(1_700_000_002)
    expect(await waiting).toBe(2)
    expect(w.io.stderr).toEqual([MESSAGE])
    expect(existsSync(lockOf(w))).toBe(false)
  })

  it('does not signal a live holder that is no wake-hook (a word like wake-hook.test.ts is not): the lock is taken, a ring is 2', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    await hook(w, '--max', '0')
    const other = await holder(w, 'wake-hook.test.ts')
    const waiting = wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '30'], w.io, 5)
    await until('the lock is this pid', () => existsSync(lockOf(w)) && text(lockOf(w)) === `${process.pid}\n`)
    w.touch(1_700_000_002)
    expect(await waiting).toBe(2)
    await sleep(50)
    expect(running(other)).toBe(true)
  })

  it('of two hooks started together, with a holder or none, exactly one watches: the other ends 0, silent, and one ring is one wake', async () => {
    for (const held of [true, false]) {
      const w = await world()
      w.touch(1_700_000_001)
      await hook(w, '--max', '0')
      const old = held ? await holder(w, 'wake-hook') : null
      const two = [0, 1].map(() => kid([MAIN, 'wake-hook', '--as', 'bob', '--dir', w.dir, '--max', '30']))
      const lost = await Promise.race(two.map((k, i) => k.ended.then(() => i)))
      const [loser, winner] = [two[lost] as Kid, two[1 - lost] as Kid]
      expect([(await loser.ended).code, loser.out]).toEqual([0, ''])
      if (old !== null) expect((await old.ended).code).toBe(0)
      await until(
        'the winner holds the lock',
        () => existsSync(lockOf(w)) && text(lockOf(w)) === `${winner.proc.pid}\n`,
      )
      await sleep(300)
      expect(running(winner)).toBe(true)
      w.touch(1_700_000_002)
      expect((await winner.ended).code).toBe(2)
      expect(winner.out).toBe(`${MESSAGE}\n`)
      expect(existsSync(lockOf(w))).toBe(false)
    }
  }, 30_000)

  it('a holder whose lock now holds another pid (a newer hook took over) ends 0, silent, at its next look', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const first = wakeHook(['--as', 'bob', '--dir', w.dir, '--max', '30'], w.io, 5)
    await until('the lock', () => existsSync(lockOf(w)))
    writeFileSync(lockOf(w), '1\n')
    expect(await first).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(text(lockOf(w))).toBe('1\n')
  })

  it('removes the lock only while it holds its own pid: not one another hook took, and a lock already gone is no error', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const first = wakeHook(['--as', 'bob', '--dir', w.dir], w.io, 60_000)
    await until('the lock', () => existsSync(lockOf(w)))
    writeFileSync(lockOf(w), '1\n')
    w.io.stop.abort()
    expect(await first).toBe(0)
    expect(text(lockOf(w))).toBe('1\n')
    rmSync(lockOf(w))
    const second = testIo(new MemoryRelay())
    const gone = wakeHook(['--as', 'bob', '--dir', w.dir], second, 60_000)
    await until('the lock', () => existsSync(lockOf(w)))
    rmSync(lockOf(w))
    second.stop.abort()
    expect(await gone).toBe(0)
  })

  it('passes on an error that is not a lock held: a state directory it cannot write is EACCES', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    chmodSync(join(w.dir, 'state', 'bob'), 0o500)
    try {
      expect((await hook(w, '--max', '0')).err[0]).toMatch(/^bag: EACCES: /)
    } finally {
      chmodSync(join(w.dir, 'state', 'bob'), 0o700)
    }
  })

  it('writes wake-seen to a temp file and renames it over, 0600, and replaces a link at wake-seen instead of following it', async () => {
    const w = await world()
    w.touch(1_700_000_001)
    const victim = join(w.dir, 'victim')
    writeFileSync(victim, 'junk')
    symlinkSync(victim, w.seen)
    writeFileSync(`${w.seen}.${process.pid}`, 'left over')
    expect((await hook(w, '--max', '0')).code).toBe(0)
    expect(lstatSync(w.seen).isSymbolicLink()).toBe(false)
    expect(statSync(w.seen).mode & 0o777).toBe(0o600)
    expect(text(w.seen)).toBe(`${statSync(w.bell).mtimeMs}\n`)
    expect(text(victim)).toBe('junk')
    expect(readdirSync(join(w.dir, 'state', 'bob')).sort()).toEqual(['doorbell', 'wake-seen'])
  })
})

describe('wake-hook --session auto: the name is read from the session file the MCP server wrote, found by the process tree', () => {
  const [s1, s2] = ['s-1111111111111111', 's-2222222222222222']
  const said = (name: string): string =>
    `bag: a message was delivered to ${name}; read it with the inbox tool and report it`
  /** A fake process tree: this hook (pid 10) under a `claude` (pid `top`) that started at `start`. */
  const tree = (top: number, start = 1000): SessionNameOptions => ({
    pid: 10,
    info: (pid) =>
      pid === 10
        ? { ppid: top, command: 'node main.ts wake-hook --session auto' }
        : pid === top
          ? { ppid: 1, command: '/usr/local/bin/claude' }
          : null,
    startOf: () => start,
  })
  const args = (w: World, max: string) => ['--as', 'bob', '--session', 'auto', '--dir', w.dir, '--max', max]
  const auto = (w: World, max: string, session: SessionNameOptions, pollMs = 5) =>
    wakeHook(args(w, max), w.io, pollMs, session)
  const lockOf = (w: World, name: string): string => join(w.dir, 'state', name, 'wake-hook.lock')
  const bellOf = (w: World, name: string): string => join(w.dir, 'state', name, 'doorbell')
  /** Sets `name`'s doorbell mtime, in seconds, making the file when it is not there. */
  function ring(w: World, name: string, seconds: number): void {
    mkdirSync(join(w.dir, 'state', name), { recursive: true })
    if (!existsSync(bellOf(w, name))) writeFileSync(bellOf(w, name), '')
    utimesSync(bellOf(w, name), seconds, seconds)
  }
  /** Makes the identity `name`, and clears what keygen printed. */
  async function make(w: World, name: string): Promise<void> {
    expect((await cli(w.io, 'keygen', name, '--dir', w.dir)).code).toBe(0)
    w.io.stdout.length = 0
    w.io.stderr.length = 0
  }
  /** bob's address, from the home. */
  async function addressOf(w: World): Promise<string> {
    const out = (await cli(w.io, 'address', 'bob', '--dir', w.dir)).out[0] as string
    w.io.stdout.length = 0
    return out
  }
  /** What the MCP server writes on its first start: the session file of `session`'s anchor, for `name`. */
  async function serve(w: World, name: string, session: SessionNameOptions, who?: string): Promise<void> {
    const address = await addressOf(w)
    const { anchor } = resolveSessionName(address, session)
    writeSessionFile(w.dir, { v: 1, name, principal: who ?? address, ...anchor })
  }
  const filePath = (w: World, pid: number, start = 1000): string =>
    join(w.dir, 'state', 'sessions', `${pid}-${start}.json`)

  it('reads the name from the session file; a ring on that name wakes with it, a ring on the principal does not', async () => {
    const w = await world()
    const t = tree(100)
    await make(w, s1)
    await serve(w, s1, t)
    ring(w, s1, 1_700_000_001)
    w.touch(1_700_000_001)
    expect(await auto(w, '0', t)).toBe(0)
    expect(text(join(w.dir, 'state', s1, 'wake-seen'))).toBe(`${statSync(bellOf(w, s1)).mtimeMs}\n`)
    w.touch(1_700_000_002)
    expect(await auto(w, '0', t)).toBe(0)
    expect(w.io.stderr).toEqual([])
    ring(w, s1, 1_700_000_003)
    expect(await auto(w, '0', t)).toBe(2)
    expect(w.io.stderr).toEqual([said(s1)])
    expect(existsSync(w.seen)).toBe(false)
    expect(readdirSync(join(w.dir, 'state', s1)).sort()).toEqual(['doorbell', 'wake-seen'])
  })

  it('JOINT: the name the server computes with the real resolveSessionName is the one the hook reaches, with no resolver injected on either side', async () => {
    // A hashing mismatch between the two sides (an address hashed, or a name) fails here, red. A contract test of
    // the session file: the test is the server; the real server-to-hook proof is the e2e on mcp/many-sessions.
    const w = await world()
    const t = tree(100)
    const address = await addressOf(w)
    const { name, anchor } = resolveSessionName(address, t)
    await make(w, name)
    writeSessionFile(w.dir, { v: 1, name, principal: address, ...anchor })
    ring(w, name, 1_700_000_001)
    expect(await auto(w, '0', t)).toBe(0)
    expect(existsSync(join(w.dir, 'state', name, 'wake-seen'))).toBe(true)
    ring(w, name, 1_700_000_002)
    expect(await auto(w, '0', t)).toBe(2)
    expect(w.io.stderr).toEqual([said(name)])
    expect(existsSync(join(w.dir, 'state', 'bob', 'wake-seen'))).toBe(false)
  })

  it('wakes two sessions of one principal each on its own ring, each under its own lock', async () => {
    const w = await world()
    const [t1, t2] = [tree(100), tree(200)]
    for (const [s, t] of [
      [s1, t1],
      [s2, t2],
    ] as const) {
      await make(w, s)
      await serve(w, s, t)
      ring(w, s, 1_700_000_001)
      expect(await auto(w, '0', t)).toBe(0)
    }
    const first = auto(w, '30', t1)
    const second = auto(w, '30', t2)
    await until('both locks', () => existsSync(lockOf(w, s1)) && existsSync(lockOf(w, s2)))
    ring(w, s2, 1_700_000_002)
    expect(await second).toBe(2)
    expect(w.io.stderr).toEqual([said(s2)])
    expect(existsSync(lockOf(w, s2))).toBe(false)
    expect(existsSync(lockOf(w, s1))).toBe(true)
    ring(w, s1, 1_700_000_003)
    expect(await first).toBe(2)
    expect(w.io.stderr).toEqual([said(s2), said(s1)])
    expect(existsSync(lockOf(w, s1))).toBe(false)
  })

  it('ends a second hook of the same session 0, silent, while the first holds the lock', async () => {
    const w = await world()
    const t = tree(100)
    await make(w, s1)
    await serve(w, s1, t)
    ring(w, s1, 1_700_000_001)
    const first = auto(w, '3500', t, 60_000)
    await until('the lock', () => existsSync(lockOf(w, s1)))
    ring(w, s1, 1_700_000_002)
    expect(await auto(w, '0', t)).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    w.io.stop.abort()
    expect(await first).toBe(0)
  })

  it('waits for the session file, then for the identity it names, then runs', async () => {
    const w = await world()
    const t = tree(100)
    const waiting = auto(w, '30', t)
    await sleep(40)
    await serve(w, s1, t)
    await sleep(40)
    expect(existsSync(join(w.dir, 'state', s1))).toBe(false)
    await make(w, s1)
    await until('the baseline', () => existsSync(join(w.dir, 'state', s1, 'wake-seen')))
    ring(w, s1, 1_700_000_002)
    expect(await waiting).toBe(2)
    expect(w.io.stderr).toEqual([said(s1)])
  })

  it('no session file by --max is refused (no-session-file); the stop signal ends the wait 0, silent; an identity that never appears ends 0', async () => {
    const w = await world()
    const t = tree(100)
    const t0 = Date.now()
    await expect(auto(w, '1', t, 10)).rejects.toThrow(/no-session-file: no file for pid 100/)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900)
    const waiting = auto(w, '30', t)
    await sleep(40)
    w.io.stop.abort()
    expect(await waiting).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    const x = await world()
    await serve(x, s1, t)
    expect(await auto(x, '1', t, 10)).toBe(0)
    expect([x.io.stdout, x.io.stderr]).toEqual([[], []])
    expect(existsSync(join(x.dir, 'state', s1))).toBe(false)
    // The stop signal during the identity wait (the file is there, its identity never appears) ends 0, silent too.
    const y = await world()
    await serve(y, s1, t)
    const idle = auto(y, '30', t)
    await sleep(40)
    y.io.stop.abort()
    expect(await idle).toBe(0)
    expect([y.io.stdout, y.io.stderr]).toEqual([[], []])
  }, 15_000)

  it('a session file of another principal is refused (session-principal), touching no state', async () => {
    const w = await world()
    const t = tree(100)
    await make(w, s1)
    await serve(w, s1, t, await addressOf(await world()))
    await expect(auto(w, '0', t)).rejects.toThrow(/session-principal: the session file is not bob's address/)
    expect(existsSync(join(w.dir, 'state', s1))).toBe(false)
  })

  it('a malformed session file is refused (bad-session-file)', async () => {
    const w = await world()
    const t = tree(100)
    const { anchor } = resolveSessionName(await addressOf(w), t)
    mkdirSync(join(w.dir, 'state', 'sessions'), { recursive: true })
    const raw = { v: 1, name: '../keys', principal: await addressOf(w), ...anchor }
    writeFileSync(filePath(w, anchor.pid, anchor.start), JSON.stringify(raw))
    await expect(auto(w, '0', t)).rejects.toThrow(SessionFileError)
    await expect(auto(w, '0', t)).rejects.toMatchObject({ code: 'bad-session-file' })
  })

  it('no claude anchor rejects with SessionNameError, which run() reports as no-session, exit 1', async () => {
    const w = await world()
    const none: SessionNameOptions = { pid: 10, info: () => null, startOf: () => 1 }
    await expect(auto(w, '0', none)).rejects.toThrow(SessionNameError)
    expect(existsSync(join(w.dir, 'state', 'bob'))).toBe(false)
  })

  it('refuses a --session other than auto, naming it; without --session nothing changes', async () => {
    const w = await world()
    const r = await hook(w, '--session', 'bob', '--max', '0')
    expect(r.code).toBe(1)
    expect(r.err[0]).toBe('bag: usage: --session takes auto or auto:codex, not bob')
    expect(existsSync(join(w.dir, 'state', 'bob'))).toBe(false)
    expect(await hook(w, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
  })
})

describe('wake-hook --session auto:codex: the name is made from the session_id of the Stop JSON on stdin', () => {
  const ID = '019a3c1e-7b2d-7c4e-8f10-5d6e7a8b9c0d'
  const stop = (id: unknown): string =>
    JSON.stringify({ hook_event_name: 'Stop', session_id: id, stop_hook_active: false })
  const said = (name: string): string =>
    `bag: a message was delivered to ${name}; read it with the inbox tool and report it`
  const run = (w: World, max = '0', pollMs = 5) =>
    wakeHook(['--as', 'bob', '--session', 'auto:codex', '--dir', w.dir, '--max', max], w.io, pollMs)
  /** bob's address, from the home, and the name the server computes from it with the real function. */
  async function nameOf(w: World, id: string): Promise<string> {
    const address = (await cli(w.io, 'address', 'bob', '--dir', w.dir)).out[0] as string
    w.io.stdout.length = 0
    return codexSessionName(address, id)
  }
  /** Makes the identity `name` (what the server's first tool call does) and rings its doorbell at `seconds`. */
  async function bound(w: World, name: string, seconds?: number): Promise<string> {
    expect((await cli(w.io, 'keygen', name, '--dir', w.dir)).code).toBe(0)
    w.io.stdout.length = 0
    w.io.stderr.length = 0
    const bell = join(w.dir, 'state', name, 'doorbell')
    if (seconds !== undefined) {
      mkdirSync(join(w.dir, 'state', name), { recursive: true, mode: 0o700 }) // keygen makes no state directory
      writeFileSync(bell, '')
      utimesSync(bell, seconds, seconds)
    }
    return bell
  }

  it('JOINT: the name codexSessionName gives (the real function, as the server calls it, on the principal address) is the identity the hook watches; a ring wakes with it, and the uuid case does not matter', async () => {
    const w = await world()
    const name = await nameOf(w, ID)
    const bell = await bound(w, name, 1_700_000_001)
    w.io.lines.push(stop(ID))
    expect(await run(w)).toBe(0) // the baseline
    expect(existsSync(join(w.dir, 'state', name, 'wake-seen'))).toBe(true)
    expect(existsSync(join(w.dir, 'state', 'bob', 'wake-seen'))).toBe(false)
    utimesSync(bell, 1_700_000_002, 1_700_000_002)
    w.io.lines.push(stop(ID.toUpperCase()))
    expect(await run(w)).toBe(2)
    expect(w.io.stderr).toEqual([said(name)])
    w.io.lines.push(stop(ID))
    expect(await run(w)).toBe(0) // the doorbell is the loop guard
    expect(w.io.stderr).toEqual([said(name)])
  })

  it('reads a Stop JSON on several lines, and the name differs by id', async () => {
    const w = await world()
    const [a, b] = [await nameOf(w, ID), await nameOf(w, ID.replace(/0d$/, '0e'))]
    expect(a).not.toBe(b)
    const bell = await bound(w, b, 1_700_000_001)
    w.io.lines.push(...JSON.stringify({ session_id: ID.replace(/0d$/, '0e') }, null, 1).split('\n'))
    expect(await run(w)).toBe(0)
    utimesSync(bell, 1_700_000_002, 1_700_000_002)
    w.io.lines.push(stop(ID.replace(/0d$/, '0e')))
    expect(await run(w)).toBe(2)
    expect(w.io.stderr).toEqual([said(b)])
  })

  it('before any tool call (no identity of that name) it exits 0 at once, silent, with no wait and no state', async () => {
    const w = await world()
    w.io.lines.push(stop(ID))
    const start = Date.now()
    expect(await run(w, '30', 1000)).toBe(0)
    expect(Date.now() - start).toBeLessThan(1000)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
    expect(existsSync(join(w.dir, 'state', await nameOf(w, ID)))).toBe(false)
  })

  it('refuses a session_id that is not a uuid (no-session) and an input that is not a JSON object with a string session_id (bad-hook-input), exit 1', async () => {
    const w = await world()
    const ran = async (...lines: string[]) => {
      w.io.lines.push(...lines)
      return cli(w.io, 'wake-hook', '--as', 'bob', '--session', 'auto:codex', '--dir', w.dir, '--max', '0')
    }
    const nope = await ran(stop('nope'))
    expect([nope.code, nope.err[0]]).toEqual([1, expect.stringMatching(/^bag: no-session: /)])
    for (const bad of [[], ['{'], ['null'], ['[]'], ['5'], [stop(5)], ['{}']]) {
      const r = await ran(...bad)
      expect([bad, r.code, r.err[0]]).toEqual([
        bad,
        1,
        'bag: bad-hook-input: the hook input on stdin is not a JSON object with a string session_id',
      ])
    }
    // A session_id quoted inside the reply of a Stop JSON that does not parse is escaped, and is not taken.
    const quoted = await ran(`{"last_assistant_message":"say \\"session_id\\": \\"${ID}\\"`)
    expect([quoted.code, quoted.err[0]]).toEqual([1, expect.stringMatching(/^bag: bad-hook-input: /)])
    expect(existsSync(join(w.dir, 'state', 'bob'))).toBe(false)
  })

  it('takes the id from a Stop JSON whose reply is long or split: past 64 KiB, cut there, or split by readline at U+2028', async () => {
    const w = await world()
    const name = await nameOf(w, ID)
    const bell = await bound(w, name, 1_700_000_001)
    w.io.lines.push(stop(ID))
    expect(await run(w)).toBe(0) // the baseline
    const reply = (text: string) => `${stop(ID).slice(0, -1)},"last_assistant_message":"${text}"}`
    for (const [lines, left] of [
      [[reply('x'.repeat(70_000)), 'b', 'c'], ['c']], // whole, past 64 KiB: the read stops at the next line
      [[reply('x'.repeat(70_000)).slice(0, 66_000), 'c'], []], // cut: no parse, the id is read from the text
      [reply('one\u2028two').split('\u2028'), []], // readline's split at U+2028, joined by a space
    ]) {
      utimesSync(bell, 1_700_000_002 + w.io.stderr.length, 1_700_000_002 + w.io.stderr.length)
      w.io.lines.push(...(lines as string[]))
      expect([lines, await run(w)]).toEqual([lines, 2])
      expect(w.io.lines).toEqual(left)
      w.io.lines.length = 0
    }
    expect(w.io.stderr).toEqual([said(name), said(name), said(name)])
  })

  it('reads a stdin that never ends for 2 s and parses what came', async () => {
    const w = await world()
    const name = await nameOf(w, ID)
    const bell = await bound(w, name, 1_700_000_001)
    w.io.lines.push(stop(ID))
    expect(await run(w)).toBe(0)
    utimesSync(bell, 1_700_000_002, 1_700_000_002)
    const feed = [stop(ID)]
    let end: (v: null) => void = () => undefined
    const hang = new Promise<null>((r) => {
      end = r
    })
    w.io.readLine = async () => feed.shift() ?? hang
    w.io.release = () => end(null)
    const start = Date.now()
    expect(await run(w)).toBe(2)
    expect(Date.now() - start).toBeGreaterThanOrEqual(1900)
    expect(w.io.stderr).toEqual([said(name)])
  }, 10_000)
})

describe('wake-hook --identities: every identity of the file, each by its own doorbell', () => {
  interface Many {
    readonly io: TestIo
    readonly file: string
    /** The state directory of each label. */
    readonly state: Record<string, string>
    /** Sets a label's doorbell mtime, in seconds. */
    touch(label: string, seconds: number): number
  }

  /** Three identities in three homes, labelled personal, lab and club, and their file, 0600. */
  async function many(): Promise<Many> {
    const io = testIo(new MemoryRelay())
    const base = join(tmp.dir, `many-${n++}`)
    const ids = [
      ['personal', 'bob'],
      ['lab', 'carol'],
      ['club', 'dave'],
    ] as const
    const state: Record<string, string> = {}
    const identities = []
    for (const [label, key] of ids) {
      const home = join(base, label)
      expect((await cli(io, 'keygen', key, '--dir', home)).code).toBe(0)
      state[label] = join(home, 'state', key)
      identities.push({ label, key, home, relays: ['http://127.0.0.1:9'] })
    }
    io.stdout.length = 0
    io.stderr.length = 0
    const file = join(base, 'ids.json')
    writeFileSync(file, JSON.stringify({ version: 1, identities }), { mode: 0o600 })
    return {
      io,
      file,
      state,
      touch(label, seconds) {
        const bell = join(state[label] as string, 'doorbell')
        mkdirSync(state[label] as string, { recursive: true })
        if (!existsSync(bell)) writeFileSync(bell, '')
        utimesSync(bell, seconds, seconds)
        return statSync(bell).mtimeMs
      },
    }
  }
  const all = (m: Many, ...more: string[]) => cli(m.io, 'wake-hook', '--identities', m.file, ...more)
  const seen = (m: Many, label: string): string => text(join(m.state[label] as string, 'wake-seen'))
  const ringOf = (label: string) =>
    `bag: a message was delivered to ${label}; read it with the inbox tool as ${label} and report it`

  it('makes each missing state directory, takes each baseline silently, then one ring exits 2 naming its label', async () => {
    const m = await many()
    expect(existsSync(m.state.lab as string)).toBe(false)
    m.touch('personal', 1_700_000_001)
    expect(await all(m, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(seen(m, 'personal')).toBe(`${1_700_000_001_000}\n`)
    expect([seen(m, 'lab'), seen(m, 'club')]).toEqual(['0\n', '0\n'])
    expect(statSync(m.state.lab as string).mode & 0o777).toBe(0o700)
    const at = m.touch('lab', 1_700_000_002)
    expect(await all(m, '--max', '0')).toEqual({ code: 2, out: [], err: [ringOf('lab')] })
    expect([seen(m, 'personal'), seen(m, 'lab'), seen(m, 'club')]).toEqual([
      `${1_700_000_001_000}\n`,
      `${at}\n`,
      '0\n',
    ])
    expect(await all(m, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    for (const s of Object.values(m.state)) expect(existsSync(join(s, 'wake-hook.lock'))).toBe(false)
  })

  it('gives one line naming each identity rung in one poll', async () => {
    const m = await many()
    expect((await all(m, '--max', '0')).code).toBe(0)
    m.touch('personal', 1_700_000_003)
    m.touch('club', 1_700_000_003)
    expect(await all(m, '--max', '0')).toEqual({
      code: 2,
      out: [],
      err: [
        'bag: a message was delivered to each of personal, club; read each with the inbox tool as its label and report it',
      ],
    })
  })

  it('takes the locks all or none: one held by a live hook ends it 0, silent, and the ones it took are released', async () => {
    const m = await many()
    for (const s of Object.values(m.state)) mkdirSync(s, { recursive: true })
    const held = join(m.state.lab as string, 'wake-hook.lock')
    writeFileSync(held, `${process.pid}\n`)
    m.touch('personal', 1_700_000_004)
    expect(await all(m, '--max', '0')).toEqual({ code: 0, out: [], err: [] })
    expect(existsSync(join(m.state.personal as string, 'wake-hook.lock'))).toBe(false)
    expect(existsSync(join(m.state.club as string, 'wake-hook.lock'))).toBe(false)
    expect(text(held)).toBe(`${process.pid}\n`)
    expect(existsSync(join(m.state.personal as string, 'wake-seen'))).toBe(false)
  })

  it('says the idle line once per mail-free stretch, for all: wake-idle in every state directory, and a ring removes its own', async () => {
    const m = await many()
    const deadline = () => wakeHook(['--identities', m.file, '--max', '1'], m.io, 10)
    const IDLE = 'bag: no message for any identity in 1 s'
    expect(await deadline()).toBe(2)
    expect(m.io.stderr).toEqual([IDLE])
    for (const s of Object.values(m.state)) expect(text(join(s, 'wake-idle'))).toBe('1\n')
    m.io.stderr.length = 0
    expect(await deadline()).toBe(0)
    expect(m.io.stderr).toEqual([])
    m.touch('club', 1_700_000_005)
    expect(await deadline()).toBe(2)
    expect(m.io.stderr).toEqual([ringOf('club')])
    expect(existsSync(join(m.state.club as string, 'wake-idle'))).toBe(false)
    expect(existsSync(join(m.state.lab as string, 'wake-idle'))).toBe(true)
    m.io.stderr.length = 0
    expect(await deadline()).toBe(2)
    expect(m.io.stderr).toEqual([IDLE])
  }, 15_000)

  it('--print writes doorbell <label> <mtime> per change and takes no lock', async () => {
    const m = await many()
    expect((await all(m, '--max', '0')).code).toBe(0) // the baselines, which --print only reads
    const printed = wakeHook(['--identities', m.file, '--print'], m.io, 5)
    const at = m.touch('lab', 1_700_000_006)
    await until('the print line', () => m.io.stdout.length > 0)
    expect(m.io.stdout).toEqual([`doorbell lab ${at}`])
    expect(existsSync(join(m.state.lab as string, 'wake-hook.lock'))).toBe(false)
    m.io.stop.abort()
    expect(await printed).toBe(0)
  })

  it('skips an identity its home lacks with one line naming its label, watches the rest, and is exit 1 when none is left', async () => {
    const m = await many()
    const doc = JSON.parse(text(m.file)) as { identities: object[] }
    const nobody = {
      label: 'x',
      key: 'nobody',
      home: join(tmp.dir, 'nohome'),
      relays: ['http://127.0.0.1:9'],
    }
    const [some, none] = [join(tmp.dir, `some-${n++}.json`), join(tmp.dir, `none-${n++}.json`)]
    writeFileSync(some, JSON.stringify({ version: 1, identities: [nobody, ...doc.identities] }), {
      mode: 0o600,
    })
    writeFileSync(none, JSON.stringify({ version: 1, identities: [nobody] }), { mode: 0o600 })
    const skipped = `bag: x skipped: ENOENT: no identity nobody in ${join(tmp.dir, 'nohome')}: no key file, keychain or agent pointer`
    expect(await cli(m.io, 'wake-hook', '--identities', some, '--max', '0')).toEqual({
      code: 0,
      out: [],
      err: [skipped],
    })
    m.touch('lab', 1_700_000_007)
    expect(await cli(m.io, 'wake-hook', '--identities', some, '--max', '0')).toEqual({
      code: 2,
      out: [],
      err: [skipped, ringOf('lab')],
    })
    expect(await cli(m.io, 'wake-hook', '--identities', none, '--max', '0')).toEqual({
      code: 1,
      out: [],
      err: [skipped, `bag: no-identity: no identity of ${none} can be watched`],
    })
    expect(existsSync(join(tmp.dir, 'nohome'))).toBe(false)
  })

  it('refuses --as, --session and --dir beside --identities, and a file open to others', async () => {
    const m = await many()
    const refused = 'bag: usage: --identities takes no --as, --session or --dir: each identity is in the file'
    expect((await all(m, '--as', 'bob')).err[0]).toBe(refused)
    expect((await all(m, '--session', 'auto')).err[0]).toBe(refused)
    expect((await all(m, '--dir', m.state.lab as string)).err[0]).toBe(refused)
    chmodSync(m.file, 0o640)
    expect((await all(m, '--max', '0')).err[0]).toBe(
      `bag: identities-invalid: ${m.file} is open to the group or others: chmod 600 it`,
    )
    expect(existsSync(join(tmp.dir, 'nohome'))).toBe(false)
  })
})
