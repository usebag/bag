import { PassThrough, Readable } from 'node:stream'
import { describe, expect, it } from 'vitest'
import { type ProcessLike, processIo } from '../src/io.ts'

function fakeProcess(
  stdin: string[] = [],
  isTTY?: boolean,
): ProcessLike & { out: string[]; err: string[]; emit(event: string): void } {
  const listeners = new Map<string, () => void>()
  const out: string[] = []
  const err: string[] = []
  return {
    out,
    err,
    stdout: { write: (t: string) => out.push(t) },
    stderr: { write: (t: string) => err.push(t) },
    stdin: Object.assign(Readable.from(stdin), isTTY === undefined ? {} : { isTTY }),
    env: { AC_HOME: '/h' },
    once(event, listener) {
      listeners.set(event, listener)
    },
    emit(event) {
      listeners.get(event)?.()
    },
  }
}

describe('processIo: the real io on a process', () => {
  it('writes lines to stdout and stderr, and reads the environment, the clock and the CSPRNG', () => {
    const proc = fakeProcess()
    const io = processIo(proc)
    io.out('one')
    io.err('two')
    expect([proc.out, proc.err, io.env.AC_HOME, io.idleMs]).toEqual([['one\n'], ['two\n'], '/h', 1000])
    expect(Math.abs(io.clock.now() - Date.now() / 1000)).toBeLessThan(2)
    expect(io.rng.bytes(32)).toHaveLength(32)
  })

  it('readAll reads stdin whole as UTF-8, and gives null past its bound', async () => {
    const chunks = [Buffer.from('{"text":'), Buffer.from('"h\u00e9"}')]
    expect(await processIo(fakeProcess(chunks as unknown as string[])).readAll?.(100)).toBe(
      '{"text":"h\u00e9"}',
    )
    expect(
      await processIo(fakeProcess([Buffer.alloc(8), Buffer.alloc(8)] as unknown as string[])).readAll?.(15),
    ).toBeNull()
  })

  it('makes relay clients with the health probe, and a record source over them', () => {
    const io = processIo(fakeProcess())
    const client = io.relay({ maxReconnects: 0 })
    const calls = ['fetch', 'fetchRecord', 'health', 'pairClaim', 'pairOpen', 'publish', 'subscribe']
    expect(Object.keys(client).sort()).toEqual(calls)
    expect(Object.keys(io.records(client)).sort()).toEqual([
      'handleRecord',
      'relayRecord',
      'txt',
      'wellKnown',
    ])
  })

  it('writes a prompt on stderr with no newline, and stdinEnded resolves when stdin ends (bag mcp)', async () => {
    const proc = fakeProcess(['a frame\n'])
    const io = processIo(proc)
    io.prompt('Paste the code: ')
    expect([proc.out, proc.err]).toEqual([[], ['Paste the code: ']])
    const ended = io.stdinEnded?.()
    proc.stdin.resume()
    await expect(ended).resolves.toBeUndefined()
  })

  for (const signal of ['SIGINT', 'SIGTERM']) {
    it(`installs its stop handlers once, when asked, and aborts on ${signal}`, () => {
      const proc = fakeProcess()
      const io = processIo(proc)
      proc.emit(signal)
      const stop = io.stopSignal()
      expect(io.stopSignal()).toBe(stop)
      expect(stop.aborted).toBe(false)
      proc.emit(signal)
      expect(stop.aborted).toBe(true)
    })
  }

  it('reads a secret with the echo off on a terminal, and as a plain line elsewhere', async () => {
    const calls: boolean[] = []
    const tty = fakeProcess(['seed one\n', 'seed two\n'], true)
    const io = processIo({ ...tty, echo: (on) => calls.push(on) })
    expect(await io.readSecret()).toBe('seed one')
    expect([calls, tty.err]).toEqual([[false, true], ['\n']])
    const pipe = fakeProcess(['line\n'], false)
    const plain = processIo({ ...pipe, echo: (on) => calls.push(on) })
    expect(await plain.readSecret()).toBe('line')
    expect(calls).toEqual([false, true])
    // Without an echo of its own, stty runs on stdin; not a terminal here, so it fails, and the line is read all the same.
    expect(await processIo(fakeProcess(['by stty\n'], true)).readSecret()).toBe('by stty')
  })

  it('reads whether stdin is a terminal: only a stream that says so is one', () => {
    expect([true, false, undefined].map((t) => processIo(fakeProcess([], t)).isTty)).toEqual([
      true,
      false,
      false,
    ])
  })

  it('confirm writes its prompt to stderr and reads one line: yes for y or yes in any case, else no', async () => {
    const answers: [string[], boolean][] = [
      [['y\n'], true],
      [[' YES \n', 'n\n'], true],
      [['n\n', 'y\n'], false],
      [['yep\n'], false],
      [['\n'], false],
      [[], false],
    ]
    for (const [lines, want] of answers) {
      const proc = fakeProcess(lines, true)
      expect(await processIo(proc).confirm('release row 7?')).toBe(want)
      expect(proc.err).toEqual(['release row 7? [y/N] '])
      expect(proc.out).toEqual([])
    }
  })

  it('readLine gives each line exactly as typed, writes nothing, and gives null at the end of input', async () => {
    const proc = fakeProcess([' Y es \n', 'second\nthird\n'], true)
    const io = processIo(proc)
    const got: (string | null)[] = []
    for (let i = 0; i < 5; i++) {
      got.push(await io.readLine())
      expect(proc.stdin.isPaused(), `after read ${i}`).toBe(true)
    }
    expect(got).toEqual([' Y es ', 'second', 'third', null, null])
    expect([proc.out, proc.err]).toEqual([[], []])
  })

  it('release resolves a pending readLine with null, pauses stdin, and makes every later readLine null at once', async () => {
    const stdin = Object.assign(new PassThrough(), { isTTY: true })
    const io = processIo({ ...fakeProcess(), stdin })
    const pending = io.readLine()
    expect(stdin.isPaused()).toBe(false)
    io.release()
    expect(await pending).toBeNull()
    expect(stdin.isPaused()).toBe(true)
    stdin.write('typed after release\n')
    expect(await io.readLine()).toBeNull()
    expect(stdin.isPaused()).toBe(true)
  })
})
