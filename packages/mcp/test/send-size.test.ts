import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { MAX_ENVELOPE_BYTES } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { realTimers } from '../src/desk.ts'
import { type ProcessIo, rawTerminal, serve, TERMINAL_LINE_BYTES } from '../src/server.ts'
import { bodyCharsFor } from '../src/tools.ts'
import {
  FakeClock,
  fakeRecords,
  MemoryLog,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'
import { frames, StreamClientTransport } from './support/streams.ts'

// Sends by size through the whole server: an MCP client on the server's stdio, the send tool, the edge's sender and a
// relay in memory that keeps each envelope's real bytes. A stdin that is a terminal runs raw (rawTerminal), since a
// terminal in canonical mode drops every byte of a line past TERMINAL_LINE_BYTES and a large send then never arrives
// (observed 2026-11-11 under an omp pty service, bag 0.2.3).

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay

beforeEach(async () => {
  tmp = tempDir('send-size')
  relay = new MemoryRelay()
  saveKeys(tmp.dir, P.alice)
  saveKeys(tmp.dir, P.bob)
  await publishAddress(relay, P.alice)
  await publishAddress(relay, P.bob)
})

afterEach(() => {
  tmp.cleanup()
})

/** A stdin as a pty gives it: a stream with isTTY and setRawMode, which records each mode asked. */
class FakeTerminal extends PassThrough {
  readonly isTTY = true
  readonly modes: boolean[] = []
  setRawMode(raw: boolean): this {
    this.modes.push(raw)
    return this
  }
}

interface Run {
  readonly stdin: PassThrough
  readonly stdout: PassThrough
  readonly out: Buffer[]
  readonly err: string[]
  readonly done: Promise<number>
}

function run(stdin: PassThrough): Run {
  const stdout = new PassThrough()
  const out: Buffer[] = []
  stdout.on('data', (chunk: Buffer) => out.push(chunk))
  const err: string[] = []
  const quiet = (): void => {}
  const io = {
    argv: ['--as', 'alice', '--dir', tmp.dir, '--relay', RELAY, '--trust-root', P.bob.address],
    env: {},
    stdin,
    stdout,
    stderr: { write: (t: string) => err.push(t) },
    clock: new FakeClock(),
    rng: seededRng('send-size'),
    relay: () => relay,
    records: fakeRecords(new Map()),
    timers: realTimers,
    pid: 4242,
    alive: () => false,
    signals: new EventEmitter() as unknown as ProcessIo['signals'],
    console: { log: quiet, info: quiet, debug: quiet, warn: quiet, error: quiet },
  } satisfies ProcessIo
  return { stdin, stdout, out, err, done: serve(io) }
}

const events = (r: Run): Record<string, unknown>[] =>
  r.err
    .join('')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as Record<string, unknown>)

/** The text of a send's answer, parsed. */
function answer(result: unknown): Record<string, unknown> {
  const content = (result as { content: { text: string }[] }).content
  return JSON.parse(content[0]?.text as string) as Record<string, unknown>
}

const KIB = 1024

describe('send by size: 1 KiB, 8 KiB and a body that fills the envelope cap, on a terminal stdin', () => {
  it('publishes each in one try with its real bytes at the relay, every frame whole, and refuses one past the cap', async () => {
    const r = run(new FakeTerminal())
    const client = new Client({ name: 'in-process', version: '0.0.0' })
    await client.connect(new StreamClientTransport(r.stdin, r.stdout))
    const send = (text: string) =>
      client.callTool({ name: 'send', arguments: { to: [P.bob.address], type: 'chat.v1', body: { text } } })
    // A body of n characters seals to about 2n bytes of envelope (the sealed part is hex), so the figure send's
    // description gives (bodyCharsFor the cap) is near the top.
    for (const n of [KIB, 8 * KIB, bodyCharsFor(MAX_ENVELOPE_BYTES)]) {
      const before = relay.envelopes.size
      const sent = await send('z'.repeat(n))
      expect(sent.isError).not.toBe(true)
      const a = answer(sent)
      expect(a.targets).toEqual([expect.objectContaining({ status: 'published', tries: 1 })])
      expect(relay.envelopes.size).toBe(before + 1)
      const bytes = relay.envelopes.get(`${RELAY} ${a.id as string}`) as Uint8Array
      expect(bytes.length).toBeGreaterThan(2 * n)
      expect(bytes.length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES)
      // Each request line is longer than a canonical terminal passes on: raw mode is what lets it arrive.
      expect(n + 100).toBeGreaterThan(TERMINAL_LINE_BYTES)
    }
    // Past the cap (a body of half the cap seals to more than the cap): refused at once with its code, nothing
    // published, the server still answering.
    const before = relay.envelopes.size
    const big = await send('z'.repeat(MAX_ENVELOPE_BYTES / 2))
    expect(big.isError).toBe(true)
    expect(JSON.stringify(big.content)).toContain('envelope-too-large')
    expect(relay.envelopes.size).toBe(before)
    const after = await send('a small one after')
    expect(answer(after).targets).toEqual([expect.objectContaining({ status: 'published' })])
    await client.close()
    expect(await r.done).toBe(0)
    expect(frames(Buffer.concat(r.out)).bad).toEqual([])
    expect((r.stdin as FakeTerminal).modes).toEqual([true, false])
    expect(events(r).find((l) => l.event === 'stdin')).toMatchObject({
      level: 'info',
      terminal: true,
      mode: 'raw',
      line_limit_bytes: TERMINAL_LINE_BYTES,
    })
  })
})

describe('rawTerminal', () => {
  it('leaves a stdin that is not a terminal alone: no mode, no log line, no listener', () => {
    const log = new MemoryLog()
    const pipe = new PassThrough()
    const t = rawTerminal(pipe, log)
    t.enter(() => {
      throw new Error('never')
    })
    pipe.write(Buffer.from([0x03]))
    t.undo()
    expect(log.lines).toEqual([])
    expect(pipe.listenerCount('data')).toBe(0)
  })

  it('leaves a terminal stdin with no setRawMode alone', () => {
    const log = new MemoryLog()
    const odd = Object.assign(new PassThrough(), { isTTY: true })
    rawTerminal(odd, log).undo()
    expect(log.lines).toEqual([])
  })

  it('ends the run on Ctrl-C or Ctrl-D, as a buffer or a string, never on a frame; undo restores the mode once', async () => {
    const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))
    for (const end of [Buffer.from([0x03]), Buffer.from('\u0004'), '\u0003']) {
      const tty = new FakeTerminal()
      const t = rawTerminal(tty, new MemoryLog(), () => () => {})
      let ended = 0
      t.enter(() => {
        ended++
      })
      tty.write('{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
      await tick()
      expect(ended).toBe(0)
      tty.write(end)
      await tick()
      expect(ended).toBe(1)
      t.undo()
      t.undo()
      expect(tty.listenerCount('data')).toBe(0)
      expect(tty.modes).toEqual([true, false])
    }
  })

  it('stays canonical until enter, so a Ctrl-C during the start is still SIGINT', () => {
    const tty = new FakeTerminal()
    const log = new MemoryLog()
    const t = rawTerminal(tty, log, () => () => {})
    expect(tty.modes).toEqual([])
    expect(tty.listenerCount('data')).toBe(0)
    expect(log.lines).toEqual([])
    t.enter(() => {})
    expect(tty.modes).toEqual([true])
    t.undo()
    expect(tty.modes).toEqual([true, false])
  })

  it('restores the mode on process exit when serve never reaches its finally, and undo removes that hook', () => {
    const tty = new FakeTerminal()
    let hooked: (() => void) | null = null
    let removed = 0
    const onExit = (restore: () => void) => {
      hooked = restore
      return () => {
        removed++
      }
    }
    const t = rawTerminal(tty, new MemoryLog(), onExit)
    expect(hooked).toBeNull()
    t.enter(() => {})
    expect(hooked).not.toBeNull()
    ;(hooked as unknown as () => void)()
    expect(tty.modes).toEqual([true, false])
    t.undo()
    expect(removed).toBe(1)
    expect(tty.modes).toEqual([true, false])
  })

  it('stops a served run on Ctrl-C with exit 0 and the terminal restored', async () => {
    const tty = new FakeTerminal()
    const r = run(tty)
    await until('the server started', () => events(r).some((l) => l.event === 'start'))
    await until('the watch is on', () => tty.listenerCount('data') >= 2)
    tty.write(Buffer.from([0x03]))
    expect(await r.done).toBe(0)
    expect(tty.modes).toEqual([true, false])
    // Raw mode comes after the start (the red team's read): its stdin line follows the start line, never precedes it.
    const names = events(r).map((l) => l.event)
    expect(names.indexOf('start')).toBeGreaterThanOrEqual(0)
    expect(names.indexOf('stdin')).toBeGreaterThan(names.indexOf('start'))
  })
})
