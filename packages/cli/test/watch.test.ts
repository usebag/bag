import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type InboxRow, SqliteStore } from '@usebag/edge'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { KILL_GRACE_MS, runExec, SHELL } from '../src/commands/watch.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli, type Ran } from './support/run.ts'

// inbox --watch: the live inbox with refusals on stderr, --exec per accepted message with its
// summary (never the body) on stdin, a row recover() finishes printed and run once, the pending runs finished after
// the stop signal (the signal processIo aborts on SIGINT or SIGTERM: io.test.ts; a real SIGTERM is e2e scenario 45's),
// and runExec's one line per failed run. The senders have an io of their own, so the watch's stdout is its own.

const tmp = tempDir('watch')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
// The real setTimeout, taken before any test fakes the global one: the polling below must keep its clock while a test
// drives runExec's timers by hand.
const realSetTimeout = globalThis.setTimeout
const sleep = (ms: number): Promise<void> => new Promise((r) => realSetTimeout(r, ms))
let n = 0

/** Polls `test` every 10 ms for up to 5 s; fails naming `what`. */
async function until(what: string, test: () => boolean): Promise<void> {
  for (const end = Date.now() + 5000; !test(); await sleep(10)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
  }
}

const lines = (file: string): string[] =>
  existsSync(file)
    ? readFileSync(file, 'utf8')
        .split('\n')
        .filter((l) => l !== '')
    : []

interface World {
  readonly relay: MemoryRelay
  /** bob's watch's io. */
  readonly io: TestIo
  /** The senders' io. */
  readonly senders: TestIo
  readonly dir: string
  readonly alice: string
  readonly bob: string
}

/** alice, bob and carol in one home, bob's address record with his sealing key at the relay. */
async function world(): Promise<World> {
  const relay = new MemoryRelay()
  const [io, senders] = [testIo(relay), testIo(relay)]
  const dir = join(tmp.dir, `home-${n++}`)
  const [alice, bob] = await Promise.all(
    ['alice', 'bob', 'carol'].map(
      async (who) => (await cli(senders, 'keygen', who, '--dir', dir)).out[0] as string,
    ),
  )
  const file = join(dir, 'bob.address.json')
  await cli(
    senders,
    'record',
    'address',
    'bob',
    '--relay',
    RELAY,
    '--sealing-key',
    '--out',
    file,
    '--dir',
    dir,
  )
  await cli(senders, 'publish', RELAY, file)
  return { relay, io, senders, dir, alice: alice as string, bob: bob as string }
}

const send = async (w: World, as: string, body: string, type = 'chat.v1'): Promise<string> => {
  const args = ['--to', w.bob, '--relay', RELAY, '--type', type, '--body', body, '--dir', w.dir]
  const sent = await cli(w.senders, 'send', '--as', as, ...args)
  expect(sent.code).toBe(0)
  return sent.out[0] as string
}

/**
 * bob's inbox --watch, trusting alice only, started and subscribed. The run is returned inside an object: an async
 * function that returned the promise itself would adopt it, and wait for the watch to end.
 */
async function watching(w: World, ...more: string[]): Promise<{ running: Promise<Ran> }> {
  const args = ['--as', 'bob', '--relay', RELAY, '--trust-root', w.alice, '--dir', w.dir]
  const running = cli(w.io, 'inbox', '--watch', ...args, ...more)
  await until('the subscription', () => w.relay.subs.size > 0)
  return { running }
}

const accepts = (io: TestIo): string[] => io.stdout.filter((l) => l.startsWith('accept '))
const summaryOf = (w: World, id: string): string => `message ${id} from ${w.alice}, type chat.v1`

describe('inbox --watch: the live inbox, refusals on stderr, --exec per accepted message', () => {
  it('prints a delivery after the watch started as inbox prints it, runs --exec with its summary on stdin, goes on after a non-zero exit, prints a refusal on stderr only, and on the stop signal closes the subscription and exits 0', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    const { running } = await watching(w, '--doorbell-path', '--exec', `cat >> '${file}'; exit 3`)
    const refused = await send(w, 'carol', '{"n":0}')
    const ids = [await send(w, 'alice', '{"n":1}'), await send(w, 'alice', '{"n":2}')]
    await until('both runs', () => w.io.stderr.length === 3)
    expect(w.io.stdout).toEqual([
      `doorbell ${join(w.dir, 'state', 'bob', 'doorbell')}`,
      ...ids.map((id, i) => `accept ${id} ${w.alice} ${w.alice} chat.v1 {"n":${i + 1}}`),
    ])
    expect(lines(file)).toEqual(ids.map((id) => summaryOf(w, id)))
    expect(w.io.stderr).toEqual([
      `reject ${refused} untrusted-root`,
      'bag: exec-failed: exit 3',
      'bag: exec-failed: exit 3',
    ])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
    expect(w.relay.subs.size).toBe(0)
  }, 15_000)

  it('finishes the runs still pending after the stop signal, then exits 0', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    // Each run waits for the gate file, so "still pending at the stop" holds by construction, not by a 0.3 s sleep.
    const gate = join(w.dir, 'gate')
    const cmd = `while [ ! -e '${gate}' ]; do sleep 0.02; done; cat >> '${file}'`
    const { running } = await watching(w, '--exec', cmd)
    try {
      const ids = [await send(w, 'alice', '{"n":1}'), await send(w, 'alice', '{"n":2}')]
      await until('both lines', () => accepts(w.io).length === 2)
      expect(lines(file)).toEqual([])
      w.io.stop.abort()
      writeFileSync(gate, '')
      expect((await running).code).toBe(0)
      expect(lines(file)).toEqual(ids.map((id) => summaryOf(w, id)))
    } finally {
      // On a failure above, open the gate and stop the watch, so the two waiting runs end.
      writeFileSync(gate, '')
      w.io.stop.abort()
    }
  }, 15_000)

  it('prints and runs a row recover() finishes once: it is acked, so the relay does not send its frame again', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    const first = await send(w, 'alice', '{"n":1}')
    // A crash after the frame was stored and before it was handled: the row is received and not acked.
    mkdirSync(join(w.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    const { bytes } = w.relay.box(w.bob)[0] as { bytes: Uint8Array }
    store.inboxAdd(RELAY, w.bob, 1, bytes, w.io.time.now)
    store.close()
    const { running } = await watching(w, '--exec', `cat >> '${file}'`)
    // Frames come in cursor order: once the second message prints, a resent first frame would have printed before it.
    const second = await send(w, 'alice', '{"n":2}')
    await until('both runs', () => lines(file).length === 2)
    expect(accepts(w.io).map((l) => l.split(' ')[1])).toEqual([first, second])
    expect(lines(file)).toEqual([summaryOf(w, first), summaryOf(w, second)])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
  }, 15_000)

  it('kills a run past --exec-timeout with SIGTERM, one stderr line naming the message, and the next queued run proceeds', async () => {
    const w = await world()
    const [marker, file] = [join(w.dir, 'marker'), join(w.dir, 'exec.txt')]
    // The first run creates the marker and hangs (exec: the SIGTERM reaches sleep itself); the second reads the marker.
    const cmd = `if [ -e '${marker}' ]; then cat >> '${file}'; else : > '${marker}'; exec sleep 30; fi`
    const { running } = await watching(w, '--exec', cmd, '--exec-timeout', '1')
    // The 1 s limit is runExec's setTimeout, faked from here on (the polling keeps the real one): the test advances it
    // only once the first run has written its marker, so shell start-up cannot let the limit fire first.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const sent: string[] = []
    try {
      sent.push(await send(w, 'alice', '{"n":1}'), await send(w, 'alice', '{"n":2}'))
      await until('the first run to hang', () => existsSync(marker))
      vi.advanceTimersByTime(1000)
      await until('the second run', () => lines(file).length === 1)
    } finally {
      vi.useRealTimers()
    }
    const [first, second] = sent as [string, string]
    expect(lines(file)).toEqual([summaryOf(w, second)])
    expect(w.io.stderr).toEqual([
      `bag: exec-timeout: message ${first} got SIGTERM after 1 s`,
      'bag: exec-failed: exit SIGTERM',
    ])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
  }, 15_000)

  // A newline type can no longer be sent (encodeContent refuses it bad-content; a hand-sealed one is
  // "reject <id> bad-content" at the receiver), so a type with a space stands in: it also shows as (not shown).
  it('without --exec (an --exec-timeout=5 is accepted and ignored) prints the line only; a type with a space prints as (not shown), one line', async () => {
    const w = await world()
    const { running } = await watching(w, '--exec-timeout=5')
    const id = await send(w, 'alice', '{"n":1}', 'chat.v1 reject forged untrusted-root')
    await until('the line', () => accepts(w.io).length === 1)
    w.io.stop.abort()
    expect(await running).toEqual({
      code: 0,
      out: [`accept ${id} ${w.alice} ${w.alice} (not shown) {"n":1}`],
      err: [],
    })
  }, 15_000)

  it('refuses what --watch does not take, and an --exec without --watch or without a command', async () => {
    const w = await world()
    const err = async (...args: string[]): Promise<string | undefined> =>
      (await cli(w.io, 'inbox', ...args)).err[0]
    const usage = (detail: string): string => `bag: usage: ${detail}`
    expect(await err('--exec', 'true', '--as', 'bob')).toBe(usage('--exec needs --watch'))
    expect(await err('--watch', '--exec=a', '--exec', 'b')).toBe(usage('--exec is given once'))
    expect(await err('--watch', '--exec')).toBe(usage('--exec needs a command'))
    expect(await err('--watch', '--exec', '--as', 'bob')).toBe(usage('--exec needs a command'))
    for (const bad of ['', 'abc', '-1', '1e3', '2000001']) {
      expect(await err('--watch', '--exec', 'true', `--exec-timeout=${bad}`)).toBe(
        usage('--exec-timeout needs seconds (0: none)'),
      )
    }
    expect(await err('--watch', '--exec', 'true', '--exec-timeout')).toBe(
      usage('--exec-timeout needs seconds (0: none)'),
    )
    expect(await err('--watch', '--once', '--as', 'bob')).toBe(usage('--watch takes no --once'))
    expect(await err('--watch', '--quarantined')).toBe(usage('--watch takes no --quarantined'))
    expect(await err('release', '1', '--watch')).toBe(usage('--watch takes no release'))
    expect(await err('--watch', '--as', 'bob', '--dir', w.dir)).toBe(usage('--relay is required'))
  })
})

/** bob's store, opened while no watch runs, to stage what a crash or a transient rejection leaves. */
function bobStore(w: World): SqliteStore {
  mkdirSync(join(w.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
  return new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
}

// edge/wake-gaps: the edge calls `accepted` once per row when it acks it, on every path; the watch prints and runs from
// it, so each path below prints one accept line and runs --exec once. inbox release prints from decide() (policy.test.ts,
// "releases a row on yes", asserts its one accept line); it needs a terminal and cannot run beside a watch (busy).
describe('inbox --watch: every path that acks an accepted row prints it once and runs --exec once', () => {
  it('a row the retrier accepts above the highest cursor handed over, with resume null, prints and runs once', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    const id = await send(w, 'alice', '{"n":1}')
    // A transient rejection left the row waiting, not due yet; the relay holds the frame's ack, so it sends it no more.
    const store = bobStore(w)
    const row = store.inboxAdd(
      RELAY,
      w.bob,
      1,
      (w.relay.box(w.bob)[0] as { bytes: Uint8Array }).bytes,
      w.io.time.now,
    )
    store.inboxPut(
      row,
      { state: 'received', reason: 'resolve-failed', tries: 1, nextAt: w.io.time.now + 5 },
      w.io.time.now,
    )
    store.close()
    w.relay.acks.set(w.bob, 1)
    // The start checks a waiting row at once (recover()): with the clock set back past the skew, that check finds the
    // envelope future-ts and the row waits again, so only the retrier, past the highest cursor, accepts it.
    w.io.time.now -= 400
    const { running } = await watching(w, '--exec', `cat >> '${file}'`)
    expect(accepts(w.io)).toEqual([])
    w.io.time.now += 410
    await until('the retried run', () => lines(file).length === 1)
    expect(accepts(w.io)).toEqual([`accept ${id} ${w.alice} ${w.alice} chat.v1 {"n":1}`])
    expect(lines(file)).toEqual([summaryOf(w, id)])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
  }, 15_000)

  it('a row a crash left routed and unacked is acked by recover() and prints and runs once', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    const id = await send(w, 'alice', '{"n":1}')
    const once = ['--as', 'bob', '--relay', RELAY, '--trust-root', w.alice, '--once', '--dir', w.dir]
    expect((await cli(w.senders, 'inbox', ...once)).code).toBe(0)
    // The crash: the route committed, the ack did not.
    const store = bobStore(w)
    store.inboxPut(store.inboxList(['acked'])[0] as InboxRow, { state: 'routed' }, w.io.time.now)
    store.close()
    const { running } = await watching(w, '--exec', `cat >> '${file}'`)
    const second = await send(w, 'alice', '{"n":2}')
    await until('both runs', () => lines(file).length === 2)
    expect(accepts(w.io).map((l) => l.split(' ')[1])).toEqual([id, second])
    expect(lines(file)).toEqual([summaryOf(w, id), summaryOf(w, second)])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
  }, 15_000)

  it('a frame the relay sends again after its row was acked prints nothing and runs nothing', async () => {
    const w = await world()
    const file = join(w.dir, 'exec.txt')
    const first = await send(w, 'alice', '{"n":1}')
    const once = ['--as', 'bob', '--relay', RELAY, '--trust-root', w.alice, '--once', '--dir', w.dir]
    expect((await cli(w.senders, 'inbox', ...once)).out).toHaveLength(1)
    w.relay.replay = true
    const { running } = await watching(w, '--exec', `cat >> '${file}'`)
    // The replay sends the first frame again, then the second: once the second prints, the first was seen and skipped.
    const second = await send(w, 'alice', '{"n":2}')
    await until('the second run', () => lines(file).length === 1)
    expect(accepts(w.io).map((l) => l.split(' ')[1])).toEqual([second])
    expect(lines(file)).toEqual([summaryOf(w, second)])
    expect(first).not.toBe(second)
    w.io.stop.abort()
    expect((await running).code).toBe(0)
  }, 15_000)
})

describe('inbox --once: a throwing output sink, and a row recover() finishes as refused', () => {
  it('an output sink that throws on an accept line (an Error, then a bare string) goes to onError as one stderr line each, the rows stay acked, and the next run prints nothing for them', async () => {
    const w = await world()
    await send(w, 'alice', '{"n":1}')
    await send(w, 'alice', '{"n":2}')
    const once = ['--as', 'bob', '--relay', RELAY, '--trust-root', w.alice, '--once', '--dir', w.dir]
    const out = w.io.out
    const thrown: unknown[] = [new Error('sink failed'), 'plain string']
    // The accept line is printed by the edge's `accepted` callback, inside Receiver.ack: a throw there reaches onError.
    ;(w.io as { out: (line: string) => void }).out = (line) => {
      if (line.startsWith('accept ') && thrown.length > 0) throw thrown.shift()
      out(line)
    }
    const first = await cli(w.io, 'inbox', ...once)
    expect(first).toEqual({
      code: 0,
      out: [],
      err: ['bag: accepted: sink failed', 'bag: accepted: plain string'],
    })
    const store = bobStore(w)
    expect(store.inboxList(['acked']).map((r) => r.state)).toEqual(['acked', 'acked'])
    expect(store.inboxList(['routed', 'queued'])).toEqual([])
    store.close()
    expect(await cli(w.io, 'inbox', ...once)).toEqual({ code: 0, out: [], err: [] })
  }, 15_000)

  it('prints its reject line once, and the row is acked', async () => {
    const w = await world()
    const refused = await send(w, 'carol', '{"n":0}')
    // The crash: the frame was stored (received), the edge never handled it.
    const store = bobStore(w)
    store.inboxAdd(RELAY, w.bob, 1, (w.relay.box(w.bob)[0] as { bytes: Uint8Array }).bytes, w.io.time.now)
    store.close()
    const once = ['--as', 'bob', '--relay', RELAY, '--trust-root', w.alice, '--once', '--dir', w.dir]
    expect(await cli(w.io, 'inbox', ...once)).toEqual({
      code: 0,
      out: [`reject ${refused} untrusted-root`],
      err: [],
    })
    const after = bobStore(w)
    expect(after.inboxList(['acked']).map((r) => r.state)).toEqual(['acked'])
    expect(after.inboxList(['received', 'rejected'])).toEqual([])
    after.close()
    expect(await cli(w.io, 'inbox', ...once)).toEqual({ code: 0, out: [], err: [] })
  }, 15_000)
})

describe('runExec: one stderr line per failed run, and it always resolves', () => {
  const failures = (io: TestIo): string[] => io.stderr.filter((l) => l.startsWith('bag: exec-failed: '))

  it('logs a signal, a spawn that throws, and a spawn that errors, once each', async () => {
    const io = testIo(new MemoryRelay())
    await runExec('kill -9 $$', 'line', io, SHELL)
    expect(failures(io)).toEqual(['bag: exec-failed: exit SIGKILL'])
    await runExec('a\0b', 'line', io, SHELL)
    expect(failures(io)).toHaveLength(2)
    // The spawn's error resolves the run; a close after it, with a negative code, adds no line.
    await runExec('true', 'line', io, join(tmp.dir, 'no-such-shell'))
    expect(failures(io)).toHaveLength(3)
    expect(failures(io)[2]).toMatch(/ENOENT/)
  })

  it('logs a stdin the command closed unread (EPIPE), and EPIPE with a non-zero exit, as one line each', async () => {
    const io = testIo(new MemoryRelay())
    // 4 MiB fills the pipe: the command exits without reading, so the write fails, possibly after the close; the code
    // the write gets (EPIPE, ECONNRESET or ENOTCONN) depends on the timing, and all three are the one fixed detail.
    await runExec('exit 0', 'x'.repeat(4 << 20), io, SHELL)
    await until('the broken pipe line', () => failures(io).length === 1)
    expect(failures(io)[0]).toBe('bag: exec-failed: stdin closed unread')
    // The exit's line or the write's, whichever comes first, is logged by the close that resolves; never both.
    await runExec('exit 3', 'x'.repeat(4 << 20), io, SHELL)
    expect(failures(io)).toHaveLength(2)
  })
})

describe('runExec with a limit: SIGTERM past the timeout, SIGKILL after the grace for a command that ignores it', () => {
  const lineFor = (sig: string): string => `bag: exec-timeout: message m1 got ${sig} after 0.3 s`

  it('sends SIGTERM to a run past its limit, one stderr line, and no SIGKILL for a command that obeys it', async () => {
    const io = testIo(new MemoryRelay())
    // No elapsed-time bound: a SIGKILL line (the 5 s grace was needed) or a missing exit SIGTERM fails the toEqual.
    await runExec('exec sleep 30', 'line', io, SHELL, { id: 'm1', secs: 0.3 })
    expect(io.stderr).toEqual([lineFor('SIGTERM'), 'bag: exec-failed: exit SIGTERM'])
  }, 15_000)

  it('sends SIGKILL after the grace to a command that ignores SIGTERM; a run within its limit, and secs 0, get no signal', async () => {
    expect(KILL_GRACE_MS).toBe(5000)
    const io = testIo(new MemoryRelay())
    const ready = join(tmp.dir, `ready-${n++}`)
    // The limit and the grace are runExec's setTimeouts, faked; the test advances them by hand. trap "" sets SIGTERM
    // to ignored, the marker says the trap is set (so shell start-up cannot let SIGTERM land before it), and exec keeps
    // an ignored signal ignored: sleep survives SIGTERM, no orphan.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const run = runExec(`trap "" TERM; : > '${ready}'; exec sleep 30`, 'line', io, SHELL, {
        id: 'm1',
        secs: 0.3,
        graceMs: 300,
      })
      await until('the trap to be set', () => existsSync(ready))
      vi.advanceTimersByTime(299)
      expect(io.stderr).toEqual([])
      vi.advanceTimersByTime(1)
      expect(io.stderr).toEqual([lineFor('SIGTERM')])
      vi.advanceTimersByTime(299)
      expect(io.stderr).toEqual([lineFor('SIGTERM')])
      vi.advanceTimersByTime(1)
      await run
    } finally {
      vi.useRealTimers()
    }
    expect(io.stderr).toEqual([lineFor('SIGTERM'), lineFor('SIGKILL'), 'bag: exec-failed: exit SIGKILL'])
    const quiet = testIo(new MemoryRelay())
    // A run that ends within its limit, and a run with secs 0, get no signal, however far the faked clock then moves.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      await runExec('exit 0', 'line', quiet, SHELL, { id: 'm1', secs: 0.3 })
      const unlimited = runExec('sleep 0.5', 'line', quiet, SHELL, { id: 'm1', secs: 0 })
      vi.advanceTimersByTime(3_600_000)
      await unlimited
    } finally {
      vi.useRealTimers()
    }
    expect(quiet.stderr).toEqual([])
  }, 15_000)
})
