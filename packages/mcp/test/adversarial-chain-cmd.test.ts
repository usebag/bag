import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Hop, signHop } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { COMMAND_MAX_BYTES, COMMAND_TIMEOUT_MS } from '../src/chain.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  saveKeys,
  sessionChain,
  T0,
  type TestServer,
  tempDir,
  testServer,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The --chain-cmd runner (packages/mcp/src/chain.ts shellRunner line 70, loadChain line 117) with the real
// /bin/sh, through a session server in process. The helper is a shell script under the test's temporary directory
// that reads a mode file: it prints the chain, a chain padded to exactly COMMAND_MAX_BYTES (262,144, line 33), over
// 262,144 bytes (yes | head -c), exits 1, or runs past COMMAND_TIMEOUT_MS (10,000, line 32; loadChain passes the
// constant at line 119, with no option to shorten it, so the timeout case is measured once at the real 10 s, by
// ChainKeeper.reread). Each failure is chain-cmd-failed; the helper's text and its output (a marker it prints) appear
// in no log line, no status result and no error. The slow helper execs sleep under its own pid, which the runner
// SIGKILLs (line 81): the test checks that pid is gone, and the directory is removed after.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let session: TestServer | null = null
const stdout = watchStdout()

const MARKER = 'MARKER-S5'
const renewed = (exp: number): Hop[] => [
  sessionChain()[0] as Hop,
  signHop(P.jane.keys.signing, P.session.address, [], exp),
]

/** The helper's path, the command the server runs, and how to set the helper's mode. */
function helper(): { path: string; command: string; mode(m: string): void } {
  const dir = tmp.dir
  const path = join(dir, 'helper.sh')
  writeFileSync(
    path,
    [
      '#!/bin/sh',
      `dir='${dir}'`,
      'mode=$(cat "$dir/mode")',
      'case "$mode" in',
      '  ok) cat "$dir/chain.json" ;;',
      '  padded) cat "$dir/padded.json" ;;',
      `  big) yes '${MARKER}-big' | head -c ${COMMAND_MAX_BYTES + 1} ;;`,
      `  fail) printf '${MARKER}-fail'; exit 1 ;;`,
      `  slow) echo $$ > "$dir/pid"; printf '${MARKER}-slow'; exec sleep 20 ;;`,
      'esac',
      '',
    ].join('\n'),
  )
  chmodSync(path, 0o755)
  writeFileSync(join(dir, 'chain.json'), `${JSON.stringify(sessionChain())}\n`)
  const chain = JSON.stringify(renewed(T0 + 7200))
  // Exactly COMMAND_MAX_BYTES bytes: the chain, then spaces (loadChain trims the output, chain.ts line 119).
  writeFileSync(join(dir, 'padded.json'), chain + ' '.repeat(COMMAND_MAX_BYTES - Buffer.byteLength(chain)))
  return {
    path,
    command: `exec '${path}'`,
    mode: (m) => writeFileSync(join(dir, 'mode'), m),
  }
}

async function sessionOn(command: string): Promise<TestServer> {
  session = await testServer({
    home: tmp.dir,
    name: 'session',
    relay,
    clock,
    timers,
    args: ['--chain-cmd', command, '--mailbox', P.jane.address, '--trust-root', P.bob.address],
    pid: 1,
    env: { PATH: process.env.PATH },
  })
  return session
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('adversarial-chain-cmd')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.org, P.jane]) await publishAddress(relay, p)
  saveKeys(tmp.dir, P.session, { signing: P.session.keys.signing, sealing: P.jane.keys.sealing })
})

afterEach(async () => {
  await session?.close()
  session = null
  tmp.cleanup()
  stdout.check()
})

/** How many times the helper's text or its marker occur in `text`. */
function leaks(text: string, h: { path: string; command: string }): number {
  let n = 0
  for (const needle of [h.command, h.path, 'helper.sh', MARKER]) {
    for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) n++
  }
  return n
}

describe('a --chain-cmd helper that overruns, overprints or fails', () => {
  it('V1 and the cap: starts on the chain the helper prints, renews on exactly 262,144 bytes; over 262,144 and exit 1 are chain-cmd-failed; nothing of the helper in the logs', async () => {
    const h = helper()
    h.mode('ok')
    const s = await sessionOn(h.command)
    const keeper = s.running.chain
    expect(keeper?.status()).toMatchObject({ source: 'command', earliest_exp: T0 + 3600, renewals: 0 })
    h.mode('padded')
    expect(Buffer.byteLength(readFileSync(join(tmp.dir, 'padded.json')))).toBe(262_144)
    expect(await keeper?.reread('adversarial')).toBe('renewed')
    const outcomes: string[] = []
    for (const m of ['big', 'fail']) {
      h.mode(m)
      outcomes.push((await keeper?.reread('adversarial')) as string)
    }
    expect(outcomes).toEqual(['chain-cmd-failed', 'chain-cmd-failed'])
    // A failure keeps the chain in place.
    expect(keeper?.status()).toMatchObject({
      earliest_exp: T0 + 7200,
      renewals: 1,
      last_reread: { why: 'adversarial', outcome: 'chain-cmd-failed' },
    })
    const status = JSON.stringify((await s.call('status')).result)
    const logs = s.log.text()
    expect(s.log.lines.filter((l) => l.event === 'chain').map((l) => l.fields.outcome)).toEqual([
      'renewed',
      'chain-cmd-failed',
      'chain-cmd-failed',
    ])
    console.log(
      `MEASURE (cap, exit): 262,144 bytes -> renewed; 262,145 bytes -> ${outcomes[0]}; exit 1 -> ${outcomes[1]}; ` +
        `${leaks(logs, h)} occurrences of the command, the path or the output in ${s.log.lines.length} log lines, ${leaks(status, h)} in status`,
    )
    expect(leaks(logs, h)).toBe(0)
    expect(leaks(status, h)).toBe(0)
  })

  it('a helper that fails at start: the server does not start, chain-cmd-failed, and the error names neither the command nor its output', async () => {
    const h = helper()
    const errors: string[] = []
    for (const m of ['fail', 'big']) {
      h.mode(m)
      try {
        await sessionOn(h.command)
        errors.push('started')
      } catch (e) {
        errors.push((e as Error).message)
      }
    }
    expect(errors).toEqual([
      'chain-cmd-failed: it exited with 1',
      `chain-cmd-failed: it printed over ${COMMAND_MAX_BYTES} bytes`,
    ])
    expect(leaks(errors.join('\n'), h)).toBe(0)
    console.log(`MEASURE (at start): exit 1 and 262,145 bytes -> ${errors.join('; ')}`)
  })

  it(`a helper that runs past COMMAND_TIMEOUT_MS (${COMMAND_TIMEOUT_MS} ms, a constant): chain-cmd-failed at the real timeout, its process killed`, async () => {
    const h = helper()
    h.mode('ok')
    const s = await sessionOn(h.command)
    h.mode('slow')
    // performance.now() is monotonic: a wall-clock step cannot move the interval.
    const started = performance.now()
    const outcome = await s.running.chain?.reread('adversarial')
    const elapsed = Math.round(performance.now() - started)
    expect(outcome).toBe('chain-cmd-failed')
    // The deterministic claim is below: the helper sleeps 20 s, and its process is gone, so the runner killed it at its
    // timeout. The wall clock is a floor and a backstop around that. libuv arms a timer from its cached loop time,
    // which can trail the clock by tens of ms on a busy loop (9,951 ms was seen once), so the floor allows a second.
    expect(elapsed).toBeGreaterThanOrEqual(COMMAND_TIMEOUT_MS - 1000)
    expect(elapsed).toBeLessThan(COMMAND_TIMEOUT_MS + 5000)
    // The helper's process (sleep, exec'd under the helper's pid) is gone: the runner killed it.
    expect(existsSync(join(tmp.dir, 'pid'))).toBe(true)
    const pid = Number(readFileSync(join(tmp.dir, 'pid'), 'utf8').trim())
    let alive = true
    for (let i = 0; i < 200 && alive; i++) {
      try {
        process.kill(pid, 0)
        await new Promise((r) => setTimeout(r, 10))
      } catch {
        alive = false
      }
    }
    expect(alive).toBe(false)
    expect(s.running.chain?.status()).toMatchObject({
      earliest_exp: T0 + 3600,
      last_reread: { outcome: 'chain-cmd-failed' },
    })
    const logs = s.log.text()
    console.log(
      `MEASURE (timeout): a helper sleeping 20 s -> ${outcome} after ${elapsed} ms (COMMAND_TIMEOUT_MS ${COMMAND_TIMEOUT_MS}, not settable through the server); its process gone; ${leaks(logs, h)} occurrences in the logs`,
    )
    expect(leaks(logs, h)).toBe(0)
  }, 20_000)
})
