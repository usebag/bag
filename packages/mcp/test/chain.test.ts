import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Hop, isAcError, signHop } from '@usebag/core'
import { EdgeError } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  type ChainHolder,
  ChainKeeper,
  type ChainKeeperOptions,
  COMMAND_MAX_BYTES,
  earliestExp,
  loadChain,
  parseChainText,
  type RunCommand,
  readChain,
  runShell,
  shellRunner,
} from '../src/chain.ts'
import { ConfigError } from '../src/config.ts'
import { FakeClock, ManualTimers, MemoryLog, P, sessionChain, T0, tempDir } from './support/fixtures.ts'

// The chain keeper's parts: reading a chain from a file or a credential helper's output, running the helper
// under /bin/sh with its limits, and the keeper's schedule. The session tests drive the keeper inside a server.

let tmp: ReturnType<typeof tempDir>

beforeEach(() => {
  tmp = tempDir('chain')
})

afterEach(() => {
  tmp.cleanup()
})

function writeChain(name: string, value: unknown): string {
  const file = join(tmp.dir, name)
  writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value)}\n`)
  return file
}

/** The code a call fails with: the closed set's, the server's own, or an errno. */
async function failure(fn: () => unknown): Promise<string> {
  try {
    await fn()
  } catch (e) {
    if (isAcError(e) || e instanceof ConfigError) return e.code
    return String((e as { code?: unknown }).code)
  }
  throw new Error('it did not fail')
}

const renewed = (exp: number): Hop[] => [
  sessionChain()[0] as Hop,
  signHop(P.jane.keys.signing, P.session.address, [], exp),
]

describe('readChain and parseChainText: the CLI delegate format', () => {
  it('reads one JSON line of hops, root first, as the CLI writes it', () => {
    const chain = sessionChain()
    expect(readChain(writeChain('chain.json', chain))).toEqual(chain)
    expect(parseChainText(JSON.stringify(chain), 'text')).toEqual(chain)
    expect(earliestExp(chain)).toBe(T0 + 3600)
  })

  it('refuses a file that is not JSON (bad-json), not a list (bad-shape), or with a bad hop (bad-hop)', async () => {
    expect(await failure(() => readChain(writeChain('a.json', '[{')))).toBe('bad-json')
    expect(await failure(() => readChain(writeChain('b.json', { hops: [] })))).toBe('bad-shape')
    expect(await failure(() => readChain(writeChain('c.json', [{ iss: 'x' }])))).toBe('bad-hop')
    expect(await failure(() => readChain(join(tmp.dir, 'missing.json')))).toBe('ENOENT')
  })
})

describe('shellRunner: /bin/sh -c with a timeout, a cap on the output, stdin closed and stderr dropped', () => {
  it("prints the command's stdout, in the environment given, with stdin closed and stderr not kept", async () => {
    expect(
      await runShell('printf \'%s\' "$AC_CHAIN_TEST"; echo noise >&2; cat', { AC_CHAIN_TEST: 'y' }, 5000),
    ).toBe('y')
    expect(await runShell('printf hi', {}, 5000)).toBe('hi')
  })

  it('fails chain-cmd-failed for an exit other than 0, a signal, a timeout and an output over the cap', async () => {
    const reason = async (command: string, ms = 5000): Promise<string> => {
      try {
        await runShell(command, {}, ms)
      } catch (e) {
        return `${(e as ConfigError).code}: ${(e as Error).message}`
      }
      return 'ok'
    }
    expect(await reason('exit 3')).toBe('chain-cmd-failed: chain-cmd-failed: it exited with 3')
    expect(await reason('kill -9 $$')).toBe('chain-cmd-failed: chain-cmd-failed: it exited with SIGKILL')
    expect(await reason('sleep 5', 100)).toBe(
      'chain-cmd-failed: chain-cmd-failed: it did not finish within 0.1 s',
    )
    expect(await reason(`head -c ${COMMAND_MAX_BYTES + 1} /dev/zero`)).toBe(
      `chain-cmd-failed: chain-cmd-failed: it printed over ${COMMAND_MAX_BYTES} bytes`,
    )
  })

  it('fails with the errno when the shell itself cannot start', async () => {
    expect(await failure(() => shellRunner(join(tmp.dir, 'no-shell'))('true', {}, 5000))).toBe('ENOENT')
  })
})

describe('loadChain: from a file, or from what a command prints', () => {
  it('reads a file, the JSON a command prints, or the file whose path it prints', async () => {
    const file = writeChain('chain.json', sessionChain())
    const printing =
      (text: string): RunCommand =>
      async () =>
        text
    expect(await loadChain({ kind: 'file', path: file }, printing(''), {})).toEqual(sessionChain())
    const json = `  ${JSON.stringify(sessionChain())}\n`
    expect(await loadChain({ kind: 'command', command: 'c' }, printing(json), {})).toEqual(sessionChain())
    expect(await loadChain({ kind: 'command', command: 'c' }, printing(`${file}\n`), {})).toEqual(
      sessionChain(),
    )
    expect(
      await loadChain({ kind: 'command', command: 'printf \'%s\' "$CHAIN"' }, runShell, { CHAIN: file }),
    ).toEqual(sessionChain())
  })

  it('refuses an empty output or several lines, and names neither the output nor the path it printed', async () => {
    const run =
      (text: string): RunCommand =>
      async () =>
        text
    for (const text of ['', '  \n', 'one\ntwo']) {
      await expect(loadChain({ kind: 'command', command: 'c' }, run(text), {})).rejects.toThrow(
        'chain-cmd-failed: it printed neither the chain JSON nor the path of one chain file',
      )
    }
    const missing = join(tmp.dir, 'secret-name.json')
    const bad = writeChain('bad.json', '[{')
    for (const [path, code] of [
      [missing, 'ENOENT'],
      [bad, 'bad-json'],
    ] as const) {
      const e = await loadChain({ kind: 'command', command: 'c' }, run(path), {}).catch((x: unknown) => x)
      expect([(e as ConfigError).code, (e as Error).message]).toEqual([
        code,
        `${code}: the chain file that --chain-cmd named cannot be read as a chain`,
      ])
    }
    expect(await failure(() => loadChain({ kind: 'command', command: 'c' }, run('[1'), {}))).toBe('bad-json')
  })
})

/**
 * A stand-in for the edge's chain (Edge.auth and Edge.renewChain): it refuses a chain that expires no later with
 * chain-not-later, else swaps it in. The session tests run the keeper against the real Edge.
 */
function holder(): ChainHolder & { auth: readonly Hop[] } {
  const h = {
    auth: sessionChain() as readonly Hop[],
    renewChain(next: readonly Hop[]): void {
      if (earliestExp(next) <= earliestExp(h.auth)) throw new EdgeError('chain-not-later', 'not later')
      h.auth = next
    },
  }
  return h
}

describe('ChainKeeper: the schedule and the outcomes of a read', () => {
  function keeper(over: Partial<ChainKeeperOptions> = {}) {
    const clock = new FakeClock()
    const timers = new ManualTimers()
    const log = new MemoryLog()
    const edge = holder()
    let renewals = 0
    const k = new ChainKeeper({
      source: { kind: 'command', command: 'c' },
      edge,
      clock,
      timers,
      run: async () => JSON.stringify(sessionChain()),
      env: {},
      log,
      onRenewed: () => {
        renewals++
      },
      ...over,
    })
    return { k, clock, timers, log, edge, renewed: () => renewals }
  }

  it('reads at once when the chain is already inside the lead, and a renewal inside the lead waits 10 s', async () => {
    const clock = new FakeClock()
    clock.t = T0 + 3590
    const short = renewed(T0 + 3630)
    const { k, timers, edge } = keeper({ clock, run: async () => JSON.stringify(short) })
    k.start()
    expect(timers.live()).toEqual([0])
    timers.fire()
    await expect.poll(() => k.status().renewals).toBe(1)
    expect(edge.auth).toEqual(short)
    expect(timers.live()).toEqual([10_000])
  })

  it('shares one read between calls made while it runs, and reports an outcome of internal for a fault', async () => {
    let calls = 0
    let release: (text: string) => void = () => {}
    const { k } = keeper({
      run: () => {
        calls++
        return new Promise<string>((resolve) => {
          release = resolve
        })
      },
    })
    const a = k.reread('one')
    const b = k.reread('two')
    release(JSON.stringify(renewed(T0 + 7200)))
    expect([await a, await b, calls]).toEqual(['renewed', 'renewed', 1])
    const faulty = keeper({
      run: async () => {
        throw new Error('a fault')
      },
    })
    expect(await faulty.k.reread('x')).toBe('internal')
    const denied = keeper({
      run: async () => {
        throw Object.assign(new Error('EACCES: denied'), { code: 'EACCES' })
      },
    })
    expect(await denied.k.reread('x')).toBe('EACCES')
    expect(denied.log.lines.at(-1)).toMatchObject({
      level: 'warn',
      event: 'chain',
      fields: { outcome: 'EACCES' },
    })
  })

  it('after stop schedules nothing and calls no renewal hook, though a read in flight still lands', async () => {
    let release: (text: string) => void = () => {}
    const {
      k,
      timers,
      renewed: count,
      edge,
    } = keeper({
      run: () =>
        new Promise<string>((resolve) => {
          release = resolve
        }),
    })
    k.start()
    expect(k.status().next_reread_at).toBe(new Date((T0 + 3540) * 1000).toISOString())
    const reading = k.reread('x')
    k.stop()
    expect([k.status().next_reread_at, timers.live()]).toEqual([null, []])
    release(JSON.stringify(renewed(T0 + 7200)))
    expect(await reading).toBe('renewed')
    expect([count(), timers.live(), earliestExp(edge.auth)]).toEqual([0, [], T0 + 7200])
  })

  it("maps the edge's refusals: chain-not-later is unchanged, chain-mismatch other-identity, another edge code is itself", async () => {
    const outcomes: string[] = []
    for (const code of ['chain-not-later', 'chain-mismatch', 'busy'] as const) {
      const { k, log } = keeper({
        edge: {
          auth: sessionChain(),
          renewChain: () => {
            throw new EdgeError(code, 'refused')
          },
        },
      })
      outcomes.push(await k.reread('x'))
      expect(log.lines.at(-1)?.level).toBe(code === 'chain-not-later' ? 'info' : 'warn')
    }
    expect(outcomes).toEqual(['unchanged', 'other-identity', 'busy'])
  })

  it('works without a renewal hook', async () => {
    const clock = new FakeClock()
    const k = new ChainKeeper({
      source: { kind: 'file', path: writeChain('renewed.json', renewed(T0 + 7200)) },
      edge: holder(),
      clock,
      timers: new ManualTimers(),
      run: runShell,
      env: {},
      log: new MemoryLog(),
    })
    expect(await k.reread('x')).toBe('renewed')
  })
})
