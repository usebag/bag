import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  createRelayClient,
  FsKeyStore,
  generateEdgeKeys,
  type RelayClient,
  readTelemetrySpool,
  setTelemetry,
  systemRng,
  TELEMETRY_NOTICE,
} from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { DEFAULT_PORT } from '../src/bridge.ts'
import { parseBridgeArgs, type RunIo, runBridge, USAGE } from '../src/run.ts'
import { AGENT, deferred } from './support.ts'

// The bridge as a process, composed on a real home: a key file, the SQLite store and the audit log under
// <home>/state/<name>/, and a relay that is not there (127.0.0.1:1), so nothing leaves this machine.

const home = mkdtempSync(join(tmpdir(), 'bag-a2a-run-'))
afterAll(() => rmSync(home, { recursive: true, force: true }))
const keys = generateEdgeKeys(systemRng)
new FsKeyStore(join(home, 'keys')).save('me', keys)
const RELAY = 'http://127.0.0.1:1'
const flags = ['--as', 'me', '--relay', RELAY, '--agent', AGENT, '--dir', home]

/** An io that keeps what is printed. */
function lines(): RunIo & { readonly outs: string[]; readonly errs: string[] } {
  const outs: string[] = []
  const errs: string[] = []
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) }
}

const until = async (test: () => boolean): Promise<void> => {
  const end = Date.now() + 10_000
  while (!test()) {
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

describe('parseBridgeArgs: the flags and the environment', () => {
  it('reads the defaults: the home from AC_HOME or ~/.bag, 127.0.0.1 and port 7741', () => {
    const minimal = ['--as', 'me', '--relay', RELAY, '--agent', AGENT]
    expect(parseBridgeArgs(minimal, {})).toEqual({
      as: 'me',
      home: resolve(homedir(), '.bag'),
      relays: [RELAY],
      agents: [AGENT],
      host: '127.0.0.1',
      port: DEFAULT_PORT,
    })
    expect(parseBridgeArgs(minimal, { AC_HOME: '/h' })).toMatchObject({ home: '/h' })
    const given = parseBridgeArgs([...minimal, '--dir', 'rel', '--port', '0', '--host', '127.0.0.2'], {})
    expect(given).toMatchObject({ home: resolve('rel'), port: 0, host: '127.0.0.2' })
    expect(parseBridgeArgs(['--help'], {})).toBe('help')
  })

  it('refuses a missing or bad flag', () => {
    const bad = (argv: string[]): string => {
      try {
        parseBridgeArgs(argv, {})
        return 'parsed'
      } catch (e) {
        return (e as Error).message
      }
    }
    expect(bad(['--relay', RELAY, '--agent', AGENT])).toBe('--as <key name> is required')
    expect(bad(['--as', 'me', '--agent', AGENT])).toBe('--relay <url> is required')
    expect(bad(['--as', 'me', '--relay', RELAY])).toMatch(/^--agent <address> is required/)
    expect(bad(['--as', 'me', '--relay', RELAY, '--agent', 'ed25519:xyz'])).toMatch(/^--agent/)
    expect(bad([...flags, '--port', 'x'])).toBe('--port is 0 to 65535')
    expect(bad([...flags, '--port', '70000'])).toBe('--port is 0 to 65535')
    expect(bad([...flags, '--port=-1'])).toBe('--port is 0 to 65535')
    expect(bad([...flags, '--nope'])).toMatch(/nope/)
  })
})

describe('runBridge: the bridge as a process', () => {
  it('a bad flag exits 2 with the usage; --help exits 0 with it; a missing key exits 1', async () => {
    const io = lines()
    const stopped = deferred()
    expect(await runBridge(['--nope'], io, { env: {}, stopped: stopped.promise })).toBe(2)
    expect(io.errs).toEqual([expect.stringMatching(/^a2a-bridge: /), USAGE])
    const help = lines()
    expect(await runBridge(['--help'], help, { env: {}, stopped: stopped.promise })).toBe(0)
    expect([help.outs, help.errs]).toEqual([[], [USAGE]])
    const nobody = lines()
    const argv = ['--as', 'nobody', '--relay', RELAY, '--agent', AGENT, '--dir', home]
    expect(await runBridge(argv, nobody, { env: {}, stopped: stopped.promise })).toBe(1)
    expect(nobody.errs).toEqual([expect.stringMatching(/^a2a-bridge: /)])
    expect(nobody.outs).toEqual([])
  })

  it('listens, prints one line, serves its loopback card path, reports edge errors, and stops with exit 0', async () => {
    const io = lines()
    const stopped = deferred()
    // A relay client whose subscribe fails at once: the edge reports it through onError.
    const relay: RelayClient = {
      ...createRelayClient(),
      subscribe: () => {
        throw new Error('no relay here')
      },
    }
    const running = runBridge([...flags, '--port', '0'], io, { env: {}, stopped: stopped.promise, relay })
    await until(() => io.outs.length > 0 && io.errs.includes('a2a-bridge: no relay here'))
    const [line] = io.outs
    expect(line).toMatch(new RegExp(`^a2a-bridge http://127\\.0\\.0\\.1:\\d+ as ${keys.signing.address}$`))
    expect(io.errs).toContain('a2a-bridge: no relay here')
    const url = (line as string).split(' ')[1] as string
    // The agent's record is not at the relay that is not there: the card path answers 502 resolve-failed.
    const card = await fetch(`${url}/a2a/${AGENT}/.well-known/agent-card.json`)
    expect(card.status).toBe(502)
    stopped.resolve()
    expect(await running).toBe(0)
  })

  it('a port already taken exits 1, and the edge is stopped and the store closed', async () => {
    const taken = createServer()
    await new Promise<void>((r) => taken.listen(0, '127.0.0.1', r))
    const { port } = taken.address() as AddressInfo
    try {
      const io = lines()
      const stopped = deferred()
      const argv = [...flags, '--port', String(port)]
      expect(await runBridge(argv, io, { env: {}, stopped: stopped.promise })).toBe(1)
      expect(io.errs.at(-1)).toMatch(/EADDRINUSE/)
      // The store was closed: the same identity opens again.
      const again = lines()
      const done = deferred()
      const next = runBridge([...flags, '--port', '0'], again, { env: {}, stopped: done.promise })
      await until(() => again.outs.length > 0)
      done.resolve()
      expect(await next).toBe(0)
    } finally {
      await new Promise<void>((r) => taken.close(() => r()))
    }
  })

  it("names the machine's telemetry switch once it listens, shows the notice to the machine's first process only, and counts its start while on", async () => {
    const own = mkdtempSync(join(tmpdir(), 'bag-a2a-telemetry-'))
    try {
      new FsKeyStore(join(own, 'keys')).save('me', keys)
      const argv = ['--as', 'me', '--relay', RELAY, '--agent', AGENT, '--dir', own, '--port', '0']
      // The machine's directory is the test's (HOME), never the real one.
      const HOME = join(own, 'machine')
      const once = async (env: NodeJS.ProcessEnv): Promise<string[]> => {
        const io = lines()
        const stopped = deferred()
        const running = runBridge(argv, io, { env, stopped: stopped.promise })
        await until(() => io.outs.length > 0)
        stopped.resolve()
        expect(await running).toBe(0)
        return io.errs.filter((l) => l.includes('telemetry'))
      }
      // Every day's cells of the machine's store, as one map.
      const cells = () => new Map([...readTelemetrySpool(join(HOME, '.bag')).values()].flatMap((m) => [...m]))
      const off = 'a2a-bridge: telemetry off (no-file); the bridge sends no report'
      expect(await once({ HOME })).toEqual([off, TELEMETRY_NOTICE])
      expect(await once({ HOME })).toEqual([off])
      // Without HOME there is no machine directory: off, and no notice.
      expect(await once({})).toEqual([off])
      setTelemetry(join(HOME, '.bag'), 'on', systemRng)
      expect(await once({ HOME })).toEqual(['a2a-bridge: telemetry on (file); the bridge sends no report'])
      // While on, its start is counted, and written at its stop; no request reached it.
      expect(cells().get('bridge_starts ok')).toBe(1)
      expect([...cells().keys()].filter((k) => k.startsWith('bridge_requests '))).toEqual([])
      expect(await once({ HOME, CI: 'true' })).toEqual([
        'a2a-bridge: telemetry off (CI); the bridge sends no report',
      ])
      expect(cells().get('bridge_starts ok')).toBe(1)
    } finally {
      rmSync(own, { recursive: true, force: true })
    }
  })
})
