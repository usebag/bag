import { mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import {
  countTelemetry,
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  HomeCustody,
  machineTelemetryNotice,
  programName,
  type RelayClient,
  SqliteStore,
  startTelemetry,
  startTelemetrySender,
  stopTelemetry,
  systemClock,
  systemRng,
  telemetryCode,
  telemetryDir,
  telemetryState,
  trackPairs,
} from '@usebag/edge'
import { A2A_TYPE } from './binding.ts'
import { A2aBridge, DEFAULT_PORT, isLoopbackHost, LOOPBACK_ONLY } from './bridge.ts'

// The bridge as a process: node packages/a2a/src/main.ts --as <key name> --relay <url> --agent <address> [options].
// It composes the edge as the CLI and the MCP server do (packages/mcp/src/open.ts): the home's custody for the key,
// the SQLite store and the audit log at <home>/state/<name>/ (the store's writer lock refuses a second process on
// the same identity), the relay client and the record source; then it starts the edge and the bridge, prints one
// line, and runs until it is stopped. From source the entry is the file; the published package's bin is bag-a2a
// (packages/bag).

export const USAGE = `bag A2A bridge (pre-release): A2A JSON-RPC on 127.0.0.1, sealed to our agents

usage: ${programName('bag-a2a', 'packages/a2a/src/main.ts')} --as <key name> --relay <url>... --agent <address>... [options]

  --as <name>             the key the bridge signs with (<home>/keys/<name>.json or a keychain identity)
  --relay <url>           a relay to subscribe to and look records up at; repeatable, at least one
  --agent <address>       an agent the bridge may call, and whose replies it accepts; repeatable, at least one
  --port <n>              the port (default ${DEFAULT_PORT}, the one the cards name; 0 takes a free one)
  --host <address>        the loopback address to listen on (default 127.0.0.1; 127.0.0.0/8, ::1 or localhost
                          only: the bridge has no caller authentication, so it never listens on a network address)
  --dir <home>            the home (default $AC_HOME, else ~/.bag); state in <home>/state/<name>/
  --help                  this text, on stderr

stdout carries one line once the bridge listens, "a2a-bridge <url> as <address>"; SIGINT or SIGTERM stops it
(exit 0). A bad flag exits 2; a key, a state or a port that cannot be opened exits 1. Once it listens, stderr names
the machine's telemetry switch, one for every home, and the notice once per machine. While it is on, the bridge counts
its start and its requests (method and outcome) into the machine's store, and tries hourly to send each finished UTC
day's report once, from 01:05 UTC, to telemetry.bag.dev; the exact report is the telemetry preview, in the bag command
line.`

export interface BridgeConfig {
  readonly as: string
  readonly home: string
  readonly relays: readonly string[]
  readonly agents: readonly string[]
  readonly host: string
  readonly port: number
}

const ADDRESS = /^ed25519:[0-9a-f]{64}$/

/** The configuration of the flags and the environment; throws an Error whose message names the bad flag. */
export function parseBridgeArgs(argv: readonly string[], env: NodeJS.ProcessEnv): BridgeConfig | 'help' {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      as: { type: 'string' },
      relay: { type: 'string', multiple: true },
      agent: { type: 'string', multiple: true },
      port: { type: 'string' },
      host: { type: 'string' },
      dir: { type: 'string' },
      help: { type: 'boolean' },
    },
    strict: true,
    allowPositionals: false,
  })
  if (values.help === true) return 'help'
  if (values.as === undefined) throw new Error('--as <key name> is required')
  const relays = values.relay ?? []
  if (relays.length === 0) throw new Error('--relay <url> is required')
  const agents = values.agent ?? []
  if (agents.length === 0 || !agents.every((a) => ADDRESS.test(a))) {
    throw new Error('--agent <address> is required, each ed25519:<64 hex>')
  }
  const port = Number(values.port ?? DEFAULT_PORT)
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error('--port is 0 to 65535')
  const host = values.host ?? '127.0.0.1'
  if (!isLoopbackHost(host)) throw new Error(LOOPBACK_ONLY)
  return {
    as: values.as,
    home: resolve(values.dir ?? env.AC_HOME ?? join(homedir(), '.bag')),
    relays,
    agents,
    host,
    port,
  }
}

export interface RunIo {
  readonly out: (line: string) => void
  readonly err: (line: string) => void
}

export interface RunDeps {
  readonly env: NodeJS.ProcessEnv
  /** Resolves when the process is told to stop (SIGINT or SIGTERM in main.ts). */
  readonly stopped: Promise<unknown>
  /** The relay client (default the edge's, over HTTP and WebSocket). */
  readonly relay?: RelayClient
  /**
   * The fetch the machine's telemetry report goes out with, hourly while it is on (the edge's telemetry-send.ts);
   * main.ts passes the global one. Without it the bridge sends none: the tests pass none.
   */
  readonly fetch?: typeof fetch
}

/** Runs the bridge until `stopped`; the exit code. */
export async function runBridge(argv: readonly string[], io: RunIo, deps: RunDeps): Promise<number> {
  let config: BridgeConfig | 'help'
  try {
    config = parseBridgeArgs(argv, deps.env)
  } catch (e) {
    io.err(`a2a-bridge: ${(e as Error).message}`)
    io.err(USAGE)
    return 2
  }
  if (config === 'help') {
    io.err(USAGE)
    return 0
  }
  let store: SqliteStore | null = null
  let edge: Edge | null = null
  // While telemetry is on the process counts into the machine's spool (the edge's tally), from here to the finally.
  const counting = startTelemetry(deps.env, systemClock)
  let started = false
  let untrack = (): void => {}
  try {
    const keys = new HomeCustody(config.home).keys(config.as)
    const stateDir = join(config.home, 'state', config.as)
    mkdirSync(stateDir, { recursive: true, mode: 0o700 })
    store = new SqliteStore(join(stateDir, 'edge.sqlite'))
    // While telemetry is on: this identity's pairs snapshot, now and before each try of the sender.
    untrack = trackPairs(deps.env, systemClock, config.home, config.as, store)
    const client = deps.relay ?? createRelayClient()
    edge = new Edge({
      keys,
      store,
      relays: { client, urls: config.relays },
      records: createRecordSource(client),
      policy: { roots: config.agents.map((address) => ({ address })), types: [A2A_TYPE], evaluators: [] },
      clock: systemClock,
      rng: systemRng,
      audit: new FsAuditSink(join(stateDir, 'audit.jsonl')),
      onError: (e) => io.err(`a2a-bridge: ${(e as Error).message}`),
      unreachableReason: true,
    })
    await edge.start()
    const { host, port, agents } = config
    const count = (method: string, outcome: string) => countTelemetry('bridge_requests', [method, outcome])
    const bridge = await A2aBridge.start({ edge, host, port, agents, count })
    started = true
    countTelemetry('bridge_starts', ['ok'])
    io.out(`a2a-bridge ${bridge.url} as ${keys.signing.address}`)
    // The machine's telemetry switch: its state, and the notice to the machine's first process that asks.
    const dir = telemetryDir(deps.env)
    const t = dir === null ? { on: false, reason: 'no-file' } : telemetryState(deps.env, dir)
    io.err(`a2a-bridge: telemetry ${t.on ? 'on' : 'off'} (${t.reason}); while on, each day is reported once`)
    const notice = machineTelemetryNotice(deps.env)
    if (notice !== null) io.err(notice)
    // Each finished day's report, once, tried now and hourly while it is on; never awaited.
    const stopSending =
      deps.fetch === undefined ? null : startTelemetrySender(deps.env, systemClock, { fetch: deps.fetch })
    await deps.stopped
    stopSending?.()
    await bridge.close()
    return 0
  } catch (e) {
    if (!started) countTelemetry('bridge_starts', [telemetryCode(e)])
    io.err(`a2a-bridge: ${(e as Error).message}`)
    return 1
  } finally {
    untrack()
    await edge?.stop()
    store?.close()
    if (counting) stopTelemetry()
  }
}
