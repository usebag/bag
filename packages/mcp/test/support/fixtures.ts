import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import type { Rng } from '@usebag/edge'
import type { EnterprisePorts } from '@usebag/enterprise-client'
import { type MockInstance, vi } from 'vitest'
import type { RunCommand } from '../../src/chain.ts'
import { parseConfig } from '../../src/config.ts'
import { type Running, startServer } from '../../src/server.ts'
import {
  type FakeClock,
  type FakeNaming,
  fakeRecords,
  type ManualTimers,
  MemoryLog,
  RELAY,
  seededRng,
} from './ports.ts'
import type { MemoryRelay } from './relay.ts'

// The MCP tests' fixtures: the ports and parties of ports.ts, and a server connected to an SDK client through the
// SDK's InMemoryTransport pair.

export * from './ports.ts'

export interface Outcome {
  readonly isError: boolean
  /** The JSON of the result's text, or {text} when the text is not JSON (the SDK's own errors). */
  readonly value: Record<string, unknown>
  readonly result: CallToolResult
}

export interface TestServer {
  readonly running: Running
  readonly client: Client
  readonly log: MemoryLog
  call(tool: string, args?: Record<string, unknown>, signal?: AbortSignal): Promise<Outcome>
  close(): Promise<void>
}

export interface ServerOptions {
  readonly home: string
  readonly name: string
  readonly relay: MemoryRelay
  readonly clock: FakeClock
  readonly timers: ManualTimers
  readonly args?: readonly string[]
  readonly domains?: Map<string, Uint8Array>
  /** TXT and handle records, for handle tests. */
  readonly naming?: FakeNaming
  readonly pid?: number
  /** Which pids are live, for a lock another server holds (default none). */
  readonly alive?: (pid: number) => boolean
  /** How --chain-cmd runs (default: the real /bin/sh). */
  readonly run?: RunCommand
  readonly env?: Readonly<Record<string, string | undefined>>
  /** The edge's wait before resubscription attempt n (default none: no test waits on the edge's backoff). */
  readonly resubscribeDelayMs?: (attempt: number) => number
  /** The server's random source (default seeded by the name). */
  readonly rng?: Rng
  /** The enterprise tools' network, wait and relays (default the process's). */
  readonly enterprise?: Partial<EnterprisePorts>
}

/** Starts a server for `name` in `home` on the memory relay, and connects an SDK client to it in memory. */
export async function testServer(o: ServerOptions): Promise<TestServer> {
  const config = parseConfig(['--as', o.name, '--dir', o.home, '--relay', RELAY, ...(o.args ?? [])], {})
  if (config === 'help') throw new Error('unexpected help')
  const log = new MemoryLog()
  const running = await startServer(config, {
    clock: o.clock,
    rng: o.rng ?? seededRng(o.name),
    relay: o.relay,
    records: fakeRecords(o.domains ?? new Map(), o.naming),
    timers: o.timers,
    pid: o.pid ?? 4242,
    alive: o.alive ?? (() => false),
    log,
    // The edge's resubscription waits (250 ms doubling) would put real time into the tests; none unless asked.
    resubscribeDelayMs: o.resubscribeDelayMs ?? (() => 0),
    ...(o.run === undefined ? {} : { run: o.run }),
    ...(o.env === undefined ? {} : { env: o.env }),
    ...(o.enterprise === undefined ? {} : { enterprise: o.enterprise }),
  })
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  await running.mcp.connect(serverSide)
  const client = new Client({ name: 'mcp-test', version: '0.0.0' })
  await client.connect(clientSide)
  return {
    running,
    client,
    log,
    async call(tool, args = {}, signal) {
      const result = (await client.callTool(
        { name: tool, arguments: args },
        undefined,
        signal === undefined ? {} : { signal },
      )) as CallToolResult
      const text = (result.content[0] as { text: string }).text
      let value: Record<string, unknown>
      try {
        value = JSON.parse(text) as Record<string, unknown>
      } catch {
        value = { text }
      }
      return { isError: result.isError === true, value, result }
    },
    async close() {
      await client.close()
      await running.stop()
    },
  }
}

/** Polls `test` every 5 ms until it holds; throws naming `what` after `ms`. */
export async function until(what: string, test: () => boolean, ms = 5000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

/**
 * Watches process.stdout.write while in-process servers run. `start()` before a test, `check()`
 * after it: it fails if anything was written (an in-process server speaks MCP on its own stream, never on stdout).
 */
export function watchStdout(): { start(): void; check(): void } {
  let spy: MockInstance | null = null
  return {
    start() {
      spy = vi.spyOn(process.stdout, 'write')
    },
    check() {
      const calls = spy?.mock.calls.length ?? 0
      spy?.mockRestore()
      spy = null
      if (calls > 0) throw new Error(`process.stdout.write was called ${calls} times while a server ran`)
    },
  }
}
