import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { codingEvaluator } from '@usebag/core'
import { FsAuditSink, HomeCustody } from '@usebag/edge'
import { Agent, AgentAudit, AgentServer, type SessionNameOptions } from '@usebag/edge/agent'
import { parseConfig } from '../../src/config.ts'
import { startServer } from '../../src/server.ts'
import type { Outcome, TestServer } from './fixtures.ts'
import {
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
} from './ports.ts'
import { MemoryRelay } from './relay.ts'

// --session servers under one agent of the home: jane, an agent identity, whose agent listens on
// <home>/agent.sock in this process. Its terminal keeps the lines it prints and answers each prompt with the next
// line a test types (`type`). Bob is a self-rooted peer on the same memory relay.

export const CAVEAT = 'type=chat.*'

export interface AgentHome {
  readonly tmp: ReturnType<typeof tempDir>
  readonly relay: MemoryRelay
  readonly clock: FakeClock
  readonly timers: ManualTimers
  readonly core: Agent
  readonly agent: AgentServer
  /** Every line the agent's terminal printed. */
  readonly printed: string[]
  /** Answers the prompt the agent shows now, or the next one. */
  type(line: string): void
  /** The request codes the agent printed, in order. */
  codes(): string[]
}

export async function agentHome(): Promise<AgentHome> {
  const tmp = tempDir('sessions')
  const relay = new MemoryRelay()
  const clock = new FakeClock()
  const timers = new ManualTimers()
  for (const p of [P.jane, P.bob]) await publishAddress(relay, p)
  saveKeys(tmp.dir, P.bob)
  new HomeCustody(tmp.dir).agent.create('jane', P.jane.keys)
  const core = new Agent({
    principal: P.jane.address,
    clock,
    rng: seededRng('agent'),
    audit: new AgentAudit(new FsAuditSink(join(tmp.dir, 'agent-audit.jsonl')), clock),
    evaluators: [codingEvaluator],
  })
  const printed: string[] = []
  const typed: string[] = []
  let answer: ((line: string) => void) | null = null
  const agent = new AgentServer({
    agent: core,
    clock,
    home: tmp.dir,
    terminal: {
      print: (line) => printed.push(line),
      ask: () =>
        new Promise<string>((resolve) => {
          const next = typed.shift()
          if (next === undefined) answer = resolve
          else resolve(next)
        }),
    },
    records: new Map(),
    ended: () => {},
    timers: { set: () => 1, clear: () => {} },
    signals: { on: () => 0, off: () => 0 },
  })
  await agent.listen()
  return {
    tmp,
    relay,
    clock,
    timers,
    core,
    agent,
    printed,
    type(line) {
      const a = answer
      answer = null
      if (a === null) typed.push(line)
      else a(line)
    },
    codes: () => printed.filter((l) => l.startsWith('request ')).map((l) => l.slice('request '.length)),
  }
}

/** A server under `--session <name> --principal jane`, its tools on an SDK client in memory; it may still wait. */
export async function sessionServer(
  h: AgentHome,
  name: string,
  pid: number,
  ...more: string[]
): Promise<TestServer> {
  return sessionServerOf(h, name, pid, undefined, ...more)
}

/** As sessionServer, with the resolver's process readers (a fake tree) for `--session auto`. */
export async function sessionServerOf(
  h: AgentHome,
  name: string,
  pid: number,
  names: SessionNameOptions | undefined,
  ...more: string[]
): Promise<TestServer> {
  const args = ['--session', name, '--principal', 'jane', '--grant-caveat', CAVEAT, '--dir', h.tmp.dir]
  const config = parseConfig([...args, '--relay', RELAY, '--trust-root', P.bob.address, ...more], {})
  if (config === 'help') throw new Error('unexpected help')
  const log = new MemoryLog()
  const running = await startServer(config, {
    clock: h.clock,
    rng: seededRng(name),
    relay: h.relay,
    records: fakeRecords(new Map()),
    timers: h.timers,
    pid,
    alive: () => true,
    log,
    resubscribeDelayMs: () => 0,
    ...(names === undefined ? {} : { names }),
  })
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  await running.mcp.connect(serverSide)
  const client = new Client({ name: 'mcp-test', version: '0.0.0' })
  await client.connect(clientSide)
  return {
    running,
    client,
    log,
    async call(tool, args = {}): Promise<Outcome> {
      const result = (await client.callTool({ name: tool, arguments: args })) as CallToolResult
      const value = JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>
      return { isError: result.isError === true, value, result }
    },
    async close() {
      await client.close()
      await running.stop()
    },
  }
}

/** Polls an async test every 5 ms until it holds; throws naming `what` after `ms`. */
export async function eventually(what: string, test: () => Promise<boolean>, ms = 5000): Promise<void> {
  const end = Date.now() + ms
  while (!(await test())) {
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** A session server that has its grant: started, the agent's prompt answered y, and open. */
export async function grantedSession(h: AgentHome, name: string, pid: number): Promise<TestServer> {
  const s = await sessionServer(h, name, pid)
  h.type('y')
  await s.running.ready
  return s
}

/** A fake process tree for `--session auto`: pid 600 is a server under the main claude 200, started at 1,793,000,000. */
export const TREE: SessionNameOptions = {
  pid: 600,
  info: (p) =>
    ({
      200: { ppid: 100, command: '/Users/u/.local/bin/claude' },
      600: { ppid: 200, command: 'node packages/mcp/src/main.ts --session auto' },
      900: { ppid: 100, command: 'node packages/mcp/src/main.ts --session auto' },
    })[p] ?? null,
  startOf: (p) => (p === 200 ? 1_793_000_000 : null),
}
