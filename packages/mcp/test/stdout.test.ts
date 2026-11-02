import { type ChildProcess, spawn } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { P, saveKeys, tempDir } from './support/fixtures.ts'
import { frames, StreamClientTransport } from './support/streams.ts'

// The server as a child process, `node packages/mcp/src/main.ts`, through a scripted session that
// calls every tool, makes them fail, breaks a schema and ends stdin. Every byte on its stdout must belong to a
// newline-terminated JSON-RPC 2.0 message; its stderr holds JSON lines (and Node's SQLite warning) and no key.

const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')
// Port 1 on loopback refuses every connection: each tool that needs the relay fails, and the server stays up.
const DOWN = 'http://127.0.0.1:1'
const WARNING = /ExperimentalWarning: SQLite is an experimental feature|node --trace-warnings/

let tmp: ReturnType<typeof tempDir>

beforeEach(() => {
  tmp = tempDir('stdout')
  saveKeys(tmp.dir, P.alice)
})

afterEach(() => {
  tmp.cleanup()
})

interface Child {
  readonly child: ChildProcess
  readonly out: Buffer[]
  readonly err: Buffer[]
  readonly exit: Promise<number | null>
}

function start(args: readonly string[]): Child {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.AC_HOME
  // The server counts into the machine's telemetry store (HOME/.bag) while it is on: off here, so no run touches it.
  env.DO_NOT_TRACK = '1'
  const child = spawn(process.execPath, [MAIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'], env })
  const out: Buffer[] = []
  const err: Buffer[] = []
  child.stdout?.on('data', (c: Buffer) => out.push(c))
  child.stderr?.on('data', (c: Buffer) => err.push(c))
  // 'close', not 'exit': Node may emit 'exit' before the last stderr data has arrived.
  const exit = new Promise<number | null>((r) => child.once('close', (code) => r(code)))
  return { child, out, err, exit }
}

/** stderr's lines without Node's warning: each must be a JSON log line. */
function logLines(c: Child): Record<string, unknown>[] {
  return Buffer.concat(c.err)
    .toString('utf8')
    .split('\n')
    .filter((l) => l !== '' && !WARNING.test(l))
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

describe('stdout carries MCP frames and nothing else', () => {
  it('a child server through a scripted session: every tool, their errors, a schema error, and the end of stdin', async () => {
    const c = start([
      '--as',
      'alice',
      '--dir',
      tmp.dir,
      '--relay',
      DOWN,
      '--trust-root',
      P.bob.address,
      '--allow-delegate',
    ])
    const client = new Client({ name: 'stdout-check', version: '0.0.0' })
    await client.connect(new StreamClientTransport(c.child.stdin as never, c.child.stdout as never))
    const calls: [string, Record<string, unknown>][] = [
      ['status', {}],
      ['inbox', {}],
      ['wait', { timeout_s: 0.05 }],
      ['delegate', { to: P.bob.address, caveats: ['type=chat.*'], exp: '+60' }],
      ['send', { to: [P.bob.address], type: 'chat.v1', body: { text: 'hi' } }],
      ['ask', { to: P.bob.address, body: 'q', timeout_s: 1 }],
      ['handoff', { to: P.bob.address, threads: ['a'.repeat(64)] }],
      ['send', { to: [P.bob.address] }],
      ['delegate', { to: 'nobody', caveats: ['repo=x'], exp: '+1' }],
      ['lookup', { address: P.bob.address }],
    ]
    const results = []
    expect((await client.listTools()).tools).toHaveLength(11)
    for (const [name, args] of calls) results.push(await client.callTool({ name, arguments: args }))
    expect(results.map((r) => r.isError === true)).toEqual([
      false,
      false,
      false,
      false,
      false,
      false,
      true,
      true,
      true,
      false,
    ])
    // The relay gives no answer: send and ask are kept waiting, handoff fails resolve-failed as before.
    expect(results.slice(4, 6).map((r) => (r.structuredContent as { waiting: boolean }).waiting)).toEqual([
      true,
      true,
    ])
    const [handoff, looked] = [results[6], results[9]] as { structuredContent: Record<string, unknown> }[]
    expect(handoff?.structuredContent.error).toBe('resolve-failed')
    expect(looked?.structuredContent.results).toEqual([
      expect.objectContaining({ outcome: 'error', detail: 'unreachable' }),
      expect.objectContaining({ outcome: 'error', detail: 'unreachable' }),
    ])
    c.child.stdin?.end()
    expect(await c.exit).toBe(0)
    const stdout = Buffer.concat(c.out)
    const checked = frames(stdout)
    expect(checked.bad).toEqual([])
    // The initialize answer, tools/list and one answer per call.
    expect(checked.lines).toBe(2 + calls.length)
    const logs = logLines(c)
    // The schema error is the SDK's own answer: it never reaches a tool, so it writes no tool line.
    expect(logs.map((l) => l.event).filter((e) => e !== 'subscription')).toEqual([
      'start',
      ...calls.slice(1).map(() => 'tool'),
      'stop',
    ])
    const seen = `${stdout.toString('utf8')}\n${Buffer.concat(c.err).toString('utf8')}`
    expect(P.alice.secrets.every((s) => !seen.includes(s))).toBe(true)
  })

  it('a refused start writes nothing to stdout: exit 2 and one JSON line on stderr', async () => {
    const c = start(['--relay', DOWN])
    expect(await c.exit).toBe(2)
    expect(Buffer.concat(c.out).length).toBe(0)
    expect(logLines(c)).toEqual([expect.objectContaining({ level: 'error', event: 'start', code: 'usage' })])
  })
})
