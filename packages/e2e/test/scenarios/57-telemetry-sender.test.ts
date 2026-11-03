import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { describe, expect, it, onTestFinished } from 'vitest'
import { CLI_MAIN, cliProcess, REPO, sleep, until, withSpawnedRelays, world } from '../harness.ts'

// Scenario 57: the client telemetry sender (the W6 design note), with real CLI, MCP server and bridge processes and a
// fake endpoint on 127.0.0.1 that every process reaches through AC_TELEMETRY_URL (loopback only). Each process gets a
// machine of its own (HOME), whose spool is seeded by hand with a finished day. Off, nothing reaches the endpoint from
// any of them. On, the day goes once, exactly as `telemetry preview --date` prints it: from the CLI's detached sender
// after a command line, and from the MCP server and the bridge at their start. Before 01:05 UTC no day is due, so a
// run then asserts that nothing is sent at all.

const MCP_MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
const BRIDGE_MAIN = join(REPO, 'packages', 'a2a', 'src', 'main.ts')

interface Request {
  readonly method: string
  readonly url: string
  readonly headers: IncomingHttpHeaders
  readonly body: string
}

/** The fake endpoint: every request it took, each answered 204. */
async function endpoint(): Promise<{ url: string; requests: Request[] }> {
  const requests: Request[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body })
      res.writeHead(204).end()
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  onTestFinished(() => {
    server.closeAllConnections()
    server.close()
  })
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests }
}

/** The UTC date `back` days before now. */
const dateBack = (back: number): string => new Date(Date.now() - back * 86_400_000).toISOString().slice(0, 10)

/** A machine's environment: this process's, its telemetry variables gone, HOME its own, the endpoint the fake. */
function machineEnv(home: string, url: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, AC_TELEMETRY_URL: url }
  for (const name of ['DO_NOT_TRACK', 'CI', 'AC_TELEMETRY', 'AC_HOME']) delete env[name]
  return env
}

/** One CLI process under `env`: its exit code and stdout lines. */
function cliIn(env: NodeJS.ProcessEnv, ...args: string[]): Promise<{ code: number; out: string[] }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI_MAIN, ...args], { cwd: REPO, env, timeout: 30_000 }, (error, stdout) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
      resolve({ code, out: stdout.split('\n').filter((l) => l !== '') })
    })
  })
}

/** Seeds the machine's spool by hand with one pairing count on `day`. */
function seed(home: string, day: string): void {
  mkdirSync(join(home, '.bag'), { recursive: true, mode: 0o700 })
  const line = JSON.stringify({ v: 1, day, counts: { pairing: { ok: 1 } } })
  writeFileSync(join(home, '.bag', 'telemetry-counts.jsonl'), `${line}\n`, { flag: 'a', mode: 0o600 })
}

/** An MCP server process under `env`, driven by the SDK's client as a host runs it, until the client closes. */
async function mcpServer(env: NodeJS.ProcessEnv, args: readonly string[]): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [MCP_MAIN, ...args],
    cwd: REPO,
    env: env as Record<string, string>,
    stderr: 'ignore',
  })
  const client = new Client({ name: 'e2e-telemetry', version: '0.0.0' })
  await client.connect(transport)
  onTestFinished(() => client.close())
  return client
}

/** A bridge process under `env`, once it prints its line; `stop` ends it with SIGTERM and waits for its exit. */
async function bridge(env: NodeJS.ProcessEnv, args: readonly string[]): Promise<{ stop(): Promise<void> }> {
  const child: ChildProcess = spawn(process.execPath, [BRIDGE_MAIN, ...args, '--port', '0'], {
    cwd: REPO,
    env,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()))
  onTestFinished(() => {
    child.kill('SIGTERM')
  })
  let out = ''
  child.stdout?.on('data', (c: Buffer) => {
    out += c.toString('utf8')
  })
  await until('the bridge listens', () => out.startsWith('a2a-bridge http://127.0.0.1:'))
  return {
    stop: async () => {
      child.kill('SIGTERM')
      await exited
    },
  }
}

/** Closes an MCP server's client, then waits for the process to let go of the identity's store. */
async function closed(client: Client): Promise<void> {
  await client.close()
  await sleep(1_500)
}

describe('e2e scenario 57: the client telemetry sender', () => {
  it('(57) off, nothing reaches the endpoint from the CLI, the MCP server or the bridge; on, a finished day goes once, exactly as previewed, from each', async () => {
    const seconds = Math.floor(Date.now() / 1000) % 86_400
    // From 01:05 UTC a day is due; a run that starts within a minute of either end of that span asserts that none goes.
    const due = seconds >= 3_960 && seconds < 86_340
    const yesterday = dateBack(1)
    const w = await withSpawnedRelays(() => world('telemetry-sender'))
    const R = w.url
    const identity = join(w.dir, 'alice-home')
    expect((await cliProcess(['keygen', 'alice', '--dir', identity])).code).toBe(0)
    const bob = (await cliProcess(['keygen', 'bob', '--dir', join(w.dir, 'bob-home')])).out[0] as string
    expect((await cliProcess(['keys', 'rotate', 'alice', '--relay', R, '--dir', identity])).code).toBe(0)
    const fake = await endpoint()
    const serve = ['--as', 'alice', '--dir', identity, '--relay', R]
    const bridgeArgs = ['--as', 'alice', '--dir', identity, '--relay', R, '--agent', bob]

    // Off: no choice on any of the three machines, each with a finished day in its spool.
    const [cliOff, mcpOff, bridgeOff] = [
      join(w.dir, 'cli-off'),
      join(w.dir, 'mcp-off'),
      join(w.dir, 'bridge-off'),
    ]
    for (const home of [cliOff, mcpOff, bridgeOff]) seed(home, yesterday)
    const offCli = machineEnv(cliOff, fake.url)
    expect((await cliIn(offCli, 'telemetry', 'status')).out[0]).toMatch(/^telemetry off reason=no-file /)
    expect((await cliIn(offCli, 'help')).code).toBe(0)
    expect((await cliIn(offCli, 'telemetry', 'send')).code).toBe(0)
    const offServer = await mcpServer(machineEnv(mcpOff, fake.url), serve)
    await offServer.callTool({ name: 'status', arguments: {} })
    await closed(offServer)
    const offBridge = await bridge(machineEnv(bridgeOff, fake.url), bridgeArgs)
    await sleep(1_000)
    await offBridge.stop()
    expect(fake.requests).toEqual([])

    // On: the CLI's machine. A command line starts the detached sender; a second one starts none.
    const cliOn = join(w.dir, 'cli-on')
    const onCli = machineEnv(cliOn, fake.url)
    expect((await cliIn(onCli, 'telemetry', 'on')).code).toBe(0)
    seed(cliOn, yesterday)
    const previewed = (await cliIn(onCli, 'telemetry', 'preview', '--date', yesterday)).out[0] as string
    expect(JSON.parse(previewed)).toMatchObject({ date: yesterday, pairing: { ok: 1 } })
    expect((await cliIn(onCli, 'help')).code).toBe(0)
    if (due) await until('the CLI sent the day', () => fake.requests.length === 1)
    expect((await cliIn(onCli, 'help')).code).toBe(0)
    await sleep(1_500)
    expect(fake.requests.length).toBe(due ? 1 : 0)

    // On: the MCP server's machine and the bridge's, each sending its day at its start.
    const [mcpOn, bridgeOn] = [join(w.dir, 'mcp-on'), join(w.dir, 'bridge-on')]
    const expected = [previewed]
    for (const home of [mcpOn, bridgeOn]) {
      const env = machineEnv(home, fake.url)
      expect((await cliIn(env, 'telemetry', 'on')).code).toBe(0)
      seed(home, yesterday)
      expected.push((await cliIn(env, 'telemetry', 'preview', '--date', yesterday)).out[0] as string)
    }
    const onServer = await mcpServer(machineEnv(mcpOn, fake.url), serve)
    if (due) await until('the MCP server sent the day', () => fake.requests.length === 2)
    await closed(onServer)
    const onBridge = await bridge(machineEnv(bridgeOn, fake.url), bridgeArgs)
    if (due) await until('the bridge sent the day', () => fake.requests.length === 3)
    await sleep(1_000)
    await onBridge.stop()

    expect(fake.requests.length).toBe(due ? 3 : 0)
    expect(fake.requests.map((r) => [r.method, r.url, r.headers['content-type'], r.body])).toEqual(
      due ? expected.map((body) => ['POST', '/v1/report', 'application/json', body]) : [],
    )
  }, 120_000)
})
