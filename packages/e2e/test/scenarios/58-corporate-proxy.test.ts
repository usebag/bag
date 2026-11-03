import { execFile } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { type AddressInfo, connect } from 'node:net'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { describe, expect, it, onTestFinished } from 'vitest'
import { CLI_MAIN, cliProcess, REPO, sleep, until, withSpawnedRelays, world } from '../harness.ts'

// Scenario 58: a corporate proxy (job #3). Real CLI and MCP server processes with HTTP_PROXY set and no
// NODE_USE_ENV_PROXY, a real relay, and a CONNECT proxy on loopback that tunnels what it is asked to and records it.
// Each process runs itself again once with NODE_USE_ENV_PROXY=1 (the edge's proxy.ts), so its fetch and its WebSocket
// go through the proxy, and under NO_PROXY they do not. The MCP server's stdio and its lock file hold across the re-run,
// status shows the proxy without its password, and telemetry goes the same way.

const MCP_MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')

/** A CONNECT proxy that tunnels every request it gets, recording each target, and a fake telemetry endpoint. */
async function proxyAndEndpoint() {
  const targets: string[] = []
  const proxy = createServer((_req, res) => res.writeHead(405).end())
  proxy.on('connect', (req, socket, head) => {
    targets.push(req.url ?? '')
    const [host = '', port = ''] = (req.url ?? '').split(':')
    const up = connect(Number(port), host, () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      up.write(head)
      up.pipe(socket)
      socket.pipe(up)
    })
    up.on('error', () => socket.destroy())
    socket.on('error', () => up.destroy())
  })
  const bodies: string[] = []
  const endpoint = createServer((req, res) => {
    let body = ''
    req.on('data', (c: Buffer) => {
      body += c.toString('utf8')
    })
    req.on('end', () => {
      bodies.push(body)
      res.writeHead(204).end()
    })
  })
  for (const s of [proxy, endpoint]) await new Promise<void>((r) => s.listen(0, '127.0.0.1', r))
  onTestFinished(() => {
    for (const s of [proxy, endpoint]) {
      s.closeAllConnections()
      s.close()
    }
  })
  const at = (s: typeof proxy): string => `http://127.0.0.1:${(s.address() as AddressInfo).port}`
  return { targets, bodies, proxy: at(proxy), endpoint: at(endpoint) }
}

/** This process's environment with every proxy setting gone, then `more`. */
function envWith(more: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  for (const k of Object.keys(env)) {
    if (/^(https?_proxy|no_proxy|node_use_env_proxy|ac_proxy_reexec)$/i.test(k)) delete env[k]
  }
  return { ...env, ...more }
}

function cliIn(
  env: NodeJS.ProcessEnv,
  ...args: string[]
): Promise<{ code: number; out: string[]; err: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI_MAIN, ...args],
      { cwd: REPO, env, timeout: 30_000 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
        resolve({ code, out: stdout.split('\n').filter((l) => l !== ''), err: stderr })
      },
    )
  })
}

describe('e2e scenario 58: behind a corporate proxy', () => {
  it('(58) the CLI and the MCP server send through HTTP_PROXY by CONNECT and bypass it under NO_PROXY; stdio, the lock and status hold; telemetry goes the same way', async () => {
    const w = await withSpawnedRelays(() => world('corporate-proxy'))
    const R = w.url
    const relayHost = new URL(R).host
    const home = join(w.dir, 'alice-home')
    expect((await cliProcess(['keygen', 'alice', '--dir', home])).code).toBe(0)
    expect((await cliProcess(['keys', 'rotate', 'alice', '--relay', R, '--dir', home])).code).toBe(0)
    const net = await proxyAndEndpoint()
    const viaProxy = envWith({ DO_NOT_TRACK: '1', HTTP_PROXY: net.proxy, HTTPS_PROXY: net.proxy })

    // The CLI through the proxy: the relay is reached by a CONNECT to it.
    expect((await cliIn(viaProxy, 'health', R)).out).toEqual(['ok'])
    expect(net.targets).toContain(relayHost)
    // NO_PROXY names the relay: no CONNECT.
    net.targets.length = 0
    expect((await cliIn({ ...viaProxy, NO_PROXY: '127.0.0.1' }, 'health', R)).out).toEqual(['ok'])
    expect(net.targets).toEqual([])

    // status names the proxy without its password, and says Node sends through it.
    const secret = envWith({
      DO_NOT_TRACK: '1',
      HTTP_PROXY: net.proxy.replace('http://', 'http://jane:s3cret@'),
    })
    const status = await cliIn(secret, 'status', '--as', 'alice', '--dir', home)
    expect(status.out[1]).toBe(`network proxy https=none http=${net.proxy} no_proxy=none active=yes`)
    expect(`${status.out.join('\n')}${status.err}`).not.toMatch(/jane|s3cret/)

    // The MCP server through the proxy: its stdio and its lock survive the re-run, and its subscription goes by CONNECT.
    net.targets.length = 0
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [MCP_MAIN, '--as', 'alice', '--dir', home, '--relay', R],
      cwd: REPO,
      env: viaProxy as Record<string, string>,
      stderr: 'ignore',
    })
    const client = new Client({ name: 'e2e-proxy', version: '0.0.0' })
    await client.connect(transport)
    onTestFinished(() => client.close())
    const r = await client.callTool({ name: 'status', arguments: {} }, undefined, { timeout: 30_000 })
    const value = JSON.parse((r.content as { text: string }[])[0]?.text ?? '{}') as { network?: unknown }
    expect(value.network).toEqual({ https: net.proxy, http: net.proxy, no_proxy: null, active: true })
    const lock = JSON.parse(readFileSync(join(home, 'state', 'alice', 'mcp.lock'), 'utf8')) as { pid: number }
    expect(lock.pid).toBe(transport.pid)
    await until('the subscription went through the proxy', () => net.targets.includes(relayHost))
    await client.close()
    await sleep(1_000)

    // Telemetry takes the same path: a due day goes to the (loopback) endpoint by a CONNECT through the proxy.
    const seconds = Math.floor(Date.now() / 1000) % 86_400
    const due = seconds >= 3_960 && seconds < 86_340
    const machine = join(w.dir, 'machine')
    const tel = envWith({ HOME: machine, AC_TELEMETRY_URL: net.endpoint, HTTP_PROXY: net.proxy })
    for (const name of ['DO_NOT_TRACK', 'CI', 'AC_TELEMETRY', 'AC_HOME']) delete tel[name]
    expect((await cliIn(tel, 'telemetry', 'on')).code).toBe(0)
    const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10)
    mkdirSync(join(machine, '.bag'), { recursive: true })
    const line = JSON.stringify({ v: 1, day: yesterday, counts: { pairing: { ok: 1 } } })
    writeFileSync(join(machine, '.bag', 'telemetry-counts.jsonl'), `${line}\n`, { flag: 'a' })
    net.targets.length = 0
    expect((await cliIn(tel, 'telemetry', 'send')).code).toBe(0)
    expect(net.bodies.length).toBe(due ? 1 : 0)
    expect(net.targets).toEqual(due ? [new URL(net.endpoint).host] : [])
  }, 120_000)
})
