import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { originGet } from '../src/adapters/well-known.ts'
import {
  bypassed,
  proxyFor,
  proxyShown,
  proxyStatus,
  REEXEC_GUARD,
  type ReexecProcess,
  useEnvProxy,
} from '../src/proxy.ts'
import { tempDir } from './support/fixtures.ts'

// A corporate proxy: NO_PROXY read as Node's EnvHttpProxyAgent reads it (the table measured on Node 24.4.1); the proxy
// for a URL; a proxy shown without its user or password; the one re-run with NODE_USE_ENV_PROXY=1, which never loops;
// and the well-known GET's CONNECT tunnel to the guard's checked address, which fails closed when the proxy refuses
// and never asks again by name. A local CONNECT proxy on loopback; nothing leaves the machine.

const tmp = tempDir('proxy')
afterAll(() => tmp.cleanup())

describe('bypassed: NO_PROXY as Node 24.4.1 reads it', () => {
  // Measured with Node's own agent (NODE_USE_ENV_PROXY=1) on 2026-11-03: the hosts each list sends DIRECT.
  const hosts = [
    'example.test',
    'a.example.test',
    'b.a.example.test',
    'xexample.test',
    'localhost',
    '127.0.0.1',
  ]
  const direct = (list: string, port = '80'): string[] => hosts.filter((h) => bypassed(list, h, port))
  it('matches the measured table', () => {
    expect(direct('')).toEqual([])
    expect(direct('*')).toEqual(hosts)
    expect(direct('example.test')).toEqual(['example.test'])
    expect(direct('.example.test')).toEqual(['a.example.test', 'b.a.example.test'])
    expect(direct('*.example.test')).toEqual(['a.example.test', 'b.a.example.test'])
    expect(direct('a.example.test')).toEqual(['a.example.test'])
    expect(direct('localhost,127.0.0.1')).toEqual(['localhost', '127.0.0.1'])
    expect(direct('example.test:80')).toEqual(['example.test'])
    expect(direct('example.test:1')).toEqual([])
    expect(direct(' EXAMPLE.TEST ')).toEqual(['example.test'])
    expect(direct('example.test a.example.test')).toEqual(['example.test', 'a.example.test'])
  })

  it('reads IPv6 addresses bare or bracketed, with a port only in brackets', () => {
    expect(bypassed('::1', '[::1]', '443')).toBe(true)
    expect(bypassed('[::1]:443', '[::1]', '443')).toBe(true)
    expect(bypassed('[::1]:80', '[::1]', '443')).toBe(false)
  })
})

describe('proxyFor and proxyStatus: the proxy of a URL, shown without credentials', () => {
  it('takes HTTPS_PROXY for https and wss, HTTP_PROXY for http and ws, the lowercase name first', () => {
    const env = {
      HTTPS_PROXY: 'http://upper:3128',
      https_proxy: 'http://lower:3128',
      HTTP_PROXY: 'http://plain:8080',
    }
    expect(proxyFor(env, 'https://relay.example/v0/health')?.host).toBe('lower:3128')
    expect(proxyFor(env, 'wss://relay.example/v0/subscribe')?.host).toBe('lower:3128')
    expect(proxyFor(env, 'http://relay.example/')?.host).toBe('plain:8080')
    expect(proxyFor({ HTTPS_PROXY: 'http://p:1', NO_PROXY: '.example' }, 'https://relay.example/')).toBeNull()
    expect(proxyFor({ HTTPS_PROXY: '  ' }, 'https://relay.example/')).toBeNull()
    expect(proxyFor({ HTTPS_PROXY: 'not a url' }, 'https://relay.example/')).toBeNull()
    expect(proxyFor({}, 'https://relay.example/')).toBeNull()
  })

  it('never shows a user or a password', () => {
    const env = {
      HTTPS_PROXY: 'http://jane:s3cret@proxy.corp:3128',
      NO_PROXY: 'localhost',
      NODE_USE_ENV_PROXY: '1',
    }
    const status = proxyStatus(env)
    expect(status).toEqual({
      https: 'http://proxy.corp:3128',
      http: null,
      no_proxy: 'localhost',
      active: true,
    })
    expect(JSON.stringify(status)).not.toMatch(/jane|s3cret/)
    expect(proxyShown(new URL('https://a:b@p:9'))).toBe('https://p:9')
    expect(proxyStatus({ HTTP_PROXY: 'http://p:8080' }).active).toBe(false)
  })
})

describe('useEnvProxy: one re-run with NODE_USE_ENV_PROXY=1, never a loop', () => {
  /** A process whose execve records its call and returns, as the real one never does. */
  function proc(env: Record<string, string | undefined>, withExecve = true) {
    const calls: { file: string; args: readonly string[]; env: Record<string, string> }[] = []
    const execve = (file: string, args: readonly string[], e: Record<string, string>): never => {
      calls.push({ file, args, env: e })
      return undefined as never
    }
    const base = { env, execPath: '/usr/bin/node', execArgv: ['--no-warnings'] }
    const p: ReexecProcess = {
      ...base,
      argv: ['/usr/bin/node', '/x/main.ts', 'send', '--as', 'me'],
      ...(withExecve ? { execve } : {}),
    }
    return Object.assign(p, { calls })
  }

  it('re-runs with the same arguments and both variables when a proxy is set, and only then', () => {
    const p = proc({ https_proxy: 'http://p:3128', HOME: '/h', GONE: undefined })
    expect(useEnvProxy(p)).toBeNull()
    expect(p.calls).toEqual([
      {
        file: '/usr/bin/node',
        args: ['/usr/bin/node', '--no-warnings', '/x/main.ts', 'send', '--as', 'me'],
        env: { https_proxy: 'http://p:3128', HOME: '/h', NODE_USE_ENV_PROXY: '1', [REEXEC_GUARD]: '1' },
      },
    ])
    for (const env of [
      {},
      { HTTPS_PROXY: '' },
      { HTTPS_PROXY: 'http://p:1', NODE_USE_ENV_PROXY: '1' },
      { HTTPS_PROXY: 'http://p:1', [REEXEC_GUARD]: '1' },
      { HTTP_PROXY: 'http://p:1', NODE_USE_ENV_PROXY: '0', [REEXEC_GUARD]: '1' },
    ]) {
      const q = proc(env)
      expect(useEnvProxy(q), JSON.stringify(env)).toBeNull()
      expect(q.calls, JSON.stringify(env)).toEqual([])
    }
  })

  it('returns the one-line hint where the platform has no execve', () => {
    expect(useEnvProxy(proc({ HTTP_PROXY: 'http://p:1' }, false))).toBe(
      'bag: a proxy is set (HTTPS_PROXY or HTTP_PROXY); set NODE_USE_ENV_PROXY=1 too, so Node sends through it',
    )
  })

  it('in a real process: runs again once, in the same pid, with the arguments and the proxy agent', () => {
    const log = join(tmp.dir, 'starts.log')
    const script = join(tmp.dir, 'entry.mjs')
    const proxyTs = fileURLToPath(new URL('../src/proxy.ts', import.meta.url))
    writeFileSync(
      script,
      [
        `import { appendFileSync } from 'node:fs'`,
        `import { useEnvProxy } from ${JSON.stringify(proxyTs)}`,
        `const d = globalThis[Symbol.for('undici.globalDispatcher.1')]?.constructor?.name ?? 'none'`,
        `appendFileSync(${JSON.stringify(log)}, JSON.stringify({ pid: process.pid, d, args: process.argv.slice(2) }) + '\\n')`,
        'useEnvProxy()',
      ].join('\n'),
    )
    const env = { PATH: process.env.PATH ?? '', HTTPS_PROXY: 'http://127.0.0.1:9' }
    const ran = spawnSync(process.execPath, [script, 'a', 'b c'], { env, timeout: 20_000 })
    expect(ran.status).toBe(0)
    const starts = readFileSync(log, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { pid: number; d: string; args: string[] })
    expect(starts).toHaveLength(2)
    expect(starts[0]?.pid).toBe(starts[1]?.pid)
    expect(starts.map((s) => s.args)).toEqual([
      ['a', 'b c'],
      ['a', 'b c'],
    ])
    expect(starts[1]?.d).toBe('EnvHttpProxyAgent')
  })
})

interface Seen {
  readonly line: string
  readonly headers: IncomingHttpHeaders
}

/** A CONNECT proxy on loopback that answers every CONNECT with `status`, recording each. */
async function proxyAnswering(status: number): Promise<{ url: string; seen: Seen[]; close(): void }> {
  const seen: Seen[] = []
  const server = createServer((req, res) => {
    seen.push({ line: `${req.method} ${req.url}`, headers: req.headers })
    res.writeHead(405).end()
  })
  server.on('connect', (req, socket) => {
    seen.push({ line: `CONNECT ${req.url}`, headers: req.headers })
    socket.end(`HTTP/1.1 ${status} Refused\r\n\r\n`)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return { url: `http://127.0.0.1:${port}`, seen, close: () => server.close() }
}

describe('the well-known GET behind a proxy: CONNECT to the checked address, closed on a refusal', () => {
  const URL_ = 'https://org.example:8443/.well-known/bag/address.json'

  it('asks the proxy for the guard checked address, never the name, and fails closed naming the refusal', async () => {
    const proxy = await proxyAnswering(403)
    try {
      const get = originGet({ HTTPS_PROXY: proxy.url })
      await expect(get(URL_, '203.0.113.7', 5_000, 1024)).rejects.toThrow(
        `resolve-failed: the proxy ${proxy.url} refused CONNECT to 203.0.113.7:8443: 403`,
      )
      await expect(get(URL_, '2001:db8::7', 5_000, 1024)).rejects.toThrow(
        'refused CONNECT to [2001:db8::7]:8443: 403',
      )
      // One CONNECT per GET, each to the address: the name never reaches the proxy, and nothing is retried by it.
      expect(proxy.seen.map((s) => s.line)).toEqual([
        'CONNECT 203.0.113.7:8443',
        'CONNECT [2001:db8::7]:8443',
      ])
      expect(JSON.stringify(proxy.seen)).not.toContain('org.example')
    } finally {
      proxy.close()
    }
  })

  it('sends the proxy its credentials as Proxy-Authorization and never puts them in an error', async () => {
    const proxy = await proxyAnswering(407)
    try {
      const authed = proxy.url.replace('http://', 'http://jane:s3cret@')
      const failed = await originGet({ https_proxy: authed })(URL_, '203.0.113.7', 5_000, 1024).catch(
        (e) => e,
      )
      expect(String(failed)).toContain('407')
      expect(String(failed)).not.toMatch(/jane|s3cret/)
      const basic = `Basic ${Buffer.from('jane:s3cret').toString('base64')}`
      expect(proxy.seen[0]?.headers['proxy-authorization']).toBe(basic)
    } finally {
      proxy.close()
    }
  })

  it('goes direct under NO_PROXY, and for http, which only the test stub uses', async () => {
    const proxy = await proxyAnswering(403)
    const target = createServer((_req, res) => res.writeHead(404).end())
    await new Promise<void>((resolve) => target.listen(0, '127.0.0.1', resolve))
    const { port } = target.address() as AddressInfo
    try {
      const env = { HTTPS_PROXY: proxy.url, HTTP_PROXY: proxy.url, NO_PROXY: 'org.example' }
      const refused = await originGet(env)(URL_, '127.0.0.1', 2_000, 1024).catch((e) => e)
      expect(String(refused)).not.toContain('the proxy')
      const plain = await originGet(env)(`http://127.0.0.1:${port}/x`, null, 2_000, 1024)
      expect(plain).toEqual({ status: 404, body: null })
      expect(proxy.seen).toEqual([])
    } finally {
      proxy.close()
      target.close()
    }
  })
})
