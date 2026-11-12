import { execFileSync, spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { launchCommand } from '../src/service.ts'
import { DIALOG_META, runPaths } from '../src/socket.ts'

// The bag service as the login agent starts it, offline: the bundle built into <home>/package/versions/<v>/, a launcher
// at <home>/package/bag-mcp.js (the CLI lane's facts: it imports versions/<current>/bag-mcp.js in its own process, keeps
// argv, and refuses a current with a slash or dot-dot), two identities made with the bundle's own keygen, the scrubbed
// launch. A fake shim binds by the typed word, calls a tool, and with a loopback ac-relay (target/release/ac-relay, or
// AC_RELAY_CMD) one identity sends to the other and the bound window is rung. SIGTERM drains: run/ is cleaned and the
// lock released. The home is a short directory under /tmp, removed after the test.

type Json = Record<string, unknown>
const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..', '..')
/** The relay binary: AC_RELAY_CMD, else the checkout's build (a worktree's own, else its main checkout's). */
const RELAY_CMD =
  process.env.AC_RELAY_CMD ||
  [join(REPO, 'target', 'release', 'ac-relay'), join(REPO, '..', '..', 'target', 'release', 'ac-relay')].find(
    (p) => existsSync(p),
  ) ||
  ''
const VERSION = '0.4.0'

let home: string
const kill: (() => void)[] = []
const sockets: Socket[] = []
beforeEach(() => {
  home = mkdtempSync('/tmp/bpr-')
})
afterEach(() => {
  for (const s of sockets.splice(0)) s.destroy()
  for (const k of kill.splice(0)) k()
  rmSync(home, { recursive: true, force: true })
})

/** Runs a module's expression in a child node (the CLI's and the bag package's code, kept out of this package). */
function nodeEval(code: string): string {
  return execFileSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', code], {
    encoding: 'utf8',
  })
}

/** The launcher the CLI lane stages, as its facts give it: Node built-ins only, in-process, argv kept. */
const LAUNCHER = `#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const pkg = dirname(fileURLToPath(import.meta.url))
let v = ''
try { v = readFileSync(join(pkg, 'current'), 'utf8').trim() } catch {}
if (v === '' || v.includes('/') || v.includes('..')) {
  process.stderr.write('bag: no version named in ' + join(pkg, 'current') + ': run the install again\\n')
  process.exit(1)
}
await import(pathToFileURL(join(pkg, 'versions', v, 'bag-mcp.js')).href)
`

/** A loopback relay, or null when no ac-relay binary is built. */
async function relay(): Promise<string | null> {
  if (RELAY_CMD === '') return null
  const child = spawn(RELAY_CMD, ['--port', '0', '--db', join(home, 'relay.sqlite'), '--exit-on-stdin-eof'], {
    stdio: ['pipe', 'pipe', 'ignore'],
  })
  child.stdin?.on('error', () => {})
  kill.push(() => child.kill('SIGKILL'))
  const lines = createInterface({ input: child.stdout as NodeJS.ReadableStream })
  return new Promise((ok, no) => {
    const t = setTimeout(() => no(new Error('no AC_RELAY_URL line in 10 s')), 10_000)
    lines.once('line', (l) => {
      clearTimeout(t)
      ok(/^AC_RELAY_URL=(.+)$/.exec(l)?.[1] ?? '')
    })
  })
}

/** A line client of the service's socket. */
async function shim(sock: string) {
  const socket = createConnection(sock)
  sockets.push(socket)
  await new Promise<void>((r) => socket.once('connect', () => r()))
  const seen: Json[] = []
  const waiters: { pick: (m: Json) => boolean; resolve: (m: Json) => void }[] = []
  let buf = ''
  socket.on('data', (b: Buffer) => {
    buf += b.toString()
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const m = JSON.parse(buf.slice(0, i)) as Json
      buf = buf.slice(i + 1)
      const w = waiters.findIndex((x) => x.pick(m))
      if (w >= 0) waiters.splice(w, 1)[0]?.resolve(m)
      else seen.push(m)
    }
  })
  let id = 0
  const next = (pick: (m: Json) => boolean): Promise<Json> => {
    const i = seen.findIndex(pick)
    if (i >= 0) return Promise.resolve(seen.splice(i, 1)[0] as Json)
    return new Promise((resolve) => waiters.push({ pick, resolve }))
  }
  const request = (method: string, params: Json = {}): Promise<Json> => {
    const n = ++id
    socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: n, method, params })}\n`)
    return next((m) => m.id === n)
  }
  const call = async (name: string, args: Json = {}): Promise<Json> => {
    const r = (await request('tools/call', { name, arguments: args })).result as {
      content: { text: string }[]
    }
    return JSON.parse(r.content[0]?.text ?? '{}') as Json
  }
  return { socket, next, request, call }
}

describe('the service started through the launcher, as the login agent starts it', () => {
  it('serves a bound shim, rings it for mail, records package_dir = versions/<v> which a prune keeps, and drains clean', async () => {
    const pkg = join(home, 'package')
    const dir = join(pkg, 'versions', VERSION)
    nodeEval(
      `const m = await import(${JSON.stringify(join(REPO, 'packages/bag/src/build.ts'))}); await m.build(${JSON.stringify(dir)}, 'test')`,
    )
    for (const v of ['2.0.0', '3.0.0']) mkdirSync(join(pkg, 'versions', v), { recursive: true })
    writeFileSync(join(pkg, 'current'), `${VERSION}\n`)
    writeFileSync(join(pkg, 'bag-mcp.js'), LAUNCHER, { mode: 0o755 })
    const bag = (...args: string[]): string => bagIn(home, ...args)
    const bagIn = (at: string, ...args: string[]): string =>
      execFileSync(process.execPath, [join(dir, 'bag.js'), ...args, '--dir', at], {
        encoding: 'utf8',
        env: { HOME: home, BAG_TEST_ZONE_FILE: join(home, 'zone.txt') },
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim()
    writeFileSync(join(home, 'zone.txt'), '')
    const alice = bag('keygen', 'alice', '--custody', 'file').split('\n').at(-1) as string
    const bob = bag('keygen', 'bob', '--custody', 'file').split('\n').at(-1) as string
    // A peer outside the service, in a home of its own: the one that sends (a service refuses a send to its own).
    const peerHome = join(home, 'peer')
    const carol = bagIn(peerHome, 'keygen', 'carol', '--custody', 'file').split('\n').at(-1) as string
    const url = await relay()
    const relays = [url ?? 'http://127.0.0.1:9']
    if (url !== null)
      for (const [name, peer] of [
        ['alice', bob],
        ['bob', alice],
      ] as const) {
        const a = join(home, `${name}-address.json`)
        const f = join(home, `${name}-accept.json`)
        bag('record', 'address', name, '--relay', url, '--sealing-key', '--out', a)
        bag(
          'record',
          'accept-from',
          name,
          '--root',
          peer,
          '--root',
          carol,
          '--max-bytes',
          '65536',
          '--ttl',
          '86400',
          '--out',
          f,
        )
        bag('publish', url, a)
        bag('publish', url, f)
      }
    const identities = join(home, 'identities.json')
    const entry = (label: string, key: string, peer: string) => ({
      label,
      key,
      home,
      relays,
      trust_roots: [peer, carol],
    })
    writeFileSync(
      identities,
      JSON.stringify({ version: 1, identities: [entry('alice', 'alice', bob), entry('bob', 'bob', alice)] }),
      { mode: 0o600 },
    )
    // The login agent's command: the launcher as main, the scrubbed environment; a loopback relay needs the flag.
    const cmd = launchCommand({
      node: process.execPath,
      main: join(pkg, 'bag-mcp.js'),
      home,
      identities,
      env: { HOME: home },
    })
    mkdirSync(runPaths(home).dir, { recursive: true, mode: 0o700 })
    const child = spawn(cmd.file, [...cmd.args, '--allow-private-relays'], {
      cwd: cmd.cwd,
      env: cmd.env,
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    kill.push(() => child.kill('SIGKILL'))
    let err = ''
    child.stderr.on('data', (b: Buffer) => {
      err += b.toString()
    })
    const exit = new Promise<number | null>((r) => child.once('exit', (c) => r(c)))
    const end = Date.now() + 20_000
    while (!existsSync(runPaths(home).token)) {
      if (Date.now() > end) throw new Error(`no token in 20 s: ${err}`)
      await new Promise((r) => setTimeout(r, 50))
    }
    const token = readFileSync(runPaths(home).token, 'utf8')
    const helloOf = (cwd: string) => ({
      contract: 1,
      token,
      host: 'claude-code',
      cwd,
      client_capabilities: { elicitation: { form: {} } },
      input_hook: true,
    })
    const a = await shim(runPaths(home).sock)
    expect((await a.request('service/hello', helloOf('/w/a'))).result).toMatchObject({ contract: 1 })
    expect((await a.request('service/identities')).result).toMatchObject({
      identities: [{ label: 'alice' }, { label: 'bob' }],
    })
    expect((await a.request('service/use', { label: 'alice', via: 'typed' })).result).toMatchObject({
      bound: true,
      as: 'alice',
      custody: 'home-key',
    })
    expect(await a.call('status')).toMatchObject({ address: alice, as: 'alice' })
    // service.json names the version directory the bundle loaded from, not the launcher argv[1] names.
    const json = JSON.parse(readFileSync(runPaths(home).json, 'utf8')) as Json
    expect(json.package_dir).toBe(realpathSync(dir))
    writeFileSync(join(pkg, 'current'), '3.0.0\n')
    const removed = nodeEval(
      `const m = await import(${JSON.stringify(join(REPO, 'packages/cli/src/packaged.ts'))}); process.stdout.write(JSON.stringify(m.pruneVersions(${JSON.stringify(home)}, () => false)))`,
    )
    expect(JSON.parse(removed)).toEqual([])
    expect(existsSync(join(dir, 'bag-mcp.js'))).toBe(true)
    writeFileSync(join(pkg, 'current'), `${VERSION}\n`)
    let rang: Json | null = null
    if (url !== null) {
      const c = join(home, 'carol-address.json')
      bagIn(peerHome, 'record', 'address', 'carol', '--relay', url, '--sealing-key', '--out', c)
      bagIn(peerHome, 'publish', url, c)
      bagIn(
        peerHome,
        'send',
        '--as',
        'carol',
        '--to',
        alice,
        '--relay',
        url,
        '--type',
        'chat.v1',
        '--body',
        '"hi"',
        '--allow-private-relays',
      )
      rang = await Promise.race([
        a.next((m) => m.method === 'service/ring'),
        new Promise<Json>((_, no) =>
          setTimeout(() => no(new Error(`no service/ring in 20 s: ${err}`)), 20_000),
        ),
      ])
      expect(rang.params).toMatchObject({ as: 'alice', speaking: true, unread: 1 })
      const inbox = await a.call('inbox')
      expect(JSON.stringify(inbox)).toContain(carol)
    }
    process.stdout.write(
      `service-process: ring ${rang === null ? 'skipped (no ac-relay)' : JSON.stringify(rang.params)}\n`,
    )
    void DIALOG_META
    child.kill('SIGTERM')
    expect(await exit).toBe(0)
    const { sock, json: status, lock } = runPaths(home)
    expect([existsSync(sock), existsSync(runPaths(home).token), existsSync(status)]).toEqual([
      false,
      false,
      false,
    ])
    const got = spawnSync(
      process.execPath,
      [
        '--no-warnings',
        '-e',
        `const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(${JSON.stringify(lock)}, { timeout: 0 });
         try { db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT'); process.stdout.write('got') } catch { process.stdout.write('busy') }`,
      ],
      { encoding: 'utf8' },
    )
    expect(got.stdout).toBe('got')
  }, 120_000)
})
