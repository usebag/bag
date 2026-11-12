import {
  closeSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { createConnection, createServer } from 'node:net'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { bridgeDirOf } from '../src/bridge.ts'
import {
  ancestors,
  boundOf,
  endSession,
  hostPidOf,
  openChannel,
  postBridge,
  postUse,
  psRow,
  safeDir,
  typedName,
  writeBound,
} from '../src/channel.ts'
import {
  errorOf,
  frame,
  isNotification,
  isRequest,
  isResponse,
  Lines,
  LineTooLong,
  parse,
} from '../src/frames.ts'
import { hostKind, toolTimeoutMs } from '../src/host.ts'
import { isLabel, removeRing, ringOf, writeRing } from '../src/ring.ts'
import { launchEnv, openServiceLog, run, type ShimIo, serviceEntry, startService } from '../src/run.ts'
import { absent, socketConnect } from '../src/service.ts'
import { backoff, realTimers } from '../src/shim.ts'
import {
  bagCode,
  handleOf,
  homeOf,
  ownsHome,
  readToken,
  socketPathProblem,
  withHandle,
  withoutBagMeta,
} from '../src/wire.ts'
import { dropHome, FakeService, shortHome } from './fake-service.ts'

let home: string
beforeEach(() => {
  home = shortHome()
})
afterEach(() => dropHome(home))

describe('frames', () => {
  it('splits lines across chunks, keeps split UTF-8 whole, strips a CR and drops what is not JSON-RPC', () => {
    const l = new Lines(64)
    const euro = Buffer.from('{"jsonrpc":"2.0","method":"x","params":{"t":"€"}}\r\n')
    const a = l.push(euro.subarray(0, 40))
    expect(a.messages).toEqual([])
    const b = l.push(Buffer.concat([euro.subarray(40), Buffer.from('\nnope\n[1]\n{"jsonrpc":"1.0"}\n')]))
    expect(b.messages).toEqual([{ jsonrpc: '2.0', method: 'x', params: { t: '€' } }])
    expect(b.dropped).toEqual(['nope', '[1]', '{"jsonrpc":"1.0"}'])
    expect(() => l.push('x'.repeat(65))).toThrow(LineTooLong)
    expect(l.push(`${'y'.repeat(100)}\n`).dropped[0]).toMatch(/\.\.\.$/)
    expect(parse('null')).toBeNull()
  })

  it('tells requests, notifications and responses apart', () => {
    expect(isRequest({ jsonrpc: '2.0', id: 1, method: 'a' })).toBe(true)
    expect(isNotification({ jsonrpc: '2.0', method: 'a' })).toBe(true)
    expect(isResponse({ jsonrpc: '2.0', id: 1, result: {} })).toBe(true)
    expect(isResponse({ jsonrpc: '2.0', id: 1 })).toBe(false)
    expect(errorOf(1, -1, 'm', { a: 1 })).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -1, message: 'm', data: { a: 1 } },
    })
    expect(frame({ jsonrpc: '2.0', method: 'a' })).toBe('{"jsonrpc":"2.0","method":"a"}\n')
  })
})

describe('host', () => {
  it('finds the host kind as the install page does', () => {
    expect(hostKind({ OMPCODE: '1', CLAUDECODE: '1' })).toBe('omp')
    expect(hostKind({ CLAUDECODE: '1' }, 'codex')).toBe('claude-code')
    expect(hostKind({}, 'codex-mcp-client')).toBe('codex')
    expect(hostKind({}, 'Claude Code')).toBe('claude-code')
    expect(hostKind({}, 'omp')).toBe('omp')
    expect(hostKind({}, 'opencode')).toBe('other')
    expect(toolTimeoutMs('codex')).toBe(60_000)
    expect(toolTimeoutMs('claude-code')).toBeNull()
  })
})

describe('wire', () => {
  it('finds the home, the token, the handle and the bag code', () => {
    expect(homeOf(['--dir', '/h'], {})).toBe('/h')
    expect(homeOf([], { AC_HOME: '/a' })).toBe('/a')
    expect(homeOf([], { HOME: '/u' })).toBe('/u/.bag')
    expect(homeOf([], {})).toBeNull()
    expect(readToken('/x', () => `${'a'.repeat(64)}\n`)).toBe('a'.repeat(64))
    expect(readToken('/x', () => 'short')).toBeNull()
    expect(readToken(join(home, 'none'))).toBeNull()
    expect(handleOf({ _meta: { 'bag.dev/dialog': 'h' } })).toBe('h')
    expect(handleOf({ _meta: { 'bag.dev/dialog': '' } })).toBeNull()
    expect(handleOf(undefined)).toBeNull()
    expect(withoutBagMeta({ a: 1 })).toEqual({ a: 1 })
    expect(withoutBagMeta({ a: 1, _meta: { 'bag.dev/dialog': 'h' } })).toEqual({ a: 1 })
    expect(withHandle(null, 'h')).toEqual({ _meta: { 'bag.dev/dialog': 'h' } })
    expect(bagCode({ data: { code: 'busy' } })).toBe('busy')
    expect(bagCode(undefined)).toBeNull()
    expect(socketPathProblem(`/${'x'.repeat(103)}`, 'darwin')).toMatch(/104 bytes; this platform allows 103/)
    expect(socketPathProblem(`/${'x'.repeat(103)}`, 'linux')).toBeNull()
  })

  it('checks that the service named by service.json is the one that answered, and alive', () => {
    mkdirSync(join(home, 'run'))
    writeFileSync(join(home, 'run', 'service.json'), JSON.stringify({ pid: 77 }))
    expect(ownsHome(home, 77, () => true)).toBe(true)
    expect(ownsHome(home, 78, () => true)).toBe(false)
    expect(ownsHome(home, 77, () => false)).toBe(false)
    expect(ownsHome(join(home, 'none'), 77, () => true)).toBe(false)
  })
})

describe('service connection', () => {
  it('says absent for nothing listening and closes a peer that sends an endless line', async () => {
    expect(absent({ code: 'ENOENT' })).toBe(true)
    expect(absent({ code: 'EPIPE' })).toBe(false)
    expect(absent(null)).toBe(false)
    await expect(
      socketConnect(join(home, 'none.sock'))({ message() {}, dropped() {}, closed() {} }),
    ).rejects.toThrow()
    const path = join(home, 's.sock')
    const server = createServer((s) => {
      s.on('error', () => {})
      s.write('garbage\n')
      s.write('z'.repeat(5 * 1024 * 1024))
    })
    await new Promise<void>((r) => server.listen(path, r))
    const dropped: string[] = []
    const { promise, resolve } = Promise.withResolvers<NodeJS.ErrnoException | null>()
    const conn = await socketConnect(path)({ message() {}, dropped: (d) => dropped.push(d), closed: resolve })
    expect((await promise)?.code).toBe('ELINE')
    expect(dropped).toEqual(['garbage'])
    expect(conn.send({ jsonrpc: '2.0', method: 'x' })).toBe(false)
    conn.close()
    await new Promise<void>((r) => server.close(() => r()))
  })

  it('backs off from 100 ms to 5 s, and real timers cancel', async () => {
    expect([0, 1, 2, 10].map(backoff)).toEqual([100, 200, 400, 5000])
    let fired = false
    realTimers.after(5, () => (fired = true))()
    await new Promise((r) => setTimeout(r, 20))
    expect(fired).toBe(false)
  })
})

describe('the typed-word channel', () => {
  it('matches only a whole `use <name>` prompt', () => {
    expect(typedName('use omp-3')).toBe('omp-3')
    expect(typedName('  USE  omp_2.x  ')).toBe('omp_2.x')
    expect(typedName('use omp now')).toBeNull()
    expect(typedName('use -x')).toBeNull()
    expect(typedName('use ../x')).toBeNull()
  })

  it('finds the host past launchers, and a hook its ancestors', () => {
    const rows: Record<number, { ppid: number; comm: string }> = {
      50: { ppid: 40, comm: 'npx' },
      40: { ppid: 30, comm: 'sh' },
      30: { ppid: 1, comm: 'claude' },
      20: { ppid: 1, comm: 'sh' },
    }
    const ps = (pid: number) => rows[pid] ?? null
    expect(hostPidOf(50, ps)).toBe(30)
    expect(hostPidOf(30, ps)).toBe(30)
    expect(hostPidOf(20, ps)).toBe(20)
    expect(hostPidOf(99, ps)).toBe(99)
    expect(ancestors(50, ps)).toEqual([50, 40, 30])
    expect(ancestors(99, ps)).toEqual([99])
    expect(psRow(process.pid)?.ppid).toBe(process.ppid)
    expect(psRow(0x7ffffff0)).toBeNull()
  })

  it('writes the bound file for the wake hook, removes only its own, and refuses an unsafe directory', () => {
    writeBound(home, 11, 22, ['omp'])
    expect(JSON.parse(readFileSync(boundOf(home, 11), 'utf8'))).toEqual({ v: 1, as: ['omp'], shim: 22 })
    writeBound(home, 11, 33, [])
    expect(statSync(boundOf(home, 11)).isFile()).toBe(true)
    writeBound(home, 11, 22, [])
    expect(() => statSync(boundOf(home, 11))).toThrow()
    writeBound(home, 11, 22, [])
    const other = shortHome()
    try {
      mkdirSync(join(other, 'run', 'shim'), { recursive: true, mode: 0o755 })
      expect(() => writeBound(other, 1, 2, ['x'])).toThrow('unsafe')
    } finally {
      dropHome(other)
    }
  })

  it('refuses an unsafe directory', () => {
    const open = join(home, 'open')
    mkdirSync(open, { mode: 0o755 })
    expect(safeDir(open)).toBe('open to group or others')
    expect(safeDir(join(home, 'mine'), 0)).toBe('owned by another user')
    const link = join(home, 'link')
    symlinkSync(join(home, 'mine'), link)
    expect(safeDir(link)).toBe('not a directory')
  })

  it('serves typed words with the secret and refuses without it; turns itself off when it cannot run', async () => {
    const logs: string[] = []
    const log = (e: string) => logs.push(e)
    const ch = await openChannel(
      home,
      123,
      456,
      {
        use: async (n: string) => ({ bound: true as const, as: n }),
        typed: () => true,
        bridge: () => '/b.consent',
      },
      log,
      103,
    )
    expect(ch).not.toBeNull()
    expect(await postUse(home, [9, 123], 'omp')).toEqual({ bound: true, as: 'omp' })
    expect(await postBridge(home, [123])).toBe('/b.consent')
    expect(await postBridge(home, [9])).toBeNull()
    const idx = JSON.parse(readFileSync(join(home, 'run', 'shim', '123.json'), 'utf8')) as { sock: string }
    const sock = join(home, 'run', 'shim', idx.sock)
    expect(statSync(sock).mode & 0o077).toBe(0)
    const raw = (line: string) =>
      new Promise<string>((resolve) => {
        const c = require('node:net').createConnection({ path: sock }) as import('node:net').Socket
        let out = ''
        c.on('connect', () => c.write(line))
        c.on('data', (d: Buffer) => (out += d.toString()))
        c.on('close', () => resolve(out))
      })
    expect(
      JSON.parse(
        await raw(`${JSON.stringify({ v: 1, kind: 'use', name: 'omp', secret: 'a'.repeat(64) })}\n`),
      ),
    ).toEqual({
      bound: false,
      code: 'bad-auth',
    })
    expect(JSON.parse(await raw('{\n'))).toEqual({ bound: false, code: 'bad-json' })
    expect(await raw('x'.repeat(5000))).toBe('')
    const secret = (
      JSON.parse(readFileSync(join(home, 'run', 'shim', '123.json'), 'utf8')) as { secret: string }
    ).secret
    expect(JSON.parse(await raw(`${JSON.stringify({ v: 1, kind: 'use', name: 'a b', secret })}\n`))).toEqual({
      bound: false,
      code: 'usage',
    })
    ch?.close()
    ch?.close()
    expect(await postUse(home, [123], 'omp')).toBeNull()
    writeFileSync(
      join(home, 'run', 'shim', '7.json'),
      JSON.stringify({ v: 1, sock: 'deadbeef.sock', secret: 'x' }),
    )
    expect(await postUse(home, [7], 'omp', 200)).toBeNull()
    writeFileSync(join(home, 'run', 'shim', '8.json'), JSON.stringify({ v: 1, sock: '../x', secret: 'x' }))
    expect(await postUse(home, [8], 'omp', 200)).toBeNull()
    expect(
      await openChannel(
        home,
        1,
        2,
        { use: async () => ({ bound: false as const, code: 'x' }), typed: () => false, bridge: () => null },
        log,
        10,
      ),
    ).toBeNull()
    expect(
      await openChannel(
        '/dev/null/x',
        1,
        2,
        { use: async () => ({ bound: false as const, code: 'x' }), typed: () => false, bridge: () => null },
        log,
        103,
      ),
    ).toBeNull()
    expect(logs).toContain('channel-off')
  })
})

describe('the session files at exit', () => {
  it('removes the hook files and its own when .bound or .ring names this shim, else leaves all four', () => {
    const dir = join(home, 'run', 'shim')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const hookFiles = () => ['9.ring-seen', '9.wake-hook.lock'].map((f) => join(dir, f))
    const plant = () => {
      for (const f of hookFiles()) writeFileSync(f, '1\n')
    }
    plant()
    writeBound(home, 9, 100, ['omp'])
    writeRing(home, 9, 100, { n: 1, as: 'omp', unread: 1, speaking: true, at: null })
    expect(endSession(home, 9, 200)).toBe(false)
    expect(readdirSync(dir).sort()).toEqual(['9.bound', '9.ring', '9.ring-seen', '9.wake-hook.lock'])
    expect(endSession(home, 9, 100)).toBe(true)
    expect(readdirSync(dir)).toEqual([])
    // The connection dropped: no .bound left, the .ring still names the shim.
    plant()
    writeRing(home, 9, 100, { n: 2, as: 'omp', unread: 1, speaking: true, at: null })
    expect(endSession(home, 9, 100)).toBe(true)
    expect(readdirSync(dir)).toEqual([])
    plant()
    expect(endSession(home, 9, 100)).toBe(false)
    expect(readdirSync(dir).sort()).toEqual(['9.ring-seen', '9.wake-hook.lock'])
  })
})

describe('the ring file', () => {
  it('writes the shape, 0600, renamed over, and removes only its own', () => {
    mkdirSync(join(home, 'run', 'shim'), { recursive: true, mode: 0o700 })
    writeRing(home, 5, 6, { n: 1, as: 'omp', unread: 2, speaking: true, at: 'a' })
    writeRing(home, 5, 6, { n: 2, as: 'omp', unread: 3, speaking: false, at: 'b' })
    expect(JSON.parse(readFileSync(ringOf(home, 5), 'utf8'))).toEqual({
      v: 1,
      n: 2,
      as: 'omp',
      unread: 3,
      speaking: false,
      at: 'b',
      shim: 6,
    })
    expect(statSync(ringOf(home, 5)).mode & 0o777).toBe(0o600)
    removeRing(home, 5, 7)
    expect(statSync(ringOf(home, 5)).isFile()).toBe(true)
    removeRing(home, 5, 6)
    expect(() => statSync(ringOf(home, 5))).toThrow()
    removeRing(home, 5, 6)
    expect(isLabel('..')).toBe(false)
    expect(isLabel('omp-3')).toBe(true)
  })
})

describe('the omp bridge folder', () => {
  it('takes only a 0700 <home>/run/shim/<connection>.consent of the user, not a link', () => {
    const dir = join(home, 'run', 'shim', 'c-42.consent')
    expect(bridgeDirOf(home, dir)).toBeNull()
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    expect(bridgeDirOf(home, dir)).toBe(dir)
    expect(bridgeDirOf(home, 5)).toBeNull()
    expect(bridgeDirOf(home, join(home, 'run', 'x.consent'))).toBeNull()
    expect(bridgeDirOf(home, join(home, 'run', 'shim', 'a b.consent'))).toBeNull()
    expect(bridgeDirOf(home, dir, 0)).toBeNull()
    const loose = join(home, 'run', 'shim', 'c-43.consent')
    mkdirSync(loose, { mode: 0o755 })
    expect(bridgeDirOf(home, loose)).toBeNull()
    const link = join(home, 'run', 'shim', 'c-45.consent')
    symlinkSync(dir, link)
    expect(bridgeDirOf(home, link)).toBeNull()
  })
})

describe('the scrubbed launch', () => {
  it('passes only the allow-listed environment', () => {
    expect(
      launchEnv({ HOME: '/u', NODE_OPTIONS: '--inspect', HTTPS_PROXY: 'p', PATH: '/evil', LANG: 'C' }, '/h'),
    ).toEqual({
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      AC_HOME: '/h',
      HOME: '/u',
      LANG: 'C',
      HTTPS_PROXY: 'p',
    })
  })

  it('starts the current package entry with --disable-sigusr1, core dumps off, the home as cwd', async () => {
    expect(serviceEntry(home)).toBeNull()
    expect(startService(home, {})).toBe(false)
    mkdirSync(join(home, 'package', 'versions', '0.4.0'), { recursive: true })
    writeFileSync(join(home, 'package', 'current'), '../x\n')
    expect(serviceEntry(home)).toBeNull()
    writeFileSync(join(home, 'package', 'current'), '0.4.0\n')
    const out = join(home, 'launched.json')
    writeFileSync(
      join(home, 'package', 'versions', '0.4.0', 'bag-mcp.js'),
      `require('node:fs').writeFileSync(${JSON.stringify(out)}, JSON.stringify({ argv: process.argv.slice(2), execArgv: process.execArgv, cwd: process.cwd(), opts: process.env.NODE_OPTIONS ?? null, core: require('node:child_process').execSync('ulimit -c').toString().trim() }))`,
    )
    expect(startService(home, { NODE_OPTIONS: '--inspect', HOME: home })).toBe(true)
    for (let i = 0; i < 100; i++) {
      try {
        statSync(out)
        break
      } catch {
        await new Promise((r) => setTimeout(r, 30))
      }
    }
    await new Promise((r) => setTimeout(r, 50))
    const got = JSON.parse(readFileSync(out, 'utf8')) as Record<string, unknown>
    expect(got).toMatchObject({
      argv: ['--service', '--dir', home],
      execArgv: ['--disable-sigusr1'],
      opts: null,
      core: '0',
    })
    expect(String(got.cwd).endsWith(home.slice('/tmp'.length))).toBe(true)
  })

  it('gives the child <home>/run/service.log as stdout and stderr: 0600, appended, never truncated', async () => {
    mkdirSync(join(home, 'package', 'versions', '0.4.0'), { recursive: true })
    writeFileSync(join(home, 'package', 'current'), '0.4.0\n')
    writeFileSync(
      join(home, 'package', 'versions', '0.4.0', 'bag-mcp.js'),
      "process.stderr.write('died early: ' + process.argv[2] + '\\n'); process.stdout.write('out line\\n')",
    )
    const file = join(home, 'run', 'service.log')
    mkdirSync(join(home, 'run'), { mode: 0o700 })
    writeFileSync(file, 'a line before\n', { mode: 0o600 })
    const wait = async (n: number) => {
      for (let i = 0; i < 100 && readFileSync(file, 'utf8').split('\n').length < n; i++) {
        await new Promise((r) => setTimeout(r, 30))
      }
    }
    expect(startService(home, {})).toBe(true)
    await wait(4)
    expect(startService(home, {})).toBe(true)
    await wait(6)
    const lines = readFileSync(file, 'utf8')
      .split('\n')
      .filter((l) => l !== '')
    expect(lines[0]).toBe('a line before')
    expect(lines.filter((l) => l === 'died early: --service')).toHaveLength(2)
    expect(lines.filter((l) => l === 'out line')).toHaveLength(2)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    // The open is O_APPEND: a fresh descriptor's first write lands at the end (without it, at offset 0, over the
    // first line).
    const fd = openServiceLog(home, () => {}) as number
    writeSync(fd, 'appended\n')
    closeSync(fd)
    const after = readFileSync(file, 'utf8')
    expect(after.startsWith('a line before\n')).toBe(true)
    expect(after.endsWith('appended\n')).toBe(true)
  })

  it('starts without the log when it cannot open it, and says so', () => {
    const events: string[] = []
    mkdirSync(join(home, 'run'), { mode: 0o755 })
    expect(openServiceLog(home, (e) => events.push(e))).toBe('ignore')
    expect(events).toEqual(['service-log-failed'])
    const other = shortHome()
    try {
      mkdirSync(join(other, 'run'), { mode: 0o700 })
      symlinkSync('/tmp/nowhere-bag-shim', join(other, 'run', 'service.log'))
      expect(openServiceLog(other, () => {})).toBe('ignore')
    } finally {
      dropHome(other)
    }
  })
})

describe('run in process', () => {
  function io(argv: string[], more: Partial<ShimIo> = {}) {
    const stdin = new PassThrough()
    const stdout = new PassThrough()
    let err = ''
    const handlers = new Map<string, () => void>()
    const io: ShimIo = {
      argv,
      env: { HOME: home, CLAUDECODE: '1' },
      cwd: home,
      pid: 999_001,
      ppid: process.pid,
      stdin,
      stdout,
      stderr: { write: (t: string) => (err += t) },
      signals: {
        once: (e, l) => handlers.set(e, l),
        removeListener: (e) => handlers.delete(e),
      },
      ps: () => null,
      startService: () => false,
      ...more,
    }
    return { io, stdin, stdout, handlers, err: () => err }
  }

  it('prints usage and help, and needs a home', async () => {
    expect(await run(io(['--what']).io)).toBe(2)
    expect(await run(io(['--help']).io)).toBe(0)
    const x = io([])
    expect(await run({ ...x.io, env: {} })).toBe(2)
    expect(x.err()).toContain('no home directory')
  })

  it('serves until a signal, drops bad lines, closes on EPIPE and on a line too long', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const a = io(['--dir', home, '--input-hook'])
      const done = run(a.io)
      const out: string[] = []
      a.stdout.on('data', (d: Buffer) => out.push(d.toString()))
      a.stdin.write('junk\n')
      a.stdin.write(
        frame({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'claude-code' } },
        }),
      )
      for (let i = 0; i < 100 && out.length === 0; i++) await new Promise((r) => setTimeout(r, 10))
      expect(out.join('')).toContain('"serverInfo"')
      a.handlers.get('SIGHUP')?.()
      expect(await done).toBe(0)
      expect(a.err()).toContain('"event":"host-bad-line"')

      const b = io(['--dir', home])
      const doneB = run(b.io)
      await new Promise((r) => setTimeout(r, 20))
      b.stdout.emit('error', Object.assign(new Error('pipe'), { code: 'EPIPE' }))
      expect(await doneB).toBe(0)
      expect(b.err()).toContain('"reason":"epipe"')

      const c = io(['--dir', home])
      const doneC = run(c.io)
      await new Promise((r) => setTimeout(r, 20))
      c.stdin.write(Buffer.alloc(4 * 1024 * 1024 + 10, 0x61))
      expect(await doneC).toBe(0)
      expect(c.err()).toContain('"reason":"line-too-long"')
    } finally {
      await svc.close()
    }
  })

  it('runs raw on a terminal stdin and ends on Ctrl-D', async () => {
    const modes: boolean[] = []
    const stdin = Object.assign(new PassThrough(), { isTTY: true, setRawMode: (r: boolean) => modes.push(r) })
    const a = io(['--dir', home], { stdin })
    const done = run(a.io)
    await new Promise((r) => setTimeout(r, 20))
    stdin.write(Buffer.from([0x04]))
    expect(await done).toBe(0)
    expect(modes).toEqual([true, false])
  })

  it('serves a whole session in process: ring, owner check, the hook for a typed word and a plain prompt', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const a = io(['--dir', home, '--input-hook'])
      const done = run(a.io)
      const out: string[] = []
      a.stdout.on('data', (d: Buffer) => out.push(d.toString()))
      await new Promise((r) => setTimeout(r, 30))
      a.stdin.write(
        frame({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: { elicitation: {} },
            clientInfo: { name: 'x' },
          },
        }),
      )
      await svc.next((m) => m.method === 'initialize')
      svc.notify('service/ring', { as: 'omp', speaking: true })
      svc.notify('service/ring', { as: '../bad', speaking: true })
      void svc.ask('elicitation/create', { message: 'm', requestedSchema: {} })
      for (let i = 0; i < 100 && !out.join('').includes('elicitation/create'); i++) {
        await new Promise((r) => setTimeout(r, 10))
      }
      expect(
        JSON.parse(readFileSync(join(home, 'run', 'shim', `${process.pid}.ring`), 'utf8')),
      ).toMatchObject({
        v: 1,
        n: 1,
        as: 'omp',
        speaking: true,
        shim: 999_001,
      })
      expect(a.err()).toContain('"event":"ring-bad"')
      const hook = (prompt: string) => {
        const stdin = new PassThrough()
        const stdout = new PassThrough()
        const h = io(['hook', '--dir', home], { stdin, stdout })
        const p = run(h.io)
        stdin.end(JSON.stringify({ prompt }))
        return p.then(() => String(stdout.read() ?? ''))
      }
      expect(JSON.parse(await hook('use omp'))).toEqual({
        decision: 'block',
        reason: 'bag: this session now acts as omp.',
      })
      expect(await hook('hello there')).toBe('')
      await svc.next((m) => m.method === 'service/typed')
      a.handlers.get('SIGTERM')?.()
      expect(await done).toBe(0)
      expect(a.err()).toContain('"input_hook":true')
    } finally {
      await svc.close()
    }
  })

  it('serves an omp session in process: the bridge capability, and the folder from the reply to the extension', async () => {
    const svc = new FakeService(home)
    const folder = join(home, 'run', 'shim', 'c-7.consent')
    mkdirSync(folder, { recursive: true, mode: 0o700 })
    svc.bridgeDir = folder
    await svc.start()
    try {
      const a = io(['--dir', home, '--input-hook'])
      const done = run({ ...a.io, env: { HOME: home, OMPCODE: '1' } })
      await new Promise((r) => setTimeout(r, 30))
      a.stdin.write(
        frame({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'omp' } },
        }),
      )
      await svc.next((m) => m.method === 'initialize')
      expect(await postBridge(home, [process.pid])).toBe(folder)
      expect(svc.hellos[0]?.client_capabilities).toEqual({ experimental: { 'bag.dev/consent-bridge': {} } })
      expect(readdirSync(folder)).toEqual([])
      a.handlers.get('SIGINT')?.()
      expect(await done).toBe(0)
    } finally {
      await svc.close()
    }
  })

  it('the hook stays silent with no home', async () => {
    const stdin = new PassThrough()
    const out = new PassThrough()
    const a = io(['hook'], { stdin, stdout: out, env: {} })
    const done = run(a.io)
    stdin.end(JSON.stringify({ prompt: 'use omp' }))
    expect(await done).toBe(0)
    expect(out.read()).toBeNull()
  })
})

describe('more edge branches', () => {
  it('finds no entry when the current version has no bag-mcp.js, and starts without the log when it cannot open it', () => {
    mkdirSync(join(home, 'package', 'versions', '2.0.0'), { recursive: true })
    writeFileSync(join(home, 'package', 'current'), '2.0.0\n')
    expect(serviceEntry(home)).toBeNull()
    writeFileSync(join(home, 'package', 'versions', '2.0.0', 'bag-mcp.js'), '')
    mkdirSync(join(home, 'run'), { mode: 0o755 })
    const events: string[] = []
    expect(startService(home, {}, (e) => events.push(e))).toBe(true)
    expect(events).toEqual(['service-log-failed'])
  })

  it('reads a channel request split across writes, and refuses an index without a secret', async () => {
    const ch = await openChannel(
      home,
      321,
      654,
      { use: async () => ({ bound: false as const, code: 'x' }), typed: () => true, bridge: () => null },
      () => {},
      103,
    )
    const idx = JSON.parse(readFileSync(join(home, 'run', 'shim', '321.json'), 'utf8')) as {
      sock: string
      secret: string
    }
    const got = await new Promise<string>((resolve) => {
      const c = createConnection({ path: join(home, 'run', 'shim', idx.sock) })
      let out = ''
      c.on('connect', () => {
        const line = `${JSON.stringify({ v: 1, kind: 'typed', secret: idx.secret })}\n`
        c.write(line.slice(0, 10))
        setTimeout(() => c.write(line.slice(10)), 20)
      })
      c.on('data', (d: Buffer) => (out += d.toString()))
      c.on('close', () => resolve(out))
    })
    expect(JSON.parse(got)).toEqual({ typed: true })
    // A use on the same channel gets the handler's own answer.
    expect(await postUse(home, [321], 'omp')).toEqual({ bound: false, code: 'x' })
    ch?.close()
    writeFileSync(join(home, 'run', 'shim', '77.json'), JSON.stringify({ v: 1, sock: 'abcdef01.sock' }))
    expect(await postUse(home, [77], 'omp', 200)).toBeNull()
  })

  it('the hook ignores a prompt that is not a string; the shim stops on a stdout error that is not EPIPE', async () => {
    const stdin = new PassThrough()
    const stdout = new PassThrough()
    let done = run({
      argv: ['hook', '--dir', home],
      env: {},
      cwd: home,
      pid: 1,
      ppid: process.pid,
      stdin,
      stdout,
      stderr: { write: () => true },
      signals: { once: () => {}, removeListener: () => {} },
      ps: () => null,
    })
    stdin.end(JSON.stringify({ prompt: 5 }))
    expect(await done).toBe(0)
    expect(stdout.read()).toBeNull()
    let err = ''
    const out2 = new PassThrough()
    done = run({
      argv: ['--dir', home],
      env: {},
      cwd: home,
      pid: 2,
      ppid: process.pid,
      stdin: new PassThrough(),
      stdout: out2,
      stderr: { write: (t: string) => (err += t) },
      signals: { once: () => {}, removeListener: () => {} },
      ps: () => null,
      startService: () => false,
    })
    await new Promise((r) => setTimeout(r, 20))
    out2.emit('error', Object.assign(new Error('io'), { code: 'EIO' }))
    expect(await done).toBe(0)
    expect(err).toContain('"reason":"stdout-error"')
  })
})
