import {
  closeSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { createConnection, createServer } from 'node:net'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  ancestors,
  boundOf,
  endSession,
  hostPidOf,
  indexOf,
  moveSession,
  openChannel,
  ownerHeld,
  type PsRow,
  postUse,
  psRow,
  safeDir,
  sessionKey,
  startOf,
  terminalOwner,
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
import { hostKind, surfaceOf, toolTimeoutMs } from '../src/host.ts'
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
    expect(surfaceOf({ CLAUDE_CODE_ENTRYPOINT: 'claude-vscode' })).toBe('claude-vscode')
    expect(surfaceOf({ CLAUDE_CODE_ENTRYPOINT: 'claude-desktop' })).toBe('claude-desktop')
    expect(surfaceOf({ CLAUDE_CODE_ENTRYPOINT: 'cli' })).toBe('cli')
    expect(surfaceOf({ CLAUDE_CODE_ENTRYPOINT: 'CLI' })).toBeNull()
    expect(surfaceOf({})).toBeNull()
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
    expect(psRow(process.pid)?.uid).toBe(process.getuid?.())
    expect(psRow(0x7ffffff0)).toBeNull()
  })

  // The two trees measured on 2026-11-23 (ps pid, ppid, tty, comm only): omp 19.1.0, three windows on ttys014-016 and
  // one terminal-less core (the parent of window 1's shim and of the other two windows' shims); omp 18.20.0, each shim
  // under its own window, which holds the terminal.
  const ME = 501
  const tree: Record<number, NonNullable<PsRow>> = {
    90872: { ppid: 79942, comm: 'omp', uid: ME, tty: 'ttys014' },
    90977: { ppid: 82787, comm: 'omp', uid: ME, tty: 'ttys015' },
    91141: { ppid: 83618, comm: 'omp', uid: ME, tty: 'ttys016' },
    90985: { ppid: 90872, comm: 'omp', uid: ME, tty: null },
    8400: { ppid: 8045, comm: 'omp', uid: ME, tty: 'ttys006' },
    67506: { ppid: 94415, comm: 'omp', uid: ME, tty: 'ttys008' },
    62646: { ppid: 8400, comm: 'omp', uid: ME, tty: null },
    5100: { ppid: 5000, comm: 'claude', uid: ME, tty: 'ttys006' },
    5200: { ppid: 8400, comm: 'omp', uid: ME, tty: 'ttys006' },
    6000: { ppid: 1, comm: 'omp', uid: 0, tty: 'ttys020' },
    6100: { ppid: 1, comm: 'zsh', uid: ME, tty: 'ttys021' },
    6200: { ppid: 1, comm: 'omp', uid: ME, tty: null },
  }
  const ps = (pid: number): PsRow => tree[pid] ?? null
  const owner = (walked: number, value: string | undefined) =>
    terminalOwner(walked, value === undefined ? {} : { PI_TERMINAL_OWNER_PID: value }, ps, ME)

  it('takes omp 19 windows from PI_TERMINAL_OWNER_PID behind the terminal-less core', () => {
    expect(hostPidOf(90985, ps)).toBe(90985) // the walk stops at the core: it is not a launcher
    expect(owner(90985, '90872')).toBe(90872) // window 1, the core's own parent
    expect(owner(90985, '90977')).toBe(90977) // windows 2 and 3: not ancestors of their shims
    expect(owner(90985, '91141')).toBe(91141)
  })

  it('keeps the walk wherever the variable is unset, malformed, dead, foreign, not omp or has no terminal', () => {
    expect(owner(90985, undefined)).toBeNull()
    for (const bad of ['', 'abc', '0', '-90872', '90872x', ' 90872', '1e5', '12345678901']) {
      expect(owner(90985, bad)).toBeNull()
    }
    expect(owner(90985, '424242')).toBeNull() // dead: ps has no row
    expect(owner(90985, '6000')).toBeNull() // a live omp of another user
    expect(owner(90985, '6100')).toBeNull() // a live process of this user that is not omp
    expect(owner(90985, '6200')).toBeNull() // an omp with no terminal is not a window
    expect(terminalOwner(90985, { PI_TERMINAL_OWNER_PID: '90977' }, ps, 0)).toBeNull() // not this user's
  })

  it('never reads the variable where the walk ends at a host with a terminal: omp 18, a nested omp, Claude Code', () => {
    expect(owner(8400, '8400')).toBeNull() // omp 18: the owner is the parent; the walk already names it
    expect(owner(67506, '67506')).toBeNull()
    expect(owner(8400, '67506')).toBeNull() // even a different live window: the walk ended at a window
    expect(owner(5200, '8400')).toBeNull() // `omp -p` run from window 8400's shell keeps the terminal
    expect(owner(5100, '8400')).toBeNull() // Claude Code started from an omp window's shell inherits the variable
    expect(owner(6100, '8400')).toBeNull() // a walk that ends at a shell
    const old = (pid: number): PsRow => {
      const row = tree[pid]
      return row === undefined ? null : { ppid: row.ppid, comm: row.comm }
    }
    expect(terminalOwner(90985, { PI_TERMINAL_OWNER_PID: '90977' }, old, ME)).toBeNull() // rows without a tty
    // The named residue: a terminal-less child omp of an omp 18 window takes its window; ownerHeld then keeps a live
    // window shim's files from it (the run test "a second shim with the same owner").
    expect(owner(62646, '8400')).toBe(8400)
  })

  it('sees an owner held while another live shim names its index, bound or ring file', () => {
    mkdirSync(join(home, 'run', 'shim'), { recursive: true, mode: 0o700 })
    expect(ownerHeld(home, 4242, 999_001)).toBe(false) // no file
    for (const file of [indexOf(home, 4242), boundOf(home, 4242), ringOf(home, 4242)]) {
      writeFileSync(file, JSON.stringify({ v: 1, shim: process.pid }), { mode: 0o600 })
      expect(ownerHeld(home, 4242, 999_001)).toBe(true) // a live other shim
      expect(ownerHeld(home, 4242, process.pid)).toBe(false) // this shim's own
      writeFileSync(file, JSON.stringify({ v: 1, shim: 0x7ffffff0 }), { mode: 0o600 })
      expect(ownerHeld(home, 4242, 999_001)).toBe(false) // a dead shim's leftover
      rmSync(file)
    }
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
      },
      log,
      103,
    )
    expect(ch).not.toBeNull()
    expect(await postUse(home, [9, 123], 'omp')).toEqual({ bound: true, as: 'omp' })
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
        { use: async () => ({ bound: false as const, code: 'x' }), typed: () => false },
        log,
        10,
      ),
    ).toBeNull()
    expect(
      await openChannel(
        '/dev/null/x',
        1,
        2,
        { use: async () => ({ bound: false as const, code: 'x' }), typed: () => false },
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

describe('the session files of two Codex windows under one host process', () => {
  // Codex 0.167 runs one server process for all of its TUI windows: both shims have host pid 9.
  const [A, B] = ['0a1b2c3d-0000-4000-8000-00000000000a', '0a1b2c3d-0000-4000-8000-00000000000b']
  const ring = (as: string) => ({ n: 1, as, unread: 1, speaking: true, at: null })

  it('keys a window by <host pid>-<session id> for a uuid only, else by the host pid', () => {
    expect(sessionKey(9, A)).toBe(`9-${A}`)
    expect(sessionKey(9, A.toUpperCase())).toBe(`9-${A}`)
    expect(sessionKey(9, null)).toBe(9)
    expect(sessionKey(9, '../x')).toBe(9)
    expect(sessionKey(9, `${A}.bound`)).toBe(9)
  })

  it('gives each window its own .bound and .ring, and an unbind or an exit removes only its own', () => {
    const dir = join(home, 'run', 'shim')
    const [ka, kb] = [sessionKey(9, A), sessionKey(9, B)]
    writeBound(home, ka, 100, ['id-a'])
    writeBound(home, kb, 200, ['id-b'])
    writeRing(home, ka, 100, ring('id-a'))
    writeRing(home, kb, 200, ring('id-b'))
    for (const f of [`${ka}.ring-seen`, `${kb}.ring-seen`]) writeFileSync(join(dir, f), '1 1\n')
    expect(JSON.parse(readFileSync(boundOf(home, ka), 'utf8'))).toEqual({ v: 1, as: ['id-a'], shim: 100 })
    expect(JSON.parse(readFileSync(boundOf(home, kb), 'utf8'))).toEqual({ v: 1, as: ['id-b'], shim: 200 })
    expect(JSON.parse(readFileSync(ringOf(home, ka), 'utf8')).as).toBe('id-a')
    // B unbinds: A's file stays.
    writeBound(home, kb, 200, [])
    expect(existsSync(boundOf(home, kb))).toBe(false)
    expect(existsSync(boundOf(home, ka))).toBe(true)
    // A's shim exits: its four files go, B's ring and ring-seen stay; a shim never ends another window's key.
    expect(endSession(home, kb, 100)).toBe(false)
    expect(endSession(home, ka, 100)).toBe(true)
    expect(readdirSync(dir).sort()).toEqual([`${kb}.ring`, `${kb}.ring-seen`])
  })

  it("writes the shim's start time into .bound when known, for wake-hook --end's check", () => {
    writeBound(home, sessionKey(9, A), 100, ['id-a'], 'Fri Nov 13 01:00:00 2026')
    expect(JSON.parse(readFileSync(boundOf(home, sessionKey(9, A)), 'utf8'))).toEqual({
      v: 1,
      as: ['id-a'],
      shim: 100,
      started: 'Fri Nov 13 01:00:00 2026',
    })
    expect(startOf(process.pid)).toMatch(/\d{4}$/)
    expect(startOf(0x7ffffff0)).toBeNull()
    writeBound(home, sessionKey(9, A), 100, [])
  })

  it("a second shim with the window's key (a sub-agent's) that binds and exits leaves the window's files", () => {
    const dir = join(home, 'run', 'shim')
    const k = sessionKey(9, A)
    const parent = process.pid // alive
    writeBound(home, k, parent, ['id-a'])
    writeRing(home, k, parent, ring('id-a'))
    writeFileSync(join(dir, `${k}.ring-seen`), `${parent} 1\n`)
    // The second shim binds (the parent's identity or another) and rings: nothing of the window's is replaced.
    writeBound(home, k, 777_001, ['id-a'])
    writeRing(home, k, 777_001, ring('id-b'))
    expect(JSON.parse(readFileSync(boundOf(home, k), 'utf8')).shim).toBe(parent)
    expect(JSON.parse(readFileSync(ringOf(home, k), 'utf8'))).toMatchObject({ as: 'id-a', shim: parent })
    // It unbinds and exits: it removes nothing, for nothing there names it.
    writeBound(home, k, 777_001, [])
    expect(endSession(home, k, 777_001)).toBe(false)
    expect(readdirSync(dir).sort()).toEqual([`${k}.bound`, `${k}.ring`, `${k}.ring-seen`])
    // The window's next ring is written: its wake still rings.
    writeRing(home, k, parent, { ...ring('id-a'), n: 2 })
    expect(JSON.parse(readFileSync(ringOf(home, k), 'utf8'))).toMatchObject({ n: 2, shim: parent })
    // A window's shim that is gone no longer holds the key; and a host pid key keeps "the newest shim writes".
    writeBound(home, k, 0x7ffffff0, ['x'])
    writeBound(home, k, 777_001, ['id-b'])
    expect(JSON.parse(readFileSync(boundOf(home, k), 'utf8')).shim).toBe(parent)
    rmSync(boundOf(home, k))
    writeBound(home, k, 0x7ffffff0, ['x'])
    writeBound(home, k, 777_001, ['id-b'])
    expect(JSON.parse(readFileSync(boundOf(home, k), 'utf8')).shim).toBe(777_001)
    writeBound(home, 9, parent, ['cc'])
    writeBound(home, 9, 777_001, ['cc'])
    expect(JSON.parse(readFileSync(boundOf(home, 9), 'utf8')).shim).toBe(777_001)
  })

  it('moves a binding to the window key when a tool call names the window, or a new session starts in it', () => {
    const dir = join(home, 'run', 'shim')
    writeBound(home, 9, 100, ['id-a'])
    moveSession(home, 9, sessionKey(9, A), 100, ['id-a'])
    expect(readdirSync(dir)).toEqual([`9-${A}.bound`])
    moveSession(home, sessionKey(9, A), sessionKey(9, B), 100, ['id-a'])
    expect(readdirSync(dir)).toEqual([`9-${B}.bound`])
    // Unbound: the old key's files go and nothing is written.
    moveSession(home, sessionKey(9, B), sessionKey(9, A), 100, [])
    expect(readdirSync(dir)).toEqual([])
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
        on: (e, l) => handlers.set(e, l),
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

  it('serves an omp session in process: the hello carries the omp pid capability, and the channel names no folder', async () => {
    const svc = new FakeService(home)
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
      expect(svc.hellos[0]?.client_capabilities).toEqual({
        experimental: { 'bag.dev/consent-bridge': { pid: expect.any(Number) } }, // the omp pid (item 7)
      })
      // 0.4.2: no bridge folder; the channel's generation-one "bridge" request is gone (channel.ts).
      expect(existsSync(join(home, 'run', 'shim', `${process.pid}.consent`))).toBe(false)
      a.handlers.get('SIGINT')?.()
      expect(await done).toBe(0)
    } finally {
      await svc.close()
    }
  })

  // omp 19 in process: the shim's parent is the terminal-less core 700_001, whose own parent is window 1 (700_005); the
  // window this shim serves is 700_002, named only by PI_TERMINAL_OWNER_PID (not an ancestor: windows two and three).
  const CORE = 700_001
  const WINDOW_ONE = 700_005
  const WINDOW = 700_002
  const UID = 4242
  const omp19: Record<number, NonNullable<PsRow>> = {
    [CORE]: { ppid: WINDOW_ONE, comm: 'omp', uid: UID, tty: null },
    [WINDOW_ONE]: { ppid: 1, comm: 'omp', uid: UID, tty: 'ttys014' },
    [WINDOW]: { ppid: 1, comm: 'omp', uid: UID, tty: 'ttys015' },
  }
  const ompIo = (argv: string[], starts: Map<number, string>, more: Partial<ShimIo> = {}) =>
    io(argv, {
      env: { HOME: home, OMPCODE: '1', PI_TERMINAL_OWNER_PID: String(WINDOW) },
      ppid: CORE,
      ps: (pid) => omp19[pid] ?? null,
      uid: UID,
      startOf: (pid) => starts.get(pid) ?? null,
      ...more,
    })
  const initOmp = (a: { stdin: PassThrough }) =>
    a.stdin.write(
      frame({
        jsonrpc: '2.0',
        id: 0,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'omp' } },
      }),
    )
  const bridgeOf = (h: Record<string, unknown> | undefined) =>
    (h?.client_capabilities as { experimental?: Record<string, unknown> } | undefined)?.experimental?.[
      'bag.dev/consent-bridge'
    ]
  const waitFor = async (ok: () => boolean) => {
    for (let i = 0; i < 200 && !ok(); i++) await new Promise((r) => setTimeout(r, 10))
  }

  it('omp 19: keys the window by PI_TERMINAL_OWNER_PID behind the core, in the hello, the files and the hook', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const a = ompIo(['--dir', home, '--input-hook'], new Map([[WINDOW, 'Mon Nov 23 00:10:00 2026']]))
      const done = run(a.io)
      await new Promise((r) => setTimeout(r, 30))
      initOmp(a)
      await svc.next((m) => m.method === 'initialize')
      expect(bridgeOf(svc.hellos[0])).toEqual({ pid: WINDOW }) // the window, never the core
      expect(existsSync(indexOf(home, WINDOW))).toBe(true)
      expect(existsSync(indexOf(home, CORE))).toBe(false)
      svc.notify('service/ring', { as: 'omp', speaking: true })
      await waitFor(() => existsSync(ringOf(home, WINDOW)))
      expect(JSON.parse(readFileSync(ringOf(home, WINDOW), 'utf8'))).toMatchObject({
        as: 'omp',
        shim: 999_001,
      })
      // The hook in the same tree finds this shim through the owner (it is not among the core's ancestors).
      const stdin = new PassThrough()
      const stdout = new PassThrough()
      const h = ompIo(['hook', '--dir', home], new Map(), { stdin, stdout })
      const p = run(h.io)
      stdin.end(JSON.stringify({ prompt: 'use omp' }))
      await p
      expect(JSON.parse(String(stdout.read() ?? ''))).toEqual({
        decision: 'block',
        reason: 'bag: this session now acts as omp.',
      })
      expect(a.err()).toContain('"event":"host","from":"owner"')
      a.handlers.get('SIGINT')?.()
      expect(await done).toBe(0)
    } finally {
      await svc.close()
    }
  })

  for (const [why, later] of [
    ['dies', null],
    ['is reused by another process (another start time)', 'Mon Nov 23 09:00:00 2026'],
  ] as const) {
    it(`omp 19: when the window ${why}, no bridge pid, no wake file, its own files gone, never the core`, async () => {
      const svc = new FakeService(home)
      await svc.start()
      const starts = new Map([[WINDOW, 'Mon Nov 23 00:10:00 2026']])
      const a = ompIo(['--dir', home, '--input-hook'], starts)
      const done = run(a.io)
      try {
        await new Promise((r) => setTimeout(r, 30))
        initOmp(a)
        await svc.next((m) => m.method === 'initialize')
        await waitFor(() => a.err().includes('"connected"'))
        svc.notify('service/bound', { as: 'omp', granted: 'dialog' })
        await waitFor(() => existsSync(boundOf(home, WINDOW)))
        expect(existsSync(boundOf(home, WINDOW))).toBe(true)
        if (later === null) starts.delete(WINDOW)
        else starts.set(WINDOW, later)
        svc.notify('service/ring', { as: 'omp', speaking: true })
        await waitFor(() => a.err().includes('"event":"host-gone"'))
        expect(a.err()).toContain('"event":"host-gone"')
        expect(existsSync(ringOf(home, WINDOW))).toBe(false) // no wake file written
        expect(existsSync(boundOf(home, WINDOW))).toBe(false) // this shim's own, removed
        expect(existsSync(indexOf(home, WINDOW))).toBe(false) // the typed-word channel, closed
        expect(existsSync(ringOf(home, CORE))).toBe(false) // never the core's pid in its place
        expect(existsSync(boundOf(home, CORE))).toBe(false)
        a.handlers.get('SIGUSR2')?.() // a release: the shim connects again and sends a new hello
        await waitFor(() => svc.hellos.length >= 2)
        expect(bridgeOf(svc.hellos[1])).toEqual({}) // the bridge with no pid: no window is named
      } finally {
        // Stopped whatever an assertion did: a shim left running keeps openChannel's umask for the tests after it.
        a.handlers.get('SIGINT')?.()
        expect(await done).toBe(0)
        await svc.close()
      }
    })
  }

  it('omp 19: a second shim with the same owner keeps the walk while the first is alive, and takes it once it is dead', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      mkdirSync(join(home, 'run', 'shim'), { recursive: true, mode: 0o700 })
      const first = { v: 1, sock: 'x', secret: 's', shim: process.pid } // a live shim: this test process
      for (const f of [indexOf(home, WINDOW), boundOf(home, WINDOW), ringOf(home, WINDOW)])
        writeFileSync(f, JSON.stringify(first), { mode: 0o600 })
      const before = [indexOf(home, WINDOW), boundOf(home, WINDOW), ringOf(home, WINDOW)].map((f) =>
        readFileSync(f, 'utf8'),
      )
      const starts = new Map([[WINDOW, 'Mon Nov 23 00:10:00 2026']])
      const a = ompIo(['--dir', home, '--input-hook'], starts)
      const done = run(a.io)
      await new Promise((r) => setTimeout(r, 30))
      initOmp(a)
      await svc.next((m) => m.method === 'initialize')
      expect(bridgeOf(svc.hellos[0])).toEqual({ pid: CORE }) // the walk, as before the change
      svc.notify('service/ring', { as: 'omp', speaking: true })
      await waitFor(() => existsSync(ringOf(home, CORE)))
      const after = [indexOf(home, WINDOW), boundOf(home, WINDOW), ringOf(home, WINDOW)].map((f) =>
        readFileSync(f, 'utf8'),
      )
      expect(after).toEqual(before) // the first shim's .json, .bound and .ring untouched
      expect(a.err()).toContain('"event":"host","from":"parent","owner":"held"')
      a.handlers.get('SIGINT')?.()
      expect(await done).toBe(0)

      // The first shim dead (a leftover naming a dead pid): the next shim takes the window.
      const dead = { ...first, shim: 0x7ffffff0 }
      for (const f of [indexOf(home, WINDOW), boundOf(home, WINDOW), ringOf(home, WINDOW)])
        writeFileSync(f, JSON.stringify(dead), { mode: 0o600 })
      const b = ompIo(['--dir', home, '--input-hook'], starts)
      const done2 = run(b.io)
      await new Promise((r) => setTimeout(r, 30))
      initOmp(b)
      await waitFor(() => svc.hellos.length >= 2)
      expect(bridgeOf(svc.hellos.at(-1))).toEqual({ pid: WINDOW })
      b.handlers.get('SIGINT')?.()
      expect(await done2).toBe(0)
    } finally {
      await svc.close()
    }
  })

  // The 23:31 UTC report: one local mail to new-omp-1 acted on by two omp 19 windows. Before this change every shim of
  // the core keyed the core, so no window had a <window pid>.bound; omp-wake then watched the identity's doorbell in
  // each window (omp-wake.ts ringMode), and one accepted mail woke them all. Each window now has its own key.
  it('omp 19: two windows on one core, two keys: a typed use from window one binds shim one only, a ring wakes window one only', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const starts = new Map([
        [WINDOW_ONE, 'Mon Nov 23 00:09:00 2026'],
        [WINDOW, 'Mon Nov 23 00:10:00 2026'],
      ])
      const env = (w: number) => ({ HOME: home, OMPCODE: '1', PI_TERMINAL_OWNER_PID: String(w) })
      const a = ompIo(['--dir', home, '--input-hook'], starts, { env: env(WINDOW_ONE), pid: 999_101 })
      const b = ompIo(['--dir', home, '--input-hook'], starts, { env: env(WINDOW), pid: 999_102 })
      // One after the other: openChannel holds umask 077 across its listen, and two openings at once in one process
      // would leave it there for every later test (a host runs one shim per process, so only a test can interleave).
      const done = [run(a.io)]
      await waitFor(() => existsSync(indexOf(home, WINDOW_ONE)))
      done.push(run(b.io))
      await waitFor(() => existsSync(indexOf(home, WINDOW)))
      initOmp(a)
      initOmp(b)
      await waitFor(() => svc.hellos.length >= 2)
      const connOf = (w: number) =>
        svc.conns.find((c) => (bridgeOf(c.hello ?? undefined) as { pid?: number })?.pid === w)
      const [one, two] = [connOf(WINDOW_ONE), connOf(WINDOW)]
      expect(one).toBeDefined()
      expect(two).toBeDefined()
      expect(existsSync(indexOf(home, WINDOW_ONE)) && existsSync(indexOf(home, WINDOW))).toBe(true)
      // The typed word from window one's hook (its omp-wake reads <window one>.json the same way).
      const stdin = new PassThrough()
      const stdout = new PassThrough()
      const h = ompIo(['hook', '--dir', home], starts, { env: env(WINDOW_ONE), stdin, stdout })
      const p = run(h.io)
      stdin.end(JSON.stringify({ prompt: 'use new-omp-1' }))
      await p
      expect(JSON.parse(String(stdout.read() ?? ''))).toMatchObject({ decision: 'block' })
      const uses = (c: typeof one) => c?.got.filter((m) => m.method === 'service/use').length ?? -1
      expect(uses(one)).toBe(1)
      expect(uses(two)).toBe(0)
      // The service rings the connection bound to the identity (wake-router.ts ring): window one's file only.
      one?.send({
        jsonrpc: '2.0',
        method: 'service/ring',
        params: { as: 'new-omp-1', unread: 1, speaking: true },
      })
      await waitFor(() => existsSync(ringOf(home, WINDOW_ONE)))
      expect(JSON.parse(readFileSync(ringOf(home, WINDOW_ONE), 'utf8'))).toMatchObject({
        as: 'new-omp-1',
        shim: 999_101,
      })
      expect(existsSync(ringOf(home, WINDOW))).toBe(false)
      expect(existsSync(ringOf(home, CORE))).toBe(false)
      a.handlers.get('SIGINT')?.()
      b.handlers.get('SIGINT')?.()
      expect(await Promise.all(done)).toEqual([0, 0])
    } finally {
      await svc.close()
    }
  })

  it('omp 18: the owner is the parent, so the hello, the files and the log are as before the change', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const win = 8400
      const tree18: Record<number, NonNullable<PsRow>> = {
        [win]: { ppid: 8045, comm: 'omp', uid: UID, tty: 'ttys006' },
      }
      const runOnce = async (env: Record<string, string>) => {
        const a = io(['--dir', home, '--input-hook'], {
          env,
          ppid: win,
          ps: (pid) => tree18[pid] ?? null,
          uid: UID,
          startOf: () => 'Mon Nov 23 00:10:00 2026',
        })
        const done = run(a.io)
        await new Promise((r) => setTimeout(r, 30))
        initOmp(a)
        const n = svc.hellos.length
        await waitFor(() => svc.hellos.length > n)
        const hello = svc.hellos.at(-1)
        const files = readdirSync(join(home, 'run', 'shim'))
          .filter((f) => /\.(json|bound|ring)$/.test(f))
          .sort()
        a.handlers.get('SIGINT')?.()
        expect(await done).toBe(0)
        return { bridge: bridgeOf(hello), files, host: a.err().includes('"event":"host"') }
      }
      const without = await runOnce({ HOME: home, OMPCODE: '1' })
      const withOwner = await runOnce({ HOME: home, OMPCODE: '1', PI_TERMINAL_OWNER_PID: String(win) })
      expect(without).toEqual({ bridge: { pid: win }, files: [`${win}.json`], host: false })
      expect(withOwner).toEqual(without)
    } finally {
      await svc.close()
    }
  })

  it('on SIGUSR2 removes the session files and connects again unbound, and keeps serving', async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const a = io(['--dir', home])
      const done = run(a.io)
      await new Promise((r) => setTimeout(r, 30))
      a.stdin.write(
        frame({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'claude-code' } },
        }),
      )
      await svc.next((m) => m.method === 'initialize')
      for (let i = 0; i < 100 && !a.err().includes('"connected"'); i++)
        await new Promise((r) => setTimeout(r, 10))
      svc.notify('service/bound', { as: 'id-a', granted: 'dialog' })
      const dir = join(home, 'run', 'shim')
      const bound = () => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.bound')) : [])
      for (let i = 0; i < 100 && bound().length === 0; i++) await new Promise((r) => setTimeout(r, 10))
      expect(bound()).toHaveLength(1)
      const onRelease = a.handlers.get('SIGUSR2')
      onRelease?.()
      expect(bound()).toEqual([])
      // A second SessionEnd during the release: the one handler, still registered (on), takes it; nothing exits.
      expect(a.handlers.get('SIGUSR2')).toBe(onRelease)
      onRelease?.()
      for (let i = 0; i < 200 && svc.hellos.length < 2; i++) await new Promise((r) => setTimeout(r, 10))
      expect(svc.hellos.length).toBe(2)
      expect(a.handlers.get('SIGUSR2')).toBe(onRelease)
      a.handlers.get('SIGINT')?.()
      expect(await done).toBe(0)
      expect(a.handlers.has('SIGUSR2')).toBe(false)
    } finally {
      await svc.close()
    }
  })

  it("a Codex sub-agent's shim (the window's sessionId, its own threadId) writes no wake files when it binds", async () => {
    const svc = new FakeService(home)
    await svc.start()
    try {
      const a = io(['--dir', home])
      const done = run({ ...a.io, env: { HOME: home } })
      await new Promise((r) => setTimeout(r, 30))
      a.stdin.write(
        frame({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'codex-mcp-client' },
          },
        }),
      )
      await svc.next((m) => m.method === 'initialize')
      for (let i = 0; i < 100 && !a.err().includes('"connected"'); i++)
        await new Promise((r) => setTimeout(r, 10))
      const sid = '0a1b2c3d-0000-4000-8000-00000000000a'
      const meta = { sessionId: sid, threadId: '0a1b2c3d-0000-4000-8000-0000000000ff' }
      a.stdin.write(
        frame({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'status', _meta: meta } }),
      )
      await svc.next((m) => m.method === 'tools/call')
      svc.notify('service/bound', { as: 'id-a', granted: 'typed' })
      for (let i = 0; i < 100 && !a.err().includes('"bound"'); i++)
        await new Promise((r) => setTimeout(r, 10))
      await new Promise((r) => setTimeout(r, 30))
      const dir = join(home, 'run', 'shim')
      expect(existsSync(dir) ? readdirSync(dir).filter((f) => /\.(bound|ring)$/.test(f)) : []).toEqual([])
      expect(a.err()).toContain('"subagent"')
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
      { use: async () => ({ bound: false as const, code: 'x' }), typed: () => true },
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
      signals: { once: () => {}, on: () => {}, removeListener: () => {} },
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
      signals: { once: () => {}, on: () => {}, removeListener: () => {} },
      ps: () => null,
      startService: () => false,
    })
    await new Promise((r) => setTimeout(r, 20))
    out2.emit('error', Object.assign(new Error('io'), { code: 'EIO' }))
    expect(await done).toBe(0)
    expect(err).toContain('"reason":"stdout-error"')
  })
})
