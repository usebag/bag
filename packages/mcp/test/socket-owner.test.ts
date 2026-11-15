import { execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { createConnection, createServer, type Socket } from 'node:net'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  FD_MAX,
  holds,
  LSOF_PINNED,
  lsofPeer,
  PEER_MS,
  type ProcFs,
  peerIs,
  run,
  serviceFd,
  ssPeer,
  within,
} from '../src/socket-owner.ts'

// The peer lookup of a consent registration. LIVE is lsof's output recorded on a Mac; the ss rows are made up, shaped
// like ss -xnH output, with other sockets' rows and a socket with no peer.

/**
 * RECORDED, not made up: `/usr/sbin/lsof -nPw -U -a -p 68953,68954 -F pfdn`, lsof 4.91, macOS 15.7 (24G222),
 * Darwin 24.6.0, 2026-11-15 07:46 UTC. Three node processes: a unix socket server 68953 (its listener fd 12; fd 13
 * accepted from 68954; fd 14 accepted from 68956, which is not listed) and the client 68954 (its end fd 12). Each
 * process's fd 1 is the stdout pipe its parent gave it. Verbatim but for the line breaks.
 */
const LIVE = [
  'p68953',
  'f1',
  'd0x11c7d9f2510a3822',
  'n->0xa37e5f7e8c60418e',
  'f12',
  'd0xc2b7df66d227326d',
  'ns.sock',
  'f13',
  'd0x2f5f52dca9734ed9',
  'ns.sock',
  'f14',
  'd0xfbe681a3c99aed77',
  'ns.sock',
  'p68954',
  'f1',
  'd0xf2b94bd4ed1736b0',
  'n->0x832f1048acd39667',
  'f12',
  'd0x636dd5c72c261d22',
  'n->0x2f5f52dca9734ed9',
  '',
].join('\n')
const S = 68953
const P = 68954
const M = 68956

/** Made-up ss -xnH rows: the service end is inode 9001, its peer 9002; one listening socket, one with no peer. */
const SS = [
  'u_str LISTEN 0      511    /home/u/.bag/run/service.sock 8000            * 0',
  'u_str ESTAB  0      0      /home/u/.bag/run/service.sock 9001            * 9002',
  'u_str ESTAB  0      0      * 9002            * 9001',
  'u_str ESTAB  0      0      /run/dbus/system_bus_socket 7001            * 7002',
  'u_dgr UNCONN 0      0      * 6001            * 0',
  '',
].join('\n')

describe('lsofPeer reads lsof -F pfdn records in the recorded form only', () => {
  it("matches the client whose end is named '->' the service end's address, and only that exact pair", () => {
    expect(lsofPeer(LIVE, S, 13, P)).toBe('match')
    // Another process's registration claiming P: its own accepted end has no row of P pointing at it.
    expect(lsofPeer(LIVE, S, 14, P)).toBe('other')
    // The right connection but another pid asked: not listed, or the service itself.
    expect(lsofPeer(LIVE, S, 13, M)).toBe('other')
    expect(lsofPeer(LIVE, S, 13, S)).toBe('other')
    // The service end not listed at all: no answer.
    expect(lsofPeer(LIVE, S, 99, P)).toBeNull()
  })

  it('refuses any form the recording does not show', () => {
    // The service end named as pointing somewhere (here its stdout pipe): not an accepted end, no answer.
    expect(lsofPeer(LIVE, S, 1, P)).toBeNull()
    // The service end with no 0x address.
    expect(lsofPeer(LIVE.replace('d0x2f5f52dca9734ed9', 'd2f5f52dca9734ed9'), S, 13, P)).toBeNull()
    expect(lsofPeer(LIVE.replace('d0x2f5f52dca9734ed9', 'd'), S, 13, P)).toBeNull()
    // The client's name in another spelling of the address: no match.
    expect(lsofPeer(LIVE.replace('n->0x2f5f52dca9734ed9', 'n->2f5f52dca9734ed9'), S, 13, P)).toBe('other')
    expect(lsofPeer(LIVE.replace('n->0x2f5f52dca9734ed9', 'n->0x2F5F52DCA9734ED9'), S, 13, P)).toBe('other')
    // The pairing read the other way round (the service end named after the client's address): never read.
    const flipped = ['p500', 'f14', 'd0xaaa1', 'n->0xbbb2', 'p600', 'f9', 'd0xbbb2', 'n/some/path', ''].join(
      '\n',
    )
    expect(lsofPeer(flipped, 500, 14, 600)).toBeNull()
  })
})

describe('ssPeer reads ss -xnH rows (made-up samples)', () => {
  it("answers the peer inode of the service end's own inode", () => {
    expect(ssPeer(SS, '9001')).toBe('9002')
    expect(ssPeer(SS, '9002')).toBe('9001')
  })
  it('answers null for a socket with no peer and for one not listed', () => {
    expect(ssPeer(SS, '6001')).toBeNull()
    expect(ssPeer(SS, '8000')).toBeNull()
    expect(ssPeer(SS, '1234')).toBeNull()
  })
})

describe('the service end file descriptor', () => {
  it("an accepted socket's _handle.fd is a non-negative integer (pinned: a Node change shows here)", async () => {
    const dir = mkdtempSync('/tmp/bpp-')
    const server = createServer()
    const accepted = new Promise<Socket>((r) => server.once('connection', r))
    await new Promise<void>((r) => server.listen(join(dir, 's.sock'), () => r()))
    const client = createConnection(join(dir, 's.sock'))
    const end = await accepted
    const fd = (end as unknown as { _handle?: { fd?: unknown } })._handle?.fd
    expect(Number.isSafeInteger(fd) && (fd as number) >= 0).toBe(true)
    expect(serviceFd(end)).toBe(fd)
    client.destroy()
    end.destroy()
    await new Promise<void>((r) => server.close(() => r()))
    rmSync(dir, { recursive: true, force: true })
  })

  it('a missing handle, a missing fd or a non-integer fd is null, and the lookup answers unavailable', async () => {
    for (const s of [
      null,
      {},
      { _handle: null },
      { _handle: {} },
      { _handle: { fd: '3' } },
      { _handle: { fd: 1.5 } },
    ])
      expect(serviceFd(s)).toBeNull()
    expect(serviceFd({ _handle: { fd: -1 } })).toBeNull()
    expect(await peerIs({ _handle: { fd: '3' } } as unknown as Socket, process.pid)).toBe('unavailable')
  })
})

describe("one lookup child's answer", () => {
  it('too much output is no answer (unavailable), not a timeout; a child past its limit is a timeout', async () => {
    const loud = ['-e', 'process.stdout.write("x".repeat(4096))']
    expect(await run(process.execPath, loud, PEER_MS, 1024)).toBeNull()
    expect(await run(process.execPath, loud, PEER_MS)).toBe('x'.repeat(4096))
    expect(await run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], 300)).toBe('timeout')
  })
})

describe("the Linux /proc walk, under the lookup's one deadline (fake /proc)", () => {
  const fake = (n: number, link: (path: string) => Promise<string>): ProcFs => ({
    readdir: async () => Array.from({ length: n }, (_, i) => String(i)),
    readlink: link,
  })
  it('matches the fd linked to the peer inode, else other', async () => {
    const fs = fake(5, async (p) => (p === '/proc/600/fd/3' ? 'socket:[9002]' : 'pipe:[1]'))
    expect(await holds(600, '9002', fs)).toBe('match')
    expect(await holds(600, '9003', fs)).toBe('other')
  })
  it('a process with more open files than the cap is unavailable, at once and with no link read', async () => {
    expect(FD_MAX).toBe(4096)
    let read = 0
    const link = async () => {
      read++
      return ''
    }
    const t = Date.now()
    expect(await holds(600, '9002', fake(100_000, link))).toBe('unavailable')
    expect(read).toBe(0)
    expect(Date.now() - t).toBeLessThan(PEER_MS)
    expect(await holds(600, '9002', fake(FD_MAX, link))).toBe('other')
  })
  it('a walk that never ends answers timeout at the deadline, while it is still reading', async () => {
    const t = Date.now()
    const stuck = fake(FD_MAX, () => new Promise<string>(() => {}))
    expect(await within(holds(600, '9002', stuck), 200)).toBe('timeout')
    expect(Date.now() - t).toBeLessThan(1000)
    // A lookup that rejects is unavailable, never a match.
    expect(await within(Promise.reject(new Error('x')), 200)).toBe('unavailable')
  })
})

describe('the real lookup on this machine', () => {
  it('omp holding the other end matches; another process does not; macOS with the pin off answers unavailable', async (ctx) => {
    expect(PEER_MS).toBe(3000)
    expect(LSOF_PINNED).toBe(true)
    const dir = mkdtempSync('/tmp/bpp-')
    const server = createServer()
    const accepted = new Promise<Socket>((r) => server.once('connection', r))
    await new Promise<void>((r) => server.listen(join(dir, 's.sock'), () => r()))
    const client = createConnection(join(dir, 's.sock'))
    const end = await accepted
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { stdio: 'ignore' })
    const other = child.pid as number
    try {
      const ss = ['/usr/bin/ss', '/usr/sbin/ss', '/bin/ss'].some((f) => existsSync(f))
      if (process.platform === 'linux' && !ss) {
        // Without ss the lookup cannot run: it must refuse (unavailable), and the test says it did not run the rest.
        expect(await peerIs(end, process.pid)).toBe('unavailable')
        ctx.skip(
          'no ss on this Linux machine (install iproute2): the real lookup did not run; it answered unavailable',
        )
      } else if (process.platform === 'linux') {
        expect(await peerIs(end, process.pid)).toBe('match')
        expect(await peerIs(end, other)).toBe('other')
      } else if (process.platform === 'darwin') {
        expect(await peerIs(end, process.pid)).toBe('match')
        expect(await peerIs(end, other)).toBe('other')
        expect(await peerIs(end, process.pid, PEER_MS, false)).toBe('unavailable')
      } else expect(await peerIs(end, process.pid)).toBe('unavailable')
    } finally {
      child.kill('SIGKILL')
      client.destroy()
      end.destroy()
      await new Promise<void>((r) => server.close(() => r()))
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

/**
 * RECORDED, not made up, 2026-11-15 08:07 UTC, lsof 4.91, macOS 15.7 (24G222), Darwin 24.6.0: a server 91550 (fd 13
 * accepted from 91551), a client 91551 that connected and then spawned `/bin/sh -c 'sleep 30'` with piped stdio, and
 * that child 91552. `lsof -nPw -U -a -p 91550,91552 -F pfdn`: the child holds only its three stdio pipes, none named
 * "->" the accepted end's 0x376736ef427f16ad, so a registration claiming the child is not matched. Verbatim.
 */
const CHILD = [
  'p91550',
  'f1',
  'd0x431d027300396e9b',
  'n->0xe70f81be41eb066a',
  'f12',
  'd0xdceac551b821fa9c',
  'ni.sock',
  'f13',
  'd0x376736ef427f16ad',
  'ni.sock',
  'p91552',
  'f0',
  'd0x497cd67db7fed471',
  'n->0x7fd66bf75ac77687',
  'f1',
  'd0x1393274753988a56',
  'n->0x81a373e71a942274',
  'f2',
  'd0x7eb53342b5165bc',
  'n->0x9b8d4d2ffcc87f2c',
  '',
].join('\n')

describe("a child of the linked process holds no end of the extension's socket", () => {
  it('the recorded child shows no row naming the accepted end: not matched', () => {
    expect(lsofPeer(CHILD, 91550, 13, 91552)).toBe('other')
  })

  it('live: a client connects, then spawns a shell; the client matches, the shell does not', async (ctx) => {
    const ss = ['/usr/bin/ss', '/usr/sbin/ss', '/bin/ss'].some((f) => existsSync(f))
    if (process.platform !== 'darwin' && !(process.platform === 'linux' && ss))
      ctx.skip(
        'no real lookup on this machine (macOS, or Linux with ss, only): the inheritance check did not run',
      )
    const dir = mkdtempSync('/tmp/bpp-')
    const server = createServer()
    const accepted = new Promise<Socket>((r) => server.once('connection', r))
    await new Promise<void>((r) => server.listen(join(dir, 's.sock'), () => r()))
    // The client opens its socket first and spawns its child after, as omp's extension links before a shell runs.
    const code = `const c = require('node:net').connect(${JSON.stringify(join(dir, 's.sock'))}, () => {
      const k = require('node:child_process').spawn('/bin/sh', ['-c', 'sleep 30'], { stdio: 'pipe' })
      console.log(String(k.pid))
    }); setInterval(() => {}, 1000)`
    const client = spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'pipe', 'ignore'] })
    let shell: number | undefined
    let end: Socket | undefined
    // Every wait is bounded inside the try, so a client that never connects fails red and the finally still runs.
    const by = <T>(p: Promise<T>, what: string) =>
      Promise.race([
        p,
        new Promise<never>((_, no) => setTimeout(() => no(new Error(`${what}: none in 8 s`)), 8000).unref()),
      ])
    try {
      shell = await by(
        new Promise<number>((r) => client.stdout.once('data', (b) => r(Number(String(b).trim())))),
        "the client's shell pid",
      )
      end = await by(accepted, "the client's connection")
      expect(Number.isSafeInteger(shell) && shell > 0).toBe(true)
      expect(await peerIs(end, client.pid as number)).toBe('match')
      expect(await peerIs(end, shell)).toBe('other')
      if (process.platform === 'darwin') {
        const fd = serviceFd(end) as number
        const listed = (pids: string) => {
          try {
            return execFileSync('/usr/sbin/lsof', ['-nPw', '-U', '-a', '-p', pids, '-F', 'pfdn'], {
              encoding: 'utf8',
            })
          } catch (e) {
            return String((e as { stdout?: unknown }).stdout ?? '')
          }
        }
        expect(lsofPeer(listed(`${process.pid},${shell}`), process.pid, fd, shell)).toBe('other')
        expect(lsofPeer(listed(`${process.pid},${client.pid}`), process.pid, fd, client.pid as number)).toBe(
          'match',
        )
      }
    } finally {
      // Only the two processes this test started, by their pids: the shell first, then its client.
      // A positive pid only: kill(0) or a negative pid would signal a whole process group.
      for (const p of [shell, client.pid])
        if (p !== undefined && Number.isSafeInteger(p) && p > 0)
          try {
            process.kill(p, 'SIGKILL')
          } catch {}
      end?.destroy()
      await new Promise<void>((r) => server.close(() => r()))
      rmSync(dir, { recursive: true, force: true })
    }
  }, 10_000)
})
