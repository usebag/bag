import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { readdir, readlink } from 'node:fs/promises'
import type { Socket } from 'node:net'

// Whether an omp registering its consent link is the process at the other end of that very connection, read from
// the kernel's socket identity: lsof on macOS, ss and /proc on Linux, each run as a child with a time limit. No
// native code and nothing installed; any doubt answers no match, and the registration is refused.

/** match: `pid` holds the other end; other: it does not; timeout and unavailable: no answer, refused alike. */
export type Peer = 'match' | 'other' | 'timeout' | 'unavailable'

/** How long one lookup may take, in milliseconds; at the limit its child is killed and the answer is timeout. */
export const PEER_MS = 3000

/**
 * macOS reads lsof in the one form recorded from two live processes (lsof 4.91, macOS 15.7, Darwin 24.6): the
 * accepted end's row is d<its address> with its path as the name, and the client end's row is named "->" that
 * address. lsofPeer accepts that form only; false turns the macOS lookup off (unavailable, refused).
 */
export const LSOF_PINNED = true

/** The service end's file descriptor (Node's internal handle): anything but a non-negative integer is null. */
export function serviceFd(socket: unknown): number | null {
  const fd = (socket as { _handle?: { fd?: unknown } } | null)?._handle?.fd
  return typeof fd === 'number' && Number.isSafeInteger(fd) && fd >= 0 ? fd : null
}

/**
 * One child's output, never blocking: at `ms` it is killed with SIGKILL by Node's handle on that child alone (its
 * own pid), and the answer is timeout. A failed run is null, and so is output past `max` bytes (Node kills that child
 * too, but it is too much output, not too slow); lsof's exit 1 (a pid with no unix socket) keeps its output.
 */
export function run(
  file: string,
  args: readonly string[],
  ms: number,
  max = 16 << 20,
): Promise<string | 'timeout' | null> {
  return new Promise((done) => {
    execFile(file, args, { timeout: ms, killSignal: 'SIGKILL', maxBuffer: max }, (e, out) => {
      if (e === null) return done(String(out))
      if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return done(null)
      done(e.killed === true ? 'timeout' : e.code === 1 && String(out) !== '' ? String(out) : null)
    })
  })
}

/**
 * lsof -F pfdn records (p<pid>, then per file f<fd>, d<address>, n<name>): match when a row of `pid` is named "->"
 * the service end's own 0x address. Null (unavailable) when the service end is not listed or is not in the recorded
 * form: no 0x address, or a name that itself points somewhere.
 */
export function lsofPeer(text: string, service: number, fd: number, pid: number): 'match' | 'other' | null {
  const rows: { p: number; f: string; d: string; n: string }[] = []
  let p = -1
  for (const line of text.split('\n')) {
    const k = line[0]
    const v = line.slice(1)
    const row = rows.at(-1)
    if (k === 'p') p = Number(v)
    else if (k === 'f') rows.push({ p, f: v, d: '', n: '' })
    else if (row !== undefined && (k === 'd' || k === 'n')) row[k] = v
  }
  const own = rows.find((r) => r.p === service && r.f === String(fd))
  if (own === undefined || !/^0x[0-9a-f]+$/.test(own.d) || own.n.startsWith('->')) return null
  return rows.some((r) => r !== own && r.p === pid && r.n === `->${own.d}`) ? 'match' : 'other'
}

/** ss -xnH rows end in the socket's own inode, its peer's address and the peer's inode: the peer of `inode`, or null. */
export function ssPeer(text: string, inode: string): string | null {
  for (const line of text.split('\n')) {
    const t = line.trim().split(/\s+/)
    const far = t.at(-1) ?? ''
    if (t.length >= 6 && t.at(-3) === inode && /^[1-9]\d*$/.test(far)) return far
  }
  return null
}

/** The reads of /proc the Linux lookup makes; a test passes its own. */
export interface ProcFs {
  readonly readdir: (path: string) => Promise<string[]>
  readonly readlink: (path: string) => Promise<string>
}
const PROC: ProcFs = { readdir: (p) => readdir(p), readlink: (p) => readlink(p) }

/** The most open files of omp's process the lookup reads; a process with more is unavailable, refused. */
export const FD_MAX = 4096

/** Whether `pid` holds socket inode `far`, from its /proc fd links (at most FD_MAX of them). */
export async function holds(pid: number, far: string, fs: ProcFs = PROC): Promise<Peer> {
  const fds = await fs.readdir(`/proc/${pid}/fd`).catch(() => null)
  if (fds === null || fds.length > FD_MAX) return 'unavailable'
  for (const f of fds)
    if ((await fs.readlink(`/proc/${pid}/fd/${f}`).catch(() => '')) === `socket:[${far}]`) return 'match'
  return 'other'
}

async function linux(fd: number, pid: number, ms: number, fs: ProcFs): Promise<Peer> {
  const own = /^socket:\[(\d+)\]$/.exec(await fs.readlink(`/proc/self/fd/${fd}`).catch(() => ''))?.[1]
  const ss = ['/usr/bin/ss', '/usr/sbin/ss', '/bin/ss'].find((f) => existsSync(f))
  if (own === undefined || ss === undefined) return 'unavailable'
  const out = await run(ss, ['-xnH'], ms)
  const far = out === null || out === 'timeout' ? null : ssPeer(out, own)
  if (far === null) return out === 'timeout' ? out : 'unavailable'
  return holds(pid, far, fs)
}

/** `lookup`'s answer, or timeout at `ms` whatever it is still doing: one deadline over the whole lookup. */
export function within(lookup: Promise<Peer>, ms: number): Promise<Peer> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<Peer>((r) => {
    timer = setTimeout(r, ms, 'timeout')
  })
  return Promise.race([lookup.catch((): Peer => 'unavailable'), late]).finally(() => clearTimeout(timer))
}

/**
 * Whether `pid` holds the other end of `socket` (the service end of one accepted connection), answered within `ms`:
 * at that deadline the answer is timeout, even while a /proc walk is still reading.
 */
export function peerIs(
  socket: Socket,
  pid: number,
  ms = PEER_MS,
  pinned = LSOF_PINNED,
  fs = PROC,
): Promise<Peer> {
  return within(lookup(socket, pid, ms, pinned, fs), ms)
}

async function lookup(socket: Socket, pid: number, ms: number, pinned: boolean, fs: ProcFs): Promise<Peer> {
  const fd = serviceFd(socket)
  if (fd === null || !Number.isSafeInteger(pid) || pid <= 0) return 'unavailable'
  if (process.platform === 'linux') return linux(fd, pid, ms, fs)
  if (process.platform !== 'darwin' || !pinned) return 'unavailable'
  const out = await run(
    '/usr/sbin/lsof',
    ['-nPw', '-U', '-a', '-p', `${process.pid},${pid}`, '-F', 'pfdn'],
    ms,
  )
  if (out === null || out === 'timeout') return out ?? 'unavailable'
  return lsofPeer(out, process.pid, fd, pid) ?? 'unavailable'
}
