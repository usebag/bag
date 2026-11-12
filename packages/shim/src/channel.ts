// The typed-word channel: how a host's input hook hands the person's own `use <name>` to ITS shim, never to the
// service (contract section 5, service/use via "typed"). The shim makes a per-launch secret at its start (32 random
// bytes, never sent to the service) and listens on a unix socket whose name it draws at random, in <home>/run/shim/
// (0700, the user's, not a link), under the service's own <home>/run/ so that one sandbox deny entry for <home>/run/
// covers the token, the service socket and this channel, for read and write (the red team's requirement: the session's
// model must not be able to write to it). It writes one index file per host process, <home>/run/shim/<host pid>.json
// (0600):
// {v: 1, sock, secret, shim}. A hook finds its shim by walking its own ancestors (the host process is an ancestor of
// both: Claude Code runs the hook through a shell and the shim directly or through a launcher; omp's extension runs in
// the host process itself), reads the index, connects and sends one line: {v: 1, kind: "use", name, secret} for a
// prompt that is exactly `use <name>`, else {v: 1, kind: "typed", secret} (every interactive prompt, so the service
// knows the speaking window: service/typed, svc-mail). The shim compares the secret (timingSafeEqual); for "use" it
// sends service/typed and then service/use via "typed" on its own connection and answers {bound: true, as} or
// {bound: false, code}; for "typed" it sends service/typed and answers {typed: true|false}. The index and the socket go
// when the shim closes.
//
// Its honest limit, the same as the launch token's (contract section 4): same-user is not a security boundary. Any
// process of the user that can read <home>/run/shim/ can read an index and post a typed word for that window; a model's
// unsandboxed shell can. The secret stops other users (with the 0700 directories), every shim after it closes, and a
// process that cannot read or write <home>/run/: the case where the host's sandbox denies the model's tools that path
// (the CLI lane's install writes the deny entry). It does not stop an unsandboxed shell.
import { execFileSync } from 'node:child_process'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { createConnection, createServer, type Server } from 'node:net'
import { join } from 'node:path'
import { LABEL, removeRing, ringOf } from './ring.ts'

/** The pattern a hook matches the whole prompt against (W1's, contract section 5): "use" in any case, the name as typed. */
export const USE_WORD = /^\s*use\s+([a-z0-9][a-z0-9._-]{0,63})\s*$/i

/** The name a prompt binds to, or null for a prompt that is not exactly `use <name>`. */
export function typedName(prompt: string): string | null {
  const m = USE_WORD.exec(prompt)
  const name = m?.[1]
  return name !== undefined && /^[a-z0-9]/.test(name) && LABEL.test(name) ? name : null
}

export const channelDir = (home: string): string => join(home, 'run', 'shim')
export const indexOf = (home: string, hostPid: number): string => join(channelDir(home), `${hostPid}.json`)
export const boundOf = (home: string, hostPid: number): string => join(channelDir(home), `${hostPid}.bound`)

/**
 * Writes <home>/run/shim/<host pid>.bound, the session's bound identities for the wake hook and the omp extension:
 * {"v":1,"as":["omp"],"shim":<pid>}, 0600, written beside and renamed over; removed when the list is empty. A reader
 * ignores a file whose shim pid is not alive (a shim killed by SIGKILL leaves one behind). Errors are the caller's.
 */
export function writeBound(home: string, hostPid: number, shimPid: number, labels: readonly string[]): void {
  const file = boundOf(home, hostPid)
  if (labels.length === 0) {
    removeOwn(file, shimPid)
    return
  }
  if (safeDir(channelDir(home)) !== null)
    throw Object.assign(new Error('unsafe channel directory'), { code: 'unsafe-path' })
  const tmp = `${file}.${shimPid}.tmp`
  writeFileSync(tmp, JSON.stringify({ v: 1, as: labels, shim: shimPid }), { mode: 0o600 })
  renameSync(tmp, file)
}

/**
 * At the shim's exit: when <host pid>.bound or <host pid>.ring still names this shim, removes the wake hook's
 * <host pid>.ring-seen and <host pid>.wake-hook.lock (the CLI lane's, beside the shim's files; the hook recreates them
 * on its next run), then the shim's own .bound and .ring. When neither names it, a newer shim of the same host owns
 * them, and all four stay. True when it removed them.
 */
export function endSession(home: string, hostPid: number, shimPid: number): boolean {
  const names = (file: string): boolean => {
    try {
      return (JSON.parse(readFileSync(file, 'utf8')) as { shim?: unknown }).shim === shimPid
    } catch {
      return false
    }
  }
  if (!names(boundOf(home, hostPid)) && !names(ringOf(home, hostPid))) return false
  for (const f of [`${hostPid}.ring-seen`, `${hostPid}.wake-hook.lock`])
    rmSync(join(channelDir(home), f), { force: true })
  removeOwn(boundOf(home, hostPid), shimPid)
  removeRing(home, hostPid, shimPid)
  return true
}

/** Removes a JSON file of the channel directory only while it still names this shim (a newer shim may own it). */
function removeOwn(file: string, shimPid: number): void {
  try {
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { shim?: unknown }
    if (doc.shim === shimPid) rmSync(file, { force: true })
  } catch {}
}

/** What a typed word comes back as. */
export type UseAnswer =
  | { readonly bound: true; readonly as: string }
  | { readonly bound: false; readonly code: string }

/** What the shim does with a channel request: a bind by typed word, or a plain "the person typed here". */
export interface ChannelHandlers {
  use(name: string): Promise<UseAnswer>
  typed(): boolean
  /** The connection's omp bridge folder from the hello reply, or null before it. */
  bridge(): string | null
}

/** The longest line the channel reads, in bytes: a request is under 200. */
const MAX_REQUEST = 4096

/** A process as ps shows it: its parent and its command's base name. */
export type PsRow = { readonly ppid: number; readonly comm: string } | null

export function psRow(pid: number): PsRow {
  try {
    const out = execFileSync('ps', ['-o', 'ppid=,comm=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const m = /^\s*(\d+)\s+(.+?)\s*$/.exec(out)
    return m === null ? null : { ppid: Number(m[1]), comm: (m[2] as string).split('/').at(-1) as string }
  } catch {
    return null
  }
}

/** Launchers between a host and the process it starts. */
const WRAPPERS = /^(?:-?(?:sh|bash|zsh|dash|fish)|env|npx|npm|pnpm|yarn|bunx|uvx)$/

/**
 * The host process of the shim: its parent, or while the parent is a launcher (a shell, npx, env) that one's parent,
 * up to four steps. Only the parents' command names are read, never a command line.
 */
export function hostPidOf(ppid: number, ps: (pid: number) => PsRow = psRow): number {
  let pid = ppid
  for (let i = 0; i < 4 && pid > 1; i++) {
    const row = ps(pid)
    if (row === null || !WRAPPERS.test(row.comm) || row.ppid <= 1) return pid
    pid = row.ppid
  }
  return pid
}

/** A hook's ancestors, nearest first, up to eight, stopping at pid 1. */
export function ancestors(ppid: number, ps: (pid: number) => PsRow = psRow): number[] {
  const out: number[] = []
  for (let pid = ppid; pid > 1 && out.length < 8; ) {
    out.push(pid)
    const row = ps(pid)
    if (row === null) break
    pid = row.ppid
  }
  return out
}

/** Makes a directory (0700) or checks it: a directory of this user, not a link, no group or other bit. */
export function safeDir(dir: string, uid: number = process.getuid?.() ?? -1): string | null {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const st = lstatSync(dir)
  if (!st.isDirectory() || st.isSymbolicLink()) return 'not a directory'
  if (uid !== -1 && st.uid !== uid) return 'owned by another user'
  if ((st.mode & 0o077) !== 0) return 'open to group or others'
  return null
}

/** The shim's side: listens until close; each request is handed to `use`. */
export interface Channel {
  readonly socket: string
  close(): void
}

/**
 * Opens the channel for host process hostPid. Resolves null (with the reason logged) when the directory is unsafe or
 * the socket path would not fit: the shim then says input_hook false and the person binds by dialog.
 */
export async function openChannel(
  home: string,
  hostPid: number,
  shimPid: number,
  on: ChannelHandlers,
  log: (event: string, fields?: Record<string, unknown>) => void,
  maxPath: number,
): Promise<Channel | null> {
  const dir = channelDir(home)
  let problem: string | null
  try {
    problem = safeDir(join(home, 'run')) ?? safeDir(dir)
  } catch (e) {
    problem = (e as { code?: string }).code ?? 'error'
  }
  if (problem !== null) {
    log('channel-off', { reason: problem })
    return null
  }
  const socket = join(dir, `${randomBytes(4).toString('hex')}.sock`)
  if (Buffer.byteLength(socket) > maxPath) {
    log('channel-off', { reason: 'path-too-long' })
    return null
  }
  const secret = randomBytes(32)
  const server: Server = createServer((c) => {
    let buf = ''
    c.setEncoding('utf8')
    c.on('error', () => {})
    c.setTimeout(10_000, () => c.destroy())
    c.on('data', (chunk: string) => {
      buf += chunk
      if (buf.length > MAX_REQUEST) {
        c.destroy()
        return
      }
      const nl = buf.indexOf('\n')
      if (nl === -1) return
      const line = buf.slice(0, nl)
      buf = ''
      void answer(line).then((a) => c.end(`${JSON.stringify(a)}\n`))
    })
  })
  const answer = async (
    line: string,
  ): Promise<UseAnswer | { typed: boolean } | { bridge: string | null }> => {
    let r: { v?: unknown; kind?: unknown; name?: unknown; secret?: unknown }
    try {
      r = JSON.parse(line) as typeof r
    } catch {
      return { bound: false, code: 'bad-json' }
    }
    const given =
      typeof r.secret === 'string' && /^[0-9a-f]{64}$/.test(r.secret) ? Buffer.from(r.secret, 'hex') : null
    if (given === null || !timingSafeEqual(given, secret)) {
      log('channel-refused', { code: 'bad-auth' })
      return { bound: false, code: 'bad-auth' }
    }
    if (r.v === 1 && r.kind === 'typed') return { typed: on.typed() }
    if (r.v === 1 && r.kind === 'bridge') return { bridge: on.bridge() }
    if (
      r.v !== 1 ||
      r.kind !== 'use' ||
      typeof r.name !== 'string' ||
      typedName(`use ${r.name}`) !== r.name
    ) {
      return { bound: false, code: 'usage' }
    }
    return on.use(r.name)
  }
  const old = process.umask(0o077)
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(socket, () => resolve())
    })
  } catch (e) {
    log('channel-off', { reason: (e as { code?: string }).code ?? 'listen' })
    return null
  } finally {
    process.umask(old)
  }
  server.unref()
  const index = indexOf(home, hostPid)
  const tmp = `${index}.${shimPid}.tmp`
  writeFileSync(
    tmp,
    JSON.stringify({
      v: 1,
      sock: socket.slice(dir.length + 1),
      secret: secret.toString('hex'),
      shim: shimPid,
    }),
    { mode: 0o600 },
  )
  renameSync(tmp, index)
  log('channel-on', {})
  let open = true
  return {
    socket,
    close() {
      if (!open) return
      open = false
      server.close()
      rmSync(socket, { force: true })
      // Only our own index: a newer shim of the same host may have replaced it.
      removeOwn(index, shimPid)
    },
  }
}

/**
 * The hook's side: finds the shim of the first ancestor with an index and posts the typed word. Resolves the
 * shim's answer, or null when no shim answers within timeoutMs (no index, a stale one, a shim that is gone).
 */
export async function postUse(
  home: string,
  pids: readonly number[],
  name: string,
  timeoutMs = 5000,
): Promise<UseAnswer | null> {
  const a = await post(home, pids, { kind: 'use', name }, timeoutMs)
  if (a?.bound === true && typeof a.as === 'string') return { bound: true, as: a.as }
  if (a?.bound === false && typeof a.code === 'string') return { bound: false, code: a.code }
  return null
}

/** The hook's side for any other prompt: tells its shim the person typed. True when a shim took it. */
export async function postTyped(home: string, pids: readonly number[], timeoutMs = 1000): Promise<boolean> {
  return (await post(home, pids, { kind: 'typed' }, timeoutMs))?.typed === true
}

/**
 * The omp extension's side: the bridge folder of its shim's connection, or null (no shim, or no hello reply yet, so
 * no bridge). The extension repeats these few lines (it cannot import this package).
 */
export async function postBridge(
  home: string,
  pids: readonly number[],
  timeoutMs = 1000,
): Promise<string | null> {
  const b = (await post(home, pids, { kind: 'bridge' }, timeoutMs))?.bridge
  return typeof b === 'string' ? b : null
}

async function post(
  home: string,
  pids: readonly number[],
  body: Record<string, unknown>,
  timeoutMs: number,
): Promise<Record<string, unknown> | null> {
  for (const pid of pids) {
    let doc: { v?: unknown; sock?: unknown; secret?: unknown }
    try {
      doc = JSON.parse(readFileSync(indexOf(home, pid), 'utf8')) as typeof doc
    } catch {
      continue
    }
    if (doc.v !== 1 || typeof doc.sock !== 'string' || !/^[0-9a-f]{8}\.sock$/.test(doc.sock)) continue
    if (typeof doc.secret !== 'string') continue
    const line = JSON.stringify({ v: 1, ...body, secret: doc.secret })
    return ask(join(channelDir(home), doc.sock), line, timeoutMs)
  }
  return null
}

function ask(path: string, line: string, timeoutMs: number): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    const c = createConnection({ path })
    let buf = ''
    const done = (a: Record<string, unknown> | null): void => {
      clearTimeout(timer)
      c.destroy()
      resolve(a)
    }
    const timer = setTimeout(() => done(null), timeoutMs)
    c.setEncoding('utf8')
    c.on('connect', () => c.write(`${line}\n`))
    c.on('data', (chunk: string) => {
      buf += chunk
      const nl = buf.indexOf('\n')
      if (nl === -1) return
      let a: unknown = null
      try {
        a = JSON.parse(buf.slice(0, nl))
      } catch {}
      done(typeof a === 'object' && a !== null && !Array.isArray(a) ? (a as Record<string, unknown>) : null)
    })
    c.on('error', () => done(null))
    c.on('close', () => done(null))
  })
}
