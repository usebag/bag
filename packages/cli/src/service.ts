import { existsSync, readFileSync } from 'node:fs'
import { connect, type Socket } from 'node:net'
import { join, resolve } from 'node:path'
import { CliError } from './args.ts'
import { homeDir } from './home.ts'
import type { Io } from './io.ts'
import { versionLine } from './packaged.ts'

// The CLI as a client of the bag service (docs/bag-service.md, contract 1). When
// <home>/run/service.sock answers a hello, the service owns every identity of the home, so an identity act of the CLI
// asks it to lend that identity (service/lend), runs as it does without a service, with its own terminal prompts, and
// gives it back (service/return; the connection's close is a return). No socket, or one that refuses: as today.

/** The service's socket and launch token of `home` (contract section 2). */
export const runPath = (home: string, file: 'service.sock' | 'service.token'): string =>
  join(resolve(home), 'run', file)

/** What a hello answered: the service's version, pid and start, and the contract it speaks. */
export interface Hello {
  readonly contract: number
  readonly service: { readonly version: string; readonly pid: number; readonly started_at?: string }
}

/** One connection to the service: a request, its answer (a CliError with the bag code on an error), and the close. */
export interface Conn {
  readonly hello: Hello
  call(method: string, params: Record<string, unknown>, ms: number): Promise<Record<string, unknown>>
  close(): void
}

/**
 * Connects to the service of `home` and says hello as the CLI, or null when no service answers (no socket, refused,
 * or nothing within `ms`). A service that answers and refuses the hello throws its code (bad-auth, draining, ...).
 */
export async function connectService(home: string, ms = 2000): Promise<Conn | null> {
  const path = runPath(home, 'service.sock')
  const sock = await new Promise<Socket | null>((done) => {
    const s = connect(path)
    const end = (v: Socket | null) => {
      clearTimeout(timer)
      if (v === null) s.destroy()
      done(v)
    }
    const timer = setTimeout(() => end(null), ms)
    s.once('connect', () => end(s))
    s.once('error', () => end(null))
  })
  if (sock === null) return null
  let buf = ''
  let next = 1
  const waiting = new Map<number, (m: Record<string, unknown>) => void>()
  const fail = () => {
    for (const w of waiting.values())
      w({ error: { data: { code: 'unreachable', detail: 'the bag service closed the connection' } } })
    waiting.clear()
  }
  sock.on('data', (chunk) => {
    buf += chunk.toString('utf8')
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const line = buf.slice(0, i)
      buf = buf.slice(i + 1)
      try {
        const m = JSON.parse(line) as Record<string, unknown>
        const id = m.id
        if (typeof id === 'number') {
          waiting.get(id)?.(m)
          waiting.delete(id)
        }
      } catch {
        // not a frame for the CLI: notifications and the service's own MCP traffic are ignored
      }
    }
  })
  sock.on('close', fail)
  sock.on('error', fail)
  const call = (method: string, params: Record<string, unknown>, wait: number) =>
    new Promise<Record<string, unknown>>((done, reject) => {
      const id = next++
      const timer = setTimeout(() => {
        waiting.delete(id)
        reject(
          new CliError('unreachable', `the bag service did not answer ${method} within ${wait / 1000} s`),
        )
      }, wait)
      waiting.set(id, (m) => {
        clearTimeout(timer)
        const e = m.error as { data?: { code?: unknown; detail?: unknown }; message?: unknown } | undefined
        if (e === undefined) return done((m.result ?? {}) as Record<string, unknown>)
        const code = typeof e.data?.code === 'string' ? e.data.code : 'error'
        reject(new CliError(code, String(e.data?.detail ?? e.message ?? code)))
      })
      sock.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    })
  const close = () => sock.destroy()
  let token = ''
  try {
    token = readFileSync(runPath(home, 'service.token'), 'utf8').trim()
  } catch {
    // no token: the hello carries none and the service refuses bad-auth
  }
  const params = {
    contract: 1,
    token,
    host: 'cli',
    cwd: process.cwd(),
    client_capabilities: {},
    input_hook: false,
    shim: { version: versionLine().split(' ')[1] ?? 'source', pid: process.pid },
  }
  try {
    const hello = (await call('service/hello', params, ms)) as unknown as Hello
    return { hello, call, close }
  } catch (e) {
    close()
    throw e
  }
}

/**
 * Every verb that writes an identity's keys, records, trust or state, and where it names the identity: `--as`, the first argument after the command (or after its subcommand), or
 * nothing it can be lent by (publish: a record file of any identity, refused while a service runs).
 */
const BY_AS = new Set([
  'pair',
  'inbox',
  'send',
  'unpair',
  'resend',
  'held',
  'peer',
  'lookup',
  'logout',
  'record-keep',
])
const BY_NAME = new Set(['init', 'restore', 'onboard'])
const BY_SUB_NAME = new Set([
  'keys-rotate',
  'keys-prune',
  'identity-remove',
  'identity-relays',
  'identity-custody',
  'record-address',
  'record-accept-from',
  'group-create',
  'group-add',
  'group-remove',
  'group-rotate',
  'group-keep',
])

/** The act of `argv` a running service must lend (verb, name), `refuse` for one it cannot lend, or null for none. */
export function actOf(argv: readonly string[]): { verb: string; name: string | null } | 'refuse' | null {
  const [cmd = '', sub = ''] = argv
  if (cmd === 'publish') return 'refuse'
  // record keep --plist and --crontab print a job and touch nothing.
  if (cmd === 'record' && sub === 'keep' && argv.some((a) => a === '--plist' || a === '--crontab'))
    return null
  const verb = BY_SUB_NAME.has(`${cmd}-${sub}`) || `${cmd}-${sub}` === 'record-keep' ? `${cmd}-${sub}` : cmd
  const positional = (at: number) => {
    const v = argv[at]
    return v === undefined || v.startsWith('-') ? null : v
  }
  if (BY_AS.has(verb)) {
    const i = argv.indexOf('--as')
    const eq = argv.find((a) => a.startsWith('--as='))?.slice(5)
    // record keep --identities runs every identity of a file: it names no one identity, so it is refused.
    return { verb, name: i >= 0 ? (positional(i + 1) ?? null) : (eq ?? null) }
  }
  if (BY_NAME.has(verb)) return { verb, name: positional(1) }
  if (BY_SUB_NAME.has(verb)) return { verb, name: positional(2) }
  return null
}

/** A lent identity: give it back (the service re-derives from disk whether it still exists). */
export interface Lease {
  end(): Promise<void>
}

/**
 * For an identity act (actOf) in a home whose service answers: the identity lent by the service, else null (no act, or
 * no service: the CLI acts as it does without one). A refusal of the lend throws the service's code and detail.
 */
export function leaseFor(argv: readonly string[], io: Io): Promise<Lease | null> | null {
  const act = actOf(argv)
  if (act === null) return null
  const dir = argv.includes('--dir') ? argv[argv.indexOf('--dir') + 1] : undefined
  let home: string
  try {
    home = homeDir(io, dir)
  } catch {
    return null // the command refuses the missing home itself
  }
  // Synchronous to here: a command with no service starts in the same tick, as it did before the service.
  if (!existsSync(runPath(home, 'service.sock'))) return null
  if (act === 'refuse' || act.name === null) return refuse(home, argv[0] ?? '')
  return lend(io, home, { verb: act.verb, name: act.name })
}

/** An act that names no identity it can be lent by, while a service may run: held when one answers, else as today. */
async function refuse(home: string, cmd: string): Promise<null> {
  const conn = await connectService(home)
  if (conn === null) return null
  conn.close()
  throw new CliError(
    'held',
    `the bag service (pid ${conn.hello.service.pid}) holds the identities of ${home}, and ${cmd} names none it can lend: name the identity (--as or first), or stop the service first`,
  )
}

async function lend(io: Io, home: string, act: { verb: string; name: string }): Promise<Lease | null> {
  const conn = await connectService(home)
  if (conn === null) return null
  try {
    await conn.call('service/lend', { label: act.name, verb: act.verb }, 15_000)
  } catch (e) {
    conn.close()
    // An identity the service does not hold (a new one: init, onboard): the act runs as today.
    if (e instanceof CliError && e.code === 'unknown-identity') return null
    // A window bound to it, or a pairing of it, holds it: today's held, never retried here.
    if (e instanceof CliError && e.code === 'busy') {
      throw new CliError(
        'held',
        `the identity ${act.name} is held by the bag service (${e.message}); close that window, then run this again`,
      )
    }
    throw e
  }
  io.err(
    `the bag service (pid ${conn.hello.service.pid}) lent ${act.name} to this command; it takes it back after`,
  )
  return {
    async end() {
      try {
        await conn.call('service/return', { label: act.name }, 15_000)
      } catch {
        // the close below is a return
      } finally {
        conn.close()
      }
    },
  }
}

/** status's line for a home whose service answers a hello, else null. */
export async function serviceLine(home: string): Promise<string | null> {
  let conn: Conn | null = null
  try {
    conn = await connectService(home)
  } catch (e) {
    return `service at ${runPath(home, 'service.sock')} refused: ${(e as CliError).code}`
  }
  if (conn === null) return null
  conn.close()
  const s = conn.hello.service
  return `service bag ${s.version} pid ${s.pid} contract ${conn.hello.contract} ${runPath(home, 'service.sock')}`
}
