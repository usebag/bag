// The shim's side of the wire contract with the bag service (docs/bag-service.md, contract 1, lane svc-core): the
// method names, the hello's shape, where the socket and the launch token are, and how a dialog's answer carries its
// handle. Every name the contract fixes lives here and nowhere else in the shim.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { HostKind } from './host.ts'

/** The contract this shim speaks (section 7). */
export const CONTRACT = 1
/** The first request on every connection (section 5). */
export const HELLO = 'service/hello'
/** A bind by the person's typed word or the shim's own choice dialog (W1). */
export const USE = 'service/use'
/** Notifications from the service: a bind made, mail for a bound identity, a drain started. */
export const BOUND = 'service/bound'
export const RING = 'service/ring'
export const DRAINING = 'service/draining'
/** Shim to service: the person typed in this window (svc-mail's speaking window; params {}). */
export const TYPED = 'service/typed'
/** Where a dialog carries its per-connection handle, and where the answer echoes it (section 5, "Dialogs"). */
export const HANDLE_META = 'bag.dev/dialog'
/** The experimental client capability the shim adds for an omp host: the service writes its consents into a folder. */
export const BRIDGE_CAPABILITY = 'bag.dev/consent-bridge'

/** The shim's own version, sent in the hello: the package's (version.ts, replaced by the build). */
export { SHIM_VERSION } from './version.ts'

/** What the shim tells the service about itself and its host, once per connection (exactly these members). */
export interface Hello {
  readonly contract: number
  readonly token: string
  readonly host: HostKind
  readonly cwd: string
  readonly client_capabilities: Record<string, unknown>
  readonly input_hook: boolean
  readonly shim: { readonly version: string; readonly pid: number }
}

type Env = Readonly<Record<string, string | undefined>>

/** The home the service serves: --dir, else AC_HOME, else $HOME/.bag, as every bag command finds it. */
export function homeOf(argv: readonly string[], env: Env): string | null {
  const at = argv.indexOf('--dir')
  if (at !== -1 && argv[at + 1] !== undefined) return argv[at + 1] as string
  if (env.AC_HOME) return env.AC_HOME
  if (env.HOME) return join(env.HOME, '.bag')
  return null
}

/** The run directory, socket and token file of a home (section 2). */
export const runDir = (home: string): string => join(home, 'run')
export const socketOf = (home: string): string => join(home, 'run', 'service.sock')
export const tokenFileOf = (home: string): string => join(home, 'run', 'service.token')

/** The longest socket path this platform takes, in bytes, NUL excluded: 103 on macOS, 107 elsewhere (section 2). */
export const maxSocketPath = (platform: string = process.platform): number =>
  platform === 'darwin' ? 103 : 107

/** The socket path's refusal when it is too long for sun_path (section 2's detail), else null. */
export function socketPathProblem(path: string, platform: string = process.platform): string | null {
  const n = Buffer.byteLength(path, 'utf8')
  const max = maxSocketPath(platform)
  return n > max
    ? `the socket path is ${n} bytes; this platform allows ${max}: set AC_HOME to a shorter home`
    : null
}

/**
 * The launch token of the running service: the first line of <home>/run/service.token when it is 64 lowercase hex,
 * else null. Read at each connect, held in memory for that hello only; never logged, never written (section 4).
 */
export function readToken(
  file: string,
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): string | null {
  try {
    const line = read(file).split('\n')[0]?.trim() ?? ''
    return /^[0-9a-f]{64}$/.test(line) ? line : null
  } catch {
    return null
  }
}

const metaOf = (o: Record<string, unknown> | undefined): Record<string, unknown> | undefined => {
  const m = o?._meta
  return typeof m === 'object' && m !== null ? (m as Record<string, unknown>) : undefined
}

/** The handle a dialog from the service carries in params._meta, or null. */
export function handleOf(params: Record<string, unknown> | undefined): string | null {
  const h = metaOf(params)?.[HANDLE_META]
  return typeof h === 'string' && h !== '' ? h : null
}

/** The params without the handle in _meta: the host never sees it. */
export function withoutBagMeta(params: Record<string, unknown>): Record<string, unknown> {
  const meta = metaOf(params)
  if (meta === undefined) return params
  const rest: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(meta)) if (k !== HANDLE_META) rest[k] = v
  const out: Record<string, unknown> = { ...params }
  if (Object.keys(rest).length === 0) delete out._meta
  else out._meta = rest
  return out
}

/** A result with the handle echoed in its _meta, for the service to match against the connection that asked. */
export function withHandle(result: unknown, handle: string): Record<string, unknown> {
  const r = typeof result === 'object' && result !== null ? (result as Record<string, unknown>) : {}
  return { ...r, _meta: { ...(metaOf(r) ?? {}), [HANDLE_META]: handle } }
}

/** The bag code of a JSON-RPC error from the service (data.code), else null. */
export function bagCode(error: { readonly data?: unknown } | undefined): string | null {
  const c = (error?.data as { code?: unknown } | undefined)?.code
  return typeof c === 'string' ? c : null
}

/**
 * Whether the service that answered the hello still owns the home (the red team's recommendation): <home>/run/
 * service.json names that pid and it is alive. Node cannot ask who holds the service's fcntl lock without taking it,
 * and a probe that took it would make a starting service exit busy, so this is the check short of the lock: it closes
 * a squat on the socket by a process that did not also rewrite service.json.
 */
export function ownsHome(
  home: string,
  servicePid: number,
  alive: (pid: number) => boolean,
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): boolean {
  try {
    const doc = JSON.parse(read(join(home, 'run', 'service.json'))) as { pid?: unknown }
    return doc.pid === servicePid && alive(servicePid)
  } catch {
    return false
  }
}
