// A corporate proxy (job #3; Node 24.4.1, measured 2026-11-03): HTTPS_PROXY, HTTP_PROXY and NO_PROXY, each in either
// case, the lowercase name first, as curl and Node read them. Node's own fetch and WebSocket go through them only when
// NODE_USE_ENV_PROXY is set as the process starts, and Node reads it only then (setting it later changes nothing), so
// each entry point calls useEnvProxy first: with a proxy set and that variable not, it runs itself again, once, in
// the same process (process.execve: the same pid, arguments and stdio), with NODE_USE_ENV_PROXY=1. Everything that
// goes out by fetch or WebSocket then uses Node's EnvHttpProxyAgent: the relay client, the subscription, telemetry.
// node:https ignores the variable, so well-known.ts tunnels its one request itself (proxyFor, tunnelTo). A proxy's
// user and password are never shown: proxyShown names its scheme, host and port only.

type Env = Readonly<Record<string, string | undefined>>

/** Set in the re-run's environment, so a process re-runs itself at most once whatever its environment says. */
export const REEXEC_GUARD = 'AC_PROXY_REEXEC'

/** The value of `name` in `env`, its lowercase spelling first, as curl reads it; null when unset or empty. */
function read(env: Env, name: string): string | null {
  const v = env[name.toLowerCase()] ?? env[name.toUpperCase()]
  return v === undefined || v.trim() === '' ? null : v.trim()
}

/** The proxy URL for `url` (https: HTTPS_PROXY, http: HTTP_PROXY), or null for a direct connection. */
export function proxyFor(env: Env, url: string): URL | null {
  const target = URL.canParse(url) ? new URL(url) : null
  if (target === null) return null
  const raw = read(
    env,
    target.protocol === 'https:' || target.protocol === 'wss:' ? 'https_proxy' : 'http_proxy',
  )
  const proxy = raw !== null && URL.canParse(raw) ? new URL(raw) : null
  const port = target.port || (target.protocol === 'https:' || target.protocol === 'wss:' ? '443' : '80')
  return proxy === null || bypassed(read(env, 'no_proxy') ?? '', target.hostname, port) ? null : proxy
}

/**
 * Whether NO_PROXY's list names `host` at `port`, as Node's EnvHttpProxyAgent reads it (measured on 24.4.1): `*` for
 * every host; a name or an address for itself only; `.example.com` or `*.example.com` for its subdomains, not the name
 * itself; `:port` for that port only. Entries are split by commas or spaces, and case does not count.
 */
export function bypassed(list: string, host: string, port: string): boolean {
  const name = host.toLowerCase().replace(/^\[(.*)\]$/, '$1')
  return list
    .toLowerCase()
    .split(/[\s,]+/)
    .filter((e) => e !== '')
    .some((entry) => {
      if (entry === '*') return true
      // A bare IPv6 address has colons and no port; a port follows a name, an IPv4 address or [an IPv6 one].
      const bare = (entry.match(/:/g) ?? []).length > 1 && !entry.startsWith('[')
      const at = bare ? null : /^(.*?)(?::(\d+))?$/.exec(entry)
      const [pattern = '', only] = at === null ? [entry, undefined] : [at[1], at[2]]
      if (only !== undefined && only !== port) return false
      const suffix = pattern.startsWith('*.') ? pattern.slice(1) : pattern.startsWith('.') ? pattern : null
      return suffix === null ? name === pattern.replace(/^\[(.*)\]$/, '$1') : name.endsWith(suffix)
    })
}

/** A proxy as it may be shown in a status or a log line: its scheme, host and port, never its user or password. */
export function proxyShown(proxy: URL): string {
  return `${proxy.protocol}//${proxy.host}`
}

/** The proxies of `env` as status shows them: each `scheme://host:port` or null, and NO_PROXY's list as written. */
export function proxyStatus(env: Env): {
  readonly https: string | null
  readonly http: string | null
  readonly no_proxy: string | null
  readonly active: boolean
} {
  const shown = (name: string): string | null => {
    const raw = read(env, name)
    return raw !== null && URL.canParse(raw) ? proxyShown(new URL(raw)) : null
  }
  const [https, http] = [shown('https_proxy'), shown('http_proxy')]
  const active = (https !== null || http !== null) && env.NODE_USE_ENV_PROXY !== undefined
  return { https, http, no_proxy: read(env, 'no_proxy'), active }
}

/** The part of a process useEnvProxy reads and replaces. */
export interface ReexecProcess {
  readonly env: Env
  readonly execPath: string
  readonly execArgv: readonly string[]
  readonly argv: readonly string[]
  readonly execve?: (file: string, args: readonly string[], env: Record<string, string>) => never
}

/**
 * The first call of each entry point (the CLI, the MCP server, the bridge): with HTTPS_PROXY or HTTP_PROXY set and
 * neither NODE_USE_ENV_PROXY nor the guard, runs this process again in its place (process.execve), with both set, so
 * Node's fetch and WebSocket use the proxy. It does not return then. Without process.execve (Windows) it returns the
 * one line to show; otherwise null, and nothing changes.
 */
export function useEnvProxy(proc: ReexecProcess = process): string | null {
  const { env } = proc
  const proxied = read(env, 'https_proxy') !== null || read(env, 'http_proxy') !== null
  if (!proxied || env.NODE_USE_ENV_PROXY !== undefined || env[REEXEC_GUARD] !== undefined) return null
  if (proc.execve === undefined) {
    return 'bag: a proxy is set (HTTPS_PROXY or HTTP_PROXY); set NODE_USE_ENV_PROXY=1 too, so Node sends through it'
  }
  const next: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined) next[k] = v
  proc.execve(proc.execPath, [proc.execPath, ...proc.execArgv, ...proc.argv.slice(1)], {
    ...next,
    NODE_USE_ENV_PROXY: '1',
    [REEXEC_GUARD]: '1',
  })
  return null // not reached: execve replaced the process (a test's stand-in returns)
}
