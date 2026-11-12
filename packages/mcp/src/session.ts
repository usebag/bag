import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Clock, type EdgeKeys, generateEdgeKeys, HomeCustody, type Rng } from '@usebag/edge'
import {
  AgentClient,
  codexSessionId,
  codexSessionName,
  type GrantReply,
  readSessionFile,
  requestGrant,
  resolveSessionName,
  type SessionName,
  SessionNameError,
  type SessionNameOptions,
  sessionFilePath,
  writeSessionFile,
} from '@usebag/edge/agent'
import { CODEX_SESSION, type Config, ConfigError } from './config.ts'
import type { Timers } from './desk.ts'
import { acquireLock } from './open.ts'

// --session: one agent session per Claude Code session, all on one principal. The name is the shared
// resolver's (or the flag's); the server takes the session's mcp.lock at once, so a second server of one session is
// refused busy before any prompt, makes the key file <home>/keys/<name>.json if absent, and asks the home's agent for
// the first grant (one y at the agent's terminal), kept at <home>/state/<name>/grant.json. The server does not wait
// for it to start: until the y, every tool answers grant-pending (never the agent's not-in-grant) with the request code. At close the key file goes.
// Under auto the name comes from the main claude process: with none above the server, startSession refuses no-session
// (a stderr line, exit 1) and never falls back to another name. The server leaves the hook <home>/state/sessions/
// <anchor pid>-<anchor start>.json (the edge's SessionFile) and, while a grant is asked, <home>/state/<name>/
// grant-request.json {v, code, at}: the code the agent shows, for the SessionStart hook to print, so that the person
// types y only at the prompt whose code matches. A grant lost later (logout, a new login, the window's end) is asked
// again with regrant() under a fresh key (spec/SPEC.md §13.5, "Re-grant after a revocation"): ac logout revokes the
// key it granted, and a revoked key signs nothing a reader accepts, so the key file is made again; the server
// registers its threads again on the new opening (server.ts), so replies on them still reach it. A first grant the
// agent refuses `revoked` (a key kept from before a logout) is asked once more under a fresh key. Only the session's
// own key is replaced: one this server made, or one the session's grant.json names (left by an earlier server of this
// name). A key file the person made is never replaced; its re-grant is refused `revoked`, naming the way out.
//
// Under auto:codex the server starts unbound: no name, lock, key file or grant request. The first tools/call whose
// _meta carries Codex's sessionId (else its threadId), a uuid, binds it: the name is codexSessionName(<the principal's
// address, as auto hashes it>, id), and the fixed-name start below runs then, synchronously, so two first calls bind
// once. A call with no usable id before that, or with another session's id after it, is refused and changes nothing. A
// bind that fails (busy: another server holds that name's lock) leaves the server unbound and holds no lock (the state
// directory may stay, as after a refused fixed-name start); the next call tries again. The trust boundary: Codex sets
// threadId in every call's _meta, and sessionId only from rust-v0.156.0; before that a sessionId the model supplied
// would pass untouched and win, which can deny the session its name (busy) but grants nothing.
//
// Precondition: every session of a principal holds the same caveats (the plugin passes one --grant-caveat list). The
// front desk refuses as final a root that a session whose caveats differ would have admitted.

/** How often a session asks again while no agent answers (no ac login yet, or a window that ended), in ms. */
export const GRANT_RETRY_MS = 10_000

export interface SessionDeps {
  readonly clock: Clock
  readonly rng: Rng
  readonly timers: Timers
  readonly pid: number
  readonly alive: (pid: number) => boolean
  /** The resolver's process readers, for tests (default ps). */
  readonly names?: SessionNameOptions
}

export interface SessionStart {
  /** The session's own configuration: --as its name, --auth its grant.json, --mailbox its principal (unbound: given). */
  readonly config: Config
  /** The principal's state directory, <home>/state/<principal name>, where the front desk's files live. */
  readonly deskDir: string
  /** Settles when grant.json holds a grant for the session's key; rejects with the refusal that ends the wait. */
  readonly granted: Promise<void>
  /** Asks the agent for a new grant (the old one is gone) and returns the new `granted`. */
  regrant(): Promise<void>
  /** Why the tools cannot run yet: the waiting line, with the request code once the agent has printed it. */
  waiting(): ConfigError
  /** Stops asking, removes the session's key file and releases its mcp.lock. */
  close(): void
  /** Binds an auto:codex session to the Codex session of a tools/call's _meta, or refuses the call; else nothing. */
  bind(meta: unknown): void
}

/**
 * The mark of a session key the bag service made (openAgentUnit): a crash-left keys/<label>.service.json is proven the
 * service's own by it, so the service's start-up sweep never takes a real identity that happens to have that name.
 * Key readers (edge keysOf) read only suite, sign_seed and seal_priv, so the extra fields change nothing for them.
 */
export interface SessionKeyMark {
  readonly kind: 'session-key'
  /** The principal's key name: the agent-custody identity this session key acts under. */
  readonly principal: string
}

/** Adds `mark`'s fields to the key file this server just made, by a 0600 temporary file and a rename. */
function markKey(file: string, mark: SessionKeyMark): void {
  const key = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
  writeAtomic(file, JSON.stringify({ ...key, kind: mark.kind, principal: mark.principal }))
}

/** Whether the key file carries `mark` (kind session-key and this principal); false for a file that cannot be read. */
function carriesMark(file: string, mark: SessionKeyMark): boolean {
  try {
    const key = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    return key.kind === mark.kind && key.principal === mark.principal
  } catch {
    return false
  }
}

/** The name and anchor of the Claude Code session this server runs in; no-session when there is none. */
function autoName(principal: string, names: SessionNameOptions | undefined) {
  try {
    return resolveSessionName(principal, names)
  } catch (e) {
    if (!(e instanceof SessionNameError)) throw e
    throw new ConfigError(
      e.code,
      `${e.message}; --session auto names the Claude Code session this server runs in: start it from one, or pass --session <name>`,
    )
  }
}

/** Writes `text` to `path` at mode 0600 by a temporary file and a rename, so a reader never sees half of it. */
function writeAtomic(path: string, text: string): void {
  const temp = `${path}.${process.pid}.tmp`
  writeFileSync(temp, text, { mode: 0o600 })
  renameSync(temp, path)
}

/** The subject of the hop in a session's grant.json; null when the file is absent or does not read. */
function grantSub(file: string): string | null {
  try {
    const [hop] = JSON.parse(readFileSync(file, 'utf8')) as [{ sub?: unknown }?]
    return typeof hop?.sub === 'string' ? hop.sub : null
  } catch {
    return null
  }
}

/** What a refused Codex id says next. */
const CODEX_WAY_OUT =
  "--session auto:codex takes its name from the sessionId or threadId in the _meta of Codex's tool calls, which " +
  'Codex rust-v0.123.0 or later sends; or start the server with --session <name>'

/** The Codex session id of a tools/call's _meta: its sessionId, else its threadId; null with neither. */
function codexIdOf(meta: unknown): string | null {
  const m = (typeof meta === 'object' && meta !== null ? meta : {}) as Record<string, unknown>
  const raw = m.sessionId ?? m.threadId
  if (raw === undefined) return null
  try {
    return codexSessionId(raw)
  } catch (e) {
    throw new ConfigError('no-session', `${(e as Error).message}; ${CODEX_WAY_OUT}`)
  }
}

export function startSession(given: Config, deps: SessionDeps, mark?: SessionKeyMark): SessionStart {
  const s = given.session as NonNullable<Config['session']>
  const custody = new HomeCustody(given.home)
  const mailbox = custody.agent.entry(s.principal).address
  if (s.name === CODEX_SESSION)
    return codexSession(given, (id) =>
      named(given, deps, custody, mailbox, codexSessionName(mailbox, id), null, mark),
    )
  const { name, anchor } = s.name === 'auto' ? autoName(mailbox, deps.names) : { name: s.name, anchor: null }
  return named(given, deps, custody, mailbox, name, anchor, mark)
}

/** An auto:codex session: unbound until a tool call's _meta names it, then the session `start` makes for its id. */
function codexSession(given: Config, start: (id: string) => SessionStart): SessionStart {
  const s = given.session as NonNullable<Config['session']>
  let inner: SessionStart | null = null
  let id: string | null = null
  let closed = false
  const bound = Promise.withResolvers<SessionStart>()
  const first = bound.promise.then((b) => b.granted)
  first.catch(() => {})
  return {
    get config() {
      return inner?.config ?? given
    },
    deskDir: join(given.home, 'state', s.principal),
    get granted() {
      return inner?.granted ?? first
    },
    regrant: () => (inner as SessionStart).regrant(),
    waiting: () =>
      inner?.waiting() ??
      new ConfigError('no-session', `not named before Codex's first tool call; ${CODEX_WAY_OUT}`),
    bind(meta) {
      const asked = codexIdOf(meta)
      if (inner !== null) {
        if (asked === null || asked === id) return
        throw new ConfigError(
          'busy',
          `this server serves Codex session ${id} (${inner.config.as}), not ${asked}: one server serves one Codex ` +
            'session; restart Codex, or start the server with --session <name>',
        )
      }
      if (closed) throw new ConfigError('busy', 'the server is closing')
      if (asked === null)
        throw new ConfigError(
          'no-session',
          `this call's _meta has no sessionId or threadId; ${CODEX_WAY_OUT}`,
        )
      inner = start(asked)
      id = asked
      bound.resolve(inner)
    },
    close() {
      closed = true
      if (inner === null)
        bound.reject(new ConfigError('busy', 'the server closed before its first tool call'))
      else inner.close()
    },
  }
}

/** The session of `name` (anchored on the main claude process under auto): its lock, key file and grant request. */
function named(
  given: Config,
  deps: SessionDeps,
  custody: HomeCustody,
  mailbox: string,
  name: string,
  anchor: SessionName['anchor'] | null,
  mark?: SessionKeyMark,
): SessionStart {
  const s = given.session as NonNullable<Config['session']>
  const state = join(given.home, 'state', name)
  mkdirSync(state, { recursive: true, mode: 0o700 })
  const release = acquireLock(join(state, 'mcp.lock'), deps.pid, deps.alive)
  const keyFile = join(given.home, 'keys', `${name}.json`)
  const grantFile = join(state, 'grant.json')
  const requestFile = join(state, 'grant-request.json')
  let line = `waiting for the agent of ${s.principal}`
  let closed = false
  let client: AgentClient | null = null
  let cancel = (): void => {}
  // The session's own key, which this server removes at close and replaces at a re-grant: made here, or found named by
  // the session's grant.json.
  let ours = false
  let address: string
  try {
    // The service's opening (a mark given) adopts only its own session key for this principal: a key file there that
    // lacks the mark (a real identity someone named <x>.service) is refused before the agent is asked, or the agent's
    // y would hand the principal's hop to another identity's key. The --session form (no mark) adopts as before.
    if (mark !== undefined && existsSync(keyFile) && !carriesMark(keyFile, mark))
      throw new ConfigError(
        'exists',
        `keys/${name}.json exists and is not the bag service's session key for ${mark.principal}: ` +
          'it is left as it is; rename that identity, or remove the file if it is a stale key',
      )
    if (!existsSync(keyFile)) {
      custody.create(name, generateEdgeKeys(deps.rng), { custody: 'file' })
      if (mark !== undefined) markKey(keyFile, mark)
      ours = true
    }
    address = custody.entry(name).address
    ours ||= grantSub(grantFile) === address
    if (anchor !== null) writeSessionFile(given.home, { v: 1, name, principal: mailbox, ...anchor })
  } catch (e) {
    release()
    throw e
  }
  const forget = (file: string): void => {
    if (existsSync(file)) unlinkSync(file)
  }
  /** The session's key file made again with a fresh key; a key file the person made is refused, not replaced. */
  const rekey = (): void => {
    if (!ours) {
      line =
        `keys/${name}.json predates this server and is not the session's own key, so it is not replaced: ` +
        'remove it, or start with another --session name'
      throw new ConfigError('revoked', line)
    }
    forget(keyFile)
    address = custody.create(name, generateEdgeKeys(deps.rng), { custody: 'file' }).address
    if (mark !== undefined) markKey(keyFile, mark)
  }
  const grant = async (rekeyed: boolean): Promise<void> => {
    let fresh = rekeyed
    for (;;) {
      if (closed) throw new ConfigError('busy', 'the server closed before the grant')
      const r = await requestGrant(
        () => (client = new AgentClient(join(given.home, 'agent.sock'))),
        address,
        s.caveats,
        s.exp,
        deps.clock,
        (code) => {
          line = `waiting for y at the agent, request ${code}`
          writeAtomic(requestFile, JSON.stringify({ v: 1, code, at: deps.clock.now() }))
        },
      )
      if (closed) throw new ConfigError('busy', 'the server closed before the grant')
      if (r?.ok) {
        forget(requestFile)
        return writeAtomic(grantFile, JSON.stringify([r.hop]))
      }
      if (r?.code === 'revoked' && !fresh) {
        // The key is in the principal's revoked list, refused before the agent's prompt: once more, under a fresh key.
        fresh = true
        rekey()
        continue
      }
      if (r !== null && r.code !== 'agent-locked') {
        forget(requestFile)
        line =
          r.code === 'declined' ? 'no y at the agent: restart the session to ask again' : 'the agent refused'
        throw new ConfigError(r.code, line)
      }
      line = `no agent of ${s.principal} answers: run ac login; asked again every ${GRANT_RETRY_MS / 1000} s`
      await new Promise<void>((done) => {
        const stop = deps.timers.after(GRANT_RETRY_MS, done)
        cancel = () => {
          stop()
          done()
        }
      })
    }
  }
  let granted = grant(false)
  granted.catch(() => {})
  return {
    config: { ...given, as: name, auth: grantFile, mailbox, session: { ...s, name } },
    deskDir: join(given.home, 'state', s.principal),
    get granted() {
      return granted
    },
    regrant: () => {
      line = `waiting for the agent of ${s.principal}`
      granted = (async () => {
        rekey()
        return grant(true)
      })()
      granted.catch(() => {})
      return granted
    },
    waiting: () => new ConfigError('grant-pending', `${name}: ${line}`),
    close: () => {
      closed = true
      cancel()
      client?.close()
      forget(requestFile)
      if (ours && existsSync(keyFile)) unlinkSync(keyFile)
      if (anchor !== null) {
        try {
          if (readSessionFile(given.home, anchor)?.name === name)
            unlinkSync(sessionFilePath(given.home, anchor))
        } catch {} // a file that is not this session's (malformed, or another's) is left as it is
      }
      release()
    },
    bind: () => {},
  }
}

/**
 * The bag service's opening of the agent-custody identity `label` (svc-core's unit open, decision 92): the --session
 * form for the service, so a window bound to it can act. A session key of its own under the agent's hop, opening at
 * the principal's mailbox, with the same lock, key file, grant request, regrant and close as --session; the session is
 * named `<label>.service`. `caveats` is the principal's configured list, never empty (the red team's MEDIUM on
 * connectionGrant). A label that is not an agent-custody identity is refused as startSession refuses it.
 */
export function openAgentUnit(
  given: Config,
  label: string,
  o: { readonly caveats: readonly string[]; readonly exp?: string | null },
  deps: SessionDeps,
): SessionStart {
  if (o.caveats.length === 0)
    throw new ConfigError(
      'usage',
      `${label}: an agent-custody identity needs the principal's caveat list: none is configured`,
    )
  return startSession(
    {
      ...given,
      session: { name: `${label}.service`, principal: label, caveats: o.caveats, exp: o.exp ?? null },
    },
    deps,
    { kind: 'session-key', principal: label },
  )
}

/** An agent-class binding's own grant (binding.ts): a fresh session key held in memory, and the agent's hop to it. */
export interface ConnectionGrant {
  readonly keys: EdgeKeys
  readonly hop: Extract<GrantReply, { ok: true }>['hop']
}

/**
 * The grant of one bag service connection bound to an agent-class identity (red team M3): a fresh key made for this
 * connection alone, never written to a file, and the agent's first grant to it through requestGrant, one y at the
 * agent's terminal per connection, so one connection's grant never serves another. A refusal throws its code.
 */
export async function connectionGrant(
  home: string,
  o: {
    readonly rng: Rng
    readonly clock: Clock
    readonly caveats?: readonly string[]
    readonly exp?: string | null
    readonly connect?: () => Pick<AgentClient, 'grant' | 'close'>
    readonly onCode?: (code: string) => void
  },
): Promise<ConnectionGrant> {
  // The principal's configured caveat list, the same for every connection (svc-core passes it): never none, for a grant
  // with no caveat would give a window the principal's whole authority (the red team's MEDIUM).
  if ((o.caveats ?? []).length === 0)
    throw new ConfigError(
      'usage',
      "an agent-class window needs the principal's caveat list: none is configured",
    )
  const keys = generateEdgeKeys(o.rng)
  const connect = o.connect ?? (() => new AgentClient(join(home, 'agent.sock')))
  const r = await requestGrant(
    connect,
    keys.signing.address,
    o.caveats ?? [],
    o.exp ?? null,
    o.clock,
    o.onCode ?? (() => {}),
  )
  if (r === null)
    throw new ConfigError('agent-locked', 'no agent answers: the person runs ac login, then binds again')
  if (!r.ok) throw new ConfigError(r.code, 'the agent did not grant this window')
  return { keys, hop: r.hop }
}
