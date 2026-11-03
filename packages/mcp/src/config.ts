import { parseArgs } from 'node:util'
import { isAddress } from '@usebag/core'
import { programName, type TrustedRoot, wellKnownUrl } from '@usebag/edge'
import { EXP_TEXT } from '@usebag/edge/agent'
import { readIdentities } from './identities.ts'

// The server's configuration, from its flags and the environment only (never from stdin, which carries MCP frames).
// Parsing reads no file but the --identities file (identities.ts) and opens nothing; open.ts does that.

/** The caveat profiles --honor may name: the coding profile's type= and repo= caveats (spec/SPEC.md §6.4). */
export const PROFILES = ['coding'] as const
/** What --push may name: the inbox resource (resource.ts), the log line and the channel event (push.ts). */
export const PUSH_KINDS = ['resource', 'log', 'channel'] as const

/**
 * The longest a wait or ask call blocks by default, in seconds: under opencode's 30 s and Codex's 60 s tool timeouts
 * A longer timeout_s goes on through the resume token.
 */
export const DEFAULT_MAX_TOOL_SECONDS = 25
/** The largest --max-tool-seconds, the largest timeout_s. */
export const MAX_TOOL_SECONDS = 300
/** Seconds between two progress notifications of a wait or ask call, by default (progress.ts). */
export const DEFAULT_PROGRESS_SECONDS = 15

/** The server as its usage names it: bag-mcp from the package, node <its main.ts> from source. */
const MAIN = programName('bag-mcp', 'packages/mcp/src/main.ts')

export const USAGE = `bag MCP server (pre-release): an address and a durable mailbox inside an MCP host

usage: ${MAIN} --as <key name> --relay <url>... [options]
       ${MAIN} --identities <file> [options]

  --as <name>                   the signing key: a key file, <home>/keys/<name>.json, or a keychain identity,
                                <home>/keychain/<name>.json (a self-rooted principal, or a session)
  --relay <url>                 a relay to subscribe to and look records up at; repeatable, at least one
  --rendezvous <url>            the relay that hosts pairing codes for pair_invite and pair_accept, shared by both
                                peers when their relays differ (default the first --relay)
  --identities <file>           several unlinked identities in one server: an absolute path to a 0600 JSON file
                                that gives each its label, key, home, relays and trust; beside it only
                                --max-tool-seconds, --progress-seconds, --push, --allow-private-relays and
                                --default-handler (every other flag is per identity, in the file)
  --trust-root <domain|address> a root whose messages are accepted; repeatable (none: every message is rejected
                                as untrusted-root)
  --honor <profile>             a caveat profile to evaluate (coding); repeatable (none: any caveat fails closed)
  --accept-type <type>          an accepted sealed type: exact, <prefix>.* or *; repeatable (default *)
  --receipts-to <address>       a peer this identity answers read receipts from; an address, and never a name, so
                                that no pairing can add to it; repeatable; none by default, and a peer not named gets
                                none and no sign of why. Not for a --session. A receipt reveals to that peer, and in part to the relay, that this
                                identity's edge accepted that message, and roughly when, even with its jitter of up
                                to 20 s. It means the edge accepted it, not that anyone has read it
  --default-handler queue       messages on threads no session holds are kept for inbox and wait; the only mode in
                                v0: nothing is ever spawned or woken
  --auth <chain.json>           a session: the chain from its root to the --as key (one JSON line, a list of hops),
                                read again 60 s before its earliest exp and on a hop-expired refusal
  --chain-cmd <command>         a session: a command (run by /bin/sh -c, 10 s at most) that prints the chain JSON or
                                the path of a chain file; run at start, 60 s before the earliest exp and on a
                                hop-expired refusal; its output is never logged (in place of --auth)
  --mailbox <address>           a session's mailbox: its principal's address, the chain's last issuer. When it is an
                                agent identity of the home (<home>/agent/<name>.json; ac login), the agent opens what
                                arrives, each thread is registered at the agent before a send on it, the --auth chain
                                is the one hop ac grant printed and the agent renews it; --allow-delegate is refused
  --session auto|<name>         a session of --principal named for this Claude Code session (auto: from its main
                                claude process) or <name>, in place of --as, --auth and --mailbox: its key is made at
                                the first start, its first grant asked of the agent (a y at the agent's terminal;
                                until then every tool answers grant-pending with the request code), and its key file
                                removed at close; one session, the front desk, takes the principal's root messages.
                                A --session server keeps sends waiting for their recipient in memory: they end with
                                the session. Only a fixed --as identity keeps them across a restart
  --session auto:codex          as auto, for Codex: named at Codex's first tool call, from its _meta.sessionId, else
                                threadId (Codex rust-v0.123.0 or later; the id is Codex-authenticated from
                                rust-v0.156.0); not with --push resource
  --principal <name>            a session's principal: an agent identity of the home (ac keygen --custody agent)
  --grant-caveat <caveat>       a caveat of a session's grant; repeatable, at least one with --session
  --grant-exp <unix s|+s>       a session's grant's exp (default 8 hours, halved until the window admits it)
  --allow-delegate              list the delegate tool, which grants authority: at least one caveat,
                                an expiry within 8 hours; off by default, and then the tool is not listed
  --allow-session-delegation    a session may delegate on (replies to its delegate would go to the session key,
                                which has no mailbox); off by default; without --allow-delegate it does nothing
  --keep-alive-records          re-sign and publish this identity's address and accept-from records at half the
                                address record's ttl (a self-rooted principal only); off by default
  --allow-private-relays        send to a peer's relay on a loopback, link-local or private address that is not
                                one of --relay (a LAN of several relays); off by default
  --policy <file>               the org's served policy record (signed by the org root)
  --members <file>              the org's members record, 0600 like a key file, never served: its roots, rate,
                                outbound deny list, breakers and moderation; with it every send goes through the
                                outbound gate, and inbox lists quarantined rows and held sends (metadata only).
                                Both are read and verified once, at start; one that does not verify exits 2.
                                Release and drop are a person's, through the CLI on a terminal: no tool does them
  --max-tool-seconds <n>        the longest a wait or ask call blocks, 1 to 300 (default 25, under the tool timeouts
                                of common hosts); a longer timeout_s goes on through the resume token
  --progress-seconds <n>        during a wait or ask call, a progress notification every n seconds, 0 to 300
                                (default 15; 0 sends none); only when the host's call carries a progressToken
  --push <kind>                 tell the host of each delivered message in one line (id, from, type; never the body):
                                log (notifications/message at info, once the client sets a level) or channel (Claude
                                Code's notifications/claude/channel); or resource, the MCP resource
                                bag://inbox/<name> and its resources/updated to a subscriber; repeatable; none
                                by default
  --dir <home>                  the home (default $AC_HOME, else ~/.bag); state in <home>/state/<name>/
  --help                        this text, on stderr

stdout carries MCP frames (JSON-RPC over stdio) and nothing else; logs are JSON lines on stderr. A bad flag exits 2,
a key, chain or state that cannot be opened exits 1, and the end of stdin, SIGINT or SIGTERM stops the server (0).`

/**
 * A refusal of the server's own, with a code (`usage`, `busy`, `chain-cmd-failed`, or one of the closed set) and a
 * detail: at start, a flag, a key, a lock or a chain; later, a chain the server could not read again.
 */
export class ConfigError extends Error {
  readonly code: string

  constructor(code: string, detail: string) {
    super(`${code}: ${detail}`)
    this.name = 'ConfigError'
    this.code = code
  }
}

export interface Config {
  /** The name tools take as `as`: the file's label, or the key name without --identities. */
  readonly label: string
  /** The key name, as HomeCustody names an identity (a key file or a keychain pointer). */
  readonly as: string
  readonly home: string
  readonly relays: readonly string[]
  /** The relay pairing codes meet at (--rendezvous; the first of `relays` by default). */
  readonly rendezvous: string
  /** The --trust-root values as given, and as the edge's policy takes them. */
  readonly trustRootTexts: readonly string[]
  readonly trustRoots: readonly TrustedRoot[]
  readonly honor: readonly string[]
  readonly acceptTypes: readonly string[]
  readonly defaultHandler: 'queue'
  /** The chain file of a session, or null (a self-rooted principal, or a session under --chain-cmd). */
  readonly auth: string | null
  /** The command that prints a session's chain, or null. */
  readonly chainCmd: string | null
  /** A session's mailbox (its principal), or null. */
  readonly mailbox: string | null
  /** --session: its name (auto, auto:codex or a name), its principal, its grant's caveats and exp; or null. */
  readonly session: {
    readonly name: string
    readonly principal: string
    readonly caveats: readonly string[]
    readonly exp: string | null
  } | null
  /** Whether the delegate tool is listed at all (delegating grants authority; off by default). */
  readonly allowDelegate: boolean
  /** Whether a session may delegate on (its delegate's replies would reach no mailbox). */
  readonly allowSessionDelegation: boolean
  /** Whether the server keeps its own address and accept-from records alive. */
  readonly keepAliveRecords: boolean
  /** --receipts-to: the addresses whose receipt requests this reader answers; none by default. */
  readonly receiptsTo: readonly string[]
  /** The longest a wait or ask call blocks, in seconds. */
  readonly maxToolSeconds: number
  /** Seconds between two progress notifications of a wait or ask call; 0 sends none. */
  readonly progressSeconds: number
  /** Whether the edge may call a peer's relay on a private address that is not one of `relays` (guard off). */
  readonly allowPrivateRelays: boolean
  /** The org's served policy record file (--policy), or null; read and verified at start (policy.ts). */
  readonly policy: string | null
  /** The org's members record file (--members), or null; 0600, read and verified at start (policy.ts). */
  readonly members: string | null
  /** What the server pushes to the host on a delivered message (--push); [] by default. */
  readonly push: readonly (typeof PUSH_KINDS)[number][]
}

/** The server's identities and its server-wide flags: the --identities file's, else the one of the flags. */
export interface ServerConfig {
  readonly identities: readonly Config[]
  /** The label reads take when `as` is omitted: the file's default, else its first identity's. */
  readonly defaultLabel: string
  /** Whether the identities came from --identities (then every act names `as`). */
  readonly multi: boolean
  readonly maxToolSeconds: number
  readonly progressSeconds: number
  readonly push: Config['push']
  readonly allowPrivateRelays: boolean
  readonly defaultHandler: 'queue'
}

/** The server-wide values, which every identity of a server shares. */
export type ServerWide = Pick<
  ServerConfig,
  'maxToolSeconds' | 'progressSeconds' | 'push' | 'allowPrivateRelays' | 'defaultHandler'
>

/** The flags --identities takes beside it; every other is per identity, in the file. */
const SERVER_WIDE =
  'identities max-tool-seconds progress-seconds push allow-private-relays default-handler'.split(' ')

const OPTIONS = {
  identities: { type: 'string' },
  as: { type: 'string' },
  relay: { type: 'string', multiple: true },
  rendezvous: { type: 'string' },
  'trust-root': { type: 'string', multiple: true },
  honor: { type: 'string', multiple: true },
  'accept-type': { type: 'string', multiple: true },
  'default-handler': { type: 'string' },
  auth: { type: 'string' },
  'chain-cmd': { type: 'string' },
  mailbox: { type: 'string' },
  session: { type: 'string' },
  principal: { type: 'string' },
  'grant-caveat': { type: 'string', multiple: true },
  'grant-exp': { type: 'string' },
  'allow-delegate': { type: 'boolean' },
  'allow-session-delegation': { type: 'boolean' },
  'keep-alive-records': { type: 'boolean' },
  'receipts-to': { type: 'string', multiple: true },
  'allow-private-relays': { type: 'boolean' },
  'max-tool-seconds': { type: 'string' },
  'progress-seconds': { type: 'string' },
  policy: { type: 'string' },
  members: { type: 'string' },
  push: { type: 'string', multiple: true },
  dir: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
} as const

const usage = (detail: string): ConfigError => new ConfigError('usage', detail)

/** A peer of --receipts-to or an identity's receipts_to: an address alone, for a name's address can change. */
export function receiptPeer(text: string, what: string): string {
  if (isAddress(text)) return text
  throw new ConfigError('usage', `${what} ${JSON.stringify(text)} is not an address`)
}

/** The --session value that names a Codex session at its first tool call, from its _meta (session.ts). */
export const CODEX_SESSION = 'auto:codex'

/** A relay URL: http or https, without trailing slashes. */
export function relayUrl(text: string, flag = '--relay'): string {
  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw usage(`${flag} ${JSON.stringify(text)} is not a URL`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw usage(`${flag} ${JSON.stringify(text)} is not an http or https URL`)
  }
  return text.replace(/\/+$/, '')
}

/** A --trust-root value: an address, trusted by key, or a domain, whose well-known record is pinned at first use. */
export function trustedRoot(text: string, flag = '--trust-root'): TrustedRoot {
  if (isAddress(text)) return { address: text }
  try {
    wellKnownUrl(text)
  } catch {
    throw usage(`${flag} ${JSON.stringify(text)} is neither an address nor a domain`)
  }
  return { domain: text }
}

/** --max-tool-seconds: a whole number of seconds from 1 to 300; 25 when absent. */
export function maxToolSeconds(text: string | undefined): number {
  if (text === undefined) return DEFAULT_MAX_TOOL_SECONDS
  const n = /^[1-9][0-9]{0,2}$/.test(text) ? Number(text) : Number.NaN
  if (!(n <= MAX_TOOL_SECONDS)) {
    throw usage(`--max-tool-seconds ${JSON.stringify(text)} is not a whole number of seconds from 1 to 300`)
  }
  return n
}

/** --progress-seconds: a whole number of seconds from 0 (none) to 300; 15 when absent. */
export function progressSeconds(text: string | undefined): number {
  if (text === undefined) return DEFAULT_PROGRESS_SECONDS
  const n = /^(0|[1-9][0-9]{0,2})$/.test(text) ? Number(text) : Number.NaN
  if (!(n <= MAX_TOOL_SECONDS)) {
    throw usage(`--progress-seconds ${JSON.stringify(text)} is not a whole number of seconds from 0 to 300`)
  }
  return n
}

/** The home directory: --dir, else AC_HOME, else HOME/.bag. */
function homeDir(dir: string | undefined, env: Readonly<Record<string, string | undefined>>): string {
  if (dir !== undefined) return dir
  if (env.AC_HOME) return env.AC_HOME
  if (env.HOME) return `${env.HOME.replace(/\/+$/, '')}/.bag`
  throw usage('no home directory: pass --dir, or set AC_HOME or HOME')
}

/** --session and its flags; null without --session, whose flags then are refused. */
function sessionOf(values: Record<string, string | boolean | string[] | undefined>): Config['session'] {
  const name = values.session as string | undefined
  const principal = values.principal as string | undefined
  const exp = values['grant-exp'] as string | undefined
  const caveats = (values['grant-caveat'] as string[] | undefined) ?? []
  if (name === undefined) {
    if (principal !== undefined || caveats.length > 0 || exp !== undefined)
      throw usage('--principal, --grant-caveat and --grant-exp go with --session')
    return null
  }
  for (const f of ['as', 'auth', 'chain-cmd', 'mailbox', 'keep-alive-records', 'allow-delegate'])
    if (values[f] !== undefined) throw usage(`--${f} does not go with --session (it makes its own)`)
  if (values['receipts-to'] !== undefined)
    throw usage('--receipts-to does not go with --session: a session answers none')
  if (name !== 'auto' && name !== CODEX_SESSION && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
    throw usage(
      `--session is auto, auto:codex or a name of letters, digits, - and _ (at most 64), not ${JSON.stringify(name)}`,
    )
  }
  if (principal === undefined) throw usage('--session needs --principal <agent identity name>')
  if (caveats.length === 0) throw usage('--session needs --grant-caveat <caveat>, at least one')
  if (exp !== undefined && !EXP_TEXT.test(exp))
    throw usage(`--grant-exp is unix seconds or +seconds, not ${JSON.stringify(exp)}`)
  return { name, principal, caveats: [...new Set(caveats)], exp: exp ?? null }
}

type Values = Record<string, string | boolean | string[] | undefined>
type Env = Readonly<Record<string, string | undefined>>

/** The flags as parseArgs reads them; ConfigError for a flag it cannot take. */
function flagsOf(argv: readonly string[]): Values {
  try {
    return parseArgs({ args: [...argv], options: OPTIONS, allowPositionals: false, strict: true }).values
  } catch (e) {
    throw usage((e as Error).message)
  }
}

/** The server-wide flags: --push, --default-handler, the two timings and --allow-private-relays. */
function serverWideOf(values: Values): ServerWide {
  const push = [...new Set((values.push as string[] | undefined) ?? [])] as Config['push'][number][]
  for (const k of push)
    if (!PUSH_KINDS.includes(k)) throw usage(`--push "${k}" is not resource, log or channel`)
  const handler = (values['default-handler'] as string | undefined) ?? 'queue'
  if (handler !== 'queue') {
    throw usage(
      `--default-handler ${JSON.stringify(handler)}: queue is the only mode in v0 (nothing is spawned)`,
    )
  }
  return {
    maxToolSeconds: maxToolSeconds(values['max-tool-seconds'] as string | undefined),
    progressSeconds: progressSeconds(values['progress-seconds'] as string | undefined),
    push,
    allowPrivateRelays: values['allow-private-relays'] === true,
    defaultHandler: 'queue',
  }
}

/** Parses the flags of one identity; 'help' for --help; ConfigError for a flag it cannot take. */
export function parseConfig(argv: readonly string[], env: Env): Config | 'help' {
  const values = flagsOf(argv)
  return values.help === true ? 'help' : configOf(values, env)
}

/** Parses the flags into the server's identities: the --identities file's (identities.ts), else parseConfig's one. */
export function parseServerConfig(argv: readonly string[], env: Env): ServerConfig | 'help' {
  const values = flagsOf(argv)
  if (values.help === true) return 'help'
  const file = values.identities as string | undefined
  if (file === undefined) {
    const one = configOf(values, env)
    return { identities: [one], defaultLabel: one.label, multi: false, ...serverWideOf(values) }
  }
  for (const f of Object.keys(values))
    if (!SERVER_WIDE.includes(f))
      throw usage(`--${f} does not go with --identities: it goes in the file, or not at all`)
  const wide = serverWideOf(values)
  return { ...readIdentities(file, wide), multi: true, ...wide }
}

/** One identity's Config from its flags. */
function configOf(values: Values, env: Env): Config {
  if (values.identities !== undefined)
    throw usage('--identities is read by parseServerConfig, not parseConfig')
  const session = sessionOf(values)
  const as = (values.as as string | undefined) ?? session?.name
  if (as === undefined) throw usage('--as <key name> or --session auto|auto:codex|<name> is required')
  const relays = ((values.relay as string[] | undefined) ?? []).map((r) => relayUrl(r))
  if (relays.length === 0) throw usage('--relay <url> is required, at least once')
  const given = values.rendezvous as string | undefined
  const rendezvous = given === undefined ? (relays[0] as string) : relayUrl(given, '--rendezvous')
  const trustRootTexts = (values['trust-root'] as string[] | undefined) ?? []
  const honor = [...new Set((values.honor as string[] | undefined) ?? [])]
  for (const name of honor) {
    if (!(PROFILES as readonly string[]).includes(name)) {
      throw usage(`--honor ${JSON.stringify(name)} is not a profile; the profiles are ${PROFILES.join(', ')}`)
    }
  }
  const wide = serverWideOf(values)
  // The inbox resource's URI holds the name, and auto:codex has none until Codex's first tool call.
  if (session?.name === CODEX_SESSION && wide.push.includes('resource'))
    throw usage('--push resource does not go with --session auto:codex (named only at the first tool call)')
  const types = (values['accept-type'] as string[] | undefined) ?? []
  if (types.some((t) => t === '')) throw usage('--accept-type is a type, <prefix>.* or *, not empty')
  const auth = (values.auth as string | undefined) ?? null
  const chainCmd = (values['chain-cmd'] as string | undefined) ?? null
  const mailbox = (values.mailbox as string | undefined) ?? null
  if (auth !== null && chainCmd !== null) {
    throw usage('--auth and --chain-cmd are two sources of one chain: pass one of them')
  }
  if (chainCmd !== null && chainCmd.trim() === '') throw usage('--chain-cmd is a command, not empty')
  const chained = auth !== null || chainCmd !== null
  if (chained && mailbox === null) {
    throw usage(
      "a session (--auth or --chain-cmd) receives at its principal's mailbox: pass --mailbox <principal address>",
    )
  }
  if (!chained && mailbox !== null)
    throw usage('--mailbox is for a session: pass --auth <chain.json> or --chain-cmd <command> too')
  if (mailbox !== null && !isAddress(mailbox)) {
    throw new ConfigError('bad-address', `--mailbox ${JSON.stringify(mailbox)} is not an address`)
  }
  const keepAliveRecords = values['keep-alive-records'] === true
  if (keepAliveRecords && chained) {
    throw usage(
      "--keep-alive-records re-signs this identity's own records: a session cannot sign its principal's",
    )
  }
  return {
    label: as,
    as,
    home: homeDir(values.dir as string | undefined, env),
    relays: [...new Set(relays)],
    rendezvous,
    trustRootTexts,
    trustRoots: trustRootTexts.map((t) => trustedRoot(t)),
    honor,
    acceptTypes: types.length > 0 ? [...new Set(types)] : ['*'],
    auth,
    chainCmd,
    mailbox,
    session,
    allowDelegate: values['allow-delegate'] === true,
    allowSessionDelegation: values['allow-session-delegation'] === true,
    keepAliveRecords,
    receiptsTo: ((values['receipts-to'] as string[] | undefined) ?? []).map((t) =>
      receiptPeer(t, '--receipts-to'),
    ),
    policy: (values.policy as string | undefined) ?? null,
    members: (values.members as string | undefined) ?? null,
    ...wide,
  }
}
