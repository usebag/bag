import { existsSync } from 'node:fs'
import { chainPath, profiles, readSession, type Session, selectOrg } from './session.ts'

// What bag's send and inbox take from the home's live enterprise session when a flag is not given, so that
// `bag send --to <name|address> --body <json>` and `bag inbox --once` need nothing else. send: --as the
// session key (<name>.session), --relay the organisation's first relay, --auth the session's chain. inbox: --as the
// agent (<name>), --relay every organisation relay, --trust-root the organisation's root, an address, so no domain
// lookup runs. A flag given wins, and the relays, the chain and the root follow only the session's own identities.
// The session's domain, given as a trust root (or held in trust.json), reads as that root address too: an instance
// on one machine has no DNS record. With no session, or one that is not live, nothing is filled in. A home with
// several organisations' profiles uses --org's, else the most recently connected, and names it on stderr as status does.

type Values = Readonly<Record<string, unknown>>
type Command = 'send' | 'inbox'
const REQUIRED: Readonly<Record<Command, readonly string[]>> = {
  send: ['as', 'to', 'relay', 'body'],
  inbox: ['as', 'relay'],
}

/**
 * The live session (of `org` when given) with its chain on disk and its local hop unexpired; else why not (a string),
 * or null for none.
 */
export function liveSession(at: () => string, now: number, org?: string): Session | string | null {
  let home: string
  let s: Session | null
  try {
    home = at()
  } catch {
    return null // no home: no session, and the command says what it lacks
  }
  try {
    s = readSession(home, org)
  } catch {
    return 'the enterprise session file does not read'
  }
  if (s === null) return org === undefined ? null : `no enterprise session of ${org} in this home`
  const chain = s.hop !== null && (s.local_hop?.exp ?? 0) > now && existsSync(chainPath(home, s.domain))
  if (s.state === 'live' && chain && s.org.relays.length > 0) return s
  const why = s.state !== 'live' ? s.state : chain ? 'live, with no relays' : 'live, without a live chain'
  return `the enterprise session of ${s.domain} is ${why}: bag status`
}

/** What a command needs of its caller: the clock, a stderr line, and the home of a --dir (or none). */
export interface SessionIo {
  readonly clock: { now(): number }
  err(line: string): void
}

/**
 * Parsed `send` or `inbox` flags with what a live session knows filled in where a flag is absent, then checked for the
 * command's required flags (a `Fail`, `--<flag> is required ...`, naming why the session filled nothing in when it
 * exists); `root` maps a trust root as inbox takes it, the session's domain to its root address.
 */
export function withSession<P extends { readonly values: Values }>(
  p: P,
  command: Command,
  io: SessionIo,
  home: (dir: string | undefined) => string,
  Fail: new (detail: string) => Error,
): P & { readonly root: (text: string) => string } {
  const v: Record<string, unknown> = { ...p.values }
  const keys = command === 'send' ? ['as', 'relay', 'auth'] : ['as', 'relay', 'trust-root']
  const need = command === 'inbox' || keys.some((k) => v[k] === undefined)
  const [dir, org] = [v.dir as string | undefined, v.org as string | undefined]
  const s = need ? liveSession(() => home(dir), io.clock.now(), org) : null
  const live = typeof s === 'object' ? s : null
  const before = JSON.stringify(v)
  if (live !== null && command === 'send') {
    const sender = `${live.name}.session`
    v.as ??= sender
    if (v.as === sender) v.relay ??= live.org.relays[0]
    if (v.as === sender) v.auth ??= chainPath(home(dir), live.domain)
  } else if (live !== null) {
    v.as ??= live.name
    if (v.as === live.name) v.relay ??= [...live.org.relays]
    if (v.as === live.name) v['trust-root'] ??= [live.org.root]
  }
  if (live !== null && org === undefined && JSON.stringify(v) !== before) named(io, home(dir), live.domain)
  const why = typeof s === 'string' ? ` (${s})` : ''
  for (const k of REQUIRED[command]) if (v[k] === undefined) throw new Fail(`--${k} is required${why}`)
  const root = (text: string): string => (live !== null && text === live.domain ? live.org.root : text)
  return { ...p, values: v, root }
}

/** With several profiles and no --org, the one line status prints: the organisation used and the others. */
function named(io: SessionIo, home: string, used: string): void {
  const others = profiles(home).filter((d) => d !== used)
  if (others.length === 0) return
  const which = selectOrg(home) === used ? 'the most recently connected' : 'the one with a session'
  io.err(`bag: using ${used}, ${which}; also signed in to ${others.join(', ')} (--org)`)
}
