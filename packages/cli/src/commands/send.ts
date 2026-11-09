import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs'
import { checkThread, isAddress, isHandle, MAX_ENVELOPE_BYTES } from '@usebag/core'
import { type Edge, membershipHop, type OutboxTarget, SendHeld, type SendResult } from '@usebag/edge'
import { resolveHandle, withSession } from '@usebag/enterprise-client'
import { CliError, flag, list, type Parsed, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { readChain } from '../chain.ts'
import { CLI_SESSION, homeDir, type OpenEdge, openEdge } from '../home.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'
import { loadRecords, type OrgRecords, withRecords } from '../policy.ts'
import { readTrust } from '../trust.ts'
import { groupStore } from './group.ts'

/** The next step after a 403 root-not-accepted, naming the root the recipient's accept-from record should list. */
export function rootHint(root: string): string {
  return `the recipient does not accept this identity's root yet: ask them to add ${root} (or your org's domain root) to their accept-from record, or send under a chain from a root they accept (send --auth / delegate)`
}

/** What a refusal says when that peer had finished pairing: its accept-from has dropped this root since (ac unpair). */
export function unpairedNote(peer: string, address: string, as: string, relay: string): string {
  return `${peer} no longer accepts mail from you (it unpaired you): ask them to pair again, or run unpair ${address} --as ${as} --relay ${relay} to stop keeping their root (this is not a relay ban)`
}

/**
 * The note for the one recipient a finished pairing left in this home, by what a pairing writes: its name in the book
 * and its address in the trust file. Null for several (the refusal does not say which), a former address, and a file
 * that does not read: the refusal still goes out, with the accept-from hint.
 */
export function unpaired(io: Io, p: Parsed, to: readonly string[]): string | null {
  const [peer] = to
  if (peer === undefined || to.length > 1) return null
  try {
    const home = homeDir(io, str(p, 'dir'))
    const known = NameBook.load(home).display(peer)
    if (known === null || known.former || !Object.hasOwn(readTrust(home), peer)) return null
    return unpairedNote(known.name, peer, req(p, 'as'), relayUrl(req(p, 'relay')))
  } catch {
    return null
  }
}

/** One target's line: its state and relay, its tries, and its reason or next try when it has one. */
export function targetLine(t: OutboxTarget): string {
  const reason = t.reason === null ? '' : ` reason=${t.reason}`
  const next = t.nextAt === null ? '' : ` next_at=${t.nextAt}`
  return `${t.state} ${t.relay} tries=${t.tries}${reason}${next}`
}

/**
 * Prints a send's id and one line per target; fails with the reason of a target that was not published (its bytes
 * stay in the outbox, and resend sends them), naming the next step for root-not-accepted: `note`'s when it has one and
 * the envelope is signed under this identity's own root (a pairing says nothing of a chain's), else rootHint.
 */
export function reportSent(
  io: Io,
  edge: Edge,
  result: Pick<SendResult, 'id' | 'targets'>,
  note: () => string | null = () => null,
): number {
  io.out(result.id)
  for (const t of result.targets) io.out(targetLine(t))
  const unsent = result.targets.find((t) => t.state !== 'published')
  // A target that was not published is in retry or failed, and both carry the relay's code or publish-failed.
  if (unsent !== undefined) {
    // A 403 root-not-accepted: the recipient's accept-from record does not list this identity's root.
    const root = unsent.reason === 'root-not-accepted' ? (edge.auth[0]?.iss ?? edge.address) : null
    const next = root === null ? '' : `; ${(edge.auth.length === 0 ? note() : null) ?? rootHint(root)}`
    throw new CliError(
      `${unsent.reason}`,
      `${unsent.relay} ${unsent.state}; the bytes stay in the outbox, and resend --id ${result.id} sends them${next}`,
    )
  }
  return 0
}

/**
 * --body as given; `@-`, the JSON on stdin, read whole; `@<path>`, a regular file, never through a symbolic link. Either
 * is at most the envelope cap (body-too-large), so text from elsewhere never has to be quoted into the command line.
 */
async function bodyText(io: Io, text: string): Promise<string> {
  if (!text.startsWith('@')) return text
  const big = () =>
    new CliError('body-too-large', `--body ${text}: over ${MAX_ENVELOPE_BYTES} bytes, the envelope cap`)
  if (text === '@-') return (await io.readAll?.(MAX_ENVELOPE_BYTES)) ?? Promise.reject(big())
  const fd = openSync(text.slice(1), constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw new UsageError(`--body ${text} is not a regular file`)
    if (st.size > MAX_ENVELOPE_BYTES) throw big()
    return readFileSync(fd, 'utf8')
  } finally {
    closeSync(fd)
  }
}

/** True for a --to that is resolved without the name book: an address, or a handle (spec/SPEC.md §12.3). */
const unnamed = (t: string): boolean => isAddress(t) || isHandle(t)

/**
 * send --as <name> --to <name|address|handle>... --relay <url> --body <json|@-|@file> [--type <type>] [--auth <chain.json>]
 * [--thread <id> [--prev <id>...]] [--policy <file>] [--members <file>] [--allow-private-relays] [--dir <home>]: one
 * envelope through the edge's Sender, sealed to every recipient, its exact bytes kept in the outbox and published to every recipient relay (the relay
 * given looks the recipients' records up). The identity signs as its own root, or, with --auth, as a session under the
 * chain that delegate wrote: `from` is the identity, the chain's last subject must be it, and its first issuer is the
 * root the recipient trusts. The chain is the relay's and the recipient's to judge: an expired hop is the
 * relay's hop-expired. A recipient relay on a private, loopback or link-local address other than --relay is refused
 * resolve-failed (the edge's guard) unless --allow-private-relays turns the guard off. Prints the id, then one
 * line per target; fails with the reason of a target that was not published (its bytes stay in the outbox). A --to
 * that is neither an address nor a handle is resolved through the home's name book (names.ts): name-unknown when the
 * book lacks it. A handle, `jane@acme.example`, is resolved by the edge (spec/SPEC.md §12.4 item 4: the domain's TXT
 * record, its org record, the handle record under the org's pinned key, checked against the org's revoked list at
 * every send) to its address, whose records are read at the org record's relays first; a step that fails is
 * resolve-failed naming it (or revoked), and nothing is sent. A handle whose domain is a profile of the home with a
 * session is first the organisation's directory's agent of that label (resolveHandle); a miss, or a directory that
 * cannot answer (a line on stderr), takes the public path.
 * With --members, the edge sends through its outbound gate: a recipient the deny list names is refused
 * policy-refused before sealing, and a send a breaker trips is held: `held <id> <rule>`, for a person (held.ts).
 */
export async function send(args: readonly string[], io: Io): Promise<number> {
  const spec = {
    positionals: [],
    options: {
      as: { type: 'string' },
      to: { type: 'string', multiple: true },
      relay: { type: 'string' },
      type: { type: 'string' },
      body: { type: 'string' },
      auth: { type: 'string' },
      thread: { type: 'string' },
      prev: { type: 'string', multiple: true },
      policy: { type: 'string' },
      members: { type: 'string' },
      'allow-private-relays': { type: 'boolean' },
      dir: { type: 'string' },
      org: { type: 'string' },
    },
  } as const
  const p = withSession(parse(args, spec), 'send', io, (d) => homeDir(io, d), UsageError)
  // A --to that is neither an address nor a handle is a name: the book is read only then.
  const given = list(p, 'to')
  const book = given.every(unnamed) ? null : NameBook.load(homeDir(io, str(p, 'dir')))
  // A handle of a profile's own organisation is the directory's agent first (resolveHandle), else the public path.
  const own = { ...(io.fetch && { fetch: io.fetch }), warn: (line: string) => io.err(line) }
  const handle = async (t: string) =>
    isHandle(t) ? ((await resolveHandle(homeDir(io, str(p, 'dir')), t, own)) ?? t) : t
  const named = await Promise.all(
    given.map((t) => (unnamed(t) ? handle(t) : (book as NameBook).find(t, io.fetch, str(p, 'org')))),
  )
  let body: unknown
  try {
    body = JSON.parse(await bodyText(io, req(p, 'body')))
  } catch (e) {
    throw e instanceof CliError || (e as { code?: unknown }).code !== undefined
      ? e
      : new UsageError('--body is not JSON')
  }
  const [threadId, prev] = [str(p, 'thread'), list(p, 'prev')]
  if (threadId === undefined && prev.length > 0) throw new UsageError('--prev needs --thread')
  const thread = threadId === undefined ? undefined : checkThread({ id: threadId, prev })
  const { opened } = openSender(io, p, named)
  try {
    const { edge } = opened
    const { to, relays } = await edge.resolver.addresses(named)
    const input = {
      to,
      relays,
      type: str(p, 'type') ?? 'chat.v1',
      body,
      session: CLI_SESSION,
      ...(thread === undefined ? {} : { thread }),
    }
    const sent = await edge.send(input).catch((e: unknown) => {
      if (e instanceof SendHeld) return e.held
      throw e
    })
    if (!('held' in sent)) return reportSent(io, edge, sent, () => unpaired(io, p, to))
    io.out(`held ${sent.id} ${sent.rule}`)
    io.out(
      `nothing was sealed or sent: a person releases or drops it on a terminal (held release|drop ${sent.id})`,
    )
    return 0
  } finally {
    opened.close()
  }
}

/** The edge send and held open: --as at --relay, under --auth or a held group's hop, with the org's records. */
export function openSender(io: Io, p: Parsed, to: string[] = []): { opened: OpenEdge; records: OrgRecords } {
  const [chain, home, g = ''] = [str(p, 'auth'), homeDir(io, str(p, 'dir')), ...to]
  const groups = groupStore(home, req(p, 'as'))
  const held = to.length === 1 && isAddress(g) && !groups.state(g) && groups.generations(g).length > 0
  const records = loadRecords(str(p, 'policy'), str(p, 'members'), io.clock.now())
  const opened = openEdge(io, {
    home,
    name: req(p, 'as'),
    relay: relayUrl(req(p, 'relay')),
    client: io.relay({}),
    policy: withRecords({ roots: [], types: [] }, records),
    auth: chain !== undefined ? readChain(chain) : held ? [membershipHop(groups, g)] : [],
    allowPrivateRelays: flag(p, 'allow-private-relays'),
  })
  return { opened, records }
}
