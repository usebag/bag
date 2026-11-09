import { type AddressRecord, isAddress, isDomainHost } from '@usebag/core'
import {
  acceptPeer,
  continueFrom,
  digitsMatch,
  INVITE_PREFIX,
  inviteOf,
  invitePeer,
  keepAddressCopy,
  type Lagging,
  MAX_DIGIT_TRIES,
  MAX_INVITE_TTL,
  RelayGuard,
  refuseOtherInviter,
} from '@usebag/edge'
import { CliError, flag, int, type Parsed, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { currentKey, laggingLines } from '../epochs.ts'
import { homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'
import { instant, NAME, NameBook } from '../names.ts'
import { confirmed, needTty } from '../policy.ts'
import { addTrust } from '../trust.ts'

// peer invite and peer accept: one ceremony pairs two identities, CLI only, on two
// terminals. The protocol is the edge's (packages/edge/src/pairing.ts); the CLI parses the arguments, asks the two
// questions, prints the lines, and writes the name book and the trust file. Neither command opens the edge store.
// Under forward secrecy each side pairs with its current key record (currentKey), publishing a new epoch first
// when one is due, so its lines may begin with rotateEpoch's `published key ...`. When the rendezvous relay (--rendezvous,
// by default --relay; both sides name the same one) offers pair/open, the inviter prints a short pairing code to send
// else the invite string. The acceptor's person reads the check digits
// out; the inviter's never sees them and types what it hears, so a
// reflexive y cannot admit a peer. The acceptor hears nothing of a mismatch: it gets no-answer at the invitation's end.
// A name the book holds stops either command at its first step, before a code goes out or a person is asked, since the
// peer's address may come only with its request, after the whole ceremony; it goes on only under --for, its own address.

const S = { type: 'string' } as const
const PRIVATE = { 'allow-private-relays': { type: 'boolean' } } as const

/** peer invite | peer accept. */
export function peer(args: readonly string[], io: Io): Promise<number> {
  const [verb, ...rest] = args
  if (verb === 'invite') return invite(rest, io)
  if (verb === 'accept') return accept(rest, io)
  throw new UsageError('peer invite ... | peer accept ... <code or invite>')
}

/**
 * What both commands take: a terminal first (no-tty before any network), then the name, --for, the home, the book's
 * check of the name, the keys and the root to trust: the peer's address, or with --trust-domain <host> the domain root
 * `domain:<host>` (no port, SPEC.md §7.4) of a peer whose chains its org signs, which the question names before the y.
 * A rendezvous relay on a private or loopback address other than --relay and --rendezvous (a code's @host) is
 * resolve-failed unless --allow-private-relays (spec/SPEC.md §9 item 11). `named` is the book as it is now with the
 * peer named: it refuses a name taken since the first check, and a save from it keeps what another command wrote.
 */
/** The edge's pairing ports for `as` in `home`: the relay client, the guard over `own`, the epochs' steps. */
export function pairingPorts(
  io: Io,
  home: string,
  as: string,
  keys: ReturnType<typeof loadKeys>,
  own: string[],
  allowPrivate = false,
) {
  return {
    client: io.relay({}),
    clock: io.clock,
    rng: io.rng,
    pollMs: io.idleMs,
    guard: new RelayGuard({ own, allowPrivate }),
    continueFrom: (found: AddressRecord | null) => continueFrom(found, home, as, keys.signing.address),
    keepAddress: (r: AddressRecord) => keepAddressCopy(home, as, r),
    lagging: (lag: Lagging) => laggingLines(io, keys.signing.address, [lag]),
  }
}

function common(p: Parsed, io: Io, what: string) {
  needTty(io, what)
  const name = req(p, 'name')
  if (!NAME.test(name)) throw new UsageError(`--name ${JSON.stringify(name)} is not a name (${NAME.source})`)
  const only = str(p, 'for')
  if (only !== undefined && !isAddress(only)) throw new UsageError('--for takes an address')
  const domain = str(p, 'trust-domain')
  if (domain !== undefined && !isDomainHost(domain)) {
    throw new UsageError(`--trust-domain ${JSON.stringify(domain)} is not a host (a DNS name, no port)`)
  }
  const home = homeDir(io, str(p, 'dir'))
  NameBook.load(home).check(name, only)
  const named = (peer: string): NameBook => {
    const book = NameBook.load(home)
    book.check(name, peer)
    book.add(name, peer, io.clock.now())
    return book
  }
  const as = req(p, 'as')
  const keys = loadKeys(io, home, as)
  const root = (address: string): string => (domain === undefined ? address : `domain:${domain}`)
  const also = domain === undefined ? '' : `, trusting every agent of ${domain}`
  const relay = relayUrl(req(p, 'relay'))
  const rendezvous = relayUrl(str(p, 'rendezvous') ?? relay)
  const ports = pairingPorts(io, home, as, keys, [relay, rendezvous], flag(p, 'allow-private-relays'))
  const key = (): ReturnType<typeof currentKey> => currentKey(io, home, as, keys, relay)
  return { home, keys, key, ports, relay, rendezvous, name, only, named, root, also }
}

/**
 * peer invite --as <name> --relay <url> [--rendezvous <url>] --name <petname> [--for <address>] [--ttl <s>]
 * [--trust-domain <host>] [--allow-private-relays] [--dir <home>]: name-exists at once for a --name the book holds
 * under any address but --for's; prints `pairing code <code>` (or `invite <string>` when the rendezvous relay offers
 * no pair call) and its end, `refused <address> <code>` per refused request, the first good request and the
 * ask to type its digits, never the digits (MAX_DIGIT_TRIES tries, then digits-mismatch; the end of input declines),
 * `second request <address>: the invite string leaked` per later request, and `paired <name> <address>`.
 */
async function invite(args: readonly string[], io: Io): Promise<number> {
  const options = {
    as: S,
    relay: S,
    rendezvous: S,
    name: S,
    for: S,
    ttl: S,
    dir: S,
    'trust-domain': S,
    ...PRIVATE,
  }
  const p = parse(args, { positionals: [], options, required: ['as', 'relay', 'name'] })
  const ttl = int(p, 'ttl') ?? MAX_INVITE_TTL
  if (ttl > MAX_INVITE_TTL) throw new UsageError(`--ttl is at most ${MAX_INVITE_TTL} seconds, not ${ttl}`)
  const { home, keys, key, ports, relay, rendezvous, name, only, named, root, also } = common(
    p,
    io,
    'peer invite',
  )
  const say = 'the other side reads you six digits, and you type them here'
  const q = await invitePeer(ports, {
    relay,
    rendezvous,
    keys,
    key: await key(),
    ttl,
    ...(only === undefined ? {} : { only }),
    opened: (text, exp) => {
      io.out(text.startsWith(INVITE_PREFIX) ? `invite ${text}` : `pairing code ${text}`)
      io.out(`one request until ${instant(exp)}; ${say}`)
    },
    refused: (from, code) => io.out(`refused ${from} ${code}`),
    ask: async (q) => {
      named(q.from)
      io.out(`request ${q.from}`)
      io.out(`to pair with it as ${name}${also}, type the six digits the other side reads you`)
      for (let left = MAX_DIGIT_TRIES - 1; left >= 0; left--) {
        const typed = await io.readLine()
        if (typed === null) return false
        if (digitsMatch(typed, q.code)) return true
        if (left > 0) io.out(`no match; tries left: ${left}; ask the other side to repeat them`)
      }
      throw new CliError('digits-mismatch', 'the typed digits did not match; nothing was written')
    },
    leaked: (from) => io.out(`second request ${from}: the invite string leaked`),
    write: (q) => {
      named(q.from).save()
      addTrust(home, root(q.from), io.clock.now())
    },
  })
  io.out(`paired ${name} ${q.from}`)
  return 0
}

/**
 * peer accept --as <name> --relay <url> [--rendezvous <url>] --name <petname> [--for <address>] <code or invite>
 * [--trust-domain <host>] [--allow-private-relays] [--dir <home>]: name-exists at once for a --name the book holds
 * under any address but --for's; prints the inviter and the check digits (a code's nameplate claimed first at the
 * rendezvous relay, or at the code's @host; not-for, nothing sent, for an inviter other than --for), asks, prints
 * `requested; waiting until <end> for the inviter's answer`, then `paired <name> <address>`.
 */
async function accept(args: readonly string[], io: Io): Promise<number> {
  const options = { as: S, relay: S, rendezvous: S, name: S, for: S, dir: S, 'trust-domain': S, ...PRIVATE }
  const p = parse(args, { positionals: ['invite'], options, required: ['as', 'relay', 'name'] })
  const { home, keys, key, ports, relay, rendezvous, name, only, named, root, also } = common(
    p,
    io,
    'peer accept',
  )
  const v = await inviteOf(ports, rendezvous, p.positionals[0] as string)
  refuseOtherInviter(v, only)
  named(v.inviter)
  await acceptPeer(ports, keys, relay, v, {
    key: await key(),
    ask: async (code) => {
      io.out(`inviter ${v.inviter} at ${v.relay}`)
      io.out(`check digits ${code}`)
      io.out('read them out now, not where the code was sent, before you answer: that is the security check')
      await confirmed(io, `pair with it as ${name}${also}?`, 'no request was sent; nothing was written')
    },
    sent: (exp) => io.out(`requested; waiting until ${instant(exp)} for the inviter's answer`),
    write: () => {
      named(v.inviter).save()
      addTrust(home, root(v.inviter), io.clock.now())
    },
  })
  io.out(`paired ${name} ${v.inviter}`)
  return 0
}
