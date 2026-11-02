import {
  type CaveatEvaluator,
  codingEvaluator,
  domainOfRoot,
  GROUP_KEY_TYPE,
  groupEvaluator,
  isAddress,
  parseEnvelope,
  type SealedContent,
  verifyChain,
} from '@usebag/core'
import {
  type AcceptOptions,
  acceptGroupKey,
  type Frame,
  type InboxRow,
  memberKeys,
  membershipHop,
  type Receiver,
  type RelayClient,
  type Resolver,
  type Subscription,
  type SubscriptionLink,
  type TrustedRoot,
} from '@usebag/edge'
import { flag, list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import {
  CLI_SESSION,
  checkIdentity,
  doorbellPath,
  homeDir,
  loadKeys,
  type OpenEdge,
  type OpenOptions,
  openEdge,
  receivingKeys,
} from '../home.ts'
import type { Io } from '../io.ts'
import { instant, NameBook, short } from '../names.ts'
import { confirmed, loadRecords, needTty, type Quarantined, quarantinedLine, withRecords } from '../policy.ts'
import { readTrust } from '../trust.ts'
import { groupStore } from './group.ts'

// inbox: the edge's Receiver at one relay. The CLI wraps the subscription the Receiver reads, to print each frame's
// outcome when the Receiver acks it, and, for --once, to end the stream once no frame has come for io.idleMs.

// A host name with an optional port, as the edge's well-known resolver takes it.
const DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/

/** The caveat profiles inbox --honor names: the coding profile's type= and repo= caveats (spec/SPEC.md §6.4). */
export const PROFILES: ReadonlyMap<string, CaveatEvaluator> = new Map([['coding', codingEvaluator]])

/** The evaluators of the --honor values; UsageError for a profile that does not exist. */
export function honored(names: readonly string[]): CaveatEvaluator[] {
  return [...new Set(names)].map((name) => {
    const evaluator = PROFILES.get(name)
    if (evaluator === undefined) {
      throw new UsageError(
        `--honor ${JSON.stringify(name)} is not a profile; the profiles are ${[...PROFILES.keys()]}`,
      )
    }
    return evaluator
  })
}

/** A --trust-root value: an address, trusted by key, or a domain, whose well-known record is pinned at first use. */
export function trustedRoot(text: string): TrustedRoot {
  if (isAddress(text)) return { address: text }
  if (DOMAIN.test(text)) return { domain: text }
  throw new UsageError(`--trust-root ${JSON.stringify(text)} is neither an address nor a domain`)
}

/**
 * <from> for a person (display: petname, verified handle, address): the name book's label, or, when the
 * edge holds a verified handle for the message's principal, the petname (with its former-address mark), the handle
 * `local@domain`, then the short address, and the former-address warning last.
 */
export function fromLabel(book: NameBook, from: string, handle: string | null): string {
  if (handle === null) return book.label(from)
  const d = book.display(from)
  const name = d === null ? '' : `${d.name}${d.former ? '?' : ''} `
  const label = `${name}${handle} (${short(from)})`
  return d?.former === true
    ? `${label} WARNING: former address of ${d.name}, replaced ${instant(d.replacedAt)}`
    : label
}

/**
 * The line of a handled row: `accept <id> <from> <root> <type> <body>`, `reject <id> <code>`, or `quarantined <id>
 * <code>` for a row the org's policy holds (no body: none is stored; inbox --quarantined names its rule). A row that
 * waits for a retry after a transient rejection (received, with its code) prints as rejected with that
 * code, as it did before; when a retry accepts it, the Receiver acks it again and it prints as accepted. With the
 * home's name book, <from> and <root> print through its label: "<name> (<short>)", a former address with its
 * warning, or as is. A verified handle of the principal, or else of the sender, follows the petname in <from>
 * (fromLabel): only from a handle
 * record the edge resolved and holds, unexpired, under the domain's pinned key, signed by the chain's root
 * (Resolver.handleOf); a handle is shown only for a peer this edge has resolved by handle. <type> is shownType's.
 */
export function rowLine(row: InboxRow, book: NameBook, resolver: Pick<Resolver, 'handleOf'>): string {
  if (row.state === 'quarantined') return `quarantined ${row.id} ${row.reason}`
  if (row.state === 'rejected' || row.state === 'received') return `reject ${row.id ?? '-'} ${row.reason}`
  const env = parseEnvelope(row.bytes)
  const { root, principal } = verifyChain(env.auth, env.from, env.ts)
  const content = JSON.parse(row.content as string) as SealedContent
  // The principal's handle (a person under an org), else the sender's: under onboard's one-hop chain the
  // principal is the org itself and the handle record names the agent that sent. Either must be signed by the root.
  const handle = (resolver.handleOf(principal, root) ?? resolver.handleOf(env.from, root))?.handle ?? null
  const from = fromLabel(book, env.from, handle)
  return `accept ${env.id} ${from} ${book.label(root)} ${shownType(content.type)} ${JSON.stringify(content.body)}`
}

/** The states rowLine prints as `reject` (rejected, or received and waiting for a retry) or `quarantined`. */
export const REFUSED: ReadonlySet<string> = new Set(['rejected', 'received', 'quarantined'])

/**
 * A message's type as a line shows it: a short token as is, anything else `(not shown)`. The core refuses a type
 * with a control character or a line separator at decode (SPEC §5.2), but a space or other non-token character is
 * still legal and would forge fields here, so a line shows a short token only.
 */
export function shownType(type: string): string {
  return /^[\w.+*-]{1,64}$/.test(type) ? type : '(not shown)'
}

/** A live inbox's lines for its connection, one when it goes and one when it is back: why nothing arrives, for a person. */
export function linkLines(io: Pick<Io, 'err'>): (link: SubscriptionLink) => void {
  let lost = false
  return (link) => {
    if (link.admitted !== lost) return
    lost = !link.admitted
    io.err(link.admitted ? 'bag: subscribed again' : `bag: ${link.error.message}; trying again`)
  }
}

/** A subscription that reports every ack, and, given an idle limit, ends when no frame arrives within it. */
export class ObservedSubscription implements Subscription {
  readonly #inner: Subscription
  readonly #idleMs: number | null
  readonly #onAck: (cursor: number) => void

  constructor(inner: Subscription, idleMs: number | null, onAck: (cursor: number) => void) {
    this.#inner = inner
    this.#idleMs = idleMs
    this.#onAck = onAck
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<Frame> {
    const frames = this.#inner[Symbol.asyncIterator]()
    for (;;) {
      const next = await this.#next(frames)
      if (next === null || next.done === true) return
      yield next.value
    }
  }

  ack(cursor: number): void {
    this.#inner.ack(cursor)
    this.#onAck(cursor)
  }

  close(): void {
    this.#inner.close()
  }

  async #next(frames: AsyncIterator<Frame>): Promise<IteratorResult<Frame> | null> {
    const pending = frames.next()
    if (this.#idleMs === null) return pending
    let timer: NodeJS.Timeout | undefined
    const idle = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), this.#idleMs as number)
    })
    try {
      return await Promise.race([pending, idle])
    } finally {
      clearTimeout(timer)
    }
  }
}

const [S, M, B] = [{ type: 'string' }, { type: 'string', multiple: true }, { type: 'boolean' }] as const
const OPTIONS = { as: S, once: B, quarantined: B, policy: S, members: S, dir: S, group: S }
const FLAGS = { 'allow-private-relays': B, 'doorbell-path': B }

/**
 * inbox --as <name> --relay <url>... [--once] [--quarantined] [--trust-root <domain|address>...] [--honor <profile>...]
 * [--accept-type <type>...] [--policy <file>] [--members <file>] [--allow-private-relays] [--doorbell-path] [--dir
 * <home>]: receives at the identity's mailbox through the edge's Receiver (verify, policy, dedup, unseal, caveats,
 * route, ack, every step audited) and prints one line per handled frame (rowLine). No --trust-root trusts no one
 * (every message is untrusted-root); no --honor honors no caveat profile, so any caveat fails closed
 * (unknown-caveat), and --honor coding evaluates the coding profile's; no --accept-type accepts every type.
 * --allow-private-relays turns the edge's private-address guard off, as for send; the receive path calls only --relay
 * today, which the guard always allows. --once ends when no frame has come for a second; without it, inbox runs until
 * SIGINT or SIGTERM. The home's name book, read once at start, labels <from> and <root> (rowLine). --policy and
 * --members are the org's records (policy.ts). --quarantined prints the rows they hold, `<seq> <id> <from> <root>
 * <rule>`, and ends. `inbox release|drop <seq>` (same options) is a person's act on a terminal (no-tty
 * otherwise): the row's line, a question, then release checks the row again with its rule waived, or drop rejects it
 * policy-refused; it prints `<seq> <state> <reason>` and, for an accepted row, its line. The edge rings the
 * identity's doorbell for each accepted message (home.ts, openEdge). --doorbell-path prints `doorbell
 * <absolute path>` once, first, before anything is received (--once too). `shown`, given, takes each handled row and
 * its line in place of printing it (inbox --watch, watch.ts).
 */
export async function inbox(
  args: readonly string[],
  io: Io,
  shown?: (row: InboxRow, line: string) => void,
): Promise<number> {
  const show = shown ?? ((_row: InboxRow, line: string) => io.out(line))
  const act = args[0] === 'release' || args[0] === 'drop' ? args[0] : null
  const p = parse(act === null ? args : args.slice(1), {
    positionals: act === null ? [] : ['seq'],
    options: { ...OPTIONS, ...FLAGS, relay: M, 'trust-root': M, honor: M, 'accept-type': M },
    required: ['as', 'relay'],
  })
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  const relay = relays[0] as string
  const home = homeDir(io, str(p, 'dir'))
  // The book is read once, at start: a name added while inbox runs shows from its next start.
  const book = NameBook.load(home)
  const [name, group] = [req(p, 'as'), str(p, 'group')]
  const g = group === undefined ? [] : [book.resolve(group)]
  const stored = Object.keys(readTrust(home)).map((r) => domainOfRoot(r) ?? r) // a domain root reads as its host
  const roots = [...list(p, 'trust-root'), ...stored, ...g].map(trustedRoot)
  const evaluators = [...honored(list(p, 'honor')), ...(group === undefined ? [] : [groupEvaluator])]
  const types = list(p, 'accept-type')
  const seq = act === null ? 0 : seqOf(p.positionals[0] as string)
  if (act !== null) needTty(io, `inbox ${act}`)
  const records = loadRecords(str(p, 'policy'), str(p, 'members'), io.clock.now())
  const once = flag(p, 'once') || act !== null || flag(p, 'quarantined')
  const policy = withRecords({ roots, types: types.length > 0 ? types : ['*'], evaluators }, records)
  const allowPrivateRelays = flag(p, 'allow-private-relays')
  if (flag(p, 'doorbell-path')) {
    // The name and the identity are checked before a path is printed: the custody refuses a name that could leave the
    // state directory, and a home without the identity is ENOENT.
    checkIdentity(io, home, name)
    io.out(`doorbell ${doorbellPath(home, name)}`)
  }
  const receive = async (live: boolean, o: Partial<OpenOptions>, accept?: Omit<AcceptOptions, 'audit'>) => {
    const signal = live ? io.stopSignal() : undefined
    const base = io.relay(live ? {} : { maxReconnects: 0 })
    const linkLine = live ? linkLines(io) : undefined
    let opened: OpenEdge | undefined
    // An accepted row prints from the edge's `accepted`, once, when the edge acks it on any path (a frame, the
    // retrier, recover()); a frame's ack prints only a refused, waiting or held row, before the edge acks it.
    const onAck = (url: string, cursor: number): void => {
      const { edge, store } = opened as OpenEdge
      const row = store.inboxFind(url, edge.mailbox, cursor) as InboxRow
      // Read at two relays a message arrives twice: the copy is no refusal worth a line.
      if (relays.length > 1 && row.reason === 'duplicate') return
      if (REFUSED.has(row.state)) show(row, rowLine(row, book, edge.resolver))
    }
    // inbox release prints its row in decide(), so it takes no `accepted`.
    const accepted = (row: InboxRow): void =>
      show(row, rowLine(row, book, (opened as OpenEdge).edge.resolver))
    const client: RelayClient = {
      publish: base.publish.bind(base),
      fetch: base.fetch.bind(base),
      fetchRecord: base.fetchRecord.bind(base),
      subscribe: (url, mailbox, signer, hops, cursor) =>
        new ObservedSubscription(
          base.subscribe(url, mailbox, signer, hops, cursor, linkLine),
          live ? null : io.idleMs,
          (cursor) => onAck(url, cursor),
        ),
    }
    // A throw from `accepted` (the edge reports it, the row stays acked) is one stderr line, as the doorbell's is.
    const onError = (e: unknown): void =>
      io.err(`bag: accepted: ${e instanceof Error ? e.message : String(e)}`)
    const seam = act === null ? { accepted, onError } : {}
    opened = openEdge(io, { home, name, relay, relays, client, policy, allowPrivateRelays, ...seam, ...o })
    const { edge } = opened
    try {
      if (act !== null) return await decide(act, seq, edge, book, io)
      if (flag(p, 'quarantined')) {
        for (const q of edge.receiver.quarantined()) io.out(quarantinedLine(q, book))
        return 0
      }
      const deliver = (m: Parameters<typeof acceptGroupKey>[0]): void => {
        if (accept === undefined || m.type !== GROUP_KEY_TYPE) return
        const { body, kept } = acceptGroupKey(m, { ...accept, audit: edge.audit })
        io.out(`group-key ${book.label(body.group)} generation ${body.generation} ${kept}`)
      }
      edge.setDefault({ session: CLI_SESSION, deliver })
      // recover() acks every row it finishes, so its accepted rows have printed from `accepted`; the rest print here.
      for (const row of await edge.receiver.recover()) {
        if (REFUSED.has(row.state)) show(row, rowLine(row, book, edge.resolver))
      }
      const at = o.mailbox === undefined ? null : (await edge.resolver.recipient(o.mailbox)).relays[0]
      // One subscription per relay (spec/SPEC.md §9 item 10): a relay that stays down costs the others nothing.
      const ran = await Promise.allSettled((at ? [at] : relays).map((url) => edge.receiver.run(url, signal)))
      const down = ran.flatMap((r) => (r.status === 'rejected' ? [r.reason as unknown] : []))
      if (down.length === ran.length && down.length > 0) throw down[0]
      for (const e of down) io.err(`bag: a relay ended: ${e instanceof Error ? e.message : String(e)}`)
      return 0
    } finally {
      opened.close()
    }
  }
  if (g[0] === undefined) return receive(!once, {})
  if (act !== null || flag(p, 'quarantined')) throw new UsageError('--group: no release, drop, --quarantined')
  // The identity's epoch-aware keys: its own mailbox, and the group-key messages sealed to its current epoch key,
  // which a member's opener opens again at each generation it holds.
  const [keys, store] = [receivingKeys(home, loadKeys(io, home, name)), groupStore(home, name)]
  await receive(false, { keys }, { keys, store, clock: io.clock })
  const auth = [membershipHop(store, g[0])]
  return receive(!once, { keys: memberKeys(store, g[0], keys, io.clock), mailbox: g[0], auth })
}

/** A row number: decimal digits from 1 on. */
function seqOf(text: string): number {
  if (!/^[1-9][0-9]{0,15}$/.test(text))
    throw new UsageError(`<seq> is a row number, not ${JSON.stringify(text)}`)
  return Number(text)
}

/** inbox release|drop <seq>, once the person at the terminal confirms; a row not quarantined has the edge's refusal. */
async function decide(
  act: 'release' | 'drop',
  seq: number,
  edge: { readonly receiver: Receiver; readonly resolver: Pick<Resolver, 'handleOf'> },
  book: NameBook,
  io: Io,
): Promise<number> {
  const { receiver } = edge
  const apply = async (): Promise<InboxRow> =>
    act === 'release' ? receiver.release(seq) : receiver.drop(seq)
  const entry = receiver.quarantined().find((q) => q.row.seq === seq)
  if (entry === undefined) await apply()
  io.out(quarantinedLine(entry as Quarantined, book))
  await confirmed(io, `${act} quarantined row ${seq}?`, `row ${seq} stays quarantined`)
  const row = await apply()
  io.out(`${row.seq} ${row.state} ${row.reason ?? '-'}`)
  if (row.content !== null) io.out(rowLine(row, book, edge.resolver))
  return 0
}
