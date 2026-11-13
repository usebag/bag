import {
  closeSync,
  constants,
  futimesSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { codingEvaluator, type Hop, type SigningKey, toHex, verifyChain } from '@usebag/core'
import {
  type Clock,
  createRecordSource,
  Edge,
  type EdgeKeys,
  EpochOpener,
  FsAuditSink,
  HomeCustody,
  type InboxRow,
  jitterOf,
  KeyEpochStore,
  KeyRecordAdmin,
  type PairOpen,
  processStart,
  publishedKeyRecord,
  type RecordSource,
  type RelayClient,
  type Rng,
  type SendInput,
  SqliteStore,
  START_TOLERANCE,
  type Subscription,
  type SubscriptionLink,
} from '@usebag/edge'
import type { AgentOpener, EnvelopeOpener } from '@usebag/edge/agent'
import { receiptsAnswered } from '@usebag/enterprise-client'
import { type SessionAgent, sessionAgent } from './agent.ts'
import { readChain } from './chain.ts'
import { type Config, ConfigError } from './config.ts'
import type { EpochRotation } from './keepalive.ts'
import { loadRecords, type OrgRecords, withRecords } from './policy.ts'
import { trustFileRoots } from './trust.ts'

const { O_APPEND, O_CREAT, O_NOFOLLOW, O_NONBLOCK, O_WRONLY } = constants

// Opening an identity, composed from the edge exactly as the CLI composes it: the home's custody (HomeCustody: a
// key file at <home>/keys or a keychain item), the SQLite store and the audit log at <home>/state/<name>/, the relay client, the record source and the policy. Two
// additions: a lock file, so that two servers never write one audit chain, and a wrapper on the relay client, which
// reports each frame's arrival and passes each subscription's error on; an accepted row reaches the server through the
// edge's `accepted`, once per row at its ack. The edge is opened with unreachableReason (a try with no answer from its relay
// is retry with reason unreachable, spec/SPEC.md Appendix A) and, with --allow-private-relays, allowPrivateRelays. A
// renewed chain goes through Edge.renewChain (chain.ts), so the current chain is the edge's, edge.auth.

/**
 * Who this server is: the key it signs with, the mailbox it reads, the principal and root its chain names (a renewal
 * keeps all four). The chain itself, which a renewal swaps, is the edge's: Edge.auth, [] for a self-rooted principal.
 */
export interface Identity {
  readonly address: string
  readonly mailbox: string
  readonly principal: string
  readonly root: string
}

export interface OpenDeps {
  readonly clock: Clock
  readonly rng: Rng
  readonly relay: RelayClient
  /** Where records come from (default: well-known URLs over https, and the relays). */
  readonly records?: (client: RelayClient) => RecordSource
  /** The edge's `accepted`: once per accepted row, right after its ack (a frame, the retrier, release, recover()). */
  readonly accepted: (row: InboxRow) => void
  readonly onError: (error: unknown) => void
  /** Called with every error a subscription meets, before the edge's Receiver sees it. */
  readonly onSubscriptionError?: (relay: string, error: unknown) => void
  /** Called with what the client says of each connection to a relay (subscriptions.ts). */
  readonly onLink?: (relay: string, link: SubscriptionLink) => void
  /** Called when a frame of `relay` arrives, before the Receiver handles it (subscriptions.ts). */
  readonly onArrival?: (relay: string) => void
  /** The edge's doorbell: called at most once per message the edge accepts, in Receiver.ack. */
  readonly doorbell?: () => void
  /** A local row's receipt, sent on this machine by the bag service (edge.ts localSend). */
  readonly localSend?: (input: SendInput) => Promise<unknown>
  /** The bag service's local roots of this identity, from its reconciled pair table (q1); with none, no roots (r3). */
  readonly localRoots?: () => readonly string[]
  /** The edge's wait before resubscription attempt n (default the edge's: 250 ms × 2^n, at most 30 s). */
  readonly resubscribeDelayMs?: (attempt: number) => number
  /** The keys, already read (the bag service reads them first, so a Keychain dialog never stalls another identity). */
  readonly keys?: EdgeKeys
  /** The chain, already read (from --chain-cmd); without it, --auth's file is read here. */
  readonly auth?: readonly Hop[]
  /** This process's pid, written into the lock file. */
  readonly pid: number
  /** True while a process with that pid exists. */
  readonly alive: (pid: number) => boolean
  /** The release of a mcp.lock taken already (a --session server takes it at start); without it, it is taken here. */
  readonly release?: () => void
  /** A session's agent says its grant is gone (agent.ts): the server asks a new one and opens again. */
  readonly lost?: () => void
  /** Threads the session registered before its grant was lost, registered again at the agent at open. */
  readonly threads?: readonly string[]
  /** A thread of `threads` that could not be registered again. */
  readonly replayFailed?: (thread: string, error: unknown) => void
  /** Wraps the agent's opener (the edge's FrontDesk); `registered` says whether the agent holds a thread. */
  readonly opener?: (inner: AgentOpener, registered: (thread: string) => boolean) => EnvelopeOpener
}

export interface Opened {
  readonly identity: Identity
  readonly edge: Edge
  readonly store: SqliteStore
  readonly audit: FsAuditSink
  /** The signing key, for delegation hops and the server's own records. Never logged, never returned. */
  readonly signer: SigningKey
  /** The public half of the long-term sealing key, hex, as an address record named it before forward secrecy. */
  readonly sealingKey: string
  /** The identity's epochs for the keep-alive to rotate; null under agent custody. */
  readonly epochs: EpochRotation | null
  /** The relay client as wrapped, the edge's own. */
  readonly client: RelayClient
  readonly stateDir: string
  /** The doorbell's absolute path (doorbellPath); the server rings it when the edge calls its doorbell. */
  readonly doorbell: string
  /** The org's policy records the edge enforces (--policy, --members), verified at start; {} without them. */
  readonly records: OrgRecords
  /** The agent of a session whose mailbox is an agent identity of the home (agent.ts), or null. */
  readonly agent: SessionAgent | null
  /** Closes the store and releases the lock. */
  close(): void
}

/** The doorbell, absolute: <home>/state/<name>/doorbell. The CLI's home.ts computes the same path. */
export function doorbellPath(home: string, name: string): string {
  return resolve(home, 'state', name, 'doorbell')
}

/**
 * Rings the doorbell: creates it empty, mode 0600, in a 0700 directory, or moves its mtime to now. Nothing is written
 * into it: its mtime is the signal, which a host hook may watch. The edge decides when (receiver.ts).
 */
export function ring(path: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  // O_NOFOLLOW: a link at the path is refused (ELOOP), never followed; O_NONBLOCK: a FIFO there fails (ENXIO) at
  // once instead of blocking the delivery path. The mtime is the wall clock's, by design.
  const fd = openSync(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
  try {
    const now = new Date()
    futimesSync(fd, now, now)
  } finally {
    closeSync(fd)
  }
}

/** True while a process with this pid exists (EPERM: it exists, under another user). */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/** What the lock file says of its holder; every field but the pid is absent from a lock an older server wrote. */
export interface LockInfo {
  readonly pid: number
  readonly startedAt?: string
  readonly cwd?: string
  readonly host?: string
}

/** The lock's holder, or null when the file is missing or does not name a pid. */
export function readLock(path: string): LockInfo | null {
  try {
    const v = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
    if (!Number.isSafeInteger(v.pid)) return null
    const text = (x: unknown): string | undefined => (typeof x === 'string' ? x : undefined)
    const [startedAt, cwd, host] = [text(v.started_at), text(v.cwd), text(v.host)]
    return {
      pid: v.pid as number,
      ...(startedAt === undefined ? {} : { startedAt }),
      ...(cwd === undefined ? {} : { cwd }),
      ...(host === undefined ? {} : { host }),
    }
  } catch {
    return null
  }
}

function lockPid(path: string): number | null {
  return readLock(path)?.pid ?? null
}

/** The identity's lock is held by a live process: carries who, for the held-by answer of every tool. */
export class HeldError extends ConfigError {
  readonly holder: LockInfo
  readonly path: string

  constructor(name: string, holder: LockInfo, path: string) {
    const when = holder.startedAt === undefined ? '' : `, started ${holder.startedAt}`
    const host = holder.host === undefined ? '' : `, ${holder.host}`
    const where = holder.cwd === undefined ? '' : ` in ${holder.cwd}`
    super(
      'busy',
      `bag: the identity ${name} is held by another session (pid ${holder.pid}${when}${host})${where}; ` +
        'close that session or run bag in its own folder',
    )
    this.name = 'HeldError'
    this.holder = holder
    this.path = path
  }
}

/** What the lock records beside the pid, so a refused second session can name the holder. */
export interface LockMeta {
  readonly cwd?: string
  readonly ppid?: number
  readonly startedAt?: string
}

/**
 * Whether the lock's holder is a live process of that lock: its pid answers, and the process did not start after the
 * lock was written (a pid used again by an unrelated process). The reference time is started_at, else the file's mtime.
 */
export function holderLives(path: string, holder: LockInfo, alive: (pid: number) => boolean): boolean {
  if (!alive(holder.pid)) return false
  try {
    const wrote = holder.startedAt === undefined ? Number.NaN : Date.parse(holder.startedAt) / 1000
    const at = Number.isFinite(wrote) ? wrote : statSync(path).mtimeMs / 1000
    const began = processStart(holder.pid)
    return began === null || began <= at + START_TOLERANCE
  } catch {
    return true
  }
}

/** Publishes `body` at `path` whole or not at all: a temp file linked into place, EEXIST while the path exists. */
function publish(path: string, body: string): void {
  const tmp = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`
  const fd = openSync(tmp, 'wx', 0o600)
  try {
    try {
      writeSync(fd, body)
    } finally {
      closeSync(fd)
    }
    linkSync(tmp, path)
  } finally {
    rmSync(tmp, { force: true })
  }
}

/**
 * Takes <state>/mcp.lock for this pid, or refuses with `busy` (a HeldError naming the holder) while a live process
 * holds it. The file appears whole (a temp file linked into place), so a reader never sees it empty. A lock left by a
 * process that is gone, or whose pid another process now has, is taken over by moving it aside and checking that it
 * still names the dead holder; a server that wins the race in between makes this one refuse as held by it. Returns the
 * release, which removes the file only while it still names this pid. `keepAlive` is written beside the pid: a
 * server keeping its records alive, for which a background `ac record keep` stands aside. The file is {pid,
 * keep_alive?, started_at, cwd, ppid, host?}: readers that want the pid alone (lockPid, the wake-hook) still get it.
 */
export function acquireLock(
  path: string,
  pid: number,
  alive: (pid: number) => boolean,
  keepAlive?: boolean,
  meta: LockMeta = {},
): () => void {
  const body = JSON.stringify({
    pid,
    ...(keepAlive === undefined ? {} : { keep_alive: keepAlive }),
    started_at: meta.startedAt ?? new Date().toISOString(),
    cwd: meta.cwd ?? process.cwd(),
    ppid: meta.ppid ?? process.ppid,
  })
  const name = basename(dirname(path))
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      publish(path, body)
      break
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'EEXIST') throw e
    }
    const holder = readLock(path)
    if (holder !== null && holderLives(path, holder, alive)) throw new HeldError(name, holder, path)
    // Stale (or unreadable): move it aside, then look at what was moved. A live lock that was swapped in meanwhile goes back.
    const aside = `${path}.stale.${pid}`
    try {
      renameSync(path, aside)
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT') continue // another server took it over and released: try again
      throw e
    }
    const moved = readLock(aside)
    if (moved !== null && moved.pid !== holder?.pid && holderLives(aside, moved, alive)) {
      try {
        linkSync(aside, path)
      } catch {}
      rmSync(aside, { force: true })
      throw new HeldError(name, moved, path)
    }
    rmSync(aside, { force: true })
    if (attempt === 3)
      throw new ConfigError('busy', `${path} keeps changing hands: another server is starting`)
  }
  return () => {
    try {
      if (lockPid(path) === pid) unlinkSync(path)
    } catch {}
  }
}

/** Adds the MCP host's kind to the lock this pid holds (known only after initialize); a lock that moved on is left. */
export function noteLockHost(path: string, pid: number, host: string): void {
  try {
    const v = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
    if (v.pid !== pid) return
    const tmp = `${path}.${pid}.host`
    writeFileSync(tmp, JSON.stringify({ ...v, host }), { mode: 0o600 })
    renameSync(tmp, path)
  } catch {}
}

/** What the relay client's wrapper reports. */
export interface Observer {
  /** The one mailbox reported on: a pairing's invitation subscribes through this client, and is no sign of it. */
  readonly mailbox: string
  /** Called with every error a subscription's frames end in, before the Receiver sees it. */
  readonly onSubscriptionError?: (relay: string, error: unknown) => void
  /** Called when a frame has arrived, before the Receiver handles it. */
  readonly onFrame?: () => void
  /** Called with what the client says of each connection to a relay: admitted, or lost. */
  readonly onLink?: (relay: string, link: SubscriptionLink) => void
  /** Called when a frame of `relay` has arrived (not the end of the subscription), before the Receiver handles it. */
  readonly onArrival?: (relay: string) => void
}

/**
 * The relay client with, for the mailbox, each connection reported to `onLink`, each frame's arrival reported and each
 * subscription error passed on; acks go through as they are (an accepted row reaches the desk from the edge's
 * `accepted`, not from here); publish, fetch and subscribe go through as
 * the edge calls them, with the hops the edge presents (those of the chain Edge.renewChain last swapped
 * in). The pair rendezvous calls go through when the client offers them, and stay absent when it does not, so the
 * edge's pairing falls back to the invite string (edge pair-code.ts).
 */
export function observed(client: RelayClient, o: Observer): RelayClient {
  const { pairOpen, pairClaim } = client
  return {
    ...(pairOpen === undefined
      ? {}
      : { pairOpen: (url: string, open: PairOpen) => pairOpen.call(client, url, open) }),
    ...(pairClaim === undefined
      ? {}
      : { pairClaim: (url: string, n: string) => pairClaim.call(client, url, n) }),
    publish: (url, bytes) => client.publish(url, bytes),
    fetch: (url, id, proof) => client.fetch(url, id, proof),
    fetchRecord: (url, address, kind) => client.fetchRecord(url, address, kind),
    subscribe: (url, mailbox, signer, hops, cursor): Subscription => {
      if (mailbox !== o.mailbox) return client.subscribe(url, mailbox, signer, hops, cursor)
      const sub = client.subscribe(url, mailbox, signer, hops, cursor, (link) => o.onLink?.(url, link))
      return {
        [Symbol.asyncIterator]: () => {
          const frames = sub[Symbol.asyncIterator]()
          return {
            next: async () => {
              try {
                const next = await frames.next()
                o.onFrame?.()
                if (next.done !== true) o.onArrival?.(url)
                return next
              } catch (e) {
                o.onSubscriptionError?.(url, e)
                throw e
              }
            },
          }
        },
        ack: (n) => sub.ack(n),
        close: () => sub.close(),
      }
    },
  }
}

/** Who the keys and the chain say this server is; refuses a chain that does not verify now, or a stray mailbox. */
function identityOf(address: string, auth: readonly Hop[], mailbox: string | null, now: number): Identity {
  if (auth.length === 0) return { address, mailbox: address, principal: address, root: address }
  const chain = verifyChain(auth, address, now)
  if (mailbox !== chain.principal) {
    throw new ConfigError(
      'usage',
      `--mailbox must be the chain's principal (its last issuer, ${chain.principal}), where replies arrive`,
    )
  }
  return { address, mailbox, principal: chain.principal, root: chain.root }
}

/**
 * How old the newest epoch is when the keep-alive publishes the next: half a key record's day, an
 * hour early, as record keep's, so the day-long key record never lapses between two cycles.
 */
export const EPOCH_DUE = 11 * 3600

/** Opens the identity of a configuration: keys, chain, lock, store, audit log and edge. Nothing is started. */
export function openIdentity(config: Config, deps: OpenDeps): Opened {
  // The keys first: the custody refuses a name that could leave its directory before any path is made from it.
  let agent: SessionAgent | null = null
  const custody = new HomeCustody(config.home, { client: () => (agent as SessionAgent).client() })
  const own = deps.keys ?? custody.keys(config.as)
  if (deps.auth === undefined && config.chainCmd !== null) {
    throw new ConfigError('usage', "a --chain-cmd session's chain is read before its identity is opened")
  }
  // The chain the edge starts under; a renewal swaps it through Edge.renewChain (chain.ts) and never changes this array.
  const chain: readonly Hop[] = deps.auth ?? (config.auth === null ? [] : readChain(config.auth))
  const identity = identityOf(own.signing.address, chain, config.mailbox, deps.clock.now())
  // Under `agent` custody the agent opens at the mailbox and the session's own key signs.
  const underAgent = custody.agent.list().some((e) => e.address === config.mailbox)
  if (underAgent && (config.allowDelegate || chain.length !== 1)) {
    throw new ConfigError(
      'usage',
      'under agent custody --auth is the one hop ac grant printed, and --allow-delegate is refused (A-3)',
    )
  }
  const sealing = underAgent ? custody.agent.opener(identity.mailbox) : null
  // Called only by a session's front desk (deps.opener), and a session's opening always has its agent.
  const registered = (t: string): boolean => (agent as SessionAgent).registered(t)
  // Forward secrecy: an identity of its own that holds epoch keys (<home>/key-records, as the CLI keeps them)
  // opens with them, never with its long-term sealing key; under agent custody the agent opens with P's.
  // The long-term key is tried last while none or epoch 1 is held (the changeover; as the CLI's receivingKeys). The
  // store is read at each open: the server's own keep-alive may publish its first epoch after it opened.
  const epochs = new KeyEpochStore(join(config.home, 'key-records'))
  const at = own.signing.address
  const held = () => epochs.epochs(at).map((n) => epochs.epoch(at, n).key)
  const last = () => {
    const e = epochs.epochs(at)
    return e.length === 0 || e.includes(1) ? [own.sealing] : []
  }
  const mine = { signing: own.signing, sealing: new EpochOpener(() => [...held(), ...last()]) }
  const keys =
    sealing === null ? mine : { signing: own.signing, sealing: deps.opener?.(sealing, registered) ?? sealing }
  const records = loadRecords(config, deps.clock.now())
  // The edge's Policy keeps this array and reads it at each admission: it is read again from trust.json before each
  // frame (a pairing needs no restart); a file that does not read leaves the --trust-root flags alone.
  const roots = [...config.trustRoots, ...trustFileRoots(config.home)]
  const reread = (): void => {
    let file: typeof roots = []
    try {
      file = trustFileRoots(config.home)
    } catch {}
    roots.splice(0, roots.length, ...config.trustRoots, ...file)
  }
  const stateDir = join(config.home, 'state', config.as)
  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  const release =
    deps.release ?? acquireLock(join(stateDir, 'mcp.lock'), deps.pid, deps.alive, config.keepAliveRecords)
  let store: SqliteStore | null = null
  try {
    store = new SqliteStore(join(stateDir, 'edge.sqlite'), { waitingInMemory: config.session !== null })
    const audit = new FsAuditSink(join(stateDir, 'audit.jsonl'))
    const client = observed(deps.relay, {
      mailbox: identity.mailbox,
      onFrame: reread,
      ...(deps.onSubscriptionError === undefined ? {} : { onSubscriptionError: deps.onSubscriptionError }),
      ...(deps.onLink === undefined ? {} : { onLink: deps.onLink }),
      ...(deps.onArrival === undefined ? {} : { onArrival: deps.onArrival }),
    })
    const edge = new Edge({
      keys,
      auth: chain,
      ...(config.mailbox === null ? {} : { mailbox: config.mailbox }),
      // The organisation of an enterprise session can turn its agents' receipts off (receiptsAnswered), read each time.
      receiptsTo: () => (receiptsAnswered(config.home, config.as) ? config.receiptsTo : []),
      store,
      relays: { client, urls: config.relays },
      records: (deps.records ?? createRecordSource)(client),
      policy: withRecords(
        {
          roots,
          types: config.acceptTypes,
          evaluators: config.honor.includes('coding') ? [codingEvaluator] : [],
        },
        records,
      ),
      clock: deps.clock,
      rng: deps.rng,
      audit,
      onError: deps.onError,
      // A try with no answer from its relay is retry with reason unreachable (spec/SPEC.md Appendix A).
      unreachableReason: true,
      // The edge's guard refuses a peer's relay on a private address unless it is one of --relay; the flag lifts it.
      allowPrivateRelays: config.allowPrivateRelays,
      ...(deps.resubscribeDelayMs === undefined ? {} : { resubscribeDelayMs: deps.resubscribeDelayMs }),
      ...(deps.doorbell === undefined ? {} : { doorbell: deps.doorbell }),
      ...(deps.localSend === undefined ? {} : { localSend: deps.localSend }),
      accepted: deps.accepted,
      // Trusted for a row the bag service injects (LOCAL_RELAY) only, from its reconciled table; with no service (stdio)
      // there are none, so a stored local: row that recover() re-receives is refused, whatever the disk says (r3).
      localRoots: deps.localRoots ?? (() => []),
    })
    const first = chain[0] as Hop
    if (underAgent) {
      agent = sessionAgent(config.home, own.signing, first, () => edge.auth, deps.clock, deps.rng, {
        ...(deps.lost === undefined ? {} : { lost: deps.lost }),
        ...(deps.threads === undefined ? {} : { replay: deps.threads }),
        ...(deps.replayFailed === undefined ? {} : { replayFailed: deps.replayFailed }),
      })
    }
    const opened = store
    return {
      identity,
      edge,
      store,
      audit,
      signer: keys.signing,
      sealingKey: toHex((sealing === null ? own : keys).sealing.publicKey),
      // An identity of its own publishes its next epoch 11 hours after the newest.
      epochs:
        sealing === null
          ? {
              // Due at once with none held, or with the newest unpublished (a publish failed: it goes out again).
              dueAt: () => {
                const n = epochs.epochs(at)[0]
                const e = n === undefined ? null : epochs.epoch(at, n)
                return e === null || !e.published ? 0 : e.iat + EPOCH_DUE
              },
              rotate: (held) =>
                new KeyRecordAdmin({
                  edge,
                  keys: own,
                  store: epochs,
                  clock: deps.clock,
                  rng: deps.rng,
                  relays: config.relays,
                  held,
                }).rotate(),
              keyRecord: () => publishedKeyRecord(epochs, own, deps.clock.now()),
            }
          : null,
      client,
      stateDir,
      doorbell: doorbellPath(config.home, config.as),
      records,
      agent,
      close() {
        agent?.close()
        opened.close()
        release()
      },
    }
  } catch (e) {
    store?.close()
    release()
    throw e
  }
}

/**
 * One identity's wait before reconnect or resubscription attempt n (an --identities server, B2): the edge's 250 ms × 2^n,
 * at most 30 s, times a factor in [0.5, 1.5) drawn from `rng` at each attempt, and still at most 30 s, so that the
 * identities of one server do not come back in the same instants after a network drop (the multi-identity design, §4.1).
 */
export function jitteredDelay(rng: Rng): (attempt: number) => number {
  return (attempt) => {
    const base = Math.min(250 * 2 ** attempt, 30_000)
    return Math.floor(Math.min(base * (0.5 + jitterOf(rng.bytes(4))), 30_000))
  }
}

/** One identity's wait before its network start, in ms: uniform in [0, `spreadS` s) from `rng`, 0 for a spread of 0. */
export function startDelayMs(rng: Rng, spreadS: number): number {
  return Math.floor(jitterOf(rng.bytes(4)) * spreadS * 1000)
}
