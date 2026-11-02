import {
  closeSync,
  constants,
  existsSync,
  futimesSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
} from 'node:fs'
import { connect } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { AcError, type Hop, type SealingKey } from '@usebag/core'
import {
  Audit,
  acquireLock,
  Edge,
  type EdgeKeys,
  EpochOpener,
  FsAuditSink,
  HomeCustody,
  type InboxRow,
  KeyEpochStore,
  type PolicyOptions,
  processStart,
  type RelayClient,
  type SecurityRunner,
  SqliteStore,
  START_TOLERANCE,
} from '@usebag/edge'
import { CliError, UsageError } from './args.ts'
import type { Io } from './io.ts'

const { O_APPEND, O_CREAT, O_NOFOLLOW, O_NONBLOCK, O_WRONLY } = constants

// The CLI's home directory: --dir, else $AC_HOME, else ~/.bag. An identity's keys are in one custody (the
// edge's HomeCustody): a key file in <home>/keys (FsKeyStore: 0600 in 0700), or a macOS keychain item that
// <home>/keychain/<name>.json points to, or the agent (<home>/agent/<name>.json, public data);
// keygen chooses file or keychain, and every command finds it there. An identity's edge state is in
// <home>/state/<name>/: edge.sqlite, audit.jsonl and the doorbell.

/** The session id under which the CLI binds the threads it opens and routes what it receives. */
export const CLI_SESSION = 'cli'

/** The audit log of what the CLI signs outside an edge, in the identity's state directory, beside the edge's. */
export const CLI_AUDIT = 'cli-audit.jsonl'

/**
 * The audit log a command that opens no edge writes (the last-mile rulings, section 5): a chain of its own, from the
 * genesis, because a hash chain takes one live writer and a live edge may hold audit.jsonl. Each line takes this file's
 * own lock, never one the open path waits on, and then puts this file's anchor in the edge store, opened without the
 * writer lock: its row is the set's record that the file must exist, which an edge checks at start and `audit verify`
 * reads. A crash between the two leaves the file a line ahead of its anchor, as the edge's own log can be.
 */
export function cliAudit(home: string, name: string, io: Io): Pick<Audit, 'record'> {
  const dir = join(home, 'state', name)
  return {
    record(entry) {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const release = acquireLock(join(dir, 'cli-audit.lock'))
      try {
        const line = new Audit(new FsAuditSink(join(dir, CLI_AUDIT)), io.clock).record(entry)
        const store = new SqliteStore(join(dir, 'edge.sqlite'), { lock: false })
        try {
          store.auditAnchorPut(CLI_AUDIT, { seq: line.seq, hash: line.hash }, io.clock.now())
        } finally {
          store.close()
        }
        return line
      } finally {
        release()
      }
    },
  }
}

/**
 * Whether a live MCP server that keeps its records alive holds the identity, by its mcp.lock: `keep_alive` true, and a
 * pid alive that started before the file was written, so a pid used again is not taken for it. Then a keep has nothing
 * to do. A courtesy only: it can race a server starting, and what makes a keep safe beside any writer is its own file.
 */
export function renewing(home: string, name: string): boolean {
  const file = join(home, 'state', name, 'mcp.lock')
  try {
    const { pid, keep_alive: keeps } = JSON.parse(readFileSync(file, 'utf8')) as {
      pid: number
      keep_alive?: boolean
    }
    if (keeps !== true) return false
    process.kill(pid, 0)
    const start = processStart(pid)
    return start === null || start <= statSync(file).mtimeMs / 1000 + START_TOLERANCE
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/** The home directory for `--dir`, else AC_HOME, else HOME/.bag. */
export function homeDir(io: Io, dir: string | undefined): string {
  if (dir !== undefined) return dir
  if (io.env.AC_HOME) return io.env.AC_HOME
  if (io.env.HOME) return join(io.env.HOME, '.bag')
  throw new UsageError('no home directory: pass --dir, or set AC_HOME or HOME')
}

/** The doorbell, absolute: <home>/state/<name>/doorbell; the MCP server's open.ts computes the same. */
export function doorbellPath(home: string, name: string): string {
  return resolve(home, 'state', name, 'doorbell')
}

/**
 * Rings the doorbell: creates it empty, mode 0600, in a 0700 directory, or moves its mtime to now. Nothing is written
 * into it: its mtime is the signal, which a host hook may watch. The edge decides when (openEdge).
 */
export function ring(path: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  // O_NOFOLLOW: a link at the path is refused (ELOOP), never followed. O_NONBLOCK: a FIFO at the path fails the open
  // with ENXIO, never blocks delivery. The mtime is the wall clock's, by design.
  const fd = openSync(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
  try {
    const now = new Date()
    futimesSync(fd, now, now)
  } finally {
    closeSync(fd)
  }
}

/** The runner of an io without /usr/bin/security: every keychain call refuses ENOENT. */
const noSecurity: SecurityRunner = () => {
  throw Object.assign(new Error('keychain: this io runs no /usr/bin/security'), { code: 'ENOENT' })
}

/** The custodies of a home, which run /usr/bin/security through the io. */
export function homeCustody(io: Io, home: string): HomeCustody {
  return new HomeCustody(home, { run: io.security ?? noSecurity })
}

/** Refuses a name the custody refuses, and an identity the home lacks (ENOENT: no key file, keychain or agent). */
export function checkIdentity(io: Io, home: string, name: string): void {
  homeCustody(io, home).holder(name)
  if (!['keys', 'keychain', 'agent'].some((d) => existsSync(join(home, d, `${name}.json`))))
    throw new CliError('ENOENT', `no identity ${name} in ${home}: no key file, keychain or agent pointer`)
}

/** The agent identity whose login window of this home is open on `address` (its socket accepts), else null. */
export async function windowOf(io: Io, home: string, address: string): Promise<string | null> {
  const sock = join(home, 'agent.sock')
  if (!existsSync(sock)) return null
  const held = homeCustody(io, home)
    .agent.list()
    .find((e) => e.address === address)
  if (held === undefined) return null
  const live = await new Promise<boolean>((done) => {
    const s = connect(sock, () => {
      s.destroy()
      done(true)
    })
    s.on('error', () => done(false))
  })
  return live ? held.name : null
}

/**
 * Refuses (window-open) a record of `address` while a login window of this home holds it: the agent re-signs the
 * address record it read at login when the window ends, so a record published meanwhile would be overwritten.
 */
export async function checkNoWindow(io: Io, home: string, address: string): Promise<void> {
  const name = await windowOf(io, home, address)
  if (name !== null) throw new CliError('window-open', `a login window holds ${name}: run ac logout first`)
}

/** A home's epoch key store: <home>/key-records, one directory per address. */
export const epochStore = (home: string): KeyEpochStore => new KeyEpochStore(join(home, 'key-records'))

/**
 * The keys an edge receives with (forward secrecy): an identity that holds epoch keys opens with them, newest
 * first, and with its long-term sealing key last only while epoch 1 is held (mail sealed before
 * the changeover). An address record and a key record both live a day at most, so the long-term key's horizon, the
 * last pre-FS seal plus the retention and the skew, is epoch 1's own; once epoch 1 is deleted, so is that last try.
 * An identity that holds no epoch opens with its long-term key, as before. The store is read at each open, so an edge
 * opened before its identity's first epoch (a long-running inbox, while record keep or login rotates) opens mail
 * sealed to an epoch published after.
 */
export function receivingKeys(home: string, keys: EdgeKeys): EdgeKeys {
  const store = epochStore(home)
  const address = keys.signing.address
  const held = (): SealingKey[] => store.epochs(address).map((n) => store.epoch(address, n).key)
  return {
    signing: keys.signing,
    sealing: new EpochOpener(() => [...held(), ...(changeover(store, address) ? [keys.sealing] : [])]),
  }
}

/**
 * Whether the long-term sealing key still opens: while no epoch is held (before forward secrecy) and while epoch
 * 1 is held (pre-FS mail, sealed to it, may still arrive).
 */
export function changeover(store: KeyEpochStore, address: string): boolean {
  const held = store.epochs(address)
  return held.length === 0 || held.includes(1)
}

/** The keys of an identity, from its custody (name and modes checked); the agent's are not-authorized. */
export function loadKeys(io: Io, home: string, name: string): EdgeKeys {
  const custody = homeCustody(io, home)
  if (custody.entry(name).custody === 'agent') {
    throw new AcError('not-authorized', `${name} is held by the agent, which signs a session's hops only`)
  }
  return custody.keys(name)
}

/** An open edge for an identity, and how to close its store. */
export interface OpenEdge {
  readonly edge: Edge
  readonly store: SqliteStore
  close(): void
}

export interface OpenOptions {
  readonly home: string
  readonly name: string
  readonly relay: string
  /** Every relay it reads, when more than `relay` (inbox). */
  readonly relays?: readonly string[]
  readonly client: RelayClient
  readonly policy: PolicyOptions
  /** The chain from a root to the identity, when it signs as a session (send --auth); [] by default. */
  readonly auth?: readonly Hop[]
  /** Turns the edge's private-address guard off (--allow-private-relays); off by default. */
  readonly allowPrivateRelays?: boolean
  /** The keys and the mailbox when not the identity's own: a member at a group's mailbox (inbox --group). */
  readonly keys?: EdgeKeys
  readonly mailbox?: string
  /** Called once per accepted row, when the edge acks it in the store (the edge's `accepted` seam). */
  readonly accepted?: (row: InboxRow) => void
  /** Called with the error a doorbell or `accepted` callback threw (the edge's `onError`). */
  readonly onError?: (error: unknown) => void
}

/**
 * Opens the edge of an identity at one relay: its keys, its SQLite store and its audit log, all under the home, and
 * the chain it signs under, whose last hop's subject must be the identity (chain-not-to-sender otherwise).
 */
export function openEdge(io: Io, o: OpenOptions): OpenEdge {
  // The keys first: the custody refuses a name that could leave the directory before any path is made from it.
  // The identity's own keys open with its epochs (receivingKeys); keys given (a group's admin, a member at a group's
  // mailbox, an inbox that made them epoch-aware already) are used as they are.
  const keys = o.keys ?? receivingKeys(o.home, loadKeys(io, o.home, o.name))
  const auth = o.auth ?? []
  const last = auth.at(-1)
  if (last !== undefined && last.sub !== keys.signing.address) {
    throw new AcError('chain-not-to-sender', `the chain's last hop is to ${last.sub}, not to ${o.name}`)
  }
  const dir = join(o.home, 'state', o.name)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const store = new SqliteStore(join(dir, 'edge.sqlite'))
  try {
    const edge = new Edge({
      keys,
      auth,
      store,
      relays: { client: o.client, urls: o.relays ?? [o.relay] },
      records: io.records(o.client),
      policy: o.policy,
      clock: io.clock,
      rng: io.rng,
      audit: new FsAuditSink(join(dir, 'audit.jsonl')),
      ...(o.allowPrivateRelays === true ? { allowPrivateRelays: true } : {}),
      ...(o.mailbox === undefined ? {} : { mailbox: o.mailbox }),
      ...(o.accepted === undefined ? {} : { accepted: o.accepted }),
      ...(o.onError === undefined ? {} : { onError: o.onError }),
      // The edge calls it at most once per accepted message, when it acks the row, just before `accepted`;
      // never for a refusal or a hold. A touch that fails is one stderr line, and the message is delivered all the same, as in the MCP server.
      doorbell: () => {
        try {
          ring(doorbellPath(o.home, o.name))
        } catch (e) {
          const code = String((e as { code?: unknown }).code)
          io.err(`bag: doorbell ${code}: ${String((e as Error).message).replace(`${code}: `, '')}`)
        }
      },
    })
    return { edge, store, close: () => store.close() }
  } catch (e) {
    store.close()
    throw e
  }
}
