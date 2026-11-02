import type {
  AcErrorCode,
  Hop,
  PolicyCode,
  RecordKind,
  SealedContent,
  SealingKey,
  SigningKey,
  Thread,
} from '@usebag/core'
import type { RelayGuard } from './net.ts'

// The edge's ports (spec/SPEC.md §9): every effect the services need, as an interface. src/adapters/ holds the
// production implementations; tests pass fakes. Every port but the relay, the record source and the spawn hook is
// synchronous, so a check and the write that follows it cannot interleave with another frame.

/** Wall-clock time in whole Unix seconds. */
export interface Clock {
  now(): number
}

/** A cryptographically secure source of random bytes. Tests pass a seeded one. */
export interface Rng {
  bytes(length: number): Uint8Array
}

/**
 * Signs as one address (spec/SPEC.md §3): `sign` returns the 64-byte Ed25519 signature of a message, which every
 * signing path makes a 32-byte digest (§2). The core's SigningKey is one.
 */
export interface Signer {
  readonly address: string
  sign(message: Uint8Array): Uint8Array
}

/**
 * Opens what is sealed to one X25519 key (spec/SPEC.md §4): `open` is HPKE's single-shot open of one wrap, and
 * `publicKey` the key a record publishes as `sealing_key`. The core's SealingKey is one.
 */
export interface Opener {
  readonly publicKey: Uint8Array
  open(enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array
}

/** An opener that opens a whole envelope itself, asynchronously (the agent's): never a bare wrap. */
export interface EnvelopeOpener extends Opener {
  openEnvelope(bytes: Uint8Array): Promise<SealedContent>
}

export const isEnvelopeOpener = (opener: Opener): opener is EnvelopeOpener => 'openEnvelope' in opener

/** An identity's two keys: `signing` signs as `from`, `sealing` opens the wraps addressed to the mailbox. */
export interface KeyPair<S extends Signer = Signer, O extends Opener = Opener> {
  readonly signing: S
  readonly sealing: O
}

/**
 * The edge's private keys: the core's key objects, held in this process. The core's signing and opening functions take
 * a structural Signer and Opener, so a custody whose keys never enter the process (the agent's) can
 * reach them; EdgeKeys stays the classes for the services that read a seed (key files, group openers).
 */
export type EdgeKeys = KeyPair<SigningKey, SealingKey>

/** A session edge's keys: its own signing key in this process; its sealing key here, or the agent's opener. */
export type SessionKeys = KeyPair<SigningKey, Opener>

/** Where private keys live (adapter: fs-keys). An implementation never logs, prints or returns key material. */
export interface KeyStore {
  load(name: string): EdgeKeys
  save(name: string, keys: EdgeKeys): void
}

/** Where an identity's keys are kept: a key file (fs-keys), a macOS keychain item (keychain) or the agent. */
export type CustodyKind = 'file' | 'keychain' | 'agent'

/** What a custody tells of an identity: public data only, never key material. */
export interface KeyEntry {
  /** The identity's name in its home: 1 to 64 of [a-z0-9._-], starting with a letter or digit. */
  readonly name: string
  /** The signing key's address, `ed25519:` and 64 hex: public by design. */
  readonly address: string
  readonly custody: CustodyKind
  /** When the custody took the keys, in Unix seconds; null when it does not know. */
  readonly created: number | null
  /** The recovery setting of an agent identity's pointer (the format field, unread); undefined for any other. */
  readonly recovery?: string | undefined
}

/**
 * A custody of keys: it lists its identities, takes new ones, and gives the
 * signer and the opener of an address. `P` is what it gives: the core's keys for a custody that reads them into this
 * process (a file, a keychain item), so the Edge can take them; a Signer and an Opener that hold no seed for one that
 * never releases it. An implementation never logs, prints or returns key material in a message, an entry or an
 * error.
 */
export interface KeyCustody<P extends KeyPair = EdgeKeys> {
  readonly kind: CustodyKind
  /** Every identity it holds, sorted by name. */
  list(): readonly KeyEntry[]
  /** The identity `name`; throws ENOENT when it holds none. */
  entry(name: string): KeyEntry
  /** Takes new keys under a name it does not hold yet (EEXIST otherwise), and never overwrites any. */
  create(name: string, keys: EdgeKeys): KeyEntry
  /** The signer of `address`; throws ENOENT when it holds none. */
  signer(address: string): P['signing']
  /** The opener of the mailbox `address` (the identity's signing address); throws ENOENT when it holds none. */
  opener(address: string): P['sealing']
}

/**
 * Outbox states of one envelope at one relay (spec/SPEC.md §9.1); `retry` waits until next_at, at most until ts + TTL;
 * `retired` was given up before then with a later listed relay promoted in its place (§4.3), and is never tried again.
 */
export type OutboxState = 'sealed' | 'publishing' | 'published' | 'retry' | 'failed' | 'retired'

/** An envelope in the outbox: its exact bytes, which every retry and every resend publish unchanged. */
export interface OutboxEntry {
  readonly id: string
  readonly bytes: Uint8Array
  readonly thread: string
  readonly session: string | null
  readonly createdAt: number
}

/** A target that is due, with the bytes it publishes. */
export interface DueTarget {
  readonly target: OutboxTarget
  readonly bytes: Uint8Array
}

/**
 * Why an outbox target's last try failed: a code of the closed set (the relay's, or `publish-failed`), or
 * `unreachable`, a try that got no answer from its relay, which spec/SPEC.md Appendix A
 * names, so the closed set holds it.
 */
export type OutboxReason = AcErrorCode

/** What leaves or enters with an envelope, in its transaction: the waiting row it came from, its failover plan. */
export interface OutboxAddOptions {
  readonly waiting?: number | undefined
  /** The Sender's shares, JSON (spec/SPEC.md §4.3), so that a later process can promote. */
  readonly plan?: string
}

/** A read receipt for an envelope of the outbox (receipts.ts): who answered, and when it arrived here. */
export interface Receipt {
  readonly reader: string
  readonly at: number
}

/**
 * A send waiting for its recipient to resolve (Sender.sendOrWait), as the store keeps it: `input` is the message as
 * given, JSON, in plaintext; `view` the WaitingSend, JSON, which carries no body; `nextAt` its `nextAt`.
 */
export interface WaitingRow {
  readonly seq: number
  readonly input: string
  readonly view: string
  readonly nextAt: number
}

/** The outbox state of one envelope at one target relay. `reason` is the last failure's. */
export interface OutboxTarget {
  readonly id: string
  readonly relay: string
  readonly state: OutboxState
  readonly tries: number
  readonly nextAt: number | null
  readonly reason: OutboxReason | null
  readonly updatedAt: number
}

/**
 * Inbox states (spec/SPEC.md §9.2): received, then verified or rejected, then routed or queued, then acked. A row
 * rejected with a transient code stays received with a `nextAt` (it waits for a retry) until ts + TTL. A row an
 * org policy holds is `quarantined`, with its content null, until a release (back to received, checked again
 * with the held rule waived) or a drop (rejected).
 */
export type InboxState =
  | 'received'
  | 'verified'
  | 'rejected'
  | 'routed'
  | 'queued'
  | 'acked'
  | 'quarantined'
  | 'consumed'

/** One frame from a relay as the inbox keeps it: the exact bytes, and the content once it verified. */
export interface InboxRow {
  readonly seq: number
  readonly relay: string
  readonly mailbox: string
  readonly cursor: number
  readonly bytes: Uint8Array
  readonly id: string | null
  readonly state: InboxState
  readonly reason: PolicyCode | null
  readonly session: string | null
  /** The sealed content `{type, thread, body}` as JSON text, from `verified` on. */
  readonly content: string | null
  /** How many checks ended in a transient rejection; 0 for a row checked once. */
  readonly tries: number
  /** When a row that waits after a transient rejection is due again; null for every other row. */
  readonly nextAt: number | null
  readonly receivedAt: number
  readonly updatedAt: number
}

/** A change of an inbox row: its new state and the columns that change with it. */
export interface InboxPatch {
  readonly state: InboxState
  readonly id?: string | null
  readonly reason?: PolicyCode | null
  readonly session?: string | null
  readonly content?: string | null
  readonly tries?: number
  readonly nextAt?: number | null
}

/**
 * Why a row is quarantined: the rule that held it, the code it would be refused with, the rule's detail as
 * JSON text, and the rules earlier releases of this row waived, which every later check of the row skips.
 */
export interface Hold {
  readonly seq: number
  readonly rule: string
  readonly code: PolicyCode
  readonly detail: string | null
  readonly waived: readonly string[]
  readonly heldAt: number
}

/** A send held before it is sealed: `input` is the send's input as JSON text. */
export interface HeldSend {
  readonly id: string
  readonly input: string
  readonly rule: string
  readonly detail: string | null
  readonly state: 'pending-approval' | 'released' | 'dropped'
  readonly heldAt: number
  readonly decidedAt: number | null
}

/** How often a policy rule ended in an outcome (refused, quarantined, held, released, dropped, allowed). */
export interface PolicyCount {
  readonly rule: string
  readonly outcome: string
  readonly n: number
}

/** A pinned key: `subject` is `domain:<domain>` or `address:<address>`; `record` is the address record that set it. */
export interface Pin {
  readonly subject: string
  readonly key: string
  readonly record: Uint8Array | null
  readonly pinnedAt: number
  readonly updatedAt: number
}

/** The last line an audit log is known to have had: its seq and hash, kept outside the log's file. */
export interface AuditAnchor {
  readonly seq: number
  readonly hash: string
}

/** An audit file's anchor, with the file's name. */
export interface NamedAnchor extends AuditAnchor {
  readonly name: string
}

/**
 * The edge's durable state (adapter: sqlite-store): outbox, outbox_targets, inbox, seen, threads, pins, fs_known,
 * record_cache and audit_anchor. A frame is identified by its position, (relay, mailbox, cursor), and its envelope id:
 * a redelivered frame finds its row, and a new envelope at a position a restored relay used again gets its own.
 */
export interface EdgeStore {
  /** Runs `fn` atomically (inside an open transaction, as part of it). */
  transaction<T>(fn: () => T): T
  /** Persists an envelope's exact bytes with one target per relay, in one transaction. */
  /** Adds an envelope and its targets, in one transaction with `also`. */
  outboxAdd(entry: OutboxEntry, targets: readonly OutboxTarget[], also?: OutboxAddOptions): void
  outboxGet(id: string): OutboxEntry | null
  outboxTargets(id: string): OutboxTarget[]
  /** Targets to publish now: sealed, publishing (left by a crash), and retry with next_at at or before `now`. */
  outboxDue(now: number): DueTarget[]
  outboxPut(target: OutboxTarget): void
  /** Adds a target to an envelope already in the outbox (a promoted relay, §4.3); one already there is left as it is. */
  outboxAddTarget(target: OutboxTarget): void
  /** The envelope's failover plan, null for a row from before plans, or one with none. */
  outboxPlan(id: string): string | null
  outboxPlanPut(id: string, plan: string): void
  /** Keeps a read receipt; one already kept for this envelope and reader stays as it is. */
  receiptAdd(id: string, reader: string, at: number): void
  /** The receipts of envelope `id`, in the order they arrived. */
  receiptsOf(id: string): Receipt[]
  /** Keeps a waiting send, returning its seq, never reused. */
  waitingAdd(input: string, view: string, nextAt: number): number
  waitingPut(seq: number, view: string, nextAt: number): void
  waitingDelete(seq: number): void
  /** The waiting sends, oldest first; with `due`, those whose nextAt has come by then. */
  waitingList(due?: number): WaitingRow[]
  /** A new row in state received, holding the frame's bytes; the receiver checks first that it holds none for them. */
  inboxAdd(relay: string, mailbox: string, cursor: number, bytes: Uint8Array, now: number): InboxRow
  /** The newest row at a position. */
  inboxFind(relay: string, mailbox: string, cursor: number): InboxRow | null
  /** Every row at a position, oldest first: a relay restored from an older copy issues used cursors again. */
  inboxAt(relay: string, mailbox: string, cursor: number): InboxRow[]
  /** Writes a row's next state (the inbox state machine checks the move first). */
  inboxPut(row: InboxRow, patch: InboxPatch, now: number): InboxRow
  inboxList(states?: readonly InboxState[]): InboxRow[]
  /** The rows of a mailbox at a relay that wait after a transient rejection and are due at `now`, oldest first. */
  inboxDue(relay: string, mailbox: string, now: number): InboxRow[]
  /** The highest acked cursor of a mailbox at a relay. A subscription does not resume from it: see Receiver.run. */
  inboxLastAcked(relay: string, mailbox: string): number | null
  /** True while an id's entry lives: through its expires_at second, the last one the stale check still accepts. */
  seenHas(id: string, now: number): boolean
  seenAdd(id: string, firstSeen: number, expiresAt: number): void
  /** Deletes the entries that expired before `now`; returns how many. */
  seenPrune(now: number): number
  /** The session bound to a thread, from threads(thread_id, session_id). */
  threadGet(threadId: string): string | null
  /** Binds a thread to a session; `now` is its last use. */
  threadSet(threadId: string, session: string, now: number): void
  /** Records a bound thread's last use; an unbound thread is left unbound. */
  threadTouch(threadId: string, now: number): void
  /** Deletes the bindings last used before `before` (a row without used_at counts its created_at); returns how many. */
  threadsPrune(before: number): number
  pinGet(subject: string): Pin | null
  pinPut(pin: Pin): void
  /**
   * Forward secrecy: whether `subject` (an `address:<address>`) has ever been seen resolve a key record. A one-way
   * ratchet set by `fsKnownSet` and never unset, so the resolver never downgrades a known identity to its long-lived
   * address sealing key once the identity has published a key record (no transition downgrade). Durable: it survives
   * cache expiry and a fresh store over the same file. Kept apart from the address-record pin, which a withholding
   * relay may leave absent while a key record resolves.
   */
  fsKnownGet(subject: string): boolean
  fsKnownSet(subject: string): void
  /** A cached record's bytes while `now` is before its expires_at. */
  cacheGet(subject: string, kind: CacheKind, now: number): Uint8Array | null
  cachePut(subject: string, kind: CacheKind, bytes: Uint8Array, expiresAt: number): void
  /** The anchor of the audit log `name`, or null when none was kept. */
  auditAnchorGet(name: string): AuditAnchor | null
  auditAnchorPut(name: string, anchor: AuditAnchor, now: number): void
  /** Every audit file the store anchors: the authority for which files must exist. */
  auditAnchors(): readonly NamedAnchor[]
  // The org policy's state: holds of quarantined rows, held sends, the senders' contacts and the counts.
  inboxGet(seq: number): InboxRow | null
  /** The rows with content received at or after `since`: what the echo breaker compares a send with. */
  inboxContentSince(since: number): InboxRow[]
  /** Writes a row's hold, keeping the waivers of earlier releases. */
  holdPut(seq: number, hold: Pick<Hold, 'rule' | 'code' | 'detail'>, now: number): void
  holdGet(seq: number): Hold | null
  holdWaive(seq: number, waived: readonly string[]): void
  heldSendPut(send: HeldSend): void
  heldSendGet(id: string): HeldSend | null
  heldSendList(state: HeldSend['state']): HeldSend[]
  /** Records a send that went out: its id and second, and each recipient's first contact. */
  sendLog(id: string, to: readonly string[], at: number): void
  /** How many sends went out at or after `since`, and how many recipients were first sent to then. */
  fanoutSince(since: number): { readonly sends: number; readonly contacts: number }
  /** The addresses of `to` never sent to. */
  contactsNew(to: readonly string[]): string[]
  policyCount(rule: string, outcome: string): void
  policyCounts(): PolicyCount[]
  /** How many rows are quarantined and how many sends are pending approval now: what the caps bound. */
  heldCounts(): { readonly quarantined: number; readonly pending: number }
  close(): void
}

/**
 * What a relay answers a record publish with (spec/SPEC.md §8.2, Appendix B 65): the record's kind, its
 * signer's address, its `iat`, and `valid_until`, the last second the relay holds it valid (`iat + ttl` for an address
 * record, `exp` for a key record, null for an accept-from record, which does not expire).
 */
export interface RecordAnswer {
  readonly kind: string
  readonly signer: string
  readonly iat: number
  readonly valid_until: number | null
}

/**
 * What a relay answers a publish with (spec/SPEC.md §8.2). A record has no id and fills no mailbox: its result is
 * `{id: '', duplicate: false, delivered: 0}`, with `record`, the relay's answer, when the relay names one (an older
 * relay answers `{"ok": true}` alone).
 */
export interface PublishResult {
  readonly id: string
  readonly duplicate: boolean
  readonly delivered: number
  readonly record?: RecordAnswer
}

/**
 * The proof of a fetch by id (spec/SPEC.md §8.3): AC-Signer, AC-Ts, AC-Sig and, when not empty, AC-Auth. The signature
 * also covers the relay URL the fetch is addressed to, byte for byte (its audience), which no header carries: a proof
 * made for one URL is good only at the relay that URL names.
 */
export interface FetchProof {
  readonly signer: string
  readonly ts: number
  readonly sig: string
  readonly auth: readonly Hop[]
}

/**
 * One delivered envelope: its mailbox cursor and its exact bytes, and `receivedAt`, the relay's clock in Unix seconds
 * when it received the envelope, when the relay names it.
 */
export interface Frame {
  readonly cursor: number
  readonly envelopeBytes: Uint8Array
  readonly receivedAt?: number
}

/**
 * The exact bytes a fetch by id returns, with `receivedAt`, the relay's clock in Unix seconds when it received the
 * envelope, when the relay names it. Plain bytes are such a value, so a client without the stamp returns them.
 */
export type FetchedBytes = Uint8Array & { readonly receivedAt?: number }

/**
 * A live subscription: frames in cursor order; `ack(cursor)` acknowledges every frame up to it. Its
 * iteration ends once it is closed, or rejects with its own error: a RelayError with the relay's code (or
 * null) for an error frame, a failed socket or the reconnect limit; RelayError('bad-shape') for a frame it
 * cannot parse; or whatever a local fault threw; each subscription has its own error, and one failing ends
 * no other.
 */
export interface Subscription extends AsyncIterable<Frame> {
  ack(cursor: number): void
  close(): void
}

/**
 * What the connection under a subscription did: the relay admitted it, its ok frame on each connect, or it was lost:
 * closed, never admitted or dropped, and tried again, or refused by an error frame, whose code `error` carries. A
 * client reports what reading its frames cannot show: a connection refused at a cap closes with no frame.
 */
export type SubscriptionLink =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly error: RelayError }

/** The relay API (spec/SPEC.md §8): publish, fetch in its two shapes, and subscribe. */
export interface RelayClient {
  publish(url: string, bytes: Uint8Array): Promise<PublishResult>
  fetch(url: string, id: string, proof: FetchProof): Promise<FetchedBytes>
  /** The latest record of `address` and `kind`, or null when the relay holds none (404). */
  fetchRecord(url: string, address: string, kind: RecordKind): Promise<Uint8Array | null>
  subscribe(
    url: string,
    mailbox: string,
    signer: SigningKey,
    hops: readonly Hop[],
    cursor: number | null,
    onLink?: (link: SubscriptionLink) => void,
  ): Subscription
  /** The optional pair rendezvous: null when the relay lacks it. */
  pairOpen?(url: string, open: PairOpen): Promise<string | null>
  /** The reach an open nameplate holds, or null when none is open under it (404). */
  pairClaim?(url: string, nameplate: string): Promise<PairReach | null>
}

/**
 * What pair/open sends: the inviter, the invitation identity I, the relays serving I, I's ttl (s, at most 600), and
 * I's signature over ["ac/pair-open/1", inviter, invitation, relays, ttl]. `inviter` is provisional (v1): a review of
 * linkability at an untrusted shared rendezvous may move it onto an authenticated exchange with I.
 */
export interface PairOpen {
  readonly inviter: string
  readonly invitation: string
  readonly relays: readonly string[]
  readonly ttl: number
  readonly sig: string
}

/** What pair/claim answers: the open's reach, with its end (Unix s) in place of the ttl and the signature. */
export type PairReach = Omit<PairOpen, 'ttl' | 'sig'> & { readonly exp: number }

/**
 * A failed relay call. `status` is the HTTP status, 0 when no response arrived; `code` is the relay's code when its
 * body named one from the closed set; `retryAfter` is a 429's Retry-After in seconds.
 */
export class RelayError extends Error {
  readonly code: AcErrorCode | null
  readonly status: number
  readonly retryAfter: number | null

  constructor(code: AcErrorCode | null, status: number, retryAfter: number | null, detail: string) {
    super(`${code ?? (status === 0 ? 'no response' : `status ${status}`)}: ${detail}`)
    this.name = 'RelayError'
    this.code = code
    this.status = status
    this.retryAfter = retryAfter
  }
}

/** The code of an edge's local refusal, outside the closed set of Appendix A (the chain codes among them). */
export type EdgeErrorCode =
  | 'busy'
  | 'truncated'
  | 'diverged'
  | 'chain-mismatch'
  | 'chain-not-later'
  | 'no-held-record'

/**
 * A refusal of the edge's own, not a protocol verdict: `busy` when another writer holds an identity's state,
 * `truncated` or `diverged` when an audit log no longer matches its anchor, `chain-mismatch` or `chain-not-later`
 * when a renewed chain does not continue the current one (Edge.renewChain), and `no-held-record` when a swept
 * identity has no copy of its address record to continue from (custody/key-records.ts, lastAddress).
 */
export class EdgeError extends Error {
  readonly code: EdgeErrorCode

  constructor(code: EdgeErrorCode, detail: string) {
    super(`${code}: ${detail}`)
    this.name = 'EdgeError'
    this.code = code
  }
}

/** What the record cache holds: a record's kind, or `handle`, a handle record (spec/SPEC.md §12.4). */
export type CacheKind = RecordKind | 'handle'

/** The TXT records at a DNS name, each as its character-strings (RFC 1035 §3.3.14); [] for none (§12.2 item 4). */
export interface Dns {
  txt(name: string): Promise<string[][]>
}

/**
 * Where records come from: an org's address record and handle records at its origin's host (spec/SPEC.md §12.1), the
 * TXT records of DNS discovery (§12.2), and records stored at relays. A source that fetches over the network applies
 * the guard it is handed to every fetch at an origin, and connects to the address the guard checked (§9 item 11);
 * a fake ignores it. A source without `txt` asks no DNS: a domain's origin is then `https://<domain>`.
 */
export interface RecordSource {
  /** The bytes at https://<host>/.well-known/bag/address.json; throws when there are none. */
  wellKnown(host: string, guard?: RelayGuard): Promise<Uint8Array>
  relayRecord(url: string, address: string, kind: RecordKind): Promise<Uint8Array | null>
  txt?: Dns['txt']
  /** The bytes of a handle's record at https://<host>/.well-known/bag/handles/<local>.json; null for a 404. */
  handleRecord?(host: string, handle: string, guard?: RelayGuard): Promise<Uint8Array | null>
}

/**
 * The audit log's storage (adapter: fs-audit): append-only lines, and the last one, to continue the chain. `name`
 * keys the log's anchor in the edge store (default "audit"); `read`, when present, returns every line, so that a new
 * edge can find the line its anchor names.
 */
export interface AuditSink {
  readonly name?: string
  append(line: string): void
  last(): string | null
  read?(): readonly string[]
  /** The lines of the audit file `name` beside this one, null when it is not there: the set an edge checks at start. */
  peer?(name: string): readonly string[] | null
}

/** A verified, unsealed message as a session receives it (spec/SPEC.md §9.6). */
export interface InboundMessage {
  readonly id: string
  /** The session key that signed it. */
  readonly from: string
  /** The key the chain names as acting through `from`; replies address it. */
  readonly principal: string
  readonly root: string
  readonly to: readonly string[]
  readonly ts: number
  readonly type: string
  readonly thread: Thread
  readonly body: unknown
  readonly caveats: readonly string[]
  /** The relay it arrived through. */
  readonly relay: string
}

/** A live session's handler. `session` is the id kept in threads(thread_id, session_id). */
export interface SessionHandler {
  readonly session: string
  deliver(message: InboundMessage): void | Promise<void>
}

/** What a spawn hook is told about a root message that no session handles. */
export interface SpawnContext {
  readonly message: InboundMessage
}

/**
 * The spawn-on-arrival seam, an interface only: v0 never spawns a process. A hook may answer a handler for a
 * root message on an unregistered thread; absent, or answering null, the message is queued.
 */
export interface SpawnHook {
  onUnroutedThread(ctx: SpawnContext): Promise<SessionHandler | null>
}
