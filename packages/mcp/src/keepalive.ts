import {
  type AcceptFromRecord,
  type AcRecord,
  type AddressRecord,
  type KeyRecord,
  parseRecord,
  type RecordKind,
  type SigningKey,
  signRecord,
  verifyRecord,
} from '@usebag/core'
import {
  type Clock,
  continueFrom,
  type Edge,
  EdgeError,
  heldAccept,
  INCOMPLETE_REVOCATION,
  jitterOf,
  keepAcceptCopy,
  keepAddressCopy,
  type Lagging,
  type Offered,
  offerRecord,
  type RelayClient,
  type Rng,
  readRecoveryState,
} from '@usebag/edge'
import type { Timers } from './desk.ts'
import type { Logger } from './log.ts'
import { codeOf } from './tools.ts'

// The server's own records, kept alive. An address record lives a day at most and
// nothing re-signs one for a self-rooted identity, so a day after it was published a peer whose cache has expired
// cannot resolve the identity. With --keep-alive-records the server reads its newest address and accept-from records
// at its relays and, at half the address record's ttl after its iat, re-signs each with the same content and a new
// iat (core's signRecord) and publishes both at each of its relays (the edge's publishRecord). It re-signs only
// records that its own key signed and that name its own long-term sealing key or none (forward secrecy), and never
// a rotation (a record that names rotated_from: the countersignature covers the old iat). A record newer than the last
// one it signed, a person's republish, becomes the content it keeps alive. With `epochs`, a cycle first publishes the
// identity's next epoch when one is due (11 hours after the newest, an hour early, or none held), which leaves
// the address record with no sealing key. With an rng (an --identities server) each re-sign falls due a random offset
// of up to a tenth of the ttl after half of it, so that identities whose records were made together do not re-sign
// together; 0.4 of the ttl still remains before the record expires. The address record is copied to the home whenever it
// changes, and a server that finds it swept from every relay (a lapse) heals from that copy, with its rotation key and
// revoked list: it never publishes an empty first record over an
// identity that published before, so a copy that is missing or unreadable publishes nothing (no-held-record).
// A record goes to every relay and is offered until each holds it (spec/SPEC.md Appendix B 110): each cycle reads every
// relay back, offers the newest published epoch's key record to each relay not seen holding it, and, when it re-signs
// nothing, offers the records it holds, unchanged, the same way; a relay that took one since answers stale-record, which
// counts as held. A relay left behind brings the next cycle forward to the retry wait, for a cycle otherwise comes only
// when something falls due, hours on: that is how long a relay that missed a rotation would serve the old key. A record
// that carries a revoked list and a relay that did not take it are an incomplete revocation, since that relay honours
// only the list it stored: a security gap, reported as its own outcome until every relay holds it, never as a re-sign.

/** The first wait after a cycle that re-signed nothing, in seconds; it doubles up to an hour. */
export const KEEP_ALIVE_RETRY_S = 60
export const KEEP_ALIVE_RETRY_MAX_S = 3600

const noop = (): void => {}
const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()

/** What a relay that did not take a record with a revoked list means, in the CLI's words (ac keys rotate, ac record keep). */
export const incompleteLine = (address: string, lag: Lagging): string =>
  `incomplete revocation ${address} ${lag.relay} ${lag.code}: ${INCOMPLETE_REVOCATION}`

/** A relay that did not take a record, as a log line holds it. */
const lagLine = (lag: Lagging): string => `${lag.kind} ${lag.relay} ${lag.code}`

/** The keep-alive's state, as status reports it. */
export interface KeepAliveStatus {
  /** When the next cycle runs: the next re-sign, or the next look for a record to re-sign. */
  readonly next_at: string | null
  readonly address_iat: number | null
  readonly accept_from_iat: number | null
  /** The last heal: when the copy it continued was signed, and since when the home's recovery copy is stale, if it is. */
  readonly healed: { readonly signed_at: string; readonly stale_since: string | null } | null
  readonly last: {
    readonly at: string
    readonly outcome: string
    /** The address and accept-from records the relays took and did not take; the key record's offer is in `lagging`. */
    readonly published: number
    readonly failed: number
    /** The code of the cycle's last failure, a read with no answer or a publish refused; null for none. */
    readonly code: string | null
    /** Each relay that did not take a record this cycle, absent for none: the next cycle offers it again. */
    readonly lagging?: readonly Lagging[]
    /** One line per lagging relay of a record with a revoked list, absent for none: a security gap, not a delay. */
    readonly incomplete?: readonly string[]
  } | null
}

/** An identity's epochs, as the keep-alive rotates them: when the next is due, and the rotation that publishes it. */
export interface EpochRotation {
  /** The unix second the next epoch is due: the newest's iat plus 11 hours, or 0 when none is held or it is unpublished. */
  dueAt(): number
  /**
   * Publishes the next epoch (KeyRecordAdmin.rotate) from the held address record: the address record it leaves, and
   * the relays that did not take a record.
   */
  rotate(held: AddressRecord): Promise<{
    readonly epoch: number
    readonly key: KeyRecord
    readonly address: AddressRecord
    readonly lagging: readonly Lagging[]
  }>
  /** The newest published epoch's key record, or null with none to offer (publishedKeyRecord). */
  keyRecord(): KeyRecord | null
}

export interface RecordKeeperOptions {
  /** The edge whose publishRecord publishes, at the relays given. */
  readonly edge: Edge
  /** The relay client the records are read with. */
  readonly client: RelayClient
  readonly relays: readonly string[]
  /** The identity's signing key: it signs its records. */
  readonly signer: SigningKey
  /** The public half of its long-term sealing key, hex: an address record must name it, or none. */
  readonly sealingKey: string
  /** The identity's epochs, rotated before a re-sign; none (null) under agent custody, where the agent opens P's mail. */
  readonly epochs?: EpochRotation | null
  /** The home and the name its copy of the address record lives under. */
  readonly home: string
  readonly name: string
  readonly clock: Clock
  readonly timers: Timers
  readonly log: Logger
  /**
   * An --identities server's (B2): each re-sign falls due u × ttl / 10 seconds after half the ttl, u drawn from it each
   * time, so that identities whose records were made together do not re-sign together. Without it, at half the ttl.
   */
  readonly rng?: Rng
}

/**
 * Re-signs and republishes the server's address and accept-from records at half the address record's ttl. A cycle's
 * outcome is "re-signed", "not-due" (the newest record is not half way through its ttl), "no-record" (none of its own
 * at its relays and never published from this home), "no-held-record" (swept, and its copy is missing or unreadable),
 * "other-sealing-key", "rotation" (neither is re-signed), "publish-failed" (no relay took it) or "incomplete-revocation"
 * (re-signed or not due, with a relay that did not take a record with a revoked list). A heal is logged on its
 * own, "heal" with the copy's date, and a heal re-signs at once, with the next epoch published first whenever it is
 * due. An epoch it publishes first is logged on its own, "epoch" with its number or "epoch-failed"; after a failure the next
 * cycle, 60 s later, publishes it again (it is kept unpublished, so dueAt says it is due now).
 */
export class RecordKeeper {
  readonly #o: RecordKeeperOptions
  #address: AddressRecord | null = null
  #accept: AcceptFromRecord | null = null
  /** Cycles in a row that re-signed nothing and found nothing due later, or left a relay behind. */
  #misses = 0
  #last: KeepAliveStatus['last'] = null
  /** The code of the last read this cycle that a relay gave no answer to: no answer is not an answer of "none". */
  #noAnswer: string | null = null
  /** What each relay holds as of this cycle, read back or taken in its rotation: `<url> <kind> <iat>`. */
  readonly #seen = new Set<string>()
  #healed: KeepAliveStatus['healed'] = null
  /** The copy a heal holds until a publish replaces it: while it is `#address` the heal is owed, whatever its age. */
  #owed: AddressRecord | null = null
  #next: number | null = null
  #cancel: () => void = noop
  #running: Promise<void> | null = null
  #stopped = false

  constructor(options: RecordKeeperOptions) {
    this.#o = options
  }

  /** The first cycle: it reads the records and re-signs them only when they are due. */
  start(): Promise<void> {
    return this.#run()
  }

  status(): KeepAliveStatus {
    return {
      next_at: this.#next === null ? null : iso(this.#next),
      address_iat: this.#address?.iat ?? null,
      accept_from_iat: this.#accept?.iat ?? null,
      healed: this.#healed,
      last: this.#last,
    }
  }

  /** Cancels the next cycle; a cycle in flight finishes but schedules nothing. */
  stop(): void {
    this.#stopped = true
    this.#cancel()
    this.#next = null
  }

  #run(): Promise<void> {
    // A cycle reports its own failures; a fault outside them is logged and retried, never thrown into a timer.
    this.#running ??= this.#cycle()
      .catch((e: unknown) => {
        this.#o.log.log('error', 'keep-alive', { outcome: 'internal', detail: String(e) })
        if (!this.#stopped) this.#schedule(this.#o.clock.now() + KEEP_ALIVE_RETRY_S)
      })
      .finally(() => {
        this.#running = null
      })
    return this.#running
  }

  async #cycle(): Promise<void> {
    const { clock, epochs, log, signer } = this.#o
    const refused = await this.#refresh()
    let outcome: string
    let next: number | null = null
    let address = this.#address
    let retry = false
    if (address !== null && this.#own(address)) {
      // A heal rotates whenever it can: the key record went with the address record, whatever dueAt says.
      retry = !(await this.#epoch(address, address === this.#owed))
      address = this.#address as AddressRecord
    }
    // Before the address record, as a rotation does it: a sender prefers a key record over a record with no sealing key.
    const key = await this.#offerKey()
    let offers: readonly Offered[] = []
    if (address === null)
      outcome = refused !== null ? 'no-held-record' : this.#noAnswer === null ? 'no-record' : 'unreachable'
    else if (address.sealing_key !== null && address.sealing_key !== this.#o.sealingKey)
      outcome = 'other-sealing-key'
    else if (address.rotated_from !== null) outcome = 'rotation'
    else if (address !== this.#owed && clock.now() < address.iat + address.ttl / 2) {
      outcome = 'not-due'
      next = address.iat + address.ttl / 2 + this.#offset(address.ttl)
    } else {
      const r = await this.#resign(address)
      offers = r.offers
      outcome = r.renewed === null ? 'publish-failed' : 're-signed'
      // After a re-sign, the next is due at half the new record's ttl; after a failure, after the retry wait.
      if (r.renewed !== null) next = r.renewed.iat + r.renewed.ttl / 2 + this.#offset(r.renewed.ttl)
    }
    if (address !== null && offers.length === 0) offers = await this.#carry()
    const published = offers.reduce((n, o) => n + o.held.length, 0)
    const failed = offers.reduce((n, o) => n + o.lagging.length, 0)
    const lagging = [...(key?.lagging ?? []), ...offers.flatMap((o) => o.lagging)]
    const incomplete = lagging.filter((l) => l.revokes).map((l) => incompleteLine(signer.address, l))
    const fine = outcome === 're-signed' || outcome === 'not-due'
    if (fine && incomplete.length > 0) outcome = 'incomplete-revocation'
    const now = clock.now()
    // The next epoch is a reason to wake too; one that failed is tried again after the first retry wait.
    const epochAt = !epochs ? null : retry ? now + KEEP_ALIVE_RETRY_S : epochs.dueAt()
    if (next !== null && epochAt !== null && epochAt > now) next = Math.min(next, epochAt)
    if (next === null || lagging.length > 0) {
      const wait = now + Math.min(KEEP_ALIVE_RETRY_S * 2 ** this.#misses, KEEP_ALIVE_RETRY_MAX_S)
      next = next === null ? wait : Math.min(next, wait)
      this.#misses++
    } else {
      this.#misses = 0
    }
    const gap = incomplete.length === 0 ? {} : { incomplete }
    const code = lagging.at(-1)?.code ?? this.#noAnswer
    this.#last = {
      at: iso(now),
      outcome,
      published,
      failed,
      code,
      ...(lagging.length === 0 ? {} : { lagging }),
      ...gap,
    }
    log.log(fine && lagging.length === 0 ? 'info' : 'warn', 'keep-alive', {
      outcome,
      address_iat: this.#address?.iat ?? null,
      accept_from_iat: this.#accept?.iat ?? null,
      published,
      failed,
      next_at: iso(next),
      ...(lagging.length === 0 ? {} : { lagging: lagging.map(lagLine) }),
      ...gap,
      ...(refused === null ? {} : { detail: refused }),
    })
    if (!this.#stopped) this.#schedule(next)
  }

  /** The keep-alive offset of a re-sign at half `ttl`, in whole seconds: u × ttl / 10 with an rng, 0 without. */
  #offset(ttl: number): number {
    return this.#o.rng === undefined ? 0 : Math.floor((jitterOf(this.#o.rng.bytes(4)) * ttl) / 10)
  }

  /** Whether a record is one the keep-alive keeps: its own sealing key or none, and no rotation. */
  #own(a: AddressRecord): boolean {
    return (a.sealing_key === null || a.sealing_key === this.#o.sealingKey) && a.rotated_from === null
  }

  /**
   * The next epoch when one is due, from the held address record, which it replaces with the one the rotation leaves;
   * false when no relay took it (logged "epoch-failed"), true otherwise, with the relays that did not take a record on
   * its log line. `now` rotates whether it is due or not.
   */
  async #epoch(held: AddressRecord, now: boolean): Promise<boolean> {
    const { epochs, clock, log } = this.#o
    if (!epochs || (!now && clock.now() < epochs.dueAt())) return true
    try {
      const r = await epochs.rotate(held)
      this.#address = r.address
      this.#keep(r.address)
      // What it signed is held where it was taken, so the offers that follow go only to the relays that did not take it.
      const took = (url: string, kind: RecordKind) =>
        !r.lagging.some((l) => l.kind === kind && l.relay === url)
      for (const url of this.#o.relays) {
        if (took(url, 'key')) this.#seen.add(`${url} key ${r.key.iat}`)
        if (took(url, 'address') && r.address.iat > held.iat)
          this.#seen.add(`${url} address ${r.address.iat}`)
      }
      const lagging = r.lagging.length === 0 ? {} : { lagging: r.lagging.map(lagLine) }
      const fields = { outcome: 'epoch', epoch: r.epoch, address_iat: r.address.iat, ...lagging }
      log.log(r.lagging.length === 0 ? 'info' : 'warn', 'keep-alive', fields)
      return true
    } catch (e) {
      log.log('warn', 'keep-alive', { outcome: 'epoch-failed', detail: String(e) })
      return false
    }
  }

  /**
   * Reads both records at every relay and keeps the newest of each that its own key signed, if newer than its own, and
   * the copy of a new address record. It comes back from the copy when no relay holds a record and none is held here,
   * or when the copy is newer than any relay's (a replay): the copy, so held from here on. With no record and a relay
   * that failed it does neither: that relay may hold one, and a re-sign in an outage would go behind it. It returns why
   * a swept identity cannot come back (no-held-record), or null.
   */
  async #refresh(): Promise<string | null> {
    const { relays, home, name, signer, log } = this.#o
    const before = this.#address
    let unread = false
    this.#noAnswer = null
    this.#seen.clear()
    for (const url of relays) {
      const address = await this.#read(url, 'address')
      if (address === undefined) unread = true
      if (address?.kind === 'address' && address.iat > (this.#address?.iat ?? -1)) this.#address = address
      const accept = await this.#read(url, 'accept-from')
      if (accept?.kind === 'accept-from' && accept.iat > (this.#accept?.iat ?? -1)) this.#accept = accept
      if (this.#o.epochs) await this.#read(url, 'key')
    }
    // Heal the accept-from from the home copy when no relay holds one (a rotation stranded it): the carry re-publishes
    // it, so a stranded copy never leaves peers unable to resolve the roots; else keep the copy current (newer-stays).
    if (this.#accept === null) this.#accept = heldAccept(null, home, name, signer.address)
    else keepAcceptCopy(home, name, this.#accept)
    const found = this.#address
    if (found !== null && found !== before) this.#keep(found)
    if (found === null && unread) return null
    let copy: AddressRecord | null
    try {
      copy = continueFrom(found, home, name, signer.address)
    } catch (e) {
      if (e instanceof EdgeError && e.code === 'no-held-record') return e.message
      throw e
    }
    if (copy === null || copy === found) return null
    const since = this.#staleSince()
    this.#address = this.#owed = copy
    this.#healed = { signed_at: iso(copy.iat), stale_since: since === null ? null : iso(since) }
    log.log('warn', 'keep-alive', { outcome: 'heal', ...this.#healed })
    return null
  }

  /** Since when the home's recovery copy is stale; an unreadable state file is logged, and never stops a heal. */
  #staleSince(): number | null {
    const { home, signer, log } = this.#o
    try {
      return readRecoveryState(home, signer.address)?.stale_since ?? null
    } catch (e) {
      log.log('warn', 'keep-alive', { outcome: 'recovery-state', detail: String(e) })
      return null
    }
  }

  /** Keeps `record` as the home's copy (a copy as new or newer stays); a failed write costs the cycle nothing. */
  #keep(record: AddressRecord): void {
    const { home, name, log } = this.#o
    try {
      keepAddressCopy(home, name, record)
    } catch (e) {
      log.log('warn', 'keep-alive', { outcome: 'copy-failed', detail: String(e) })
    }
  }

  /**
   * One record of the identity's own at one relay, signed by its own key; null when the relay holds none, and undefined
   * when it failed or what it holds is not that, so it cannot be said to hold none.
   */
  async #read(url: string, kind: RecordKind): Promise<AcRecord | null | undefined> {
    const own = this.#o.signer.address
    let bytes: Uint8Array | null
    try {
      bytes = await this.#o.client.fetchRecord(url, own, kind)
    } catch (e) {
      this.#noAnswer = codeOf(e)
      return undefined
    }
    try {
      if (bytes === null) return null
      const r = parseRecord(bytes)
      const signer = r.kind === 'accept-from' ? r.owner : r.key
      // At its own iat a record is neither early nor expired, so this checks its signature and form.
      if (r.kind !== kind || signer !== own) return undefined
      const read = verifyRecord(r, r.iat)
      this.#seen.add(`${url} ${kind} ${read.iat}`)
      return read
    } catch {
      return undefined
    }
  }

  /** Offers `record` to `relays`, one at a time: a relay that does not take it is a laggard, never a failed cycle. */
  #offer(record: AcRecord, relays: readonly string[], staleHolds = false): Promise<Offered> {
    const publish = (url: string) => this.#o.edge.publishRecord(record, [url])
    return offerRecord(record, relays, publish, { staleHolds })
  }

  /**
   * Offers the newest key record to the relays that did not read back as holding it, until each holds it (spec/SPEC.md
   * Appendix B 110). Never to one that holds it: its stale-record would spend the address's publishes for nothing.
   */
  async #offerKey(): Promise<Offered | null> {
    const record = this.#o.epochs?.keyRecord() ?? null
    if (record === null) return null
    const behind = this.#o.relays.filter((url) => !this.#seen.has(`${url} key ${record.iat}`))
    return this.#offer(record, behind, true)
  }

  /**
   * Offers the records held, unchanged, to the relays that did not read back as holding them: a relay left behind, a
   * person's republish or a rotation that one relay missed. A relay that has taken one since answers stale-record.
   */
  async #carry(): Promise<Offered[]> {
    const offers: Offered[] = []
    for (const record of [this.#address, this.#accept]) {
      if (record === null) continue
      const behind = this.#o.relays.filter((url) => !this.#seen.has(`${url} ${record.kind} ${record.iat}`))
      if (behind.length > 0) offers.push(await this.#offer(record, behind, true))
    }
    return offers
  }

  /**
   * Signs both records again, unchanged but for a newer iat, and offers them to every relay: what each offer did, and
   * the new address record once at least one relay took it (else null).
   */
  async #resign(address: AddressRecord): Promise<{ offers: Offered[]; renewed: AddressRecord | null }> {
    const { clock, relays, signer } = this.#o
    const accept = this.#accept
    const iat = Math.max(clock.now(), address.iat + 1, (accept?.iat ?? 0) + 1)
    const next = signRecord(signer, {
      kind: 'address',
      key: address.key,
      sealing_key: address.sealing_key,
      relays: address.relays,
      rotation_key: address.rotation_key,
      revoked: address.revoked,
      ttl: address.ttl,
      iat,
      rotated_from: null,
    })
    const nextAccept =
      accept === null
        ? null
        : signRecord(signer, {
            kind: 'accept-from',
            owner: accept.owner,
            roots: accept.roots,
            max_bytes: accept.max_bytes,
            ttl: accept.ttl,
            iat,
          })
    const sent = await this.#offer(next, relays)
    const offers = nextAccept === null ? [sent] : [sent, await this.#offer(nextAccept, relays)]
    if (sent.held.length === 0) return { offers, renewed: null }
    this.#address = next
    this.#keep(next)
    this.#accept = nextAccept
    if (nextAccept !== null) keepAcceptCopy(this.#o.home, this.#o.name, nextAccept)
    return { offers, renewed: next }
  }

  #schedule(at: number): void {
    this.#cancel()
    this.#next = at
    this.#cancel = this.#o.timers.after(Math.max(0, (at - this.#o.clock.now()) * 1000), () => {
      this.#next = null
      void this.#run()
    })
  }
}
