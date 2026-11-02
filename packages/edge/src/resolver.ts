import {
  AcError,
  type AddressRecord,
  checkDiscovered,
  DEFAULT_SKEW,
  DISCOVERY_PREFIX,
  type Discovery,
  discover,
  fromHex,
  type HandleRecord,
  handlePath,
  isAcError,
  isDomainHost,
  isHandle,
  isSpecialUseDomain,
  type KeyRecord,
  parseHandle,
  parseHandleRecord,
  parseRecord,
  type RecordKind,
  serializeHandleRecord,
  serializeRecord,
  txtName,
  verifyHandleRecord,
  verifyRecord,
  WELL_KNOWN_RECORD_PATH,
} from '@usebag/core'
import { type Audit, reasonOf } from './audit.ts'
import { GuardRefused, guardRefusal, type RelayGuard } from './net.ts'
import { Pins } from './pins.ts'
import { type CacheKind, type Clock, type EdgeStore, type RecordSource, RelayError } from './ports.ts'

// The resolver (spec/SPEC.md §9.4): an org's address record found by DNS discovery (§12.2: the TXT record at
// _bag.<domain> names the key its record agrees with and its one origin), address and key records from relays,
// each verified, pinned when it is an address record, and cached no longer than it is valid; and handles (§12.4), each
// bound to an address by a handle record its org's pinned key signs, cached no longer than that record's iat + ttl. A
// relay the guard refuses (a private address that is not one of the edge's own relays) is skipped as a relay that
// failed; a fetch at an org's origin goes through the guard in the record source, which connects to the address
// the guard checked. A resolve-failed names the step that failed: from relay, naming each relay asked
// and what it answered, from dns, well-known or handle. `lookup` asks every source without the cache, to
// show where an address's, a domain's or a handle's records live.

export interface ResolverOptions {
  readonly store: EdgeStore
  readonly source: RecordSource
  readonly clock: Clock
  readonly audit: Audit
  /** The edge's own relays: where records are looked up after any hints. */
  readonly relays: readonly string[]
  readonly skew?: number
  /** The private-address guard; without one, every relay URL is asked. */
  readonly guard?: RelayGuard
}

/** What a sender needs of a recipient: the address to seal to, its sealing key and the relays to publish to. */
export interface ResolvedRecipient {
  readonly address: string
  readonly sealingKey: Uint8Array
  readonly relays: readonly string[]
}

type Resolved = AddressRecord | KeyRecord

/** One relay asked for a record, and what came of it: found, none, refused (the guard), unreachable, or a code. */
export interface Tried {
  /** The relay URL, a user name or password in it left out (recorded). */
  readonly relay: string
  readonly outcome: string
}

/** A resolve-failed from the relays, with every relay asked and its outcome, in the order asked. */
export class ResolveFailed extends AcError {
  readonly tried: readonly Tried[]

  constructor(detail: string, tried: readonly Tried[]) {
    super('resolve-failed', detail)
    this.name = 'ResolveFailed'
    this.tried = tried
  }
}

/** What one relay answered for a record: its outcome, and the record that verified or the failure. */
interface RelayAnswer {
  readonly url: string
  readonly tried: Tried
  readonly record?: Resolved
  readonly failure?: unknown
}

/** How long past a record's validity its iat is remembered: a day, the longest an older record can outlive it. */
const SEEN_SECONDS = 86_400

/** What the cache holds of a subject now: the record's kind, iat and last valid second, and where it came from. */
export interface CachedRecord {
  readonly kind: CacheKind
  readonly iat: number
  readonly valid_until: number
  /** The relay URL or `well-known`, when this process cached it; null for a record an earlier process cached. */
  readonly source: string | null
}

/** What a lookup asks a source for: a record of a kind, a handle record, or the TXT records of a domain. */
export type LookupKind = CacheKind | 'txt'

/** One source asked by a lookup for one kind of record. */
export interface LookupResult {
  /**
   * The relay URL (recorded), the URL of a record at a domain's origin, or, for the TXT step, the DNS name asked. A TXT
   * found names its key in `key` and the origin in `detail`; a handle record found names its org in `key` and the
   * address in `detail`.
   */
  readonly relay: string
  readonly kind: LookupKind
  /** found (a record that verifies), none (404), refused (the guard, before any request) or error. */
  readonly outcome: 'found' | 'none' | 'refused' | 'error'
  readonly iat?: number
  readonly valid_until?: number
  readonly key?: string
  readonly detail?: string
}

/** Where an address's records were found: what the cache holds, and each source's answer, in the resolver's order. */
export interface LookupReport {
  readonly subject: string
  readonly cached: CachedRecord | null
  readonly results: readonly LookupResult[]
}

/** A relay URL with a user name or password in it as its scheme and host (the port kept); any other as it is. */
export function recorded(url: string): string {
  // A target's URL comes from a checked record (an http or https URL) or the edge's own relays; one that does not
  // parse is recorded as it is.
  const u = URL.parse(url)
  return u?.username || u?.password ? `${u.protocol}//${u.host}` : url
}

/** The outcome of a relay call that threw: unreachable for no answer, the relay's or the core's code, else error. */
function outcomeOf(e: unknown): string {
  if (e instanceof RelayError) return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
  return isAcError(e) ? e.code : 'error'
}

/** The last second a record is valid: an address record's iat + ttl, a key record's exp. */
function validUntil(r: Resolved): number {
  return r.kind === 'address' ? r.iat + r.ttl : r.exp
}

/** Special-use top-level labels a lookup never fetches a well-known record under (RFC 6761, 6762, 7686, 9476). */
export const SPECIAL_USE_TLDS: ReadonlySet<string> = new Set([
  'local',
  'localhost',
  'internal',
  'onion',
  'alt',
  'arpa',
  'invalid',
])

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * Why `host` is not a domain root as spec/SPEC.md §7.4 writes one, or null when it is: a lowercase DNS name of at
 * most 253 characters, two or more labels of 1 to 63 letters, digits and inner hyphens, no trailing dot, no port,
 * scheme, path or user part, and not an IP literal (a last label of decimal digits or 0x and hex digits, nor a bracket
 * or a colon anywhere); a special-use top-level label (SPECIAL_USE_TLDS) is refused on top of the grammar.
 */
export function domainRootRefusal(host: string): string | null {
  const q = JSON.stringify(host)
  if (host.length === 0 || host.length > 253) return `${q} is not a domain root: 1 to 253 characters`
  if (host !== host.toLowerCase()) return `${q} is not a domain root: lowercase only`
  if (host.includes('://') || host.includes('/') || host.includes('@') || host.includes('?'))
    return `${q} is not a domain root: no scheme, path, user or query part`
  if (host.includes(':') || host.includes('['))
    return `${q} is not a domain root: no port and no IPv6 literal`
  if (host.endsWith('.')) return `${q} is not a domain root: no trailing dot`
  const labels = host.split('.')
  if (labels.length < 2) return `${q} is not a domain root: two or more labels`
  if (!labels.every((l) => LABEL.test(l))) return `${q} is not a domain root: a label is not RFC 1123`
  const last = labels[labels.length - 1] as string
  if (/^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last)) return `${q} is not a domain root: an IP literal`
  if (SPECIAL_USE_TLDS.has(last)) return `${q} is not a domain root: .${last} is a special-use name`
  return null
}

/** A handle's binding (spec/SPEC.md §12.4): the address it names under its org's key, and the org record's relays. */
export interface HandleBinding {
  readonly handle: string
  readonly domain: string
  readonly address: string
  /** The org key that signed the handle record: the domain's pinned key when it was resolved. */
  readonly org: string
  /** The org record's relays, where the address's records are read first (§12.4 item 4 step 3). */
  readonly relays: readonly string[]
  /** The handle record's iat + ttl: the binding is cached no longer (step 5). */
  readonly valid_until: number
}

/** A sender's handle as a person or a model is shown it: verified, with its domain. */
export interface VerifiedHandle {
  readonly handle: string
  readonly domain: string
  readonly verified: true
}

/** Where a domain's org records are: the discovery (its TXT key, null without one), its origin's host, the TXT name asked. */
interface Origin {
  readonly discovery: Discovery
  readonly host: string
  /** The TXT name asked, or null when none was (a source without DNS, a host that is not a DNS name). */
  readonly asked: string | null
}

/** What a lookup reports of a record found: its iat and last valid second, its key, and a detail. */
type Found = Pick<LookupResult, 'iat' | 'valid_until' | 'key' | 'detail'>

const summary = (r: Resolved): Found => ({ iat: r.iat, valid_until: validUntil(r), key: r.key })

/** True for a handle (the core's isHandle, without narrowing a string that is not one to never). */
const named = (text: string): boolean => isHandle(text)

/** The detail of a step that threw: the core's or the edge's message, else the relay outcome. */
const detailOf = (e: unknown): string => (isAcError(e) ? e.message : outcomeOf(e))

export class Resolver {
  readonly #o: ResolverOptions
  readonly #pins: Pins
  /** Where this process cached each subject's record from, by `<subject> <kind>`. */
  readonly #sources = new Map<string, string>()

  constructor(options: ResolverOptions) {
    this.#o = options
    this.#pins = new Pins(options.store, options.audit, options.clock)
  }

  /**
   * The address record of an org (spec/SPEC.md §12.2): its origin from the TXT record at _bag.<domain>
   * (`https://<domain>` without one, `https://bag.<domain>` with host=bag), its record fetched there
   * through the guard, verified, agreeing with the TXT's key (the key itself, or one rotation it countersigned), then
   * pinned and cached. A special-use domain is refused before any lookup; two bag TXT records, a malformed one
   * or a failed lookup are resolve-failed, and nothing falls back to the well-known URL then.
   */
  async domain(domain: string, initialKey?: string): Promise<AddressRecord> {
    return this.#org(domain, initialKey, null)
  }

  async #org(domain: string, initialKey: string | undefined, known: Origin | null): Promise<AddressRecord> {
    const subject = `domain:${domain}`
    const cached = this.#cached(subject, 'address')
    if (cached !== null) return cached as AddressRecord
    let step = 'dns'
    let record: AddressRecord
    try {
      const origin = known ?? (await this.#origin(domain))
      step = 'well-known'
      const bytes = await this.#o.source.wellKnown(origin.host, this.#o.guard)
      record = this.#verify(bytes, 'address') as AddressRecord
      checkDiscovered(record, origin.discovery)
    } catch (e) {
      throw this.#failed(subject, step, e)
    }
    this.#pins.check(subject, record, initialKey)
    return this.#keep(subject, record, 'well-known')
  }

  /**
   * Where a domain's org records are (spec/SPEC.md §12.2 item 4): resolve-failed for a special-use domain, before any
   * lookup; the TXT records at _bag.<domain> read by the core's discover when the source reads DNS and the
   * domain is a DNS name of a length DNS can hold; else the domain itself, as without discovery.
   */
  async #origin(domain: string): Promise<Origin> {
    if (isSpecialUseDomain(domain))
      throw new AcError('resolve-failed', `${domain} is under a special-use name`)
    const { source } = this.#o
    const name = isDomainHost(domain) ? txtName(domain) : null
    if (source.txt === undefined || name === null) {
      const origin = `https://${domain}`
      return {
        discovery: { key: null, origin, url: origin + WELL_KNOWN_RECORD_PATH },
        host: domain,
        asked: null,
      }
    }
    const discovery = discover(await source.txt(name), domain)
    return { discovery, host: new URL(discovery.origin).host, asked: name }
  }

  /**
   * A handle's binding (spec/SPEC.md §12.4 item 4): the org record of its domain (step 1), its handle record at the
   * org's origin, verified under the domain's pinned key, which that record carries (step 2: a 404 is "no such
   * handle"), cached no longer than the record's iat + ttl (step 5), audited with the handle and the address. A cached
   * binding is used until it expires, never refreshed early (a handle moved to another address without a rotation of
   * the org key is followed only once the binding it replaces expires), and is checked at every call against the
   * revoked list of the freshest org record: `revoked`. A binding signed by a key the domain no longer pins (a
   * countersigned rotation moved the pin) is resolved again. Step 3, the address's records, is `recipient`'s.
   */
  async handle(handle: string): Promise<HandleBinding> {
    const { domain } = parseHandle(handle)
    const subject = `handle:${handle}`
    const held = this.#held(subject)
    if (held !== null) {
      const org = await this.domain(domain)
      if (held.org === org.key) {
        if (org.revoked.includes(held.address)) {
          throw this.#failed(
            subject,
            'handle',
            new AcError('revoked', `${held.address} is revoked by its org`),
          )
        }
        return bindingOf(held, domain, org)
      }
    }
    let origin: Origin
    try {
      origin = await this.#origin(domain)
    } catch (e) {
      throw this.#failed(subject, 'dns', e)
    }
    const org = await this.#org(domain, undefined, origin)
    const now = this.#o.clock.now()
    let record: HandleRecord
    try {
      const { source } = this.#o
      if (source.handleRecord === undefined)
        throw new AcError('resolve-failed', 'this record source reads no handle record')
      const bytes = await source.handleRecord(origin.host, handle, this.#o.guard)
      if (bytes === null) throw new AcError('resolve-failed', `no such handle at ${origin.host}`)
      const expected = { org: org.key, handle, revoked: org.revoked }
      record = verifyHandleRecord(parseHandleRecord(bytes), expected, now, this.#o.skew ?? DEFAULT_SKEW)
    } catch (e) {
      throw this.#failed(subject, 'handle', e)
    }
    const expiresAt = Math.min(now, record.iat) + record.ttl
    const bytes = serializeHandleRecord(record)
    this.#o.store.cachePut(subject, 'handle', bytes, expiresAt)
    // The reverse entry, by address, lets handleOf find the binding of a sender without a scan.
    this.#o.store.cachePut(`handle-of:${record.address}`, 'handle', bytes, expiresAt)
    this.#sources.set(`${subject} handle`, origin.host)
    this.#o.audit.record({
      event: 'resolve',
      decision: 'accept',
      detail: {
        subject,
        kind: 'handle',
        source: origin.host,
        handle,
        address: record.address,
        org: record.org,
        expires_at: expiresAt,
      },
    })
    return bindingOf(record, domain, org)
  }

  /**
   * The verified handle of a sender, or null: shown only when this edge holds an unexpired handle
   * record, one it resolved and cached, that names `address` (the message's principal), is signed by `root` (the
   * chain's root) and by the key the handle's domain is pinned to now. A handle is shown only for a peer this edge has
   * resolved by handle; nothing here asks a relay or DNS.
   */
  handleOf(address: string, root: string): VerifiedHandle | null {
    const back = this.#held(`handle-of:${address}`)
    const r = back === null ? null : this.#held(`handle:${back.handle}`)
    if (r === null || r.address !== address || r.org !== root) return null
    const { domain } = parseHandle(r.handle)
    const pinned = this.#o.store.pinGet(`domain:${domain}`)?.key
    return pinned === r.org ? { handle: r.handle, domain, verified: true } : null
  }

  /**
   * Recipients given as addresses or handles: each handle resolved to its address (`handle`), with the relays of its
   * org's record, where its address's records are read first; addresses as they are.
   */
  async addresses(to: readonly string[]): Promise<{ to: string[]; relays: string[] }> {
    const out: string[] = []
    const relays: string[] = []
    for (const t of to) {
      const b = named(t) ? await this.handle(t) : null
      out.push(b?.address ?? t)
      relays.push(...(b?.relays ?? []))
    }
    return { to: out, relays: [...new Set(relays)] }
  }

  /** The newest address record of a key at the hint relays and the edge's relays; null when none holds one. */
  async address(address: string, hints: readonly string[] = []): Promise<AddressRecord | null> {
    return (await this.#fromRelays(address, 'address', hints)).record as AddressRecord | null
  }

  /** The key record of a key, looked up as `address` is. */
  async key(address: string, hints: readonly string[] = []): Promise<KeyRecord | null> {
    return (await this.#fromRelays(address, 'key', hints)).record as KeyRecord | null
  }

  /**
   * A recipient's sealing key and relays (forward secrecy): the current key record's sealing key when there is
   * one, else the address record's sealing key, else resolve-failed. Preferring the key record means a sender seals to
   * the short-lived epoch key an individual publishes, never to a long-lived address key while that key record stands;
   * a group, which publishes no key record, seals to the generation key its address record carries (groups unchanged);
   * an individual whose address record carries a null sealing key and whose key record is withheld cannot be sealed to
   * at all (no silent downgrade, since a signed null address sealing key cannot be forged non-null). A second rule closes the
   * transition downgrade: an identity ever seen to resolve a key record is marked fs-known in the store, so even a
   * still-valid non-null (legacy) address sealing key is refused as a fallback once the key record is withheld or
   * faults -- a known identity is never rolled back to a long-lived address key. Relays are the
   * address record's, else the hints, else the edge's own. A handle (spec/SPEC.md §12.4 item 4) is resolved to its
   * address first, whose records are read at its org record's relays, then the hints, then the edge's own (step 3).
   */
  async recipient(to: string, hints: readonly string[] = []): Promise<ResolvedRecipient> {
    if (named(to)) {
      const b = await this.handle(to)
      return this.recipient(b.address, [...b.relays, ...hints])
    }
    const address = to
    const subject = `address:${address}`
    const record = await this.address(address, hints)
    const relays =
      record !== null && record.relays.length > 0 ? record.relays : hints.length > 0 ? hints : this.#o.relays
    // Forward secrecy: an identity ever seen to resolve a key record (fs-known) is never downgraded to its
    // long-lived address sealing key, so a withheld or faulting key record cannot roll it back to a legacy key.
    const toAddressKey = (): ResolvedRecipient | null =>
      !this.#o.store.fsKnownGet(subject) && record !== null && record.sealing_key !== null
        ? { address: record.key, sealingKey: fromHex(record.sealing_key, 32), relays }
        : null
    let found: { record: Resolved | null; tried: Tried[] }
    try {
      found = await this.#fromRelays(address, 'key', hints)
    } catch (e) {
      // A relay fault while reading the key record must not downgrade a group, whose generation key is in its address
      // record; an individual with no address sealing key still fails, surfacing the relay's cause to the sender.
      const fallback = toAddressKey()
      if (fallback !== null) return fallback
      throw e
    }
    const key = found.record as KeyRecord | null
    if (key !== null) return { address: key.key, sealingKey: fromHex(key.sealing_key, 32), relays }
    const fallback = toAddressKey()
    if (fallback !== null) return fallback
    throw this.#failed(
      `address:${address}`,
      'relay',
      new AcError('resolve-failed', 'no sealing key'),
      found.tried,
    )
  }

  /**
   * The newest record of a kind (spec/SPEC.md §9 item 4): every relay is asked, together, and the greatest iat that
   * verifies among those that answered is taken, so a relay holding an older record that still verifies cannot stand in
   * for a newer one: the revoked list and the epoch key acted on are the newest seen. A relay that does not answer is
   * never a disagreement and never blocks: its failure counts only when nothing verified. Below an iat that verified
   * before, what answered is refused, never taken, so the relay that served the newest being gone is resolve-failed.
   */
  async #fromRelays(
    address: string,
    kind: RecordKind,
    hints: readonly string[],
  ): Promise<{ record: Resolved | null; tried: Tried[] }> {
    const subject = `address:${address}`
    const cached = this.#cached(subject, kind)
    if (cached !== null) return { record: cached, tried: [] }
    const answers = await Promise.all(this.#order(hints).map((url) => this.#answer(url, address, kind)))
    const tried = answers.map((a) => a.tried)
    let best: RelayAnswer | null = null
    for (const a of answers) {
      if (a.record !== undefined && a.record.iat > (best?.record?.iat ?? -1)) best = a
    }
    const record = best?.record
    if (best === null || record === undefined) {
      const failed = answers.find((a) => a.failure !== undefined)
      if (failed !== undefined) throw this.#failed(subject, 'relay', failed.failure, tried)
      return { record: null, tried }
    }
    const seen = this.#seenIat(subject, kind)
    if (record.iat < seen) {
      const older = new AcError('resolve-failed', `only records older than iat ${seen} answered`)
      throw this.#failed(subject, 'relay', older, tried)
    }
    // Outside any catch: pin-mismatch, and any fault of the store, propagate.
    if (record.kind === 'address') this.#pins.check(subject, record, address)
    const until = validUntil(record) + SEEN_SECONDS
    this.#o.store.cachePut(`iat-seen:${subject}`, kind, Buffer.from(String(record.iat)), until)
    return { record: this.#keep(subject, record, best.url, tried), tried }
  }

  /** One relay asked for a record: a guard's refusal, none, a record that verifies, or what failed. */
  async #answer(url: string, address: string, kind: RecordKind): Promise<RelayAnswer> {
    const tried = (outcome: string): Tried => ({ relay: recorded(url), outcome })
    try {
      const refusal = guardRefusal(this.#o.guard, url)
      const refused = refusal instanceof Promise ? await refusal : refusal
      if (refused !== null) {
        return { url, tried: tried('refused'), failure: new AcError('resolve-failed', refused.detail) }
      }
      const bytes = await this.#o.source.relayRecord(url, address, kind)
      if (bytes === null) return { url, tried: tried('none') }
      const record = this.#verify(bytes, kind)
      if (record.kind === 'key' && record.key !== address)
        throw new AcError('bad-record', 'a key record of another key')
      return { url, tried: tried('found'), record }
    } catch (e) {
      return { url, tried: tried(outcomeOf(e)), failure: e }
    }
  }

  /** The relays asked for an address's records: the hints, then the edge's own, each once. */
  #order(hints: readonly string[]): string[] {
    return [...new Set([...hints, ...this.#o.relays])]
  }

  /**
   * Where records are, for a person or a model asking why a resolution failed: what the cache holds now, then each
   * source in the resolver's order. For an address, every relay (hints, then the edge's own) asked for the address
   * record and the key record; for `domain:<host>`, the TXT step (when DNS is read) and the org record at its origin;
   * for a handle, those two, its handle record, then the address's records at the org record's relays, the hints and
   * the edge's own. It never throws, never reads or writes the cache past that first look, pins nothing and writes no
   * audit line; a relay the guard refuses is not called, nor is an origin.
   */
  async lookup(subject: string, hints: readonly string[] = []): Promise<LookupReport> {
    const results: LookupResult[] = []
    if (named(subject)) {
      const found = await this.#lookupOrg(parseHandle(subject).domain, results)
      const address = found === null ? null : await this.#lookupHandle(subject, found, results)
      if (found !== null && address !== null)
        await this.#lookupRelays(address, [...found.org.relays, ...hints], results)
      const key = `handle:${subject}`
      return { subject: key, cached: this.#peek(key), results }
    }
    if (subject.startsWith('domain:')) {
      await this.#lookupOrg(subject.slice('domain:'.length), results)
      return { subject, cached: this.#peek(subject), results }
    }
    await this.#lookupRelays(subject, hints, results)
    return { subject: `address:${subject}`, cached: this.#peek(`address:${subject}`), results }
  }

  /** A lookup's TXT step and org record step; the org record and its origin when it was found and agreed. */
  async #lookupOrg(
    host: string,
    results: LookupResult[],
  ): Promise<{ org: AddressRecord; origin: Origin } | null> {
    // The host comes from a person or a model, so it is held to §7.4's domain-root grammar before any request,
    // and the fetch at its origin goes through the private-address guard like a relay URL.
    const shape = domainRootRefusal(host)
    if (shape !== null) {
      const relay = `https://${host}${WELL_KNOWN_RECORD_PATH}`
      results.push({ relay, kind: 'address', outcome: 'refused', detail: shape })
      return null
    }
    let origin: Origin
    try {
      origin = await this.#origin(host)
    } catch (e) {
      results.push({ relay: DISCOVERY_PREFIX + host, kind: 'txt', outcome: 'error', detail: detailOf(e) })
      return null
    }
    const { discovery: d, asked } = origin
    if (asked !== null) {
      const detail = `origin ${d.origin}`
      results.push(
        d.key === null
          ? { relay: asked, kind: 'txt', outcome: 'none', detail }
          : { relay: asked, kind: 'txt', outcome: 'found', key: d.key, detail },
      )
    }
    let org: AddressRecord | null = null
    results.push(
      await this.#ask(d.url, 'address', async () => {
        const record = this.#verify(await this.#o.source.wellKnown(origin.host, this.#o.guard), 'address')
        checkDiscovered(record as AddressRecord, d)
        org = record as AddressRecord
        return summary(record)
      }),
    )
    return org === null ? null : { org, origin }
  }

  /** A lookup's handle record step, verified under the org record's key; the address it names when it verifies. */
  async #lookupHandle(
    handle: string,
    found: { org: AddressRecord; origin: Origin },
    results: LookupResult[],
  ): Promise<string | null> {
    const { org, origin } = found
    let address: string | null = null
    const url = `https://${origin.host}${handlePath(handle)}`
    results.push(
      await this.#ask(url, 'handle', async () => {
        const bytes = await this.#o.source.handleRecord?.(origin.host, handle, this.#o.guard)
        if (bytes === undefined)
          throw new AcError('resolve-failed', 'this record source reads no handle record')
        if (bytes === null) return null
        const expected = { org: org.key, handle, revoked: org.revoked }
        const now = this.#o.clock.now()
        const r = verifyHandleRecord(parseHandleRecord(bytes), expected, now, this.#o.skew ?? DEFAULT_SKEW)
        address = r.address
        return { iat: r.iat, valid_until: r.iat + r.ttl, key: r.org, detail: `address ${r.address}` }
      }),
    )
    return address
  }

  /** A lookup's relay steps: the address record, then the key record, at every relay in the resolver's order. */
  async #lookupRelays(address: string, hints: readonly string[], results: LookupResult[]): Promise<void> {
    for (const kind of ['address', 'key'] as const) {
      for (const url of this.#order(hints)) {
        const read = async () => {
          const bytes = await this.#o.source.relayRecord(url, address, kind)
          if (bytes === null) return null
          const r = this.#verify(bytes, kind)
          if (r.key !== address) throw new AcError('bad-record', `a ${kind} record of another key`)
          return summary(r)
        }
        results.push(await this.#ask(recorded(url), kind, read, url))
      }
    }
  }

  /**
   * One source asked by a lookup: `read` fetches and verifies, null for none. A relay URL in `guarded` goes through the
   * guard first, here; a fetch at an origin goes through it in the source, which throws GuardRefused.
   */
  async #ask(
    relay: string,
    kind: LookupKind,
    read: () => Promise<Found | null>,
    guarded?: string,
  ): Promise<LookupResult> {
    try {
      const refused = guarded === undefined ? null : await guardRefusal(this.#o.guard, guarded)
      if (refused !== null) return { relay, kind, outcome: 'refused', detail: refused.detail }
      const found = await read()
      return found === null ? { relay, kind, outcome: 'none' } : { relay, kind, outcome: 'found', ...found }
    } catch (e) {
      if (e instanceof GuardRefused) return { relay, kind, outcome: 'refused', detail: e.refusal.detail }
      return { relay, kind, outcome: 'error', detail: detailOf(e) }
    }
  }

  /** What the cache holds of a subject now: a handle's binding, else its address record, else its key record. */
  #peek(subject: string): CachedRecord | null {
    const source = (kind: CacheKind) => this.#sources.get(`${subject} ${kind}`) ?? null
    const h = this.#held(subject)
    if (h !== null)
      return { kind: 'handle', iat: h.iat, valid_until: h.iat + h.ttl, source: source('handle') }
    for (const kind of ['address', 'key'] as const) {
      const r = this.#cached(subject, kind)
      if (r !== null) return { kind, iat: r.iat, valid_until: validUntil(r), source: source(kind) }
    }
    return null
  }

  #verify(bytes: Uint8Array, kind: RecordKind): Resolved {
    const record = verifyRecord(parseRecord(bytes), this.#o.clock.now(), this.#o.skew ?? DEFAULT_SKEW)
    if (record.kind !== kind) throw new AcError('bad-record', `a ${record.kind} record, not ${kind}`)
    return record as Resolved
  }

  #cached(subject: string, kind: RecordKind): Resolved | null {
    const bytes = this.#o.store.cacheGet(subject, kind, this.#o.clock.now())
    return bytes === null ? null : (parseRecord(bytes) as Resolved)
  }

  /** The greatest iat that verified for a subject and kind, -1 for none: a resolution never takes a lower one. */
  #seenIat(subject: string, kind: RecordKind): number {
    const bytes = this.#o.store.cacheGet(`iat-seen:${subject}`, kind, this.#o.clock.now())
    return bytes === null ? -1 : Number(Buffer.from(bytes).toString())
  }

  /** The handle record the cache holds under a subject, unexpired; null for none. */
  #held(subject: string): HandleRecord | null {
    const bytes = this.#o.store.cacheGet(subject, 'handle', this.#o.clock.now())
    return bytes === null ? null : parseHandleRecord(bytes)
  }

  /**
   * Caches a record until it stops being valid: an address record's iat + ttl (up to a day), but a key record for at
   * most DEFAULT_SKEW seconds, never to its exp. A key record is an individual's short-lived epoch sealing key;
   * a restore mints a fresh epoch and deletes the old private key, so a peer that cached the old key record to its exp
   * would seal to a dead key for up to a day. The short cap means a stale epoch key is re-read within DEFAULT_SKEW.
   */
  #keep<R extends Resolved>(subject: string, record: R, source: string, tried?: readonly Tried[]): R {
    const now = this.#o.clock.now()
    const expiresAt =
      record.kind === 'address'
        ? Math.min(now, record.iat) + record.ttl
        : Math.min(record.exp, now + DEFAULT_SKEW)
    this.#o.store.cachePut(subject, record.kind, serializeRecord(record), expiresAt)
    // Forward secrecy: a verified key record ratchets the subject fs-known, so it is never later downgraded to a
    // long-lived address sealing key. This is the one chokepoint every freshly resolved key record passes through.
    if (record.kind === 'key') this.#o.store.fsKnownSet(subject)
    this.#sources.set(`${subject} ${record.kind}`, source === 'well-known' ? source : recorded(source))
    this.#o.audit.record({
      event: 'resolve',
      decision: 'accept',
      detail: {
        subject,
        kind: record.kind,
        source,
        key: record.key,
        expires_at: expiresAt,
        ...(tried === undefined ? {} : { tried: tried.map((t) => `${t.relay} (${t.outcome})`) }),
      },
    })
    return record
  }

  /**
   * The failure of a subject's resolution at a step (dns, well-known, handle or relay), audited: `revoked` for a
   * revoked address, else resolve-failed. From the relays it names each relay asked and its outcome, as
   * `address:<key> from relay; tried <url> (none), <url> (unreachable)`, in its message and in the audit line's detail;
   * from any other step, the cause's message, as `domain:<host> from dns: <why>`.
   */
  #failed(subject: string, source: string, error: unknown, tried?: readonly Tried[]): AcError {
    const list = tried?.map((t) => `${t.relay} (${t.outcome})`)
    const code = isAcError(error, 'revoked') ? 'revoked' : 'resolve-failed'
    this.#o.audit.record({
      event: 'resolve',
      decision: 'reject',
      reason: code,
      detail: {
        subject,
        source,
        cause: reasonOf(error, 'resolve-failed'),
        ...(list === undefined ? {} : { tried: list }),
      },
    })
    if (list === undefined) {
      const why = detailOf(error).replace(/^resolve-failed: /, '')
      return new AcError(code, `${subject} from ${source}: ${why}`)
    }
    const asked = list.length === 0 ? 'no relay' : list.join(', ')
    return new ResolveFailed(`${subject} from ${source}; tried ${asked}`, tried as readonly Tried[])
  }
}

/** The binding a verified handle record makes, with the org record's relays. */
function bindingOf(r: HandleRecord, domain: string, org: AddressRecord): HandleBinding {
  return {
    handle: r.handle,
    domain,
    address: r.address,
    org: r.org,
    relays: org.relays,
    valid_until: r.iat + r.ttl,
  }
}
