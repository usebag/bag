import {
  AcError,
  type AddressRecord,
  type CaveatContext,
  type CaveatEvaluator,
  type CaveatResult,
  type ChainResult,
  evaluateCaveats,
  type Hop,
  isAcError,
  isAddress,
  type MembersRecord,
  matchesCaveat,
  type PolicyCode,
  type PolicyRecord,
  type PolicyRoots,
  typeMatches,
} from '@usebag/core'
import type { AuditValue } from './audit.ts'
import {
  type ModerationInput,
  type ModerationOutcome,
  type Moderator,
  runModeration,
} from './moderation/modules.ts'
import type { Resolver } from './resolver.ts'

export { typeMatches }

// The edge's policy (spec/SPEC.md §9.5): which roots it trusts, which caveat evaluators it honors (any caveat they do
// not know fails closed), which sealed types it accepts, and the root's revocation list. An org's two policy records
// narrow it before routing and never widen it: the members record's roots allowed,
// denied or unknown and its rate per root, the served record's external chains and its types and sizes per scope.

/** A trusted root: an org by its domain, optionally with its key pinned in advance, or a key trusted directly. */
export interface TrustedRoot {
  readonly domain?: string
  readonly key?: string
  readonly address?: string
}

export interface PolicyOptions {
  readonly roots: readonly TrustedRoot[]
  /** Accepted sealed types: an exact type, "<prefix>.*", or "*" for any. */
  readonly types: readonly string[]
  /** The evaluators honored; with none, every caveat fails closed. */
  readonly evaluators?: readonly CaveatEvaluator[]
  /** The org's served policy record, verified by whoever loaded it: its scopes and external rules. */
  readonly org?: PolicyRecord
  /** The org's members record, verified, never served: its roots, rate, outbound rules and moderation. */
  readonly members?: MembersRecord
  /** The moderation modules this edge has, by name: the members record names the one it runs. */
  readonly moderators?: readonly Moderator[]
  /** How long a moderation module may take, in milliseconds (default 10,000). */
  readonly moderationTimeoutMs?: number
  /** The most rows held in quarantine at once (default 1,024): a hold past it is refused, rule quarantine.full. */
  readonly maxQuarantined?: number
}

type Detail = Record<string, AuditValue>

/** An org rule's refusal or hold: the code it refuses (or would refuse) with, the rule, and the line's detail. */
export interface Ruling {
  readonly action: 'refuse' | 'hold'
  readonly code: PolicyCode
  readonly rule: string
  readonly detail: Detail
}

/** What the org's rules decided: pass, or a ruling. */
export type Decision = { readonly action: 'pass' } | Ruling

/**
 * The message facts the org rules read: its ts, the edge's clock, the rules a release of its row waived, and the key a
 * domain is pinned to at this edge (a deny list matches it when the domain is dark).
 */
export interface Facts {
  readonly ts: number
  readonly now: number
  readonly waived: readonly string[]
  readonly pinned: (host: string) => string | null
}

const PASS: Decision = { action: 'pass' }

function verdict(action: Ruling['action'], code: PolicyCode, rule: string, detail: Detail = {}): Ruling {
  return { action, code, rule, detail }
}

function validRoot(r: TrustedRoot): boolean {
  if (r.domain !== undefined) return r.address === undefined && (r.key === undefined || isAddress(r.key))
  return r.key === undefined && isAddress(r.address)
}

export class Policy {
  readonly #o: PolicyOptions
  readonly #resolver: Resolver
  /** Admitted messages per root in the current rate window, in memory as the relay's v0 counters are. */
  readonly #rates = new Map<string, { readonly start: number; readonly n: number }>()

  constructor(options: PolicyOptions, resolver: Resolver) {
    if (!options.roots.every(validRoot)) {
      throw new Error('policy: a trusted root is a domain, with an optional key, or an address')
    }
    if (new Set([options.org?.key ?? [], options.members?.key ?? []].flat()).size > 1) {
      throw new Error('policy: the served and members records are signed by one org root')
    }
    this.#o = options
    this.#resolver = resolver
  }

  /** The org root of the records the edge has, or null without either: a chain rooted elsewhere is external. */
  get orgKey(): string | null {
    return this.#o.org?.key ?? this.#o.members?.key ?? null
  }

  /** The most rows held in quarantine at once. */
  get maxQuarantined(): number {
    return this.#o.maxQuarantined ?? 1024
  }

  /**
   * Admits a verified chain: untrusted-root unless its root is trusted; pin-mismatch or resolve-failed when a domain
   * root cannot be read or its key changed without a valid rotation; revoked when a hop's sub is in the root's
   * current revoked list. A chain with hops needs the root's address record; an empty chain needs none.
   */
  async admit(chain: ChainResult, auth: readonly Hop[]): Promise<void> {
    this.#revoked(await this.#rootRecord(chain.root, auth.length > 0), auth)
  }

  /**
   * Admits a verified chain under the org's rules, else as admit does: a root the deny list names, by a key
   * it resolves to or is pinned to, is refused; one the edge does not trust, or an allow list does not name, is
   * unknown, and `roots.unknown` refuses or holds it (a release waives the hold); then an external chain's length,
   * hop lifetimes and required caveats, and the rate per root. Throws as admit does for resolution, pins, revocation.
   */
  async decide(chain: ChainResult, auth: readonly Hop[], facts: Facts): Promise<Decision> {
    const roots = this.#o.members?.roots ?? null
    if (this.orgKey === null || roots === null) await this.admit(chain, auth)
    else {
      const ruling = await this.#roots(roots, chain, auth, facts)
      if (ruling !== null) return ruling
    }
    return this.#external(chain, auth, facts.ts) ?? this.#rate(chain.root, facts) ?? PASS
  }

  async #roots(roots: PolicyRoots, chain: ChainResult, auth: readonly Hop[], facts: Facts) {
    const denied = roots.mode === 'deny' ? await this.#listed(roots.list, chain.root, facts) : null
    if (denied !== null) return verdict('refuse', 'untrusted-root', 'roots.deny', { entry: denied })
    let record: AddressRecord | null = null
    let unknown = false
    try {
      record = await this.#rootRecord(chain.root, auth.length > 0)
      unknown = roots.mode === 'allow' && (await this.#listed(roots.list, chain.root, null)) === null
    } catch (e) {
      if (!isAcError(e, 'untrusted-root')) throw e
      unknown = true
    }
    if (unknown && roots.unknown === 'refuse') return verdict('refuse', 'untrusted-root', 'roots.unknown')
    if (unknown && !facts.waived.includes('roots.unknown'))
      return verdict('hold', 'untrusted-root', 'roots.unknown')
    // A released unknown root the edge does not trust at all needs its own record for its revoked list.
    if (unknown && record === null && auth.length > 0) record = await this.#keyRecord(chain.root)
    this.#revoked(record, auth)
    return null
  }

  /**
   * The org's scopes: each scope whose match an effective caveat meets applies, so a message must be of a
   * type each accepts (type-not-accepted) and an envelope within each one's max_bytes (policy-refused). Null passes.
   */
  scope(caveats: readonly string[], type: string, bytes: number): Ruling | null {
    for (const [i, s] of (this.#o.org?.scopes ?? []).entries()) {
      if (!matchesCaveat(s.match, caveats)) continue
      if (!s.accept_types.some((p) => typeMatches(p, type))) {
        return verdict('refuse', 'type-not-accepted', `scopes[${i}].accept_types`, { type })
      }
      if (bytes > s.max_bytes) {
        return verdict('refuse', 'policy-refused', `scopes[${i}].max_bytes`, {
          bytes,
          max_bytes: s.max_bytes,
        })
      }
    }
    return null
  }

  /**
   * Runs the module the members record names on a message, with the ruling its action makes of a flag:
   * a hold (quarantine) or a refusal (drop), none for allow. Null without moderation, or once a release waived it.
   */
  async moderate(
    input: Omit<ModerationInput, 'params'>,
    waived: readonly string[],
  ): Promise<(ModerationOutcome & { readonly ruling: Ruling | null }) | null> {
    const m = this.#o.members?.moderation ?? null
    if (m === null || waived.some((w) => w.startsWith('moderation'))) return null
    const module = this.#o.moderators?.find((x) => x.name === m.module)
    const out = await runModeration(m, module, input, this.#o.moderationTimeoutMs ?? 10_000)
    const action = m.action === 'drop' ? 'refuse' : 'hold'
    const ruling =
      out.flag && m.action !== 'allow' ? verdict(action, 'policy-refused', out.rule, out.detail) : null
    return { ...out, ruling }
  }

  /** Evaluates the effective caveats with the honored evaluators, after unsealing. */
  caveats(caveats: readonly string[], ctx: CaveatContext): CaveatResult {
    return evaluateCaveats(caveats, this.#o.evaluators ?? [], ctx)
  }

  /** True when a sealed type is accepted. */
  acceptsType(type: string): boolean {
    return this.#o.types.some((p) => typeMatches(p, type))
  }

  /**
   * A chain rooted outside the org: at most max_hops hops, each hop's exp - ts at most max_hop_lifetime, and the
   * required caveat patterns each met.
   */
  #external(chain: ChainResult, auth: readonly Hop[], ts: number): Ruling | null {
    const e = this.#o.org?.external ?? null
    if (e === null || chain.root === this.orgKey) return null
    if (e.max_hops !== null && auth.length > e.max_hops) {
      return verdict('refuse', 'policy-refused', 'external.max_hops', { hops: auth.length })
    }
    const life = e.max_hop_lifetime
    const long = life === null ? -1 : auth.findIndex((h) => h.exp - ts > life)
    if (long >= 0) {
      const lifetime = (auth[long] as Hop).exp - ts
      return verdict('refuse', 'policy-refused', 'external.max_hop_lifetime', { hop: long, lifetime })
    }
    const missing = e.required_caveats.findIndex((p) => !matchesCaveat(p, chain.caveats))
    if (missing < 0) return null
    return verdict('refuse', 'policy-refused', `external.required_caveats[${missing}]`, {
      pattern: e.required_caveats[missing] as string,
    })
  }

  /** At most per_root admitted messages per root in a window aligned to multiples of it; one over is held. */
  #rate(root: string, facts: Facts): Ruling | null {
    const r = this.#o.members?.rates ?? null
    if (r === null || facts.waived.includes('rates.per_root')) return null
    const start = facts.now - (facts.now % r.window)
    const seen = this.#rates.get(root)
    const n = seen?.start === start ? seen.n : 0
    if (n >= r.per_root) return verdict('hold', 'policy-refused', 'rates.per_root', { n, window: r.window })
    this.#rates.set(root, { start, n: n + 1 })
    return null
  }

  /**
   * The entry of `list` that names `root`: the address itself, or a domain whose current key it is. With `facts` (a
   * deny list), a domain also names the key it is pinned to here, and one that does not resolve matches nothing else;
   * without (an allow list), a failure to resolve is thrown when nothing matched.
   */
  async #listed(list: readonly string[], root: string, facts: Facts | null): Promise<string | null> {
    if (list.includes(root)) return root
    let failure: unknown = null
    for (const entry of list) {
      if (!entry.startsWith('domain:')) continue
      const host = entry.slice('domain:'.length)
      if (facts?.pinned(host) === root) return entry
      try {
        if ((await this.#resolver.domain(host)).key === root) return entry
      } catch (e) {
        failure ??= e
      }
    }
    if (facts === null && failure !== null) throw failure
    return null
  }

  #revoked(record: AddressRecord | null, auth: readonly Hop[]): void {
    const i = record === null ? -1 : auth.findIndex((h) => record.revoked.includes(h.sub))
    if (i >= 0) throw new AcError('revoked', `hop ${i}'s sub is in the root's revoked list`)
  }

  async #keyRecord(root: string): Promise<AddressRecord> {
    const record = await this.#resolver.address(root)
    if (record === null)
      throw new AcError('resolve-failed', 'no address record of the root, for its revoked list')
    return record
  }

  async #rootRecord(root: string, needed: boolean): Promise<AddressRecord | null> {
    if (this.#o.roots.some((r) => r.address === root)) return needed ? await this.#keyRecord(root) : null
    let failure: unknown = null
    for (const r of this.#o.roots) {
      if (r.domain === undefined) continue
      try {
        const record = await this.#resolver.domain(r.domain, r.key)
        if (record.key === root) return record
      } catch (e) {
        failure ??= e
      }
    }
    throw failure ?? new AcError('untrusted-root', 'the chain root is not a trusted root')
  }
}
