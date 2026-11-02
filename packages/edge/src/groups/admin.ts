import {
  type AcceptFromRecord,
  type AddressRecord,
  type Rng as CoreRng,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  GROUP_KEY_TYPE,
  GROUP_RECORD_TTL,
  type GroupKeyBody,
  type GroupKeyInput,
  generateSealingKey,
  type Hop,
  MAX_ENVELOPE_BYTES,
  MEMBERSHIP_SECONDS,
  openGroupKey,
  type SealingKey,
  sealGroupKey,
  signGroupRecord,
  signMembership,
  signRecord,
} from '@usebag/core'
import { errno } from '../custody/files.ts'
import type { GroupKeyStore, GroupMember, GroupState, RevokedMember } from '../custody/groups.ts'
import type { Edge } from '../edge.ts'
import { FANOUT_EXEMPT } from '../moderation/gate.ts'
import type { Clock, EdgeKeys, Rng } from '../ports.ts'
import type { ResolvedRecipient } from '../resolver.ts'
import { coreRng, type SendResult } from '../sender.ts'

// The admin's side of a group: the group made with its first generation and its two
// records; a member added with its hop and the current generation; a member removed, or the members kept, by a new
// generation sent to every remaining member before the group's new record is published. The admin's own copy of each
// generation is wrapped to the group's identity sealing key, which never leaves the admin, and its membership state
// is the store's state.json.

/** How the admin makes a group: its relays, who may post besides its members, and its records' numbers. */
export interface CreateOptions {
  readonly relays: readonly string[]
  /** The group's rotation key, its cold key, which the group record names: it countersigns a rotation. */
  readonly rotationKey: string
  /** Roots its accept-from record admits besides the group itself, whose chains its members post under. */
  readonly roots?: readonly string[]
  /** The group record's ttl; GROUP_RECORD_TTL (an hour) by default. */
  readonly ttl?: number
  readonly maxBytes?: number
  /** The accept-from record's ttl, how long relays keep the group's mail; the relay TTL by default. */
  readonly retention?: number
}

/** A rotation: the new generation, what was sent to each remaining member, and the record published after. */
export interface Rotation {
  readonly generation: number
  readonly sent: readonly SendResult[]
  readonly record: AddressRecord
}

export interface GroupAdminOptions {
  /** The admin's edge, composed with the group's identity keys, so it publishes and sends as the group. */
  readonly edge: Edge
  /** The group's identity keys: the signing key, whose address is the group's, and the identity sealing key. */
  readonly keys: EdgeKeys
  readonly store: GroupKeyStore
  readonly clock: Clock
  readonly rng: Rng
}

type Holder = GroupMember & { readonly recipient: ResolvedRecipient }

export class GroupAdmin {
  readonly #o: GroupAdminOptions
  readonly #rng: CoreRng

  constructor(options: GroupAdminOptions) {
    this.#o = options
    this.#rng = coreRng(options.rng)
  }

  /** The group's address. */
  get group(): string {
    return this.#o.keys.signing.address
  }

  /** The admin's state of the group; ENOENT before create. */
  state(): GroupState {
    const state = this.#o.store.state(this.group)
    if (state === null) throw errno('ENOENT', `groups: no admin state of ${this.group} is kept here`)
    return state
  }

  /** Makes generation 1, publishes the group record and its accept-from record, then keeps the admin's copy. */
  async create(
    o: CreateOptions,
  ): Promise<{ readonly record: AddressRecord; readonly accept: AcceptFromRecord }> {
    const { clock, edge, keys, store } = this.#o
    if (store.state(this.group) !== null) throw errno('EEXIST', `groups: ${this.group} is kept here already`)
    const iat = clock.now()
    const key = generateSealingKey(this.#rng)
    const ttl = o.ttl ?? GROUP_RECORD_TTL
    const state: GroupState = {
      group: this.group,
      generation: 1,
      iat,
      relays: o.relays,
      ttl,
      rotationKey: o.rotationKey,
      members: [],
      revoked: [],
    }
    const record = this.#record(state, key)
    const accept = signRecord(keys.signing, {
      kind: 'accept-from',
      owner: this.group,
      roots: [this.group, ...(o.roots ?? [])],
      max_bytes: o.maxBytes ?? MAX_ENVELOPE_BYTES,
      ttl: o.retention ?? DEFAULT_TTL,
      iat,
    })
    // Published first and kept after: a create whose records a relay refuses leaves nothing, and can run again.
    await edge.publishRecord(record, state.relays)
    await edge.publishRecord(accept, state.relays)
    this.#keepCopy(1, key)
    store.saveState(state)
    return { record, accept }
  }

  /**
   * Adds a member, or renews one: its hop until `exp` (7 days by default) and the current generation, sent to
   * it; a member added again keeps the relays it was added with unless others are given. One audit line.
   */
  async add(
    member: string,
    o: { readonly exp?: number; readonly relays?: readonly string[] } = {},
  ): Promise<SendResult> {
    const state = this.state()
    const relays = o.relays ?? state.members.find((x) => x.address === member)?.relays ?? []
    const m = { address: member, exp: o.exp ?? this.#o.clock.now() + MEMBERSHIP_SECONDS, relays }
    const sent = await this.#send(state.generation, this.#current(state), await this.#resolve([m]))
    this.#o.store.saveState({ ...state, members: [...state.members.filter((x) => x.address !== member), m] })
    this.#audit('add', state.generation, member)
    return sent[0] as SendResult
  }

  /** Removes a member: a rotation without it, which lists it in revoked until its hop's exp + TTL + skew. */
  async remove(member: string): Promise<Rotation> {
    const state = this.state()
    const gone = state.members.find((m) => m.address === member)
    if (gone === undefined) throw errno('ENOENT', `groups: ${member} is not a member of ${this.group}`)
    const revoked = [...state.revoked, { address: member, until: gone.exp + DEFAULT_TTL + DEFAULT_SKEW }]
    const members = state.members.filter((m) => m !== gone)
    return this.#rotate(state, members, revoked, member)
  }

  /** A new generation for the current members. */
  rotate(): Promise<Rotation> {
    const state = this.state()
    return this.#rotate(state, state.members, state.revoked, null)
  }

  /** Re-signs the current generation's record with a later iat, from the state, and publishes it. */
  async keep(): Promise<AddressRecord> {
    const kept = this.state()
    const state = this.#next(kept, kept.revoked)
    const record = this.#record(state, this.#current(state))
    this.#o.store.saveState(state)
    await this.#o.edge.publishRecord(record, state.relays)
    return record
  }

  /** Keys first, record after: every holder resolved, the new generation sent, then the record published. */
  async #rotate(
    state: GroupState,
    members: readonly GroupMember[],
    revoked: readonly RevokedMember[],
    removed: string | null,
  ): Promise<Rotation> {
    const holders = await this.#resolve(members)
    const generation = state.generation + 1
    const key = generateSealingKey(this.#rng)
    this.#keepCopy(generation, key)
    const sent = await this.#send(generation, key, holders)
    const next = { ...this.#next(state, revoked), generation, members }
    const record = this.#record(next, key)
    this.#o.store.saveState(next)
    this.#audit(removed === null ? 'rotate' : 'remove', generation, removed)
    await this.#o.edge.publishRecord(record, next.relays)
    return { generation, sent, record }
  }

  /** Every member's sealing key, resolved before anything changes, so a member with no record stops the whole step. */
  async #resolve(members: readonly GroupMember[]): Promise<Holder[]> {
    const holders: Holder[] = []
    for (const m of members)
      holders.push({ ...m, recipient: await this.#o.edge.resolver.recipient(m.address, m.relays) })
    return holders
  }

  /** One `group-key.v1` message to each holder: generation `generation`, wrapped to its sealing key, with its hop. */
  async #send(generation: number, key: SealingKey, holders: readonly Holder[]): Promise<SendResult[]> {
    const sent: SendResult[] = []
    for (const h of holders) {
      const holder = { address: h.address, sealingKey: h.recipient.sealingKey }
      const hop = signMembership(this.#o.keys.signing, h.address, h.exp)
      const body = this.#seal(generation, key, holder, hop)
      const input = { to: [h.address], type: GROUP_KEY_TYPE, body, relays: h.relays }
      FANOUT_EXEMPT.add(input)
      sent.push(await this.#o.edge.send(input))
    }
    return sent
  }

  /** The admin's own copy of a generation: its body with no hop, wrapped to the identity sealing key. */
  #keepCopy(generation: number, key: SealingKey): void {
    const holder = { address: this.group, sealingKey: this.#o.keys.sealing.publicKey }
    this.#o.store.put(this.#seal(generation, key, holder, null))
  }

  #seal(generation: number, key: SealingKey, holder: GroupKeyInput['holder'], hop: Hop | null): GroupKeyBody {
    const { clock, keys } = this.#o
    const iat = clock.now()
    return sealGroupKey({ group: keys.signing, generation, key, holder, hop, iat, rng: this.#rng })
  }

  /** The current generation's key, from the admin's copy. */
  #current(state: GroupState): SealingKey {
    const body = this.#o.store.body(this.group, state.generation)
    return openGroupKey(body, { address: this.group, key: this.#o.keys.sealing }, this.#o.clock.now()).key
  }

  /** The state of the next record: a later iat, and the revoked entries that still live. */
  #next(state: GroupState, revoked: readonly RevokedMember[]): GroupState {
    const now = this.#o.clock.now()
    return { ...state, iat: Math.max(now, state.iat + 1), revoked: revoked.filter((r) => r.until >= now) }
  }

  #record(state: GroupState, key: SealingKey): AddressRecord {
    const { relays, ttl, iat, rotationKey } = state
    const revoked = state.revoked.map((r) => r.address)
    const group = this.#o.keys.signing
    return signGroupRecord({ group, sealingKey: key.publicKey, relays, revoked, ttl, iat, rotationKey })
  }

  /** The admin's audit line of a step: add, remove or rotate, the generation after it, the member it names. */
  #audit(action: 'add' | 'remove' | 'rotate', generation: number, member: string | null): void {
    const detail = { subject: `group:${this.group}`, action, generation, member }
    this.#o.edge.audit.record({ event: 'rotate', decision: 'accept', from: this.group, detail })
  }
}
