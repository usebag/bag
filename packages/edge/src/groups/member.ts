import {
  AcError,
  DEFAULT_SKEW,
  GROUP_KEY_TYPE,
  type GroupKeyBody,
  type Hop,
  isAcError,
  openGroupKey,
  type RecipientKey,
  SealingKey,
} from '@usebag/core'
import type { Audit } from '../audit.ts'
import { errno } from '../custody/files.ts'
import type { GroupKeyStore, Kept } from '../custody/groups.ts'
import type { Clock, EdgeKeys, InboundMessage } from '../ports.ts'

// A member's side of a group: a `group-key.v1` message verified and kept, and what
// its edge at the group's mailbox runs with: its own signing key, the hop from the newest generation it holds, and an
// opener that tries the current and the previous generation it holds.

/** How many generations an opener tries, newest first: the current and the previous. */
export const GENERATIONS_TRIED = 2

/**
 * The opener of a group's mailbox: a SealingKey, because the Receiver opens with the core's openSealed, which
 * takes that class. Its open tries, in order, each key that `keys` gives at the time of the call,
 * and fails as the first of them failed; its publicKey is the generation that was current when it was made.
 */
export class GroupOpener extends SealingKey {
  readonly #keys: () => readonly SealingKey[]

  constructor(keys: () => readonly SealingKey[]) {
    const current = keys()[0]
    if (current === undefined) throw errno('ENOENT', 'groups: no generation of the group is held')
    super(current.exportSeed())
    this.#keys = keys
  }

  override open(enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
    const failures: unknown[] = []
    for (const key of this.#keys()) {
      try {
        return key.open(enc, info, aad, ct)
      } catch (e) {
        failures.push(e)
      }
    }
    throw failures[0] ?? new AcError('open-failed', 'no generation of the group is held')
  }
}

/**
 * The opener of the newest `count` generations the store holds, each key kept in memory. It uses the generation key
 * the member kept at rest (store.heldKey), which outlives the member's short-lived epoch sealing key; only for a
 * generation with no key kept (a body put without an accept, or a store with no keys root) does it fall back to
 * verifying the body once and opening its wrap against `holder`.
 */
export function groupOpener(
  store: GroupKeyStore,
  group: string,
  holder: RecipientKey,
  clock: Clock,
  count: number = GENERATIONS_TRIED,
): GroupOpener {
  const opened = new Map<number, SealingKey>()
  return new GroupOpener(() =>
    store
      .generations(group)
      .slice(0, count)
      .map((n) => {
        const have = opened.get(n)
        if (have !== undefined) return have
        const key = store.heldKey(group, n) ?? openGroupKey(store.body(group, n), holder, clock.now()).key
        opened.set(n, key)
        return key
      }),
  )
}

/**
 * A member's keys at the group's mailbox: its own signing key, and the group's opener, which opens with the generation
 * keys the member kept at rest and falls back to its own sealing key only for a generation it has not kept.
 */
export function memberKeys(store: GroupKeyStore, group: string, keys: EdgeKeys, clock: Clock): EdgeKeys {
  const holder = { address: keys.signing.address, key: keys.sealing }
  return { signing: keys.signing, sealing: groupOpener(store, group, holder, clock) }
}

/** The membership hop of the newest generation held: the chain a member subscribes and posts with. */
export function membershipHop(store: GroupKeyStore, group: string): Hop {
  const newest = store.generations(group)[0]
  const hop = newest === undefined ? null : store.body(group, newest).hop
  if (hop === null) throw errno('ENOENT', `groups: no membership hop of ${group} is held`)
  return hop
}

/** What acceptGroupKey takes: the holder's own keys, its store, its clock, its audit log and the skew. */
export interface AcceptOptions {
  readonly keys: EdgeKeys
  readonly store: GroupKeyStore
  readonly clock: Clock
  readonly audit: Audit
  readonly skew?: number
}

/**
 * Accepts a `group-key.v1` message for its holder: type-not-accepted for another type, then openGroupKey's
 * codes, then the store's (bad-key for another key at a held generation). It keeps the body and, while the delivering
 * sealing key is still live, the opened generation key at rest under the member's keys root (store.putKey), so the
 * member opens the generation after its short-lived epoch sealing key is deleted (forward secrecy); a store with
 * no keys root keeps only the body. It writes one audit line, `rotate accept` naming the group, the generation, its
 * public key, the hop's exp and how the body was kept, or `rotate reject` with the code; never key material. A local
 * fault (the file system) propagates with no line.
 */
export function acceptGroupKey(
  message: InboundMessage,
  o: AcceptOptions,
): { readonly body: GroupKeyBody; readonly kept: Kept } {
  const line = { event: 'rotate', id: message.id, from: message.from, root: message.root } as const
  try {
    if (message.type !== GROUP_KEY_TYPE) {
      throw new AcError('type-not-accepted', `a group key comes as ${GROUP_KEY_TYPE}`)
    }
    const holder = { address: o.keys.signing.address, key: o.keys.sealing }
    const { body, key } = openGroupKey(message.body, holder, o.clock.now(), o.skew ?? DEFAULT_SKEW)
    const kept = o.store.put(body)
    o.store.putKey(body.group, body.generation, key)
    const { group, generation, sealing_key, hop } = body
    o.audit.record({
      ...line,
      decision: 'accept',
      detail: { subject: `group:${group}`, generation, sealing_key, hop_exp: hop?.exp ?? null, kept },
    })
    return { body, kept }
  } catch (e) {
    if (isAcError(e)) o.audit.record({ ...line, decision: 'reject', reason: e.code })
    throw e
  }
}
