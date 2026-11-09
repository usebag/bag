// The agent's own records at its organisation's relays (the agent contract's records): after the grant, and again before
// they lapse, the agent publishes its address record (its signing key, its sealing key, the org's relays) and its
// accept-from record (the agent's accept list: the org's root, and each partner's in scope, accept-list.ts) at each relay the grant names (org.relays). Without them no
// peer can resolve the agent's address (send: resolve-failed) and no relay takes mail for it. Both are signed by A, the
// agent key, here on the agent's machine; the instance never sees them.
//
// When: due when no copy is kept, when the org's relays or the accept list changed, or at half the address record's ttl (the relays drop
// a record at its ttl). The kept copy, <home>/enterprise/records.json (0600), holds the iat, the relays and the roots.
// A relay that refuses or does not answer is one line and does not fail the tick: the next tick tries again.
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AddressRecord,
  MAX_ADDRESS_TTL,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import type { EdgeKeys, RelayClient } from '@usebag/edge'
import { acceptRoots } from './accept-list.ts'
import { pairedPeers } from './pairings.ts'
import { type Session, writeJson } from './session.ts'

/** The address record's ttl: the most the relays take, a day. */
export const ADDRESS_TTL = MAX_ADDRESS_TTL
/** The accept-from record's retention, the relay TTL (7 days), and its largest envelope: bag's own defaults. */
export const ACCEPT_TTL = 604_800
export const ACCEPT_MAX_BYTES = 65_536

/** The kept copy: when the records were last published and where. */
export interface RecordsCopy {
  readonly v: 1
  readonly agent_address: string
  readonly iat: number
  readonly relays: string[]
  /** The accept-from record's roots; a copy from before the accept list names none, and reads as [org.root]. */
  readonly roots?: string[]
}

export type Publisher = Pick<RelayClient, 'publish'>

export const recordsPath = (home: string): string => join(home, 'enterprise', 'records.json')

export function readRecordsCopy(home: string): RecordsCopy | null {
  const path = recordsPath(home)
  if (!existsSync(path)) return null
  try {
    const c = JSON.parse(readFileSync(path, 'utf8')) as RecordsCopy
    const ok =
      c.v === 1 &&
      typeof c.agent_address === 'string' &&
      Number.isSafeInteger(c.iat) &&
      Array.isArray(c.relays) &&
      c.relays.every((r) => typeof r === 'string') &&
      (c.roots === undefined || (Array.isArray(c.roots) && c.roots.every((r) => typeof r === 'string')))
    return ok ? c : null
  } catch {
    return null
  }
}

/** Through the session files' one writer (session.ts writeJson): a new 0600 file of a random name, wx, renamed. */
function writeRecordsCopy(home: string, c: RecordsCopy): void {
  writeJson(recordsPath(home), c)
}

/** True when the agent's records are to be published: a live session with relays, and no fresh copy for them and its roots. */
/** The accept-from record's roots: the organisation's accept list, then the peers this profile paired (pairings.ts). */
export const signedRoots = (s: Session, peers: readonly string[] = []): string[] => [
  ...new Set([...acceptRoots(s), ...peers]),
]

export function recordsDue(
  s: Session,
  copy: RecordsCopy | null,
  now: number,
  peers: readonly string[] = [],
): boolean {
  if (s.state !== 'live' || s.org.relays.length === 0) return false
  if (copy === null || copy.agent_address !== s.agent_address) return true
  const equal = (a: readonly string[], b: readonly string[]) =>
    a.length === b.length && a.every((r, i) => r === b[i])
  const same = equal(copy.relays, s.org.relays) && equal(copy.roots ?? [s.org.root], signedRoots(s, peers))
  return !same || now >= copy.iat + Math.floor(ADDRESS_TTL / 2)
}

/** The two records, signed by A: the address record over A's sealing key and the org's relays, the accept-from. */
export function agentRecords(
  keys: EdgeKeys,
  s: Session,
  iat: number,
  peers: readonly string[] = [],
): { address: AddressRecord; accept: AcceptFromRecord } {
  const self = keys.signing.address
  const address = signRecord(keys.signing, {
    kind: 'address',
    key: self,
    sealing_key: toHex(keys.sealing.publicKey),
    relays: [...s.org.relays],
    rotation_key: null,
    revoked: [],
    ttl: ADDRESS_TTL,
    iat,
    rotated_from: null,
  })
  const accept = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: self,
    roots: signedRoots(s, peers),
    max_bytes: ACCEPT_MAX_BYTES,
    ttl: ACCEPT_TTL,
    iat,
  })
  return { address, accept }
}

/** One line per record and relay: `records <kind> <relay> published`, or `failed <code>`. */
export interface PublishOutcome {
  readonly kind: 'address' | 'accept-from'
  readonly relay: string
  readonly ok: boolean
  readonly code: string | null
}

const codeOf = (e: unknown): string => {
  const x = e as { code?: unknown; status?: unknown; message?: unknown }
  if (typeof x?.code === 'string') return x.code
  if (typeof x?.status === 'number') return x.status === 0 ? 'unreachable' : `http-${x.status}`
  return 'error'
}

/**
 * Publishes both records at each of the org's relays when they are due; the copy is written once every relay took the
 * address record, so a relay that failed is tried again at the next tick. Returns what it did (empty when not due).
 */
export async function publishAgentRecords(input: {
  readonly home: string
  readonly session: Session
  readonly keys: EdgeKeys
  readonly publisher: Publisher
  readonly now: number
}): Promise<PublishOutcome[]> {
  const { home, session: s, keys, publisher, now } = input
  const copy = readRecordsCopy(home)
  const peers = pairedPeers(home)
  if (!recordsDue(s, copy, now, peers)) return []
  if (keys.signing.address !== s.agent_address) return []
  const iat = Math.max(now, (copy?.iat ?? 0) + 1)
  const { address, accept } = agentRecords(keys, s, iat, peers)
  const out: PublishOutcome[] = []
  for (const relay of s.org.relays) {
    for (const r of [address, accept]) {
      try {
        await publisher.publish(relay, serializeRecord(r))
        out.push({ kind: r.kind, relay, ok: true, code: null })
      } catch (e) {
        out.push({ kind: r.kind, relay, ok: false, code: codeOf(e) })
      }
    }
  }
  if (out.every((o) => o.ok)) {
    const roots = signedRoots(s, peers)
    writeRecordsCopy(home, { v: 1, agent_address: s.agent_address, iat, relays: [...s.org.relays], roots })
  }
  return out
}

export const outcomeLine = (o: PublishOutcome): string =>
  `records ${o.kind} ${o.relay} ${o.ok ? 'published' : `failed ${o.code}`}`
