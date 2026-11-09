import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isAddress } from '@usebag/core'
import { digitsMatch, MAX_DIGIT_TRIES, MAX_INVITE_TTL, type PeerRequest } from '@usebag/edge'
import type { Fetch } from './instance.ts'
import { enterpriseDir, type Session, writeJson } from './session.ts'

// Pairing one of the organisation's agents with someone outside it, started from the console (decision 38b): the
// client pulls GET <instance>/api/v1/agent/pairings with the session's bearer ({ pairings, etag }, 304 on the etag) and
// answers each by POST <instance>/api/v1/agent/pairings/<id> events. For a `pair` the client mints the OSS invitation
// on this machine (the edge's invitePeer, under --for when the outside address is known) and posts its code; when a
// request comes it posts `request`, then waits for the six digits the console's person typed as the outside party read
// them out (the console holds them in memory only), and checks them here, MAX_DIGIT_TRIES times. The person on the
// console is the one who confirms, as the person at the inviter's terminal does in `peer invite`. A link the console
// revokes (`unpair`), or one whose term ended, leaves the trust file and the accept-from (`unpaired`). The links this
// profile paired are kept in <profile>/enterprise/pairings.json (0600): the id, the peer, the name, when it ends.

export const PAIRINGS_PATH = '/api/v1/agent/pairings'
const [TIMEOUT_MS, POLL_MS, DAY] = [3_000, 3_000, 86_400]
const UUID = /^[0-9a-f-]{36}$/
/** The failed reason for the edge's refusal that ended an invitation: declined is the console's revoke or no digits. */
const END: Record<string, 'expired' | 'refused'> = {
  'invite-expired': 'expired',
  'no-answer': 'expired',
  declined: 'refused',
}

export interface PairingCommand {
  readonly id: string
  readonly action: 'pair' | 'unpair'
  readonly termDays: number | null
  readonly outsideAddress: string | null
  readonly name: string | null
  readonly expiresAt: number
  readonly spoken: string | null // the six numerals the console's person typed, once typed
}

/** A link this profile paired: its id at the instance, the peer, its petname, and when its term ends (Unix s). */
export interface PairedLink {
  readonly id: string
  readonly peer: string
  readonly name: string
  readonly paired_at: number
  readonly until: number | null
}

interface Kept {
  readonly v: 1
  readonly links: PairedLink[]
  readonly done: string[] // ids answered to the end (paired, failed), never run again
}

export type PairingEvent =
  | { readonly event: 'code_shown'; readonly code: string; readonly until: number }
  | { readonly event: 'request'; readonly from: string }
  | { readonly event: 'confirm_retry'; readonly triesLeft: number }
  | { readonly event: 'paired'; readonly peerAddress: string }
  | { readonly event: 'failed'; readonly reason: 'expired' | 'confirm_mismatch' | 'refused' | 'error' }
  | { readonly event: 'unpaired' }

/** What the machine does for a pairing: the OSS ceremony, the name book and trust write, the removal, a wait. */
export interface PairingPorts {
  /** Runs the edge's invitePeer with these steps (its relay and keys the caller's) and gives the peer's address. */
  readonly invite: (o: {
    /** The organisation's first relay, where the agent's records and mailbox are: the invitation opens there. */
    readonly relay?: string
    readonly ttl: number
    readonly only?: string
    readonly opened: (text: string, exp: number) => void
    readonly ask: (q: PeerRequest) => Promise<boolean>
  }) => Promise<string>
  /** Names the peer in the book and trusts its root, as `peer invite`'s write does. */
  readonly write: (peer: string, name: string) => void
  /** Takes the peer's root out of the trust file; the next records publish drops it from the accept-from. */
  readonly remove: (peer: string) => Promise<void>
  readonly now: () => number
  readonly sleep: (ms: number) => Promise<void>
}

export const pairingsPath = (profile: string): string => join(enterpriseDir(profile), 'pairings.json')

/** The kept links and answered ids of a profile; none when missing, a symbolic link or not this user's 0600 file. */
export function readPairings(profile: string): Kept {
  const none: Kept = { v: 1, links: [], done: [] }
  let fd: number
  try {
    fd = openSync(pairingsPath(profile), constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch {
    return none
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o077) !== 0) return none
    const doc = JSON.parse(readFileSync(fd, 'utf8')) as Partial<Kept>
    const ok = (l: PairedLink) => UUID.test(l?.id) && isAddress(l.peer) && typeof l.name === 'string'
    const links = Array.isArray(doc.links) ? doc.links.filter(ok) : []
    const done = Array.isArray(doc.done) ? doc.done.filter((d) => typeof d === 'string').slice(-500) : []
    return doc.v === 1 ? { v: 1, links, done } : none
  } catch {
    return none
  } finally {
    closeSync(fd)
  }
}

/** The peers this profile's links name: the accept-from keeps them beside the organisation's list (records.ts). */
export const pairedPeers = (profile: string): string[] => readPairings(profile).links.map((l) => l.peer)

const headers = (s: Session) =>
  new Headers({ accept: 'application/json', authorization: `Bearer ${s.access_token}` })

/** The commands the instance holds for this agent, or null when it does not answer them (a failure, an older one). */
export async function pairingCommands(s: Session, f: Fetch): Promise<PairingCommand[] | null> {
  try {
    const signal = AbortSignal.timeout(TIMEOUT_MS)
    const res = await f(`${s.instance}${PAIRINGS_PATH}`, {
      method: 'GET',
      headers: headers(s),
      redirect: 'error',
      signal,
    })
    if (res.status !== 200) return null
    const doc = JSON.parse(await res.text()) as { pairings?: unknown }
    return Array.isArray(doc.pairings) ? doc.pairings.filter(command) : null
  } catch {
    return null
  }
}

function command(x: unknown): x is PairingCommand {
  const c = x as Partial<Record<keyof PairingCommand, unknown>> | null
  return (
    typeof c?.id === 'string' &&
    UUID.test(c.id) &&
    (c.action === 'pair' || c.action === 'unpair') &&
    (c.termDays === null || c.termDays === undefined || Number.isSafeInteger(c.termDays)) &&
    (c.outsideAddress === null || c.outsideAddress === undefined || isAddress(c.outsideAddress)) &&
    (c.spoken === null || c.spoken === undefined || typeof c.spoken === 'string')
  )
}

/** One event for a pairing; true when the instance took it (204). */
export async function postEvent(s: Session, f: Fetch, id: string, e: PairingEvent): Promise<boolean> {
  const h = headers(s)
  h.set('content-type', 'application/json')
  try {
    const signal = AbortSignal.timeout(TIMEOUT_MS)
    const init = { method: 'POST', headers: h, body: JSON.stringify(e), redirect: 'error' as const, signal }
    return (await f(`${s.instance}${PAIRINGS_PATH}/${id}`, init)).status === 204
  } catch {
    return false
  }
}

/**
 * Runs one `pair` command to its end: the invitation minted and its code posted, the request posted, the digits the
 * console's person typed checked (a miss is confirm_retry; the last, failed confirm_mismatch), then the peer written and
 * kept with its term, and paired posted. A command the console revoked meanwhile ends the invitation unanswered; the
 * invitation's end with no request is failed expired.
 */
export async function runPairing(
  s: Session,
  f: Fetch,
  profile: string,
  c: PairingCommand,
  ports: PairingPorts,
): Promise<void> {
  const kept = readPairings(profile)
  writeJson(pairingsPath(profile), { ...kept, done: [...kept.done, c.id] })
  const name = c.name ?? `peer-${(c.outsideAddress ?? '').slice(8, 16) || c.id.slice(0, 8)}`
  const ttl = Math.max(1, Math.min(MAX_INVITE_TTL, c.expiresAt - ports.now()))
  let exp = ports.now() + ttl
  const ask = async (q: PeerRequest): Promise<boolean> => {
    await postEvent(s, f, c.id, { event: 'request', from: q.from })
    for (let left = MAX_DIGIT_TRIES - 1; left >= 0; left--) {
      const typed = await digitsOf(s, f, c.id, exp, ports)
      if (typed === null) return false
      if (digitsMatch(typed, q.code)) return true
      if (left > 0) await postEvent(s, f, c.id, { event: 'confirm_retry', triesLeft: left })
    }
    await postEvent(s, f, c.id, { event: 'failed', reason: 'confirm_mismatch' })
    throw Object.assign(new Error('the typed digits did not match; nothing was written'), {
      code: 'digits-mismatch',
    })
  }
  let peer: string
  try {
    peer = await ports.invite({
      ...(s.org.relays[0] === undefined ? {} : { relay: s.org.relays[0] }),
      ttl,
      ...(c.outsideAddress === null ? {} : { only: c.outsideAddress }),
      opened: (code, until) => {
        exp = until
        void postEvent(s, f, c.id, { event: 'code_shown', code: code.slice(0, 2048), until })
      },
      ask,
    })
  } catch (e) {
    const code = (e as { code?: unknown }).code
    if (code === 'digits-mismatch') return
    const reason = code === 'declined' && ports.now() >= exp ? 'expired' : (END[code as string] ?? 'error')
    await postEvent(s, f, c.id, { event: 'failed', reason })
    return
  }
  try {
    ports.write(peer, name)
  } catch {
    await postEvent(s, f, c.id, { event: 'failed', reason: 'error' })
    return
  }
  const now = ports.now()
  const until = c.termDays === null ? null : now + c.termDays * DAY
  const after = readPairings(profile)
  const link: PairedLink = { id: c.id, peer, name, paired_at: now, until }
  writeJson(pairingsPath(profile), { ...after, links: [...after.links.filter((l) => l.id !== c.id), link] })
  await postEvent(s, f, c.id, { event: 'paired', peerAddress: peer })
}

/** The digits the console's person typed for `id`, polled until they come; null when the command left or `exp` passed. */
async function digitsOf(s: Session, f: Fetch, id: string, exp: number, ports: PairingPorts) {
  while (ports.now() < exp) {
    const c = (await pairingCommands(s, f))?.find((x) => x.id === id)
    if (c === undefined || c.action !== 'pair') return null
    if (typeof c.spoken === 'string') return c.spoken
    await ports.sleep(POLL_MS)
  }
  return null
}

/**
 * Ends the links the console revoked (an `unpair` command naming a kept link) and those whose term passed: the peer
 * removed, the link dropped, unpaired posted. Returns the ids it ended.
 */
export async function endLinks(
  s: Session,
  f: Fetch,
  profile: string,
  commands: readonly PairingCommand[],
  ports: Pick<PairingPorts, 'remove' | 'now'>,
): Promise<string[]> {
  const revoked = new Set(commands.filter((c) => c.action === 'unpair').map((c) => c.id))
  const now = ports.now()
  const ended: string[] = []
  for (const l of readPairings(profile).links) {
    if (!revoked.has(l.id) && (l.until === null || l.until > now)) continue
    await ports.remove(l.peer)
    const kept = readPairings(profile)
    writeJson(pairingsPath(profile), { ...kept, links: kept.links.filter((k) => k.id !== l.id) })
    await postEvent(s, f, l.id, { event: 'unpaired' })
    ended.push(l.id)
  }
  return ended
}

/** The `pair` commands not yet run by this profile. */
export const newPairs = (profile: string, commands: readonly PairingCommand[]): PairingCommand[] => {
  const kept = readPairings(profile)
  const seen = new Set([...kept.done, ...kept.links.map((l) => l.id)])
  return commands.filter((c) => c.action === 'pair' && !seen.has(c.id))
}
