import { createHmac, timingSafeEqual } from 'node:crypto'
import * as core from '@usebag/core'
import { generateEdgeKeys } from './edge.ts'
import { guardCheck, type RelayGuard } from './net.ts'
import { heldSomewhere, type Lagging, offerRecord } from './offer.ts'
import {
  type Code,
  claimRendezvous,
  codeSecret,
  formatCode,
  newWords,
  openRendezvous,
  parseCode,
  WORDS,
} from './pair-code.ts'
import { type Clock, type EdgeKeys, type Frame, type RelayClient, RelayError, type Rng } from './ports.ts'
import { coreRng } from './sender.ts'
import { countTelemetry, telemetryCode } from './telemetry.ts'

// The `peer` grant, for a client that asks a person: the CLI on a terminal, or the MCP
// server's pair tools through a dialog the model cannot answer: a
// one-time invitation identity I, one request under the invite's secret S, six digits compared, then each side admits
// the other in its accept-from. No edge store is opened; the client writes its files through hooks.
// Under forward secrecy a side passes its current key record: its
// request carries it, the code and the mac bind its sealing key, the inviter checks it and shares it with the address
// record, and the side's own address record is kept with no sealing key: one is never written back into it. A side
// with no key record keeps the address record's sealing key, as before. I, the invitation, keeps its own.
// The word code is the path whenever the rendezvous relay offers
// pair/open: the inviter opens a rendezvous for I there, signed by I, and gives out the code, whose words make S; else
// it gives out the invite string. I and its mailbox live at the rendezvous, where the acceptor's request goes.

type Address = core.AddressRecord
type Accept = core.AcceptFromRecord
type Relays = readonly string[]
export const PEER_REQUEST_TYPE = 'peer.request.v1'
export const INVITE_PREFIX = 'ac-peer1:'
export const MAX_INVITE_TTL = 600
/** The bad-code requests a code's invitation takes; the last ends it (the guess bound, whatever relays carry them). */
export const MAX_CODE_MISSES = 20
/** The tries the inviter's person has to type the peer's check digits. */
export const MAX_DIGIT_TRIES = 3

/** Whether a person's typed digits are `code`, spaces and hyphens ignored, in constant time; any other length is no. */
export function digitsMatch(typed: string, code: string): boolean {
  const [a, b] = [typed, code].map((s) => Buffer.from(s.replace(/[\s-]/g, ''))) as [Buffer, Buffer]
  return a.length === b.length && timingSafeEqual(a, b)
}
/** I's accept-from max_bytes: a request is one sealed address record (8,192). */
const INVITE_BYTES = 8192
/** The refusals a person is told of: a request that failed only its mac, and not-for. Any other is dropped unsaid. */
const TOLD = new Set(['bad-code', 'bad-mac', 'not-for'])

/**
 * A refusal and its code: bad-invite, bad-code, invite-expired, bad-request, bad-mac, not-for, leaked, declined,
 * no-answer.
 */
function refusal(code: string, detail: string): Error & { readonly code: string } {
  return Object.assign(new Error(`${code}: ${detail}`), { code })
}

/** What an invite string binds: the inviter's address, the invitation I, the relay serving I, and S in hex. */
export interface Invite {
  readonly inviter: string
  readonly i: string
  readonly relay: string
  readonly secret: string
}

/** The relay client, the clock, the random source, how often a wait polls (ms), and the guard for rendezvous relays. */
export interface PairingPorts {
  readonly client: RelayClient
  readonly clock: Clock
  readonly rng: Rng
  readonly pollMs: number
  readonly guard?: RelayGuard
  /** What the identity continues from, given what its relay holds: continueFrom over its home, which may refuse. */
  readonly continueFrom?: (found: Address | null) => Address | null
  /** Keeps a record a pairing published as that copy: keepAddressCopy. */
  readonly keepAddress?: (record: Address) => void
  /** Told each relay that did not take this identity's record; the keep-alive carries the rest (Appendix B 110). */
  readonly lagging?: (lag: Lagging) => void
}

/**
 * A checked request: the requester, its address record, its key record (null before forward secrecy), and the code
 * compared.
 */
export type PeerRequest = {
  readonly from: string
  readonly record: Address
  readonly key: core.KeyRecord | null
  readonly code: string
}

/** The invite string: the prefix and base64url of canonical(["ac/peer-invite/1", inviter, I, relay, S]). */
export function inviteText(v: Invite): string {
  const list = core.canonical(['ac/peer-invite/1', v.inviter, v.i, v.relay, v.secret])
  return `${INVITE_PREFIX}${Buffer.from(list).toString('base64url')}`
}

/** The fields of an invite string; bad-invite for anything else. */
export function readInvite(text: string): Invite {
  try {
    const raw = Buffer.from(text.slice(INVITE_PREFIX.length), 'base64url').toString()
    const [tag, inviter, i, relay, secret] = JSON.parse(raw)
    const ok = text.startsWith(INVITE_PREFIX) && tag === 'ac/peer-invite/1' && core.isAddress(inviter)
    if (ok && core.isAddress(i) && /^https?:\/\/\S+$/.test(relay) && /^[0-9a-f]{32}$/.test(secret)) {
      return { inviter, i, relay, secret }
    }
  } catch {}
  throw refusal('bad-invite', 'not a string that peer invite printed')
}

/**
 * What a person pasted, read: an invite string (spaces and line breaks in it dropped), or a code whose nameplate is
 * claimed at the `rendezvous` relay (or the code's @host) and whose words make S. bad-code for neither, or for a word
 * not in the list; invite-expired when no invitation is open under it.
 */
export async function inviteOf(p: PairingPorts, rendezvous: string, text: string): Promise<Invite> {
  const flat = text.replace(/\s/g, '')
  if (flat.startsWith(INVITE_PREFIX)) return readInvite(flat)
  const c = parseCode(text)
  if (c === null || !c.words.every((w) => WORDS.includes(w))) {
    throw refusal('bad-code', 'neither a code nor an invite string')
  }
  const at = c.at ?? rendezvous
  const r = await claimRendezvous(p.client, at, c.nameplate, p.guard)
  const relay = r?.relays[0] ?? ''
  if (
    r === null ||
    !core.isAddress(r.inviter) ||
    !core.isAddress(r.invitation) ||
    !/^https?:\/\/\S+$/.test(relay)
  ) {
    throw refusal('invite-expired', `${at} holds no open invitation ${c.nameplate}`)
  }
  return { inviter: r.inviter, i: r.invitation, relay, secret: codeSecret(c, r.invitation) }
}

/**
 * not-for for an invitation from any inviter but `only`, the address the acceptor holds out of band (spec/SPEC.md
 * §8.10): before the digits are shown and before anything is sent. A claim does not consume the invitation.
 */
export function refuseOtherInviter(v: Invite, only: string | undefined): void {
  if (only !== undefined && v.inviter !== only) {
    throw refusal('not-for', `that invitation is from ${v.inviter}, not ${only}: nothing was sent`)
  }
}

/** The six digits: SHA-256 of [tag, inviter, I, requester, its sealing key, S], 4 bytes big-endian mod 10^6. */
export function pairingCode(v: Invite, requester: string, sealing: string): string {
  const d = core.sha256(core.canonical(['ac/peer-code/1', v.inviter, v.i, requester, sealing, v.secret]))
  const n = String(Buffer.from(d).readUInt32BE(0) % 1_000_000).padStart(6, '0')
  return `${n.slice(0, 3)} ${n.slice(3)}`
}

/** The request's mac: HMAC-SHA256 under S of [tag, inviter, I, requester, its sealing key, exp], in hex. */
export function macOf(v: Invite, requester: string, sealing: string, exp: number): string {
  const text = core.canonical(['ac/peer-request/1', v.inviter, v.i, requester, sealing, exp])
  return createHmac('sha256', core.fromHex(v.secret)).update(text).digest('hex')
}

/**
 * The newest record of `kind` that `owner` signed at the relays that answer, its form and signature checked; null for
 * none. A relay's failure counts only when none answers, so one down relay of two neither ends a read nor holds a wait
 * up. `strict`, for a wait, also refuses a record of another kind or owner, which a plain read passes over.
 */
async function newest(client: RelayClient, at: Relays, owner: string, kind: core.RecordKind, strict = false) {
  let best: core.AcRecord | null = null
  let answered = false
  let silent: RelayError | null = null
  for (const url of at) {
    let bytes: Uint8Array | null
    try {
      bytes = await client.fetchRecord(url, owner, kind)
      answered = true
    } catch (e) {
      if (!(e instanceof RelayError)) throw e
      silent ??= e
      continue
    }
    const r = bytes === null ? null : core.parseRecord(bytes)
    if (strict && r !== null && (r.kind !== kind || core.recordSigner(r) !== owner)) {
      throw new core.AcError('bad-record', `${url} answered for ${owner} with what is not its ${kind} record`)
    }
    if (r?.kind === kind && core.recordSigner(r) === owner && r.iat > (best?.iat ?? -1)) {
      best = core.verifyRecord(r, r.iat)
    }
  }
  if (!answered && silent !== null) throw silent
  return best
}

/**
 * Offers a record to each relay, and refuses only when none took it. A relay that holds a newer one (stale-record)
 * keeps it. Unless `theirs`, a peer's record, a relay that did not take it goes to the `lagging` port.
 */
async function share(p: PairingPorts, at: Relays, r: core.AcRecord, theirs = false): Promise<void> {
  const publish = (url: string) => p.client.publish(url, core.serializeRecord(r))
  const offered = heldSomewhere(await offerRecord(r, at, publish, { staleHolds: true }))
  if (!theirs) for (const lag of offered.lagging) p.lagging?.(lag)
}

/** An address record of `k` naming `sealing` (or none), with `held`'s relays, rotation key and revoked list if any. */
function addressOf(
  k: EdgeKeys,
  sealing: string | null,
  relays: string[],
  ttl: number,
  iat: number,
  held: Address | null,
): Address {
  return core.signRecord(k.signing, {
    kind: 'address',
    key: k.signing.address,
    sealing_key: sealing,
    relays: held?.relays ?? relays,
    rotation_key: held?.rotation_key ?? null,
    revoked: held?.revoked ?? [],
    ttl,
    iat,
    rotated_from: null,
  })
}

/**
 * The identity's newest address record at its relay, or, when that relay gives no answer, at the relays the home's
 * copy lists: one relay of those may be down. Throws the relay's failure when there is no copy to go on.
 */
async function ownFound(p: PairingPorts, relay: string, me: string): Promise<Address | null> {
  try {
    return (await newest(p.client, [relay], me, 'address')) as Address | null
  } catch (e) {
    const copy = e instanceof RelayError ? (p.continueFrom?.(null) ?? null) : null
    if (copy === null) throw e
    return (await newest(p.client, copy.relays, me, 'address')) as Address | null
  }
}

/**
 * The identity's current address record, signed (a day) and offered to its relays when none is live or it names
 * another sealing key: with its own sealing key before forward secrecy, and with none under forward secrecy
 * (`fs`) or when the held record names none, so a sealing key is never written back into a record without
 * one.
 */
async function ownAddress(p: PairingPorts, relay: string, k: EdgeKeys, fs: boolean): Promise<Address> {
  const found = await ownFound(p, relay, k.signing.address)
  const held = p.continueFrom === undefined ? found : p.continueFrom(found)
  const now = p.clock.now()
  const sealing = fs || held?.sealing_key === null ? null : core.toHex(k.sealing.publicKey)
  if (held !== null && held === found && held.sealing_key === sealing && now <= held.iat + held.ttl)
    return held
  const r = addressOf(k, sealing, [relay], core.MAX_ADDRESS_TTL, Math.max(now, (held?.iat ?? -1) + 1), held)
  await share(p, [...new Set([relay, ...r.relays])], r)
  p.keepAddress?.(r)
  return r
}

/** Re-signs the newest accept-from: `peer` added (a list: those roots, the rollback). Returns the old roots. */
async function admit(p: PairingPorts, at: Relays, k: EdgeKeys, peer: string | Relays): Promise<Relays> {
  const owner = k.signing.address
  const old = (await newest(p.client, at, owner, 'accept-from')) as Accept | null
  const was = old?.roots ?? []
  const roots =
    typeof peer !== 'string' ? peer : was.includes('*') || was.includes(peer) ? was : [...was, peer]
  const base = { max_bytes: core.MAX_ENVELOPE_BYTES, ttl: core.DEFAULT_TTL, ...old }
  const iat = Math.max(p.clock.now(), (old?.iat ?? -1) + 1)
  const r = core.signRecord(k.signing, { ...base, kind: 'accept-from', owner, roots, iat })
  // Not share: stale-record here is a record this one would have replaced, a change it must not pass over.
  const publish = (url: string) => p.client.publish(url, core.serializeRecord(r))
  for (const lag of heldSomewhere(await offerRecord(r, at, publish)).lagging) p.lagging?.(lag)
  return old?.roots ?? [owner]
}

/**
 * The ms a wait holds off after a read that brought no record: a relay's Retry-After within the invitation's end, else
 * until its next poll. Only a delivered record that fails verification ends a wait, and that is no RelayError:
 * an HTTP answer or none is no news, whatever its status, so a failed read
 * costs no pairing and an acceptor never ends early or with a transport code. A wait does not classify them.
 */
function notYet(p: PairingPorts, e: unknown, end: number): number {
  if (!(e instanceof RelayError)) throw e
  return Math.max(p.pollMs, Math.min(e.retryAfter ?? 0, Math.max(0, end - p.clock.now())) * 1000)
}

/**
 * Polls until `owner`'s accept-from, newer than `after`, admits `peer` (true) or the clock reaches `end` (false). The
 * record seen at `after`, served again, is a wait; one older than it is a replay, and fatal.
 */
async function admitted(
  p: PairingPorts,
  end: number,
  at: Relays,
  owner: string,
  peer: string,
  after: number,
) {
  for (;;) {
    let wait = p.pollMs
    const r = (await newest(p.client, at, owner, 'accept-from', true).catch((e: unknown) => {
      wait = notYet(p, e, end)
      return null
    })) as Accept | null
    if (r !== null && r.iat < after)
      throw new core.AcError('stale-record', `${owner}'s accept-from went back`)
    if (r !== null && r.iat > after && (r.roots.includes(peer) || r.roots.includes('*'))) return true
    if (p.clock.now() >= end) return false
    await new Promise((resolve) => setTimeout(resolve, wait))
  }
}

/** The sender of a frame, or '-' when it is not an envelope. */
function senderOf(f: Frame): string {
  try {
    return core.parseEnvelope(f.envelopeBytes).from
  } catch {
    return '-'
  }
}

/**
 * I's accept-from: ["*"], which lapses at I's end and is never closed before it. Record reads are public, so an early
 * close would tell anyone holding the code that the inviter ended, however silent the acceptor's own wait.
 * A late request goes unconsumed, and its sender's wait ends in no-answer.
 */
function invitationAccept(i: EdgeKeys, ttl: number, iat: number): Accept {
  const owner = i.signing.address
  const roots = ['*']
  return core.signRecord(i.signing, { kind: 'accept-from', owner, roots, max_bytes: INVITE_BYTES, ttl, iat })
}

/**
 * The inviter's options (--relay, the rendezvous relay, by default --relay, its keys, its current key record,
 * I's ttl, 1 to 600 s, --for) and its client's steps (ask: true, yes). `opened` gets the code, or the invite string
 * (INVITE_PREFIX) when the rendezvous relay offers no pair call.
 */
export interface Inviter {
  readonly relay: string
  readonly rendezvous?: string
  readonly keys: EdgeKeys
  readonly key?: core.KeyRecord
  readonly ttl: number
  readonly only?: string
  readonly opened: (text: string, exp: number) => void
  readonly refused: (from: string, code: string) => void
  readonly ask: (q: PeerRequest) => Promise<boolean>
  readonly leaked: (from: string) => void
  readonly write: (q: PeerRequest) => void
}

/**
 * The inviter's side: I opened, the first good request asked; on yes the requester admitted, its newer accept-from
 * awaited, then `write`; else the roots go back. Nothing a stranger sends ends an open invitation: a frame that fails
 * is dropped, and only a request whose sole failure is the mac under a code counts, the MAX_CODE_MISSES-th ending it. A
 * copy of a frame already checked is not counted again. leaked is a request that passes from another requester, so a
 * retry by the same requester, a new envelope, is none.
 */
async function inviting(p: PairingPorts, o: Inviter): Promise<PeerRequest> {
  const i = generateEdgeKeys(p.rng)
  const secret = core.toHex(p.rng.bytes(16))
  // The invitation lives at the rendezvous, the one relay a pairing requires (spec/SPEC.md Appendix B 110): the
  // inviter's first relay may be down.
  const at = o.rendezvous ?? o.relay
  const v = { inviter: o.keys.signing.address, i: i.signing.address, relay: at, secret }
  const iat = p.clock.now()
  const exp = iat + o.ttl
  const pub = (r: core.AcRecord) => p.client.publish(at, core.serializeRecord(r))
  const queue: Frame[] = []
  let failure: unknown = null
  let word: Code | null = null
  let misses = 0
  const checked = new Set<string>()
  /** False for bytes already checked: pairing acks nothing, so a resumed subscription delivers them again (§8.5). */
  const fresh = (f: Frame): boolean => {
    const id = core.toHex(core.sha256(f.envelopeBytes))
    if (checked.has(id)) return false
    checked.add(id)
    return true
  }
  const check = (f: Frame): PeerRequest => {
    const env = core.parseEnvelope(f.envelopeBytes)
    core.verifyOuter(env, p.clock.now())
    const c = core.openSealed(env, { address: v.i, key: i.sealing })
    const body = c.body as { record?: unknown; key?: unknown; mac?: unknown } | null
    const now = p.clock.now()
    const r = core.verifyRecord(core.parseRecord(String(body?.record)), now)
    // Its key record, when it sends one, is checked at now (signed by the requester, not past exp); its sealing key is
    // then the one the code and the mac bind, and the address record's is not used.
    const kr = body?.key === undefined ? null : core.verifyRecord(core.parseRecord(String(body.key)), now)
    const key = kr?.kind === 'key' && kr.key === env.from ? kr : null
    const ok =
      env.auth.length === 0 &&
      c.type === PEER_REQUEST_TYPE &&
      r.kind === 'address' &&
      r.key === env.from &&
      (kr === null || key !== null)
    const sealing = key === null ? (r as Address).sealing_key : key.sealing_key
    if (!ok || sealing === null) throw refusal('bad-request', `${env.from}: not a ${PEER_REQUEST_TYPE}`)
    const mac = Buffer.from(macOf(v, env.from, sealing, exp))
    const given = Buffer.from(String(body?.mac))
    if (given.length !== mac.length || !timingSafeEqual(given, mac)) {
      throw refusal(word === null ? 'bad-mac' : 'bad-code', env.from)
    }
    if (o.only !== undefined && env.from !== o.only) throw refusal('not-for', env.from)
    return { from: env.from, record: r, key, code: pairingCode(v, env.from, sealing) }
  }
  const tell = (f: Frame, e: unknown): string => {
    const code = (e as { code: string }).code
    if (TOLD.has(code)) o.refused(senderOf(f), code)
    return code
  }
  /** The frames behind `first`'s request, told: how many are requests that pass from another requester. */
  const extras = (first: string): number => {
    let second = 0
    for (const f of queue.splice(0).filter(fresh)) {
      try {
        if (check(f).from === first) continue
        o.leaked(senderOf(f))
        second++
      } catch (e) {
        tell(f, e)
      }
    }
    return second
  }
  let close = (): void => {}
  try {
    await pub(addressOf(i, core.toHex(i.sealing.publicKey), [at], o.ttl, iat, null))
    await pub(invitationAccept(i, o.ttl, iat))
    const mine = await ownAddress(p, o.relay, o.keys, o.key !== undefined)
    // Its records at the relay the acceptor reads them from, which its address record may not name, and at the relays
    // it lists; a relay that holds one already keeps it (share).
    const reached = [...new Set([at, ...mine.relays])]
    if (!mine.relays.includes(at)) await share(p, [at], mine)
    if (o.key !== undefined) await share(p, reached, o.key)
    const sub = p.client.subscribe(at, v.i, i.signing, [], null)
    close = () => sub.close()
    ;(async () => {
      for await (const f of sub) queue.push(f)
    })().catch((e: unknown) => {
      failure = e
    })
    const reach = { inviter: v.inviter, invitation: v.i, relays: [at], ttl: o.ttl }
    const sig = core.signPreimage(i.signing, ['ac/pair-open/1', v.inviter, v.i, [at], o.ttl])
    const nameplate = await openRendezvous(p.client, at, { ...reach, sig }, p.guard)
    word = nameplate === null ? null : { nameplate, words: newWords(p.rng) }
    if (word !== null) v.secret = codeSecret(word, v.i)
    o.opened(word === null ? inviteText(v) : formatCode(word), exp)
    let q: PeerRequest | null = null
    while (q === null) {
      while (queue.length === 0 && failure === null && p.clock.now() < exp) {
        await new Promise((resolve) => setTimeout(resolve, p.pollMs))
      }
      if (failure !== null) throw failure
      const f = queue.shift()
      if (f === undefined) throw refusal('invite-expired', 'no request came before the invitation ended')
      if (!fresh(f)) continue
      try {
        q = check(f)
      } catch (e) {
        if (tell(f, e) === 'bad-code' && ++misses === MAX_CODE_MISSES) throw e
      }
    }
    const yes = await o.ask(q)
    if (extras(q.from) > 0) throw refusal('leaked', 'a second request reached this invitation')
    if (!yes) throw refusal('declined', 'nothing was written')
    await share(p, mine.relays, q.record, true)
    if (q.key !== null) await share(p, mine.relays, q.key, true)
    const seen = (await newest(p.client, q.record.relays, q.from, 'accept-from'))?.iat ?? -1
    const before = await admit(p, reached, o.keys, q.from)
    const answer = admitted(p, exp, q.record.relays, q.from, v.inviter, seen)
    if (!(await answer.catch(() => false))) {
      await admit(p, reached, o.keys, before)
      throw refusal('no-answer', `${q.from} did not admit this identity before the invitation ended`)
    }
    o.write(q)
    extras(q.from)
    return q
  } finally {
    close()
  }
}

/**
 * The acceptor's current key record, and its client's steps: ask (resolving on yes, throwing on no), told
 * the request went, write its files.
 */
export interface Acceptor {
  readonly key?: core.KeyRecord
  readonly ask: (code: string) => Promise<void>
  readonly sent: (exp: number) => void
  readonly write: () => void
}

/**
 * The acceptor's side: the inviter's relay guarded (resolve-failed before any request), I read, asked, the request
 * sent, the inviter's yes awaited, `write`, the inviter admitted.
 */
async function accepting(p: PairingPorts, k: EdgeKeys, relay: string, v: Invite, h: Acceptor) {
  await guardCheck(p.guard, v.relay)
  const me = k.signing.address
  const sealing = h.key?.sealing_key ?? core.toHex(k.sealing.publicKey)
  const i = (await newest(p.client, [v.relay], v.i, 'address')) as Address | null
  if (!i?.sealing_key || p.clock.now() > i.iat + i.ttl + core.DEFAULT_SKEW) {
    throw refusal('invite-expired', `${v.relay} serves no current invitation ${v.i}`)
  }
  const exp = i.iat + i.ttl
  await h.ask(pairingCode(v, me, sealing))
  const mine = await ownAddress(p, relay, k, h.key !== undefined)
  // Its key record at its own relays too, where its peers resolve it (the inviter shares it at the inviter's).
  if (h.key !== undefined) await share(p, [...new Set([relay, ...mine.relays])], h.key)
  const seen = (await newest(p.client, [v.relay], v.inviter, 'accept-from'))?.iat ?? -1
  const text = (r: core.AcRecord): string => Buffer.from(core.serializeRecord(r)).toString()
  const body = {
    record: text(mine),
    ...(h.key === undefined ? {} : { key: text(h.key) }),
    mac: macOf(v, me, sealing, exp),
  }
  const to = [{ address: v.i, sealingKey: core.fromHex(i.sealing_key) }]
  const rng = coreRng(p.rng)
  const thread = core.newThread(rng)
  const ts = p.clock.now()
  const env = core.buildEnvelope({ from: k.signing, to, type: PEER_REQUEST_TYPE, thread, body, ts, rng })
  await p.client.publish(v.relay, env.bytes)
  h.sent(exp)
  if (!(await admitted(p, exp, [v.relay], v.inviter, me, seen))) {
    throw refusal('no-answer', `${v.inviter} did not admit this identity before the invitation ended`)
  }
  // The inviter's records, shared at this side's relays: its address record, and its key record.
  for (const kind of ['address', 'key'] as const) {
    const theirs = await newest(p.client, [v.relay], v.inviter, kind)
    if (theirs !== null) await share(p, mine.relays, theirs, true)
  }
  h.write()
  await admit(p, mine.relays, k, v.inviter)
}

/** A pairing's outcome, counted for the machine's telemetry while it is on (`ok` or its code); the promise as is. */
async function counted<T>(run: Promise<T>): Promise<T> {
  try {
    const v = await run
    countTelemetry('pairing', ['ok'])
    return v
  } catch (e) {
    countTelemetry('pairing', [telemetryCode(e)])
    throw e
  }
}

/** The inviter's side (inviting, above), its outcome counted. */
export function invitePeer(p: PairingPorts, o: Inviter): Promise<PeerRequest> {
  return counted(inviting(p, o))
}

/** The acceptor's side (accepting, above), its outcome counted. */
export function acceptPeer(p: PairingPorts, k: EdgeKeys, relay: string, v: Invite, h: Acceptor) {
  return counted(accepting(p, k, relay, v, h))
}
