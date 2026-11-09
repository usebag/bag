import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { type Hop, isAcError, parseEnvelope, parseRecord, signHop, signPreimage } from '@usebag/core'
import {
  acquireLock,
  type Clock,
  createRelayClient,
  Edge,
  FsKeyStore,
  generateEdgeKeys,
  type RelayClient,
  type Rng,
  SqliteStore,
  type Subscription,
} from '@usebag/edge'
import { syncAcceptList } from './accept-list.ts'
import { type DiscoveryNet, discoverInstance } from './discovery.ts'
import { AGENT_PATHS, call, EnterpriseError, type Fetch } from './instance.ts'
import { bindNonce, bindPreimage, layerNonce, refreshPreimage, statePreimage } from './layer-auth.ts'
import { endLinks, pairingCommands } from './pairings.ts'
import {
  outcomeLine,
  type Publisher,
  type PublishOutcome,
  publishAgentRecords,
  recordsPath,
} from './records.ts'
import * as f from './session.ts'
import { removePairedRoot, type SourcedRoot, syncSourcedTrust, type TrustSync } from './trust-file.ts'

// The agent side of a bag enterprise session (the instance's agent contract): sign-in by the device flow or a console
// code with the binding, the refresher (one per home, under its lock) with the generation, the chain org root -> A ->
// session key, the organisation's trust roots with their provenance, and sign-out. bag's sign-in, sign-out and status
// commands call it; everything generic (keys, key files, the lock, the canonical form, signing, hops) is
// @usebag/core's and @usebag/edge's own.

const H = 3600
/** The client's half of the contract's AGENT_CLOCKS, in seconds. */
export const CLOCKS = {
  refreshUnder: 12 * H,
  localMax: 24 * H,
  localUnder: 12 * H,
  margin: 60,
  state: H,
} as const

/** The flow's ports: the home, the clock and rng, the network, a wait, stdout, and the console code. */
export interface EnterpriseDeps {
  readonly home: string
  readonly env: Readonly<Record<string, string | undefined>>
  readonly clock: Clock
  readonly rng: Rng
  readonly fetch: Fetch | undefined
  readonly net: DiscoveryNet
  readonly sleep: (ms: number) => Promise<void>
  readonly say: (line: string) => void
  /** The console sign-in code: BAG_ORG_CODE, else one line of stdin; never argv. */
  readonly readCode: () => Promise<string | null>
  /**
   * Where the agent's records go (records.ts): the org's relays; unset, bag's own relay client. A full RelayClient here
   * (a test's relay) also carries the probes of connect and status; a publisher alone leaves them to bag's own client.
   */
  readonly relays?: Publisher | RelayClient
  /** Told the records' outcomes when the sign-in's tick published them (connect prints the failures). */
  readonly onRecords?: (outcomes: readonly PublishOutcome[]) => void
  /** The organisation acted on (--org): unset, the only profile, else the most recently connected (selectOrg). */
  readonly org?: string
  /** A line for a person beside the output (the CLI's stderr): which profile a command chose among several. */
  readonly note?: (line: string) => void
}

export interface SignInOptions {
  readonly domain: string
  /** The instance's origin when the caller already holds it (connect's code): no discovery then. */
  readonly instance?: string
  readonly name?: string
  readonly label?: string
  readonly code: boolean
  readonly wait: boolean
  readonly version: string
}

type Doc = Record<string, unknown>
const isStr = (v: unknown): v is string => typeof v === 'string'
const isInt = (v: unknown): v is number => Number.isSafeInteger(v)
const iso = (s: number | null | undefined): string =>
  s === null || s === undefined ? 'none' : new Date(s * 1000).toISOString().replace('.000Z', 'Z')
/** A source a profile is granted by name: a peer link, or a partnership of its organisation with another. */
const linked = (src: string): boolean => src.startsWith('peer:') || src.startsWith('partner:')
/**
 * The trust sources a profile's sync claims: its org's, and the peer links and partnerships it was granted (`peers`).
 * A session from before profiles kept no list: it claims every one while it is the home's only profile.
 */
const owns = (d: EnterpriseDeps, s: f.Session, peers: readonly string[] = []) => {
  const all = s.trust_peers === undefined && f.profiles(d.home).length <= 1
  const mine = new Set([...(s.trust_peers ?? []), ...peers])
  return (src: string) => src === `org:${s.domain}` || (linked(src) && (all || mine.has(src)))
}
/** A profile's own home (session.ts profileHome). */
const dirOf = (d: EnterpriseDeps, domain: string): string => f.profileHome(d.home, domain)
const trustFail = (detail: string): EnterpriseError => new EnterpriseError('trust-invalid', detail)
const key = (d: EnterpriseDeps, name: string) => f.loadKey(d.home, name).signing
type Key = ReturnType<typeof key>
/** An agent's three keys: A, the sign-in key, the session key. */
const keysOf = (d: EnterpriseDeps, name: string) => f.keyNames(name).map((n) => key(d, n)) as [Key, Key, Key]
/** The label given at sign-in, carried from the options to the pending sign-in and on to the session. */
const labelOf = (o: { readonly label?: string | undefined }) =>
  o.label === undefined ? {} : { label: o.label }
/** The key name a sign-in makes when none is given: the domain with dots as dashes, at most 48 characters. */
export const defaultName = (domain: string): string => domain.replaceAll('.', '-').slice(0, 48)
/** A's key as a person compares it on the approval page: its first 32 hex characters in four groups of eight. */
export const fingerprint = (address: string): string => (address.slice(8, 40).match(/.{8}/g) ?? []).join(' ')

/** A's binding (bag-ent/bind/1) over the nonce derived from `secret`, the device code or the console code. */
function binding(d: EnterpriseDeps, p: f.Pending, secret: string) {
  const [agent, signin] = keysOf(d, p.name)
  const ts = d.clock.now()
  return {
    ts,
    sig: signPreimage(agent, bindPreimage(p.domain, agent.address, signin.address, bindNonce(secret), ts)),
  }
}

/**
 * What /agent/code and /agent/redeem are told: the domain, A and the sign-in key, the label, the version. A redeem names
 * a label only when the person gave --label: a connect code carries the label its agent is to hold, and the grant
 * answers the label the agent got; a label the person named is taken only when no live agent holds it (label_taken).
 */
function codeBody(d: EnterpriseDeps, o: SignInOptions, name: string, redeem = false) {
  const [agent, signin] = keysOf(d, name).map((k) => k.address)
  const label = redeem && o.label === undefined ? {} : { label: (o.label ?? name).slice(0, 100) }
  const keys = { agent_address: agent, signin_address: signin }
  return { client_id: 'bag-agent', domain: o.domain, ...keys, ...label, bag_version: o.version }
}

/** POST /agent/code (route a): the pending sign-in, written before anyone approves it. */
async function startCode(d: EnterpriseDeps, o: SignInOptions, at: string, name: string): Promise<f.Pending> {
  const r = await call<Doc>(d.fetch, at, AGENT_PATHS.code, codeBody(d, o, name))
  const nonce =
    r.bind_nonce === undefined || (isStr(r.device_code) && r.bind_nonce === bindNonce(r.device_code))
  if (!isStr(r.device_code) || !isInt(r.expires_in) || !nonce)
    throw new EnterpriseError('bad-answer', `${at} gave no device code, or a bind_nonce not derived from it`)
  const user_code = isStr(r.user_code) ? r.user_code : null
  const verification_uri = isStr(r.verification_uri) ? r.verification_uri : null
  const interval = Math.min(Math.max(Number(r.interval) || 5, 1), 60)
  const code = { device_code: r.device_code, expires_at: d.clock.now() + r.expires_in, interval }
  const p: f.Pending = {
    v: 1,
    domain: o.domain,
    instance: at,
    name,
    ...code,
    user_code,
    verification_uri,
    ...labelOf(o),
  }
  f.write(dirOf(d, o.domain), 'pending', p)
  return p
}

/** POST /agent/redeem (route b): the console code with the binding over its derived nonce, answered by the grant. */
async function redeem(d: EnterpriseDeps, o: SignInOptions, p: f.Pending): Promise<number> {
  const code = (await d.readCode())?.trim() ?? null
  // A plain console code, or a connect code (connect-code.ts): the whole string, at most 900 characters.
  const form = /^bagcode_[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{43})?$/
  if (code === null || code.length > 900 || !form.test(code))
    throw new EnterpriseError('usage', '--code reads a bagcode_ code from BAG_ORG_CODE or a line of stdin')
  const body = { ...codeBody(d, o, p.name, true), code, binding: binding(d, p, code) }
  return granted(d, p, await call<Doc>(d.fetch, p.instance, AGENT_PATHS.redeem, body))
}

/**
 * bag sign-in <domain>: finds the instance, makes A, the sign-in key and the session key (never over a key file), then
 * redeems a console code (--code), or asks for a device code, shows what to approve and polls with the binding until
 * the grant. A pending sign-in of the domain resumes with its keys; an expired one asks again with them. Exit 0 signed
 * in, 4 waiting (a person, or the organisation's signer).
 */
export async function signIn(d: EnterpriseDeps, o: SignInOptions): Promise<number> {
  f.secureHome(d.home)
  // Each organisation has its own profile: a session of another stays as it is, and nothing is revoked here.
  const x = dirOf(d, o.domain)
  const had = f.sessionAt(x)
  const lapsed = had !== null && had.state === 'lapsed'
  if (had !== null && had.state !== 'ended' && !lapsed) return report(d, had, null)
  if (had !== null && !lapsed)
    throw new EnterpriseError(
      'signed-in',
      `an ended session of ${had.domain}: bag sign-out --org ${o.domain}`,
    )
  // An expired pending code: written before any call, so a sign-in that fails resumes with its keys. A lapse is final
  // for its session: signing in again with the same keys is the way back (a new approval revives the address in place).
  const none = { device_code: '', user_code: null, verification_uri: null, interval: 5, expires_at: 0 }
  const again = lapsed
    ? { v: 1 as const, domain: o.domain, instance: had.instance, name: had.name, ...none, ...labelOf(had) }
    : null
  let p = f.pendingAt(x) ?? again
  if (p !== null && p.domain !== o.domain)
    throw new EnterpriseError('pending', `a sign-in to ${p.domain} is waiting: bag sign-out drops it`)
  if (p !== null && o.instance !== undefined && p.instance !== o.instance)
    throw new EnterpriseError('pending', `a sign-in to ${p.instance} is waiting: bag sign-out drops it`)
  if (p === null) {
    const instance = o.instance ?? (await discoverInstance(o.domain, d.env, d.net))
    const name = o.name ?? defaultName(o.domain)
    const held = f.keyNames(name).find((n) => existsSync(f.keyFile(d.home, n)))
    if (held !== undefined)
      throw new EnterpriseError('EEXIST', `the key file ${held} exists: name another with --as`)
    for (const n of f.keyNames(name)) new FsKeyStore(join(d.home, 'keys')).create(n, generateEdgeKeys(d.rng))
    p = { v: 1, domain: o.domain, instance, name, ...none, ...labelOf(o) }
    f.write(x, 'pending', p)
  }
  if (o.code) return redeem(d, o, p)
  if (p.expires_at <= d.clock.now()) p = await startCode(d, o, p.instance, p.name)
  if (p.user_code !== null && p.verification_uri !== null) {
    d.say(`open ${p.verification_uri} and enter the code ${p.user_code}`)
    d.say(`fingerprint ${fingerprint(key(d, p.name).address)} (the agent's key, as that page shows it)`)
    d.say('approve only a code you started yourself')
  }
  return poll(d, p, o.wait)
}

/** Polls /agent/token every interval until the grant, with the binding over the device code's nonce on every poll. */
async function poll(d: EnterpriseDeps, p: f.Pending, wait: boolean): Promise<number> {
  let interval = p.interval
  const grant = { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'bag-agent' }
  for (;;) {
    if (d.clock.now() >= p.expires_at) {
      f.dropPending(dirOf(d, p.domain))
      throw new EnterpriseError('expired_token', 'the code expired before a person approved it')
    }
    const body = { ...grant, device_code: p.device_code, binding: binding(d, p, p.device_code) }
    try {
      return await granted(d, p, await call<Doc>(d.fetch, p.instance, AGENT_PATHS.token, body))
    } catch (e) {
      if (!(e instanceof EnterpriseError)) throw e
      if (!['authorization_pending', 'slow_down'].includes(e.code)) {
        if (['access_denied', 'expired_token', 'invalid_grant'].includes(e.code))
          f.dropPending(dirOf(d, p.domain))
        throw e
      }
      if (e.code === 'slow_down') interval = Math.min(interval + 5, 60)
      const where = p.user_code === null ? '' : ` the code ${p.user_code}`
      if (!wait)
        throw new EnterpriseError(
          'authorization_pending',
          `a person is to approve${where}: bag sign-in ${p.domain} resumes`,
        )
      await d.sleep(interval * 1000)
    }
  }
}

/** The grant: the session written and the code dropped, then one tick settles the chain and the trust roots. */
async function granted(d: EnterpriseDeps, p: f.Pending, g: Doc): Promise<number> {
  const now = d.clock.now()
  const [agent, , session] = keysOf(d, p.name).map((k) => k.address)
  const org = f.checkOrg(g.org, p.domain)
  const ok = g.agent_address === agent && g.generation === 0 && isStr(g.access_token) && isInt(g.expires_in)
  if (!ok || agent === undefined || session === undefined)
    throw new EnterpriseError('bad-answer', 'the grant is not for this agent at generation 0')
  const hop = f.checkOrgHop(g.hop, org, agent, now)
  const [where, keys] = [
    { domain: p.domain, instance: p.instance, name: p.name, ...labelOf(p) },
    { agent_address: agent, session_address: session },
  ]
  const token = {
    access_token: g.access_token as string,
    token_exp: now + (g.expires_in as number),
    generation: 0,
  }
  const rest = { trust_etag: isStr(g.trust_etag) ? g.trust_etag : '', trust_applied: null, local_hop: null }
  const clocks = { hop_got_at: hop === null ? null : now, refreshed_at: now, state_call_at: null }
  const s: f.Session = {
    v: 1,
    ...where,
    ...keys,
    ...token,
    ...rest,
    ...clocks,
    org,
    hop,
    state: 'live',
    reason: null,
    // The label the instance says this agent holds, when it says one: it wins over the one asked for.
    ...(isStr(g.label) && g.label !== '' ? { label: g.label.slice(0, 100) } : {}),
  }
  f.write(dirOf(d, p.domain), 'session', s)
  f.dropPending(dirOf(d, p.domain))
  f.setCurrent(d.home, p.domain)
  const t = await tick({ ...d, org: p.domain })
  for (const root of t.trust?.added ?? []) d.say(`trust ${root} source org:${p.domain}`)
  for (const o of t.records ?? []) d.say(outcomeLine(o))
  if (t.records !== undefined) d.onRecords?.(t.records)
  return report(d, t.session ?? s, t.error)
}

/** bag's relay client over this io's fetch (a test's fake answers it); a subscription that cannot connect fails at once. */
function relayClient(fetch: Fetch | undefined): RelayClient {
  if (fetch === undefined) return createRelayClient({ maxReconnects: 0 })
  const own: typeof globalThis.fetch = (input, init) =>
    fetch(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, init ?? {})
  return createRelayClient({ fetch: own, maxReconnects: 0 })
}

/** The relay client of the probes: the deps' relays when they are a full client, else bag's own. */
const relayOf = (d: EnterpriseDeps): RelayClient =>
  d.relays !== undefined && 'subscribe' in d.relays ? d.relays : relayClient(d.fetch)

/** The bound of each relay probe, in ms: a relay that has not answered within it fails the step with `timeout`. */
export const PROBE_MS = 5000
/** The type of connect's one envelope to the agent itself. */
export const CHECK_TYPE = 'bag.connect-check'

/** A step of connect or status that failed at a relay: `<what> at <relay> (<code>)`. */
export class StepFailed extends Error {
  constructor(what: string, relay: string, code: string) {
    super(`${what} at ${relay} (${code})`)
  }
}

const codeOf = (e: unknown): string => {
  const x = e as { code?: unknown; status?: unknown }
  if (isAcError(e) || typeof x?.code === 'string') return String(x.code)
  return typeof x?.status === 'number' ? (x.status === 0 ? 'unreachable' : `http-${x.status}`) : 'error'
}

/** `work`'s answer, or `late()` after `ms`; any other failure becomes `failed`'s with its code. */
async function within<T>(ms: number, work: Promise<T>, failed: (code: string) => Error): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<never>((_, no) => {
    timer = setTimeout(() => no(failed('timeout')), ms)
  })
  work.catch(() => {}) // a late failure, after the bound, is not an unhandled rejection
  try {
    return await Promise.race([work, late])
  } catch (e) {
    throw e instanceof StepFailed ? e : failed(codeOf(e))
  } finally {
    clearTimeout(timer)
  }
}

/**
 * connect's proof of the path: one envelope from the session key to the agent's own address, through the same Edge
 * send that bag send runs (the address record resolved at the org's first relay, sealed, the chain org root -> agent ->
 * session key), then read back on the agent's own subscription at that relay. When it is the first frame there, it is
 * acknowledged, so the agent's inbox does not show it. Its ms on a monotonic clock, bounded by `bound`.
 */
export async function roundTrip(d: EnterpriseDeps, s: f.Session, bound = PROBE_MS): Promise<number> {
  const relay = s.org.relays[0]
  const failed = (code: string) => new StepFailed('the relay round trip failed', relay ?? 'none', code)
  if (relay === undefined || s.hop === null || s.local_hop === null)
    throw failed(relay === undefined ? 'no-relay' : 'no-chain')
  const [client, start, open] = [relayOf(d), performance.now(), {} as { sub?: Subscription }]
  const run = async (auth: Hop[]): Promise<number> => {
    const [store, lines] = [new SqliteStore(':memory:'), [] as string[]]
    try {
      const edge = new Edge({
        ...{ keys: f.loadKey(d.home, `${s.name}.session`), auth, store, clock: d.clock, rng: d.rng },
        relays: { client, urls: s.org.relays },
        policy: { roots: [], types: [] },
        audit: { append: (l) => void lines.push(l), last: () => lines.at(-1) ?? null },
        leaveRecords: false,
      })
      const body = { check: 'relay round trip' }
      const sent = await edge.send({ to: [s.agent_address], relays: [relay], type: CHECK_TYPE, body })
      const target = sent.targets.find((t) => t.relay === relay)
      if (target?.state !== 'published') throw failed(target?.reason ?? 'not-published')
      open.sub = client.subscribe(relay, s.agent_address, key(d, s.name), [], null)
      let first = true
      for await (const frame of open.sub) {
        if (parseEnvelope(frame.envelopeBytes).id !== sent.id) first = false
        else {
          if (first) open.sub.ack(frame.cursor)
          return Math.round(performance.now() - start)
        }
      }
      throw failed('subscription-ended')
    } finally {
      store.close()
    }
  }
  try {
    return await within(bound, run([s.hop, s.local_hop]), failed)
  } finally {
    open.sub?.close()
  }
}

/** bag status's probe, which sends nothing: the agent's address record read back from the org's first relay; its ms. */
export async function recordProbe(d: EnterpriseDeps, s: f.Session, bound = PROBE_MS): Promise<number> {
  const relay = s.org.relays[0]
  const failed = (code: string) => new StepFailed('the relay round trip failed', relay ?? 'none', code)
  if (relay === undefined) throw failed('no-relay')
  const start = performance.now()
  const bytes = await within(bound, relayOf(d).fetchRecord(relay, s.agent_address, 'address'), failed)
  const r = bytes === null ? null : parseRecord(bytes)
  if (r?.kind !== 'address' || r.key !== s.agent_address) throw failed('no-record')
  return Math.round(performance.now() - start)
}

/** The one line of a live path: `Connected as <label>; relay round trip <n> ms`. */
export const connectedLine = (label: string, ms: number): string =>
  `Connected as ${label}; relay round trip ${ms} ms`

/**
 * The agent's address and accept-from records at the org's relays, when due (records.ts). A relay that fails does not
 * fail the tick: the next tick tries again. Sign-in prints the outcomes; the refresher and status keep quiet.
 */
async function records(d: EnterpriseDeps, s: f.Session): Promise<PublishOutcome[]> {
  if (s.state !== 'live' || s.org.relays.length === 0) return []
  return publishAgentRecords({
    home: dirOf(d, s.domain),
    session: s,
    keys: f.loadKey(d.home, s.name),
    publisher: d.relays ?? relayClient(d.fetch),
    now: d.clock.now(),
  })
}

/**
 * The pairings the console revoked or whose term passed, ended before the records are signed, so the accept-from drops
 * their peers at once (pairings.ts). An instance that does not answer the pairings ends only the terms that passed.
 */
async function endedLinks(d: EnterpriseDeps, s: f.Session): Promise<void> {
  if (s.state !== 'live' || d.fetch === undefined) return
  const commands = (await pairingCommands(s, d.fetch)) ?? []
  const remove = async (peer: string) => void removePairedRoot(d.home, peer, trustFail)
  const ended = await endLinks(s, d.fetch, dirOf(d, s.domain), commands, { remove, now: () => d.clock.now() })
  for (const id of ended) d.note?.(`bag: pairing ${id} ended; its peer left trust.json`)
}

/** What one tick did: the session after it, a refusal it met, whether another process held the lock. */
export interface Tick {
  readonly session: f.Session | null
  readonly error: EnterpriseError | null
  readonly held: boolean
  readonly trust?: TrustSync
  /** The agent's records, when this tick published them (records.ts). */
  readonly records?: readonly PublishOutcome[]
}

/** True when a refresh is due: not live, no org hop, the token under 12 h, or the org hop under half its life. */
export function refreshDue(s: f.Session, now: number): boolean {
  if (s.state !== 'live' || s.hop === null || s.token_exp - now < CLOCKS.refreshUnder) return true
  return s.hop.exp - now < (s.hop.exp - (s.hop_got_at ?? now)) / 2
}

/** How a refresh or a state call names the session: A's address and the sign-in key's (the server's key is the latter). */
const who = (d: EnterpriseDeps, s: f.Session) => ({
  agent_address: s.agent_address,
  signin_address: key(d, `${s.name}.signin`).address,
})

/** POST /agent/refresh (no bearer): the sign-in key's signature over the generation this home holds. */
async function refresh(d: EnterpriseDeps, s: f.Session): Promise<f.Session> {
  const [now, nonce] = [d.clock.now(), layerNonce(d.rng)]
  const pre = refreshPreimage(s.agent_address, s.generation, nonce, now)
  const sig = signPreimage(key(d, `${s.name}.signin`), pre)
  const body = { ...who(d, s), generation: s.generation, nonce, ts: now, sig }
  const r = await call<Doc>(d.fetch, s.instance, AGENT_PATHS.refresh, body)
  if (r.generation !== s.generation + 1 || !isStr(r.access_token) || !isInt(r.expires_in))
    throw new EnterpriseError('bad-answer', `the refresh did not answer generation ${s.generation + 1}`)
  const kept = s.hop !== null && s.hop.exp > now ? s.hop : null
  const hop = f.checkOrgHop(r.hop ?? null, s.org, s.agent_address, now) ?? kept
  const etag = isStr(r.trust_etag) ? r.trust_etag : s.trust_etag
  const got = { hop, hop_got_at: hop?.sig === s.hop?.sig ? s.hop_got_at : now, trust_etag: etag }
  const token = { access_token: r.access_token, token_exp: now + r.expires_in, generation: r.generation }
  return {
    ...s,
    ...token,
    ...got,
    org: refreshedOrg(s, r.org),
    state: 'live',
    reason: null,
    refreshed_at: now,
  }
}

/**
 * The org's relays as the refresh names them now (the instance reads its active relays again), so records.ts publishes
 * the agent's records at a relay added after sign-in. Only the relays move: an answer for another domain or root, or
 * none (an older instance), leaves the session's org as it was.
 */
function refreshedOrg(s: f.Session, org: unknown): f.Org {
  if (org === undefined || org === null) return s.org
  const named = f.checkOrg(org, s.domain)
  return named.root === s.org.root ? { ...s.org, relays: named.relays } : s.org
}

/** The local hop A -> session key, re-signed under 12 h left, on a new org hop, or when it outlives the org hop. */
function localHop(d: EnterpriseDeps, s: f.Session): f.Session {
  const [now, h] = [d.clock.now(), s.local_hop]
  const within = h !== null && h.exp - now >= CLOCKS.localUnder && h.exp <= (s.hop?.exp ?? 0)
  const fresh = within && existsSync(f.chainAt(dirOf(d, s.domain)))
  if (s.hop === null || s.state !== 'live' || fresh) return s
  const exp = Math.min(s.hop.exp, now + CLOCKS.localMax)
  if (exp - now <= CLOCKS.margin) return s
  const local = signHop(key(d, s.name), s.session_address, [], exp)
  f.writeJson(f.chainAt(dirOf(d, s.domain)), [s.hop, local])
  return { ...s, local_hop: local }
}

/** GET /agent/trust when its etag moved: the organisation's roots become exactly the sourced entries of trust.json. */
async function trust(d: EnterpriseDeps, s: f.Session): Promise<[f.Session, TrustSync | undefined]> {
  if (s.state !== 'live' || s.trust_applied === s.trust_etag) return [s, undefined]
  const t = await call<Doc>(d.fetch, s.instance, AGENT_PATHS.trust, null, s.access_token)
  if (!Array.isArray(t.roots) || typeof t.trust_etag !== 'string')
    throw new EnterpriseError('bad-answer', 'the trust answer has no roots')
  const roots = t.roots as SourcedRoot[]
  const peers = roots.map((r) => r?.source).filter((x) => typeof x === 'string' && linked(x))
  const sync = syncSourcedTrust(d.home, owns(d, s, peers), roots, d.clock.now(), trustFail)
  return [{ ...s, trust_etag: t.trust_etag, trust_applied: t.trust_etag, trust_peers: peers }, sync]
}

/** POST /agent/state about hourly, signed by the sign-in key over the generation this home holds; no relays yet. */
async function stateCall(d: EnterpriseDeps, s: f.Session): Promise<f.Session> {
  const now = d.clock.now()
  if (s.state !== 'live' || (s.state_call_at !== null && now - s.state_call_at < CLOCKS.state)) return s
  const nonce = layerNonce(d.rng)
  const sig = signPreimage(
    key(d, `${s.name}.signin`),
    statePreimage(s.agent_address, s.generation, nonce, now, []),
  )
  const body = { ...who(d, s), generation: s.generation, nonce, ts: now, reported_relays: [], sig }
  await call(d.fetch, s.instance, AGENT_PATHS.state, body)
  return { ...s, state_call_at: now }
}

/** An ended session: the organisation's roots leave trust.json as a set, and the chain goes. */
function ended(d: EnterpriseDeps, s: f.Session): void {
  syncSourcedTrust(d.home, owns(d, s), [], d.clock.now(), trustFail)
  f.drop(f.chainAt(dirOf(d, s.domain)))
}

const STATES: Record<string, Pick<f.Session, 'state'>> = {
  stale_generation: { state: 'frozen' },
  agent_frozen: { state: 'frozen' },
  org_suspended: { state: 'paused' },
  agent_revoked: { state: 'ended' },
  agent_lapsed: { state: 'lapsed' },
}

/**
 * One refresher tick under the home's lock (held by another: nothing done): the refresh when due, the local hop, the
 * trust roots when their etag moved, the state call. A refusal that changes the state (frozen on a stale generation,
 * as a copied home's next call is; paused; ended) is written before it is returned; any other leaves the session.
 */
export async function tick(d: EnterpriseDeps): Promise<Tick> {
  f.secureHome(d.home)
  const org = f.selectOrg(d.home, d.org)
  const x = org === null ? d.home : dirOf(d, org)
  if (org === null || f.sessionAt(x) === null) return { session: null, error: null, held: false }
  let release: () => void
  try {
    release = acquireLock(f.lockAt(x))
  } catch (e) {
    if ((e as { code?: unknown }).code !== 'busy') throw e
    return { session: f.sessionAt(x), error: null, held: true }
  }
  let s = f.sessionAt(x) as f.Session
  try {
    if (s.state === 'ended' || s.state === 'lapsed') return { session: s, error: null, held: false }
    if (refreshDue(s, d.clock.now())) s = await refresh(d, s)
    const [next, sync] = await trust(d, localHop(d, s))
    s = await syncAcceptList(await stateCall(d, next), d.fetch, d.note ?? (() => {}))
    f.write(x, 'session', s)
    await endedLinks(d, s)
    const published = await records(d, s)
    return {
      session: s,
      error: null,
      held: false,
      ...(sync === undefined ? {} : { trust: sync }),
      ...(published.length === 0 ? {} : { records: published }),
    }
  } catch (e) {
    if (!(e instanceof EnterpriseError)) throw e
    const next = STATES[e.code]
    const kept = s.reason === 'stale_generation' && e.code === 'agent_frozen'
    if (next !== undefined) s = { ...s, ...next, reason: kept ? s.reason : e.code }
    if (s.state === 'ended') ended(d, s)
    else if (s.state === 'live') s = localHop(d, s)
    f.write(x, 'session', s)
    return { session: s, error: e, held: false }
  } finally {
    release()
  }
}

const SAID: Record<string, string> = {
  stale_generation:
    'frozen: the organisation saw a stale generation, so this home may be a copy of another (a restored backup, a VM snapshot, a copied home); an admin unfreezes or revokes it',
  agent_frozen: 'frozen: an admin of the organisation unfreezes or revokes this agent',
  org_suspended: 'paused: the organisation is suspended; nothing refreshes until it resumes',
  agent_revoked: "ended: the agent was revoked; the organisation's roots left trust.json: bag sign-out",
  agent_lapsed:
    'lapsed: final for this session; bag sign-in <domain> again (a new approval keeps the address)',
  nohop: "waiting: the organisation's signer has not signed this agent's hop yet; bag status fetches it",
}

/** The status lines of a session; its exit: 3 ended, 4 frozen, paused or without a chain, 1 a dead token unrefreshed. */
export function report(d: EnterpriseDeps, s: f.Session, error: EnterpriseError | null): number {
  const path = f.chainAt(dirOf(d, s.domain))
  const [chain, why] = [existsSync(path), s.reason ?? '']
  d.say(`signed-in ${s.domain} agent ${s.agent_address} state ${s.state}${why === '' ? '' : ` (${why})`}`)
  d.say(`instance ${s.instance} generation ${s.generation} refreshed ${iso(s.refreshed_at)}`)
  d.say(
    `token-until ${iso(s.token_exp)} hop-until ${iso(s.hop?.exp)} local-hop-until ${iso(s.local_hop?.exp)}`,
  )
  if (s.state !== 'live') d.say(SAID[why] ?? `${s.state}: ${why}`)
  else if (s.hop === null) d.say(SAID.nohop as string)
  if (error !== null) d.say(`refresh ${error.message}`)
  if (chain) d.say(`chain ${path}: bag send --as ${s.name}.session --auth ${path} ...`)
  if (s.state === 'ended' || s.state === 'lapsed') return 3
  if (s.state !== 'live' || s.local_hop === null || !chain) return 4
  return error !== null && s.token_exp <= d.clock.now() ? 1 : 0
}

/** bag status --chain: the chain JSON after a tick, for the MCP server's --chain-cmd; refused without a live chain. */
export async function chainText(d: EnterpriseDeps): Promise<string> {
  const s = (await tick(d)).session
  if (s === null || s.state === 'ended' || s.state === 'lapsed')
    throw new EnterpriseError('signed-out', 'no session: bag sign-in <domain>')
  const live = s.state === 'live' && s.hop !== null && (s.local_hop?.exp ?? 0) - d.clock.now() > CLOCKS.margin
  if (!live)
    throw new EnterpriseError(
      'no-hop',
      `no live chain: the session is ${s.state}, its org hop ${iso(s.hop?.exp)}`,
    )
  return JSON.stringify([s.hop, s.local_hop])
}

/**
 * bag sign-out: POST /agent/sign-out (the token refreshed first near its end), which revokes A for good; then, or at
 * once for an ended session, the organisation's roots leave trust.json as a set and the session's files and the
 * sign-in and session keys go. A and its mailbox stay. Any other refusal removes nothing.
 */
export async function signOut(d: EnterpriseDeps): Promise<number> {
  f.secureHome(d.home)
  const all = f.profiles(d.home)
  // Several organisations: which one to revoke is the person's word, never a guess.
  if (d.org === undefined && all.length > 1)
    throw new EnterpriseError(
      'usage',
      `signed in to ${all.join(' and ')}: bag sign-out --org <domain>, one of them`,
    )
  const org = f.selectOrg(d.home, d.org)
  const x = org === null ? d.home : dirOf(d, org)
  let s = org === null ? null : f.sessionAt(x)
  const p = org === null ? null : f.pendingAt(x)
  if (s === null && p === null)
    throw new EnterpriseError(
      'signed-out',
      `${d.org === undefined ? 'this home is' : `${d.org} is`} not signed in`,
    )
  if (s === null) {
    f.dropPending(x)
    d.say(`dropped the waiting sign-in to ${p?.domain}; the key files of ${p?.name} stay`)
    return 0
  }
  if (s.state !== 'ended' && s.token_exp - d.clock.now() < 300)
    s = (await tick({ ...d, org: s.domain })).session ?? s
  // A lapsed session's token is long dead: it is cleared here without a call (its hop has run out).
  if (s.state !== 'ended' && s.state !== 'lapsed') {
    try {
      await call(d.fetch, s.instance, AGENT_PATHS.signOut, {}, s.access_token)
    } catch (e) {
      if (!(e instanceof EnterpriseError) || !['agent_revoked', 'agent_lapsed'].includes(e.code)) throw e
    }
  }
  ended(d, s)
  f.dropSession(x)
  f.drop(recordsPath(x), f.keyFile(d.home, `${s.name}.signin`), f.keyFile(d.home, `${s.name}.session`))
  const rest = f.profiles(d.home)
  if (rest.length > 0 && f.selectOrg(d.home) === s.domain) f.setCurrent(d.home, rest[0] as string)
  d.say(`signed-out ${s.domain}: ${s.agent_address} is revoked for good; the identity ${s.name} stays`)
  return 0
}

/**
 * bag status: one tick, then the session's lines and, when it is live, the round-trip line of one probe that sends
 * nothing (recordProbe; exit 1 when it fails); a pending sign-in's line (4); none: exit 3.
 */
export async function enterpriseStatus(d: EnterpriseDeps): Promise<number> {
  f.secureHome(d.home)
  const [all, org] = [f.profiles(d.home), f.selectOrg(d.home, d.org)]
  if (d.org !== undefined && org === null)
    throw new EnterpriseError(
      'signed-out',
      `not signed in to ${d.org}${all.length ? `: one of ${all.join(', ')}` : ''}`,
    )
  const others = all.filter((o) => o !== org)
  // Several profiles and no --org: every one is refreshed (the hourly job is this status), the most recent reported.
  if (d.org === undefined && others.length > 0) {
    for (const o of others) await tick({ ...d, org: o })
    d.note?.(
      `bag: showing ${org}, the most recently connected; also signed in to ${others.join(', ')} (--org)`,
    )
  }
  const t = await tick({ ...d, ...(org === null ? {} : { org }) })
  const p = t.session === null && org !== null ? f.pendingAt(dirOf(d, org)) : null
  if (t.session === null && p === null)
    throw new EnterpriseError('signed-out', 'not signed in: bag sign-in <domain>')
  if (t.session === null) {
    d.say(`waiting ${p?.domain}: a person is to approve the code ${p?.user_code ?? '(a console code)'}`)
    d.say(`until ${iso(p?.expires_at)}; bag sign-in ${p?.domain} resumes`)
    return 4
  }
  if (t.held) d.say(`held refresh ${f.lockAt(dirOf(d, t.session.domain))}`)
  const exit = report(d, t.session, t.error)
  if (exit !== 0 || t.session.org.relays.length === 0) return exit
  // A live session: one probe of the path at the org's first relay, which sends nothing; a failure is exit 1.
  const label = `${t.session.label ?? t.session.name}${others.length > 0 ? ` (${t.session.domain})` : ''}`
  try {
    d.say(connectedLine(label, await recordProbe(d, t.session)))
    return 0
  } catch (e) {
    if (!(e instanceof StepFailed)) throw e
    d.say(`Connected as ${label}, but ${e.message}`)
    return 1
  }
}
