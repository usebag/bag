import {
  type CanonicalValue,
  canonical,
  isAddress,
  isCanonicalInteger,
  isDomainHost,
  isHex,
  sha256hex,
  toHex,
} from '@usebag/core'
import type { Rng } from '@usebag/edge'

// The three layer-auth preimages of a bag enterprise session (the agent contract's tag spec): never on a relay,
// verified only by the instance. One namespace, `bag-ent/`, whose first byte differs from every SPEC 2.4 tag's
// (`ac/`); `bagent/refresh/1` is superseded. Each is signed by the core's signPreimage over its one canonicaliser and
// checked by its strict verifyPreimage, never another path. Every field has a fixed form, checked before the canonical
// form (bad-request): none is free text. test/fixtures/bag-ent-auth.json pins them.

export const AGENT_TAGS = {
  bind: 'bag-ent/bind/1',
  refresh: 'bag-ent/refresh/1',
  state: 'bag-ent/state/1',
} as const

/** A relay the agent reports on the state call: its URL and when it last subscribed there, never an IP. */
export interface ReportedRelay {
  readonly url: string
  readonly last_subscribed_at: number
}

function check(ok: boolean, field: string): void {
  if (!ok)
    throw Object.assign(new Error(`bad-request: ${field} is not in its contract form`), {
      code: 'bad-request',
    })
}
const fields = (agent: string, generation: number, nonce: string, ts: number): void => {
  check(isAddress(agent), 'agent_address')
  check(isCanonicalInteger(generation), 'generation')
  check(isHex(nonce, 32), 'nonce')
  check(isCanonicalInteger(ts), 'ts')
}

/**
 * The binding's nonce, derived (no server column): sha256hex("bag-ent/bind-nonce/1\n" + secret), the secret the device
 * code (route a) or the console sign-in code (route b).
 */
export const bindNonce = (secret: string): string => sha256hex(`bag-ent/bind-nonce/1\n${secret}`)

/** ["bag-ent/bind/1", domain, agent_address, signin_address, 0, bind_nonce, ts]: signed by A at sign-in. */
export function bindPreimage(domain: string, agent: string, signin: string, nonce: string, ts: number) {
  check(isDomainHost(domain), 'domain')
  check(isAddress(signin) && signin !== agent, 'signin_address')
  fields(agent, 0, nonce, ts)
  return [AGENT_TAGS.bind, domain, agent, signin, 0, nonce, ts] as CanonicalValue
}

/** ["bag-ent/refresh/1", agent_address, generation, nonce, ts]: signed by the sign-in key on every refresh. */
export function refreshPreimage(agent: string, generation: number, nonce: string, ts: number) {
  fields(agent, generation, nonce, ts)
  return [AGENT_TAGS.refresh, agent, generation, nonce, ts] as CanonicalValue
}

/**
 * sha256hex(utf8(canonical(reported_relays))), at most 16 base URLs (a host and an optional port, no path). The canonical form (SPEC 2.1) holds no object, so each
 * relay goes in as the pair [url, last_subscribed_at], in the body's order; the empty list, all R1 reports, is "[]".
 */
export function reportedHash(relays: readonly ReportedRelay[]): string {
  const ok = (r: ReportedRelay) =>
    /^https?:\/\/[^\s/?#@]+$/.test(r.url) && isCanonicalInteger(r.last_subscribed_at)
  check(relays.length <= 16 && relays.every(ok), 'reported_relays')
  return sha256hex(canonical(relays.map((r) => [r.url, r.last_subscribed_at])))
}

/** ["bag-ent/state/1", agent_address, generation, nonce, ts, reported_hash]: signed by the sign-in key, hourly. */
export function statePreimage(
  agent: string,
  generation: number,
  nonce: string,
  ts: number,
  relays: ReportedRelay[],
) {
  fields(agent, generation, nonce, ts)
  return [AGENT_TAGS.state, agent, generation, nonce, ts, reportedHash(relays)] as CanonicalValue
}

/** A fresh 32-byte nonce, 64 lowercase hex, from the edge's CSPRNG. */
export const layerNonce = (rng: Rng): string => toHex(rng.bytes(32))
