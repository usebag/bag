import { randomBytes } from 'node:crypto'
import {
  type Hop,
  isAddress,
  isCanonicalInteger,
  isHex,
  signHop,
  signingKeyFromSeed,
  verifyPreimage,
} from '@usebag/core'
import { bindNonce, bindPreimage, refreshPreimage, statePreimage } from '../../src/layer-auth.ts'

// A recorded fake of a bag enterprise instance's agent routes (/api/v1/auth/agent/*), in memory, no network. The
// answers carry the agent contract's shapes and codes, and every signed object is checked as the contract orders it:
// the generation machine with its 120 s grace and the freeze, the nonce window, the skew; refresh and state name the
// session by signin_address; the binding's nonce is derived from the device code (or the console code) and the
// binding rides on every poll, checked at the exchange; /agent/redeem takes the binding and answers the grant itself;
// the code answer carries the derived bind_nonce, and an approved code polled without the binding answers
// authorization_pending. Exported as @usebag/enterprise-client/testing, for bag's CLI and MCP tests too.
//
// The API:
//   new FakeInstance({ domain, origin?, now })  origin defaults to https://ent.example.test; now() is the clock in s
//   fetch(url, init)            the agent's network (a Fetch): only <origin>/api/v1/auth/... answers, else TypeError
//   calls                       every call the agent made, { path, body }, in order
//   approve(userCode) / deny(userCode)   the person's side of the device flow (user codes BCDF-GGG0, BCDF-GGG1, ...)
//   consoleCodes                the console codes /agent/redeem takes, each once (add a connect code here)
//   signer                      whether the organisation's signer signs hops (false: the grant's hop is null)
//   hopLife                     the org hop's life when signed, in seconds (7 days)
//   down                        path -> how many next calls to it fail as the network would
//   extraRoots, trustEtag       what GET /agent/trust lists beside the org's own domain root, and its etag
//   wrongNonce                  a /agent/code answer whose bind_nonce is not derived from its device code
//   root, relays, origin, domain   the org's root key (fixed synthetic seed), its relays, the instance
//   row() / rows / codes / revoked / byUser(userCode)   the instance's state: set row().state to freeze, pause,
//                               revoke or lapse the agent
//   generationOutcome(G, graceUntil, now, g)   the generation machine, exported beside the class

const DAY = 86_400
type Body = Record<string, unknown>
interface Code {
  domain: string
  agent: string
  signin: string
  label: string
  user_code: string | null
  decision: 'pending' | 'approved' | 'denied'
  expires_at: number
  used: boolean
}
interface Row {
  agent: string
  signin: string
  G: number
  grace_until: number
  token: string
  token_exp: number
  prev: string | null
  hop: Hop | null
  state: 'live' | 'frozen' | 'paused' | 'lapsed' | 'ended'
  nonces: Map<string, number>
  last_state_at: number | null
}

export interface FakeInstanceOptions {
  readonly domain: string
  readonly origin?: string
  readonly now: () => number
}

/** The fake instance. `fetch` is the agent's network; everything else is the test's hand on the instance. */
export class FakeInstance {
  readonly domain: string
  readonly origin: string
  readonly root = signingKeyFromSeed(new Uint8Array(32).fill(7))
  readonly relays = ['https://relay.example.test']
  readonly calls: { path: string; body: Body | null }[] = []
  /** Whether the organisation's signer signs hops (C3): until it does, hop is null. */
  signer = true
  /** The org hop's life when signed, in seconds. */
  hopLife = 7 * DAY
  /** Paths whose next call fails as the network would, and how many times. */
  readonly down = new Map<string, number>()
  /** Extra roots GET /agent/trust lists beside the org's own domain root. */
  extraRoots: { root: string; source: string; granted_by: string | null; granted_at: number }[] = []
  trustEtag = 't1'
  /** GET /api/v1/agent/accept-list's roots and etag; null, an instance older than the list (404). */
  acceptList: string[] | null = null
  acceptEtag = 'a1'
  /** A /agent/code answer whose bind_nonce is not the one derived from its device code. */
  wrongNonce = false
  readonly codes = new Map<string, Code>()
  readonly consoleCodes = new Set<string>()
  /** The label a console code carries (the instance minted it); absent, <domain with dashes>-<the next free n>. */
  readonly codeLabels = new Map<string, string>()
  /** The labels the organisation's live agents hold; a grant adds its own. */
  readonly liveLabels = new Set<string>()
  readonly rows = new Map<string, Row>()
  readonly revoked = new Set<string>()
  readonly #now: () => number

  constructor(o: FakeInstanceOptions) {
    this.domain = o.domain
    this.origin = o.origin ?? 'https://ent.example.test'
    this.#now = o.now
  }

  /** The device code row of a user code. */
  byUser(userCode: string): Code {
    const c = [...this.codes.values()].find((x) => x.user_code === userCode)
    if (c === undefined) throw new Error(`no code ${userCode}`)
    return c
  }

  approve(userCode: string): void {
    this.byUser(userCode).decision = 'approved'
  }

  deny(userCode: string): void {
    this.byUser(userCode).decision = 'denied'
  }

  /** The one session row (tests sign in one agent). */
  row(): Row {
    const r = [...this.rows.values()][0]
    if (r === undefined) throw new Error('no session')
    return r
  }

  readonly fetch = async (url: string, init: RequestInit): Promise<Response> => {
    if (url === `${this.origin}/api/v1/agent/accept-list`) return this.#acceptList(init)
    const prefix = `${this.origin}/api/v1/auth`
    if (!url.startsWith(prefix)) throw new TypeError(`fetch failed: ${url}`)
    const path = url.slice(prefix.length)
    const left = this.down.get(path) ?? 0
    if (left > 0) {
      this.down.set(path, left - 1)
      throw new TypeError('fetch failed')
    }
    const body = init.body === undefined ? null : (JSON.parse(String(init.body)) as Body)
    this.calls.push({ path, body })
    const auth = new Headers(init.headers).get('authorization')
    const bearer = auth?.startsWith('Bearer ') ? auth.slice(7) : null
    const out = this.#route(path, body ?? {}, bearer)
    return out.status === 204
      ? new Response(null, { status: 204 })
      : new Response(JSON.stringify(out.body), { status: out.status })
  }

  #acceptList(init: RequestInit): Response {
    if (this.acceptList === null) return new Response('{}', { status: 404 })
    if (new Headers(init.headers).get('if-none-match') === this.acceptEtag)
      return new Response(null, { status: 304 })
    return new Response(JSON.stringify({ accept: this.acceptList, etag: this.acceptEtag }), { status: 200 })
  }

  #route(path: string, b: Body, bearer: string | null): { status: number; body?: unknown } {
    switch (path) {
      case '/agent/code':
      case '/agent/redeem':
        return this.#code(b, path === '/agent/redeem')
      case '/agent/token':
        return this.#token(b)
      case '/agent/refresh':
        return this.#refresh(b, false)
      case '/agent/state':
        return this.#refresh(b, true)
      case '/agent/sign-out':
        return this.#signOut(bearer)
      case '/agent/trust':
        return this.#trust(bearer)
      default:
        return err(404, 'invalid_request', `no route ${path}`)
    }
  }

  #code(b: Body, redeem: boolean): { status: number; body?: unknown } {
    if (b.client_id !== 'bag-agent') return err(401, 'invalid_client', 'not the agent client')
    if (b.domain !== this.domain) return err(400, 'unknown_domain', 'not proved here')
    // A redeem may leave the label out: the console code carries one.
    const labelGiven = typeof b.label === 'string'
    if (!isAddress(b.agent_address) || !isAddress(b.signin_address) || (!labelGiven && !redeem))
      return err(400, 'invalid_request', 'the body is not the contract form')
    let label = labelGiven ? (b.label as string) : ''
    if (redeem) {
      const free = (base: string, from: number) => {
        let n = from
        while (this.liveLabels.has(`${base}-${n}`)) n += 1
        return `${base}-${n}`
      }
      const carried = typeof b.code === 'string' ? this.codeLabels.get(b.code) : undefined
      if (labelGiven && this.liveLabels.has(label))
        return err(409, 'label_taken', `The label ${label} is held by a live agent of this organisation`)
      if (!labelGiven) {
        const base = this.domain.replaceAll('.', '-')
        label = carried ?? free(base, 1)
        if (this.liveLabels.has(label)) {
          const numbered = /^(.*)-([1-9][0-9]*)$/.exec(label)
          label = numbered ? free(numbered[1] ?? base, Number(numbered[2]) + 1) : free(label, 2)
        }
      }
    }
    if (this.revoked.has(b.agent_address)) return err(409, 'agent_key_revoked', 'make fresh keys')
    const c: Code = {
      domain: this.domain,
      agent: b.agent_address,
      signin: b.signin_address,
      label,
      user_code: redeem ? null : `BCDF-${String(this.codes.size).padStart(4, 'G')}`,
      decision: redeem ? 'approved' : 'pending',
      expires_at: this.#now() + 600,
      used: false,
    }
    if (redeem) {
      if (typeof b.code !== 'string' || !this.consoleCodes.delete(b.code))
        return err(400, 'invalid_grant', 'the code is unknown, used, expired or for another organisation')
      return this.#binding(c, b.code, b.binding) ?? this.#grant(c)
    }
    const device_code = randomBytes(16).toString('hex')
    this.codes.set(device_code, c)
    const answer = {
      device_code,
      user_code: c.user_code,
      verification_uri: 'https://id.example.test/auth/agent',
    }
    const bind_nonce = this.wrongNonce ? '00'.repeat(32) : bindNonce(device_code)
    return { status: 200, body: { ...answer, expires_in: 600, interval: 5, bind_nonce } }
  }

  /** The binding over the nonce derived from `secret`, or the refusal it earns (null: it verifies). */
  #binding(c: Code, secret: string, given: unknown): { status: number; body: unknown } | null {
    const { ts, sig } = (given ?? {}) as { ts?: unknown; sig?: unknown }
    if (!isCanonicalInteger(ts) || !isHex(sig, 64))
      return err(400, 'invalid_grant', 'no binding', 'bad-request')
    if (Math.abs(ts - this.#now()) > 300) return err(400, 'invalid_grant', 'stale', 'bind-stale')
    const pre = bindPreimage(c.domain, c.agent, c.signin, bindNonce(secret), ts)
    return verifyPreimage(c.agent, pre, sig) ? null : err(400, 'invalid_grant', 'bad binding', 'bad-bind-sig')
  }

  #token(b: Body): { status: number; body?: unknown } {
    const c = this.codes.get(String(b.device_code))
    if (b.grant_type !== 'urn:ietf:params:oauth:grant-type:device_code')
      return err(400, 'unsupported_grant_type', '')
    if (c === undefined || c.used) return err(400, 'invalid_grant', 'unknown or used')
    if (this.#now() > c.expires_at) return err(400, 'expired_token', 'the code expired')
    if (c.decision === 'denied') return err(400, 'access_denied', 'a person denied it')
    // Before the approval, and for an approved code polled without the binding: pending.
    if (c.decision !== 'approved' || b.binding === undefined)
      return err(400, 'authorization_pending', 'waiting')
    return this.#binding(c, String(b.device_code), b.binding) ?? this.#grant(c)
  }

  #grant(c: Code): { status: number; body: unknown } {
    const now = this.#now()
    c.used = true
    const hop = this.signer ? this.#hop(c.agent) : null
    const row: Row = {
      agent: c.agent,
      signin: c.signin,
      G: 0,
      grace_until: 0,
      token: token(),
      token_exp: now + DAY,
      prev: null,
      hop,
      state: 'live',
      nonces: new Map(),
      last_state_at: null,
    }
    this.rows.set(c.signin, row)
    const org = { domain: this.domain, root: this.root.address, relays: this.relays }
    const grant = {
      access_token: row.token,
      token_type: 'Bearer',
      expires_in: DAY,
      scope: 'agent',
      generation: 0,
    }
    const rest = { org, team: null, caveats: [], hop, hop_exp: hop?.exp ?? null, trust_etag: this.trustEtag }
    this.liveLabels.add(c.label)
    return { status: 200, body: { ...grant, agent_address: c.agent, ...rest, label: c.label } }
  }

  #hop(agent: string): Hop {
    return signHop(this.root, agent, [], this.#now() + this.hopLife)
  }

  #refresh(b: Body, state: boolean): { status: number; body?: unknown } {
    const now = this.#now()
    const { agent_address: a, signin_address: si, generation: g, nonce, ts, sig } = b
    if (
      !isAddress(a) ||
      !isCanonicalInteger(g) ||
      !isHex(nonce, 32) ||
      !isCanonicalInteger(ts) ||
      !isHex(sig, 64)
    )
      return err(400, 'invalid_grant', '', 'bad-request')
    const row = this.rows.get(String(si))
    if (row === undefined || row.agent !== a) return err(400, 'invalid_grant', 'unknown session')
    if (Math.abs(ts - now) > 300)
      return { status: 400, body: { error: 'clock_skew', error_description: 'skew', server_time: now } }
    const relays = (b.reported_relays ?? []) as { url: string; last_subscribed_at: number }[]
    const pre = state ? statePreimage(a, g, nonce, ts, relays) : refreshPreimage(a, g, nonce, ts)
    if (!verifyPreimage(row.signin, pre, sig))
      return err(400, 'invalid_grant', 'bad signature', 'bad-refresh-sig')
    if (row.state === 'ended') return err(401, 'agent_revoked', 'revoked')
    if (row.state === 'lapsed') return err(401, 'agent_lapsed', 'lapsed')
    if (row.state === 'frozen') return err(401, 'agent_frozen', 'frozen')
    if (row.state === 'paused') return err(403, 'org_suspended', 'suspended')
    for (const [n, at] of row.nonces) if (now - at > 600) row.nonces.delete(n)
    if (row.nonces.has(nonce)) return err(400, 'invalid_grant', 'nonce seen', 'nonce-seen')
    row.nonces.set(nonce, now)
    const outcome = generationOutcome(row.G, row.grace_until, now, g)
    const grace = outcome === 'grace'
    if (outcome === 'clone_suspected') {
      row.state = 'frozen'
      return err(401, 'stale_generation', 'a stale or forked generation: frozen')
    }
    if (state) {
      row.last_state_at = now
      return { status: 204 }
    }
    if (!grace) {
      row.prev = row.token
      row.token = token()
      row.token_exp = now + DAY
      row.G = g + 1
      row.grace_until = now + 120
    }
    const half = row.hop === null || row.hop.exp - now < this.hopLife / 2
    if (this.signer && half) row.hop = this.#hop(row.agent)
    return {
      status: 200,
      body: {
        access_token: row.token,
        token_type: 'Bearer',
        expires_in: row.token_exp - now,
        generation: row.G,
        hop: row.hop,
        hop_exp: row.hop?.exp ?? null,
        trust_etag: this.trustEtag,
        org: { domain: this.domain, root: this.root.address, relays: [...this.relays] },
      },
    }
  }

  #bearer(bearer: string | null): Row | { status: number; body: unknown } {
    const row = [...this.rows.values()].find((r) => r.token === bearer || r.prev === bearer)
    if (row === undefined) return err(401, 'token_expired', 'unknown token')
    if (row.token !== bearer && this.#now() > row.grace_until)
      return err(401, 'token_superseded', 'superseded')
    if (row.token_exp < this.#now()) return err(401, 'token_expired', 'past its life')
    if (row.state === 'ended') return err(401, 'agent_revoked', 'revoked')
    return row
  }

  #signOut(bearer: string | null): { status: number; body?: unknown } {
    const row = this.#bearer(bearer)
    if (!('agent' in row)) return row
    row.state = 'ended'
    this.revoked.add(row.agent)
    return { status: 200, body: { signed_out: true } }
  }

  #trust(bearer: string | null): { status: number; body?: unknown } {
    const row = this.#bearer(bearer)
    if (!('agent' in row)) return row
    const own = {
      root: `domain:${this.domain}`,
      source: `org:${this.domain}`,
      granted_by: 'person-1',
      granted_at: 1,
    }
    return { status: 200, body: { trust_etag: this.trustEtag, roots: [own, ...this.extraRoots] } }
  }
}

/**
 * The agent contract's generation machine: a refresh or state call at `g` against the row's G and grace. test/fixtures/bag-ent-auth.json's `generation` cases come from it.
 */
export function generationOutcome(G: number, graceUntil: number, now: number, g: number): string {
  if (g === G) return 'accept'
  return g === G - 1 && now <= graceUntil ? 'grace' : 'clone_suspected'
}

const token = (): string => `bagagt_${randomBytes(32).toString('base64url')}`

function err(status: number, error: string, description: string, detail?: string) {
  return {
    status,
    body: { error, error_description: description, ...(detail === undefined ? {} : { detail }) },
  }
}
