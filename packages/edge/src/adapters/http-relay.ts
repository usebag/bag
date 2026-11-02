import { concatBytes, isAcErrorCode, type RecordKind } from '@usebag/core'
import {
  type FetchedBytes,
  type FetchProof,
  type PairOpen,
  type PairReach,
  type PublishResult,
  type RelayClient,
  RelayError,
} from '../ports.ts'
import { countRelayCall, countRelayError } from '../telemetry.ts'
import { RelayTurns } from './relay-turns.ts'
import { createWsSubscriber, jsonObject, type WsSubscriberOptions } from './ws-relay.ts'

// The relay's HTTP calls (spec/SPEC.md §8) on the global fetch: POST /v0/publish, GET /v0/fetch/{id} with the
// AC-Signer, AC-Ts, AC-Sig and AC-Auth headers, whose answer names AC-Received-At, GET
// /v0/fetch/record/{address}/{kind} and GET /v0/health. Redirects are never followed (Appendix B 41); a
// 3xx is the relay's answer with its status, a failed try like any other, where before it read as no answer
// (status 0, so `unreachable`). The optional pair rendezvous: POST /v0/pair/open and GET
// /v0/pair/claim/{nameplate}; a relay without it answers 404 or 405.

/** The largest response read: the relay's request body cap, 256 KiB. */
export const MAX_RESPONSE_BYTES = 262_144

/** AC-Received-At as Unix seconds: null when absent, a RelayError unless it is a plain decimal integer (§2.5). */
function receivedAtOf(res: Response): number | null {
  const header = res.headers.get('ac-received-at')
  if (header === null) return null
  const seconds = /^(0|[1-9][0-9]*)$/.test(header) ? Number(header) : Number.NaN
  if (!Number.isSafeInteger(seconds)) {
    throw new RelayError('bad-shape', res.status, null, `AC-Received-At is not Unix seconds: ${header}`)
  }
  return seconds
}

export interface HttpRelayOptions {
  /** A fetch to use in place of the global one. */
  readonly fetch?: typeof fetch
  /** Per request, its wait for a turn included, in milliseconds (default 10,000). */
  readonly timeoutMs?: number
  /** The process's turns at its relays (default: this client's own). */
  readonly turns?: RelayTurns
}

/** A response body of at most `cap` bytes; RelayError past it. */
export async function readCapped(res: Response, cap: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of res.body ?? []) {
    size += chunk.length
    if (size > cap) throw new RelayError(null, res.status, null, `a response over ${cap} bytes`)
    chunks.push(chunk)
  }
  return concatBytes(...chunks)
}

async function failure(res: Response): Promise<RelayError> {
  const code = jsonObject(await readCapped(res, MAX_RESPONSE_BYTES)).error
  const after = Number(res.headers.get('retry-after') ?? Number.NaN)
  return new RelayError(
    isAcErrorCode(code) ? code : null,
    res.status,
    Number.isSafeInteger(after) && after >= 0 ? after : null,
    `${res.url} answered ${res.status}`,
  )
}

const base = (url: string): string => url.replace(/\/+$/, '')

type Call = <T>(url: string, init: RequestInit, read: (res: Response) => Promise<T>) => Promise<T>

const noAnswer = (url: string, e: unknown): RelayError =>
  new RelayError(null, 0, null, `${url}: ${e instanceof Error ? e.message : String(e)}`)

/**
 * One request with the options' fetch and timeout, following no redirect: a 3xx is returned as the answer. It runs on a
 * turn, held until `read` has its answer, since the pool's connection is busy until the response has come in. The
 * machine's telemetry, while it is on, counts the call by the relay's name and a failure by its code, never the URL.
 */
function caller(options: HttpRelayOptions): Call {
  const turns = options.turns ?? new RelayTurns()
  return async (url, init, read) => {
    const signal = AbortSignal.timeout(options.timeoutMs ?? 10_000)
    const leave = await turns.wait(url, signal).catch((e: unknown) => {
      throw noAnswer(url, e)
    })
    countRelayCall(url)
    try {
      let res: Response
      try {
        res = await (options.fetch ?? fetch)(url, { ...init, redirect: 'manual', signal })
      } catch (e) {
        throw noAnswer(url, e)
      }
      return await read(res)
    } catch (e) {
      countRelayError(url, e)
      throw e
    } finally {
      leave()
    }
  }
}

async function body(res: Response): Promise<Uint8Array> {
  if (res.status !== 200) throw await failure(res)
  return readCapped(res, MAX_RESPONSE_BYTES)
}

/**
 * A fetch by id: the exact bytes, with the relay's AC-Received-At as their `receivedAt` (spec/SPEC.md §8.3), a property
 * that does not enumerate, so the bytes still compare as bytes; left out when the relay names none.
 */
function stamped(call: Call, url: string, id: string, proof: FetchProof): Promise<FetchedBytes> {
  const headers: Record<string, string> = {
    'AC-Signer': proof.signer,
    'AC-Ts': String(proof.ts),
    'AC-Sig': proof.sig,
  }
  if (proof.auth.length > 0)
    headers['AC-Auth'] = Buffer.from(JSON.stringify(proof.auth)).toString('base64url')
  return call(`${base(url)}/v0/fetch/${id}`, { headers }, async (res) => {
    const bytes = await body(res)
    const receivedAt = receivedAtOf(res)
    return receivedAt === null ? bytes : Object.defineProperty(bytes, 'receivedAt', { value: receivedAt })
  })
}

/** The HTTP half of a RelayClient, and the health probe. */
export function createHttpRelay(options: HttpRelayOptions = {}): Omit<RelayClient, 'subscribe'> & {
  health(url: string): Promise<boolean>
} {
  const call = caller(options)
  return {
    async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
      const init = { method: 'POST', headers: { 'content-type': 'application/json' }, body: bytes }
      const r = jsonObject(await call(`${base(url)}/v0/publish`, init, body))
      // A record (a body with a top-level `kind`, as the relay dispatches it) has no id and fills no mailbox; the
      // relay answers {ok, kind, signer, iat, valid_until} (spec/SPEC.md §8.2, Appendix B 65), returned as
      // `record`; an older relay answers {"ok": true} alone, read as a result with no `record`. Correction
      // (2026-10-24): this was read as an envelope's answer.
      if (Object.hasOwn(jsonObject(bytes), 'kind')) {
        if (r.ok !== true)
          throw new RelayError('bad-shape', 200, null, 'publish answered 200 without {ok: true}')
        if (!Object.hasOwn(r, 'kind')) return { id: '', duplicate: false, delivered: 0 }
        const { kind, signer, iat, valid_until } = r
        if (
          typeof kind !== 'string' ||
          typeof signer !== 'string' ||
          !Number.isSafeInteger(iat) ||
          !(valid_until === null || Number.isSafeInteger(valid_until))
        ) {
          throw new RelayError(
            'bad-shape',
            200,
            null,
            'a record publish answered 200 without {kind, signer, iat, valid_until}',
          )
        }
        const record = { kind, signer, iat: iat as number, valid_until: valid_until as number | null }
        return { id: '', duplicate: false, delivered: 0, record }
      }
      if (
        r.ok !== true ||
        typeof r.id !== 'string' ||
        typeof r.duplicate !== 'boolean' ||
        typeof r.delivered !== 'number'
      ) {
        throw new RelayError(
          'bad-shape',
          200,
          null,
          'publish answered 200 without {ok, id, duplicate, delivered}',
        )
      }
      return { id: r.id, duplicate: r.duplicate, delivered: r.delivered }
    },
    fetch(url: string, id: string, proof: FetchProof): Promise<FetchedBytes> {
      return stamped(call, url, id, proof)
    },
    fetchRecord(url: string, address: string, kind: RecordKind): Promise<Uint8Array | null> {
      return call(`${base(url)}/v0/fetch/record/${address}/${kind}`, {}, async (res) =>
        res.status === 404 ? readCapped(res, MAX_RESPONSE_BYTES).then(() => null) : body(res),
      )
    },
    async pairOpen(url: string, open: PairOpen): Promise<string | null> {
      const init = {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(open),
      }
      const answer = await call(`${base(url)}/v0/pair/open`, init, async (res) =>
        res.status === 404 || res.status === 405 ? res.arrayBuffer().then(() => null) : body(res),
      )
      if (answer === null) return null
      const n = jsonObject(answer).nameplate
      if (typeof n === 'string' && /^[1-9][0-9]{0,8}$/.test(n)) return n
      throw new RelayError('bad-shape', 200, null, 'pair/open answered 200 without {nameplate}')
    },
    async pairClaim(url: string, nameplate: string): Promise<PairReach | null> {
      const answer = await call(
        `${base(url)}/v0/pair/claim/${encodeURIComponent(nameplate)}`,
        {},
        async (res) => (res.status === 404 ? res.arrayBuffer().then(() => null) : body(res)),
      )
      if (answer === null) return null
      const { inviter, invitation, relays, exp } = jsonObject(answer)
      const list =
        Array.isArray(relays) && relays.every((r) => typeof r === 'string') ? (relays as string[]) : null
      if (
        typeof inviter === 'string' &&
        typeof invitation === 'string' &&
        list !== null &&
        Number.isSafeInteger(exp)
      ) {
        return { inviter, invitation, relays: list, exp: exp as number }
      }
      throw new RelayError(
        'bad-shape',
        200,
        null,
        'pair/claim answered 200 without {inviter, invitation, relays, exp}',
      )
    },
    health(url: string): Promise<boolean> {
      return call(`${base(url)}/v0/health`, {}, async (res) => {
        await res.arrayBuffer()
        return res.status === 200
      })
    },
  }
}

/** A RelayClient: the HTTP calls on fetch and subscribe on the global WebSocket. */
export function createRelayClient(options: HttpRelayOptions & WsSubscriberOptions = {}): RelayClient {
  const held = { ...options, turns: options.turns ?? new RelayTurns() }
  return { ...createHttpRelay(held), ...createWsSubscriber(held) }
}
