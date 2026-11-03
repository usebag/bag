import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import type { Duplex } from 'node:stream'
import { connect as tlsConnect } from 'node:tls'
import { AcError, handlePath, type RecordKind } from '@usebag/core'
import { type RelayGuard, systemDns } from '../net.ts'
import type { Dns, RecordSource, RelayClient } from '../ports.ts'
import { proxyFor, proxyShown } from '../proxy.ts'
import { MAX_RESPONSE_BYTES } from './http-relay.ts'

// An org's records at its one origin (spec/SPEC.md §12.1): its address record at
// https://<host>/.well-known/bag/address.json and its handle records at .../handles/<local>.json, fetched
// without following redirects (as MTA-STS, RFC 8461, does not); the TXT records of DNS discovery through node:dns
// (§12.2); and records at relays through the client. Every fetch at an origin goes through the
// private-address guard the resolver hands it, and connects to the address the guard checked: node:https with a
// lookup that answers that address, so the TLS name stays the host's and no second DNS answer is used (§9 item 11).

export const WELL_KNOWN_PATH = '/.well-known/bag/address.json'

// A host name, with a port for the e2e stub: no scheme, path, user or query can ride along.
const DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/

/** One GET's answer: its status, and its body when the status is 200. */
export interface OriginAnswer {
  readonly status: number
  readonly body: Uint8Array | null
}

/**
 * A GET of `url` that connects to `connect` when it is given (else to what the host resolves to), within `timeoutMs`,
 * reading at most `cap` bytes of a 200's body (resolve-failed past it); it follows no redirect.
 */
export type OriginGet = (
  url: string,
  connect: string | null,
  timeoutMs: number,
  cap: number,
) => Promise<OriginAnswer>

export interface WellKnownOptions {
  /** A GET in place of node:http(s), for tests. */
  readonly get?: OriginGet
  readonly timeoutMs?: number
  /**
   * Test only: http in place of https, for the e2e harness's local stub, and no guard on it (the stub is on loopback).
   * Never set it in production.
   */
  readonly allowInsecureHttp?: boolean
  /** Where TXT records are read: by default the system's resolver (node:dns); none with allowInsecureHttp. */
  readonly dns?: Dns
}

/** The URL of `path` at a host; resolve-failed for a string that is not a host name. */
function originUrl(host: string, path: string, allowInsecureHttp: boolean): string {
  if (!DOMAIN.test(host)) throw new AcError('resolve-failed', `${JSON.stringify(host)} is not a domain`)
  return `${allowInsecureHttp ? 'http' : 'https'}://${host}${path}`
}

/** The well-known URL of a domain; resolve-failed for a string that is not a host name. */
export function wellKnownUrl(domain: string, allowInsecureHttp = false): string {
  return originUrl(domain, WELL_KNOWN_PATH, allowInsecureHttp)
}

/**
 * The OriginGet of node:http and node:https under `env`'s proxy: one request, pinned to `connect` through its lookup
 * when given. Behind a proxy (HTTPS_PROXY, unless NO_PROXY names the host: proxy.ts), an https request goes through a
 * CONNECT tunnel to the address the guard checked, never to the name, with the TLS name kept the host's, so the proxy
 * resolves nothing and the guard's pinning holds. A proxy that refuses that CONNECT (many refuse a bare address) fails
 * the request, resolve-failed with the proxy's answer: it never falls back to a CONNECT by name, which a hostile
 * record could point at an internal host behind the proxy.
 */
export function originGet(env: Readonly<Record<string, string | undefined>>): OriginGet {
  return async (url, connect, timeoutMs, cap) => {
    const signal = AbortSignal.timeout(timeoutMs)
    const proxy = url.startsWith('https:') ? proxyFor(env, url) : null
    if (proxy === null) {
      // With autoSelectFamily off, net asks the lookup for one address, and this one answers the checked address.
      const lookup: LookupFunction = (_host, _options, done) =>
        done(null, connect as string, isIP(connect as string))
      return answer(url, connect === null ? {} : { autoSelectFamily: false, lookup }, signal, cap)
    }
    const { hostname, port } = new URL(url)
    const to = connect === null ? hostname : isIP(connect) === 6 ? `[${connect}]` : connect
    const socket = await tunnel(proxy, `${to}:${port || '443'}`, signal)
    return answer(url, { createConnection: () => tlsConnect({ socket, servername: hostname }) }, signal, cap)
  }
}

/** The OriginGet of this process: originGet under its environment. */
export const httpGet: OriginGet = originGet(process.env)

/** A socket through `proxy` to `authority` (host:port) by CONNECT; resolve-failed naming the proxy when it refuses. */
function tunnel(proxy: URL, authority: string, signal: AbortSignal): Promise<Duplex> {
  const shown = proxyShown(proxy)
  const user = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`
  const auth =
    proxy.username === '' ? {} : { 'proxy-authorization': `Basic ${Buffer.from(user).toString('base64')}` }
  const request = proxy.protocol === 'https:' ? httpsRequest : httpRequest
  return new Promise<Duplex>((resolve, reject) => {
    const refused = (why: string): void => reject(new AcError('resolve-failed', `the proxy ${shown} ${why}`))
    const req = request({
      host: proxy.hostname,
      port: proxy.port || (proxy.protocol === 'https:' ? 443 : 80),
      method: 'CONNECT',
      path: authority,
      headers: { host: authority, ...auth },
      signal,
    })
    req.on('connect', (res, socket) => {
      if (res.statusCode === 200) resolve(socket)
      else {
        socket.destroy()
        refused(`refused CONNECT to ${authority}: ${res.statusCode}`)
      }
    })
    req.on('error', (e) => refused(`failed: ${(e as { code?: string }).code ?? e.message}`))
    req.end()
  })
}

/** One GET of `url` with `extra` options: a 200's body up to `cap`, or another status with none. */
function answer(url: string, extra: object, signal: AbortSignal, cap: number): Promise<OriginAnswer> {
  return new Promise<OriginAnswer>((resolve, reject) => {
    const request = url.startsWith('https:') ? httpsRequest : httpRequest
    const options = { method: 'GET', signal, ...extra }
    const req = request(url, options, (res) => {
      const status = res.statusCode as number
      if (status !== 200) {
        res.resume()
        resolve({ status, body: null })
        return
      }
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > cap) {
          res.destroy()
          reject(new AcError('resolve-failed', `${url}: a response over ${cap} bytes`))
        } else chunks.push(chunk)
      })
      res.on('end', () => resolve({ status, body: new Uint8Array(Buffer.concat(chunks)) }))
    })
    req.on('error', reject)
    req.end()
  })
}

/**
 * A RecordSource: an origin's records over https (or the test-only http), each fetch through the guard the resolver
 * hands it and connected to the address that guard checked; TXT records through `dns`; relay records through `relay`.
 */
export function createRecordSource(
  relay: Pick<RelayClient, 'fetchRecord'>,
  options: WellKnownOptions = {},
): RecordSource {
  const insecure = options.allowInsecureHttp === true
  const get = options.get ?? httpGet
  const at = async (url: string, guard: RelayGuard | undefined): Promise<OriginAnswer> => {
    const connect = insecure || guard === undefined ? null : await guard.connectTo(url)
    return get(url, connect, options.timeoutMs ?? 10_000, MAX_RESPONSE_BYTES)
  }
  const answered = (url: string, status: number): AcError =>
    new AcError('resolve-failed', `${url} answered ${status}`)
  const dns = options.dns ?? (insecure ? null : systemDns)
  return {
    async wellKnown(host, guard) {
      const url = wellKnownUrl(host, insecure)
      const { status, body } = await at(url, guard)
      if (body === null) throw answered(url, status)
      return body
    },
    async handleRecord(host, handle, guard) {
      const url = originUrl(host, handlePath(handle), insecure)
      const { status, body } = await at(url, guard)
      if (status === 404) return null
      if (body === null) throw answered(url, status)
      return body
    },
    relayRecord: (url: string, address: string, kind: RecordKind) => relay.fetchRecord(url, address, kind),
    ...(dns === null ? {} : { txt: (name: string) => dns.txt(name) }),
  }
}
