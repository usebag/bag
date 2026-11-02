import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { AcError, handlePath, type RecordKind } from '@usebag/core'
import { type RelayGuard, systemDns } from '../net.ts'
import type { Dns, RecordSource, RelayClient } from '../ports.ts'
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

/** The OriginGet of node:http and node:https: one request, pinned to `connect` through its lookup when given. */
export const httpGet: OriginGet = (url, connect, timeoutMs, cap) =>
  new Promise<OriginAnswer>((resolve, reject) => {
    // With autoSelectFamily off, net asks the lookup for one address, and this one answers the checked address.
    const lookup: LookupFunction = (_host, _options, done) =>
      done(null, connect as string, isIP(connect as string))
    const pinned = connect === null ? {} : { autoSelectFamily: false, lookup }
    const request = url.startsWith('https:') ? httpsRequest : httpRequest
    const options = { method: 'GET', signal: AbortSignal.timeout(timeoutMs), ...pinned }
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
