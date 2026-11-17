import { parseRecord, recordSigner } from '@usebag/core'
import type { RecordSource, RelayClient } from '../../src/ports.ts'

// The falsifier of a local-only identity: a relay client and a record
// source that record each call and then throw, so a test of an identity on this machine only, before its promotion,
// fails on the first network call and can assert that the call list is empty. The other packages' tests import it by
// the package name, @usebag/edge/test-support (package.json exports), as the dependency-direction check requires.

/** One call a tripwire saw: the method and its URL (a relay's, or the host of a DNS or well-known read). */
export interface TripwireCall {
  readonly method: string
  readonly url: string
}

/** What a tripwire throws: `RelayCalledBeforePromotion: <method> <url>`. */
export class RelayCalledBeforePromotion extends Error {
  constructor(method: string, url: string) {
    super(`RelayCalledBeforePromotion: ${method} ${url}`)
    this.name = 'RelayCalledBeforePromotion'
  }
}

/** Records the call in `calls`, then throws. */
const trip = (calls: TripwireCall[], method: string, url: string): never => {
  calls.push({ method, url })
  throw new RelayCalledBeforePromotion(method, url)
}

/** A relay client every method of which records {method, url} in `calls` and throws RelayCalledBeforePromotion. */
export function relayTripwire(): RelayClient & { readonly calls: TripwireCall[] } {
  const calls: TripwireCall[] = []
  return {
    calls,
    publish: async (url) => trip(calls, 'publish', url),
    fetch: async (url) => trip(calls, 'fetch', url),
    fetchRecord: async (url) => trip(calls, 'fetchRecord', url),
    subscribe: (url) => trip(calls, 'subscribe', url),
    pairOpen: async (url) => trip(calls, 'pairOpen', url),
    pairClaim: async (url) => trip(calls, 'pairClaim', url),
  }
}

/** A record source (the resolver's DNS TXT and well-known reads, and a relay's record) that records and throws. */
export function fetchTripwire(): RecordSource & { readonly calls: TripwireCall[] } {
  const calls: TripwireCall[] = []
  return {
    calls,
    wellKnown: async (host) => trip(calls, 'wellKnown', host),
    relayRecord: async (url) => trip(calls, 'relayRecord', url),
    txt: async (name) => trip(calls, 'txt', name),
    handleRecord: async (host) => trip(calls, 'handleRecord', host),
  }
}

/** One publish a recording relay passed on: the URL, the record's kind and signer, and the record's relays if any. */
export interface PublishCall {
  readonly url: string
  readonly kind: string
  readonly address: string
  readonly relays: readonly string[] | null
}

/**
 * `inner`, with each publish recorded (in order) in `published` and every other call's {method, url} in `calls`: the
 * stub a promotion test swaps in at the yes, to assert the order key, address, accept-from.
 */
export function recordingRelay(
  inner: RelayClient,
): RelayClient & { readonly published: PublishCall[]; readonly calls: TripwireCall[] } {
  const published: PublishCall[] = []
  const calls: TripwireCall[] = []
  /** Records the call, then passes it on. */
  const via = <T>(method: string, url: string, call: () => T): T => {
    calls.push({ method, url })
    return call()
  }
  return {
    published,
    calls,
    publish: async (url, bytes) => {
      const r = parseRecord(bytes)
      const relays = 'relays' in r && Array.isArray(r.relays) ? [...(r.relays as string[])] : null
      published.push({ url, kind: r.kind, address: recordSigner(r), relays })
      return via('publish', url, () => inner.publish(url, bytes))
    },
    fetch: (url, id, proof) => via('fetch', url, () => inner.fetch(url, id, proof)),
    fetchRecord: (url, address, kind) => via('fetchRecord', url, () => inner.fetchRecord(url, address, kind)),
    subscribe: (url, ...rest) => via('subscribe', url, () => inner.subscribe(url, ...rest)),
  }
}
