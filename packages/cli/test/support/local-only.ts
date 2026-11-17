import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  fetchTripwire,
  RelayCalledBeforePromotion,
  relayTripwire,
  type TripwireCall,
} from '@usebag/edge/test-support'
import type * as Home from '@usebag/home'
import { vi } from 'vitest'
import type { CliRelay } from '../../src/io.ts'

// Local-only identities (bag 0.4.3), the command line's tests: the home acts the CLI hands an identity to, watched by
// pass-through spies (their own code runs), and packages/edge's tripwire: a relay client and
// a record source whose every call is recorded and fails the test, for any act on an identity with no relays yet.

/** The overrides of @usebag/home for a vi.mock factory: pass-through spies on the acts the CLI calls. */
export function homeOverrides(real: typeof Home) {
  return {
    identityRemove: vi.fn(real.identityRemove),
    createIdentity: vi.fn(real.createIdentity),
  }
}

/** Writes <home>/identities.json with `name` on this machine only (relays []), as keygen --local leaves it. */
export function makeLocalOnly(home: string, name: string): void {
  const entry = { label: name, key: name, home, relays: [] }
  writeFileSync(join(home, 'identities.json'), JSON.stringify({ version: 1, identities: [entry] }), {
    mode: 0o600,
  })
}

/**
 * The tripwire as the test io's relay network: relayTripwire, with the CLI's health probe tripping too. `calls` must
 * stay empty before a promotion.
 */
export function noRelay(): { client(): CliRelay; readonly calls: TripwireCall[] } {
  const wire = relayTripwire()
  const health = async (url: string): Promise<boolean> => {
    wire.calls.push({ method: 'health', url })
    throw new RelayCalledBeforePromotion('health', url)
  }
  const client: CliRelay = Object.assign(wire, { health })
  return { client: () => client, calls: wire.calls }
}

/** The io's record source (DNS TXT and well-known reads) as fetchTripwire, and its fetch tripping too; returns the calls. */
export function tripFetch(io: object): TripwireCall[] {
  const source = fetchTripwire()
  const fetch = async (url: unknown): Promise<never> => {
    source.calls.push({ method: 'fetch', url: String(url) })
    throw new RelayCalledBeforePromotion('fetch', String(url))
  }
  Object.assign(io, { records: () => source, fetch })
  return source.calls
}

/** `client`'s calls as text lines (method, then each string or byte argument), each passed on to it. */
export function recording<T extends object>(client: T): { client: T; readonly calls: string[] } {
  const calls: string[] = []
  const text = (a: unknown): string =>
    typeof a === 'string' ? a : a instanceof Uint8Array ? new TextDecoder().decode(a) : ''
  const wrapped = new Proxy(client, {
    get(target, key, receiver) {
      const v = Reflect.get(target, key, receiver)
      if (typeof v !== 'function') return v
      return (...args: unknown[]) => {
        calls.push([String(key), ...args.map(text)].join(' '))
        return v.apply(target, args)
      }
    },
  })
  return { client: wrapped, calls }
}
