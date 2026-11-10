import { readFileSync } from 'node:fs'
import type { Dns } from './ports.ts'

// The test zone switch (decision 61): two bag enterprise instances and their relays on one machine, under the zone
// pilot.bag.dev, which no public resolver serves. Off unless BAG_TEST_ZONE_FILE names a zone file; then, for this
// process only and with one loud line on stderr: (1) a TXT lookup of a name in pilot.bag.dev reads that file (the format
// docker/dns/zone.sh writes and bag enterprise's ORIGIN_ZONE_FILE reads: `<owner> IN TXT "<string>"...`, the owner
// relative to the zone unless it ends in a dot, `@` the zone itself); (2) a test-zone domain that
// BAG_TEST_ZONE_ORIGINS maps (`<domain>=http://127.0.0.1:<port>,...`, as bag enterprise's
// BAG_ENTERPRISE_PARTNER_ORIGINS) has its /.well-known/bag/ records, its handle records and its enterprise record fetched
// over http from that loopback address and port, the request still naming the host (Host: bag.<domain>:<port>, which bag
// enterprise's origin serves by), the pair's key being the domain or its bag. origin host; (3) a relay URL whose host is a loopback literal (127.0.0.0/8, ::1) passes the
// private-address rule (spec/SPEC.md §9 item 11). Any other name, origin or relay is judged exactly as with it off.

export const TEST_ZONE = 'pilot.bag.dev'
export const TEST_ZONE_FILE_ENV = 'BAG_TEST_ZONE_FILE'
export const TEST_ZONE_ORIGINS_ENV = 'BAG_TEST_ZONE_ORIGINS'

export interface TestZone {
  readonly file: string
  /** A test-zone domain's origin: http on a loopback literal, no path. */
  readonly origins: ReadonlyMap<string, string>
}

/** A usage error naming the variable, never its value. */
const usage = (detail: string): Error => Object.assign(new Error(`usage: ${detail}`), { code: 'usage' })

const LOOPBACK_ORIGIN = /^http:\/\/(?:127(?:\.\d{1,3}){3}|\[::1\]):\d{1,5}$/

/** True for the zone and the names under it, in any case, with or without the root dot. */
export function isInTestZone(name: string): boolean {
  const plain = name.toLowerCase().replace(/\.$/, '')
  return plain === TEST_ZONE || plain.endsWith(`.${TEST_ZONE}`)
}

/** The switch as `env` sets it: null when BAG_TEST_ZONE_FILE is unset or empty; usage for anything malformed. */
export function testZoneFromEnv(env: Readonly<Record<string, string | undefined>>): TestZone | null {
  const file = env[TEST_ZONE_FILE_ENV] ?? ''
  const raw = env[TEST_ZONE_ORIGINS_ENV] ?? ''
  if (file === '') {
    if (raw !== '') throw usage(`${TEST_ZONE_ORIGINS_ENV} needs ${TEST_ZONE_FILE_ENV}`)
    return null
  }
  const origins = new Map<string, string>()
  for (const pair of raw === '' ? [] : raw.split(',')) {
    const at = pair.indexOf('=')
    const domain = pair.slice(0, at).trim().toLowerCase()
    const origin = pair
      .slice(at + 1)
      .trim()
      .replace(/\/$/, '')
    if (at < 1 || !isInTestZone(domain) || !LOOPBACK_ORIGIN.test(origin))
      throw usage(`${TEST_ZONE_ORIGINS_ENV} takes <${TEST_ZONE} domain>=http://127.0.0.1:<port> pairs`)
    origins.set(domain, origin)
  }
  return { file, origins }
}

/** The line a process prints once when the switch is on. */
export function testZoneLine(z: TestZone): string {
  const o = [...z.origins].map(([d, origin]) => `${d}=${origin}`).join(', ')
  const origins = o === '' ? '' : `; origins ${o}`
  return `bag: test zone on: ${TEST_ZONE} from ${z.file}${origins}; loopback relays allowed. Never for real use.`
}

let active: TestZone | null = null

/**
 * Turns the switch on for this process from `env`, once: the zone, and `warn` gets the line. Unset, it stays off and
 * nothing is printed. A second call changes nothing.
 */
export function activateTestZone(
  env: Readonly<Record<string, string | undefined>>,
  warn: (line: string) => void,
): TestZone | null {
  if (active !== null) return active
  active = testZoneFromEnv(env)
  if (active !== null) warn(testZoneLine(active))
  return active
}

/** The switch of this process: null while off. */
export const testZone = (): TestZone | null => active

/** Tests only: the switch as `z` (null turns it off). */
export function setTestZone(z: TestZone | null): void {
  active = z
}

/** The TXT records of `name` in the zone file, read again at each lookup. */
function zoneTxt(file: string, name: string): string[][] {
  const want = name.toLowerCase().replace(/\.$/, '')
  const out: string[][] = []
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const m = /^(\S+)\s+IN\s+TXT\s+(.+)$/.exec(line.trim())
    if (m === null) continue
    const owner = (m[1] as string).toLowerCase()
    const full =
      owner === '@' ? TEST_ZONE : owner.endsWith('.') ? owner.slice(0, -1) : `${owner}.${TEST_ZONE}`
    if (full !== want) continue
    const strings = [...(m[2] as string).matchAll(/"([^"]*)"/g)].map((s) => s[1] as string)
    if (strings.length > 0) out.push(strings)
  }
  return out
}

/** `real`, with the zone file answering the names of the test zone while the switch is on. */
export function testZoneDns(real: Dns): Dns {
  return {
    txt: async (name) => {
      const z = active
      return z !== null && isInTestZone(name) ? zoneTxt(z.file, name) : real.txt(name)
    },
  }
}

/** The loopback origin the switch maps `host` (a domain, or its bag.<domain> origin host) to; null when it maps none. */
export function testZoneOrigin(host: string): string | null {
  const plain = host.toLowerCase().replace(/\.$/, '')
  const o = active?.origins
  return o?.get(plain) ?? (plain.startsWith('bag.') ? o?.get(plain.slice(4)) : undefined) ?? null
}

/**
 * Where a GET of `path` at `host` goes under the switch: `http://<host>:<port><path>`, connected to the mapped loopback
 * address, so the request names the host; null when the switch maps no origin for `host`.
 */
export function testZoneFetch(host: string, path: string): { url: string; connect: string } | null {
  const origin = testZoneOrigin(host)
  if (origin === null) return null
  const { hostname, port } = new URL(origin)
  return {
    url: `http://${host.toLowerCase().replace(/\.$/, '')}:${port}${path}`,
    connect: hostname.replace(/^\[|\]$/g, ''),
  }
}

/** True while the switch is on: the guard then lets a relay on a loopback literal through. */
export const testZoneLoopback = (): boolean => active !== null
