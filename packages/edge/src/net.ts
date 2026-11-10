import { lookup as dnsLookup, resolveTxt } from 'node:dns/promises'
import { isIPv4, isIPv6 } from 'node:net'
import { AcError } from '@usebag/core'
import type { Dns } from './ports.ts'
import { testZoneLoopback } from './test-zone.ts'

// The private-address guard. A relay URL whose host is a loopback, link-local, private (RFC 1918),
// unique-local, multicast or unspecified address, IPv4 or IPv6 (an IPv4-mapped or NAT64 address read as the IPv4 it
// carries), or a name that resolves to any such address, is refused, unless it is one of the edge's own relays: those
// the operator configured, which the edge already talks to. One non-public answer refuses the name, as the core's
// judgeAddresses does, because the HTTP client may connect to any answer it is given. The table is
// the one the relay uses; it moves to packages/core/src/net.ts when the relay's guard lands there.

/** What kind of address an IP is, by the guard's table; every address outside the table is public. */
export type AddressClass =
  | 'public'
  | 'loopback'
  | 'link-local'
  | 'private'
  | 'ula'
  | 'multicast'
  | 'unspecified'

/** The four bytes of a dotted-quad IPv4 address, or null for any other text. */
export function ipv4Bytes(text: string): Uint8Array | null {
  return isIPv4(text) ? Uint8Array.from(text.split('.'), Number) : null
}

const groups = (part: string): number[] =>
  part === '' ? [] : part.split(':').map((g) => Number.parseInt(g, 16))

/**
 * The sixteen bytes of an IPv6 address, with `::`, an embedded IPv4 tail, and a zone id (`%en0`, as getaddrinfo
 * writes a link-local answer); null for any other text.
 */
export function ipv6Bytes(text: string): Uint8Array | null {
  const bare = text.replace(/%.*$/, '')
  if (!isIPv6(bare)) return null
  let head = bare
  const tail: number[] = []
  const cut = bare.lastIndexOf(':')
  const v4 = ipv4Bytes(bare.slice(cut + 1))
  if (v4 !== null) {
    tail.push(((v4[0] as number) << 8) | (v4[1] as number), ((v4[2] as number) << 8) | (v4[3] as number))
    head = bare.endsWith(`::${bare.slice(cut + 1)}`) ? bare.slice(0, cut + 1) : bare.slice(0, cut)
  }
  const [left, right] = head.includes('::') ? head.split('::') : [head, undefined]
  const l = groups(left as string)
  const r = right === undefined ? [] : groups(right)
  const words = [...l, ...new Array<number>(8 - l.length - r.length - tail.length).fill(0), ...r, ...tail]
  const out = new Uint8Array(16)
  for (const [i, w] of words.entries()) {
    out[2 * i] = w >> 8
    out[2 * i + 1] = w & 0xff
  }
  return out
}

function classify4(a: number, b: number): AddressClass {
  if (a === 0) return 'unspecified' // 0.0.0.0/8, "this host on this network": 0.0.0.0 reaches the local host
  if (a === 127) return 'loopback'
  if (a === 169 && b === 254) return 'link-local'
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private'
  if (a >= 224 && a <= 239) return 'multicast'
  return 'public'
}

function classify6(x: Uint8Array): AddressClass {
  const zeros = (n: number): boolean => x.subarray(0, n).every((byte) => byte === 0)
  if (zeros(16)) return 'unspecified'
  if (zeros(15) && x[15] === 1) return 'loopback'
  // An IPv4-mapped address (::ffff:a.b.c.d), the deprecated IPv4-compatible form (::a.b.c.d), and a NAT64 address
  // (64:ff9b::/96, RFC 6052), as the IPv4 their low 32 bits carry, as the core reads the first and the last.
  const nat64 =
    x[0] === 0 && x[1] === 0x64 && x[2] === 0xff && x[3] === 0x9b && x.subarray(4, 12).every((b) => b === 0)
  if ((zeros(10) && x[10] === 0xff && x[11] === 0xff) || zeros(12) || nat64)
    return classify4(x[12] as number, x[13] as number)
  if (x[0] === 0xfe && ((x[1] as number) & 0xc0) === 0x80) return 'link-local'
  if (((x[0] as number) & 0xfe) === 0xfc) return 'ula'
  if (x[0] === 0xff) return 'multicast'
  return 'public'
}

/** The class of an IP address, IPv4 or IPv6; null for text that is not one (a host name). */
export function classifyAddress(ip: string): AddressClass | null {
  const v4 = ipv4Bytes(ip)
  if (v4 !== null) return classify4(v4[0] as number, v4[1] as number)
  const v6 = ipv6Bytes(ip)
  return v6 === null ? null : classify6(v6)
}

/** A URL's host as the guard reads it: lowercase, an IPv6 literal without its brackets, a name without a final dot. */
export function hostOf(url: string): string {
  const host = new URL(url).hostname
  return host.startsWith('[') ? host.slice(1, -1) : host.replace(/\.$/, '')
}

/** Every address a host name resolves to. */
export type Lookup = (host: string) => Promise<readonly string[]>

/** getaddrinfo through node:dns, every answer. */
export const systemLookup: Lookup = async (host) =>
  (await dnsLookup(host, { all: true, verbatim: true })).map((a) => a.address)

/** A relay URL as the guard compares it: parsed and without a trailing slash, or as given when it does not parse. */
export function relayKey(url: string): string {
  try {
    return new URL(url).href.replace(/\/+$/, '')
  } catch {
    return url
  }
}

export interface RelayGuardOptions {
  /** The edge's own relays, which the guard always allows. */
  readonly own: readonly string[]
  /** Allows every relay URL: for tests, and a network of several relays on private addresses. */
  readonly allowPrivate?: boolean
  readonly lookup?: Lookup
}

/**
 * Why the guard refuses a URL: the class of its address, `bad-url` for one that does not parse, or `userinfo` for one
 * that carries a user name or password (fetch would refuse it at every try anyway).
 */
export interface Refusal {
  readonly range: Exclude<AddressClass, 'public'> | 'bad-url' | 'userinfo'
  readonly detail: string
}

export class RelayGuard {
  readonly #own: ReadonlySet<string>
  readonly #o: RelayGuardOptions

  constructor(options: RelayGuardOptions) {
    this.#o = options
    this.#own = new Set(options.own.map(relayKey))
  }

  /** True for a URL the guard allows without looking at it: one of the edge's own relays, or any with allowPrivate. */
  allows(url: string): boolean {
    return this.#o.allowPrivate === true || this.#own.has(relayKey(url))
  }

  /**
   * Null when the edge may call `url`; else why not. A name with any non-public answer is refused, the range naming the
   * first. A name that does not resolve is not refused: the call that follows fails on its own, and a later try asks
   * again.
   */
  async refusal(url: string): Promise<Refusal | null> {
    return this.allows(url) ? null : (await this.#judge(url)).refusal
  }

  /**
   * The address a discovery fetch of `url` connects to (spec/SPEC.md §9 item 11, §12.1): null when the
   * guard allows the URL outright (any address may serve it); else the URL's literal address or the first public
   * answer of the one lookup the guard judged. GuardRefused for a URL the guard refuses; resolve-failed for a name with
   * no answer, since there is then no checked address to connect to.
   */
  async connectTo(url: string): Promise<string | null> {
    if (this.allows(url)) return null
    const { refusal, address, answers } = await this.#judge(url)
    if (refusal !== null) throw new GuardRefused(refusal, answers)
    if (address === null) throw new AcError('resolve-failed', `${url}: ${hostOf(url)} does not resolve`)
    return address
  }

  /**
   * The guard's verdict on a URL it does not allow outright, the address it checked (null for none), and the addresses
   * it judged (the literal, or every answer of the name's lookup).
   */
  async #judge(
    url: string,
  ): Promise<{ refusal: Refusal | null; address: string | null; answers: readonly string[] }> {
    const pass = (address: string | null) => ({ refusal: null, address, answers: [] })
    const refuse = (refusal: Refusal, answers: readonly string[] = []) => ({
      refusal,
      address: null,
      answers,
    })
    let parsed: URL
    try {
      parsed = new URL(url)
    } catch {
      return refuse({ range: 'bad-url', detail: `${JSON.stringify(url)} is not a URL` })
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return refuse({ range: 'userinfo', detail: 'a relay URL with a user name or password in it' })
    }
    const host = hostOf(url)
    const literal = classifyAddress(host)
    // The test zone switch (test-zone.ts) lets a loopback literal through, and nothing else.
    if (literal === 'loopback' && testZoneLoopback()) return pass(host)
    if (literal !== null) {
      return literal === 'public'
        ? pass(host)
        : refuse({ range: literal, detail: `${url}: ${host} is a ${literal} address` }, [host])
    }
    if (host === 'localhost' || host.endsWith('.localhost')) {
      return refuse({ range: 'loopback', detail: `${url}: ${host} is a loopback name (RFC 6761)` })
    }
    let answers: readonly string[]
    try {
      answers = await (this.#o.lookup ?? systemLookup)(host)
    } catch {
      return pass(null)
    }
    const classes = answers.map(classifyAddress)
    const inside = classes.filter((c): c is Exclude<AddressClass, 'public'> => c !== null && c !== 'public')
    const first = inside[0]
    if (first === undefined) return pass(answers.find((_, i) => classes[i] === 'public') ?? null)
    const n = answers.length
    return refuse(
      {
        range: first,
        detail: `${url}: ${host} resolves to a non-public address (${[...new Set(inside)].join(', ')}) among ${n} answer${n === 1 ? '' : 's'}`,
      },
      answers,
    )
  }

  /** Throws resolve-failed for a URL the guard refuses. */
  async check(url: string): Promise<void> {
    const refused = await this.refusal(url)
    if (refused !== null) throw new AcError('resolve-failed', refused.detail)
  }
}

/** A guard's refusal of a discovery fetch: resolve-failed, carrying the refusal (a lookup reports it as refused). */
export class GuardRefused extends AcError {
  readonly refusal: Refusal
  /** The addresses the guard judged: the URL's literal address, or every answer of its name's lookup; else none. */
  readonly addresses: readonly string[]

  constructor(refusal: Refusal, addresses: readonly string[] = []) {
    super('resolve-failed', refusal.detail)
    this.name = 'GuardRefused'
    this.refusal = refusal
    this.addresses = addresses
  }
}

/** A TXT lookup: the records at a name, each its character-strings (RFC 1035 §3.3.14), as node:dns answers them. */
export type ResolveTxt = (name: string) => Promise<string[][]>

/**
 * The Dns port over a TXT lookup (spec/SPEC.md §12.2 item 4): a name that does not exist (ENOTFOUND) or holds no TXT
 * record (ENODATA) has none; any other failure (a server failure, a timeout, a refused or unreadable answer) is
 * resolve-failed, naming the name and the error's code.
 */
export function txtDns(resolve: ResolveTxt = resolveTxt): Dns {
  return {
    async txt(name) {
      try {
        return await resolve(name)
      } catch (e) {
        const code = (e as { code?: unknown } | null)?.code
        if (code === 'ENOTFOUND' || code === 'ENODATA') return []
        throw new AcError('resolve-failed', `the TXT lookup of ${name} failed (${String(code ?? e)})`)
      }
    },
  }
}

/** The system's resolver through node:dns/promises resolveTxt (the system resolver at the edge). */
export const systemDns: Dns = txtDns()

/**
 * Checks `url` with the guard, when there is one and it does not allow the URL outright; synchronous for the edge's
 * own relays, so a call to one of them starts in the same turn as before the guard existed.
 */
export function guardCheck(guard: RelayGuard | undefined, url: string): Promise<void> | undefined {
  return guard === undefined || guard.allows(url) ? undefined : guard.check(url)
}

/** The guard's refusal of `url`, or null; synchronous (no await) for a URL it allows outright. */
export function guardRefusal(
  guard: RelayGuard | undefined,
  url: string,
): Refusal | null | Promise<Refusal | null> {
  return guard === undefined || guard.allows(url) ? null : guard.refusal(url)
}
