// The private-address guard (spec/SPEC.md §10): whether an IP address may be the target of a
// fetch that another party chose, such as a relay reading the well-known record of a domain an accept-from record
// names, or an edge posting to the relays a recipient's record lists. Pure: it parses and classifies text and
// resolves nothing; the caller resolves a host itself and passes every address it got. crates/ac-core/src/net.rs
// classifies the same way, and both are tested on one table of cases.

/** Where an address belongs: `public`, or the special-purpose range that makes it not public. */
export type NetCategory =
  | 'public'
  | 'unspecified'
  | 'loopback'
  | 'link-local'
  | 'private'
  | 'shared'
  | 'ula'
  | 'multicast'
  | 'documentation'
  | 'benchmarking'
  | 'special'
  | 'reserved'

/** Every category, `public` first. */
export const NET_CATEGORIES: readonly NetCategory[] = [
  'public',
  'unspecified',
  'loopback',
  'link-local',
  'private',
  'shared',
  'ula',
  'multicast',
  'documentation',
  'benchmarking',
  'special',
  'reserved',
]

// The IPv4 ranges that are not public, as [first octets, prefix length, category], checked in order (the IANA IPv4
// special-purpose registry; 192.88.99.0/24 is the 6to4 anycast that RFC 7526 deprecated).
const V4: readonly (readonly [readonly number[], number, NetCategory])[] = [
  [[0], 8, 'unspecified'],
  [[10], 8, 'private'],
  [[100, 64], 10, 'shared'],
  [[127], 8, 'loopback'],
  [[169, 254], 16, 'link-local'],
  [[172, 16], 12, 'private'],
  [[192, 0, 0], 24, 'special'],
  [[192, 0, 2], 24, 'documentation'],
  [[192, 88, 99], 24, 'reserved'],
  [[192, 168], 16, 'private'],
  [[198, 18], 15, 'benchmarking'],
  [[198, 51, 100], 24, 'documentation'],
  [[203, 0, 113], 24, 'documentation'],
  [[224], 4, 'multicast'],
  [[240], 4, 'reserved'],
]

// The IPv6 ranges inside 2000::/3 that are not public, as [first bytes, prefix length, category]; everything outside
// 2000::/3 that the checks before them leave is reserved.
const V6: readonly (readonly [readonly number[], number, NetCategory])[] = [
  [[0x20, 0x01, 0x0d, 0xb8], 32, 'documentation'],
  [[0x3f, 0xff], 20, 'documentation'],
  [[0x20, 0x01, 0x00], 23, 'special'],
  [[0x20, 0x02], 16, 'special'],
]

function inPrefix(bytes: Uint8Array, first: readonly number[], prefix: number): boolean {
  for (let bit = 0; bit < prefix; bit++) {
    const mask = 0x80 >> (bit % 8)
    if (((bytes[bit >> 3] as number) & mask) !== ((first[bit >> 3] ?? 0) & mask)) return false
  }
  return true
}

const DIGITS = /^[0-9]{1,3}$/
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/

function parseV4(text: string): number[] | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const p of parts) {
    // Decimal only, and no leading zero: 010 is octal to some readers and decimal to others (Rust refuses it too).
    if (!DIGITS.test(p) || (p.length > 1 && p.startsWith('0'))) return null
    const n = Number(p)
    if (n > 255) return null
    octets.push(n)
  }
  return octets
}

// Reads colon-separated groups, the last two of which may be a dotted IPv4 address, into at most `limit` 16-bit
// groups: Rust's Ipv6Addr reader, read_groups. Returns the groups and whether an IPv4 tail ended them, or null.
function readGroups(text: string, limit: number): { groups: number[]; v4: boolean } | null {
  if (text === '') return { groups: [], v4: false }
  const parts = text.split(':')
  const groups: number[] = []
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] as string
    if (i === parts.length - 1 && p.includes('.') && groups.length + 2 <= limit) {
      const v4 = parseV4(p)
      if (v4 === null) return null
      groups.push(((v4[0] as number) << 8) | (v4[1] as number), ((v4[2] as number) << 8) | (v4[3] as number))
      return { groups, v4: true }
    }
    if (!HEX_GROUP.test(p) || groups.length === limit) return null
    groups.push(Number.parseInt(p, 16))
  }
  return { groups, v4: false }
}

function parseV6(text: string): Uint8Array | null {
  const halves = text.split('::')
  if (halves.length > 2) return null
  let groups: number[]
  if (halves.length === 1) {
    const all = readGroups(text, 8)
    if (all === null || all.groups.length !== 8) return null
    groups = all.groups
  } else {
    const head = readGroups(halves[0] as string, 7)
    // An IPv4 tail may not come before "::", and "::" stands for at least one group of zeros.
    if (head === null || head.v4) return null
    const tail = readGroups(halves[1] as string, 7 - head.groups.length)
    if (tail === null) return null
    groups = [...head.groups, ...Array(8 - head.groups.length - tail.groups.length).fill(0), ...tail.groups]
  }
  const bytes = new Uint8Array(16)
  groups.forEach((g, i) => {
    bytes[2 * i] = g >> 8
    bytes[2 * i + 1] = g & 0xff
  })
  return bytes
}

/**
 * The 4 or 16 bytes of an IP address literal, or null when the text is not one: a dotted-quad IPv4 address with
 * decimal octets and no leading zeros, or an IPv6 address in RFC 4291 §2.2 text (hex groups of either case, at most
 * one `::`, an optional dotted IPv4 tail), exactly as Rust's `IpAddr::from_str` reads them: no brackets, zone or port.
 */
export function parseIp(text: string): Uint8Array | null {
  if (text.includes(':')) return parseV6(text)
  const v4 = parseV4(text)
  return v4 === null ? null : Uint8Array.from(v4)
}

function classifyV4(bytes: Uint8Array): NetCategory {
  for (const [first, prefix, category] of V4) if (inPrefix(bytes, first, prefix)) return category
  return 'public'
}

function classifyBytes(bytes: Uint8Array): NetCategory {
  if (bytes.length === 4) return classifyV4(bytes)
  const zeroUpTo = (n: number): boolean => bytes.subarray(0, n).every((b) => b === 0)
  if (zeroUpTo(15)) return bytes[15] === 0 ? 'unspecified' : bytes[15] === 1 ? 'loopback' : 'reserved'
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96, RFC 6052): the address they carry decides.
  if (zeroUpTo(10) && bytes[10] === 0xff && bytes[11] === 0xff) return classifyV4(bytes.subarray(12))
  if (inPrefix(bytes, [0x00, 0x64, 0xff, 0x9b], 96)) return classifyV4(bytes.subarray(12))
  if (inPrefix(bytes, [0xfc], 7)) return 'ula'
  if (inPrefix(bytes, [0xfe, 0x80], 10)) return 'link-local'
  if (inPrefix(bytes, [0xff], 8)) return 'multicast'
  if (!inPrefix(bytes, [0x20], 3)) return 'reserved'
  for (const [first, prefix, category] of V6) if (inPrefix(bytes, first, prefix)) return category
  return 'public'
}

/**
 * The category of an IP address literal (`parseIp`), or null when the text is not one. An IPv4-mapped address
 * (::ffff:0:0/96) or a NAT64 one (64:ff9b::/96) takes the category of the IPv4 address it carries.
 */
export function classifyIp(text: string): NetCategory | null {
  const bytes = parseIp(text)
  return bytes === null ? null : classifyBytes(bytes)
}

/** True when the text is an IP address literal of the public category. */
export function isPublicIp(text: string): boolean {
  return classifyIp(text) === 'public'
}

/** One resolved address and its category, `not-an-address` for text that `parseIp` does not read. */
export interface AddressVerdict {
  readonly address: string
  readonly category: NetCategory | 'not-an-address'
}

/**
 * Judges the addresses a host resolved to, for a fetch another party chose: each with its category, and `allPublic`,
 * true only when there is at least one address and every one is public. A fetch goes ahead only then (refuse
 * when any address is not public), and only to those addresses.
 */
export function judgeAddresses(addresses: readonly string[]): {
  readonly allPublic: boolean
  readonly verdicts: readonly AddressVerdict[]
} {
  const verdicts = addresses.map(
    (address): AddressVerdict => ({
      address,
      category: classifyIp(address) ?? 'not-an-address',
    }),
  )
  return { allPublic: verdicts.length > 0 && verdicts.every((v) => v.category === 'public'), verdicts }
}

const NUMBER = /^(?:[0-9]+|0x[0-9a-f]*)$/i

/**
 * True when a host is an IP literal, or would be read as one: it is an address (`parseIp`, also inside brackets), or
 * its last dot-separated label is decimal digits or `0x` and hex digits, the WHATWG URL rule ("ends in a number")
 * that inet_aton-style resolvers follow too, so that `127.1`, `0177.0.0.1` and `0x7f.1` count as literals.
 */
export function isIpLiteralHost(host: string): boolean {
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  if (parseIp(bare) !== null) return true
  const labels = bare.split('.')
  // A trailing dot names the root zone: the label before it is the last one.
  if (labels.length > 1 && labels[labels.length - 1] === '') labels.pop()
  return NUMBER.test(labels[labels.length - 1] as string)
}
