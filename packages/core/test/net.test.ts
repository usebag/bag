import { describe, expect, it } from 'vitest'
import {
  classifyIp,
  isIpLiteralHost,
  isPublicIp,
  judgeAddresses,
  NET_CATEGORIES,
  type NetCategory,
  parseIp,
} from '../src/net.ts'

// The classification table, row for row the same as crates/ac-core/src/net/tests.rs.
const CLASSIFIED: readonly (readonly [string, NetCategory])[] = [
  ['0.0.0.0', 'unspecified'],
  ['0.255.255.255', 'unspecified'],
  ['1.1.1.1', 'public'],
  ['8.8.8.8', 'public'],
  ['9.255.255.255', 'public'],
  ['10.0.0.0', 'private'],
  ['10.255.255.255', 'private'],
  ['11.0.0.0', 'public'],
  ['100.63.255.255', 'public'],
  ['100.64.0.0', 'shared'],
  ['100.127.255.255', 'shared'],
  ['100.128.0.0', 'public'],
  ['126.255.255.255', 'public'],
  ['127.0.0.1', 'loopback'],
  ['127.255.255.254', 'loopback'],
  ['128.0.0.0', 'public'],
  ['169.253.255.255', 'public'],
  ['169.254.0.1', 'link-local'],
  ['169.254.169.254', 'link-local'],
  ['169.255.0.0', 'public'],
  ['172.15.255.255', 'public'],
  ['172.16.0.0', 'private'],
  ['172.31.255.255', 'private'],
  ['172.32.0.0', 'public'],
  ['192.0.0.8', 'special'],
  ['192.0.1.0', 'public'],
  ['192.0.2.1', 'documentation'],
  ['192.88.99.1', 'reserved'],
  ['192.167.255.255', 'public'],
  ['192.168.0.1', 'private'],
  ['192.168.255.255', 'private'],
  ['192.169.0.0', 'public'],
  ['198.17.255.255', 'public'],
  ['198.18.0.0', 'benchmarking'],
  ['198.19.255.255', 'benchmarking'],
  ['198.20.0.0', 'public'],
  ['198.51.100.7', 'documentation'],
  ['203.0.113.9', 'documentation'],
  ['223.255.255.255', 'public'],
  ['224.0.0.1', 'multicast'],
  ['239.255.255.250', 'multicast'],
  ['240.0.0.1', 'reserved'],
  ['255.255.255.255', 'reserved'],
  ['::', 'unspecified'],
  ['::1', 'loopback'],
  ['::2', 'reserved'],
  ['::1.2.3.4', 'reserved'],
  ['::ffff:127.0.0.1', 'loopback'],
  ['::ffff:7f00:1', 'loopback'],
  ['::ffff:10.1.2.3', 'private'],
  ['::ffff:169.254.169.254', 'link-local'],
  ['::ffff:8.8.8.8', 'public'],
  ['64:ff9b::8.8.8.8', 'public'],
  ['64:ff9b::192.168.1.1', 'private'],
  ['64:ff9b:1::1', 'reserved'],
  ['100::1', 'reserved'],
  ['1fff:ffff::1', 'reserved'],
  ['2001::1', 'special'],
  ['2001:1ff:ffff::1', 'special'],
  ['2001:200::1', 'public'],
  ['2001:db8::1', 'documentation'],
  ['2002:c000:204::1', 'special'],
  ['2606:4700:4700::1111', 'public'],
  ['2a00:1450:4001::1', 'public'],
  ['3fff::1', 'documentation'],
  ['3fff:1000::1', 'public'],
  ['4000::1', 'reserved'],
  ['fc00::1', 'ula'],
  ['fd12:3456:789a::1', 'ula'],
  ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ula'],
  ['fe80::1', 'link-local'],
  ['FE80::ABCD', 'link-local'],
  ['febf:ffff::1', 'link-local'],
  ['fec0::1', 'reserved'],
  ['ff02::1', 'multicast'],
  ['ff0e::1', 'multicast'],
]
// Text that is not an IP address literal, the same list as crates/ac-core/src/net/tests.rs.
const UNPARSED: readonly string[] = [
  '',
  '1.2.3',
  '1.2.3.4.5',
  '256.0.0.1',
  '01.2.3.4',
  '1.2.3.04',
  '0x7f.0.0.1',
  '1.2.3.4 ',
  ' 1.2.3.4',
  '::1%en0',
  '[::1]',
  '1:2:3:4:5:6:7:8:9',
  '1::2::3',
  ':::',
  ':1',
  '1:',
  '12345::',
  '::ffff:1.2.3',
  '1.2.3.4::',
  '1:2:3:4:5:6:7:1.2.3.4',
  '::g',
]

describe('net: the private-address guard', () => {
  it.each(CLASSIFIED)('classifies %s as %s', (text, category) => {
    expect(parseIp(text)).not.toBeNull()
    expect(classifyIp(text)).toBe(category)
    expect(isPublicIp(text)).toBe(category === 'public')
  })

  it('has every category in the table, with these counts (a dropped row fails)', () => {
    const counts = Object.fromEntries(NET_CATEGORIES.map((c) => [c, 0])) as Record<NetCategory, number>
    for (const [, category] of CLASSIFIED) counts[category]++
    expect(counts).toEqual({
      public: 24,
      unspecified: 3,
      loopback: 5,
      'link-local': 6,
      private: 8,
      shared: 2,
      ula: 3,
      multicast: 4,
      documentation: 5,
      benchmarking: 2,
      special: 4,
      reserved: 10,
    })
    expect(CLASSIFIED.length).toBe(76)
    expect(new Set(CLASSIFIED.map(([text]) => text)).size).toBe(76)
  })

  it.each(UNPARSED.map((t) => [t]))('reads %j as no address', (text) => {
    expect(parseIp(text)).toBeNull()
    expect(classifyIp(text)).toBeNull()
    expect(isPublicIp(text)).toBe(false)
  })

  it('reads IPv4 into 4 bytes and IPv6 into 16, with an IPv4 tail and "::" in place', () => {
    expect(parseIp('192.0.2.1')).toEqual(Uint8Array.from([192, 0, 2, 1]))
    expect(parseIp('::ffff:1.2.3.4')).toEqual(Uint8Array.from([...Array(10).fill(0), 0xff, 0xff, 1, 2, 3, 4]))
    expect(parseIp('1::')).toEqual(Uint8Array.from([0, 1, ...Array(14).fill(0)]))
    expect(parseIp('1:2:3:4:5:6:7::')).toEqual(
      Uint8Array.from([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0]),
    )
    expect(parseIp('::2:3:4:5:6:7:8')).toEqual(
      Uint8Array.from([0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]),
    )
    expect(parseIp('1:2:3:4:5:6:1.2.3.4')).toEqual(
      Uint8Array.from([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4]),
    )
    expect(parseIp('ABCD:ef01::')?.slice(0, 4)).toEqual(Uint8Array.from([0xab, 0xcd, 0xef, 0x01]))
    // "::" stands for one group at least, and an IPv4 tail needs room for two groups.
    expect(parseIp('1:2:3:4:5:6:7:8::')).toBeNull()
    expect(parseIp('1:2:3:4:5:6::1.2.3.4')).toBeNull()
    expect(parseIp('1:2:3:4:5:6:7')).toBeNull()
  })

  it('judges a host by every address it resolved to: public only when all are, and there is one', () => {
    expect(judgeAddresses([])).toEqual({ allPublic: false, verdicts: [] })
    expect(judgeAddresses(['8.8.8.8', '2606:4700:4700::1111']).allPublic).toBe(true)
    expect(judgeAddresses(['8.8.8.8', '127.0.0.1', 'nope'])).toEqual({
      allPublic: false,
      verdicts: [
        { address: '8.8.8.8', category: 'public' },
        { address: '127.0.0.1', category: 'loopback' },
        { address: 'nope', category: 'not-an-address' },
      ],
    })
  })

  it.each([
    ['1.2.3.4', true],
    ['127.1', true],
    ['0177.0.0.1', true],
    ['0x7f.1', true],
    ['1.0x7f', true],
    ['1.0X7F', true],
    ['example.0x', true],
    ['2130706433', true],
    ['1.2.3.4.', true],
    ['::1', true],
    ['[::1]', true],
    ['[fe80::1]', true],
    ['acme.example', false],
    ['acme.example.', false],
    ['0x7f.example', false],
    ['a1.b2', false],
    ['1a.2b', false],
    ['.', false],
    ['', false],
    ['[acme.example]', false],
  ] as const)('isIpLiteralHost(%j) is %s', (host, literal) => {
    expect(isIpLiteralHost(host)).toBe(literal)
  })
})
