import { describe, expect, it } from 'vitest'
import {
  classifyAddress,
  GuardRefused,
  guardCheck,
  guardRefusal,
  hostOf,
  ipv4Bytes,
  ipv6Bytes,
  RelayGuard,
  relayKey,
  systemDns,
  systemLookup,
  txtDns,
} from '../src/net.ts'

// The private-address guard: the table, the parsers, and the guard's answers.

describe('the address table: loopback, link-local, RFC 1918, ULA, multicast and unspecified, IPv4 and IPv6', () => {
  it('classifies IPv4 addresses, with 0.0.0.0/8 unspecified and everything outside the table public', () => {
    const table: [string, string][] = [
      ['0.0.0.0', 'unspecified'],
      ['0.1.2.3', 'unspecified'],
      ['127.0.0.1', 'loopback'],
      ['127.255.255.254', 'loopback'],
      ['169.254.169.254', 'link-local'],
      ['10.1.2.3', 'private'],
      ['172.16.0.1', 'private'],
      ['172.31.255.255', 'private'],
      ['192.168.1.1', 'private'],
      ['224.0.0.1', 'multicast'],
      ['239.255.255.255', 'multicast'],
      ['172.15.0.1', 'public'],
      ['172.32.0.1', 'public'],
      ['192.169.1.1', 'public'],
      ['169.255.0.1', 'public'],
      ['100.64.0.1', 'public'],
      ['240.0.0.1', 'public'],
      ['1.1.1.1', 'public'],
    ]
    for (const [ip, range] of table) expect(classifyAddress(ip), ip).toBe(range)
  })

  it('classifies IPv6 addresses, an IPv4-mapped or IPv4-compatible one as the IPv4 it holds, and a zone id', () => {
    const table: [string, string][] = [
      ['::', 'unspecified'],
      ['::1', 'loopback'],
      ['::2', 'unspecified'],
      ['fe80::1', 'link-local'],
      ['febf::1', 'link-local'],
      ['fe80::1%en0', 'link-local'],
      ['fc00::1', 'ula'],
      ['fdff::1', 'ula'],
      ['ff02::1', 'multicast'],
      ['::ffff:127.0.0.1', 'loopback'],
      ['::ffff:7f00:1', 'loopback'],
      ['::ffff:192.168.0.1', 'private'],
      ['::ffff:8.8.8.8', 'public'],
      ['::127.0.0.1', 'loopback'],
      ['fec0::1', 'public'],
      ['2606:4700:4700::1111', 'public'],
      ['1:2:3:4:5:6:7.7.7.7', 'public'],
      ['a::b:1.2.3.4', 'public'],
    ]
    for (const [ip, range] of table) expect(classifyAddress(ip), ip).toBe(range)
    for (const text of ['example.com', '', '1.2.3', '01.2.3.4', '::g', '1::2::3']) {
      expect(classifyAddress(text), text).toBeNull()
    }
  })

  it('classifies a NAT64 address (64:ff9b::/96) as the IPv4 its low 32 bits carry, in the same six classes', () => {
    const table: [string, string][] = [
      ['64:ff9b::0a00:0001', 'private'],
      ['64:ff9b::a00:1', 'private'],
      ['64:ff9b::10.0.0.1', 'private'],
      ['64:ff9b::7f00:1', 'loopback'],
      ['64:ff9b::a9fe:a9fe', 'link-local'],
      ['64:ff9b::c0a8:101', 'private'],
      ['64:ff9b::e000:1', 'multicast'],
      ['64:ff9b::', 'unspecified'],
      ['64:ff9b::101:101', 'public'],
      ['64:ff9b::8.8.8.8', 'public'],
      // Outside the /96: not NAT64 to this table, so read as before.
      ['64:ff9b:0:0:0:1:a00:1', 'public'],
      ['64:ff9a::a00:1', 'public'],
      ['65:ff9b::a00:1', 'public'],
    ]
    for (const [ip, range] of table) expect(classifyAddress(ip), ip).toBe(range)
  })

  it('parses the bytes of both families', () => {
    expect(ipv4Bytes('192.168.0.255')).toEqual(Uint8Array.of(192, 168, 0, 255))
    expect(ipv4Bytes('::1')).toBeNull()
    expect(ipv6Bytes('::ffff:127.0.0.1')).toEqual(
      Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1),
    )
    expect(ipv6Bytes('::1.2.3.4')).toEqual(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4))
    expect(ipv6Bytes('1::')).toEqual(Uint8Array.of(0, 1, ...new Array<number>(14).fill(0)))
    expect(ipv6Bytes('fe80::1:2')).toEqual(
      Uint8Array.of(0xfe, 0x80, ...new Array<number>(10).fill(0), 0, 1, 0, 2),
    )
    expect(ipv6Bytes('1.2.3.4')).toBeNull()
  })

  it('reads a URL host as the guard does, and keys relay URLs without a trailing slash', () => {
    expect(hostOf('http://[::1]:7/')).toBe('::1')
    expect(hostOf('http://LOCALHOST./x')).toBe('localhost')
    expect(hostOf('http://2130706433/')).toBe('127.0.0.1')
    expect(hostOf('https://relay-acme.usuals.now')).toBe('relay-acme.usuals.now')
    expect(() => hostOf('no url')).toThrow()
    expect([relayKey('http://h:1/'), relayKey('HTTP://H:1'), relayKey('http://h:1/x//')]).toEqual([
      'http://h:1',
      'http://h:1',
      'http://h:1/x',
    ])
    expect(relayKey('not a url')).toBe('not a url')
  })
})

describe('RelayGuard', () => {
  const refused = (guard: RelayGuard, url: string) => guard.refusal(url).then((r) => r?.range ?? null)

  it("allows the edge's own relays, whatever their address, and every URL with allowPrivate", async () => {
    const guard = new RelayGuard({ own: ['http://127.0.0.1:7777/', 'http://192.168.1.5:7701'] })
    expect(guard.allows('http://127.0.0.1:7777')).toBe(true)
    expect(await refused(guard, 'http://127.0.0.1:7777/')).toBeNull()
    expect(await refused(guard, 'http://192.168.1.5:7701')).toBeNull()
    expect(await refused(guard, 'http://127.0.0.1:7778')).toBe('loopback')
    const open = new RelayGuard({ own: [], allowPrivate: true })
    expect([open.allows('http://10.0.0.1'), await refused(open, 'http://10.0.0.1')]).toEqual([true, null])
  })

  it('refuses a literal outside the public range, a loopback name and a bad URL; allows a public literal', async () => {
    const guard = new RelayGuard({ own: [], lookup: async () => ['1.1.1.1'] })
    expect(await guard.refusal('http://169.254.169.254/latest')).toEqual({
      range: 'link-local',
      detail: 'http://169.254.169.254/latest: 169.254.169.254 is a link-local address',
    })
    expect(await refused(guard, 'http://[::ffff:10.0.0.1]:80')).toBe('private')
    expect(await refused(guard, 'http://localhost:7777')).toBe('loopback')
    expect(await refused(guard, 'http://relay.localhost')).toBe('loopback')
    expect(await guard.refusal('nope')).toEqual({ range: 'bad-url', detail: '"nope" is not a URL' })
    // Credentials in a relay URL: refused, and never written into a detail (post-hoc).
    expect(await guard.refusal('https://user:secret@1.1.1.1/')).toEqual({
      range: 'userinfo',
      detail: 'a relay URL with a user name or password in it',
    })
    expect(await refused(guard, 'https://user@1.1.1.1/')).toBe('userinfo')
    expect(await refused(guard, 'https://1.1.1.1')).toBeNull()
    expect(await refused(guard, 'https://[2606:4700:4700::1111]')).toBeNull()
  })

  it('resolves a name: refused when any address is non-public; allowed when all are public, or no answer', async () => {
    const answers = new Map<string, readonly string[] | Error>([
      ['inside.test', ['10.0.0.7', 'fd00::7', '10.0.0.7']],
      ['mixed.test', ['93.184.215.14', '10.0.0.7']],
      ['loop.test', ['127.0.0.1']],
      ['nat64.test', ['2606:4700:4700::1111', '64:ff9b::7f00:1']],
      ['public.test', ['93.184.215.14', '2606:4700:4700::1111']],
      ['empty.test', []],
      ['odd.test', ['not an address']],
      ['down.test', new Error('ENOTFOUND')],
    ])
    const guard = new RelayGuard({
      own: [],
      lookup: async (host) => {
        const a = answers.get(host) as readonly string[] | Error
        if (a instanceof Error) throw a
        return a
      },
    })
    expect(await guard.refusal('http://inside.test')).toEqual({
      range: 'private',
      detail:
        'http://inside.test: inside.test resolves to a non-public address (private, ula) among 3 answers',
    })
    expect(await guard.refusal('http://mixed.test')).toEqual({
      range: 'private',
      detail: 'http://mixed.test: mixed.test resolves to a non-public address (private) among 2 answers',
    })
    expect(await guard.refusal('http://loop.test')).toEqual({
      range: 'loopback',
      detail: 'http://loop.test: loop.test resolves to a non-public address (loopback) among 1 answer',
    })
    expect(await refused(guard, 'http://nat64.test')).toBe('loopback')
    for (const host of ['public.test', 'empty.test', 'odd.test', 'down.test']) {
      expect(await refused(guard, `https://${host}`), host).toBeNull()
    }
    await expect(guard.check('http://inside.test')).rejects.toMatchObject({ code: 'resolve-failed' })
    await expect(guard.check('http://mixed.test')).rejects.toMatchObject({ code: 'resolve-failed' })
    await expect(guard.check('http://public.test')).resolves.toBeUndefined()
    // The edge's own relay and allowPrivate are not looked up at all, so a mixed name is allowed for them.
    const own = new RelayGuard({
      own: ['http://mixed.test'],
      lookup: async () => ['93.184.215.14', '10.0.0.7'],
    })
    expect(await refused(own, 'http://mixed.test/')).toBeNull()
    expect(await refused(own, 'http://other.test')).toBe('private')
    const open = new RelayGuard({
      own: [],
      allowPrivate: true,
      lookup: async () => ['93.184.215.14', '10.0.0.7'],
    })
    expect(await refused(open, 'http://mixed.test')).toBeNull()
  })

  it('checks synchronously, with no await, a URL it allows outright', async () => {
    const guard = new RelayGuard({ own: ['http://home.test'] })
    expect(guardCheck(undefined, 'http://10.0.0.1')).toBeUndefined()
    expect(guardCheck(guard, 'http://home.test/')).toBeUndefined()
    await expect(guardCheck(guard, 'http://10.0.0.1')).rejects.toMatchObject({ code: 'resolve-failed' })
    expect(guardRefusal(undefined, 'http://10.0.0.1')).toBeNull()
    expect(guardRefusal(guard, 'http://home.test')).toBeNull()
    expect(await guardRefusal(guard, 'http://10.0.0.1')).toMatchObject({ range: 'private' })
  })

  it("resolves through the system's resolver by default: localhost is a loopback address", async () => {
    const answers = await systemLookup('localhost')
    expect(answers.some((a) => classifyAddress(a) === 'loopback')).toBe(true)
  })
})

describe('connectTo: the address a discovery fetch connects to, the one the guard checked', () => {
  it('answers the literal or the first public answer, null for a URL allowed outright, and refuses the rest', async () => {
    const own = new RelayGuard({ own: ['https://relay.acme.test'], lookup: async () => ['10.0.0.1'] })
    expect(await own.connectTo('https://relay.acme.test')).toBeNull()
    expect(await new RelayGuard({ own: [], allowPrivate: true }).connectTo('https://acme.test')).toBeNull()
    const guard = new RelayGuard({ own: [], lookup: async () => ['not-an-ip', '203.0.113.9', '1.1.1.1'] })
    expect(await guard.connectTo('https://acme.test/x')).toBe('203.0.113.9')
    expect(await guard.connectTo('https://93.184.216.34/x')).toBe('93.184.216.34')
    const refused = await guard.connectTo('https://10.1.2.3/x').catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(GuardRefused)
    expect(refused).toMatchObject({
      code: 'resolve-failed',
      refusal: { range: 'private' },
      addresses: ['10.1.2.3'],
    })
    expect((refused as Error).message).toBe(
      'resolve-failed: https://10.1.2.3/x: 10.1.2.3 is a private address',
    )
    const lan = new RelayGuard({ own: [], lookup: async () => ['1.1.1.1', 'fe80::1%en0'] })
    await expect(lan.connectTo('https://acme.test')).rejects.toMatchObject({
      refusal: { range: 'link-local' },
      addresses: ['1.1.1.1', 'fe80::1%en0'],
    })
    // The refusal carries every answer it judged, so a caller can read each one's class.
    const orb = new RelayGuard({ own: [], lookup: async () => ['192.168.138.154', 'fd07:b51a:cc66::2'] })
    await expect(orb.connectTo('https://bag.orb.local')).rejects.toMatchObject({
      refusal: { range: 'private' },
      addresses: ['192.168.138.154', 'fd07:b51a:cc66::2'],
    })
  })

  it('refuses a name with no answer, since no checked address is left to connect to', async () => {
    const none = new RelayGuard({ own: [], lookup: async () => [] })
    await expect(none.connectTo('https://gone.acme.test/x')).rejects.toThrow(
      'resolve-failed: https://gone.acme.test/x: gone.acme.test does not resolve',
    )
    const failing = new RelayGuard({
      own: [],
      lookup: async () => {
        throw new Error('ENOTFOUND')
      },
    })
    await expect(failing.connectTo('https://gone.acme.test')).rejects.toThrow(/does not resolve$/)
    expect(await failing.refusal('https://gone.acme.test')).toBeNull()
  })
})

describe('txtDns: the TXT records of a name, the Dns port over node:dns (spec/SPEC.md §12.2 item 4)', () => {
  const failing = (e: unknown) => txtDns(async () => Promise.reject(e))

  it('answers the records, none for a name that does not exist or holds no TXT, resolve-failed for any other failure', async () => {
    const asked: string[] = []
    const dns = txtDns(async (name) => {
      asked.push(name)
      return [['v=ac1; key=', 'x'], ['v=spf1 -all']]
    })
    expect(await dns.txt('_bag.acme.test')).toEqual([['v=ac1; key=', 'x'], ['v=spf1 -all']])
    expect(asked).toEqual(['_bag.acme.test'])
    expect(await failing(Object.assign(new Error('nx'), { code: 'ENOTFOUND' })).txt('a.test')).toEqual([])
    expect(await failing(Object.assign(new Error('nodata'), { code: 'ENODATA' })).txt('a.test')).toEqual([])
    await expect(failing(Object.assign(new Error('x'), { code: 'ESERVFAIL' })).txt('a.test')).rejects.toThrow(
      'resolve-failed: the TXT lookup of a.test failed (ESERVFAIL)',
    )
    await expect(failing(null).txt('a.test')).rejects.toThrow('the TXT lookup of a.test failed (null)')
    expect(typeof systemDns.txt).toBe('function')
  })
})
