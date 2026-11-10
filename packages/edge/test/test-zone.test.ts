import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createRecordSource, type OriginGet } from '../src/adapters/well-known.ts'
import { RelayGuard } from '../src/net.ts'
import {
  activateTestZone,
  isInTestZone,
  setTestZone,
  TEST_ZONE,
  testZone,
  testZoneDns,
  testZoneFetch,
  testZoneFromEnv,
  testZoneLine,
  testZoneOrigin,
} from '../src/test-zone.ts'

// The test zone switch (decision 61): off unless BAG_TEST_ZONE_FILE is set; on, pilot.bag.dev's TXT comes from the
// zone file, a mapped test-zone domain's records from its loopback origin, and a loopback relay literal passes the
// guard. Every case is also run with the switch off, where nothing differs from before.

const dir = mkdtempSync(join(tmpdir(), 'bag-test-zone-'))
const ZONE = join(dir, 'zone.db')
writeFileSync(
  ZONE,
  [
    '$ORIGIN pilot.bag.dev.',
    '_bag.acme IN TXT "v=bag1; key=ed25519:aa"',
    '_bag.okok.pilot.bag.dev. IN TXT "v=bag1;" " key=ed25519:bb"',
    '@ IN TXT "zone"',
    'acme IN A 127.0.0.1',
  ].join('\n'),
)
const ON = { file: ZONE, origins: new Map([['acme.pilot.bag.dev', 'http://127.0.0.1:8788']]) }
const real = { txt: async (name: string) => [[`real ${name}`]] }

afterEach(() => setTestZone(null))

describe('testZoneFromEnv and the line', () => {
  it('is off unset, and reads the file and the origin pairs', () => {
    expect(testZoneFromEnv({})).toBeNull()
    expect(testZoneFromEnv({ BAG_TEST_ZONE_FILE: '' })).toBeNull()
    const z = testZoneFromEnv({
      BAG_TEST_ZONE_FILE: ZONE,
      BAG_TEST_ZONE_ORIGINS:
        'Acme.pilot.bag.dev=http://127.0.0.1:8788/, okok.pilot.bag.dev=http://[::1]:8789',
    })
    expect(z?.file).toBe(ZONE)
    expect([...(z?.origins ?? [])]).toEqual([
      ['acme.pilot.bag.dev', 'http://127.0.0.1:8788'],
      ['okok.pilot.bag.dev', 'http://[::1]:8789'],
    ])
    expect(testZoneLine(z as NonNullable<typeof z>)).toBe(
      `bag: test zone on: ${TEST_ZONE} from ${ZONE}; origins acme.pilot.bag.dev=http://127.0.0.1:8788, okok.pilot.bag.dev=http://[::1]:8789; loopback relays allowed. Never for real use.`,
    )
    expect(testZoneLine({ file: ZONE, origins: new Map() })).toBe(
      `bag: test zone on: ${TEST_ZONE} from ${ZONE}; loopback relays allowed. Never for real use.`,
    )
  })

  it('refuses origins without a file, a domain outside the zone, and an origin that is not http on loopback', () => {
    expect(() => testZoneFromEnv({ BAG_TEST_ZONE_ORIGINS: 'acme.pilot.bag.dev=http://127.0.0.1:1' })).toThrow(
      'usage: BAG_TEST_ZONE_ORIGINS needs BAG_TEST_ZONE_FILE',
    )
    for (const pair of [
      'acme.com=http://127.0.0.1:1',
      'evilpilot.bag.dev=http://127.0.0.1:1',
      'acme.pilot.bag.dev=https://127.0.0.1:1',
      'acme.pilot.bag.dev=http://10.0.0.1:1',
      'acme.pilot.bag.dev=http://localhost:1',
      'acme.pilot.bag.dev=http://127.0.0.1:1/path',
      'acme.pilot.bag.dev',
      '=http://127.0.0.1:1',
    ]) {
      const e = (() => {
        try {
          testZoneFromEnv({ BAG_TEST_ZONE_FILE: ZONE, BAG_TEST_ZONE_ORIGINS: pair })
        } catch (x) {
          return x as Error & { code?: unknown }
        }
        return null
      })()
      expect([e?.code, e?.message], pair).toEqual([
        'usage',
        'usage: BAG_TEST_ZONE_ORIGINS takes <pilot.bag.dev domain>=http://127.0.0.1:<port> pairs',
      ])
    }
  })

  it('activates once, printing the line once; unset prints nothing and stays off', () => {
    const lines: string[] = []
    expect(activateTestZone({}, (l) => lines.push(l))).toBeNull()
    expect([testZone(), lines]).toEqual([null, []])
    activateTestZone({ BAG_TEST_ZONE_FILE: ZONE }, (l) => lines.push(l))
    activateTestZone({ BAG_TEST_ZONE_FILE: '/elsewhere' }, (l) => lines.push(l))
    expect([testZone()?.file, lines.length]).toEqual([ZONE, 1])
    expect(lines[0]).toMatch(/^bag: test zone on: pilot\.bag\.dev from /)
  })

  it('names the zone and its names only', () => {
    for (const n of [TEST_ZONE, `acme.${TEST_ZONE}`, `_bag.ACME.${TEST_ZONE}.`])
      expect(isInTestZone(n), n).toBe(true)
    for (const n of [`evil${TEST_ZONE}`, `${TEST_ZONE}.evil.com`, 'bag.dev'])
      expect(isInTestZone(n), n).toBe(false)
  })
})

describe('testZoneDns', () => {
  it('reads the zone file for names in the zone while on; every other name, and every name while off, is real', async () => {
    const dns = testZoneDns(real)
    expect(await dns.txt(`_bag.acme.${TEST_ZONE}`)).toEqual([[`real _bag.acme.${TEST_ZONE}`]])
    setTestZone(ON)
    expect(await dns.txt(`_bag.acme.${TEST_ZONE}`)).toEqual([['v=bag1; key=ed25519:aa']])
    expect(await dns.txt(`_bag.okok.${TEST_ZONE}.`)).toEqual([['v=bag1;', ' key=ed25519:bb']])
    expect(await dns.txt(TEST_ZONE)).toEqual([['zone']])
    expect(await dns.txt(`acme.${TEST_ZONE}`)).toEqual([])
    expect(await dns.txt('_bag.acme.com')).toEqual([['real _bag.acme.com']])
  })
})

describe('createRecordSource under the switch', () => {
  const asked: { url: string; connect: string | null }[] = []
  const get: OriginGet = async (url, connect) => {
    asked.push({ url, connect })
    return { status: 200, body: new TextEncoder().encode('{}') }
  }
  const guard = new RelayGuard({ own: [], lookup: async () => ['93.184.216.34'] })

  it("fetches a mapped domain's records at its loopback origin with no guard; any other domain as before", async () => {
    const source = createRecordSource({ fetchRecord: async () => null }, { get, dns: real })
    asked.length = 0
    await source.wellKnown('acme.pilot.bag.dev', guard)
    setTestZone(ON)
    await source.wellKnown('acme.pilot.bag.dev', guard)
    await source.handleRecord?.('bag.acme.pilot.bag.dev', 'jane-claude@acme.pilot.bag.dev', guard)
    await source.wellKnown('okok.pilot.bag.dev', guard)
    await source.wellKnown('acme.com', guard)
    expect(asked).toEqual([
      { url: 'https://acme.pilot.bag.dev/.well-known/bag/address.json', connect: '93.184.216.34' },
      // The request names the host (Host: <host>:<port>), as bag enterprise's origin serves by it, at the loopback address.
      { url: 'http://acme.pilot.bag.dev:8788/.well-known/bag/address.json', connect: '127.0.0.1' },
      {
        url: 'http://bag.acme.pilot.bag.dev:8788/.well-known/bag/handles/jane-claude.json',
        connect: '127.0.0.1',
      },
      { url: 'https://okok.pilot.bag.dev/.well-known/bag/address.json', connect: '93.184.216.34' },
      { url: 'https://acme.com/.well-known/bag/address.json', connect: '93.184.216.34' },
    ])
    expect(await source.txt?.(`_bag.acme.${TEST_ZONE}`)).toEqual([['v=bag1; key=ed25519:aa']])
    expect(testZoneOrigin('ACME.pilot.bag.dev.')).toBe('http://127.0.0.1:8788')
    expect(testZoneOrigin('bag.acme.pilot.bag.dev')).toBe('http://127.0.0.1:8788')
    expect(testZoneOrigin('bag.okok.pilot.bag.dev')).toBeNull()
    setTestZone({ file: ZONE, origins: new Map([['okok.pilot.bag.dev', 'http://[::1]:8789']]) })
    expect(testZoneFetch('bag.okok.pilot.bag.dev', '/x')).toEqual({
      url: 'http://bag.okok.pilot.bag.dev:8789/x',
      connect: '::1',
    })
    expect(testZoneFetch('acme.pilot.bag.dev', '/x')).toBeNull()
  })
})

describe('RelayGuard under the switch', () => {
  it('lets a loopback literal through while on, and refuses it while off; private addresses and names stay refused', async () => {
    const guard = new RelayGuard({ own: [], lookup: async () => ['127.0.0.1'] })
    const range = async (url: string) => (await guard.refusal(url))?.range ?? null
    expect(await range('http://127.0.0.1:7777/')).toBe('loopback')
    setTestZone(ON)
    expect(await range('http://127.0.0.1:7777/')).toBeNull()
    expect(await range('http://[::1]:7777/')).toBeNull()
    expect(await guard.connectTo('http://127.0.0.1:7777/')).toBe('127.0.0.1')
    expect(await range('http://10.0.0.1:7777/')).toBe('private')
    expect(await range('http://localhost:7777/')).toBe('loopback')
    expect(await range('http://relay.example:7777/')).toBe('loopback')
  })
})
