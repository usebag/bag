import { serializeRecord } from '@usebag/core'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  createRecordSource,
  httpGet,
  type OriginGet,
  WELL_KNOWN_PATH,
  wellKnownUrl,
} from '../src/adapters/well-known.ts'
import { GuardRefused, RelayGuard } from '../src/net.ts'
import { addressRecord, P } from './support/fixtures.ts'
import { startHttp, type TestServer } from './support/http.ts'

let server: TestServer
beforeAll(async () => {
  server = await startHttp()
})
afterAll(() => server.close())

const noRelay = { fetchRecord: async () => null }

describe('well-known: an org address record at https://<domain>/.well-known/bag/address.json', () => {
  it('builds the https URL, http only with the test-only option, and refuses anything but a host name', () => {
    expect(wellKnownUrl('acme.com')).toBe('https://acme.com/.well-known/bag/address.json')
    expect(wellKnownUrl('127.0.0.1:8080', true)).toBe('http://127.0.0.1:8080/.well-known/bag/address.json')
    for (const d of [
      '',
      'a/b',
      'u@acme.com',
      'Acme.com',
      '-acme.com',
      'acme.com.',
      'acme.com?x',
      'acme.com:123456',
      'https://acme.com',
    ]) {
      expect(() => wellKnownUrl(d), d).toThrow(/^resolve-failed: /)
    }
  })

  it('reads the record from a local stub over http, when allowed for the test', async () => {
    const record = serializeRecord(addressRecord(P.org))
    server.handle = (req, res) => {
      if (req.url === WELL_KNOWN_PATH) res.writeHead(200).end(record)
      else res.writeHead(404).end()
    }
    const host = server.url.slice('http://'.length)
    const source = createRecordSource(noRelay, { allowInsecureHttp: true })
    expect(await source.wellKnown(host)).toEqual(record)
    server.handle = (_req, res) => {
      res.writeHead(404).end()
    }
    await expect(source.wellKnown(host)).rejects.toThrow(/^resolve-failed: .* answered 404$/)
    server.handle = (_req, res) => {
      res.writeHead(301, { location: `${server.url}/elsewhere` }).end()
    }
    await expect(source.wellKnown(host)).rejects.toThrow(/answered 301$/)
  })

  it('fetches handle records at the origin: 200 the bytes, 404 null, any other status resolve-failed; no guard on the test-only http', async () => {
    const record = new TextEncoder().encode('{"kind":"handle"}')
    server.handle = (req, res) => {
      if (req.url === '/.well-known/bag/handles/jane.json') res.writeHead(200).end(record)
      else if (req.url === '/.well-known/bag/handles/boom.json') res.writeHead(500).end()
      else res.writeHead(404).end()
    }
    const host = server.url.slice('http://'.length)
    // A guard that would refuse the loopback stub: the test-only http does not consult it (the e2e harness's stubs).
    const guard = new RelayGuard({ own: [] })
    const source = createRecordSource(noRelay, { allowInsecureHttp: true })
    expect(await source.handleRecord?.(host, 'jane@acme.example', guard)).toEqual(record)
    expect(await source.handleRecord?.(host, 'nobody@acme.example', guard)).toBeNull()
    await expect(source.handleRecord?.(host, 'boom@acme.example', guard)).rejects.toThrow(
      /^resolve-failed: http:\/\/127\.0\.0\.1:\d+\/\.well-known\/bag\/handles\/boom\.json answered 500$/,
    )
    await expect(source.handleRecord?.('a/b', 'jane@acme.example')).rejects.toThrow(/^resolve-failed: /)
    await expect(source.handleRecord?.(host, 'Jane@acme.example')).rejects.toThrow(/^bad-address: /)
    expect(source.txt, 'the test-only http reads no DNS by default').toBeUndefined()
  })

  it('asks for https by default through the guard it is handed, and connects to the address the guard checked', async () => {
    const asked: [string, string | null][] = []
    const get: OriginGet = async (url, connect) => {
      asked.push([url, connect])
      return url.endsWith('missing.json')
        ? { status: 404, body: null }
        : { status: 200, body: new TextEncoder().encode('{}') }
    }
    const source = createRecordSource(
      { fetchRecord: async (url, address, kind) => new TextEncoder().encode(`${url} ${address} ${kind}`) },
      { get },
    )
    const publicGuard = new RelayGuard({ own: [], lookup: async () => ['203.0.113.9', '93.184.216.34'] })
    expect(new TextDecoder().decode(await source.wellKnown('acme.com', publicGuard))).toBe('{}')
    expect(await source.handleRecord?.('bag.acme.com', 'missing@acme.com', publicGuard)).toBeNull()
    // Without a guard (a resolver built without one), the host is connected to as it resolves.
    await source.wellKnown('acme.com')
    expect(asked).toEqual([
      ['https://acme.com/.well-known/bag/address.json', '203.0.113.9'],
      ['https://bag.acme.com/.well-known/bag/handles/missing.json', '203.0.113.9'],
      ['https://acme.com/.well-known/bag/address.json', null],
    ])
    // A host on the LAN is refused before any request.
    const lan = new RelayGuard({ own: [], lookup: async () => ['10.0.0.7'] })
    const refused = await source.wellKnown('intranet.acme.com', lan).catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(GuardRefused)
    expect((refused as GuardRefused).refusal.range).toBe('private')
    expect(asked).toHaveLength(3)
    expect(
      new TextDecoder().decode((await source.relayRecord('http://r', P.bob.address, 'key')) as Uint8Array),
    ).toBe(`http://r ${P.bob.address} key`)
  })

  it('reads TXT records through the system resolver by default, and through the Dns it is given', async () => {
    expect(typeof createRecordSource(noRelay).txt).toBe('function')
    const names: string[] = []
    const dns = {
      txt: async (name: string) => {
        names.push(name)
        return [['v=ac1; ', 'key=x']]
      },
    }
    const source = createRecordSource(noRelay, { dns, allowInsecureHttp: true })
    expect(await source.txt?.('_bag.acme.com')).toEqual([['v=ac1; ', 'key=x']])
    expect(names).toEqual(['_bag.acme.com'])
  })
})

describe('httpGet: one GET, pinned to the address the guard checked', () => {
  it('connects to the given address while the URL keeps its host name: no DNS is asked for acme.test', async () => {
    server.handle = (req, res) => {
      res.writeHead(200).end(`${req.headers.host} ${req.url}`)
    }
    const port = new URL(server.url).port
    const pinned = await httpGet(`http://acme.test:${port}/x`, '127.0.0.1', 5000, 1024)
    expect(pinned.status).toBe(200)
    expect(new TextDecoder().decode(pinned.body as Uint8Array)).toBe(`acme.test:${port} /x`)
    const direct = await httpGet(`${server.url}/y`, null, 5000, 1024)
    expect(new TextDecoder().decode(direct.body as Uint8Array)).toBe(`127.0.0.1:${port} /y`)
  })

  it('answers a status other than 200 without its body, follows no redirect, and caps the body', async () => {
    server.handle = (_req, res) => {
      res.writeHead(302, { location: '/elsewhere' }).end('moved')
    }
    expect(await httpGet(`${server.url}/z`, null, 5000, 1024)).toEqual({ status: 302, body: null })
    server.handle = (_req, res) => {
      res.writeHead(200).end('x'.repeat(2048))
    }
    await expect(httpGet(`${server.url}/big`, null, 5000, 1024)).rejects.toThrow(
      /^resolve-failed: .*\/big: a response over 1024 bytes$/,
    )
  })

  it('speaks TLS for https: a plain http server at the pinned address fails the request', async () => {
    const port = new URL(server.url).port
    await expect(httpGet(`https://acme.test:${port}/`, '127.0.0.1', 5000, 1024)).rejects.toThrow()
  })
})
