import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { WELL_KNOWN_PATH } from '@usebag/edge'

// The e2e harness's well-known stub: a node:http server on 127.0.0.1 that serves an org's address record at
// /.well-known/bag/address.json, as https://<domain>/ would. Edges reach it through createRecordSource with
// the test-only allowInsecureHttp, at the "domain" 127.0.0.1:<port>.

export interface WellKnownStub {
  /** The domain an edge trusts: 127.0.0.1:<port>. */
  readonly domain: string
  /** The record bytes to serve, computed per request (so a record can be signed at request time); null for 404. */
  serve(record: (() => Uint8Array) | null): void
  /** How many times the record was asked for. */
  requests(): number
  close(): Promise<void>
}

export async function startWellKnown(): Promise<WellKnownStub> {
  let record: (() => Uint8Array) | null = null
  let requests = 0
  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === WELL_KNOWN_PATH && record !== null) {
      requests++
      res.writeHead(200, { 'content-type': 'application/json' }).end(record())
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not-found"}')
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return {
    domain: `127.0.0.1:${port}`,
    serve: (r) => {
      record = r
    },
    requests: () => requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
  }
}
