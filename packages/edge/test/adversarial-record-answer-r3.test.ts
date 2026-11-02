import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createRelayClient } from '../src/adapters/http-relay.ts'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { RelayError } from '../src/ports.ts'
import { addressRecord, FakeClock, MemoryAuditSink, P, seededRng, T0 } from './support/fixtures.ts'
import { json, startHttp, type TestServer } from './support/http.ts'

// E1: the edge in process over a local HTTP relay stub, reading the relay's record
// answer {ok, kind, signer, iat, valid_until} (spec/SPEC.md §8.2). The edge parses the four fields with
// Number.isSafeInteger (packages/edge/src/adapters/http-relay.ts, the record branch of `publish`) and returns them
// through Edge.publishRecord (edge.ts:327-345). A hostile relay cannot push a value that overflows a clock compare or
// a non-numeric field past the type check. Predicted good behaviour:
//  (a) a safe-but-huge iat/valid_until (Number.MAX_SAFE_INTEGER) parses and is returned exactly, no NaN, no throw;
//  (b) a non-safe-integer iat is rejected as bad-shape with the 200 of the delivery kept on the RelayError;
//  (c) a missing or wrong-typed field is rejected the same way.
// E1 is a good-behaviour line with a V1 control; it asserts exact codes/values. If (a) ever misbehaves (throws, NaN,
// or a changed value) the assertion of the predicted good behaviour fails and that is the candidate finding, left red
// and reported, never flipped.

const MAX = Number.MAX_SAFE_INTEGER // 9007199254740991, the largest integer a JS number holds exactly

let server: TestServer
let store: SqliteStore
let edge: Edge

beforeAll(async () => {
  server = await startHttp()
  store = new SqliteStore(':memory:')
  // The stub is the edge's OWN relay (relays.urls), so the private-address guard always allows it (edge.ts:146-150,
  // "every relay call but those to the edge's own relays"); the real HTTP relay client does the POST and the parse.
  edge = new Edge({
    keys: P.bob.keys,
    store,
    relays: { client: createRelayClient({ timeoutMs: 5_000 }), urls: [server.url] },
    policy: { roots: [], types: [] },
    clock: new FakeClock(),
    rng: seededRng('e1'),
    audit: new MemoryAuditSink(),
  })
})

afterAll(async () => {
  await edge.stop()
  store.close()
  await server.close()
})

const RECORD = addressRecord(P.bob) // a record publish: its bytes carry a top-level `kind`

/** The RelayError a rejected publishRecord throws. */
async function rejection(p: Promise<unknown>): Promise<RelayError> {
  const e = await p.then(
    () => null,
    (x: unknown) => x,
  )
  expect(e, 'publishRecord was expected to reject').toBeInstanceOf(RelayError)
  return e as RelayError
}

describe('E1: the edge against a hostile relay record answer', () => {
  it('E1 V1 control: a well-formed record answer is parsed and returned by publishRecord', async () => {
    const answer = { kind: 'address', signer: P.bob.address, iat: T0, valid_until: T0 + 3600 }
    server.handle = (_req, res) => json(res, 200, { ok: true, ...answer })
    expect(await edge.publishRecord(RECORD)).toEqual([answer])
  })

  it('E1 (a): a safe-but-huge iat and valid_until (Number.MAX_SAFE_INTEGER) parse and are returned exactly, no NaN, no overflow, no throw', async () => {
    const answer = { kind: 'address', signer: P.bob.address, iat: MAX, valid_until: MAX }
    server.handle = (_req, res) => json(res, 200, { ok: true, ...answer })
    const got = await edge.publishRecord(RECORD)
    expect(got).toEqual([answer])
    // The exact values survived the round trip: no silent overflow and no NaN (Number.isSafeInteger let them through).
    const [record] = got
    expect([record?.iat, record?.valid_until]).toEqual([MAX, MAX])
    expect([Number.isNaN(record?.iat), Number.isNaN(record?.valid_until)]).toEqual([false, false])
  })

  it('E1 (b): a non-safe-integer iat (MAX_SAFE_INTEGER + 1, and 1e308) is rejected as bad-shape, the delivery 200 kept on the error', async () => {
    for (const iat of [MAX + 1, 1e308]) {
      server.handle = (_req, res) =>
        json(res, 200, { ok: true, kind: 'address', signer: P.bob.address, iat, valid_until: T0 })
      const e = await rejection(edge.publishRecord(RECORD))
      expect([e.code, e.status], String(iat)).toEqual(['bad-shape', 200])
    }
    // A non-safe-integer valid_until is refused the same way.
    server.handle = (_req, res) =>
      json(res, 200, { ok: true, kind: 'address', signer: P.bob.address, iat: T0, valid_until: MAX + 1 })
    const e = await rejection(edge.publishRecord(RECORD))
    expect([e.code, e.status]).toEqual(['bad-shape', 200])
  })

  it('E1 (c): a missing field (no valid_until) and a wrong-typed field (signer null, kind a number) are rejected as bad-shape, 200', async () => {
    const cases: Record<string, unknown>[] = [
      { ok: true, kind: 'address', signer: P.bob.address, iat: T0 }, // valid_until missing
      { ok: true, kind: 'address', signer: null, iat: T0, valid_until: T0 }, // signer not a string
      { ok: true, kind: 7, signer: P.bob.address, iat: T0, valid_until: T0 }, // kind not a string
    ]
    for (const body of cases) {
      server.handle = (_req, res) => json(res, 200, body)
      const e = await rejection(edge.publishRecord(RECORD))
      expect([e.code, e.status], JSON.stringify(body)).toEqual(['bad-shape', 200])
    }
  })
})
