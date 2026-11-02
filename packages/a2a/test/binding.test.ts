import { describe, expect, it } from 'vitest'
import {
  A2A_TYPE,
  jsonBytes,
  MAX_RPC_BYTES,
  readRequestBody,
  readResponseBody,
  requestBody,
  responseBody,
} from '../src/binding.ts'
import { failure, success } from '../src/jsonrpc.ts'

const request = { jsonrpc: '2.0', id: 7, method: 'GetTask', params: { id: 't' } } as const

describe('the binding: A2A JSON-RPC in the sealed body of an a2a.jsonrpc.v1 envelope', () => {
  it('names the type as the other profile types are named, and leaves room in a 64 KiB envelope', () => {
    expect(A2A_TYPE).toBe('a2a.jsonrpc.v1')
    expect(MAX_RPC_BYTES * 2).toBeLessThan(65_536)
    expect(jsonBytes({ t: 'é' })).toBe(10)
  })

  it('wraps a request with the version and reads it back; a body of another shape is Invalid Request', () => {
    expect(requestBody(request)).toEqual({ a2a: '1.0', request })
    expect(readRequestBody(requestBody(request))).toEqual({ ok: true, request })
    for (const body of [null, [], { a2a: 1, request }, { a2a: '1.0' }]) {
      const read = readRequestBody(body)
      expect(read.ok).toBe(false)
      expect(read.ok ? null : read.response).toMatchObject({ id: null, error: { code: -32600 } })
    }
    const bad = readRequestBody({ a2a: '1.0', request: { jsonrpc: '2.0', id: 1 } })
    expect(bad.ok ? null : bad.response).toMatchObject({ id: 1, error: { code: -32600 } })
  })

  it('a request of another A2A version is VersionNotSupportedError with its id', () => {
    const read = readRequestBody({ a2a: '0.3', request })
    expect(read.ok ? null : read.response).toEqual(
      failure(7, -32009, 'A2A version 0.3 is not supported; this agent speaks 1.0'),
    )
  })

  it('reads a response only when it answers the request id under version 1.0', () => {
    const answer = success(7, { id: 't' })
    expect(responseBody(answer)).toEqual({ a2a: '1.0', response: answer })
    expect(readResponseBody(responseBody(answer), 7)).toEqual(answer)
    expect(readResponseBody(responseBody(answer), 8)).toBeNull()
    expect(readResponseBody({ a2a: '0.3', response: answer }, 7)).toBeNull()
    expect(readResponseBody('x', 7)).toBeNull()
  })
})
