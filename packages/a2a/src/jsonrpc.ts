import { ERRORS, isRecord } from './protocol.ts'

// JSON-RPC 2.0 (https://www.jsonrpc.org/specification), as A2A 1.0's JSON-RPC binding uses it (section 9): one request
// object per call, an id that is a string or a number, and a response that holds `result` or `error`. A2A sends no
// notification and no batch, so a request without an id and a batch are both Invalid Request here.

export type JsonRpcId = string | number

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0'
  readonly id: JsonRpcId
  readonly method: string
  readonly params?: unknown
}

export interface JsonRpcError {
  readonly code: number
  readonly message: string
  readonly data?: unknown
}

export type JsonRpcResponse =
  | { readonly jsonrpc: '2.0'; readonly id: JsonRpcId | null; readonly result: unknown }
  | { readonly jsonrpc: '2.0'; readonly id: JsonRpcId | null; readonly error: JsonRpcError }

export const success = (id: JsonRpcId, result: unknown): JsonRpcResponse => ({ jsonrpc: '2.0', id, result })

export const failure = (id: JsonRpcId | null, code: number, message: string): JsonRpcResponse => ({
  jsonrpc: '2.0',
  id,
  error: { code, message },
})

const isId = (v: unknown): v is JsonRpcId =>
  typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v))

/** A checked request, or the error response a server answers in its place. */
export type Checked =
  | { readonly ok: true; readonly request: JsonRpcRequest }
  | { readonly ok: false; readonly response: JsonRpcResponse }

/** A request object checked, or the error response a server answers in its place. */
export function checkRequest(v: unknown): Checked {
  if (!isRecord(v)) {
    return { ok: false, response: failure(null, ERRORS.invalidRequest, 'a request is one object') }
  }
  const id = isId(v.id) ? v.id : null
  if (v.jsonrpc !== '2.0' || id === null || typeof v.method !== 'string' || v.method === '') {
    const why = 'a request has jsonrpc "2.0", an id that is a string or a number, and a method'
    return { ok: false, response: failure(id, ERRORS.invalidRequest, why) }
  }
  if (v.params !== undefined && !isRecord(v.params)) {
    return { ok: false, response: failure(id, ERRORS.invalidParams, 'params is an object') }
  }
  const request: JsonRpcRequest =
    v.params === undefined
      ? { jsonrpc: '2.0', id, method: v.method }
      : { jsonrpc: '2.0', id, method: v.method, params: v.params }
  return { ok: true, request }
}

/** Parses a request's text: Parse error for text that is not JSON, else as checkRequest. */
export function parseRequest(text: string): Checked {
  let v: unknown
  try {
    v = JSON.parse(text)
  } catch {
    return { ok: false, response: failure(null, ERRORS.parseError, 'the request is not JSON') }
  }
  return checkRequest(v)
}

/** True when the value is a JSON-RPC 2.0 response to the id: `result` or a well-formed `error`, never both. */
export function isResponseTo(v: unknown, id: JsonRpcId): v is JsonRpcResponse {
  if (!isRecord(v) || v.jsonrpc !== '2.0' || v.id !== id) return false
  const hasResult = 'result' in v
  const hasError = 'error' in v
  if (hasResult === hasError) return false
  if (hasResult) return true
  const e = v.error
  return isRecord(e) && Number.isInteger(e.code) && typeof e.message === 'string'
}
