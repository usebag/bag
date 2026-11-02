import {
  type Checked,
  checkRequest,
  failure,
  isResponseTo,
  type JsonRpcId,
  type JsonRpcRequest,
  type JsonRpcResponse,
} from './jsonrpc.ts'
import { A2A_VERSION, ERRORS, isRecord } from './protocol.ts'

// The binding of A2A to bag: one A2A JSON-RPC call is one sealed envelope of the type A2A_TYPE, and its
// answer is the reply in the same thread, of the same type. The sealed content's `body` (spec/SPEC.md §5.2: any JSON
// value, defined by profiles) is this profile's:
//
//   request  {"a2a": "1.0", "request": <the JSON-RPC 2.0 request object, as the A2A client sent it>}
//   response {"a2a": "1.0", "response": <the JSON-RPC 2.0 response object>}
//
// `a2a` carries the one A2A service parameter the binding needs, the A2A-Version the client spoke. The method name,
// the params and the result are sealed with the rest: a relay sees the nine outer members of §5.1 and nothing else.
// The type is named as the repository's other profile types are (`group-key.v1`, `peer.request.v1`): dotted, with
// its version last; §5.2 needs no change, so packages/core and the edge are unchanged.

/** The sealed `type` of an A2A JSON-RPC request and of its reply. */
export const A2A_TYPE = 'a2a.jsonrpc.v1'

/**
 * The most bytes a JSON-RPC request or response may hold, as UTF-8 JSON. An envelope is at most 65,536 bytes
 * (spec/SPEC.md §5.1) and its sealed content travels as hex, twice its size, so 24 KiB leaves room for the wraps and
 * the outer members.
 */
export const MAX_RPC_BYTES = 24_576

export interface A2aRequestBody {
  readonly a2a: string
  readonly request: JsonRpcRequest
}

export interface A2aResponseBody {
  readonly a2a: string
  readonly response: JsonRpcResponse
}

/** The UTF-8 length of a value's JSON. */
export const jsonBytes = (v: unknown): number => Buffer.byteLength(JSON.stringify(v), 'utf8')

export const requestBody = (request: JsonRpcRequest): A2aRequestBody => ({ a2a: A2A_VERSION, request })

export const responseBody = (response: JsonRpcResponse): A2aResponseBody => ({ a2a: A2A_VERSION, response })

/** The request a sealed body holds, or the error response the agent answers in its place. */
export function readRequestBody(body: unknown): Checked {
  if (!isRecord(body) || typeof body.a2a !== 'string' || !('request' in body)) {
    const why = `an ${A2A_TYPE} body is {"a2a": <version>, "request": <a JSON-RPC request>}`
    return { ok: false, response: failure(null, ERRORS.invalidRequest, why) }
  }
  const checked = checkRequest(body.request)
  if (!checked.ok || body.a2a === A2A_VERSION) return checked
  const why = `A2A version ${body.a2a} is not supported; this agent speaks ${A2A_VERSION}`
  return { ok: false, response: failure(checked.request.id, ERRORS.versionNotSupported, why) }
}

/** The response a sealed reply holds when it answers the request id, else null. */
export function readResponseBody(body: unknown, id: JsonRpcId): JsonRpcResponse | null {
  if (!isRecord(body) || body.a2a !== A2A_VERSION) return null
  return isResponseTo(body.response, id) ? body.response : null
}
