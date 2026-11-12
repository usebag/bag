// JSON-RPC 2.0 messages as newline-delimited JSON, the framing of MCP's stdio transport and of the service's socket
// (docs/bag-service.md). One message per line; a line that is not a JSON object is dropped and reported, never passed.

/** A JSON-RPC id: the spec allows a string or a number (null only in an error to a request that could not be read). */
export type Id = string | number

/** A JSON-RPC message, kept as its parsed object: the shim relays what it does not handle without reshaping it. */
export interface Message {
  readonly jsonrpc: '2.0'
  readonly id?: Id | null
  readonly method?: string
  readonly params?: Record<string, unknown>
  readonly result?: unknown
  readonly error?: { readonly code: number; readonly message: string; readonly data?: unknown }
}

/** A request has a method and an id; a notification a method and no id; a response an id and a result or error. */
export const isRequest = (m: Message): boolean =>
  typeof m.method === 'string' && m.id !== undefined && m.id !== null
export const isNotification = (m: Message): boolean => typeof m.method === 'string' && m.id === undefined
export const isResponse = (m: Message): boolean =>
  m.method === undefined && m.id !== undefined && ('result' in m || 'error' in m)

/** The longest line either side may send, in bytes (the contract's 4 MiB): past it the stream is closed. */
export const MAX_LINE = 4 * 1024 * 1024

/** Thrown by a Lines whose buffered line passed MAX_LINE. */
export class LineTooLong extends Error {}

/**
 * Splits a byte stream into lines and parses each. push takes a chunk and returns the messages it completed, with
 * a note per line it dropped. A trailing \r (a terminal's line end) is stripped. Bytes are buffered as bytes, so a
 * UTF-8 character split across two chunks decodes whole.
 */
export class Lines {
  #parts: Buffer[] = []
  #size = 0
  readonly #max: number

  constructor(max = MAX_LINE) {
    this.#max = max
  }

  push(chunk: Buffer | string): { messages: Message[]; dropped: string[] } {
    const messages: Message[] = []
    const dropped: string[] = []
    let bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
    for (let nl = bytes.indexOf(0x0a); nl !== -1; nl = bytes.indexOf(0x0a)) {
      this.#parts.push(bytes.subarray(0, nl))
      const line = Buffer.concat(this.#parts).toString('utf8').replace(/\r$/, '')
      this.#parts = []
      this.#size = 0
      bytes = bytes.subarray(nl + 1)
      if (line.trim() === '') continue
      const m = parse(line)
      if (m === null) dropped.push(line.length > 80 ? `${line.slice(0, 80)}...` : line)
      else messages.push(m)
    }
    if (bytes.length > 0) {
      this.#size += bytes.length
      if (this.#size > this.#max) throw new LineTooLong(`a line passed ${this.#max} bytes`)
      this.#parts.push(bytes)
    }
    return { messages, dropped }
  }
}

/** One line as a message: a JSON object with jsonrpc "2.0", else null. */
export function parse(line: string): Message | null {
  let v: unknown
  try {
    v = JSON.parse(line)
  } catch {
    return null
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null
  return (v as { jsonrpc?: unknown }).jsonrpc === '2.0' ? (v as Message) : null
}

/** A message as one line, newline included. */
export const frame = (m: Message): string => `${JSON.stringify(m)}\n`

/** A JSON-RPC error response. */
export function errorOf(id: Id | null, code: number, message: string, data?: unknown): Message {
  return { jsonrpc: '2.0', id, error: data === undefined ? { code, message } : { code, message, data } }
}

/** A JSON-RPC result response. */
export const resultOf = (id: Id, result: unknown): Message => ({ jsonrpc: '2.0', id, result })
