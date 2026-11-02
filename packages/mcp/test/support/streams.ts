import type { Readable, Writable } from 'node:stream'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'

// An MCP client transport over a pair of streams: newline-delimited JSON-RPC, as the stdio transport speaks it. The
// tests run the server's stdio on streams they hold (in process, or a child's pipes), so they can read every byte
// the server writes to its stdout.

export class StreamClientTransport implements Transport {
  onclose?: () => void
  onerror?: (error: Error) => void
  onmessage?: (message: JSONRPCMessage) => void
  readonly #toServer: Writable
  readonly #fromServer: Readable
  #buffer = ''

  constructor(toServer: Writable, fromServer: Readable) {
    this.#toServer = toServer
    this.#fromServer = fromServer
  }

  async start(): Promise<void> {
    this.#fromServer.on('data', (chunk: Buffer) => {
      this.#buffer += chunk.toString('utf8')
      for (let i = this.#buffer.indexOf('\n'); i >= 0; i = this.#buffer.indexOf('\n')) {
        const line = this.#buffer.slice(0, i)
        this.#buffer = this.#buffer.slice(i + 1)
        this.onmessage?.(JSON.parse(line) as JSONRPCMessage)
      }
    })
  }

  async send(message: JSONRPCMessage): Promise<void> {
    this.#toServer.write(`${JSON.stringify(message)}\n`)
  }

  async close(): Promise<void> {
    this.#toServer.end()
    this.onclose?.()
  }
}

/** Every line of what a stream carried, and whether each parses as a JSON-RPC 2.0 message; a trailing partial line fails. */
export function frames(bytes: Buffer): { readonly lines: number; readonly bad: readonly string[] } {
  const text = bytes.toString('utf8')
  const parts = text.split('\n')
  const tail = parts.pop() as string
  const bad: string[] = tail === '' ? [] : [`a partial line of ${tail.length} characters`]
  for (const [i, line] of parts.entries()) {
    let v: unknown
    try {
      v = JSON.parse(line)
    } catch {
      bad.push(`line ${i + 1} is not JSON`)
      continue
    }
    if (typeof v !== 'object' || v === null || (v as { jsonrpc?: unknown }).jsonrpc !== '2.0') {
      bad.push(`line ${i + 1} is not a JSON-RPC 2.0 message`)
    }
  }
  return { lines: parts.length, bad }
}
