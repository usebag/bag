import { createHash } from 'node:crypto'
import { createServer, type IncomingMessage } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { Duplex } from 'node:stream'

// A minimal RFC 6455 server for tests only (Node has no WebSocket server, and the repository takes no ws
// dependency in the edge): the opening handshake, text frames both ways, close, ping. Enough to drive the global
// WebSocket client through a real socket.

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

function frame(opcode: number, payload: Buffer): Buffer {
  const n = payload.length
  let head: Buffer
  if (n < 126) {
    head = Buffer.from([0x80 | opcode, n])
  } else if (n < 65_536) {
    head = Buffer.from([0x80 | opcode, 126, n >> 8, n & 0xff])
  } else {
    head = Buffer.alloc(10)
    head[0] = 0x80 | opcode
    head[1] = 127
    head.writeBigUInt64BE(BigInt(n), 2)
  }
  return Buffer.concat([head, payload])
}

/** One accepted connection, as the server sees it. */
export class WsPeer {
  readonly path: string
  readonly received: string[] = []
  readonly #socket: Duplex
  readonly #listeners: ((text: string) => void)[] = []
  #buffer = Buffer.alloc(0)

  constructor(socket: Duplex, path: string) {
    this.#socket = socket
    this.path = path
    socket.on('data', (chunk: Buffer) => this.#data(chunk))
    socket.on('error', () => {})
  }

  onMessage(listener: (text: string) => void): void {
    this.#listeners.push(listener)
  }

  send(text: string): void {
    this.#socket.write(frame(0x1, Buffer.from(text, 'utf8')))
  }

  /** An orderly close (status 1000). */
  close(): void {
    this.#socket.end(frame(0x8, Buffer.from([0x03, 0xe8])))
  }

  /** An abrupt loss of the connection. */
  drop(): void {
    this.#socket.destroy()
  }

  #data(chunk: Buffer): void {
    this.#buffer = Buffer.concat([this.#buffer, chunk])
    for (;;) {
      const b = this.#buffer
      if (b.length < 2) return
      const opcode = (b[0] as number) & 0x0f
      const masked = ((b[1] as number) & 0x80) !== 0
      let length = (b[1] as number) & 0x7f
      let offset = 2
      if (length === 126) {
        length = b.readUInt16BE(2)
        offset = 4
      } else if (length === 127) {
        length = Number(b.readBigUInt64BE(2))
        offset = 10
      }
      const mask = masked ? b.subarray(offset, offset + 4) : Buffer.alloc(4)
      if (masked) offset += 4
      if (b.length < offset + length) return
      const payload = Buffer.from(b.subarray(offset, offset + length))
      for (let i = 0; i < payload.length; i++) payload[i] = (payload[i] as number) ^ (mask[i % 4] as number)
      this.#buffer = b.subarray(offset + length)
      if (opcode === 0x1) {
        const text = payload.toString('utf8')
        this.received.push(text)
        for (const l of this.#listeners) l(text)
      } else if (opcode === 0x8) {
        this.#socket.end(frame(0x8, payload.subarray(0, 2)))
      } else if (opcode === 0x9) {
        this.#socket.write(frame(0xa, payload))
      }
    }
  }
}

export interface WsServer {
  readonly url: string
  readonly peers: WsPeer[]
  close(): Promise<void>
}

/** Listens on 127.0.0.1, port 0, and hands each accepted connection to `onPeer`. */
export async function startWsServer(onPeer: (peer: WsPeer) => void): Promise<WsServer> {
  const peers: WsPeer[] = []
  const server = createServer((_req, res) => {
    res.writeHead(404).end()
  })
  server.on('upgrade', (req: IncomingMessage, socket: Duplex) => {
    const accept = createHash('sha1').update(`${req.headers['sec-websocket-key']}${GUID}`).digest('base64')
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    )
    const peer = new WsPeer(socket, req.url ?? '')
    peers.push(peer)
    onPeer(peer)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    peers,
    close: () =>
      new Promise<void>((resolve) => {
        for (const p of peers) p.drop()
        server.close(() => resolve())
      }),
  }
}
