import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { type AddressInfo, connect } from 'node:net'

// A tiny in-process HTTP server whose handler each test swaps, recording every request with its body.

export interface Seen {
  readonly method: string
  readonly url: string
  readonly headers: IncomingMessage['headers']
  readonly body: Buffer
}

export interface TestServer {
  readonly url: string
  readonly seen: Seen[]
  handle: (req: Seen, res: ServerResponse) => void
  close(): Promise<void>
}

export async function startHttp(): Promise<TestServer> {
  const seen: Seen[] = []
  const t: { handle: TestServer['handle'] } = {
    handle: (_req, res) => {
      res.writeHead(404).end()
    },
  }
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const s = {
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks),
      }
      seen.push(s)
      t.handle(s, res)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    get handle() {
      return t.handle
    },
    set handle(h) {
      t.handle = h
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
  }
}

const handedOut = new Set<number>()

/** True when a connect to 127.0.0.1:port is refused (nothing listens); false when anything accepts or answers. */
function refused(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port })
    socket.setTimeout(1000, () => {
      socket.destroy()
      resolve(false)
    })
    socket.once('connect', () => {
      socket.destroy()
      resolve(false)
    })
    socket.once('error', (e: NodeJS.ErrnoException) => resolve(e.code === 'ECONNREFUSED'))
  })
}

/**
 * A port on 127.0.0.1 that nothing listens on. It lies below the default ephemeral ranges (Linux 32768, macOS
 * 49152), so no `listen(0)` in a parallel test file is ever handed it, and it is probed with a real connect that
 * must be refused before it is returned. Each call returns a port not returned before in this process.
 */
export async function closedPort(): Promise<number> {
  const start = 20_000 + Math.floor(Math.random() * 10_000)
  for (let i = 0; i < 1000; i++) {
    const port = 20_000 + ((start - 20_000 + i) % 10_000)
    if (handedOut.has(port) || !(await refused(port))) continue
    handedOut.add(port)
    return port
  }
  throw new Error('closedPort: no refused port found in 20000-29999')
}

export function json(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify(body))
}
