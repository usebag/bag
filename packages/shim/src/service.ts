// The shim's connection to the bag service: one unix socket, newline-delimited JSON-RPC both ways (frames.ts). The
// connection carries no key, store or token beyond the hello: the shim keeps nothing on disk.
import { createConnection, type Socket } from 'node:net'
import { frame, Lines, LineTooLong, type Message } from './frames.ts'

/** One open connection to the service. */
export interface Conn {
  /** Writes one message; false once the connection is closed (the message is dropped, never queued). */
  send(m: Message): boolean
  /** Ends the connection: a FIN after the queued bytes, then the socket is destroyed. Idempotent. */
  close(): void
}

/** What a connection reports: each message, each dropped line, and its one close (with the error, if any). */
export interface ConnEvents {
  message(m: Message): void
  dropped(line: string): void
  closed(error: NodeJS.ErrnoException | null): void
}

/** How the shim opens a connection; tests pass their own. Rejects with the connect error (ENOENT, ECONNREFUSED). */
export type Connect = (events: ConnEvents) => Promise<Conn>

/** Whether a connect error means "no service is listening": nothing there, or a stale socket nobody accepts on. */
export function absent(e: unknown): boolean {
  const code = (e as { code?: unknown } | null)?.code
  return code === 'ENOENT' || code === 'ECONNREFUSED' || code === 'ENOTSOCK' || code === 'EACCES'
}

/** Connects to the socket at path. */
export function socketConnect(path: string): Connect {
  return (events) =>
    new Promise<Conn>((resolve, reject) => {
      const socket: Socket = createConnection({ path })
      const lines = new Lines()
      let open = false
      let closed = false
      let failure: NodeJS.ErrnoException | null = null
      const conn: Conn = {
        send(m) {
          if (closed || socket.destroyed || !socket.writable) return false
          socket.write(frame(m))
          return true
        },
        close() {
          if (closed) return
          socket.end()
          socket.destroySoon()
        },
      }
      socket.on('connect', () => {
        open = true
        resolve(conn)
      })
      socket.on('data', (chunk: Buffer) => {
        let got: ReturnType<Lines['push']>
        try {
          got = lines.push(chunk)
        } catch (e) {
          if (!(e instanceof LineTooLong)) throw e
          failure = Object.assign(new Error(e.message), { code: 'ELINE' })
          socket.destroy()
          return
        }
        for (const d of got.dropped) events.dropped(d)
        for (const m of got.messages) {
          if (closed) return
          events.message(m)
        }
      })
      socket.on('error', (e: NodeJS.ErrnoException) => {
        failure = e
        if (!open) reject(e)
      })
      socket.on('close', () => {
        if (closed) return
        closed = true
        if (open) events.closed(failure)
      })
    })
}
