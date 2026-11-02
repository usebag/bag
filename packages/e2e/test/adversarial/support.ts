import { mkdtempSync, rmSync } from 'node:fs'
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { type AddressInfo, connect, createServer, type Server, type Socket } from 'node:net'
import { networkInterfaces, tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  type BuiltEnvelope,
  buildEnvelope,
  classifyIp,
  type Hop,
  type NetCategory,
  newThread,
  type SigningKey,
  serializeRecord,
  signFetchAuth,
  signSubscribe,
  type TimeWindow,
  utf8,
} from '@usebag/core'
import { coreRng, subscribeUrl, systemRng } from '@usebag/edge'
import { onTestFinished } from 'vitest'
import {
  now,
  type Party,
  type RelayHandle,
  sleep,
  startRelay,
  untilSecond,
  withSpawnedRelays,
} from '../harness.ts'

// Shared helpers of the relay adversarial set (test/adversarial/relay-*.test.ts). Everything here talks
// to 127.0.0.1, to an address this Mac holds on one of its own interfaces (read at test time), or to nothing: no line
// may open a connection that leaves this Mac. The harness (../harness.ts) is read,
// never edited; what it lacks for these rows (a raw socket, a WebSocket client that can withhold pongs or send pings,
// a well-known stub that answers a chosen status, a relay with a chosen --ttl and --skew and extra flags) lives here.

export const DEADLINE = 15_000

// --- the relay ---------------------------------------------------------------------------------------------------

/**
 * A relay spawned from AC_RELAY_CMD (never AC_RELAY_URL: the flags are each row's point) with `window` as its --ttl
 * and --skew and `args` after them, in a temporary directory of its own; stopped and removed when the test ends, its
 * stderr printed when the test failed. The harness's world() fixes --ttl and --skew at the defaults, which H3 cannot
 * use, so this calls startRelay itself.
 */
export async function spawnRelay(
  name: string,
  args: readonly string[] = [],
  window?: TimeWindow,
): Promise<RelayHandle> {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-adv-${name}-`))
  const relay = await withSpawnedRelays(() => startRelay(dir, window, args))
  onTestFinished(async (ctx) => {
    if (ctx.task.result?.state === 'fail') {
      console.error(`adversarial ${name} failed; relay stderr:\n${relay.stderr()}`)
    }
    await relay.stop()
    if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
  })
  return relay
}

/** The relay's JSON log lines, each its fields plus its timestamp in milliseconds. */
export function events(relay: RelayHandle): (Record<string, unknown> & { readonly at: number })[] {
  return relay
    .stderr()
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => {
      const line = JSON.parse(l) as { timestamp: string; fields: Record<string, unknown> }
      return { ...line.fields, at: Date.parse(line.timestamp) }
    })
}

/** The port of a relay URL http://127.0.0.1:<port>. */
export function portOf(url: string): number {
  return Number(new URL(url).port)
}

// --- envelopes, records and the relay's API ----------------------------------------------------------------------

/** A sealed chat envelope from `from` to `to`, signed now (or at `ts`), under `auth` (default self-rooted). */
export function envelope(
  from: Party,
  to: readonly Party[],
  o: { readonly auth?: readonly Hop[]; readonly ts?: number; readonly body?: unknown } = {},
): BuiltEnvelope {
  const rng = coreRng(systemRng)
  return buildEnvelope({
    from: from.signing,
    to: to.map((p) => ({ address: p.address, sealingKey: p.sealing.publicKey })),
    type: 'chat.v1',
    thread: newThread(rng),
    body: o.body ?? {},
    ts: o.ts ?? now(),
    rng,
    ...(o.auth === undefined ? {} : { auth: o.auth }),
  })
}

/** The same envelope with its outer signature replaced by 64 zero bytes: its id still holds (the id covers no sig). */
export function unsigned(built: BuiltEnvelope): Uint8Array {
  const value = JSON.parse(new TextDecoder().decode(built.bytes)) as Record<string, unknown>
  return utf8(JSON.stringify({ ...value, sig: '0'.repeat(128) }))
}

/** The same envelope with its id's last hex digit changed: `bad-id` at step 3, before any limit. */
export function wrongId(built: BuiltEnvelope): Uint8Array {
  const value = JSON.parse(new TextDecoder().decode(built.bytes)) as Record<string, unknown>
  const id = value.id as string
  return utf8(JSON.stringify({ ...value, id: `${id.slice(0, -1)}${id.endsWith('0') ? '1' : '0'}` }))
}

/** A raw POST of bytes to /v0/publish: the status, the JSON answer and Retry-After. */
export async function post(
  url: string,
  bytes: Uint8Array,
): Promise<{ readonly status: number; readonly body: unknown; readonly retryAfter: string | null }> {
  const res = await fetch(`${url}/v0/publish`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: bytes,
    signal: AbortSignal.timeout(DEADLINE),
  })
  const text = await res.text()
  let body: unknown = text
  try {
    body = JSON.parse(text)
  } catch {
    // not JSON: kept as text, so an assertion shows what came
  }
  return { status: res.status, body, retryAfter: res.headers.get('retry-after') }
}

/** Publishes records raw and asserts nothing: the statuses, in order. */
export async function publishRecords(
  url: string,
  records: readonly Parameters<typeof serializeRecord>[0][],
): Promise<number[]> {
  const out: number[] = []
  for (const r of records) out.push((await post(url, serializeRecord(r))).status)
  return out
}

/** GET /v0/fetch/<id> signed by `key` now: the status and the bytes. */
export async function fetchEnvelope(
  url: string,
  key: SigningKey,
  id: string,
): Promise<{ readonly status: number; readonly bytes: Uint8Array }> {
  const ts = now()
  const res = await fetch(`${url}/v0/fetch/${id}`, {
    headers: { 'ac-signer': key.address, 'ac-ts': String(ts), 'ac-sig': signFetchAuth(key, id, ts, url) },
    signal: AbortSignal.timeout(DEADLINE),
  })
  return { status: res.status, bytes: new Uint8Array(await res.arrayBuffer()) }
}

/** GET /v0/health: the status and how long it took, in milliseconds. */
export async function health(url: string): Promise<{ readonly status: number; readonly ms: number }> {
  const t = performance.now()
  const res = await fetch(`${url}/v0/health`, { signal: AbortSignal.timeout(5_000) })
  await res.arrayBuffer()
  return { status: res.status, ms: performance.now() - t }
}

/**
 * Subscribes as the mailbox key with `cursor` and collects frames for `ms`: the ok frame's cursor (the relay resumes
 * after min(cursor, the mailbox's last cursor), so a huge cursor reads the last cursor given out) and the env frames'
 * cursors. Uses Node's WebSocket, which answers pings itself.
 */
export async function subscribeFor(
  url: string,
  key: SigningKey,
  cursor: number | null,
  ms: number,
): Promise<{ readonly ok: number | null; readonly env: number[]; readonly errors: string[] }> {
  const ws = new WebSocket(subscribeUrl(url))
  const out = { ok: null as number | null, env: [] as number[], errors: [] as string[] }
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      ws.close()
      resolve()
    }, ms)
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as {
        t: string
        nonce?: string
        cursor?: number
        error?: string
      }
      if (f.t === 'challenge') {
        const sig = signSubscribe(key, f.nonce as string, key.address, cursor)
        ws.send(
          JSON.stringify({ t: 'auth', mailbox: key.address, signer: key.address, auth: [], cursor, sig }),
        )
      } else if (f.t === 'ok') out.ok = f.cursor as number
      else if (f.t === 'env') out.env.push(f.cursor as number)
      else if (f.t === 'error') out.errors.push(f.error as string)
    })
    ws.addEventListener('close', () => {
      clearTimeout(timer)
      resolve()
    })
  })
  return out
}

// --- time --------------------------------------------------------------------------------------------------------

/** Waits for the start of the next fixed window of `length` seconds (the relay aligns its rate windows so). */
export async function nextWindow(length: number): Promise<number> {
  const start = now() - (now() % length) + length
  await untilSecond(start)
  return start
}

/** Seconds from the Unix second `t` to the next 00:00 UTC. */
export function secondsToMidnight(t: number): number {
  return 86_400 - (t % 86_400)
}

// --- raw sockets -------------------------------------------------------------------------------------------------

/** A raw TCP connection: what it received, and when (ms after connect) it closed; destroyed at the test's end. */
export interface RawConn {
  readonly socket: Socket
  readonly connectedAt: number
  received(): Buffer
  /** Milliseconds from connect to close, or null while open. */
  closedAfter(): number | null
  /** Resolves with closedAfter() once closed, or null after `ms`. */
  closed(ms: number): Promise<number | null>
}

export function rawConn(port: number, host = '127.0.0.1'): Promise<RawConn> {
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host })
    const chunks: Buffer[] = []
    let connectedAt = 0
    let closedAt: number | null = null
    const waiters: (() => void)[] = []
    socket.on('data', (d: Buffer) => chunks.push(d))
    socket.on('error', () => {
      // a reset is a close; closedAfter says when
    })
    socket.on('close', () => {
      closedAt = performance.now()
      for (const w of waiters.splice(0)) w()
    })
    onTestFinished(() => {
      socket.destroy()
    })
    socket.once('connect', () => {
      connectedAt = performance.now()
      const conn: RawConn = {
        socket,
        connectedAt,
        received: () => Buffer.concat(chunks),
        closedAfter: () => (closedAt === null ? null : closedAt - connectedAt),
        closed: (ms) =>
          new Promise((done) => {
            if (closedAt !== null) return done(closedAt - connectedAt)
            const timer = setTimeout(() => done(null), ms)
            waiters.push(() => {
              clearTimeout(timer)
              done((closedAt as number) - connectedAt)
            })
          }),
      }
      resolve(conn)
    })
    socket.once('error', (e) => {
      if (connectedAt === 0) reject(e)
    })
  })
}

/** Writes `text` one byte every `everyMs` until the socket closes or `stop()` is called. */
export function drip(conn: RawConn, text: string, everyMs: number): { stop(): void } {
  let i = 0
  const timer = setInterval(() => {
    if (conn.closedAfter() !== null || i >= text.length) return clearInterval(timer)
    conn.socket.write(text[i++] as string)
  }, everyMs)
  onTestFinished(() => clearInterval(timer))
  return { stop: () => clearInterval(timer) }
}

/** The status line and headers of the first HTTP response in `bytes`, and its body; null when there is none. */
export function parseResponse(
  bytes: Buffer,
): { readonly status: number; readonly headers: Record<string, string>; readonly body: string } | null {
  const text = bytes.toString('latin1')
  const end = text.indexOf('\r\n\r\n')
  if (!text.startsWith('HTTP/1.1 ') || end < 0) return null
  const [line, ...rest] = text.slice(0, end).split('\r\n')
  const headers: Record<string, string> = {}
  for (const h of rest) {
    const i = h.indexOf(':')
    headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim()
  }
  return { status: Number((line as string).split(' ')[1]), headers, body: text.slice(end + 4) }
}

// --- a WebSocket client over a raw socket ------------------------------------------------------------------------

/** One frame the relay sent, and when (ms after the upgrade). */
export interface WsFrame {
  readonly at: number
  readonly opcode: number
  readonly payload: Buffer
}

/**
 * A minimal RFC 6455 client on a raw socket, because Node's WebSocket answers every ping by itself and cannot send
 * one: `autoPong` false makes a subscriber that withholds pongs (H8's silent one), and ping() sends a client ping
 * (H7's burst before the auth frame). Client frames are masked with a fixed key (V2: no randomness needed here).
 */
export interface RawWs {
  readonly frames: WsFrame[]
  /** The text frames, parsed as JSON. */
  texts(): Record<string, unknown>[]
  pings(): number
  /** The close frame's code and when it came (ms after the upgrade), or null. */
  close(): { readonly code: number; readonly reason: string; readonly at: number } | null
  /** When the TCP connection closed (ms after the upgrade), or null. */
  endedAt(): number | null
  sendText(text: string): void
  ping(): void
  /** Resolves once a text frame satisfies `test`, or throws after `ms`. */
  nextText(test: (f: Record<string, unknown>) => boolean, ms?: number): Promise<Record<string, unknown>>
  /** Resolves with close() once the relay closes, or null after `ms`. */
  closed(ms: number): Promise<{ readonly code: number; readonly reason: string; readonly at: number } | null>
}

const MASK = Buffer.from([0x5a, 0x17, 0xc3, 0x2e])

function frame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length
  const head = len < 126 ? Buffer.from([0x80 | opcode, 0x80 | len]) : Buffer.alloc(4)
  if (len >= 126) {
    if (len > 0xffff) throw new Error('frame too long for this client')
    head[0] = 0x80 | opcode
    head[1] = 0x80 | 126
    head.writeUInt16BE(len, 2)
  }
  const masked = Buffer.alloc(len)
  for (let i = 0; i < len; i++) masked[i] = (payload[i] as number) ^ (MASK[i % 4] as number)
  return Buffer.concat([head, MASK, masked])
}

export async function rawWs(url: string, o: { readonly autoPong: boolean }): Promise<RawWs> {
  const conn = await rawConn(portOf(url))
  const key = Buffer.from(systemRng.bytes(16)).toString('base64')
  conn.socket.write(
    `GET /v0/subscribe HTTP/1.1\r\nHost: 127.0.0.1:${portOf(url)}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  )
  const frames: WsFrame[] = []
  let opened = 0
  let buffer = Buffer.alloc(0)
  let upgraded = false
  let closeFrame: { code: number; reason: string; at: number } | null = null
  let ended: number | null = null
  const watchers: (() => void)[] = []
  const wake = (): void => {
    for (const w of watchers.splice(0)) w()
  }
  const parse = (): void => {
    for (;;) {
      if (buffer.length < 2) return
      const b0 = buffer[0] as number
      const b1 = buffer[1] as number
      let len = b1 & 0x7f
      let off = 2
      if (len === 126) {
        if (buffer.length < 4) return
        len = buffer.readUInt16BE(2)
        off = 4
      } else if (len === 127) {
        if (buffer.length < 10) return
        len = Number(buffer.readBigUInt64BE(2))
        off = 10
      }
      if (buffer.length < off + len) return
      const payload = buffer.subarray(off, off + len)
      buffer = buffer.subarray(off + len)
      const opcode = b0 & 0x0f
      const at = performance.now() - opened
      frames.push({ at, opcode, payload: Buffer.from(payload) })
      if (opcode === 0x9 && o.autoPong && ended === null) conn.socket.write(frame(0xa, Buffer.from(payload)))
      if (opcode === 0x8 && closeFrame === null) {
        closeFrame = {
          code: payload.length >= 2 ? payload.readUInt16BE(0) : 1005,
          reason: payload.subarray(2).toString('utf8'),
          at,
        }
      }
      wake()
    }
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no 101 within 5 s')), 5_000)
    conn.socket.on('data', (d: Buffer) => {
      buffer = Buffer.concat([buffer, d])
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n')
        if (end < 0) return
        const head = buffer.subarray(0, end).toString('latin1')
        if (!head.startsWith('HTTP/1.1 101')) {
          clearTimeout(timer)
          return reject(new Error(`upgrade refused: ${head.split('\r\n')[0]}`))
        }
        upgraded = true
        opened = performance.now()
        buffer = buffer.subarray(end + 4)
        clearTimeout(timer)
        resolve()
      }
      parse()
    })
  })
  conn.socket.on('close', () => {
    ended = performance.now() - opened
    wake()
  })
  const texts = (): Record<string, unknown>[] =>
    frames.filter((f) => f.opcode === 0x1).map((f) => JSON.parse(f.payload.toString('utf8')))
  return {
    frames,
    texts,
    pings: () => frames.filter((f) => f.opcode === 0x9).length,
    close: () => closeFrame,
    endedAt: () => ended,
    sendText: (text) => {
      if (ended === null) conn.socket.write(frame(0x1, Buffer.from(text, 'utf8')))
    },
    ping: () => {
      if (ended === null) conn.socket.write(frame(0x9, Buffer.from('h7')))
    },
    nextText: async (test, ms = 5_000) => {
      const end = Date.now() + ms
      for (;;) {
        const hit = texts().find(test)
        if (hit !== undefined) return hit
        if (Date.now() > end || ended !== null) throw new Error('no such text frame')
        await new Promise<void>((r) => {
          watchers.push(r)
          setTimeout(r, 50)
        })
      }
    },
    closed: async (ms) => {
      const end = Date.now() + ms
      while (closeFrame === null && ended === null && Date.now() < end) {
        await new Promise<void>((r) => {
          watchers.push(r)
          setTimeout(r, 50)
        })
      }
      return closeFrame
    },
  }
}

/** Answers the challenge as the mailbox key with cursor null: sends the auth frame and waits for the ok frame. */
export async function authenticate(ws: RawWs, key: SigningKey): Promise<void> {
  const challenge = await ws.nextText((f) => f.t === 'challenge')
  const sig = signSubscribe(key, challenge.nonce as string, key.address, null)
  ws.sendText(
    JSON.stringify({ t: 'auth', mailbox: key.address, signer: key.address, auth: [], cursor: null, sig }),
  )
  await ws.nextText((f) => f.t === 'ok' || f.t === 'error')
}

// --- listeners ---------------------------------------------------------------------------------------------------

/** A TCP listener that counts and drops every connection it accepts, with each peer's address. */
export interface CountingListener {
  readonly host: string
  readonly port: number
  count(): number
  readonly peers: string[]
}

export async function countingListener(host: string): Promise<CountingListener> {
  const peers: string[] = []
  const server: Server = createServer((socket) => {
    peers.push(`${socket.remoteAddress}:${socket.remotePort}`)
    socket.destroy()
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, host, resolve)
  })
  onTestFinished(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const { port } = server.address() as AddressInfo
  return { host, port, count: () => peers.length, peers }
}

/** A node:http server on 127.0.0.1 that answers with `handler` and counts requests by path. */
export async function httpStub(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ readonly port: number; readonly origin: string; requests(path?: string): number }> {
  const seen: string[] = []
  const server = createHttpServer((req, res) => {
    seen.push(req.url ?? '')
    handler(req, res)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  onTestFinished(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
  )
  const { port } = server.address() as AddressInfo
  return {
    port,
    origin: `127.0.0.1:${port}`,
    requests: (path) => (path === undefined ? seen.length : seen.filter((p) => p === path).length),
  }
}

// --- this Mac's own addresses ------------------------------------------------------------------

/**
 * The first address of `category` (the core classifier's verdict) assigned to one of this Mac's interfaces, read
 * now; null when there is none. A target that is the Mac's own address never leaves the Mac.
 */
export function ownAddress(
  category: NetCategory,
  family: 'IPv4' | 'IPv6',
): { readonly address: string; readonly iface: string } | null {
  for (const [iface, list] of Object.entries(networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family !== family || (a.family === 'IPv6' && (a.scopeid ?? 0) !== 0)) continue
      if (classifyIp(a.address) === category) return { address: a.address, iface }
    }
  }
  return null
}

export { sleep }
