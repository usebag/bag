import { describe, expect, it } from 'vitest'
import { party, until } from '../harness.ts'
import {
  authenticate,
  drip,
  events,
  health,
  parseResponse,
  portOf,
  type RawConn,
  rawConn,
  rawWs,
  sleep,
  spawnRelay,
} from './support.ts'
import { answered, loopLag, waitPings } from './support-timing.ts'

// H6, H7, H8: the connection front (crates/ac-relay/src/server.rs) and the
// subscriber's deadlines (crates/ac-relay/src/ws.rs), with the defaults (header 10 s, body 30 s, 68 connections, ping
// 30 s, idle 60 s) scaled down through the relay's flags (config.rs:174 and :179: each at least 1, idle at least twice
// ping). Every client and the health check share 127.0.0.1, so each cap is set with that in mind. Raw
// sockets and a raw WebSocket client (./support.ts) stand in for what the harness has none of.

const fmt = (ms: number | null) => (ms === null ? 'open' : `${(ms / 1000).toFixed(2)} s`)

/** min and max of a list of close times in ms, as "a to b s". */
const span = (list: readonly (number | null)[]) => {
  const done = list.filter((x): x is number => x !== null)
  return done.length === 0 ? 'none closed' : `${fmt(Math.min(...done))} to ${fmt(Math.max(...done))}`
}

describe('H6: the connection front', () => {
  it('H6a [--connections-per-ip 128 --header-timeout 2] 64 connections that never complete a request head are each closed at the header timeout; /v0/health answers 200 within 1 s throughout', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h6a', ['--connections-per-ip', '128', '--header-timeout', '2'])
    const port = portOf(relay.url)
    const conns: RawConn[] = await Promise.all(Array.from({ length: 64 }, () => rawConn(port)))
    // Half send an unfinished head at once, half drip one byte every 400 ms (a slow head).
    const head = 'GET /v0/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: '
    conns.forEach((c, i) => {
      if (i % 2 === 0) c.socket.write(head)
      else drip(c, `${head}${'a'.repeat(64)}`, 400)
    })
    const checks: { status: number; ms: number }[] = []
    const watchStart = performance.now()
    const watching = (async () => {
      const end = watchStart + 3_200
      while (performance.now() < end) {
        checks.push(await health(relay.url))
        await sleep(250)
      }
    })()
    const closes = await Promise.all(conns.map((c) => c.closed(6_000)))
    await watching
    // The receipt times below stay as a loose backstop; loopLag only reports how long this process's loop stalled.
    const stall = lag.max()
    const elapsed = performance.now() - watchStart
    const times = checks.map((c) => c.ms).sort((a, b) => a - b)
    const median = times[Math.floor(times.length / 2)] as number
    const wanted = Math.max(1, Math.min(8, Math.floor(elapsed / (250 + median)) - 1))
    const received = conns.map((c) => c.received().toString('latin1').split('\r\n')[0] ?? '')
    // The relay's own clock: one connection-timeout line per connection, reason header-timeout, age_ms from
    // its accept. The stderr pipe lags the sockets, so wait for the 64. The health checks' kept-alive connection is
    // closed by the header timer once it has idled that long (about 2 s after the last check) and logs nothing: it
    // was answered and sent no byte of another request (crates/ac-relay/src/server.rs, timeout_reason). The lines are
    // read 3 s later, past that close, so that a line of it, about 5 s after its accept, would be counted.
    const timeouts = () => events(relay).filter((e) => e.event === 'connection-timeout')
    await until('the relay logs the 64 connection-timeout lines', () => timeouts().length >= 64, 5_000)
    await sleep(3_000)
    const all = timeouts()
    // The 64 slow heads; any older line would be the health connection's idle close.
    const lines = all.filter((e) => (e.age_ms as number) < 4_000)
    const idle = all.length - lines.length
    const ages = lines.map((e) => e.age_ms as number)
    const reasons = JSON.stringify([...new Set(lines.map((e) => e.reason))])
    const report = `64 closed at ${span(closes)}; the relay's ${lines.length} lines: reasons ${reasons}, age_ms ${Math.min(...ages)} to ${Math.max(...ages)}, health keep-alive lines ${idle}; first bytes back: ${JSON.stringify([...new Set(received)])}; health ${checks.length} checks (${wanted} wanted), max ${Math.max(...times).toFixed(0)} ms; test loop stalled at most ${stall.toFixed(0)} ms`
    console.log(`H6a measure: ${report}`)
    expect(
      closes.filter((c) => c === null),
      report,
    ).toHaveLength(0)
    expect(lines, report).toHaveLength(64)
    expect(idle, report).toBe(0)
    for (const e of lines) {
      expect(e, report).toMatchObject({ reason: 'header-timeout', ip: '127.0.0.1' })
      expect(e.age_ms as number, report).toBeGreaterThanOrEqual(2_000)
      expect(e.age_ms as number, report).toBeLessThan(3_000)
    }
    for (const c of closes) {
      expect(c as number, report).toBeGreaterThanOrEqual(1_900)
      expect(c as number, report).toBeLessThanOrEqual(3_000)
    }
    expect(checks.length, report).toBeGreaterThanOrEqual(wanted)
    for (const c of checks) {
      expect(c.status, report).toBe(200)
      expect(c.ms, report).toBeLessThan(1_000)
    }
  })

  it('H6b [--connections-per-ip 8] a 9th connection from the address is closed at once with nothing answered; a new one is served once one of the 8 closes', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h6b', ['--connections-per-ip', '8'])
    const port = portOf(relay.url)
    const refusals = () => events(relay).filter((e) => e.event === 'connection-refused')
    // V1: a request on a connection of its own is answered while the address holds none.
    const control = await rawConn(port)
    control.socket.write('GET /v0/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
    await control.closed(3_000)
    expect(parseResponse(control.received())?.status).toBe(200)
    // The relay frees the control's place in the same drop that closes its socket, on another thread than the accept
    // loop; this only lets that drop finish. The 8 below do not rely on it: each one is proved accepted.
    await sleep(100)
    // Each held connection asks for /v0/health on the connection itself and waits for the answer, so the relay has
    // accepted and counted it (it takes its place at accept, before it reads a byte) before the next one opens.
    const held: RawConn[] = []
    for (let n = 1; n <= 8; n++) {
      const conn = await rawConn(port)
      held.push(conn)
      expect(await answered(conn), `held connection ${n} accepted and answered`).toBe(200)
    }
    expect(refusals(), 'none of the 8 was refused').toEqual([])
    const sentAt = Date.now()
    const ninth = await rawConn(port)
    ninth.socket.write('GET /v0/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
    const ninthClosed = await ninth.closed(3_000)
    await until('the relay logs the refusal', () => refusals().length > 0, 5_000)
    // The relay's own line says when it dropped the 9th: it is not the test's receipt time of the close.
    const refusedAfter = (refusals()[0]?.at as number) - sentAt
    const report = `9th closed after ${fmt(ninthClosed)} here, the relay's line says refused ${refusedAfter} ms after it was opened, ${ninth.received().length} bytes back; the 8 held: ${held.filter((h) => h.closedAfter() === null).length} open; test loop stalled at most ${lag.max().toFixed(0)} ms`
    console.log(`H6b measure: ${report}`)
    expect(ninthClosed, report).not.toBeNull()
    expect(ninthClosed as number, report).toBeLessThan(500 + lag.max())
    expect(refusedAfter, report).toBeLessThan(500)
    expect(ninth.received().length, report).toBe(0)
    expect(
      held.every((h) => h.closedAfter() === null),
      report,
    ).toBe(true)
    expect(refusals()).toMatchObject([{ ip: '127.0.0.1', reason: 'connections-per-ip' }])
    ;(held[0] as RawConn).socket.destroy()
    // The relay notices the close of the held connection on its own time: a new connection is served as soon as it
    // has, so ask until one is (a refused one is closed with nothing answered).
    let served: number | undefined
    const give = Date.now() + 5_000
    while (served === undefined && Date.now() < give) {
      const fresh = await rawConn(port)
      fresh.socket.write('GET /v0/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
      await fresh.closed(3_000)
      served = parseResponse(fresh.received())?.status
      if (served === undefined) await sleep(50)
    }
    expect(served, 'served once a slot freed').toBe(200)
  })

  it('H6c [--header-timeout 2] connections whose first bytes stay inside the HTTP/2 preface (16 bytes at once; one byte every 300 ms) are closed at the first-bytes deadline', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h6c', ['--header-timeout', '2'])
    const port = portOf(relay.url)
    const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    const atOnce = await rawConn(port)
    atOnce.socket.write(preface.slice(0, 16))
    const dripping = await rawConn(port)
    drip(dripping, preface.slice(0, 23), 300)
    const [a, b] = await Promise.all([atOnce.closed(6_000), dripping.closed(6_000)])
    const stall = lag.max()
    // The relay's own clock: one connection-timeout line per connection, reason first-bytes (both stay inside
    // the HTTP/2 preface, so only the relay's own deadline can close them), age_ms from its accept. The stderr pipe
    // lags the sockets, so wait for the two. The receipt times below stay as a backstop.
    const timeouts = () => events(relay).filter((e) => e.event === 'connection-timeout')
    await until('the relay logs the two connection-timeout lines', () => timeouts().length >= 2, 5_000)
    const lines = timeouts()
    const report = `16 bytes at once closed after ${fmt(a)}, the drip after ${fmt(b)}; the relay's lines: ${JSON.stringify(lines.map((e) => [e.reason, e.age_ms]))}; test loop stalled at most ${stall.toFixed(0)} ms`
    console.log(`H6c measure: ${report}`)
    expect(lines, report).toHaveLength(2)
    for (const e of lines) {
      expect(e, report).toMatchObject({ reason: 'first-bytes', ip: '127.0.0.1' })
      expect(e.age_ms as number, report).toBeGreaterThanOrEqual(2_000)
      expect(e.age_ms as number, report).toBeLessThan(3_000)
    }
    for (const c of [a, b]) {
      expect(c, report).not.toBeNull()
      expect(c as number, report).toBeGreaterThanOrEqual(1_900)
      expect(c as number, report).toBeLessThanOrEqual(3_000)
    }
    // V1: a client that completes a request on this relay is answered.
    expect((await health(relay.url)).status).toBe(200)
  })

  it('H6d [--body-timeout 1] a publish whose body never completes is answered 408 with no body and the connection closed', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h6d', ['--body-timeout', '1'])
    const port = portOf(relay.url)
    // V1: the same request with its whole body is answered at once (400 bad-json for these 6 bytes).
    const whole = await rawConn(port)
    whole.socket.write(
      'POST /v0/publish HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 6\r\nConnection: close\r\n\r\n{"v":1',
    )
    await whole.closed(3_000)
    expect(parseResponse(whole.received())?.status).toBe(400)
    const slow = await rawConn(port)
    const sentAt = Date.now()
    slow.socket.write(
      'POST /v0/publish HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"v":1',
    )
    const closed = await slow.closed(5_000)
    const answer = parseResponse(slow.received())
    // The relay logs the refusal when its body timer fires: its own timestamp, not the test's receipt of the 408.
    const refused = () =>
      events(relay).find((e) => e.event === 'publish-refused' && e.reason === 'body-timeout')
    await until('the relay logs the body timeout', () => refused() !== undefined, 5_000)
    const refusedAfter = (refused()?.at as number) - sentAt
    const report = `closed after ${fmt(closed)} here, the relay logged the 408 ${refusedAfter} ms after the request went out; answer ${JSON.stringify(answer)}; test loop stalled at most ${lag.max().toFixed(0)} ms`
    console.log(`H6d measure: ${report}`)
    expect(answer?.status, report).toBe(408)
    expect(answer?.body, report).toBe('')
    expect(answer?.headers['content-length'] ?? '0', report).toBe('0')
    expect(answer?.headers.connection, report).toBe('close')
    expect(closed, report).not.toBeNull()
    expect(refused(), report).toMatchObject({ status: 408 })
    expect(refusedAfter, report).toBeGreaterThanOrEqual(900)
    expect(refusedAfter, report).toBeLessThanOrEqual(2_500)
    expect(closed as number, report).toBeGreaterThanOrEqual(900)
    expect(closed as number, report).toBeLessThanOrEqual(2_500 + lag.max())
  })
})

describe('H7, H8: the subscriber deadlines [--ping-interval 1 --idle-timeout 2]', () => {
  const flags = ['--ping-interval', '1', '--idle-timeout', '2']

  it('H7a a burst of ping frames before the auth frame does not extend the auth deadline: close 4003 at one idle timeout', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h7a', flags)
    const openedAt = Date.now()
    const ws = await rawWs(relay.url, { autoPong: true })
    await ws.nextText((f) => f.t === 'challenge')
    const timer = setInterval(() => ws.ping(), 50)
    const close = await ws.closed(6_000)
    clearInterval(timer)
    const pongs = ws.frames.filter((f) => f.opcode === 0xa).length
    // The relay writes one connection-closed line when ws::serve returns, the no-auth return included, with its own
    // timestamp (crates/ac-relay/src/http.rs, the subscribe handler). This test opens the only WebSocket of this
    // relay (spawnRelay does not probe it, and plain HTTP connections write no such line), so exactly one line is due.
    const closedLines = () => events(relay).filter((e) => e.event === 'connection-closed')
    await until('the relay logs the connection closed', () => closedLines().length >= 1, 5_000)
    const lines = closedLines()
    const closedAfter = (lines[0]?.at as number) - openedAt
    const report = `close ${JSON.stringify(close)}, ${pongs} pongs back to our pings, TCP ended at ${fmt(ws.endedAt())}; the relay logged the close ${closedAfter} ms after the socket was opened here, ${lines.length} connection-closed line(s) ${JSON.stringify(lines[0])}; test loop stalled at most ${lag.max().toFixed(0)} ms`
    console.log(`H7a measure: ${report}`)
    expect(close?.code, report).toBe(4003)
    expect(close?.reason, report).toBe('no auth')
    // The harness starts every relay with --log-ip full, so the line names the whole address, not its /24.
    expect(lines.length, report).toBe(1)
    expect(lines[0]?.ip, report).toBe('127.0.0.1')
    expect(closedAfter, report).toBeGreaterThanOrEqual(1_900)
    expect(closedAfter, report).toBeLessThan(3_000)
    // A backstop at the client, beside the relay's own time.
    expect(close?.at as number, report).toBeGreaterThanOrEqual(1_900)
    expect(close?.at as number, report).toBeLessThanOrEqual(3_000)
    expect(pongs, `${report}: the pings reached the relay`).toBeGreaterThan(10)
  })

  it('H7b a subscriber that answers every ping, held past twice the idle timeout (5 s), is not closed', async () => {
    const relay = await spawnRelay('h7b', flags)
    const bob = party('bob')
    const ws = await rawWs(relay.url, { autoPong: true })
    await authenticate(ws, bob.signing)
    expect(ws.texts().map((f) => f.t)).toEqual(['challenge', 'ok'])
    await sleep(5_000)
    // The pings come on the relay's timer, one a second: wait for the fourth rather than count what has been read by
    // the instant the sleep ended. A subscriber that was closed meanwhile ends the wait, and the checks below fail.
    await waitPings(ws, 4, 3_000)
    const report = `after 5 s: ${ws.pings()} pings answered, close ${JSON.stringify(ws.close())}, ended ${fmt(ws.endedAt())}`
    console.log(`H7b measure: ${report}`)
    expect(ws.close(), report).toBeNull()
    expect(ws.endedAt(), report).toBeNull()
    expect(ws.pings(), report).toBeGreaterThanOrEqual(4)
    expect(events(relay).filter((e) => e.event === 'subscribe-closed')).toEqual([])
  })

  it('H8 a subscriber that answers every ping for 6 s (3 idle periods) is never closed; a silent one is closed 4003 idle at the idle timeout', async () => {
    const lag = loopLag()
    const relay = await spawnRelay('h8', flags)
    const bob = party('bob')
    const carol = party('carol')
    const answering = await rawWs(relay.url, { autoPong: true })
    const silent = await rawWs(relay.url, { autoPong: false })
    await authenticate(answering, bob.signing)
    await authenticate(silent, carol.signing)
    const authAt = silent.frames.find((f) => f.opcode === 0x1 && f.payload.toString().includes('"ok"'))
      ?.at as number
    const t0 = performance.now()
    const silentClose = await silent.closed(6_000)
    // The answering one is held for 6 s from here, three idle periods.
    await sleep(Math.max(0, t0 + 6_000 - performance.now()))
    // One ping a second on the relay's timer: wait for the fifth instead of counting at the instant the hold ended.
    await waitPings(answering, 5, 3_000)
    // The relay's own lines carry when the silent subscriber was admitted and when it was closed.
    const silentEvent = (name: string) =>
      events(relay).find((e) => e.event === name && e.mailbox === carol.address)
    await until('the relay logs the silent close', () => silentEvent('subscribe-closed') !== undefined, 5_000)
    const admittedAt = silentEvent('subscribe')?.at as number
    const relayHeld = (silentEvent('subscribe-closed')?.at as number) - admittedAt
    const report = `answering: ${answering.pings()} pings, close ${JSON.stringify(answering.close())}; silent: ${silent.pings()} pings unanswered, close ${JSON.stringify(silentClose)} at ${fmt(silentClose === null ? null : silentClose.at - authAt)} after its ok frame here, ${relayHeld} ms between its subscribe and subscribe-closed lines; test loop stalled at most ${lag.max().toFixed(0)} ms`
    console.log(`H8 measure: ${report}`)
    expect(answering.close(), report).toBeNull()
    expect(answering.endedAt(), report).toBeNull()
    expect(answering.pings(), report).toBeGreaterThanOrEqual(5)
    expect(silentClose?.code, report).toBe(4003)
    expect(silentClose?.reason, report).toBe('idle')
    expect(silentEvent('subscribe-closed'), report).toMatchObject({ reason: 'idle' })
    // The subscribe line comes after authorization, the idle deadline counts from the auth frame: a little less.
    expect(relayHeld, report).toBeGreaterThanOrEqual(1_500)
    expect(relayHeld, report).toBeLessThanOrEqual(3_000)
    expect((silentClose?.at as number) - authAt, report).toBeGreaterThanOrEqual(1_900)
    expect((silentClose?.at as number) - authAt, report).toBeLessThanOrEqual(3_000 + lag.max())
    const closed = events(relay).filter((e) => e.event === 'subscribe-closed')
    expect(closed.map((e) => [e.mailbox, e.reason])).toEqual([[carol.address, 'idle']])
  })
})
