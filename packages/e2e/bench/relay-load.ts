// The relay load generator: one process drives one relay through its public API and
// prints one summary line per load line, `L1 ...` to `L4 ...`, beside a JSON file of every number. It is not
// part of the e2e suite: vitest collects test/**/*.test.ts only (packages/e2e/vitest.config.ts), and no test imports
// this file. Identities, records and envelopes come from the e2e helpers (test/harness.ts, test/adversarial/support.ts),
// which sign with the core; nothing here signs by itself but the fetch and subscribe proofs, through the core.
//
//   node packages/e2e/bench/relay-load.ts <l1|l2|l3|l4> <relay url> [flags]
//
//   l1  subscriptions until the first refusal: fresh identities, each subscribing to its own mailbox (`auth` [], cursor
//       null), --batch at a time, until one is not answered `ok` within 15 s (an error frame, a close, a socket error
//       or the timeout) or --max-subs are held; the held ones are counted open again after --hold-s, then every socket
//       is closed (1000).
//   l2  publish rate and fetch latency at --mailboxes N: N identities publish accept-from records (roots ["*"], ttl
//       604,800) and hold one subscription each; then for each rate of --rates, envelopes built and signed before the
//       clock go out open loop at that rate for --step-s seconds, at most --inflight at once, sender i to mailbox i + 1,
//       and each 200 is fetched once by its recipient (the proof signed before the clock). A step holds when it reaches
//       95 percent of its rate with no send skipped; the ramp ends after the first step that does not.
//   l3  the publishing half of store growth: --mailboxes N hosted as in l2, with no subscription, --rate for --seconds.
//       The store's size is read outside, before and after (packages/e2e/bench/dry-run-local.sh, or the Fly logs).
//   l4  deferred until the backup stream exists: prints so and exits 0.
//
// Bounds, none of which a flag can lift past its ceiling: identities --max-identities (default 2,000, at most 20,000);
// subscriptions --max-subs (default 1,000, at most 12,000, under this Mac's 16,384 ephemeral ports, which every other
// process shares); any rate --max-rate (default 500/s, at most 2,000/s); a line ends by --deadline-s (default 540, at
// most 600). l2 and l3 stop at once on any answer but 200 (rate-limited, too-many-*, store-full, internal, any 5xx), a
// duplicate or a failed connection, print the reason and exit 3. Every WebSocket is closed (1000) before the exit,
// on SIGINT and SIGTERM too. The keys live in this process's memory only: none is written or printed.
//
// Exit status: 0 the line ran (l1's refusal is its result); 1 a failure of its own; 2 usage; 3 a hard stop on a
// refusal; 4 stopped by SIGINT or SIGTERM.

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { monitorEventLoopDelay } from 'node:perf_hooks'
import { parseArgs } from 'node:util'
import { serializeRecord, signFetchAuth, signSubscribe } from '@usebag/core'
import { subscribeUrl } from '@usebag/edge'
import { envelope, health, post } from '../test/adversarial/support.ts'
import { acceptFrom, now, type Party, party, sleep } from '../test/harness.ts'

/** The ceilings no flag lifts. */
const CEILING = { identities: 20_000, subs: 12_000, rate: 2_000, deadline: 600, prebuilt: 300_000 } as const
/** The relay TTL (spec/SPEC.md §8.1): an accept-from ttl this long keeps every mailbox row the full seven days. */
const SEVEN_DAYS = 604_800
const SUB_TIMEOUT_MS = 15_000
const CALL_TIMEOUT_MS = 15_000
const RECORD_WORKERS = 16

type Line = 'l1' | 'l2' | 'l3' | 'l4'

interface Options {
  readonly line: Line
  readonly url: string
  readonly maxIdentities: number
  readonly maxSubs: number
  readonly batch: number
  readonly holdS: number
  readonly mailboxes: number
  readonly rates: readonly number[]
  readonly stepS: number
  readonly rate: number
  readonly seconds: number
  readonly maxRate: number
  readonly inflight: number
  readonly bodyChars: number
  readonly deadlineS: number
  readonly out: string
}

class Usage extends Error {}

/** A subscription and how it went: `outcome` is `ok` or the refusal (`error:<code>`, `close:<code>`, `socket:<why>`). */
interface Sub {
  readonly ws: WebSocket
  state: 'opening' | 'held' | 'refused'
  outcome: string
  frames: number
  closedCode: number | null
}

/** An envelope built and signed before the clock: its bytes, id and recipient. */
interface Built {
  readonly bytes: Uint8Array
  readonly id: string
  readonly to: Party
}

/** One open-loop run at one rate. */
interface Step {
  readonly rate: number
  readonly seconds: number
  readonly sent: number
  readonly ok: number
  readonly skipped: number
  readonly achieved: number
  readonly held: boolean
  readonly stop: string | null
  readonly publishMs: Stats
  readonly fetchMs: Stats
  readonly pushMs: Stats
  readonly frames: number
  readonly genCpu: number
  readonly loopP99Ms: number
}

interface Stats {
  readonly n: number
  readonly p50: number | null
  readonly p99: number | null
  readonly max: number | null
}

let stopping = false
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    stopping = true
  })
}

const round = (n: number): number => Math.round(n * 10) / 10

/** The nearest-rank percentile `q` (0 to 1) of the values. */
function percentile(sorted: readonly number[], q: number): number | null {
  if (sorted.length === 0) return null
  return round(sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))] as number)
}

function stats(values: readonly number[]): Stats {
  const sorted = [...values].sort((a, b) => a - b)
  return {
    n: sorted.length,
    p50: percentile(sorted, 0.5),
    p99: percentile(sorted, 0.99),
    max: percentile(sorted, 1),
  }
}

/** What a failure says about itself: an errno code where Node gives one, else its message or name. */
function why(e: unknown): string {
  const o = e as {
    error?: unknown
    cause?: { code?: string }
    code?: string
    message?: string
    name?: string
  }
  if (o?.error !== undefined) return why(o.error)
  return o?.cause?.code ?? o?.code ?? o?.message ?? o?.name ?? String(e)
}

/** The relay's error code in an answer's body, or `-`. */
function codeOf(body: unknown): string {
  return typeof body === 'object' && body !== null && 'error' in body ? String(body.error) : '-'
}

function int(name: string, text: string | undefined, min: number, max: number): number {
  const n = Number(text)
  if (!Number.isInteger(n) || n < min || n > max)
    throw new Usage(`--${name} is an integer from ${min} to ${max}`)
  return n
}

function options(argv: readonly string[]): Options {
  const { values: v, positionals } = parseArgs({
    args: [...argv],
    allowPositionals: true,
    strict: true,
    options: {
      'max-identities': { type: 'string', default: '2000' },
      'max-subs': { type: 'string', default: '1000' },
      batch: { type: 'string', default: '50' },
      'hold-s': { type: 'string', default: '10' },
      mailboxes: { type: 'string', default: '100' },
      rates: { type: 'string', default: '25,50,100,200' },
      'step-s': { type: 'string', default: '15' },
      rate: { type: 'string', default: '20' },
      seconds: { type: 'string', default: '60' },
      'max-rate': { type: 'string', default: '500' },
      inflight: { type: 'string', default: '64' },
      'body-chars': { type: 'string', default: '1000' },
      'deadline-s': { type: 'string', default: '540' },
      out: { type: 'string' },
    },
  })
  const [line, url] = positionals
  if (line !== 'l1' && line !== 'l2' && line !== 'l3' && line !== 'l4')
    throw new Usage('the line is l1, l2, l3 or l4')
  if (url === undefined || !/^https?:\/\/[^/]+$/.test(url.replace(/\/+$/, ''))) {
    throw new Usage('the relay URL is http(s)://<host>[:<port>]')
  }
  const maxIdentities = int('max-identities', v['max-identities'], 1, CEILING.identities)
  const maxRate = int('max-rate', v['max-rate'], 1, CEILING.rate)
  const deadlineS = int('deadline-s', v['deadline-s'], 10, CEILING.deadline)
  const o: Options = {
    line,
    url: url.replace(/\/+$/, ''),
    maxIdentities,
    maxSubs: int('max-subs', v['max-subs'], 1, CEILING.subs),
    batch: int('batch', v.batch, 1, 500),
    holdS: int('hold-s', v['hold-s'], 0, 120),
    mailboxes: int('mailboxes', v.mailboxes, 1, maxIdentities),
    rates: (v.rates ?? '').split(',').map((r) => int('rates', r, 1, maxRate)),
    stepS: int('step-s', v['step-s'], 1, deadlineS),
    rate: int('rate', v.rate, 1, maxRate),
    seconds: int('seconds', v.seconds, 1, deadlineS),
    maxRate,
    inflight: int('inflight', v.inflight, 1, 1_000),
    bodyChars: int('body-chars', v['body-chars'], 0, 30_000),
    deadlineS,
    out: resolve(
      v.out ??
        `packages/e2e/bench/out/relay-load/${line}-${new Date().toISOString().replace(/[:.]/g, '')}.json`,
    ),
  }
  const prebuilt = line === 'l2' ? Math.max(...o.rates) * o.stepS : o.rate * o.seconds
  if (prebuilt > CEILING.prebuilt)
    throw new Usage(`one step would build ${prebuilt} envelopes, over ${CEILING.prebuilt}`)
  if (line === 'l2' && o.rates.length * o.stepS > deadlineS) throw new Usage('the steps outlast --deadline-s')
  if (line === 'l1' && o.maxSubs > maxIdentities) throw new Usage('--max-subs is at most --max-identities')
  return o
}

// --- the relay's calls ---------------------------------------------------------------------------------------------

/** Subscribes as `p` to its own mailbox; resolves once the relay answers `ok` or refuses. Frames after `ok` are counted,
 * passed to `onEnv` by envelope id and acknowledged, as an edge does. */
function subscribe(url: string, p: Party, onEnv?: (id: string) => void): Promise<Sub> {
  const ws = new WebSocket(subscribeUrl(url))
  const sub: Sub = { ws, state: 'opening', outcome: '', frames: 0, closedCode: null }
  return new Promise((done) => {
    const settle = (state: Sub['state'], outcome: string): void => {
      if (sub.state !== 'opening') return
      clearTimeout(timer)
      sub.state = state
      sub.outcome = outcome
      done(sub)
    }
    const timer = setTimeout(() => {
      settle('refused', 'timeout')
      ws.close()
    }, SUB_TIMEOUT_MS)
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as {
        t: string
        nonce?: string
        error?: string
        cursor?: number
        envelope?: string
      }
      if (f.t === 'challenge') {
        const sig = signSubscribe(p.signing, f.nonce ?? '', p.address, null)
        ws.send(
          JSON.stringify({ t: 'auth', mailbox: p.address, signer: p.address, auth: [], cursor: null, sig }),
        )
      } else if (f.t === 'ok') {
        settle('held', 'ok')
      } else if (f.t === 'error') {
        settle('refused', `error:${f.error}`)
      } else if (f.t === 'env') {
        sub.frames++
        onEnv?.((JSON.parse(f.envelope ?? '{}') as { id?: string }).id ?? '')
        ws.send(JSON.stringify({ t: 'ack', cursor: f.cursor }))
      }
    })
    ws.addEventListener('error', (event) => settle('refused', `socket:${why(event)}`))
    ws.addEventListener('close', (event) => {
      sub.closedCode = event.code
      settle('refused', `close:${event.code}`)
    })
  })
}

/** Closes every socket with 1000 and waits for each close, at most `ms`; how many are closed then. */
async function closeAll(subs: readonly Sub[], ms = 15_000): Promise<number> {
  const waits = subs.map(
    (s) =>
      new Promise<void>((done) => {
        if (s.ws.readyState === WebSocket.CLOSED) return done()
        s.ws.addEventListener('close', () => done(), { once: true })
        s.ws.close(1000)
      }),
  )
  await Promise.race([Promise.all(waits), sleep(ms)])
  return subs.filter((s) => s.ws.readyState === WebSocket.CLOSED).length
}

/** Each party's accept-from record (roots ["*"], 64 KiB, the seven-day ttl), 16 at a time; null, or the first refusal. */
async function host(url: string, parties: readonly Party[]): Promise<string | null> {
  let next = 0
  let refused: string | null = null
  const worker = async (): Promise<void> => {
    while (refused === null && !stopping && next < parties.length) {
      const p = parties[next++] as Party
      try {
        const r = await post(url, serializeRecord(acceptFrom(p, ['*'], 65_536, SEVEN_DAYS)))
        if (r.status !== 200) refused = `record ${r.status} ${codeOf(r.body)}`
      } catch (e) {
        refused = `record connection ${why(e)}`
      }
    }
  }
  await Promise.all(Array.from({ length: RECORD_WORKERS }, worker))
  return refused ?? (stopping ? 'interrupted' : null)
}

/** A fetch by id as the recipient, its proof signed before the clock starts: the status and the milliseconds. */
async function timedFetch(url: string, p: Party, id: string): Promise<{ status: number; ms: number }> {
  const ts = now()
  const headers = {
    'ac-signer': p.address,
    'ac-ts': String(ts),
    'ac-sig': signFetchAuth(p.signing, id, ts, url),
  }
  const t = performance.now()
  const res = await fetch(`${url}/v0/fetch/${id}`, { headers, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) })
  await res.arrayBuffer()
  return { status: res.status, ms: performance.now() - t }
}

/** `count` envelopes, sender i to mailbox i + 1, each with a body of `chars` characters. */
function build(parties: readonly Party[], count: number, chars: number): Built[] {
  const body = 'x'.repeat(chars)
  return Array.from({ length: count }, (_, i) => {
    const from = parties[i % parties.length] as Party
    const to = parties[(i + 1) % parties.length] as Party
    const b = envelope(from, [to], { body })
    return { bytes: b.bytes, id: b.envelope.id, to }
  })
}

/** Publishes the pool open loop at `rate` for `seconds`, at most `inflight` at once; with `fetchBack` each 200 is read
 * back by id. `started` keeps each envelope's start, for the push times the subscriptions measure. */
async function runStep(
  o: Options,
  rate: number,
  seconds: number,
  pool: readonly Built[],
  fetchBack: boolean,
  started: Map<string, number>,
  push: number[],
): Promise<Step> {
  const publishMs: number[] = []
  const fetchMs: number[] = []
  const pushFrom = push.length
  let sent = 0
  let ok = 0
  let skipped = 0
  let inflight = 0
  let stop: string | null = null
  const one = async (item: Built): Promise<void> => {
    try {
      const t = performance.now()
      started.set(item.id, t)
      const r = await post(o.url, item.bytes)
      const ms = performance.now() - t
      const duplicate = (r.body as { duplicate?: unknown } | null)?.duplicate === true
      if (r.status !== 200 || duplicate) {
        stop ??= `publish ${r.status} ${duplicate ? 'duplicate' : codeOf(r.body)}`
        return
      }
      ok++
      publishMs.push(ms)
      if (!fetchBack) return
      const f = await timedFetch(o.url, item.to, item.id)
      if (f.status !== 200) stop ??= `fetch ${f.status}`
      else fetchMs.push(f.ms)
    } catch (e) {
      stop ??= `connection ${why(e)}`
    } finally {
      inflight--
    }
  }
  const cpu = process.cpuUsage()
  const loop = monitorEventLoopDelay({ resolution: 10 })
  loop.enable()
  const t0 = performance.now()
  while (!stopping && stop === null) {
    const elapsed = (performance.now() - t0) / 1000
    if (elapsed >= seconds) break
    const due = Math.min(pool.length, Math.floor(elapsed * rate))
    while (sent + skipped < due) {
      const item = pool[sent + skipped] as Built
      if (inflight >= o.inflight) {
        skipped++
        continue
      }
      inflight++
      sent++
      void one(item)
    }
    await sleep(2)
  }
  const drainEnd = performance.now() + CALL_TIMEOUT_MS * 2
  while (inflight > 0 && performance.now() < drainEnd) await sleep(5)
  const wall = (performance.now() - t0) / 1000
  loop.disable()
  const used = process.cpuUsage(cpu)
  const achieved = round(ok / Math.max(seconds, wall))
  return {
    rate,
    seconds,
    sent,
    ok,
    skipped,
    achieved,
    held: stop === null && skipped === 0 && achieved >= 0.95 * rate,
    stop,
    publishMs: stats(publishMs),
    fetchMs: stats(fetchMs),
    pushMs: stats(push.slice(pushFrom)),
    frames: push.length - pushFrom,
    genCpu: Math.round((100 * (used.user + used.system)) / 1000 / (wall * 1000)),
    loopP99Ms: round(loop.percentile(99) / 1e6),
  }
}

const show = (s: Stats): string => `${s.p50 ?? '-'}/${s.p99 ?? '-'}`

function stepLine(n: number, s: Step): string {
  return (
    `# L2 step mailboxes=${n} rate=${s.rate}/s achieved=${s.achieved}/s sent=${s.sent} ok=${s.ok} ` +
    `skipped=${s.skipped} publish_ms_p50/p99=${show(s.publishMs)} fetch_ms_p50/p99=${show(s.fetchMs)} ` +
    `push_ms_p50/p99=${show(s.pushMs)} frames=${s.frames} gen_cpu=${s.genCpu}% loop_p99_ms=${s.loopP99Ms} ` +
    `held=${s.held}${s.stop === null ? '' : ` stop=${JSON.stringify(s.stop)}`}`
  )
}

// --- the lines -----------------------------------------------------------------------------------------------------

type Report = Record<string, unknown>

async function l1(o: Options, report: Report): Promise<number> {
  const held: Sub[] = []
  const refused: Sub[] = []
  const timeline: { held: number; at: string; health: string }[] = []
  const t0 = performance.now()
  const deadline = t0 + o.deadlineS * 1000
  let mark = 0
  while (held.length < o.maxSubs && refused.length === 0 && !stopping && performance.now() < deadline) {
    const n = Math.min(o.batch, o.maxSubs - held.length)
    const batch = await Promise.all(Array.from({ length: n }, (_, i) => subscribe(o.url, party(`s${i}`))))
    for (const s of batch) {
      if (s.state === 'held') held.push(s)
      else refused.push(s)
    }
    if (held.length >= mark + 1_000 || refused.length > 0) {
      mark = held.length - (held.length % 1_000)
      const h = await health(o.url).then(
        (r) => (r.status === 200 ? `${round(r.ms)} ms` : `http ${r.status}`),
        (e: unknown) => `error ${why(e)}`,
      )
      timeline.push({ held: held.length, at: new Date().toISOString(), health: h })
      console.log(
        `# L1 held=${held.length} refused=${refused.length} health=${h} at=${new Date().toISOString()}`,
      )
    }
  }
  const openS = round((performance.now() - t0) / 1000)
  const first = refused[0]?.outcome ?? (held.length >= o.maxSubs ? 'none-at-max-subs' : 'none-deadline')
  const kinds: Record<string, number> = {}
  for (const s of refused) kinds[s.outcome] = (kinds[s.outcome] ?? 0) + 1
  if (!stopping) await sleep(o.holdS * 1000)
  const stillOpen = held.filter((s) => s.ws.readyState === WebSocket.OPEN).length
  const after = await health(o.url).then(
    (r) => `http ${r.status}`,
    (e: unknown) => `error ${why(e)}`,
  )
  const all = [...held, ...refused]
  const closed = await closeAll(all)
  const result = {
    held: held.length,
    refused_in_last_batch: refused.length,
    first_refusal: first,
    refusals: kinds,
    batch: o.batch,
    max_subs: o.maxSubs,
    open_s: openS,
    still_open_after_hold: stillOpen,
    hold_s: o.holdS,
    health_after: after,
    closed,
    sockets: all.length,
    timeline,
  }
  report.result = result
  console.log(
    `L1 held=${held.length} first_refusal=${first} refused_in_batch=${refused.length} batch=${o.batch} ` +
      `open_s=${openS} still_open=${stillOpen}/${held.length} after_${o.holdS}s health_after=${JSON.stringify(after)} ` +
      `closed=${closed}/${all.length}`,
  )
  return stopping ? 4 : 0
}

async function l2(o: Options, report: Report): Promise<number> {
  const parties = Array.from({ length: o.mailboxes }, (_, i) => party(`m${i}`))
  const steps: Step[] = []
  report.result = { mailboxes: o.mailboxes, steps }
  const hosted = await host(o.url, parties)
  if (hosted !== null) {
    console.log(`L2 not run: mailboxes=${o.mailboxes} hosting stopped: ${hosted}`)
    return stopping ? 4 : 3
  }
  const started = new Map<string, number>()
  const push: number[] = []
  const onEnv = (id: string): void => {
    const t = started.get(id)
    if (t !== undefined) push.push(performance.now() - t)
  }
  const subs: Sub[] = []
  for (let i = 0; i < parties.length && !stopping; i += o.batch) {
    const batch = await Promise.all(parties.slice(i, i + o.batch).map((p) => subscribe(o.url, p, onEnv)))
    subs.push(...batch)
    const bad = batch.find((s) => s.state !== 'held')
    if (bad !== undefined) {
      const closed = await closeAll(subs)
      console.log(
        `L2 not run: mailboxes=${o.mailboxes} subscription ${subs.length} ${bad.outcome} closed=${closed}`,
      )
      return 3
    }
  }
  let code = 0
  let envelopeBytes = 0
  for (const rate of o.rates) {
    if (stopping) break
    const pool = build(parties, rate * o.stepS, o.bodyChars)
    envelopeBytes = pool[0]?.bytes.length ?? 0
    const step = await runStep(o, rate, o.stepS, pool, true, started, push)
    steps.push(step)
    console.log(stepLine(o.mailboxes, step))
    if (step.stop !== null) {
      code = 3
      break
    }
    if (!step.held) break
  }
  const open = subs.filter((s) => s.ws.readyState === WebSocket.OPEN).length
  const closed = await closeAll(subs)
  const best = steps.filter((s) => s.held).at(-1)
  const last = steps.at(-1)
  Object.assign(report.result as object, { envelope_bytes: envelopeBytes, open_at_end: open, closed })
  console.log(
    `L2 mailboxes=${o.mailboxes} envelope_bytes=${envelopeBytes} held_step=${best?.rate ?? 'none'}/s ` +
      `publish_ms_p50/p99=${best ? show(best.publishMs) : '-'} fetch_ms_p50/p99=${best ? show(best.fetchMs) : '-'} ` +
      `last_step=${last?.rate ?? '-'}/s achieved=${last?.achieved ?? '-'}/s` +
      `${last?.stop ? ` stop=${JSON.stringify(last.stop)}` : ''} subscriptions_open=${open}/${subs.length} ` +
      `closed=${closed}/${subs.length}`,
  )
  return stopping ? 4 : code
}

async function l3(o: Options, report: Report): Promise<number> {
  const parties = Array.from({ length: o.mailboxes }, (_, i) => party(`g${i}`))
  const hosted = await host(o.url, parties)
  if (hosted !== null) {
    console.log(`L3 not run: mailboxes=${o.mailboxes} hosting stopped: ${hosted}`)
    return stopping ? 4 : 3
  }
  const pool = build(parties, o.rate * o.seconds, o.bodyChars)
  const sizes = pool.map((b) => b.bytes.length)
  const startedAt = new Date().toISOString()
  const step = await runStep(o, o.rate, o.seconds, pool, false, new Map(), [])
  const endedAt = new Date().toISOString()
  const published = pool.slice(0, step.sent).reduce((n, b) => n + b.bytes.length, 0)
  const size = stats(sizes)
  report.result = {
    mailboxes: o.mailboxes,
    ...step,
    envelope_bytes: { min: Math.min(...sizes), p50: size.p50, max: Math.max(...sizes) },
    published_bytes: published,
    started_at: startedAt,
    ended_at: endedAt,
  }
  console.log(
    `L3 mailboxes=${o.mailboxes} rate=${o.rate}/s seconds=${o.seconds} sent=${step.sent} ok=${step.ok} ` +
      `skipped=${step.skipped} achieved=${step.achieved}/s envelope_bytes=${Math.min(...sizes)}..${Math.max(...sizes)} ` +
      `published_bytes=${published} publish_ms_p50/p99=${show(step.publishMs)} started=${startedAt} ended=${endedAt}` +
      `${step.stop === null ? '' : ` stop=${JSON.stringify(step.stop)}`}`,
  )
  if (stopping) return 4
  return step.stop === null ? 0 : 3
}

async function main(): Promise<number> {
  let o: Options
  try {
    o = options(process.argv.slice(2))
  } catch (e) {
    console.error(`relay-load: ${e instanceof Error ? e.message : String(e)}; see the head of this file`)
    return 2
  }
  if (o.line === 'l4') {
    console.log('L4 not run: deferred until the backup stream exists')
    return 0
  }
  const report: Report = {
    line: o.line,
    url: o.url,
    options: o,
    node: process.version,
    started: new Date().toISOString(),
  }
  const line = o.line === 'l1' ? l1 : o.line === 'l2' ? l2 : l3
  let code: number
  try {
    code = await line(o, report)
  } catch (e) {
    console.error(`relay-load: ${o.line} failed: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`)
    code = 1
  }
  report.ended = new Date().toISOString()
  report.exit = code
  report.interrupted = stopping
  mkdirSync(dirname(o.out), { recursive: true })
  writeFileSync(o.out, `${JSON.stringify(report, null, 2)}\n`)
  console.log(`# json ${o.out}`)
  return code
}

// The exit code is set and the loop left to drain, so that stdout (asynchronous on a pipe here) is written out; a
// handle left open cannot hold the process past 3 s.
process.exitCode = await main()
setTimeout(() => process.exit(), 3_000).unref()
