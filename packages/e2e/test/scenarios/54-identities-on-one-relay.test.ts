import { mkdirSync, writeFileSync } from 'node:fs'
import { connect, createServer, type Server } from 'node:net'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { serializeRecord } from '@usebag/core'
import { FsKeyStore, RELAY_TURNS } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  cliProcess,
  nodeAt,
  type Party,
  party,
  REPO,
  rawPublish,
  relayEvents,
  sleep,
  until,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 54 (identities 64): the most identities one server holds, all on one relay, from one
// address. One real MCP server process with --identities, its keys made by keygen, against the release relay at its
// default limits. An address record of 30 s makes the real keep-alive re-sign while everything is subscribed, a far
// tighter burst than a day's record gives; one more subscriber from the same address stands in for a second person.
//   direct   the server talks to the relay itself: the relay counts every connection of the address
//   proxied  through a proxy here that names the client in fly-client-ip, as the Fly deploy runs it: the relay
//            counts the address's WebSockets only
// Each run prints a `FACT 54 {...}` line. AC_S54_CAP sets --connections-per-ip and turns the assertions off, to measure
// a cap; AC_S54_MODE runs one mode. publishes_in_a_window counts by the relay's aligned 60 s windows, so a run of 40 s
// reads about 300 of 600 inside one window and 155 to 177 across two.
//
// connections_peak is the most connections open at once before the one more subscriber, counted at a front in both
// modes; in direct mode the relay counts the same ones. A process holds at most its subscriptions plus RELAY_TURNS, the
// edge's bound, so the peak is 68 whatever the load. The direct arm asserts the bound, with one place for a connection
// the client has closed and the front has not yet seen, and it asserts the arrival rather than that the send never
// waited: a send that waited through a brief refusal and then landed is correct. Before the bound the peak was the
// client's own idle connections: 67 to 74 under load, and at cap 68 every call refused for 3 to 4 s in 3 runs of 25,
// with at most 3 in flight (measured 2026-10-30). connections_peak_all adds the one more
// subscriber.
//
// As of 2026-10-30, the 4 places then left past one server were arithmetic, so two more arms measure them.
// A second process measured 5, a peak of 73, and 74 was the smallest cap clean under load; the default of 79 is that plus
// one more such process (measured 2026-10-31).
//   second      arm (c), in every run, direct and second-proxied: the server of 64 and beside it a second process at
//               the address, a server of one and CLI sends, for the whole of a renewals burst; every send lands and
//               nothing is refused
//   office-*    arm (d), only when AC_S54_MODE names it (a skipped test turns the gate red): two servers of 64, more
//               subscriptions than a relay takes from an address. office-direct or office-proxied; AC_S54_ORDER=together
//               starts both at once, else the second comes once the first is in; AC_S54_SIGNERS sets
//               --record-signers-per-day, since 128 new signers in a day from one address pass its default of 100. It
//               prints `FACT 54d {...}`: what each server holds, what is refused, what sends and renewals do, what
//               status says, and how long the second server takes once the first leaves. Direct, subscriptions stop
//               short of the cap (ruling 8), so it asserts the same as behind a proxy: the sends and renewals of both
//               servers go out, and status names no one the relay left out as subscribed.
//   reserve     arm (e), in every run, direct and reserve-proxied: arm (d)'s point at a small cap, where one server
//               meets the limit, the reserve direct and the cap behind a proxy. A refusal reads rate-limited either way.

const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
const IDENTITIES = 64
const ADDRESS_TTL = 30
/** Arm (d)'s records: long enough that two servers' renewals stay under the relay's per-address publishes in a window. */
const OFFICE_TTL = 120
const CLIENT_IP = '203.0.113.9'
const DEADLINE_MS = 75_000
/** Arm (c)'s CLI lanes, each a process after a process; AC_S54_CLI sets them, to find where the places run out. */
const CLI_LANES = Number(process.env.AC_S54_CLI ?? 1)
/** The pause between one CLI lane's processes; AC_S54_CLI_GAP_MS sets it. */
const CLI_GAP_MS = Number(process.env.AC_S54_CLI_GAP_MS ?? 0)
/** Arm (d): how long the relay's subscribers stay unchanged before they count as settled. */
const SETTLE_MS = 10_000
/** Arm (e): the subscriptions a direct cap of 16 leaves, its reserve the floor of 8, and the cap behind a proxy. */
const RESERVE_LIMIT = 8
/** The direct arm's most: the server's subscriptions, its turns, and a connection closed that the front has not seen. */
const DIRECT_PEAK = IDENTITIES + RELAY_TURNS + 1
/**
 * The peak of arm (c)'s second process, direct: the most it can hold, a server of one's subscription and its turns, and
 * the 2 places a CLI send was measured to take. It measured 73.
 */
const SECOND_PEAK = DIRECT_PEAK + 1 + RELAY_TURNS + 2
type Json = Record<string, unknown>

/** A TCP proxy to `target` that counts open connections and, `naming`, names one client in each request head, as a hosting proxy does. */
async function front(target: string, naming: boolean) {
  const port = Number(new URL(target).port)
  const publishes: number[] = []
  const connections = { open: 0, peak: 0 }
  const server = createServer((down) => {
    const up = connect(port, '127.0.0.1')
    connections.open++
    connections.peak = Math.max(connections.peak, connections.open)
    down.on('data', (chunk: Buffer) => {
      const text = chunk.toString('latin1')
      const end = text.indexOf('\r\n')
      const head = naming && /^(GET|POST|PUT|DELETE|HEAD|OPTIONS) /.test(text) && end > 0
      if (text.startsWith('POST /v0/publish')) publishes.push(Math.floor(Date.now() / 1000))
      up.write(
        head ? `${text.slice(0, end)}\r\nfly-client-ip: ${CLIENT_IP}${text.slice(end)}` : chunk,
        'latin1',
      )
    })
    up.pipe(down)
    for (const s of [up, down]) s.on('error', () => (s === up ? down : up).destroy())
    down.on('close', () => {
      connections.open--
      up.destroy()
    })
    up.on('close', () => down.destroy())
  })
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  const address = server.address() as { port: number }
  return { url: `http://127.0.0.1:${address.port}`, server: server as Server, publishes, connections }
}

/** A keygen run for each of `names`, eight at a time; each identity's home, and its keys as a Party. */
async function homes(w: World, names: readonly string[]): Promise<{ home: string; who: Party }[]> {
  const made: { home: string; who: Party }[] = []
  for (let i = 0; i < names.length; i += 8) {
    const batch = names.slice(i, i + 8).map(async (name) => {
      const home = join(w.dir, 'homes', name)
      mkdirSync(home, { recursive: true, mode: 0o700 })
      const run = await cliProcess(['keygen', name, '--dir', home])
      expect(run.code).toBe(0)
      const keys = new FsKeyStore(join(home, 'keys')).load(name)
      const who = {
        name,
        keys,
        signing: keys.signing,
        sealing: keys.sealing,
        address: keys.signing.address,
        secrets: [],
      }
      return { home, who }
    })
    made.push(...(await Promise.all(batch)))
  }
  return made
}

/** `labels` made by keygen with their records at `url`; each says if its records went in. */
async function identitiesAt(w: World, url: string, labels: readonly string[], ttl: number) {
  const made: { home: string; who: Party; published: boolean }[] = []
  const statuses: number[] = []
  for (const { home, who } of await homes(w, labels)) {
    const records = [addressRecord(who, { relays: [url], ttl }), acceptFrom(who, ['*'])]
    const answers = []
    for (const r of records) answers.push((await rawPublish(url, serializeRecord(r))).status)
    statuses.push(...answers)
    made.push({ home, who, published: answers.every((s) => s === 200) })
  }
  return { made, statuses }
}

/** One server's identities file for `made` at `url`, whose inboxes take mail from `trust_roots`. */
function identitiesFile(
  w: World,
  url: string,
  name: string,
  made: readonly { home: string; who: Party }[],
  trust_roots: readonly string[],
): string {
  const file = join(w.dir, `${name}.json`)
  const identities = made.map(({ home, who }) => ({
    label: who.name,
    key: who.name,
    home,
    relays: [url],
    trust_roots,
    keep_alive_records: true,
  }))
  writeFileSync(file, JSON.stringify({ version: 1, default: made[0]?.who.name, identities }), { mode: 0o600 })
  return file
}

async function serverOf(file: string) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [MAIN, '--identities', file],
    cwd: REPO,
    stderr: 'ignore',
  })
  const client = new Client({ name: 'e2e-54', version: '0.0.0' })
  await client.connect(transport)
  onTestFinished(() => client.close())
  return {
    async call(tool: string, a: Json = {}): Promise<{ isError: boolean; value: Json }> {
      const r = await client.callTool({ name: tool, arguments: a }, undefined, { timeout: 30_000 })
      const text = (r.content as { text: string }[])[0]?.text ?? ''
      return { isError: r.isError === true, value: JSON.parse(text) as Json }
    },
    close: () => client.close(),
  }
}

type McpServer = Awaited<ReturnType<typeof serverOf>>

const eventsOf = (w: World, name: string) => relayEvents(w.relay).filter((e) => e.event === name)
const statusesOf = async (server: McpServer, labels: readonly string[]) =>
  (await Promise.all(labels.map((as) => server.call('status', { as })))).map((s) => s.value)
const lastKeepAlive = (s: Json) =>
  (s.keep_alive as { last: { at: string; outcome?: string } | null } | null)?.last
const renewed = (s: Json) => lastKeepAlive(s)?.outcome ?? ''
const unnamed = (text: unknown) => String(text).replace(/ed25519:[0-9a-f]{64}/g, 'ed25519:<address>')
const tally = (words: readonly string[]) => {
  const counts: Record<string, number> = {}
  for (const word of words) counts[word] = (counts[word] ?? 0) + 1
  return counts
}

/** The messages `as` holds once it holds `count`, or when `ms` have passed. */
async function landed(server: McpServer, as: string, count: number, ms: number): Promise<number> {
  const end = Date.now() + ms
  for (;;) {
    const got = ((await server.call('inbox', { as, limit: 100 })).value.messages as unknown[]).length
    if (got >= count || Date.now() > end) return got
    await sleep(250)
  }
}

/** The relay's first subscribe of each mailbox, by the time it logged it. */
function firstSubscribed(w: World): Map<string, number> {
  const first = new Map<string, number>()
  for (const line of w.relay.stderr().split('\n')) {
    if (line === '') continue
    const e = JSON.parse(line) as { timestamp: string; fields: Record<string, unknown> }
    const mailbox = e.fields.mailbox as string
    if (e.fields.event === 'subscribe' && !first.has(mailbox)) first.set(mailbox, Date.parse(e.timestamp))
  }
  return first
}

/** What a run saw, printed and returned. */
async function measure(mode: 'direct' | 'proxied') {
  const cap = process.env.AC_S54_CAP
  const relayArgs = [
    ...(cap === undefined ? [] : ['--connections-per-ip', cap]),
    ...(mode === 'proxied' ? ['--trust-proxy', '127.0.0.1/32', '--client-ip-header', 'fly-client-ip'] : []),
  ]
  const w = await withSpawnedRelays(() => world(`s54-${mode}`, { relayArgs }))
  const proxy = await front(w.url, mode === 'proxied')
  onTestFinished(() => void proxy.server.close())
  const { url } = proxy

  const bob = party('bob')
  await rawPublish(url, serializeRecord(addressRecord(bob, { relays: [url] })))
  await rawPublish(url, serializeRecord(acceptFrom(bob, ['*'])))
  const labels = Array.from({ length: IDENTITIES }, (_, i) => `i${i}`)
  const { made } = await identitiesAt(w, url, labels, ADDRESS_TTL)
  const file = identitiesFile(w, url, 'identities', made, [])

  proxy.publishes.splice(0)
  proxy.connections.peak = proxy.connections.open
  const started = Date.now()
  const server = await serverOf(file)
  const events = (name: string) => eventsOf(w, name)
  const subscribed = () => new Set(events('subscribe').map((e) => e.mailbox)).size
  const end = started + DEADLINE_MS
  while (subscribed() < IDENTITIES && Date.now() < end) await sleep(250)
  const allAfterMs = subscribed() === IDENTITIES ? Date.now() - started : null

  const sent = await server.call('send', {
    as: 'i1',
    to: [bob.address],
    type: 'chat.v1',
    body: { text: 'from one of 64' },
  })
  const targets = sent.value.targets as { status: string; reason: string | null }[] | undefined

  // The keep-alive's own renewals, inside the same connections.
  let seen = await statusesOf(server, labels)
  while (seen.filter((s) => renewed(s) === 're-signed').length < IDENTITIES && Date.now() < end) {
    await sleep(1000)
    seen = await statusesOf(server, labels)
  }
  const outcomes = tally(seen.map(renewed))
  const states: Record<string, number> = {}
  for (const s of seen) {
    for (const r of s.subscriptions as { state: string }[]) states[r.state] = (states[r.state] ?? 0) + 1
  }

  // One more subscriber from the same address: a second person's identity, behind the same office address.
  const connectionsPeak = proxy.connections.peak
  const before = events('connection-refused').length
  const beyond = nodeAt(w, 'bob', url, {
    keys: bob.keys,
    roots: [{ address: made[1]?.who.address as string }],
  })
  beyond.edge.setDefault(beyond.handler('bob'))
  await beyond.edge.start()
  await sleep(2000)
  const extraSubscribed = events('subscribe').some((e) => e.mailbox === bob.address)
  const extraRefused = events('connection-refused').length - before

  // The relay's per_ip window is aligned to 60 s: the most publishes of the server's in any one.
  const windows = new Map<number, number>()
  for (const at of proxy.publishes) {
    const window = Math.floor(at / 60)
    windows.set(window, (windows.get(window) ?? 0) + 1)
  }
  const fact = {
    mode,
    cap: cap ?? 'default',
    subscribed: subscribed(),
    all_after_ms: allAfterMs,
    send: {
      error: sent.isError,
      code: sent.value.code ?? null,
      waiting: sent.value.waiting === true,
      reason: sent.value.reason ?? null,
      targets,
    },
    renewal_outcomes: outcomes,
    subscription_states: states,
    connections_peak: connectionsPeak,
    connections_peak_all: proxy.connections.peak,
    connection_refused: events('connection-refused').length,
    publishes_in_a_window: Math.max(0, ...windows.values()),
    extra_subscriber: { subscribed: extraSubscribed, refused: extraRefused },
  }
  console.log(`FACT 54 ${JSON.stringify(fact)}`)
  const arrived = () => until('the message at bob', () => beyond.received.length === 1, 30_000)
  if (cap === undefined) {
    expect(fact.subscribed).toBe(IDENTITIES + 1)
    expect(fact.send.error).toBe(false)
    expect(fact.renewal_outcomes).toEqual({ 're-signed': IDENTITIES })
    expect(fact.subscription_states).toEqual({ subscribed: IDENTITIES })
    if (mode === 'direct') expect(fact.connections_peak).toBeLessThanOrEqual(DIRECT_PEAK)
    expect(fact.connection_refused).toBe(0)
    expect(fact.publishes_in_a_window).toBeLessThan(600)
    await arrived() // from the server, so that a send still waiting has it to land
  }
  await server.close()
  if (cap !== undefined && targets?.some((t) => t.status === 'published') === true) await arrived()
  return fact
}

/** Arm (c) at the default cap: the sends of a second process through one whole renewals burst of the first. */
async function secondProcess(mode: 'direct' | 'proxied') {
  const cap = process.env.AC_S54_CAP
  const relayArgs = [
    ...(cap === undefined ? [] : ['--connections-per-ip', cap]),
    ...(mode === 'proxied' ? ['--trust-proxy', '127.0.0.1/32', '--client-ip-header', 'fly-client-ip'] : []),
  ]
  const w = await withSpawnedRelays(() => world(`s54-second-${mode}`, { relayArgs }))
  const proxy = await front(w.url, mode === 'proxied')
  onTestFinished(() => void proxy.server.close())
  const { url } = proxy
  const labels = Array.from({ length: IDENTITIES }, (_, i) => `i${i}`)
  const many = await identitiesAt(w, url, labels, ADDRESS_TTL)
  const one = await identitiesAt(w, url, ['one'], ADDRESS_TTL)
  const clerk = await identitiesAt(w, url, ['clerk'], 3600)
  const address = (party: { made: { who: Party }[] }, i = 0) => party.made[i]?.who.address as string
  const manyFile = identitiesFile(w, url, 'many', many.made, [address(one), address(clerk)])
  const oneFile = identitiesFile(w, url, 'one', one.made, [address(many, 1)])

  proxy.publishes.splice(0)
  proxy.connections.peak = proxy.connections.open
  const started = Date.now()
  const server = await serverOf(manyFile)
  const beside = await serverOf(oneFile)
  const end = started + DEADLINE_MS
  const subscribed = () => firstSubscribed(w).size
  while (subscribed() < IDENTITIES + 1 && Date.now() < end) await sleep(250)
  const allAfterMs = subscribed() === IDENTITIES + 1 ? Date.now() - started : null

  // Three lanes of sends run until every one of the 64 has re-signed since they began, so all of a burst is inside them.
  const began = Math.floor(Date.now() / 1000)
  let over = false
  const sends: { lane: string; ok: boolean; detail: string | null }[] = []
  const lane = async (
    name: string,
    gapMs: number,
    send: (n: number) => Promise<[boolean, string | null]>,
  ) => {
    for (let n = 0; !over; n++) {
      const [ok, detail] = await send(n)
      sends.push({ lane: name, ok, detail })
      await sleep(gapMs)
    }
  }
  const viaServer = async (
    from: McpServer,
    as: string,
    to: string,
    n: number,
  ): Promise<[boolean, string | null]> => {
    const sent = await from.call('send', { as, to: [to], type: 'chat.v1', body: { n } })
    const ok = !sent.isError && sent.value.waiting !== true
    return [ok, ok ? null : unnamed(`${sent.value.code ?? 'waiting'}: ${sent.value.reason ?? ''}`)]
  }
  const viaCli = async (n: number): Promise<[boolean, string | null]> => {
    const as = ['--as', 'clerk', '--to', address(many, 2), '--relay', url]
    const body = ['--type', 'chat.v1', '--body', JSON.stringify({ n })]
    const run = await cliProcess(['send', ...as, ...body, '--dir', clerk.made[0]?.home as string])
    return [run.code === 0, run.code === 0 ? null : unnamed(run.err[0] ?? `exit ${run.code}`)]
  }
  const lanes = [
    ...Array.from({ length: CLI_LANES }, (_, i) => lane('cli', CLI_GAP_MS, (n) => viaCli(1000 * i + n))),
    lane('one', 1000, (n) => viaServer(beside, 'one', address(many, 3), n)),
    lane('many', 1000, (n) => viaServer(server, 'i1', address(one), n)),
  ]
  const fresh = (s: Json) =>
    renewed(s) === 're-signed' && Date.parse(lastKeepAlive(s)?.at ?? '') >= began * 1000
  let seen = await statusesOf(server, labels)
  const last = Date.now() + 40_000
  while (seen.filter(fresh).length < IDENTITIES && Date.now() < last) {
    await sleep(500)
    seen = await statusesOf(server, labels)
  }
  over = true
  await Promise.all(lanes)
  const connectionsPeak = proxy.connections.peak
  const inBurst = proxy.publishes.filter((at) => at >= began).length

  const count = (name: string) => sends.filter((s) => s.lane === name).length
  const fact = {
    arm: 'second-process',
    mode,
    cap: cap ?? 'default',
    cli_lanes: CLI_LANES,
    cli_gap_ms: CLI_GAP_MS,
    subscribed: subscribed(),
    all_after_ms: allAfterMs,
    renewed_in_the_lanes: seen.filter(fresh).length,
    publishes_in_the_lanes: inBurst,
    sends: tally(sends.map((s) => `${s.lane} ${s.ok ? 'published' : 'not published'}`)),
    send_failures: sends.filter((s) => !s.ok).slice(0, 4),
    landed: {
      cli: await landed(server, 'i2', count('cli'), 30_000),
      one: await landed(server, 'i3', count('one'), 30_000),
      many: await landed(beside, 'one', count('many'), 30_000),
    },
    connections_peak: connectionsPeak,
    connection_refused: eventsOf(w, 'connection-refused').length,
  }
  console.log(`FACT 54c ${JSON.stringify(fact)}`)
  if (cap === undefined) {
    expect(fact.subscribed).toBe(IDENTITIES + 1)
    expect(fact.renewed_in_the_lanes).toBe(IDENTITIES)
    expect(fact.send_failures).toEqual([])
    expect(fact.landed).toEqual({ cli: count('cli'), one: count('one'), many: count('many') })
    if (mode === 'direct') expect(fact.connections_peak).toBeLessThanOrEqual(SECOND_PEAK)
    expect(fact.connection_refused).toBe(0)
  }
  await beside.close()
  await server.close()
  return fact
}

/** Arm (e): a cap small enough that one server meets the limit, so that every run crosses it end to end. */
async function reserveMet(mode: 'direct' | 'proxied') {
  const relayArgs =
    mode === 'direct'
      ? ['--connections-per-ip', '16']
      : [
          '--connections-per-ip',
          `${RESERVE_LIMIT}`,
          '--trust-proxy',
          '127.0.0.1/32',
          '--client-ip-header',
          'fly-client-ip',
        ]
  const w = await withSpawnedRelays(() => world(`s54-reserve-${mode}`, { relayArgs }))
  const proxy = await front(w.url, mode === 'proxied')
  onTestFinished(() => void proxy.server.close())
  const { url } = proxy
  const bob = party('bob')
  await rawPublish(url, serializeRecord(addressRecord(bob, { relays: [url] })))
  await rawPublish(url, serializeRecord(acceptFrom(bob, ['*'])))
  const labels = Array.from({ length: RESERVE_LIMIT + 4 }, (_, i) => `r${i}`)
  const { made } = await identitiesAt(w, url, labels, ADDRESS_TTL)
  const server = await serverOf(identitiesFile(w, url, 'reserve', made, []))
  const states = (rows: Json[]) =>
    tally(rows.flatMap((s) => (s.subscriptions as { state: string }[]).map((r) => r.state)))
  const end = Date.now() + DEADLINE_MS
  let seen = await statusesOf(server, labels)
  const settled = () =>
    states(seen).retrying === 4 && seen.filter((s) => renewed(s) === 're-signed').length === labels.length
  while (!settled() && Date.now() < end) {
    await sleep(500)
    seen = await statusesOf(server, labels)
  }
  const sent = await server.call('send', {
    as: 'r0',
    to: [bob.address],
    type: 'chat.v1',
    body: { text: 'with every subscription place taken' },
  })
  const fact = {
    arm: 'reserve',
    mode,
    subscribed: firstSubscribed(w).size,
    subscription_states: states(seen),
    last_codes: tally(
      seen.flatMap((s) => (s.subscriptions as { last_code: string | null }[]).map((r) => `${r.last_code}`)),
    ),
    renewal_outcomes: tally(seen.map(renewed)),
    send: (sent.value.targets as { status: string }[] | undefined)?.map((t) => t.status) ?? [],
    refused_by_reason: tally(eventsOf(w, 'connection-refused').map((e) => String(e.reason))),
  }
  console.log(`FACT 54e ${JSON.stringify(fact)}`)
  expect(fact.subscribed).toBe(RESERVE_LIMIT)
  expect(fact.subscription_states).toEqual({ subscribed: RESERVE_LIMIT, retrying: 4 })
  expect(fact.last_codes).toEqual({ null: RESERVE_LIMIT, 'rate-limited': 4 })
  expect(fact.renewal_outcomes).toEqual({ 're-signed': labels.length })
  expect(fact.send).toEqual(['published'])
  expect(Object.keys(fact.refused_by_reason)).toEqual([
    mode === 'direct' ? 'subscriptions-per-ip' : 'connections-per-ip',
  ])
  await server.close()
}

/** Arm (d), measured: two servers of 64 behind one address. */
async function twoServers(mode: 'direct' | 'proxied') {
  const order = process.env.AC_S54_ORDER === 'together' ? 'together' : 'second'
  const signers = process.env.AC_S54_SIGNERS
  const relayArgs = [
    ...(mode === 'proxied' ? ['--trust-proxy', '127.0.0.1/32', '--client-ip-header', 'fly-client-ip'] : []),
    ...(signers === undefined ? [] : ['--record-signers-per-day', signers]),
  ]
  const w = await withSpawnedRelays(() => world(`s54-office-${mode}`, { relayArgs }))
  const proxy = await front(w.url, mode === 'proxied')
  onTestFinished(() => void proxy.server.close())
  const { url } = proxy
  const named = (p: string) => Array.from({ length: IDENTITIES }, (_, i) => `${p}${i}`)
  const a = await identitiesAt(w, url, named('a'), OFFICE_TTL)
  const b = await identitiesAt(w, url, named('b'), OFFICE_TTL)
  const roots = (side: typeof a) => side.made.map((m) => m.who.address)
  const aFile = identitiesFile(w, url, 'a', a.made, roots(b))
  const bFile = identitiesFile(w, url, 'b', b.made, roots(a))

  const started = Date.now()
  const at = () => Date.now() - started
  const inside = (side: typeof a) => {
    const first = firstSubscribed(w)
    return side.made.filter((m) => first.has(m.who.address))
  }
  let serverA: McpServer
  let serverB: McpServer
  let secondAt: number | null = null
  if (order === 'together') {
    ;[serverA, serverB] = await Promise.all([serverOf(aFile), serverOf(bFile)])
  } else {
    serverA = await serverOf(aFile)
    while (inside(a).length < IDENTITIES && at() < DEADLINE_MS) await sleep(250)
    secondAt = at()
    serverB = await serverOf(bFile)
  }
  let settled = -1
  let still = Date.now()
  while (Date.now() - still < SETTLE_MS && at() < 120_000) {
    const now = firstSubscribed(w).size
    if (now !== settled) [settled, still] = [now, Date.now()]
    await sleep(500)
  }
  const refused = () => eventsOf(w, 'connection-refused').length
  const held = { at_ms: at(), a: inside(a).length, b: inside(b).length, refused: refused() }

  // What a person does next: one send each way between an identity that is in and each that is not.
  const inA = inside(a).filter((m) => m.published)
  const inB = inside(b).filter((m) => m.published)
  const outOf = (side: typeof a, within: typeof inA) =>
    side.made.filter((m) => m.published && !within.includes(m))
  const [outA, outB] = [outOf(a, inA), outOf(b, inB)]
  const tries = [
    { name: 'a in to b in', via: serverA, from: inA[1], to: inB[1] },
    { name: 'a in to b out', via: serverA, from: inA[2], to: outB[1] },
    { name: 'b in to a in', via: serverB, from: inB[2], to: inA[3] },
    { name: 'b out to a in', via: serverB, from: outB[2], to: inA[4] },
    { name: 'a out to b in', via: serverA, from: outA[1], to: inB[3] },
  ].filter((t) => t.from !== undefined && t.to !== undefined)
  const outcomes: {
    name: string
    ms: number
    error: boolean
    code: unknown
    waiting: boolean
    reason: unknown
    hint: unknown
    targets: string[] | undefined
    to: (typeof inA)[number]
    at: McpServer
    landed_ms: number | null
  }[] = []
  for (const t of tries) {
    const sentAt = at()
    const body = { type: 'chat.v1', body: { name: t.name } }
    const sent = await t.via.call('send', { as: t.from?.who.name, to: [t.to?.who.address], ...body })
    const targets = sent.value.targets as { status: string; reason: string | null }[] | undefined
    outcomes.push({
      name: t.name,
      ms: at() - sentAt,
      error: sent.isError,
      code: sent.value.code ?? null,
      waiting: sent.value.waiting === true,
      reason: sent.value.reason === undefined ? null : unnamed(sent.value.reason),
      hint: sent.value.hint === undefined ? null : unnamed(sent.value.hint),
      targets: targets?.map((x) => `${x.status} ${x.reason ?? ''}`.trim()),
      to: t.to as (typeof inA)[number],
      at: t.name.includes('to a') ? serverA : serverB,
      landed_ms: null,
    })
  }

  const look = async (these: typeof outcomes) => {
    for (const o of these.filter((x) => x.landed_ms === null)) {
      if ((await landed(o.at, o.to.who.name, 1, 0)) > 0) o.landed_ms = at()
    }
  }

  // The renewals fall due at half the ttl; the status is read once they have had their turn.
  const renewalsAt = OFFICE_TTL * 600 + OFFICE_TTL * 100 + 5_000
  while (at() < Math.max(renewalsAt, held.at_ms + 20_000)) {
    await sleep(1000)
    await look(outcomes)
  }
  const seenBy = async (server: McpServer, labels: readonly string[]) => {
    const seen = await statusesOf(server, labels)
    const firstNow = firstSubscribed(w)
    const addressOf = (s: Json) => s.address as string
    const reallyOut = seen.filter((s) => !firstNow.has(addressOf(s)))
    const says = (rows: Json[]) =>
      tally(rows.flatMap((s) => (s.subscriptions as { state: string }[]).map((r) => r.state)))
    return {
      subscriptions_say: says(seen),
      subscriptions_say_of_those_not_in: says(reallyOut),
      last_codes: tally(
        seen.flatMap((s) => (s.subscriptions as { last_code: string | null }[]).map((r) => `${r.last_code}`)),
      ),
      keep_alive: tally(seen.map(renewed)),
      waiting_sends: seen.reduce((n, s) => n + (s.waiting as unknown[]).length, 0),
      edge_errors: seen.reduce((n, s) => n + (s.edge_errors as number), 0),
      last_edge_errors: tally(seen.map((s) => String(s.last_edge_error ?? 'none'))),
    }
  }
  const status = { at_ms: at(), a: await seenBy(serverA, named('a')), b: await seenBy(serverB, named('b')) }
  await look(outcomes)
  const landedHeld = outcomes.filter((o) => o.landed_ms !== null).map((o) => o.name)

  // The first server leaves, and the second is offered every place: how long until all of it is in, and what then lands.
  const leftAt = at()
  await serverA.close()
  const left = at()
  const toB = outcomes.filter((o) => o.at === serverB)
  while (inside(b).length < IDENTITIES && at() < left + 75_000) {
    await sleep(500)
    await look(toB)
  }
  const allInAfterMs = inside(b).length === IDENTITIES ? at() - left : null
  const firstB = [...firstSubscribed(w).entries()]
    .filter(([mailbox]) => b.made.some((m) => m.who.address === mailbox))
    .map(([, time]) => time - started - left)
    .filter((ms) => ms >= 0)
    .sort((x, y) => x - y)
  while (toB.some((o) => o.landed_ms === null) && at() < left + 100_000) {
    await sleep(1000)
    await look(toB)
  }
  const fact = {
    arm: 'two-servers',
    mode,
    order,
    signers: signers ?? 'default',
    records_published: tally([...a.statuses, ...b.statuses].map(String)),
    second_started_ms: secondAt,
    held,
    sends: outcomes.map(({ to: _, at: _at, ...o }) => o),
    landed_with_both_up: landedHeld,
    status,
    first_left_ms: leftAt,
    after_it_left: {
      b_subscribed: inside(b).length,
      all_in_after_ms: allInAfterMs,
      first_ms: firstB[0] ?? null,
      median_ms: firstB[Math.floor(firstB.length / 2)] ?? null,
      last_ms: firstB[firstB.length - 1] ?? null,
    },
    connection_refused: refused(),
    refused_by_reason: tally(eventsOf(w, 'connection-refused').map((e) => String(e.reason))),
    publishes_in_a_window: Math.max(
      0,
      ...Object.values(tally(proxy.publishes.map((s) => String(Math.floor(s / 60))))),
    ),
  }
  console.log(`FACT 54d ${JSON.stringify(fact)}`)
  // A relay full of subscriptions still takes the calls of the address, direct as behind a proxy: only subscriptions
  // are refused, every send goes out at once, every renewal due is made, and a message to an identity left out waits
  // at the relay for its place.
  for (const o of fact.sends) expect([o.name, o.error, o.waiting]).toEqual([o.name, false, false])
  const toIn = fact.sends.filter((o) => o.name.endsWith(' in')).map((o) => o.name)
  expect(landedHeld.toSorted()).toEqual(toIn.toSorted())
  expect(fact.sends.filter((o) => o.landed_ms === null && o.name.includes('to b'))).toEqual([])
  for (const side of [status.a, status.b]) {
    expect(side.keep_alive['publish-failed'] ?? 0).toBe(0)
    expect(side.keep_alive.unreachable ?? 0).toBe(0)
    // Status tells the truth about an identity the relay did not admit.
    expect(side.subscriptions_say_of_those_not_in.subscribed ?? 0).toBe(0)
  }
  expect(
    fact.refused_by_reason[mode === 'direct' ? 'subscriptions-per-ip' : 'connections-per-ip'],
  ).toBeGreaterThan(0)
  expect(fact.after_it_left.b_subscribed).toBe(IDENTITIES)
  await serverB.close()
  return fact
}

describe('e2e scenario 54: 64 identities on one relay, from one address', () => {
  const only = process.env.AC_S54_MODE
  const runs = (arm: string) => only === undefined || only === arm
  it.runIf(runs('direct'))(
    '(54a) direct',
    async () => {
      await measure('direct')
    },
    150_000,
  )

  it.runIf(runs('proxied'))(
    '(54b) behind a proxy, as the public relay runs',
    async () => {
      await measure('proxied')
    },
    150_000,
  )

  it.runIf(runs('second'))(
    '(54c) a second process at the address, through a renewals burst, direct',
    async () => {
      await secondProcess('direct')
    },
    150_000,
  )

  it.runIf(runs('second-proxied'))(
    '(54c) a second process at the address, through a renewals burst, behind a proxy',
    async () => {
      await secondProcess('proxied')
    },
    150_000,
  )

  it.runIf(runs('reserve'))(
    '(54e) direct, with the reserve met: calls still get in, and status names who is left out',
    async () => {
      await reserveMet('direct')
    },
    150_000,
  )

  it.runIf(runs('reserve-proxied'))(
    '(54e) behind a proxy, with the cap met: calls still get in, and status names who is left out',
    async () => {
      await reserveMet('proxied')
    },
    150_000,
  )

  if (only === 'office-direct' || only === 'office-proxied') {
    it('(54d) two servers of 64 behind one address, measured', async () => {
      await twoServers(only === 'office-direct' ? 'direct' : 'proxied')
    }, 360_000)
  }
})
