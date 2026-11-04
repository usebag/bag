import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { NO_RECOVERY } from '@usebag/cli'
import {
  type AcceptFromRecord,
  type AddressRecord,
  codingEvaluator,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Hop,
  type SealingKey,
  type SigningKey,
  signRecord,
  signSubscribe,
  type TimeWindow,
  toHex,
} from '@usebag/core'
import {
  type AuditLine,
  createRecordSource,
  createRelayClient,
  Edge,
  type EdgeKeys,
  FsAuditSink,
  generateEdgeKeys,
  type InboundMessage,
  parseAuditLine,
  readAuditLines,
  type SessionHandler,
  type SocketFactory,
  SqliteStore,
  subscribeUrl,
  systemClock,
  systemRng,
  type TrustedRoot,
} from '@usebag/edge'
import { onTestFinished } from 'vitest'
import { startWellKnown, type WellKnownStub } from './well-known-stub.ts'

// The e2e harness: a real relay process per scenario (or AC_RELAY_URL), real edges on real SQLite files and audit
// files in a temporary directory, real sockets, and a local well-known stub. Nothing here is a fake: the edges are the
// library as shipped, composed as the CLI composes them.

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
export const DEFAULT_RELAY_CMD = join(REPO, 'target', 'release', 'ac-relay')
/** The one line the relay prints on stdout once it listens (spec/SPEC.md §8.1). */
export const URL_LINE = /^AC_RELAY_URL=(http:\/\/127\.0\.0\.1:(\d+))$/

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
export const now = (): number => systemClock.now()

/** Polls `test` every 20 ms until it holds; throws naming `what` after `ms`. */
export async function until(what: string, test: () => boolean, ms = 15_000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for ${what}`)
    await sleep(20)
  }
}

/** Waits until the system clock reads at least `second` (Unix seconds). */
export async function untilSecond(second: number): Promise<void> {
  while (now() < second) await sleep(25)
}

/** The second of a UTC day from which a machine's sender takes yesterday: 01:05 (the edge's telemetry-send.ts). */
const SEND_AFTER = 3_900

/**
 * The telemetry day of a scenario, read once for every process it starts: whether yesterday is due, and its date. A
 * day is due from 01:05 UTC to midnight, so within `span` seconds of either edge this first waits the edge out (at most
 * `span` s); each process started in the next `span` seconds then reads the same verdict and the same yesterday on its
 * own clock. `span` bounds how long the scenario's sends can take.
 */
export async function telemetryDay(span: number): Promise<{ due: boolean; yesterday: string }> {
  const toEdge = (t: number): number => (t % 86_400 < SEND_AFTER ? SEND_AFTER : 86_400) - (t % 86_400)
  const read = now()
  if (toEdge(read) <= span) await untilSecond(read + toEdge(read))
  const t = now()
  const yesterday = new Date((t - 86_400) * 1000).toISOString().slice(0, 10)
  return { due: t % 86_400 >= SEND_AFTER, yesterday }
}

// --- the relay --------------------------------------------------------------------------------------------------

export interface RelayHandle {
  readonly url: string
  /** False for a relay reached at AC_RELAY_URL, which the harness neither starts nor stops. */
  readonly spawned: boolean
  /** The spawned process, whose stdin is the pipe its --exit-on-stdin-eof reads; null for AC_RELAY_URL. */
  readonly child: ChildProcess | null
  /** The relay's stderr so far (its JSON log lines); '' for AC_RELAY_URL. */
  stderr(): string
  /** What the relay printed on stdout after its URL line; the contract is nothing. */
  readonly extraStdout: readonly string[]
  /** SIGTERM, then SIGKILL after 5 s; the exit code and signal, or null for AC_RELAY_URL. */
  stop(): Promise<{ readonly code: number | null; readonly signal: NodeJS.Signals | null } | null>
}

function exited(child: ChildProcess, ms: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true)
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve(true)
    })
  })
}

/**
 * A relay for one scenario. With AC_RELAY_URL set, that relay (after a health probe) and nothing spawned, so
 * `relayArgs` do not apply. Otherwise AC_RELAY_CMD (default target/release/ac-relay) with --port 0,
 * --db <dir>/relay.sqlite, --ttl, --skew, --log-ip full, --exit-on-stdin-eof and `relayArgs` (such as --bind and
 * --advertise), its stderr captured to <dir>/relay.stderr, its AC_RELAY_URL line read within 10 s. --log-ip full
 * keeps whole client addresses in the lines the scenarios read; a later --log-ip in
 * `relayArgs` wins. Its stdin is a pipe this process holds and never writes: when this process ends, however it ends
 * (a killed or crashed test run, whose stop() never runs), the pipe closes and the relay stops on its own.
 */
export async function startRelay(
  dir: string,
  window: TimeWindow = { ttl: DEFAULT_TTL, skew: DEFAULT_SKEW },
  relayArgs: readonly string[] = [],
): Promise<RelayHandle> {
  const external = process.env.AC_RELAY_URL
  if (external) {
    const url = external.replace(/\/+$/, '')
    const res = await fetch(`${url}/v0/health`)
    if (res.status !== 200) throw new Error(`AC_RELAY_URL: ${url}/v0/health answered ${res.status}`)
    await res.arrayBuffer()
    return { url, spawned: false, child: null, stderr: () => '', extraStdout: [], stop: async () => null }
  }
  const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
  if (!existsSync(cmd)) {
    throw new Error(
      `no relay at ${cmd}: run cargo build --release -p ac-relay, or set AC_RELAY_CMD or AC_RELAY_URL`,
    )
  }
  const errPath = join(dir, 'relay.stderr')
  const errFd = openSync(errPath, 'w')
  const args = [
    '--port',
    '0',
    '--db',
    join(dir, 'relay.sqlite'),
    '--ttl',
    String(window.ttl),
    '--skew',
    String(window.skew),
    '--log-ip',
    'full',
    '--exit-on-stdin-eof',
    ...relayArgs,
  ]
  const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', errFd] })
  // Never written; an error on it (the relay gone first) is no failure of the harness's.
  child.stdin?.on('error', () => {})
  closeSync(errFd)
  const stderr = (): string => (existsSync(errPath) ? readFileSync(errPath, 'utf8') : '')
  const extraStdout: string[] = []
  const lines = createInterface({ input: child.stdout as NodeJS.ReadableStream })
  const url = await new Promise<string>((resolveUrl, reject) => {
    const fail = (why: string): void => {
      clearTimeout(timer)
      child.kill('SIGKILL')
      reject(new Error(`the relay (${cmd}) ${why}\nits stderr:\n${stderr()}`))
    }
    const timer = setTimeout(() => fail('printed no AC_RELAY_URL line within 10 s'), 10_000)
    let first = true
    lines.on('line', (line) => {
      if (!first) {
        extraStdout.push(line)
        return
      }
      first = false
      const m = URL_LINE.exec(line)
      if (m === null) return fail(`printed ${JSON.stringify(line)} before its AC_RELAY_URL line`)
      clearTimeout(timer)
      resolveUrl(m[1] as string)
    })
    child.once('exit', (code, signal) => fail(`exited (${code ?? signal}) before printing AC_RELAY_URL`))
  })
  return {
    url,
    spawned: true,
    child,
    stderr,
    extraStdout,
    async stop() {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM')
        if (!(await exited(child, 5000))) {
          child.kill('SIGKILL')
          await exited(child, 5000)
        }
      }
      return { code: child.exitCode, signal: child.signalCode }
    },
  }
}

export interface Restartable {
  readonly url: string
  readonly port: number
  stop(): Promise<number | null>
}

/** A relay on a database in `dir`: port 0 takes one from the OS, a port given binds that one, tried a few times. */
export async function relayAt(dir: string, port: number): Promise<Restartable> {
  const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
  const args = ['--port', String(port), '--db', join(dir, 'relay.sqlite'), '--ttl', String(DEFAULT_TTL)]
  for (let attempt = 1; ; attempt++) {
    // stdin is a pipe this process holds and never writes: the relay stops whenever this process ends.
    const child: ChildProcess = spawn(cmd, [...args, '--skew', String(DEFAULT_SKEW), '--exit-on-stdin-eof'], {
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    child.stdin?.on('error', () => {})
    const line = await new Promise<string | null>((resolve) => {
      createInterface({ input: child.stdout as NodeJS.ReadableStream }).once('line', resolve)
      child.once('exit', () => resolve(null))
    })
    const m = line === null ? null : URL_LINE.exec(line)
    if (m === null) {
      if (attempt >= 10) throw new Error(`the relay on port ${port} printed ${line}`)
      await sleep(200)
      continue
    }
    return {
      url: m[1] as string,
      port: Number(m[2]),
      stop: () =>
        new Promise((resolve) => {
          if (child.exitCode !== null || child.signalCode !== null) resolve(child.exitCode)
          else {
            child.once('exit', (code) => resolve(code))
            child.kill('SIGTERM')
          }
        }),
    }
  }
}

// --- parties, records and nodes ---------------------------------------------------------------------------------

/** A key pair made fresh for one scenario, with the hex of its private keys to prove they never reach a log. */
export interface Party {
  readonly name: string
  readonly signing: SigningKey
  readonly sealing: SealingKey
  readonly address: string
  readonly keys: EdgeKeys
  readonly secrets: readonly string[]
}

export function party(name: string): Party {
  const keys = generateEdgeKeys(systemRng)
  return {
    name,
    signing: keys.signing,
    sealing: keys.sealing,
    address: keys.signing.address,
    keys,
    secrets: [toHex(keys.signing.exportSeed()), toHex(keys.sealing.exportSeed())],
  }
}

export interface AddressRecordOptions {
  readonly relays: readonly string[]
  /** Whether the record names the party's sealing key (default true). */
  readonly sealing?: boolean
  readonly ttl?: number
  readonly iat?: number
  readonly rotationKey?: string | null
  readonly revoked?: readonly string[]
  readonly rotatedFrom?: string | null
}

/** A party's address record, signed now. */
export function addressRecord(p: Party, o: AddressRecordOptions): AddressRecord {
  return signRecord(p.signing, {
    kind: 'address',
    key: p.address,
    sealing_key: o.sealing === false ? null : toHex(p.sealing.publicKey),
    relays: o.relays,
    rotation_key: o.rotationKey ?? null,
    revoked: o.revoked ?? [],
    ttl: o.ttl ?? 3600,
    iat: o.iat ?? now(),
    rotated_from: o.rotatedFrom ?? null,
  })
}

/** A mailbox's accept-from record, signed now: its roots (or ["*"]), 64 KiB and a day by default. */
export function acceptFrom(
  p: Party,
  roots: readonly string[],
  maxBytes = 65_536,
  ttl = 86_400,
): AcceptFromRecord {
  return signRecord(p.signing, {
    kind: 'accept-from',
    owner: p.address,
    roots,
    max_bytes: maxBytes,
    ttl,
    iat: now(),
  })
}

export interface NodeOptions {
  readonly keys: EdgeKeys
  readonly auth?: readonly Hop[]
  readonly mailbox?: string
  readonly roots?: readonly TrustedRoot[]
  /** Accepted sealed types (default every type). */
  readonly types?: readonly string[]
  readonly window?: TimeWindow
  /** Seconds added to the system clock, for a sender whose clock is off. */
  readonly clockOffset?: number
  /** The WebSocket factory, to watch or drop the subscription's sockets. */
  readonly socketFactory?: SocketFactory
  /** The state directory: a node opened again on the same files resumes where the last one stopped. */
  readonly stateDir?: string
  /** The peers this reader answers a read receipt request from (Edge's receiptsTo). A node has no receipt jitter. */
  readonly receiptsTo?: () => readonly string[]
}

/** An edge on real files: SQLite store, JSONL audit log, the relay client over real sockets. */
export class Node {
  readonly name: string
  readonly edge: Edge
  readonly store: SqliteStore
  readonly dir: string
  readonly auditPath: string
  readonly received: InboundMessage[] = []
  readonly errors: unknown[] = []
  #closed = false

  constructor(name: string, dir: string, relayUrl: string, o: NodeOptions) {
    this.name = name
    this.dir = dir
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    this.store = new SqliteStore(join(dir, 'edge.sqlite'))
    this.auditPath = join(dir, 'audit.jsonl')
    const client = createRelayClient(o.socketFactory === undefined ? {} : { socketFactory: o.socketFactory })
    const offset = o.clockOffset ?? 0
    this.edge = new Edge({
      keys: o.keys,
      ...(o.auth === undefined ? {} : { auth: o.auth }),
      ...(o.mailbox === undefined ? {} : { mailbox: o.mailbox }),
      store: this.store,
      relays: { client, urls: [relayUrl] },
      records: createRecordSource(client, { allowInsecureHttp: true }),
      policy: { roots: o.roots ?? [], types: o.types ?? ['*'], evaluators: [codingEvaluator] },
      clock: offset === 0 ? systemClock : { now: () => systemClock.now() + offset },
      rng: systemRng,
      audit: new FsAuditSink(this.auditPath),
      ...(o.window === undefined ? {} : { window: o.window }),
      ...(o.receiptsTo === undefined ? {} : { receiptsTo: o.receiptsTo }),
      receiptSpreadS: 0,
      flushEveryMs: 200,
      onError: (e) => this.errors.push(e),
    })
  }

  /** A session handler that keeps what it is given, then runs `then` (a reply, say). */
  handler(session: string, then?: (m: InboundMessage) => unknown): SessionHandler {
    return {
      session,
      deliver: async (m) => {
        this.received.push(m)
        await then?.(m)
      },
    }
  }

  /** The audit log's lines, parsed. */
  audit(): AuditLine[] {
    return readAuditLines(this.auditPath).map(parseAuditLine)
  }

  /** "event decision reason" for each audit line, of the envelope `id` when given. */
  steps(id?: string): string[] {
    return this.audit()
      .filter((l) => id === undefined || l.id === id)
      .map((l) => `${l.event} ${l.decision} ${l.reason}`)
  }

  /** The inbox rows of an envelope id. */
  rows(id: string): ReturnType<SqliteStore['inboxList']> {
    return this.store.inboxList().filter((r) => r.id === id)
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    await this.edge.stop()
    this.store.close()
  }
}

// --- the world of one scenario ----------------------------------------------------------------------------------

export interface World {
  readonly dir: string
  readonly relay: RelayHandle
  readonly url: string
  /** A well-known stub, started on first use and closed with the world. */
  wellKnown(): Promise<WellKnownStub>
  /** An edge under <dir>/<name>, closed with the world. */
  node(name: string, o: NodeOptions): Node
}

export interface WorldOptions {
  /** Flags for a spawned relay beyond --port, --db, --ttl and --skew (ignored under AC_RELAY_URL). */
  readonly relayArgs?: readonly string[]
}

/**
 * The world of one scenario: a temporary directory under AC_TEST_TMP (else the system's), removed at the end unless
 * AC_KEEP_TMP=1; a relay; nodes and a stub on demand. On failure it prints the relay's stderr and the directory.
 */
export async function world(name: string, options: WorldOptions = {}): Promise<World> {
  const root = process.env.AC_TEST_TMP || tmpdir()
  const dir = mkdtempSync(join(root, `bag-e2e-${name}-`))
  const nodes: Node[] = []
  let stub: WellKnownStub | null = null
  let relay: RelayHandle | null = null
  // Vitest 4 runs onTestFinished before onTestFailed, so the failure report comes first here, before the cleanup.
  onTestFinished(async (ctx) => {
    if (ctx.task.result?.state === 'fail') {
      const kept = process.env.AC_KEEP_TMP === '1' ? 'kept' : 'removed now (AC_KEEP_TMP=1 keeps it)'
      console.error(
        `e2e ${name} failed; its directory ${dir} is ${kept}\nrelay stderr:\n${relay?.stderr() ?? ''}`,
      )
    }
    for (const n of nodes.reverse()) await n.close()
    await stub?.close()
    await relay?.stop()
    if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
  })
  relay = await startRelay(dir, undefined, options.relayArgs)
  const r = relay
  return {
    dir,
    relay: r,
    url: r.url,
    async wellKnown() {
      stub ??= await startWellKnown()
      return stub
    },
    node(nodeName, o) {
      const n = new Node(nodeName, o.stateDir ?? join(dir, nodeName), r.url, o)
      nodes.push(n)
      return n
    },
  }
}

// --- the CLI as a process --------------------------------------------------------------------------------------

/** The CLI's process entry: node packages/cli/src/main.ts <command> (no bin entry). */
export const CLI_MAIN = join(REPO, 'packages', 'cli', 'src', 'main.ts')
// Node 24.4.1 warns once per process that node:sqlite is experimental; that is not output.
const NODE_WARNING = /ExperimentalWarning: SQLite is an experimental feature|node --trace-warnings/

/** What one CLI process printed, line by line (Node's SQLite warning left out), and its exit code. */
export interface CliRun {
  readonly code: number
  readonly out: string[]
  readonly err: string[]
}

const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')

/**
 * One CLI process, `node packages/cli/src/main.ts <args>`, from the repository root, with no AC_HOME (the
 * scenarios pass --dir); `seen` collects its raw stdout and stderr, for the check that no key was printed.
 */
export function cliProcess(args: readonly string[], seen?: string[]): Promise<CliRun> {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.AC_HOME
  // The CLI keeps one telemetry store per machine, in HOME/.bag: off here, so no scenario counts into it or marks it.
  env.DO_NOT_TRACK = '1'
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI_MAIN, ...args],
      { cwd: REPO, env, timeout: 30_000 },
      (error, stdout, stderr) => {
        seen?.push(stdout, stderr)
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
        // keygen's notice (its identity has no recovery copy) is a line, not an error; the cli tests assert it.
        const notice = (l: string): boolean => NODE_WARNING.test(l) || l === NO_RECOVERY
        resolve({ code, out: lines(stdout), err: lines(stderr).filter((l) => !notice(l)) })
      },
    )
  })
}

/** The hex of the private keys in a CLI home's key files, to prove that no output holds them. */
export function homeSecrets(home: string, names: readonly string[]): string[] {
  return names.flatMap((name) => {
    const f = JSON.parse(readFileSync(join(home, 'keys', `${name}.json`), 'utf8')) as Record<string, string>
    return [f.sign_seed as string, f.seal_priv as string]
  })
}

// --- the relay's API without the edge ---------------------------------------------------------------------------

/** A raw publish: the status, the JSON answer and the Retry-After header. */
export async function rawPublish(
  url: string,
  bytes: Uint8Array,
): Promise<{ readonly status: number; readonly body: unknown; readonly retryAfter: string | null }> {
  const res = await fetch(`${url}/v0/publish`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: bytes,
  })
  return { status: res.status, body: await res.json(), retryAfter: res.headers.get('retry-after') }
}

/**
 * The cursor a mailbox's key would resume after: subscribes with cursor null, as the key itself, and reads the
 * relay's ok frame, which names the ack the relay stored for that mailbox and signer (spec/SPEC.md §8.5).
 */
export async function storedAck(url: string, key: SigningKey): Promise<number> {
  const ws = new WebSocket(subscribeUrl(url))
  return await new Promise<number>((resolveAck, reject) => {
    const timer = setTimeout(() => {
      ws.close()
      reject(new Error('no ok frame within 10 s'))
    }, 10_000)
    ws.addEventListener('message', (event) => {
      const f = JSON.parse(String(event.data)) as {
        t: string
        nonce?: string
        cursor?: number
        error?: string
      }
      if (f.t === 'challenge') {
        const sig = signSubscribe(key, f.nonce as string, key.address, null)
        const auth = { t: 'auth', mailbox: key.address, signer: key.address, auth: [], cursor: null, sig }
        ws.send(JSON.stringify(auth))
      } else if (f.t === 'ok' || f.t === 'error') {
        clearTimeout(timer)
        ws.close()
        if (f.t === 'ok') resolveAck(f.cursor as number)
        else reject(new Error(`the relay refused: ${f.error}`))
      }
    })
  })
}

/** True when none of the parties' private keys appears in the text (a boolean, so a failure prints no key). */
export function holdsNoSecret(text: string, parties: readonly Party[]): boolean {
  return parties.every((p) => p.secrets.every((s) => !text.includes(s)))
}

// --- trust by domain at the relay ----------------------------------------------

/** The fields of a spawned relay's JSON log lines, read from its stderr. */
export function relayEvents(relay: RelayHandle): Record<string, unknown>[] {
  return relay
    .stderr()
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => (JSON.parse(l) as { fields: Record<string, unknown> }).fields)
}

/**
 * Runs `start` with AC_RELAY_URL unset, so that a scenario whose point is the relay's own flags (scenario 19) spawns
 * its relays from AC_RELAY_CMD even when the suite runs against a relay started by hand.
 */
export async function withSpawnedRelays<T>(start: () => Promise<T>): Promise<T> {
  const external = process.env.AC_RELAY_URL
  delete process.env.AC_RELAY_URL
  try {
    return await start()
  } finally {
    if (external !== undefined) process.env.AC_RELAY_URL = external
  }
}

/** A well-known stub started before the world, so that the relay's flags can name its port; closed at the end. */
export async function wellKnownFirst(): Promise<WellKnownStub> {
  const stub = await startWellKnown()
  onTestFinished(() => stub.close())
  return stub
}

/** A second relay of the scenario, spawned with `relayArgs` in its own directory under the world's; stopped at the end. */
export async function extraRelay(
  w: World,
  label: string,
  relayArgs: readonly string[],
): Promise<RelayHandle> {
  const dir = join(w.dir, label)
  mkdirSync(dir, { recursive: true })
  const relay = await withSpawnedRelays(() => startRelay(dir, undefined, relayArgs))
  onTestFinished(async () => {
    await relay.stop()
  })
  return relay
}

/** An edge on real files, like World.node, at another relay of the scenario; closed at the end. */
export function nodeAt(w: World, name: string, relayUrl: string, o: NodeOptions): Node {
  const n = new Node(name, join(w.dir, name), relayUrl, o)
  onTestFinished(() => n.close())
  return n
}
