import { type ChildProcessWithoutNullStreams, execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sealingKeyFromSeed, serializeRecord, signRecord, toHex } from '@usebag/core'
import { generateEdgeKeys, HomeCustody, KeyEpochStore, systemRng } from '@usebag/edge'

// The addendum's helper half: the
// agent as a real child process. This file is both the test's helper and, run as
// `node c31-support.ts c31-setup <home> <relay url>`, the child that makes the home: the principal's keys are made and
// written there by that child, so the test's own process never holds the principal's seeds (the heap arm needs that).
// It prints public data only: the address, the sealing public key and the signed address record.

const HERE = fileURLToPath(import.meta.url)
/** The CLI as a process (packages/cli/src/main.ts). */
export const MAIN = resolve(dirname(HERE), '..', '..', 'src', 'main.ts')
/**
 * `ac login` refuses a stdin that is no terminal (no-tty). The child's stdin is a pipe the test writes the `y` into, the
 * fake terminal the row names; this preload only marks that pipe as a terminal, so login runs. Nothing else changes.
 */
export const TTY_PRELOAD = 'data:text/javascript,process.stdin.isTTY=true'

/** The public half of the home the setup child made. */
export interface Made {
  readonly address: string
  readonly sealing: string
  readonly record: string
}

/** A child's environment: HOME in the run's temp directory, no AC_HOME, so nothing reaches a real home. */
export function childEnv(tmp: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: tmp }
  delete env.AC_HOME
  return env
}

/** Makes `home` in a child process (keys file `jane-keys`, agent pointer `jane`) and returns its public half. */
export function makeHome(home: string, relay: string, tmp: string): Made {
  const out = execFileSync(process.execPath, [HERE, 'c31-setup', home, relay], {
    env: childEnv(tmp),
    timeout: 20_000,
    encoding: 'utf8',
  })
  return JSON.parse(out) as Made
}

/** A relay that answers the record fetch of `ac login` (GET /v0/fetch/record/<address>/address) and counts the rest. */
export class RecordRelay {
  readonly server: Server
  readonly records = new Map<string, string>()
  /** Every request but a record fetch, "METHOD path" (a publish would be one). */
  readonly other: string[] = []
  url = ''

  constructor() {
    this.server = createServer((req, res) => {
      const m = /^\/v0\/fetch\/record\/([^/]+)\/([a-z-]+)$/.exec(req.url ?? '')
      const held = m === null ? undefined : this.records.get(`${m[1]} ${m[2]}`)
      if (m === null) this.other.push(`${req.method} ${req.url}`)
      req.resume()
      if (held === undefined) {
        res.writeHead(404, { 'content-type': 'application/json' })
        res.end('{"code":"not-found"}')
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(held)
    })
  }

  async listen(): Promise<string> {
    await new Promise<void>((done) => this.server.listen(0, '127.0.0.1', done))
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`
    return this.url
  }

  close(): Promise<void> {
    return new Promise((done) => this.server.close(() => done()))
  }
}

/** One `ac login` child: its lines, its exit, and the `login ... until <instant> on <socket>` line once open. */
export class LoginChild {
  readonly child: ChildProcessWithoutNullStreams
  readonly out: string[] = []
  readonly err: string[] = []
  exit: { readonly code: number | null; readonly signal: string | null; readonly at: string } | null = null
  readonly exited: Promise<void>

  constructor(home: string, relay: string, window: number, tmp: string) {
    const args = ['--import', TTY_PRELOAD, MAIN, 'login', '--as', 'jane', '--relay', relay]
    this.child = spawn(process.execPath, [...args, '--window', String(window), '--dir', home], {
      env: childEnv(tmp),
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const split = (into: string[]) => {
      let rest = ''
      return (chunk: Buffer) => {
        rest += chunk.toString('utf8')
        const parts = rest.split('\n')
        rest = parts.pop() ?? ''
        into.push(...parts)
      }
    }
    this.child.stdout.on('data', split(this.out))
    this.child.stderr.on('data', split(this.err))
    this.child.stdin.on('error', () => {})
    this.exited = new Promise((done) =>
      this.child.on('exit', (code, signal) => {
        this.exit = { code, signal, at: new Date().toISOString() }
        done()
      }),
    )
  }

  /** The window's end in Unix seconds, once the login line is out; null when the child ended or `ms` passed first. */
  async opened(ms: number): Promise<number | null> {
    for (let t = 0; t < ms; t += 20) {
      const line = this.out.find((l) => l.startsWith('login '))
      if (line !== undefined) {
        const at = / until (\S+) on /.exec(line)?.[1]
        return at === undefined ? null : Date.parse(at) / 1000
      }
      if (this.exit !== null) return null
      await new Promise((done) => setTimeout(done, 20))
    }
    return null
  }

  /** Types a line on the fake terminal (the child's stdin). */
  type(line: string): void {
    this.child.stdin.write(`${line}\n`)
  }

  kill(): void {
    if (this.exit === null) this.child.kill('SIGKILL')
  }
}

/** The agent's audit lines of one event and decision, from <home>/agent-audit.jsonl. */
export function auditedAt(home: string, event: string, decision: string): number {
  const file = `${home}/agent-audit.jsonl`
  if (!existsSync(file)) return 0
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as { event?: unknown; decision?: unknown })
    .filter((l) => l.event === event && l.decision === decision).length
}

async function setup(home: string, relay: string): Promise<void> {
  mkdirSync(home, { recursive: true, mode: 0o700 })
  const keys = generateEdgeKeys(systemRng)
  const custody = new HomeCustody(home)
  custody.create('jane-keys', keys, { custody: 'file' })
  custody.agent.create('jane', keys)
  const now = Math.floor(Date.now() / 1000)
  // A live epoch, written as the edge's KeyEpochStore writes one, so that `ac login` finds the newest epoch under
  // 12 hours old and rotates nothing. Without it login publishes an epoch of its own after the window opens, and the
  // assertions (no request but a record fetch reaches the relay while the window is open or ends) would measure that
  // publish, not the agent. The epoch key is a fresh one, not the principal's seed.
  const epochs = new KeyEpochStore(join(home, 'key-records'))
  epochs.put(keys.signing.address, 1, sealingKeyFromSeed(systemRng.bytes(32)), now, now + 86_400)
  epochs.markPublished(keys.signing.address, 1) // a published epoch: put keeps one unpublished, which is due at once
  const record = signRecord(keys.signing, {
    kind: 'address',
    key: keys.signing.address,
    sealing_key: toHex(keys.sealing.publicKey),
    relays: [relay],
    rotation_key: null,
    revoked: [],
    ttl: 3600,
    iat: now,
    rotated_from: null,
  })
  const made: Made = {
    address: keys.signing.address,
    sealing: toHex(keys.sealing.publicKey),
    record: new TextDecoder().decode(serializeRecord(record)),
  }
  process.stdout.write(JSON.stringify(made))
}

if (process.argv[2] === 'c31-setup' && resolve(process.argv[1] ?? '') === HERE) {
  await setup(process.argv[3] as string, process.argv[4] as string)
}
