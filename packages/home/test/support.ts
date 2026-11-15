import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  parseRecord,
  recordSigner,
  type SigningKey,
  serializeRecord,
  signRecord,
} from '@usebag/core'
import {
  type EdgeKeys,
  generateEdgeKeys,
  HomeCustody,
  type RelayClient,
  RelayError,
  type SecurityResult,
  type SecurityRunner,
  systemRng,
} from '@usebag/edge'
import { afterAll } from 'vitest'
import type { HomeIo } from '../src/index.ts'

// What home's tests share: a folder per test, an identity made in a home, a fake io whose question answers as the test
// says, a relay network in memory, and a /usr/bin/security that keeps its items in memory.

const root = mkdtempSync(join(tmpdir(), 'home-acts-'))
afterAll(() => rmSync(root, { recursive: true, force: true }))
let n = 0

/** A new empty folder, made 0700. */
export function folder(): string {
  const dir = join(root, `d${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

/** The signing key of `name` among `keys`. */
export const signer = (keys: Record<string, EdgeKeys>, name: string): SigningKey =>
  (keys[name] as EdgeKeys).signing

/**
 * A new home holding a key file for each of `names`, and their keys. The home is the one folder in its parent, so what
 * an act puts beside it (identity remove's bag-left-<name>-<stamp>) is its own.
 */
export function homeWith(...names: string[]): { home: string; keys: Record<string, EdgeKeys> } {
  const home = join(folder(), 'home')
  mkdirSync(home, { mode: 0o700 })
  const keys: Record<string, EdgeKeys> = {}
  for (const name of names) {
    const k = generateEdgeKeys(systemRng)
    new HomeCustody(home).create(name, k, { custody: 'file' })
    keys[name] = k
  }
  return { home, keys }
}

/** How the fake question answers: yes, no, a throw, or a function run while it is asked (it may change a file). */
export type Answer = boolean | 'throw' | (() => boolean | Promise<boolean>)

export interface FakeIo extends HomeIo {
  readonly said: string[]
  readonly warned: string[]
  readonly asked: string[]
  /** Every line in the order given, said as `out <line>` and warned as `err <line>`. */
  readonly lines: string[]
  now: number
}

/** A HomeIo whose question answers `answer`, at clock `now`, with the relay client and security runner given. */
export function fakeIo(
  o: {
    answer?: Answer
    now?: number
    env?: Record<string, string | undefined>
    relay?: FakeRelay
    security?: SecurityRunner
  } = {},
): FakeIo {
  const io: FakeIo = {
    said: [],
    warned: [],
    asked: [],
    lines: [],
    now: o.now ?? 1_800_000_000,
    say(line) {
      io.said.push(line)
      io.lines.push(`out ${line}`)
    },
    warn(line) {
      io.warned.push(line)
      io.lines.push(`err ${line}`)
    },
    async ask(question) {
      io.asked.push(question)
      const a = o.answer ?? true
      if (a === 'throw') throw new Error('the dialog failed')
      return typeof a === 'function' ? a() : a
    },
    clock: { now: () => io.now },
    rng: systemRng,
    env: o.env ?? {},
    ...(o.security === undefined ? {} : { security: o.security }),
    relay: () => client(o.relay ?? new FakeRelay()),
  }
  return io
}

/** A relay network in memory: the newest record of each signer and kind at each URL; a URL in `down` fails. */
export class FakeRelay {
  readonly records = new Map<string, Uint8Array>()
  readonly down = new Set<string>()
  /** URLs whose publish is refused with this code. */
  readonly refuse = new Map<string, 'stale-record' | 'bad-record'>()
  readonly published: string[] = []

  async publish(
    url: string,
    bytes: Uint8Array,
  ): Promise<{ id: string; duplicate: boolean; delivered: number }> {
    if (this.down.has(url)) throw new RelayError(null, 0, null, `${url} is down`)
    const code = this.refuse.get(url)
    if (code !== undefined) throw new RelayError(code, 409, null, `${url} refused it`)
    const r = parseRecord(bytes)
    this.records.set(`${url} ${recordSigner(r)} ${r.kind}`, bytes)
    this.published.push(url)
    return { id: 'x', duplicate: false, delivered: 0 }
  }

  async fetchRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    if (this.down.has(url)) throw new RelayError(null, 0, null, `${url} is down`)
    return this.records.get(`${url} ${address} ${kind}`) ?? null
  }

  /** The roots of the accept-from of `owner` at `url`, or null. */
  rootsAt(url: string, owner: string): readonly string[] | null {
    const b = this.records.get(`${url} ${owner} accept-from`)
    return b === undefined ? null : (parseRecord(b) as AcceptFromRecord).roots
  }
}

/** The fake network as the RelayClient the acts take. */
export const client = (net: FakeRelay): RelayClient => net as unknown as RelayClient

/** An accept-from of `signing`'s address naming `roots`, at `iat`. */
export function acceptFrom(signing: SigningKey, roots: string[], iat: number): AcceptFromRecord {
  return signRecord(signing, {
    kind: 'accept-from',
    owner: signing.address,
    roots,
    max_bytes: 4096,
    ttl: 3600,
    iat,
  }) as AcceptFromRecord
}

/** Publishes `record` at each URL of the fake network. */
export async function publishAt(net: FakeRelay, record: AcceptFromRecord, ...urls: string[]): Promise<void> {
  for (const url of urls) await net.publish(url, serializeRecord(record))
}

const status = (s: number): SecurityResult => ({
  status: s,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
})

/** A /usr/bin/security that keeps its items in memory, written by a `security -i` line, read by -w. */
export class FakeSecurity {
  readonly items = new Map<string, Uint8Array>()
  calls = 0

  readonly run: SecurityRunner = (args, input) => {
    this.calls++
    const line = input === undefined ? '' : new TextDecoder().decode(input)
    if (args[0] === '-i') {
      const w = [...line.trim().matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? (m[2] as string))
      const at = (flag: string): string => w[w.indexOf(flag) + 1] as string
      const key = `${at('-s')} ${at('-a')}`
      if (this.items.has(key) && !w.includes('-U')) return status(45)
      this.items.set(key, Uint8Array.from(Buffer.from(at('-X'), 'hex')))
      return status(0)
    }
    const at = (flag: string): string => args[args.indexOf(flag) + 1] as string
    const item = this.items.get(`${at('-s')} ${at('-a')}`)
    if (item === undefined) return status(44)
    return { status: 0, stdout: Uint8Array.from([...item, 10]), stderr: new Uint8Array() }
  }
}
