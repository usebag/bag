import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { type RecordSource, systemRng } from '@usebag/edge'
import type { Io } from '../../src/io.ts'
import type { MemoryRelay } from './relay.ts'

// The CLI's io for unit tests: lines captured, a clock the test moves, the system CSPRNG (keys are made fresh, and
// the tests read them back only to prove they are never printed), the memory relay, well-known records, TXT records
// and handle records from maps (no DNS, no fetch), and a stop signal the test aborts.

/** A fixed "now": 2027-01-15 08:00:00 UTC, as in spec/vectors. */
export const T0 = 1_800_000_000

export interface TestIo extends Io {
  readonly stdout: string[]
  readonly stderr: string[]
  readonly time: { now: number }
  readonly stop: AbortController
  readonly wellKnown: Map<string, Uint8Array>
  /** TXT records by DNS name (none for a name not set), and handle records by `<host> <handle>`. */
  readonly txt: Map<string, string[][]>
  readonly handles: Map<string, Uint8Array>
  stopAsked: number
  /** Whether stdin is a terminal (false by default), and the answers confirm gives, in order (none: no). */
  tty: boolean
  /** Whether stdout is a terminal (the recovery sheet prints only there); false by default. */
  outTty: boolean
  /** How many lines readSecret read (with the echo off). */
  secrets: number
  readonly answers: boolean[]
  /** The prompts confirm was asked. */
  readonly asked: string[]
  /** The texts prompt wrote on stderr with no newline (connect's "Paste the code: "), in order. */
  readonly prompts: string[]
  /** The lines readLine gives, in order (none left: null, the end of input). */
  readonly lines: string[]
}

export function testIo(
  relay: Pick<MemoryRelay, 'client'>,
  env: Record<string, string | undefined> = {},
): TestIo {
  const stdout: string[] = []
  const stderr: string[] = []
  const time = { now: T0 }
  const stop = new AbortController()
  const wellKnown = new Map<string, Uint8Array>()
  const txt = new Map<string, string[][]>()
  const handles = new Map<string, Uint8Array>()
  let released = false
  const io: TestIo = {
    stdout,
    stderr,
    time,
    stop,
    wellKnown,
    txt,
    handles,
    stopAsked: 0,
    tty: false,
    outTty: false,
    secrets: 0,
    answers: [],
    asked: [],
    prompts: [],
    lines: [],
    get isTty() {
      return io.tty
    },
    get outIsTty() {
      return io.outTty
    },
    confirm: async (prompt) => {
      io.asked.push(prompt)
      return io.answers.shift() ?? false
    },
    prompt: (text) => {
      io.prompts.push(text)
    },
    readLine: async () => (released ? null : (io.lines.shift() ?? null)),
    readSecret: async () => {
      io.secrets++
      return released ? null : (io.lines.shift() ?? null)
    },
    release: () => {
      released = true
      io.lines.length = 0
    },
    out: (line) => {
      stdout.push(line)
    },
    err: (line) => {
      stderr.push(line)
    },
    // DO_NOT_TRACK keeps the telemetry notice out of the lines a test reads; telemetry.test.ts unsets it to read it.
    env: { DO_NOT_TRACK: '1', ...env },
    clock: { now: () => time.now },
    rng: systemRng,
    relay: (options) => relay.client(options),
    records: (client): RecordSource => ({
      wellKnown: async (domain) => {
        const bytes = wellKnown.get(domain)
        if (bytes === undefined) throw new Error(`no well-known record for ${domain}`)
        return bytes
      },
      relayRecord: (url, address, kind) => client.fetchRecord(url, address, kind),
      txt: async (name) => txt.get(name) ?? [],
      handleRecord: async (host, handle) => handles.get(`${host} ${handle}`) ?? null,
    }),
    stopSignal: () => {
      io.stopAsked++
      return stop.signal
    },
    idleMs: 30,
  }
  return io
}

/** A temporary directory under AC_TEST_TMP (else the system's), removed by `cleanup` unless AC_KEEP_TMP=1. */
export function tempDir(prefix: string): { readonly dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-cli-${prefix}-`))
  return {
    dir,
    cleanup(): void {
      if (process.env.AC_KEEP_TMP === '1') return
      rmSync(dir, { recursive: true, force: true })
    },
  }
}
