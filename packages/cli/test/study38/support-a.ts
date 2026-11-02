import { existsSync, readFileSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { toHex } from '@usebag/core'
import type { AgentHome } from '../support/agent.ts'

// Half A in the cli (G1, G3): a raw client
// of an `ac login` agent's socket that reads every reply line, the agent's audit read back from its file, the
// zeroing watch of login.test.ts, and the MEASURE line.

export type Reply = Record<string, unknown>

/** One raw connection: lines in order, null once it has closed with none left. */
export class RawWire {
  readonly received: string[] = []
  error: string | null = null
  readonly #socket: Socket
  readonly #queue: string[] = []
  readonly #waiting: ((line: string | null) => void)[] = []
  #closed = false

  constructor(path: string) {
    this.#socket = createConnection(path)
    const record = (e: NodeJS.ErrnoException): void => {
      this.error ??= e.code ?? e.message
    }
    this.#socket.on('error', record)
    // The readline interface re-emits its input's error: without a listener of its own a refused connection is uncaught.
    createInterface({ input: this.#socket })
      .on('error', record)
      .on('line', (line) => {
        this.received.push(line)
        const w = this.#waiting.shift()
        if (w === undefined) this.#queue.push(line)
        else w(line)
      })
    this.#socket.on('close', () => {
      this.#closed = true
      for (const w of this.#waiting.splice(0)) w(null)
    })
  }

  next(): Promise<Reply | null> {
    const queued = this.#queue.shift()
    if (queued !== undefined) return Promise.resolve(JSON.parse(queued) as Reply)
    if (this.#closed) return Promise.resolve(null)
    return new Promise((resolve) =>
      this.#waiting.push((l) => resolve(l === null ? null : (JSON.parse(l) as Reply))),
    )
  }

  write(text: string): void {
    if (!this.#closed) this.#socket.write(text)
  }

  close(): void {
    this.#socket.destroy()
  }
}

/** The agent's audit lines of one event and decision, read back from <home>/agent-audit.jsonl. */
export function audited(h: AgentHome, event: string, decision: string): number {
  const file = join(h.dir, 'agent-audit.jsonl')
  if (!existsSync(file)) return 0
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as { event: string; decision: string })
    .filter((l) => l.event === event && l.decision === decision).length
}

/** Watches every 32-byte array overwritten with zeros (login.test.ts's watch): what it held, and the array. */
export function zeroed(): { readonly seen: Map<string, Uint8Array>; restore(): void } {
  const seen = new Map<string, Uint8Array>()
  const fill = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function (this: Uint8Array, v: number, start?: number, end?: number) {
    if (this.length === 32 && v === 0) seen.set(toHex(this), this)
    return fill.call(this, v, start, end)
  } as typeof fill
  return {
    seen,
    restore: () => {
      Uint8Array.prototype.fill = fill
    },
  }
}

/** Whether the window's end overwrote the principal's two seeds, in the buffers login read them into. */
export function seedsZeroed(z: ReturnType<typeof zeroed>, h: AgentHome): boolean {
  const own = [h.keys.signing.exportSeed(), h.keys.sealing.exportSeed()].map((s) => z.seen.get(toHex(s)))
  return own.every((b) => b?.every((x) => x === 0))
}

export function measure(line: string, arm: string, text: string): void {
  console.log(`MEASURE ${line}(${arm}): ${text}`)
}

export function notRun(line: string, arm: string, reason: string): void {
  console.log(`MEASURE ${line}(${arm}): not run: ${reason}`)
}

/** Waits, bounded, for `done`. */
export async function until(done: () => boolean, tries = 300): Promise<boolean> {
  for (let i = 0; i < tries && !done(); i++) await new Promise((resolve) => setTimeout(resolve, 10))
  return done()
}
