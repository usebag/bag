import { run } from '../../src/cli.ts'
import type { TestIo } from './io.ts'

/** What one command line printed and returned. */
export interface Ran {
  readonly code: number
  readonly out: string[]
  readonly err: string[]
}

/** Runs one command line on the test io and returns only the lines this run printed. */
export async function cli(io: TestIo, ...argv: string[]): Promise<Ran> {
  const o = io.stdout.length
  const e = io.stderr.length
  const code = await run(argv, io)
  return { code, out: io.stdout.slice(o), err: io.stderr.slice(e) }
}
