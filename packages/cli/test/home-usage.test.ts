import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The usage refusals that the identity acts throw from packages/home reach the command line as its own usage errors:
// the same stderr line as when the acts lived here, then the line that says how to read the commands, exit 1.

const tmp = tempDir('home-usage')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)
const R1 = 'https://r1.example'

/** The line every usage error prints after its own, as `bag nocommand` prints it. */
async function helpLine(): Promise<string> {
  const r = await cli(testIo(new MemoryRelay()), 'nocommand')
  return r.err[1] as string
}

/** A home with jane's key file made, and her address. */
async function withJane(io: ReturnType<typeof testIo>): Promise<{ dir: string; address: string }> {
  const dir = home()
  const made = await cli(io, 'keygen', 'jane', '--dir', dir)
  expect(made.code).toBe(0)
  return { dir, address: made.out[0] as string }
}

describe('the usage refusals of the home acts, through the command line', () => {
  it('identity custody with no HOME', async () => {
    const io = testIo(new MemoryRelay())
    const { dir } = await withJane(io)
    io.tty = true
    const r = await cli(io, 'identity', 'custody', 'jane', '--to', 'keychain', '--dir', dir)
    expect(r).toEqual({
      code: 1,
      out: [],
      err: ['bag: usage: no HOME: the old copy moves into HOME/.Trash', await helpLine()],
    })
  })

  it('keygen with an install env relay that is not a URL, or not an http or https one', async () => {
    for (const [relay, line] of [
      ['nope', 'bag: usage: "nope" is not a URL'],
      ['ftp://r.example', 'bag: usage: "ftp://r.example" is not an http or https URL'],
    ] as const) {
      const io = testIo(new MemoryRelay())
      const dir = home()
      mkdirSync(join(dir, 'install'), { recursive: true })
      writeFileSync(join(dir, 'install', 'jane.env'), `RELAYS="${relay}"\n`)
      const r = await cli(io, 'keygen', 'jane', '--dir', dir)
      expect(r).toEqual({ code: 1, out: [], err: [line, await helpLine()] })
    }
  })

  it('inbox with a --trust-root that is neither an address nor a domain', async () => {
    const io = testIo(new MemoryRelay())
    const { dir } = await withJane(io)
    const args = ['--as', 'jane', '--relay', R1, '--trust-root', 'Bad Root', '--once', '--dir', dir]
    const r = await cli(io, 'inbox', ...args)
    expect(r).toEqual({
      code: 1,
      out: [],
      err: ['bag: usage: --trust-root "Bad Root" is neither an address nor a domain', await helpLine()],
    })
  })

  it('unpair of its own address', async () => {
    const io = testIo(new MemoryRelay())
    const { dir, address } = await withJane(io)
    io.tty = true
    const r = await cli(io, 'unpair', address, '--as', 'jane', '--relay', R1, '--dir', dir)
    expect(r).toEqual({ code: 1, out: [], err: [`bag: usage: ${address} is jane itself`, await helpLine()] })
  })
})
