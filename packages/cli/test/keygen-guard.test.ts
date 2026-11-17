import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { isAddress } from '@usebag/core'
import * as homeModule from '@usebag/home'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { HOLDS_IDENTITIES, heldIdentities } from '../src/commands/keygen.ts'
import { tempDir, testIo } from './support/io.ts'
import { noRelay } from './support/local-only.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('keygen-guard')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)
const REFUSED = `bag: exists: ${HOLDS_IDENTITIES}`

// createIdentity is watched (a pass-through spy) for the options keygen passes it.
vi.mock('@usebag/home', async (importOriginal) => {
  const real = await importOriginal<typeof import('@usebag/home')>()
  return { ...real, ...(await import('./support/local-only.ts')).homeOverrides(real) }
})

describe('keygen on a home that holds identities already: a new name needs --new', () => {
  it('a fresh home is unchanged: the first identity needs no --new', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const made = await cli(io, 'keygen', 'alice', '--dir', dir)
    expect(made.code).toBe(0)
    expect(isAddress(made.out[0])).toBe(true)
    expect(heldIdentities(dir)).toEqual(['alice'])
  })

  it('refuses a second name without --new (exists, nothing written, no address printed), and makes it with --new', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    expect((await cli(io, 'keygen', 'alice', '--dir', dir)).code).toBe(0)
    const refused = await cli(io, 'keygen', 'bob', '--dir', dir)
    expect(refused).toEqual({ code: 1, out: [], err: [REFUSED] })
    expect(existsSync(join(dir, 'keys', 'bob.json'))).toBe(false)
    expect(heldIdentities(dir)).toEqual(['alice'])
    const made = await cli(io, 'keygen', 'bob', '--new', '--dir', dir)
    expect(made.code).toBe(0)
    expect(isAddress(made.out[0])).toBe(true)
    expect(heldIdentities(dir)).toEqual(['alice', 'bob'])
  })

  it('a held name keeps its own refusal, with --new and without it', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const first = await cli(io, 'keygen', 'alice', '--dir', dir)
    for (const extra of [[], ['--new']]) {
      const again = await cli(io, 'keygen', 'alice', ...extra, '--dir', dir)
      expect(again.code).toBe(1)
      expect(again.err[0]).toMatch(/^bag: EEXIST: file already exists, open '.*alice\.json'$/)
    }
    expect((await cli(io, 'address', 'alice', '--dir', dir)).out).toEqual(first.out)
  })

  it("never counts the bag service's own key files (RESERVED): a lone stale service key is a fresh home", async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    mkdirSync(join(dir, 'keys'), { recursive: true, mode: 0o700 })
    for (const f of ['alice.service.json', 'alice.session.json', 'alice.signin.json'])
      writeFileSync(join(dir, 'keys', f), '{}\n', { mode: 0o600 })
    expect(heldIdentities(dir)).toEqual([])
    const made = await cli(io, 'keygen', 'bob', '--dir', dir)
    expect(made.code).toBe(0)
    expect(isAddress(made.out[0])).toBe(true)
    // Beside a real identity, the service's files are still left out, and the guard holds for a new name.
    expect(heldIdentities(dir)).toEqual(['bob'])
    expect(await cli(io, 'keygen', 'carol', '--dir', dir)).toEqual({ code: 1, out: [], err: [REFUSED] })
  })

  it('counts a 0.3.0 home by its identity files (keys/, keychain/, agent/), never by identities.json alone', async () => {
    const io = testIo(new MemoryRelay())
    for (const d of ['keychain', 'agent']) {
      const dir = home()
      mkdirSync(join(dir, d), { recursive: true, mode: 0o700 })
      writeFileSync(join(dir, d, 'old.json'), '{}\n', { mode: 0o600 })
      expect(heldIdentities(dir)).toEqual(['old'])
      expect(await cli(io, 'keygen', 'new-one', '--dir', dir)).toEqual({ code: 1, out: [], err: [REFUSED] })
    }
    const listed = home() // identities.json names ghost, which has no identity file: not held
    mkdirSync(listed, { recursive: true, mode: 0o700 })
    const ghost = {
      label: 'ghost',
      key: 'ghost',
      home: listed,
      relays: ['https://relay.example'],
      keep_alive_records: true,
    }
    writeFileSync(
      join(listed, 'identities.json'),
      `${JSON.stringify({ version: 1, identities: [ghost] })}\n`,
      {
        mode: 0o600,
      },
    )
    expect(heldIdentities(listed)).toEqual([])
    expect((await cli(io, 'keygen', 'first', '--dir', listed)).code).toBe(0)
  })

  it('an agent pointer to a held principal needs no --new, and takes it with no effect', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const principal = (await cli(io, 'keygen', 'jane', '--dir', dir)).out[0]
    const agent = ['--custody', 'agent', '--principal', 'jane', '--dir', dir]
    expect(await cli(io, 'keygen', 'jane-agent', ...agent)).toEqual({ code: 0, out: [principal], err: [] })
    expect(await cli(io, 'keygen', 'jane-agent-2', '--new', ...agent)).toEqual({
      code: 0,
      out: [principal],
      err: [],
    })
    expect(heldIdentities(dir)).toEqual(['jane', 'jane-agent', 'jane-agent-2'])
  })
})

describe('keygen --local: an identity on this machine only', () => {
  it('passes local: true to the home, contacts no relay, and the home writes relays []', async () => {
    const net = noRelay()
    const io = testIo(net)
    const dir = home()
    const made = await cli(io, 'keygen', 'sam', '--local', '--custody', 'file', '--dir', dir)
    expect(made.code).toBe(0)
    expect(isAddress(made.out[0])).toBe(true)
    const create = vi.mocked(homeModule.createIdentity)
    expect(create.mock.lastCall?.[2]).toBe('sam')
    expect(create.mock.lastCall?.[3]).toMatchObject({ local: true, into: { custody: 'file' } })
    expect(net.calls).toEqual([])
    const doc = JSON.parse(readFileSync(join(dir, 'identities.json'), 'utf8'))
    expect(doc.identities.find((e: { label: string }) => e.label === 'sam').relays).toEqual([])
    // Without --local nothing says local.
    expect((await cli(io, 'keygen', 'ann', '--new', '--custody', 'file', '--dir', dir)).code).toBe(0)
    expect(create.mock.lastCall?.[3]).not.toHaveProperty('local')
  })

  it('--custody agent --local is usage: no pointer, nothing written', async () => {
    const io = testIo(noRelay())
    const dir = home()
    expect((await cli(io, 'keygen', 'jane', '--dir', dir)).code).toBe(0)
    const agent = ['--custody', 'agent', '--principal', 'jane', '--local', '--dir', dir]
    const refused = await cli(io, 'keygen', 'jane-agent', ...agent)
    expect(refused.code).toBe(1)
    expect(refused.err[0]).toBe('bag: usage: --local goes with --custody file or keychain')
    expect(existsSync(join(dir, 'agent', 'jane-agent.json'))).toBe(false)
  })
})
