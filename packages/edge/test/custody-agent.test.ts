import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { hopPreimage, signHop, verifyPreimage } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { type AgentClient, AgentOpener, AgentSigner } from '../src/agent/client.ts'
import { AgentCustody } from '../src/custody/agent.ts'
import { HomeCustody } from '../src/custody/home.ts'
import { envelope } from './agent/support.ts'
import { P, tempDir } from './support/fixtures.ts'

// The agent custody: a pointer of public data per identity, a signer and an opener that ask the agent, and its
// place beside the other two in a home's list.

const tmp = tempDir('cag')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `d${n++}`)
const asked: string[] = []
const connection = {
  sign: async (sub: string) => {
    asked.push(sub)
    return signHop(P.jane.signing, sub, ['c'], 1)
  },
} as unknown as AgentClient
const hop = hopPreimage({ iss: P.jane.address, sub: P.bob.address, caveats: ['c'], exp: 1 })
const code = (fn: () => unknown): string | undefined => {
  try {
    fn()
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).message
  }
  return undefined
}

describe('AgentCustody: pointers of public data', () => {
  it('writes a 0600 pointer in a 0700 directory with no seed, and lists and finds it by name and address', () => {
    const dir = fresh()
    const custody = new AgentCustody(dir)
    expect(custody.list()).toEqual([])
    const made = custody.create('jane', P.jane.keys)
    custody.create('bob', P.bob.keys)
    expect(made).toMatchObject({ name: 'jane', address: P.jane.address, custody: 'agent' })
    expect(typeof made.created).toBe('number')
    expect(custody.kind).toBe('agent')
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(join(dir, 'jane.json')).mode & 0o777).toBe(0o600)
    const text = readFileSync(join(dir, 'jane.json'), 'utf8')
    expect(P.jane.secrets.some((s) => text.includes(s))).toBe(false)
    expect(custody.list().map((e) => e.name)).toEqual(['bob', 'jane'])
    expect(custody.entry('bob').address).toBe(P.bob.address)
    expect(custody.signer(P.jane.address)).toBeInstanceOf(AgentSigner)
    expect(custody.signer(P.jane.address).address).toBe(P.jane.address)
    expect(custody.opener(P.bob.address)).toBeInstanceOf(AgentOpener)
    expect(custody.opener(P.bob.address).publicKey).toEqual(P.bob.sealing.publicKey)
  })

  it('writes a recovery setting into the pointer and reads it back, and lists it', () => {
    const dir = fresh()
    const custody = new AgentCustody(dir)
    expect(custody.create('jane', P.jane.keys, 'personal').recovery).toBe('personal')
    expect(custody.create('bob', P.bob.keys, 'none').recovery).toBe('none')
    expect(custody.entry('jane').recovery).toBe('personal')
    expect(custody.list().map((e) => [e.name, e.recovery])).toEqual([
      ['bob', 'none'],
      ['jane', 'personal'],
    ])
    expect(JSON.parse(readFileSync(join(dir, 'jane.json'), 'utf8'))).toMatchObject({ recovery: 'personal' })
  })

  it('reads a pointer without the field, or with a value outside personal and none, as unset; none is written unasked', () => {
    const dir = fresh()
    const custody = new AgentCustody(dir)
    expect(custody.create('jane', P.jane.keys).recovery).toBeUndefined()
    expect(Object.keys(JSON.parse(readFileSync(join(dir, 'jane.json'), 'utf8')))).toEqual([
      'suite',
      'custody',
      'address',
      'sealing_key',
    ])
    const text = JSON.parse(readFileSync(join(dir, 'jane.json'), 'utf8'))
    // keys list prints the field in a line-parsed format, so an odd hand-written value is not shown (a newline, a
    // space or an escape would forge a line, a field or a terminal sequence).
    for (const [i, odd] of [5, 'odd', 'personal\nx', 'none ', '\u001b[31m'].entries()) {
      writeFileSync(join(dir, `odd-${i}.json`), JSON.stringify({ ...text, recovery: odd }), { mode: 0o600 })
      expect(custody.entry(`odd-${i}`).recovery, JSON.stringify(odd)).toBeUndefined()
    }
    expect(custody.signer(P.jane.address).address).toBe(P.jane.address)
  })

  it('refuses an unknown address, a name taken, a bad name, and a pointer or directory that is not as made', () => {
    const dir = fresh()
    const custody = new AgentCustody(dir)
    expect(code(() => custody.signer(P.jane.address))).toBe('ENOENT')
    custody.create('jane', P.jane.keys)
    expect(code(() => custody.signer(P.bob.address))).toBe('ENOENT')
    expect(code(() => custody.opener(P.bob.address))).toBe('ENOENT')
    expect(code(() => custody.create('jane', P.jane.keys))).toBe('EEXIST')
    expect(code(() => custody.create('Bad Name', P.jane.keys))).toContain('a key name is 1 to 64')
    writeFileSync(join(dir, 'odd.json'), '{}', { mode: 0o600 })
    expect(code(() => custody.entry('odd'))).toContain('is not an agent pointer')
    chmodSync(join(dir, 'jane.json'), 0o644)
    expect(code(() => custody.entry('jane'))).toContain('has mode 0644')
    chmodSync(dir, 0o755)
    expect(code(() => custody.list())).toContain('has mode 0755')
  })

  it('has no connection until one is given: its signer and opener refuse with ENOENT', async () => {
    const custody = new AgentCustody(fresh())
    custody.create('jane', P.jane.keys)
    const signing = custody.signer(P.jane.address).signPreimage(hop)
    await expect(signing).rejects.toMatchObject({ code: 'ENOENT' })
    expect(code(() => custody.opener(P.jane.address).openEnvelope(envelope().bytes))).toBe('ENOENT')
  })
})

describe('the connection a custody gives its signer', () => {
  it('is the one it was made with, directly or through a home', async () => {
    const direct = new AgentCustody(fresh(), () => connection)
    direct.create('jane', P.jane.keys)
    const sig = await direct.signer(P.jane.address).signPreimage(hop)
    expect(verifyPreimage(P.jane.address, hop, sig)).toBe(true)
    const home = new HomeCustody(fresh(), { client: () => connection })
    home.agent.create('jane', P.jane.keys)
    await home.agent.signer(P.jane.address).signPreimage(hop)
    expect(asked).toEqual([P.bob.address, P.bob.address])
  })
})

describe('HomeCustody: the agent beside the key files and the keychain', () => {
  it('lists an agent identity with the others, sorted, and finds it by name', () => {
    const home = fresh()
    mkdirSync(home)
    const custody = new HomeCustody(home)
    custody.create('jane', P.jane.keys, { custody: 'file' })
    custody.agent.create('bob', P.bob.keys)
    expect(custody.list().map((e) => [e.name, e.custody])).toEqual([
      ['bob', 'agent'],
      ['jane', 'file'],
    ])
    expect(custody.entry('bob')).toMatchObject({ address: P.bob.address, custody: 'agent' })
    expect(custody.entry('jane')).toMatchObject({ address: P.jane.address, custody: 'file' })
  })

  it('refuses a name the agent and another custody both hold', () => {
    const home = fresh()
    const custody = new HomeCustody(home)
    custody.agent.create('bob', P.bob.keys)
    expect(code(() => custody.create('bob', P.bob.keys, { custody: 'file' }))).toBe('EEXIST')
    custody.files.save('bob', P.carol.keys)
    expect(code(() => custody.entry('bob'))).toBe('EEXIST')
  })
})
