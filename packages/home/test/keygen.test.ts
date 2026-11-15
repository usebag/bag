import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  createAgentPointer,
  createIdentity,
  HOLDS_IDENTITIES,
  heldIdentities,
  readIdentities,
  refuseSecond,
  visibleLine,
  wordPath,
  writeWhole,
} from '../src/index.ts'
import { FakeSecurity, fakeIo, folder, homeWith } from './support.ts'

// A new identity in a home: a key file or keychain item, or an agent pointer, its address said.

const FILE = { into: { custody: 'file' as const }, defaulted: false, allowNew: false }

describe('heldIdentities and refuseSecond', () => {
  it("names a home's key files, keychain and agent pointers, but not the service's own or a hidden file", () => {
    const { home } = homeWith('kim', 'jane')
    writeFileSync(join(home, 'keys', 'jane.service.json'), '{}')
    writeFileSync(join(home, 'keys', '.tmp.json'), '{}')
    writeFileSync(join(home, 'keys', 'notes.txt'), '')
    mkdirSync(join(home, 'agent'))
    writeFileSync(join(home, 'agent', 'amy.json'), '{}')
    expect(heldIdentities(home)).toEqual(['amy', 'jane', 'kim'])
    expect(heldIdentities(folder())).toEqual([])
  })

  it('refuses a new name on a home that holds others (exists) unless a new one is asked for', () => {
    const { home } = homeWith('jane')
    expect(() => refuseSecond(home, 'kim', false)).toThrow(`exists: ${HOLDS_IDENTITIES}`)
    expect(() => refuseSecond(home, 'kim', true)).not.toThrow()
    expect(() => refuseSecond(home, 'jane', false)).not.toThrow()
    expect(() => refuseSecond(folder(), 'jane', false)).not.toThrow()
  })
})

describe('createIdentity', () => {
  it('T6: with relays, adds its service entry with them on a home with none, in a key file, and wires nothing', () => {
    const home = folder()
    const io = fakeIo()
    const address = createIdentity(io, home, 'jane', {
      ...FILE,
      allowNew: true,
      relays: ['https://r1.example', 'http://r2.example:8080'],
    })
    expect(io.said).toEqual([address])
    const file = join(home, 'identities.json')
    expect(readIdentities(file, true).identities).toMatchObject([
      { label: 'jane', key: 'jane', relays: ['https://r1.example', 'http://r2.example:8080'] },
    ])
    expect(io.warned).toEqual([
      `added jane to ${file} for the bag service (relays https://r1.example http://r2.example:8080)`,
      visibleLine('jane'),
    ])
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
    expect(existsSync(join(home, 'keychain'))).toBe(false)
    expect(existsSync(join(home, 'install'))).toBe(false)
    expect(io.asked).toEqual([])
  })

  it('makes a key file and says its address, warning nothing on a home with no service relay', () => {
    const home = folder()
    const io = fakeIo()
    const address = createIdentity(io, home, 'jane', FILE)
    expect(io.said).toEqual([address])
    expect(io.warned).toEqual([])
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
  })

  it('warns, in order: the note, the service entry, and how to keep it apart while local delivery is on', () => {
    const home = folder()
    mkdirSync(join(home, 'install'))
    writeFileSync(join(home, 'install', 'jane.env'), 'RELAYS="https://r1.example"\n')
    const io = fakeIo()
    const address = createIdentity(io, home, 'jane', { ...FILE, note: 'a note' })
    const file = join(home, 'identities.json')
    expect(io.lines).toEqual([
      'err a note',
      `err added jane to ${file} for the bag service (relays https://r1.example)`,
      `err ${visibleLine('jane')}`,
      `out ${address}`,
    ])
    expect(readIdentities(file, true).identities.map((e) => e.label)).toEqual(['jane'])
  })

  it('says nothing of local delivery when it is off or the name is hidden', () => {
    for (const word of [
      { version: 2, local_delivery: 'off', hidden: [] },
      { version: 2, local_delivery: 'on', hidden: ['jane'] },
    ]) {
      const home = folder()
      mkdirSync(join(home, 'install'))
      writeFileSync(join(home, 'install', 'jane.env'), 'RELAYS="https://r1.example"\n')
      writeWhole(home, wordPath(home), word)
      const io = fakeIo()
      createIdentity(io, home, 'jane', FILE)
      expect(io.warned).toHaveLength(1)
    }
  })

  it('a defaulted keychain says so; a custody that refuses is mapped by the caller, nothing said', () => {
    const home = folder()
    const security = new FakeSecurity()
    const io = fakeIo({ security: security.run })
    createIdentity(io, home, 'jane', { into: { custody: 'keychain' }, defaulted: true, allowNew: false })
    expect(io.warned).toEqual(['keygen: jane is kept in the macOS keychain (bag:jane)'])
    expect(existsSync(join(home, 'keychain', 'jane.json'))).toBe(true)
    const io2 = fakeIo()
    const refused = (e: unknown) => new Error(`mapped ${(e as Error).message}`)
    expect(() =>
      createIdentity(io2, folder(), 'kim', {
        into: { custody: 'keychain' },
        defaulted: true,
        allowNew: false,
        refused,
      }),
    ).toThrow(/^mapped /)
    expect(() =>
      createIdentity(io2, folder(), 'kim', {
        into: { custody: 'keychain' },
        defaulted: true,
        allowNew: false,
      }),
    ).toThrow('this io runs no /usr/bin/security')
    expect(io2.lines).toEqual([])
  })

  it('refuses a reserved name, a second identity without allowNew, and a name a custody holds', () => {
    const { home } = homeWith('jane')
    expect(() => createIdentity(fakeIo(), home, 'kim.service', { ...FILE, allowNew: true })).toThrow(
      'bad-name',
    )
    expect(() => createIdentity(fakeIo(), home, 'kim', FILE)).toThrow(`exists: ${HOLDS_IDENTITIES}`)
    expect(() => createIdentity(fakeIo(), home, 'jane', FILE)).toThrow(/EEXIST/)
    expect(createIdentity(fakeIo(), home, 'kim', { ...FILE, allowNew: true })).toMatch(/^ed25519:/)
  })
})

describe('createAgentPointer', () => {
  it("points to a key file identity's address, with its recovery word; EEXIST for a name a key custody holds", () => {
    const { home, keys } = homeWith('jane')
    const io = fakeIo()
    expect(createAgentPointer(io, home, 'agent1', 'jane', 'none')).toBe(keys.jane?.signing.address)
    expect(io.said).toEqual([keys.jane?.signing.address])
    expect(existsSync(join(home, 'agent', 'agent1.json'))).toBe(true)
    expect(() => createAgentPointer(fakeIo(), home, 'jane', 'jane')).toThrow(
      `EEXIST: jane is held already, by ${join(home, 'keys', 'jane.json')}`,
    )
    expect(() => createAgentPointer(fakeIo(), home, 'x.signin', 'jane')).toThrow('bad-name')
  })

  it('adds the agent identity to identities.json for the bag service when a relay is known, with its warns', () => {
    const { home, keys } = homeWith('jane')
    mkdirSync(join(home, 'install'))
    writeFileSync(join(home, 'install', 'agent1.env'), 'RELAYS="https://r1.example"\n')
    const io = fakeIo()
    createAgentPointer(io, home, 'agent1', 'jane')
    const file = join(home, 'identities.json')
    expect(io.lines).toEqual([
      `err added agent1 to ${file} for the bag service (relays https://r1.example)`,
      `err ${visibleLine('agent1')}`,
      `out ${keys.jane?.signing.address}`,
    ])
    expect(readIdentities(file, true).identities).toMatchObject([
      { label: 'agent1', key: 'agent1', relays: ['https://r1.example'] },
    ])
  })

  it('writes no identities.json when no relay is known, and says only the address', () => {
    const { home, keys } = homeWith('jane')
    const io = fakeIo()
    createAgentPointer(io, home, 'agent1', 'jane')
    expect(existsSync(join(home, 'identities.json'))).toBe(false)
    expect(io.lines).toEqual([`out ${keys.jane?.signing.address}`])
  })
})
