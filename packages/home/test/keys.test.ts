import { writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  checkIdentity,
  checkNoWindow,
  createAgentPointer,
  homeCustody,
  loadKeys,
  windowOf,
} from '../src/index.ts'
import { fakeIo, homeWith } from './support.ts'

// The keys of a home's identities through their custodies, and the login window that may hold one.

describe('homeCustody, checkIdentity and loadKeys', () => {
  it('finds a key file identity and loads its keys; ENOENT for one the home lacks', () => {
    const { home, keys } = homeWith('jane')
    expect(() => checkIdentity(undefined, home, 'jane')).not.toThrow()
    expect(() => checkIdentity(undefined, home, 'kim')).toThrow(
      `ENOENT: no identity kim in ${home}: no key file, keychain or agent pointer`,
    )
    expect(() => checkIdentity(undefined, home, '../x')).toThrow()
    expect(loadKeys(undefined, home, 'jane').signing.address).toBe(keys.jane?.signing.address)
  })

  it('reaches no keychain without a runner: the keychain refuses ENOENT', () => {
    const { home } = homeWith()
    const keys = generateEdgeKeys(systemRng)
    expect(() => homeCustody(undefined, home).create('jane', keys, { custody: 'keychain' })).toThrow(
      'this io runs no /usr/bin/security',
    )
  })

  it("refuses the agent's keys: it signs a session's hops only (not-authorized)", () => {
    const { home } = homeWith('jane')
    createAgentPointer(fakeIo(), home, 'agent1', 'jane')
    expect(() => loadKeys(undefined, home, 'agent1')).toThrow('not-authorized: agent1 is held by the agent')
  })
})

describe('windowOf and checkNoWindow', () => {
  it('is null with no socket, no agent pointer for the address, or a socket that does not accept', async () => {
    const { home, keys } = homeWith('jane')
    const address = keys.jane?.signing.address as string
    expect(await windowOf(undefined, home, address)).toBeNull()
    writeFileSync(join(home, 'agent.sock'), '')
    expect(await windowOf(undefined, home, address)).toBeNull()
    createAgentPointer(fakeIo(), home, 'agent1', 'jane')
    expect(await windowOf(undefined, home, address)).toBeNull()
    await expect(checkNoWindow(undefined, home, address)).resolves.toBeUndefined()
  })

  it("names the agent identity whose window's socket accepts, and refuses a record then (window-open)", async () => {
    const { home, keys } = homeWith('jane')
    const address = keys.jane?.signing.address as string
    createAgentPointer(fakeIo(), home, 'agent1', 'jane')
    const server = createServer((s) => s.destroy())
    await new Promise<void>((done) => server.listen(join(home, 'agent.sock'), done))
    try {
      expect(await windowOf(undefined, home, address)).toBe('agent1')
      await expect(checkNoWindow(undefined, home, address)).rejects.toThrow(
        'window-open: a login window holds agent1: run ac logout first',
      )
    } finally {
      await new Promise<void>((done) => server.close(() => done()))
    }
  })
})
