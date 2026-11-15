import { existsSync, mkdirSync, readdirSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type EdgeKeys,
  generateEdgeKeys,
  HomeCustody,
  KeychainCustody,
  type SecurityRunner,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { createAgentPointer, custodyMove } from '../src/index.ts'
import { type Answer, FakeSecurity, fakeIo, folder, homeWith } from './support.ts'

// identity custody: an identity moved between its key file and its keychain item, the old copy into the Trash.

function world(answer: Answer = true) {
  const { home, keys } = homeWith('jane')
  const HOME = folder()
  const security = new FakeSecurity()
  const io = fakeIo({ answer, env: { HOME }, security: security.run })
  const address = keys.jane?.signing.address as string
  return { home, keys, HOME, security, io, address }
}

const trashOf = (HOME: string): string => {
  const [dir] = readdirSync(join(HOME, '.Trash'))
  return join(HOME, '.Trash', dir as string)
}

describe('custodyMove', () => {
  it('moves a key file into the keychain after the yes, the key file into the Trash', async () => {
    const w = world()
    await custodyMove(w.io, w.home, 'jane', { to: 'keychain' })
    const pointer = join(w.home, 'keychain', 'jane.json')
    const dest = join(trashOf(w.HOME), 'jane.json')
    expect(w.io.asked).toHaveLength(1)
    // The question reads no key, so it names no address of a key file: the key is read after the yes.
    expect(w.io.asked[0]).toContain(
      'move jane into the item bag:jane of the default keychain (access prompt):',
    )
    expect(w.io.asked[0]).not.toContain(w.address)
    expect(w.io.asked[0]).toContain('reading it back raises one macOS dialog')
    expect(w.io.said.slice(0, 4)).toEqual([
      `wrote bag:jane in the default keychain, ${pointer}`,
      `verified jane ${w.address}: the keychain copy reads back the same keys`,
      `moved ${join(w.home, 'keys', 'jane.json')} -> ${dest}`,
      `custody jane keychain ${w.address}`,
    ])
    expect(w.io.said[4]).toContain(`${dest} still holds the private key of jane`)
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(false)
    expect(existsSync(pointer)).toBe(true)
    expect(existsSync(dest)).toBe(true)
  })

  it("moves a keychain identity into a key file, and names the item's delete line", async () => {
    const home = join(folder(), 'home')
    mkdirSync(home, { mode: 0o700 })
    const security = new FakeSecurity()
    const keys = generateEdgeKeys(systemRng)
    new HomeCustody(home, { run: security.run }).create('jane', keys, {
      custody: 'keychain',
      access: 'security',
    })
    const HOME = folder()
    const io = fakeIo({ env: { HOME }, security: security.run })
    await custodyMove(io, home, 'jane', { to: 'file' })
    const address = keys.signing.address
    expect(io.said[0]).toBe(`wrote ${join(home, 'keys', 'jane.json')}`)
    expect(io.said.at(-1)).toBe(
      `the keychain item of jane stays in the macOS keychain; to delete it: security delete-generic-password -s bag:jane -a ${address}`,
    )
    expect(existsSync(join(home, 'keychain', 'jane.json'))).toBe(false)
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
  })

  it('finishes a run that stopped with both copies, and refuses two copies with other keys (bad-key)', async () => {
    const w = world()
    new KeychainCustody({ dir: join(w.home, 'keychain'), run: w.security.run }).create(
      'jane',
      w.keys.jane as EdgeKeys,
    )
    await custodyMove(w.io, w.home, 'jane', {
      to: 'keychain',
      keychain: '/k.keychain-db',
      access: 'security',
    })
    expect(w.io.asked[0]).toContain('is written already (an earlier run)')
    expect(w.io.said[0]).toBe(`verified jane ${w.address}: the keychain copy reads back the same keys`)
    const v = world()
    new KeychainCustody({ dir: join(v.home, 'keychain'), run: v.security.run }).create(
      'jane',
      generateEdgeKeys(systemRng),
    )
    await expect(custodyMove(v.io, v.home, 'jane', { to: 'keychain' })).rejects.toThrow(
      'bad-key: jane has a key file and a keychain item with different keys: nothing was changed',
    )
    // Asked first, compared after the yes: both copies stay as they were.
    expect(v.io.asked).toHaveLength(1)
    expect([
      existsSync(join(v.home, 'keys', 'jane.json')),
      existsSync(join(v.home, 'keychain', 'jane.json')),
    ]).toEqual([true, true])
  })

  it('asks before it reads the key: a no reads no key, so a keychain identity raises no keychain read', async () => {
    const home = join(folder(), 'home')
    mkdirSync(home, { mode: 0o700 })
    const security = new FakeSecurity()
    const keys = generateEdgeKeys(systemRng)
    new HomeCustody(home, { run: security.run }).create('jane', keys, {
      custody: 'keychain',
      access: 'security',
    })
    const before = security.calls
    const io = fakeIo({ answer: false, env: { HOME: folder() }, security: security.run })
    await expect(custodyMove(io, home, 'jane', { to: 'file' })).rejects.toThrow(
      'declined: nothing was changed',
    )
    // The question names the pointer's address (public), and no find-generic-password ran: the item was never read.
    expect(io.asked[0]).toContain(
      `move jane (${keys.signing.address}) into ${join(home, 'keys', 'jane.json')}:`,
    )
    expect(security.calls).toBe(before)
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(false)
    // A yes reads it once, after the question, then reads it back once more from the new file (no keychain read).
    const yes = fakeIo({ env: { HOME: folder() }, security: security.run })
    await custodyMove(yes, home, 'jane', { to: 'file' })
    expect(security.calls).toBe(before + 1)
  })

  it('refuses, changing nothing: an agent identity, the same custody, a held identity, no HOME, an item there', async () => {
    const w = world()
    createAgentPointer(fakeIo(), w.home, 'agent1', 'jane')
    await expect(custodyMove(w.io, w.home, 'agent1', { to: 'keychain' })).rejects.toThrow(
      'not-authorized: agent1 is an agent identity',
    )
    await expect(custodyMove(w.io, w.home, 'jane', { to: 'file' })).rejects.toThrow(
      'exists: jane is in file custody already',
    )
    await expect(custodyMove(w.io, w.home, 'kim', { to: 'file' })).rejects.toThrow('ENOENT')
    await expect(
      custodyMove(fakeIo({ security: w.security.run }), w.home, 'jane', { to: 'keychain' }),
    ).rejects.toThrow('usage: no HOME: the old copy moves into HOME/.Trash')
    mkdirSync(join(w.home, 'state', 'jane'), { recursive: true })
    writeFileSync(join(w.home, 'state', 'jane', 'mcp.lock'), JSON.stringify({ pid: process.pid }))
    await expect(custodyMove(w.io, w.home, 'jane', { to: 'keychain' })).rejects.toThrow(
      'held: the identity jane',
    )
    const e = world()
    e.security.items.set(`bag:jane ${e.address}`, new Uint8Array([1]))
    await expect(custodyMove(e.io, e.home, 'jane', { to: 'keychain' })).rejects.toThrow(
      'EEXIST: the keychain holds an item bag:jane already',
    )
    expect(existsSync(join(e.home, 'keychain', 'jane.json'))).toBe(false)
    expect(existsSync(join(e.home, 'keys', 'jane.json'))).toBe(true)
    expect(w.io.said).toEqual([])
  })

  it('a no, a failed dialog, or the key file changed while asked writes nothing', async () => {
    for (const [answer, err] of [
      [false, 'declined: nothing was changed'],
      ['throw', 'the dialog failed'],
    ] as const) {
      const w = world(answer)
      await expect(custodyMove(w.io, w.home, 'jane', { to: 'keychain' })).rejects.toThrow(err)
      expect([w.security.items.size, existsSync(join(w.home, 'keychain', 'jane.json'))]).toEqual([0, false])
    }
    let home = ''
    const w = world(() => {
      utimesSync(join(home, 'keys', 'jane.json'), 1, 1)
      return true
    })
    home = w.home
    await expect(custodyMove(w.io, w.home, 'jane', { to: 'keychain' })).rejects.toMatchObject({
      code: 'busy',
    })
    expect([w.security.items.size, existsSync(join(w.home, 'keychain', 'jane.json'))]).toEqual([0, false])
    expect(w.io.said).toEqual([])
  })
})

describe('custodyMove: a new copy that does not read back', () => {
  it('takes the pointer back, leaves the key file and the item, and names why and the delete line', async () => {
    const w = world()
    // The item is written; reading it back is denied at the dialog (security exits 128).
    const run: SecurityRunner = (args, input) =>
      args[0] === '-i'
        ? w.security.run(args, input)
        : { status: 128, stdout: new Uint8Array(), stderr: new Uint8Array() }
    const io = fakeIo({ env: { HOME: w.HOME }, security: run })
    await expect(custodyMove(io, w.home, 'jane', { to: 'keychain' })).rejects.toThrow(
      new RegExp(
        `^EACCES: the new copy of jane did not verify \\(.*refused, locked or denied at the dialog.*\\): nothing moved; the item stays: security delete-generic-password -s bag:jane -a ${w.address}$`,
      ),
    )
    const pointer = join(w.home, 'keychain', 'jane.json')
    expect(io.said).toEqual([`wrote bag:jane in the default keychain, ${pointer}`])
    expect(existsSync(pointer)).toBe(false)
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
    expect(w.security.items.size).toBe(1)
  })
})

describe('custodyMove: the Trash on another file system', () => {
  it('refuses EXDEV before anything is read or written: the old copy moves, never copies', async () => {
    const w = world()
    // /dev is a file system of its own on macOS and Linux: the Trash under a HOME there is never the home's.
    const io = fakeIo({ env: { HOME: '/dev/no-such-home' }, security: w.security.run })
    await expect(custodyMove(io, w.home, 'jane', { to: 'keychain' })).rejects.toThrow(
      'EXDEV: /dev/no-such-home/.Trash/bag-custody-jane-',
    )
    expect(io.asked).toEqual([])
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
    expect(w.security.items.size).toBe(0)
  })
})
