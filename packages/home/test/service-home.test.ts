import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { addToServiceHome, installEnv, RESERVED, readIdentities, refuseReserved } from '../src/index.ts'
import { folder } from './support.ts'

// The bag service's identities file in a home: an identity made or restored there is added to it.

const env = (home: string, name: string, text: string): void => {
  mkdirSync(join(home, 'install'), { recursive: true })
  writeFileSync(join(home, 'install', `${name}.env`), text)
}

describe('installEnv', () => {
  it('reads RELAYS and RENDEZVOUS as text; null with no file or no RELAYS', () => {
    const home = folder()
    expect(installEnv(home, 'jane')).toBeNull()
    env(home, 'jane', 'OTHER="1"\n')
    expect(installEnv(home, 'jane')).toBeNull()
    env(home, 'jane', 'RELAYS="https://r1.example  https://r2.example"\nRENDEZVOUS="https://meet.example"\n')
    expect(installEnv(home, 'jane')).toEqual({
      relays: ['https://r1.example', 'https://r2.example'],
      rendezvous: 'https://meet.example',
    })
    env(home, 'kim', 'RELAYS="https://r1.example"\n')
    expect(installEnv(home, 'kim')).toEqual({ relays: ['https://r1.example'], rendezvous: null })
  })
})

describe('addToServiceHome', () => {
  it('adds nothing when no relay is known, and the given relays when there are', () => {
    const home = folder()
    expect(addToServiceHome(home, 'jane')).toBeNull()
    expect(existsSync(join(home, 'identities.json'))).toBe(false)
    const file = join(home, 'identities.json')
    expect(addToServiceHome(home, 'jane', ['https://r1.example/'], 'https://meet.example')).toBe(
      `added jane to ${file} for the bag service (relays https://r1.example/)`,
    )
    expect(readIdentities(file, true).identities).toEqual([
      {
        label: 'jane',
        key: 'jane',
        home,
        relays: ['https://r1.example'],
        rendezvous: 'https://meet.example',
        keep_alive_records: true,
      },
    ])
    expect(addToServiceHome(home, 'jane', ['https://r9.example'])).toBeNull()
  })

  it("takes install/<name>.env's relays and rendezvous, else the file's first entry's relays", () => {
    const home = folder()
    env(home, 'jane', 'RELAYS="https://r1.example"\nRENDEZVOUS="https://meet.example"\n')
    expect(addToServiceHome(home, 'jane')).toContain('(relays https://r1.example)')
    expect(addToServiceHome(home, 'kim')).toContain('added kim')
    const all = readIdentities(join(home, 'identities.json'), true).identities
    expect(all.map((e) => [e.label, e.relays, e.rendezvous])).toEqual([
      ['jane', ['https://r1.example'], 'https://meet.example'],
      ['kim', ['https://r1.example'], undefined],
    ])
  })

  it("local: relays [] and no rendezvous, never the install env's or the first entry's", () => {
    const home = folder()
    env(home, 'jane', 'RELAYS="https://r1.example"\nRENDEZVOUS="https://meet.example"\n')
    addToServiceHome(home, 'kim', ['https://r2.example'])
    const file = join(home, 'identities.json')
    expect(addToServiceHome(home, 'jane', [], undefined, true)).toBe(
      `added jane to ${file} for the bag service (relays none: this machine only)`,
    )
    expect(readIdentities(file, true).identities.map((e) => [e.label, e.relays, e.rendezvous])).toEqual([
      ['kim', ['https://r2.example'], undefined],
      ['jane', [], undefined],
    ])
    // A later identity with no relay given does not inherit [] from a first entry on this machine only.
    const solo = folder()
    addToServiceHome(solo, 'jane', [], undefined, true)
    expect(addToServiceHome(solo, 'kim')).toBeNull()
  })

  it('a relay of install/<name>.env that is not a URL is usage, nothing written', () => {
    const home = folder()
    env(home, 'jane', 'RELAYS="nope"\n')
    expect(() => addToServiceHome(home, 'jane')).toThrow('usage: "nope" is not a URL')
    expect(existsSync(join(home, 'identities.json'))).toBe(false)
  })

  it('adds to a file that lists none as to no file: an empty home, not identities-invalid', () => {
    const home = folder()
    const file = join(home, 'identities.json')
    writeFileSync(file, JSON.stringify({ version: 1, identities: [] }), { mode: 0o600 })
    expect(addToServiceHome(home, 'jane', ['https://r1.example'])).toContain('added jane')
    expect(readIdentities(file, true).identities.map((e) => e.label)).toEqual(['jane'])
    // Anything else that fails the check still fails it: a file with another member is not an empty home.
    writeFileSync(file, JSON.stringify({ version: 1, identities: [], extra: 1 }), { mode: 0o600 })
    expect(() => addToServiceHome(home, 'kim', ['https://r1.example'])).toThrow('identities-invalid')
  })

  it('an empty list still passes every check of the file first: a FIFO refuses at once, a 0644 one says chmod 600', () => {
    const home = folder()
    const file = join(home, 'identities.json')
    // A FIFO would hold a blocking reader for ever: it is refused at once, never read (the test's own timeout guards).
    execFileSync('mkfifo', ['-m', '600', file])
    expect(() => addToServiceHome(home, 'jane', ['https://r1.example'])).toThrow('is not a regular file')
    rmSync(file)
    writeFileSync(file, JSON.stringify({ version: 1, identities: [] }), { mode: 0o644 })
    chmodSync(file, 0o644)
    expect(() => addToServiceHome(home, 'jane', ['https://r1.example'])).toThrow('chmod 600 it')
  }, 5000)
})

describe('refuseReserved', () => {
  it("refuses a name ending in a suffix of the service's own files, bad-name", () => {
    expect(RESERVED).toEqual(['.service', '.session', '.signin'])
    expect(() => refuseReserved('jane')).not.toThrow()
    expect(() => refuseReserved('jane.service')).toThrow(
      `bad-name: "jane.service" ends in .service, which is reserved for the bag service's own files`,
    )
  })
})
