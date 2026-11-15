import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { addTrust, isTrustRoot, readTrust, removeTrust, writeTrustFile } from '../src/index.ts'
import { folder } from './support.ts'

// The trust file of a home: the roots a person granted, written whole.

const a1 = generateEdgeKeys(systemRng).signing.address

describe('the trust file', () => {
  it('holds addresses and domain roots only', () => {
    expect(isTrustRoot(a1)).toBe(true)
    expect(isTrustRoot('domain:example.com')).toBe(true)
    expect(isTrustRoot('domain:example.com:443')).toBe(false)
    expect(isTrustRoot('*')).toBe(false)
  })

  it('reads none with no file, and refuses one that is not a trust file of version 1', () => {
    const home = folder()
    expect(readTrust(home)).toEqual({})
    writeFileSync(join(home, 'trust.json'), '{')
    expect(() => readTrust(home)).toThrow('trust-invalid: ')
    for (const d of [
      { version: 2, roots: {} },
      { version: 1, roots: [] },
      { version: 1, roots: { x: { added_at: 1 } } },
    ]) {
      writeFileSync(join(home, 'trust.json'), JSON.stringify(d))
      expect(() => readTrust(home)).toThrow('is not a trust file of version 1')
    }
    writeFileSync(
      join(home, 'trust.json'),
      JSON.stringify({ version: 1, roots: { [a1]: { added_at: 'now' } } }),
    )
    expect(() => readTrust(home)).toThrow('trust-invalid')
  })

  it('adds a root (one it has stays as it was) and removes it, 0600 each time; a root it lacks is false', () => {
    const home = folder()
    expect(() => addTrust(home, '*', 1)).toThrow('trust-invalid: "*" is not a root a trust file holds')
    expect(() => removeTrust(home, '*')).toThrow('trust-invalid')
    addTrust(home, a1, 5)
    addTrust(home, a1, 9)
    addTrust(home, 'domain:example.com', 7)
    expect(readTrust(home)).toEqual({ [a1]: { added_at: 5 }, 'domain:example.com': { added_at: 7 } })
    expect(statSync(join(home, 'trust.json')).mode & 0o777).toBe(0o600)
    expect(removeTrust(home, a1)).toBe(true)
    expect(removeTrust(home, a1)).toBe(false)
    expect(readTrust(home)).toEqual({ 'domain:example.com': { added_at: 7 } })
  })

  it('keeps fields it does not read, written as two-space JSON with a newline', () => {
    const home = folder()
    const roots = { [a1]: { added_at: 1, source: 'org:example.com', granted_by: null, granted_at: 2 } }
    writeTrustFile(home, roots)
    expect(readFileSync(join(home, 'trust.json'), 'utf8')).toBe(
      `${JSON.stringify({ version: 1, roots }, null, 2)}\n`,
    )
    addTrust(home, 'domain:example.com', 3)
    expect(readTrust(home)[a1]).toEqual(roots[a1])
  })
})
