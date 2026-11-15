import { existsSync, lstatSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  byVersion,
  currentFile,
  currentVersion,
  pruneVersions,
  stableNode,
  versionLine,
  versionsDir,
} from '../src/index.ts'
import { folder } from './support.ts'

// The node another program's files name, the version line, and the versions a home keeps under <home>/package.

describe('stableNode', () => {
  const CELLAR = '/opt/homebrew/Cellar/node/25.8.1_1/bin/node'
  const LINKS = ['/opt/homebrew/bin/node', '/usr/local/bin/node']
  const fs = (map: Record<string, string>) => (p: string) => {
    const r = map[p]
    if (r === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    return r
  }

  it("names Homebrew's link when it resolves to the node given, else that node", () => {
    expect(stableNode(CELLAR, LINKS, fs({ [CELLAR]: CELLAR, [LINKS[1] as string]: CELLAR }))).toBe(LINKS[1])
    expect(stableNode(CELLAR, LINKS, fs({ [CELLAR]: CELLAR }))).toBe(CELLAR)
    expect(stableNode('/other/node', LINKS, fs({ [LINKS[0] as string]: CELLAR }))).toBe('/other/node')
    expect(stableNode('/no/such/node')).toBe('/no/such/node')
  })
})

describe('versionLine', () => {
  it('from source: bag source and the checkout commit, or unknown', () => {
    expect(versionLine()).toMatch(/^bag source ([0-9a-f]{40}|unknown)$/)
  })
})

describe('the versions of a home', () => {
  it('orders versions by their numbers, reads current, and prunes only what no one can run', () => {
    expect(['1.0.10', '1.0.9', '0.4.0', '1.0.9-rc'].sort(byVersion)).toEqual([
      '0.4.0',
      '1.0.9',
      '1.0.9-rc',
      '1.0.10',
    ])
    const home = folder()
    expect(currentVersion(home)).toBeNull()
    expect(pruneVersions(home, () => false)).toEqual([])
    const dir = versionsDir(home)
    for (const v of ['0.3.0', '0.3.1', '0.4.0', '0.5.0', '.0.6.0.123.tmp', '.0.6.0.456.tmp'])
      mkdirSync(join(dir, v), { recursive: true })
    writeFileSync(currentFile(home), '0.4.0\n')
    expect(currentVersion(home)).toBe('0.4.0')
    mkdirSync(join(home, 'run'))
    writeFileSync(join(home, 'run', 'service.json'), JSON.stringify({ package_dir: join(dir, '0.3.0') }))
    const removed = pruneVersions(home, (pid) => pid === 123)
    expect(removed.sort()).toEqual(['.0.6.0.456.tmp', '0.5.0'])
    for (const kept of ['0.3.0', '0.3.1', '0.4.0', '.0.6.0.123.tmp'])
      expect(existsSync(join(dir, kept))).toBe(true)
    writeFileSync(currentFile(home), '../x\n')
    expect(currentVersion(home)).toBeNull()
  })
})

describe('pruneVersions and the running service', () => {
  it('keeps no version for a service.json that names none, or names a folder that is not there', () => {
    const home = folder()
    const dir = versionsDir(home)
    for (const v of ['0.0.5', '0.1.0', '0.2.0']) mkdirSync(join(dir, v), { recursive: true })
    writeFileSync(currentFile(home), '0.2.0\n')
    // No run folder: no service named.
    expect(pruneVersions(home, () => false)).toEqual(['0.0.5'])
    mkdirSync(join(dir, '0.0.6'))
    mkdirSync(join(home, 'run'))
    writeFileSync(join(home, 'run', 'service.json'), JSON.stringify({ pid: 1 }))
    expect(pruneVersions(home, () => false)).toEqual(['0.0.6'])
    mkdirSync(join(dir, '0.0.7'))
    writeFileSync(join(home, 'run', 'service.json'), JSON.stringify({ package_dir: '/no/such/dir/0.0.7' }))
    expect(pruneVersions(home, () => false)).toEqual(['0.0.7'])
    expect(existsSync(join(dir, '0.1.0'))).toBe(true)
  })
})

describe('pruneVersions and links inside a version', () => {
  it('removes a version folder that holds a symbolic link whose target is gone', () => {
    const home = folder()
    const dir = versionsDir(home)
    for (const v of ['0.0.1', '0.1.0', '0.2.0']) mkdirSync(join(dir, v), { recursive: true })
    symlinkSync('/no/such/target', join(dir, '0.0.1', 'dangling.js'))
    writeFileSync(currentFile(home), '0.2.0\n')
    expect(pruneVersions(home, () => false)).toEqual(['0.0.1'])
    expect(() => lstatSync(join(dir, '0.0.1'))).toThrow()
    expect(existsSync(join(dir, '0.1.0'))).toBe(true)
  })
})
