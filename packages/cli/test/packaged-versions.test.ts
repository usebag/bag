import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { byVersion, currentVersion, pruneVersions, versionsDir } from '../src/packaged.ts'
import { tempDir } from './support/io.ts'

// The versioned package directories the bag service starts from (docs/bag-service.md, section 9): the installer stages
// <home>/package/versions/<version>/ and the current pointer (stage.ts, the CLI lane's); pruneVersions removes only what
// no running service and no pointer names, and never a staging directory whose process lives.

let tmp: ReturnType<typeof tempDir>
let home: string
beforeEach(() => {
  tmp = tempDir('versions')
  home = tmp.dir
})
afterEach(() => tmp.cleanup())

const make = (...names: string[]): void => {
  for (const n of names) {
    mkdirSync(join(versionsDir(home), n), { recursive: true })
    writeFileSync(join(versionsDir(home), n, 'bag-mcp.js'), '')
  }
}

describe('pruneVersions', () => {
  it("keeps the current version and the running service's, a live staging dir, and removes the rest", () => {
    make('0.3.0', '0.4.0', '0.4.1', '0.4.2', '.0.4.3.4242.tmp', '.0.4.4.999.tmp')
    mkdirSync(join(home, 'run'), { recursive: true })
    writeFileSync(
      join(home, 'run', 'service.json'),
      JSON.stringify({ pid: 1, package_dir: join(versionsDir(home), '0.4.1') }),
    )
    make('0.4.10')
    writeFileSync(join(home, 'package', 'current'), '0.4.10\n')
    const removed = pruneVersions(home, (pid) => pid === 4242)
    // current (0.4.10), the one before it (0.4.2, by number), the running service's (0.4.1) and a live staging dir stay.
    expect(removed.sort()).toEqual(['.0.4.4.999.tmp', '0.3.0', '0.4.0'])
    expect(readdirSync(versionsDir(home)).sort()).toEqual(['.0.4.3.4242.tmp', '0.4.1', '0.4.10', '0.4.2'])
    rmSync(join(home, 'run', 'service.json'))
    expect(pruneVersions(home, () => false).sort()).toEqual(['.0.4.3.4242.tmp', '0.4.1'])
    expect(readdirSync(versionsDir(home)).sort()).toEqual(['0.4.10', '0.4.2'])
  })

  it('reads the pointer strictly, ignores a service.json outside versions/, and does nothing without versions/', () => {
    expect(pruneVersions(home, () => false)).toEqual([])
    make('0.4.0', '0.4.1')
    writeFileSync(join(home, 'package', 'current'), '../../evil')
    expect(currentVersion(home)).toBeNull()
    mkdirSync(join(home, 'run'), { recursive: true })
    writeFileSync(join(home, 'run', 'service.json'), JSON.stringify({ package_dir: '/elsewhere/0.4.0' }))
    expect(pruneVersions(home, () => false).sort()).toEqual(['0.4.0', '0.4.1'])
    writeFileSync(join(home, 'package', 'current'), '2.0.0')
    expect(currentVersion(home)).toBe('2.0.0')
    expect(byVersion('0.4.10', '0.4.9')).toBeGreaterThan(0)
    expect(byVersion('0.4.0', '0.4.0')).toBe(0)
    expect(byVersion('0.4.0-rc.1', '0.4.0-rc.2')).toBeLessThan(0)
  })
})
