import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { type Build, launcherText, stage, stagedMains } from '../src/index.ts'
import { folder } from './support.ts'

// The package staged into a home: from source nothing is written and the checkout's entries are named; from the
// bundle its dist/ is copied once under <home>/package/versions/<version>/ and the launchers name it.

/** A bundle's dist/ of version `version`, its four entries holding `body`. */
function bundle(version: string, body = 'v1'): Build {
  const dist = folder()
  for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js'])
    writeFileSync(join(dist, f), `// ${f} ${body}`)
  const at = (f: string) => join(dist, f)
  return {
    packaged: true,
    version,
    cli: at('bag.js'),
    mcp: at('bag-mcp.js'),
    omp: at('bag-omp-wake.js'),
    shim: at('bag-shim.js'),
  }
}

describe('stage and stagedMains', () => {
  it('from source: the entries as given, nothing written', () => {
    const home = join(folder(), 'home')
    const b: Build = { packaged: false, version: 'source', cli: '/c', mcp: '/m', omp: '/o', shim: '/s' }
    const want = { cli: '/c', mcp: '/m', omp: '/o', shim: '/s', copied: null, notice: null, versioned: null }
    expect(stagedMains(home, b)).toEqual(want)
    expect(stage(home, b, 1)).toEqual(want)
    expect(existsSync(home)).toBe(false)
  })

  it('from the bundle: names before it writes what stage then writes, once, and refuses another build of one version', () => {
    const home = join(folder(), 'home')
    const b = bundle('0.4.0')
    const planned = stagedMains(home, b)
    expect(existsSync(home)).toBe(false)
    const pkg = join(home, 'package')
    const to = join(pkg, 'versions', '0.4.0')
    const first = stage(home, b, 4242)
    expect(first).toEqual({ ...planned, copied: to })
    expect(first.shim).toBe(join(pkg, 'bag-shim.js'))
    expect(first.versioned?.mcp).toBe(join(to, 'bag-mcp.js'))
    expect(readFileSync(join(pkg, 'current'), 'utf8')).toBe('0.4.0\n')
    expect(readFileSync(join(pkg, 'bag-mcp.js'), 'utf8')).toBe(launcherText('bag-mcp.js'))
    expect(statSync(join(pkg, 'bag.js')).mode & 0o777).toBe(0o755)
    expect(statSync(pkg).mode & 0o777).toBe(0o700)
    expect(readdirSync(join(pkg, 'versions'))).toEqual(['0.4.0'])
    expect(readdirSync(pkg).filter((f) => f.includes('.tmp'))).toEqual([])
    expect(stage(home, b, 4242).copied).toBeNull()
    mkdirSync(join(home, 'run'))
    writeFileSync(
      join(home, 'run', 'service.json'),
      JSON.stringify({ pid: 77, package_dir: join(pkg, 'versions', '0.3.9') }),
    )
    expect(stage(home, b, 4242).notice).toBe(
      'the running bag service (pid 77) moves to bag 0.4.0 at its next drain and restart',
    )
    expect(() => stage(home, bundle('0.4.0', 'v2'), 4242)).toThrow(
      `exists: ${to} holds another build of bag 0.4.0`,
    )
    expect(readFileSync(join(to, 'bag.js'), 'utf8')).toBe('// bag.js v1')
  })

  it("a launcher reads current and imports that version's entry, with the text it always had", () => {
    const text = launcherText('bag-shim.js')
    expect(text.startsWith('#!/usr/bin/env node\n')).toBe(true)
    expect(text).toContain('packages/cli/src/stage.ts')
    expect(text).toContain(`join(pkg, 'versions', v, "bag-shim.js")`)
  })
})
