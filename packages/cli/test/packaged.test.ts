import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { CLI_MAIN, MCP_MAIN, OMP_WAKE, PACKAGED } from '../src/entries.ts'
import { stableMains, versionLine } from '../src/packaged.ts'
import { tempDir } from './support/io.ts'

// packaged.ts: the version line, and the stable copy of the package's dist/ that the written commands name (from
// source, the checkout's main.ts files). The package itself is built and run in packages/bag/test.

const tmp = tempDir('packaged')
afterAll(() => tmp.cleanup())

/** A stand-in for the package's dist/: two bins, a chunk and a data file. */
function dist(name: string, chunk: string): string {
  const dir = join(tmp.dir, name)
  mkdirSync(dir, { recursive: true })
  for (const bin of ['bag.js', 'bag-mcp.js']) {
    writeFileSync(join(dir, bin), `#!/usr/bin/env node\nimport './${chunk}'\n`)
    chmodSync(join(dir, bin), 0o755)
  }
  writeFileSync(join(dir, chunk), `export const v = ${JSON.stringify(name)}\n`)
  writeFileSync(join(dir, 'wordlist.json'), '[]\n')
  return dir
}

describe('versionLine', () => {
  it('from source: bag source and the checkout commit, or unknown in a worktree', () => {
    expect(versionLine()).toMatch(/^bag source ([0-9a-f]{40}|unknown)$/)
  })
})

describe('stableMains', () => {
  it('from source: the checkout main.ts files, nothing copied', () => {
    expect(PACKAGED).toBe(false)
    expect(stableMains(join(tmp.dir, 'unused'))).toEqual({
      cli: CLI_MAIN,
      mcp: MCP_MAIN,
      omp: OMP_WAKE,
      copied: null,
    })
    expect(existsSync(join(tmp.dir, 'unused'))).toBe(false)
  })

  it('from the package: copies dist/ to <home>/package and names the copies, modes kept', () => {
    const from = dist('v1', 'chunk-a.js')
    const home = join(tmp.dir, 'home')
    const m = stableMains(
      home,
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
    )
    const to = join(home, 'package')
    expect(m).toEqual({
      cli: join(to, 'bag.js'),
      mcp: join(to, 'bag-mcp.js'),
      omp: join(to, 'bag-omp-wake.js'),
      copied: to,
    })
    expect(readFileSync(join(to, 'chunk-a.js'), 'utf8')).toContain('"v1"')
    expect(existsSync(join(to, 'wordlist.json'))).toBe(true)
    expect(statSync(join(to, 'bag.js')).mode & 0o777).toBe(0o755)
    expect(statSync(to).mode & 0o777).toBe(0o700)
  })

  it('an existing <home>/package with a looser mode is set to 0700', () => {
    const home = join(tmp.dir, 'loose')
    mkdirSync(join(home, 'package'), { recursive: true, mode: 0o755 })
    chmodSync(join(home, 'package'), 0o755)
    const from = join(tmp.dir, 'v1')
    stableMains(home, join(from, 'bag.js'), join(from, 'bag-mcp.js'), true, join(from, 'bag-omp-wake.js'))
    expect(statSync(join(home, 'package')).mode & 0o777).toBe(0o700)
  })

  it('the same version again: nothing copied, the same paths', () => {
    const from = join(tmp.dir, 'v1')
    const m = stableMains(
      join(tmp.dir, 'home'),
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
    )
    expect(m).toEqual({
      cli: join(tmp.dir, 'home', 'package', 'bag.js'),
      mcp: expect.any(String),
      omp: expect.any(String),
      copied: null,
    })
  })

  it('a later version refreshes the same paths and drops the chunks it lacks', () => {
    const from = dist('v2', 'chunk-b.js')
    const home = join(tmp.dir, 'home')
    const m = stableMains(
      home,
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
    )
    const to = join(home, 'package')
    expect(m.cli).toBe(join(to, 'bag.js'))
    expect(readFileSync(join(to, 'chunk-b.js'), 'utf8')).toContain('"v2"')
    expect(existsSync(join(to, 'chunk-a.js'))).toBe(false)
    expect(existsSync(join(to, 'wordlist.json'))).toBe(true)
  })

  it('run from the copy itself: nothing copied, the same paths', () => {
    const to = join(tmp.dir, 'home', 'package')
    const m = stableMains(
      join(tmp.dir, 'home'),
      join(to, 'bag.js'),
      join(to, 'bag-mcp.js'),
      true,
      join(to, 'bag-omp-wake.js'),
    )
    expect(m).toEqual({
      cli: join(to, 'bag.js'),
      mcp: join(to, 'bag-mcp.js'),
      omp: join(to, 'bag-omp-wake.js'),
      copied: null,
    })
  })
})
