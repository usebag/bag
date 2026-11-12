import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { CLI_MAIN, MCP_MAIN, OMP_WAKE, PACKAGED } from '../src/entries.ts'
import { stableMains, stableNode, versionLine } from '../src/packaged.ts'
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

describe('stableMains: the launchers of stage.ts, and nothing else under <home>/package/', () => {
  it('from source: the checkout main.ts files, nothing written', () => {
    expect(PACKAGED).toBe(false)
    expect(stableMains(join(tmp.dir, 'unused'))).toEqual({
      cli: CLI_MAIN,
      mcp: MCP_MAIN,
      omp: OMP_WAKE,
      copied: null,
    })
    expect(existsSync(join(tmp.dir, 'unused'))).toBe(false)
  })

  it('from the package: stages versions/<version>/ once and names the launchers, which run it', () => {
    const from = dist('v1', 'chunk-a.js')
    const home = join(tmp.dir, 'home')
    const bins = [
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
    ] as const
    const m = stableMains(home, ...bins, '0.4.0')
    const pkg = join(home, 'package')
    expect(m).toEqual({
      cli: join(pkg, 'bag.js'),
      mcp: join(pkg, 'bag-mcp.js'),
      omp: join(pkg, 'bag-omp-wake.js'),
      copied: join(pkg, 'versions', '0.4.0'),
    })
    expect(readFileSync(join(pkg, 'versions', '0.4.0', 'chunk-a.js'), 'utf8')).toContain('"v1"')
    expect(statSync(join(pkg, 'bag.js')).mode & 0o777).toBe(0o755)
    expect(statSync(pkg).mode & 0o777).toBe(0o700)
    expect(stableMains(home, ...bins, '0.4.0').copied).toBeNull()
  })

  it('a keep job installed after a stage leaves only the launchers, current and versions/ under <home>/package/', async () => {
    const from = join(tmp.dir, 'v1')
    const home = join(tmp.dir, 'keep-home')
    stableMains(
      home,
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
      '0.4.0',
    )
    const before = readdirSync(join(home, 'package')).sort()
    // What record keep --plist, onboard and the refresher call again: no copy of dist/ beside the launchers.
    stableMains(
      home,
      join(from, 'bag.js'),
      join(from, 'bag-mcp.js'),
      true,
      join(from, 'bag-omp-wake.js'),
      '0.4.0',
    )
    const after = readdirSync(join(home, 'package')).sort()
    expect(after).toEqual(before)
    expect(after).toEqual(['bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js', 'bag.js', 'current', 'versions'])
  })
})

describe('stableNode', () => {
  const CELLAR = '/opt/homebrew/Cellar/node/25.8.1_1/bin/node'
  const LINKS = ['/opt/homebrew/bin/node', '/usr/local/bin/node']
  const fs = (map: Record<string, string>) => (p: string) => {
    const r = map[p]
    if (r === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    return r
  }

  it("writes Homebrew's link when it resolves to the node running", () => {
    expect(stableNode(CELLAR, LINKS, fs({ [CELLAR]: CELLAR, [LINKS[0] as string]: CELLAR }))).toBe(LINKS[0])
    expect(stableNode(CELLAR, LINKS, fs({ [CELLAR]: CELLAR, [LINKS[1] as string]: CELLAR }))).toBe(LINKS[1])
  })

  it('writes the resolved path when the link is another node, absent, or the node itself does not resolve', () => {
    const other = '/opt/homebrew/Cellar/node/24.4.1/bin/node'
    expect(stableNode(other, LINKS, fs({ [other]: other, [LINKS[0] as string]: CELLAR }))).toBe(other)
    expect(stableNode(CELLAR, LINKS, fs({ [CELLAR]: CELLAR }))).toBe(CELLAR)
    expect(stableNode(CELLAR, LINKS, fs({}))).toBe(CELLAR)
  })

  it('by default: the running node, or a link that resolves to it', () => {
    expect([process.execPath, ...LINKS]).toContain(stableNode())
  })
})
