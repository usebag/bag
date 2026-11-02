import { execFile } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it, onTestFinished } from 'vitest'
import { tempDir } from './support/fixtures.ts'

// The default is to keep the MCP SDK and gate its loaded set. A child
// Node process runs the scripted session of support/loaded-session.ts under the resolve hook of support/loaded-hook.ts,
// which records every module it resolves from node_modules, by import and by require; the packages of those modules
// must be exactly the allowlist, loaded-packages.txt. The servers run in that child over an in-memory transport, with
// no MCP client and no test framework loaded there, so what the hook sees is what the server side loads.

const HERE = dirname(fileURLToPath(import.meta.url))
const HOOK = join(HERE, 'support', 'loaded-hook.ts')
const SESSION = join(HERE, 'support', 'loaded-session.ts')
const ALLOWLIST = join(HERE, 'loaded-packages.txt')

/** The package of a node_modules URL: what follows its last node_modules/, a name or a scope and a name. */
export function packageOf(url: string): string {
  const rest = url.slice(url.lastIndexOf('/node_modules/') + '/node_modules/'.length)
  const parts = rest.split('/')
  return (rest.startsWith('@') ? parts.slice(0, 2) : parts.slice(0, 1)).join('/')
}

/** The allowlist's names: one per line, without comments and blank lines. */
function allowlist(): string[] {
  return readFileSync(ALLOWLIST, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'))
}

describe('the loaded set of the MCP server', () => {
  it('loads exactly the 8 allowlisted packages over every tool and error path, and the hook sees the SDK', async () => {
    const tmp = tempDir('loaded-set')
    onTestFinished(() => tmp.cleanup())
    const out = join(tmp.dir, 'loaded.txt')
    const env: NodeJS.ProcessEnv = { ...process.env, AC_LOADED_OUT: out }
    delete env.NODE_OPTIONS
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ['--import', pathToFileURL(HOOK).href, SESSION],
      {
        env,
        timeout: 60_000,
      },
    )
    const summary = JSON.parse(stdout.trim().split('\n').at(-1) as string) as {
      calls: number
      tool_errors: number
      mismatches: string[]
    }
    expect(summary.mismatches).toEqual([])
    const urls = readFileSync(out, 'utf8')
      .split('\n')
      .filter((l) => l !== '')
    const packages = [...new Set(urls.map(packageOf))].sort()
    console.log(
      `MEASURE loaded set: ${packages.length} packages from node_modules over ${summary.calls} tool calls ` +
        `(${summary.tool_errors} tool errors), ${urls.length} module URLs: ${packages.join(', ')}`,
    )
    // Positive control: the hook saw the server's own import of the SDK.
    expect(packages).toContain('@modelcontextprotocol/sdk')
    expect(packages).toEqual([...allowlist()].sort())
    expect(allowlist()).toHaveLength(8)
    expect(summary.calls).toBeGreaterThan(40)
  }, 60_000)

  it('reads a package name, plain or scoped, from the last node_modules of a URL', () => {
    expect(packageOf('file:///r/node_modules/ajv/dist/ajv.js')).toBe('ajv')
    expect(packageOf('file:///r/node_modules/@modelcontextprotocol/sdk/dist/esm/types.js')).toBe(
      '@modelcontextprotocol/sdk',
    )
    expect(packageOf('file:///r/node_modules/a/node_modules/fast-uri/index.js')).toBe('fast-uri')
  })
})
