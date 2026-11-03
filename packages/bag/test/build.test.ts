import { execFileSync, spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import {
  type Built,
  build,
  bundledPackages,
  checkImports,
  ENTRIES,
  notice,
  PACKAGE,
  packageVersion,
  ROOT,
  sourceCommit,
} from '../src/build.ts'

// The package build (src/build.ts) in this process, into a scratch dist/, then its bins as a person runs them.
const scratch = mkdtempSync(join(tmpdir(), 'bag-pkg-'))
const out = join(scratch, 'dist')
let built: Built

beforeAll(async () => {
  built = await build(out)
})

const run = (bin: string, args: string[], env: Record<string, string> = {}) =>
  execFileSync(process.execPath, [join(out, `${bin}.js`), ...args], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', HOME: scratch, AC_TELEMETRY: 'off', ...env },
  })

describe('the build', () => {
  it('makes the three bins with a shebang, executable, beside the chunks, the wordlist and the notices', () => {
    for (const name of Object.keys(ENTRIES)) {
      expect(readFileSync(join(out, `${name}.js`), 'utf8').startsWith('#!/usr/bin/env node\n')).toBe(true)
      expect(statSync(join(out, `${name}.js`)).mode & 0o111).toBe(0o111)
    }
    // LICENSE when the checkout has one (the public repository's root, or cut/ here); a private-mode cut has none.
    const licence = ['LICENSE', 'cut/LICENSE'].some((f) => existsSync(join(ROOT, f))) ? ['LICENSE'] : []
    expect(built.files.filter((f) => !f.endsWith('.js'))).toEqual([
      ...licence,
      'THIRD-PARTY.md',
      'wordlist.json',
    ])
  })

  it('carries the version of package.json and the source commit', () => {
    expect(built.version).toBe(packageVersion())
    expect(built.commit).toMatch(/^[0-9a-f]{40}(-dirty)?$/)
    expect(built.commit).toBe(sourceCommit())
  })

  it('bundles only the runtime packages of the server, no dev tooling', () => {
    const names = built.packages.map((d) => d.replace('node_modules/', ''))
    expect(names).toContain('@modelcontextprotocol/sdk')
    expect(names).toContain('zod')
    for (const dev of [
      'vitest',
      'rolldown',
      'typescript',
      '@biomejs/biome',
      '@vitest',
      'vite',
      'express',
      'hono',
    ])
      expect(names.some((n) => n === dev || n.startsWith(`${dev}/`))).toBe(false)
    const third = readFileSync(join(out, 'THIRD-PARTY.md'), 'utf8')
    for (const n of names) expect(third).toContain(`## ${n} `)
  })

  it('leaves no import but its own chunks and Node built-ins in the files', () => {
    for (const f of readdirSync(out).filter((x) => x.endsWith('.js'))) {
      const code = readFileSync(join(out, f), 'utf8')
      const imports = [...code.matchAll(/^import .*? from "([^"]+)";$/gm)].map((m) => m[1] as string)
      expect(imports.length).toBeGreaterThan(0)
      for (const s of imports) expect(s.startsWith('./') || s.startsWith('node:')).toBe(true)
      expect(code).not.toMatch(/createRequire|__require\(/)
    }
  })

  it('ships no dependency, no install script, and only dist/', () => {
    const pkg = JSON.parse(readFileSync(join(PACKAGE, 'package.json'), 'utf8'))
    expect(pkg.private).toBeUndefined()
    expect(pkg.dependencies).toBeUndefined()
    for (const s of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'prepublishOnly'])
      expect(pkg.scripts?.[s]).toBeUndefined()
    expect(pkg.files).toEqual(['dist'])
    expect(pkg.bin).toEqual({
      bag: 'dist/bag.js',
      'bag-mcp': 'dist/bag-mcp.js',
      'bag-a2a': 'dist/bag-a2a.js',
    })
    expect(pkg.engines.node).toBe('>=24')
    expect(pkg.publishConfig).toEqual({ access: 'public', provenance: true })
  })
})

describe('the bins', () => {
  it('bag --version and bag version print one line: bag <version> <commit>', () => {
    const line = `bag ${built.version} ${built.commit}\n`
    expect(run('bag', ['--version'])).toBe(line)
    expect(run('bag', ['version'])).toBe(line)
  })

  it('bag keygen makes a key in the home and prints the address', () => {
    expect(run('bag', ['keygen', 'alice', '--dir', join(scratch, 'home')])).toMatch(
      /^ed25519:[0-9a-f]{64}\n$/,
    )
  })

  it('bag-mcp answers initialize with the package version', async () => {
    const child = spawn(
      process.execPath,
      [
        join(out, 'bag-mcp.js'),
        '--as',
        'alice',
        '--relay',
        'http://127.0.0.1:9',
        '--dir',
        join(scratch, 'home'),
      ],
      { env: { PATH: process.env.PATH ?? '', HOME: scratch, AC_TELEMETRY: 'off' } },
    )
    const init = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
    }
    child.stdin.write(`${JSON.stringify(init)}\n`)
    const line = await new Promise<string>((resolve) => {
      let text = ''
      child.stdout.on('data', (d: Buffer) => {
        text += d.toString()
        if (text.includes('\n')) resolve(text.slice(0, text.indexOf('\n')))
      })
    })
    child.kill()
    expect(JSON.parse(line).result.serverInfo).toEqual({ name: 'bag', version: built.version })
  })

  it('each usage text names its bin, not a source path', () => {
    expect(run('bag', ['help'])).toContain('\nusage: bag <command> [options]\n')
    const mcp = spawnSync(process.execPath, [join(out, 'bag-mcp.js'), '--help'], { encoding: 'utf8' })
    expect(`${mcp.stdout}${mcp.stderr}`).toContain('usage: bag-mcp --as <key name>')
    expect(`${mcp.stdout}${mcp.stderr}`).toContain('\n       bag-mcp --identities <file>')
    const a2a = spawnSync(process.execPath, [join(out, 'bag-a2a.js'), '--help'], { encoding: 'utf8' })
    expect(`${a2a.stdout}${a2a.stderr}`).toContain('usage: bag-a2a --as <key name>')
    const bad = spawnSync(process.execPath, [join(out, 'bag.js')], {
      encoding: 'utf8',
      env: { HOME: scratch },
    })
    expect(bad.stderr).toContain('run "bag help" for the commands')
    for (const f of readdirSync(out).filter((x) => x.endsWith('.js')))
      expect(readFileSync(join(out, f), 'utf8')).not.toMatch(/usage: node packages\//)
  })

  it('bag-a2a prints its usage and does not run the card program bundled with it', () => {
    const r = spawnSync(process.execPath, [join(out, 'bag-a2a.js'), '--help'], { encoding: 'utf8' })
    expect(`${r.stdout}${r.stderr}`).toContain('A2A bridge')
    expect(`${r.stdout}${r.stderr}`).not.toMatch(/^extension |--domain/m)
  })
})

describe('the parts', () => {
  it('checkImports refuses an import that is neither a chunk nor a built-in, and names it', () => {
    const chunk = (fileName: string, imports: string[]) => ({
      fileName,
      imports,
      dynamicImports: [],
      moduleIds: [],
    })
    expect(() => checkImports([chunk('a.js', ['b.js', 'node:fs', 'fs']), chunk('b.js', [])])).not.toThrow()
    expect(() => checkImports([chunk('a.js', ['zod', 'c.js'])])).toThrow(/a\.js: zod, a\.js: c\.js$/)
  })

  it('bundledPackages reads plain and scoped packages from module ids, nested ones too', () => {
    const ids = [
      join(ROOT, 'packages/cli/src/main.ts'),
      join(ROOT, 'node_modules/zod/v4/core.js'),
      join(ROOT, 'node_modules/@scope/pkg/dist/x.js'),
      join(ROOT, 'node_modules/a/node_modules/b/index.js'),
    ]
    expect(bundledPackages(ids)).toEqual([
      'node_modules/@scope/pkg',
      'node_modules/a/node_modules/b',
      'node_modules/zod',
    ])
  })

  it('notice carries the licence files and refuses a package without one', () => {
    const dir = join(scratch, 'pkg')
    mkdirSync(dir)
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', license: 'MIT' }))
    expect(() => notice(dir)).toThrow(/no licence file/)
    writeFileSync(join(dir, 'LICENSE.md'), 'the text\n')
    expect(notice(dir)).toBe('\n## p 1.0.0 (MIT)\n\nthe text\n')
  })

  it('sourceCommit is HEAD, with -dirty when packages/ differs from it', () => {
    const repo = join(scratch, 'repo')
    mkdirSync(join(repo, 'packages'), { recursive: true })
    const git = (...args: string[]) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim()
    git('init', '--quiet')
    writeFileSync(join(repo, 'packages', 'a.txt'), 'a\n')
    git('add', '.')
    // The commit's author: the machine's own identity when the scratch repository sees one (a hook here refuses any
    // other), else a name for this scratch repository only, as on a bare CI runner, which has none.
    const ident = (() => {
      try {
        git('config', 'user.email')
        return []
      } catch {
        return ['-c', 'user.name=scratch', '-c', 'user.email=scratch@localhost']
      }
    })()
    git(...ident, 'commit', '--quiet', '--no-gpg-sign', '-m', 'scratch')
    const head = git('rev-parse', 'HEAD')
    expect(sourceCommit(repo)).toBe(head)
    writeFileSync(join(repo, 'packages', 'b.txt'), 'b\n')
    expect(sourceCommit(repo)).toBe(`${head}-dirty`)
    writeFileSync(join(repo, 'outside.txt'), 'c\n')
    expect(() => sourceCommit(join(scratch, 'pkg'))).toThrow()
  })
})
