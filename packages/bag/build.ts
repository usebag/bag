// npm run build -w packages/bag (node packages/bag/build.ts): builds dist/ from this checkout (src/build.ts), adds the
// question card's plugin (buildCard), and prints the version, the commit, the files and the bundled npm packages.
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { build as bundle } from 'rolldown'
import { build, type Chunk, checkImports, PACKAGE, packageVersion, ROOT } from './src/build.ts'

/** The plugin's source in the repository: a Claude Code plugin named bag, whose mod draws bag's question card. */
export const CARD_SOURCE = join(ROOT, 'plugins', 'claude-code-card')

/**
 * Builds the question card's directory marketplace into <dist>/claude-code: .claude-plugin/marketplace.json (the
 * marketplace "bag" listing the plugin "bag" at ./bag) and bag/, the plugin folder `src` without its TypeScript, its
 * tsconfig.json and tests, with its plugin.json's version set to `version` and each hooks module of hooks/hooks.json bundled from its .ts
 * into one .js file of Node built-ins only (hooks.json then names the .js). Staging (packages/home's stage.ts) copies
 * the folder to <home>/package/claude-code and fills @BAG_NODE@, @BAG_CLI@ and @BAG_HOME@ in its .json files. Returns
 * the files written, relative to `dist`. Throws when `src` is missing.
 */
export async function buildCard(
  dist: string,
  src = CARD_SOURCE,
  version = packageVersion(),
): Promise<string[]> {
  if (!existsSync(join(src, '.claude-plugin', 'plugin.json'))) {
    throw new Error(
      `the question card's plugin is missing: ${src} holds no .claude-plugin/plugin.json (the plugin's source, plugins/claude-code-card, must be in the checkout to build the package)`,
    )
  }
  const out = join(dist, 'claude-code')
  const plugin = join(out, 'bag')
  rmSync(out, { recursive: true, force: true })
  mkdirSync(join(out, '.claude-plugin'), { recursive: true })
  const about = "bag's questions in Claude Code's own question card"
  const market = {
    name: 'bag',
    description: about,
    owner: { name: 'bag' },
    plugins: [{ name: 'bag', source: './bag', description: about }],
  }
  writeFileSync(join(out, '.claude-plugin', 'marketplace.json'), `${JSON.stringify(market, null, 2)}\n`)
  const skip = /(^|\/)(test|tests|node_modules)(\/|$)|\.ts$|(^|\/)tsconfig\.json$/
  cpSync(src, plugin, { recursive: true, filter: (f) => !skip.test(f.slice(src.length)) })
  const manifest = join(plugin, '.claude-plugin', 'plugin.json')
  writeFileSync(
    manifest,
    `${JSON.stringify({ ...JSON.parse(readFileSync(manifest, 'utf8')), version }, null, 2)}\n`,
  )
  const hooksFile = join(plugin, 'hooks', 'hooks.json')
  const hooks = existsSync(hooksFile) ? JSON.parse(readFileSync(hooksFile, 'utf8')) : {}
  const modules: string[] = Array.isArray(hooks.modules) ? hooks.modules : []
  for (const m of modules) {
    const { output } = await bundle({
      input: join(src, 'hooks', m.replace(/\.js$/, '.ts')),
      platform: 'node',
      cwd: ROOT,
      output: {
        file: join(plugin, 'hooks', m.replace(/\.ts$/, '.js')),
        format: 'esm',
        codeSplitting: false,
      },
    })
    checkImports(output.filter((o) => o.type === 'chunk') as readonly Chunk[])
  }
  if (modules.length > 0) {
    hooks.modules = modules.map((m) => m.replace(/\.ts$/, '.js'))
    writeFileSync(hooksFile, `${JSON.stringify(hooks, null, 2)}\n`)
  }
  return (readdirSync(out, { recursive: true }) as string[])
    .filter((f) => statSync(join(out, f)).isFile())
    .map((f) => `claude-code/${f}`)
    .sort()
}

if (import.meta.main) {
  const built = await build()
  const card = await buildCard(join(PACKAGE, 'dist'))
  console.log(`@usebag/bag ${built.version} ${built.commit}`)
  for (const f of [...built.files, ...card]) console.log(`  dist/${f}`)
  console.log(`bundled npm packages: ${built.packages.map((d) => d.replace('node_modules/', '')).join(', ')}`)
}
