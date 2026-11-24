import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { buildCard, CARD_SOURCE } from '../build.ts'

// The question card's plugin in the package (build.ts's buildCard), built from a small fixture plugin folder in the
// form plugins/claude-code-card takes: a mod in TypeScript importing a helper, a test of its own, hooks.json naming
// the .ts module and the command hook with the placeholders staging fills.

const scratch = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-card-'))
const put = (file: string, text: string) => {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, text)
}

/** The fixture plugin folder. */
function fixture(): string {
  const src = join(scratch, `src-${Math.random().toString(36).slice(2)}`)
  put(join(src, '.claude-plugin', 'plugin.json'), '{"name":"bag","description":"bag\'s questions"}\n')
  const hook = { type: 'command', command: '@BAG_NODE@ @BAG_CLI@ card-hook --dir @BAG_HOME@', timeout: 600 }
  put(
    join(src, 'hooks', 'hooks.json'),
    JSON.stringify({ modules: ['./card.ts'], hooks: { Elicitation: [{ matcher: 'bag', hooks: [hook] }] } }),
  )
  put(
    join(src, 'hooks', 'card.ts'),
    "import { labelOf } from './card-logic.ts'\nexport const register = (on: (e: string, f: unknown) => void): void => on('classic.Elicitation', labelOf)\n",
  )
  put(
    join(src, 'hooks', 'card-logic.ts'),
    "export const labelOf = (s: string): string => 'card-label ' + s\n",
  )
  put(join(src, 'test', 'card.test.ts'), '// a test of the mod: never shipped\n')
  put(join(src, 'README.md'), 'the plugin\n')
  put(join(src, 'tsconfig.json'), '{"compilerOptions":{}}\n')
  return src
}

describe('buildCard: the question card in dist/', () => {
  it('writes the marketplace and the plugin, the mod bundled into one card.js with no import, no TypeScript and no tsconfig.json', async () => {
    const dist = join(scratch, 'dist1')
    const files = await buildCard(dist, fixture(), '9.9.9')
    expect(files).toEqual([
      'claude-code/.claude-plugin/marketplace.json',
      'claude-code/bag/.claude-plugin/plugin.json',
      'claude-code/bag/README.md',
      'claude-code/bag/hooks/card.js',
      'claude-code/bag/hooks/hooks.json',
    ])
    const out = join(dist, 'claude-code')
    expect(JSON.parse(readFileSync(join(out, '.claude-plugin', 'marketplace.json'), 'utf8'))).toEqual({
      name: 'bag',
      description: "bag's questions in Claude Code's own question card",
      owner: { name: 'bag' },
      plugins: [
        { name: 'bag', source: './bag', description: "bag's questions in Claude Code's own question card" },
      ],
    })
    expect(JSON.parse(readFileSync(join(out, 'bag', '.claude-plugin', 'plugin.json'), 'utf8'))).toEqual({
      name: 'bag',
      description: "bag's questions",
      version: '9.9.9',
    })
    const hooks = JSON.parse(readFileSync(join(out, 'bag', 'hooks', 'hooks.json'), 'utf8'))
    expect(hooks.modules).toEqual(['./card.js'])
    expect(hooks.hooks.Elicitation[0].hooks[0].command).toBe(
      '@BAG_NODE@ @BAG_CLI@ card-hook --dir @BAG_HOME@',
    )
    const card = readFileSync(join(out, 'bag', 'hooks', 'card.js'), 'utf8')
    expect(card).toContain('card-label')
    expect(card).not.toMatch(/\bimport\b|\brequire\(/)
    const m = await import(join(out, 'bag', 'hooks', 'card.js'))
    expect(typeof m.register).toBe('function')
  })

  it('fails with a clear message when the plugin folder is missing, and defaults to plugins/claude-code-card', async () => {
    const missing = join(scratch, 'none')
    await expect(buildCard(join(scratch, 'dist2'), missing, '9.9.9')).rejects.toThrow(
      `the question card's plugin is missing: ${missing} holds no .claude-plugin/plugin.json`,
    )
    expect(existsSync(join(scratch, 'dist2'))).toBe(false)
    expect(CARD_SOURCE.endsWith(join('plugins', 'claude-code-card'))).toBe(true)
  })
})
