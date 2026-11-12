import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// host install after stableNode (packaged.ts): an install made before it wrote the resolved node path
// (process.execPath, a Homebrew Cellar path that `brew upgrade` removes). The next install writes the stable link and
// replaces that entry and its hooks, never refusing them as "other settings" and never leaving a second hook. The node
// written is mocked: first the resolved path (the earlier install), then a link (never run). Temp directories only.

const node = vi.hoisted(() => ({ path: '' }))
vi.mock('../src/packaged.ts', async (orig) => ({
  ...(await orig<typeof import('../src/packaged.ts')>()),
  stableNode: () => node.path,
}))

const tmp = tempDir('host-install-node')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const LINK = '/opt/homebrew/bin/node'
let n = 0
beforeEach(() => {
  node.path = process.execPath
})

async function world() {
  const base = join(tmp.dir, `w${n++}`)
  const [dir, project, userHome] = [join(base, 'home'), join(base, 'project'), join(base, 'user')]
  mkdirSync(project, { recursive: true })
  mkdirSync(userHome, { recursive: true })
  const io = testIo(new MemoryRelay(), { HOME: userHome })
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  const install = (host: string, ...more: string[]) =>
    cli(io, 'host', 'install', host, '--as', 'bob', '--dir', dir, '--relay', RELAY, ...more)
  return { dir, project, userHome, install }
}
const text = (file: string): string => readFileSync(file, 'utf8')
const json = (file: string): Record<string, unknown> => JSON.parse(text(file))
/** Every hook command in a hooks document, in order. */
const commands = (doc: Record<string, unknown>): string[] =>
  JSON.stringify(doc).match(/"command":"[^"]*"/g) ?? []

describe('host install over an install that wrote the resolved node path', () => {
  it('claude-code --project: the entry and both hooks move to the link, one hook each, then nothing to change', async () => {
    const w = await world()
    const [mcp, settings] = [join(w.project, '.mcp.json'), join(w.project, '.claude', 'settings.json')]
    expect((await w.install('claude-code', '--project', w.project)).code).toBe(0)
    expect((json(mcp).mcpServers as { bag: { command: string } }).bag.command).toBe(process.execPath)
    node.path = LINK
    const r = await w.install('claude-code', '--project', w.project)
    expect(r.code).toBe(0)
    expect((json(mcp).mcpServers as { bag: { command: string } }).bag.command).toBe(LINK)
    const hooks = json(settings).hooks as Record<string, unknown>
    for (const event of ['SessionStart', 'Stop']) {
      expect(commands({ [event]: hooks[event] })).toEqual([
        expect.stringMatching(new RegExp(`^"command":"${LINK} .* wake-hook --as bob --dir .* --max 86000"$`)),
      ])
    }
    const again = await w.install('claude-code', '--project', w.project)
    expect(again.out).toContain('nothing to change')
  })

  it('claude-code --identities: the identities entry and its hook move to the link', async () => {
    const w = await world()
    const file = join(w.userHome, 'identities.json')
    const [mcp, settings] = [join(w.project, '.mcp.json'), join(w.project, '.claude', 'settings.json')]
    expect((await w.install('claude-code', '--project', w.project, '--identities', file)).code).toBe(0)
    node.path = LINK
    expect((await w.install('claude-code', '--project', w.project, '--identities', file)).code).toBe(0)
    expect((json(mcp).mcpServers as { bag: { command: string } }).bag.command).toBe(LINK)
    // SessionStart and Stop, one hook each, both on the link.
    const one = expect.stringMatching(
      new RegExp(`^"command":"${LINK} .* wake-hook --identities .*identities\\.json --max 86000"$`),
    )
    expect(commands(json(settings))).toEqual([one, one])
    expect((await w.install('claude-code', '--project', w.project, '--identities', file)).out).toContain(
      'nothing to change',
    )
  })

  it('omp: the .omp/mcp.json entry moves to the link', async () => {
    const w = await world()
    const file = join(w.project, '.omp', 'mcp.json')
    expect((await w.install('omp', '--project', w.project)).code).toBe(0)
    node.path = LINK
    expect((await w.install('omp', '--project', w.project)).code).toBe(0)
    expect((json(file).mcpServers as { bag: { command: string } }).bag.command).toBe(LINK)
    expect((await w.install('omp', '--project', w.project)).out).toContain('nothing to change')
  })

  // H8: the plain table (the default) and the session table alike.
  it.each([
    ['plain', []],
    ['--session auto:codex', ['--session', 'auto:codex']],
  ])(
    'codex --mode mcp, %s: the table is rewritten with the link and the Stop hook replaced, one of each',
    async (_, form) => {
      const w = await world()
      const [config, hooks] = [
        join(w.userHome, '.codex', 'config.toml'),
        join(w.userHome, '.codex', 'hooks.json'),
      ]
      const codex = () =>
        w.install(
          'codex',
          '--user',
          '--mode',
          'mcp',
          ...form,
          ...(form.length ? ['--grant-caveat', 'topic:build'] : []),
        )
      expect((await codex()).code).toBe(0)
      node.path = LINK
      expect((await codex()).code).toBe(0)
      expect(text(config).match(/\[mcp_servers\.bag\]/g)).toHaveLength(1)
      expect(text(config)).toContain(`command = ${JSON.stringify(LINK)}`)
      expect(text(config)).not.toContain(JSON.stringify(process.execPath))
      expect(commands(json(hooks))).toEqual([expect.stringMatching(new RegExp(`^"command":"${LINK} `))])
      expect((await codex()).out).toContain('nothing to change')
    },
  )
})
