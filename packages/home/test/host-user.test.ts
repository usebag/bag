import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  claudeFiles,
  type HostProcess,
  installUser,
  ompAgentDir,
  removeUser,
  type Staged,
  shimOf,
  tableOf,
  userNotes,
} from '../src/index.ts'
import { folder } from './support.ts'

// host install <host> --user with no --as: the bag service's shim for every identity of a home, in each host's user
// files, and host remove taking it out again. The files are found from the environment given.

const m: Staged = {
  cli: '/b/bag.js',
  mcp: '/b/bag-mcp.js',
  omp: '/b/bag-omp-wake.js',
  shim: '/b/bag-shim.js',
  copied: null,
  notice: null,
  versioned: null,
}
const p: HostProcess = { node: '/n/node', execPath: '/n/node', pid: 4242, uid: 501 }
// JSON.parse's own type, so a test reads into the document without a cast at each step.
const json = (file: string) => JSON.parse(readFileSync(file, 'utf8'))

/** A home and a user's HOME, each a new folder. */
function world() {
  const home = folder()
  const HOME = folder()
  return { home, HOME, env: { HOME } }
}

describe('installUser and removeUser: claude-code', () => {
  it('writes the shim entry, its hooks and the deny rules once, then takes the entry and hooks out', () => {
    const w = world()
    const out: string[] = []
    installUser(w.env, p, m, w.home, 'claude-code', false, out)
    const [file, settings] = [join(w.HOME, '.claude.json'), join(w.HOME, '.claude', 'settings.json')]
    expect(out[0]).toBe(`wrote ${file}: mcpServers.bag, the bag service's shim`)
    expect(out[1]).toMatch(
      new RegExp(`^wrote ${settings}: the shim's SessionStart, Stop and UserPromptSubmit hooks`),
    )
    expect(out.at(-1)).toContain('sandbox.enabled is unchanged')
    expect(json(file).mcpServers.bag).toEqual({
      type: 'stdio',
      command: '/n/node',
      args: ['/b/bag-shim.js', '--dir', w.home, '--input-hook'],
    })
    const s = json(settings)
    expect(s.hooks.SessionStart[0].hooks[0].command).toBe(
      `/n/node /b/bag.js wake-hook --session service --dir ${w.home} --max 86000`,
    )
    expect(s.hooks.UserPromptSubmit[0].hooks[0].command).toBe(`/n/node /b/bag-shim.js hook --dir ${w.home}`)
    expect(s.permissions.deny).toContain(`Read(/${join(w.home, 'run')}/**)`)
    expect(s.sandbox.enabled).toBeUndefined()
    const again: string[] = []
    installUser(w.env, p, m, w.home, 'claude-code', false, again)
    expect(again[0]).toBe('nothing to change')
    const boxed: string[] = []
    installUser(w.env, p, m, w.home, 'claude-code', true, boxed)
    expect(json(settings).sandbox.enabled).toBe(true)
    const gone: string[] = []
    removeUser(w.env, 4242, w.home, 'claude-code', gone)
    expect(gone).toEqual([
      `wrote ${file}: mcpServers.bag (the shim) removed`,
      `wrote ${settings}: bag's service hooks removed`,
      `kept the deny rules for ${w.home} in ${settings}: they protect the bag home whether or not bag is wired`,
      `kept the sandbox settings in ${settings}: turning them off could weaken a sandbox you rely on`,
    ])
    expect(json(file).mcpServers).toEqual({})
    // The hooks object bag's removal emptied is gone; the deny rules and the sandbox stay.
    const left = json(settings)
    expect(left.hooks).toBeUndefined()
    expect(left.permissions.deny).toContain(`Read(/${join(w.home, 'run')}/**)`)
    expect(left.sandbox.enabled).toBe(true)
    expect(left.sandbox.filesystem.denyRead).toEqual([join(w.home, 'run')])
  })

  it("keeps a hooks object the person had, even empty, and every other setting of the person's", () => {
    const mine = { Stop: [{ hooks: [{ type: 'command', command: 'mine' }] }] }
    // An empty one the removal finds stays empty, though it writes the file (the card's two entries go); one bag's
    // hooks shared stays with the person's own.
    for (const [hooks, install] of [
      [{}, false],
      [mine, true],
    ] as const) {
      const w = world()
      const settings = join(w.HOME, '.claude', 'settings.json')
      mkdirSync(join(w.HOME, '.claude'))
      const card = {
        extraKnownMarketplaces: {
          bag: { source: { source: 'directory', path: join(w.home, 'package', 'claude-code') } },
        },
        enabledPlugins: { 'bag@bag': true },
      }
      writeFileSync(
        settings,
        JSON.stringify({ model: 'opus', env: { A: '1' }, hooks, ...(install ? {} : card) }),
      )
      if (install) installUser(w.env, p, m, w.home, 'claude-code', false, [])
      const out: string[] = []
      removeUser(w.env, 4242, w.home, 'claude-code', out)
      expect(out[0]).toMatch(/^wrote /)
      const s = json(settings)
      expect(s.hooks).toEqual(hooks)
      expect([s.model, s.env, s.enabledPlugins]).toEqual(['opus', { A: '1' }, undefined])
    }
  })

  it('refuses a per-folder entry (exists) and leaves an entry that is not this home shim on remove', () => {
    const w = world()
    const file = join(w.HOME, '.claude.json')
    const bag = { args: ['/x/bag-mcp.js', '--as', 'jane', '--dir', w.home] }
    writeFileSync(file, JSON.stringify({ mcpServers: { bag } }))
    expect(() => installUser(w.env, p, m, w.home, 'claude-code', false, [])).toThrow(
      `exists: ${file} has mcpServers.bag for one identity (the per-folder form): run host migrate`,
    )
    const out: string[] = []
    removeUser(w.env, 4242, w.home, 'claude-code', out)
    expect(out).toEqual([
      `left ${file}: its mcpServers.bag is not the shim of ${w.home}`,
      'nothing to change',
    ])
    expect(json(file).mcpServers.bag).toEqual(bag)
  })

  it('finds the files under CLAUDE_CONFIG_DIR, refuses a relative one and no HOME, usage', () => {
    const dir = folder()
    expect(claudeFiles({ CLAUDE_CONFIG_DIR: dir })).toEqual({
      file: join(dir, '.claude.json'),
      settings: join(dir, 'settings.json'),
    })
    expect(() => claudeFiles({ CLAUDE_CONFIG_DIR: 'rel' })).toThrow(
      'usage: CLAUDE_CONFIG_DIR is "rel", a relative path',
    )
    expect(() => claudeFiles({})).toThrow('usage: no HOME: --user writes under $HOME')
    expect(userNotes({ CLAUDE_CONFIG_DIR: dir }, '/h', 'claude-code', true)[0]).toContain(
      'check once in Claude Code',
    )
  })
})

describe('installUser and removeUser: omp and codex', () => {
  it('omp: the shim entry with its timeout and the wake link, refusing a file at the link that is not ours', () => {
    const w = world()
    const out: string[] = []
    installUser(w.env, p, m, w.home, 'omp', false, out)
    const agent = ompAgentDir(w.env)
    expect(agent).toBe(join(w.HOME, '.omp', 'agent'))
    expect(json(join(agent, 'mcp.json')).mcpServers.bag.timeout).toBe(130000)
    const link = join(agent, 'hooks', 'pre', 'bag-wake.js')
    expect(readlinkSync(link)).toBe('/b/bag-omp-wake.js')
    expect(out.at(-1)).toContain('the wake extension')
    const gone: string[] = []
    removeUser(w.env, 4242, w.home, 'omp', gone)
    expect(gone).toContain(`wrote ${link}: bag's wake link removed`)
    expect(() => lstatSync(link)).toThrow()
    writeFileSync(join(agent, 'hooks', 'pre', 'bag-wake.ts'), '// mine')
    expect(() => installUser(w.env, p, m, w.home, 'omp', false, [])).toThrow("is not bag's wake link")
    expect(ompAgentDir({ PI_CODING_AGENT_DIR: '/a' })).toBe('/a')
  })

  it("codex: the table and the Stop and SessionEnd hooks, a writable root's warning, and the remove", () => {
    const w = world()
    mkdirSync(join(w.HOME, '.codex'))
    const config = join(w.HOME, '.codex', 'config.toml')
    writeFileSync(config, `[sandbox_workspace_write]\nwritable_roots = ["${w.home}"]\n`)
    const out: string[] = []
    installUser(w.env, p, m, w.home, 'codex', false, out)
    const text = readFileSync(config, 'utf8')
    expect(text).toContain(
      `[mcp_servers.bag]\ncommand = "/n/node"\nargs = ${JSON.stringify(['/b/bag-shim.js', '--dir', w.home])}\n`,
    )
    const hooks = json(join(w.HOME, '.codex', 'hooks.json')).hooks
    expect(hooks.Stop[0].hooks[0].command).toContain('wake-hook --session service')
    expect(hooks.SessionEnd[0].hooks[0].timeout).toBe(3)
    expect(out.some((l) => l.startsWith('warning: [sandbox_workspace_write] writable_roots names'))).toBe(
      true,
    )
    expect(out.find((l) => l.startsWith('warning: [sandbox_workspace_write]'))).toContain(
      'and so restart the bag service: take it out',
    )
    const again: string[] = []
    installUser(w.env, p, m, w.home, 'codex', false, again)
    expect(again[0]).toBe('nothing to change')
    const gone: string[] = []
    removeUser(w.env, 4242, w.home, 'codex', gone)
    expect(gone[0]).toBe(`wrote ${config}: [mcp_servers.bag] (the shim) removed`)
    expect(readFileSync(config, 'utf8')).not.toContain('mcp_servers.bag')
  })

  it("codex: refuses one identity's table, and leaves it on remove", () => {
    const w = world()
    mkdirSync(join(w.HOME, '.codex'))
    const config = join(w.HOME, '.codex', 'config.toml')
    writeFileSync(config, '[mcp_servers.bag]\ncommand = "n"\nargs = ["/m/bag-mcp.js", "--as", "jane"]\n')
    expect(() => installUser(w.env, p, m, w.home, 'codex', false, [])).toThrow(
      `exists: ${config} has [mcp_servers.bag] of one identity, or of another home`,
    )
    const out: string[] = []
    removeUser(w.env, 4242, w.home, 'codex', out)
    expect(out[0]).toBe(`left ${config}: its [mcp_servers.bag] is not the shim of ${w.home}`)
    expect(existsSync(config)).toBe(true)
  })
})

describe('shimOf and tableOf', () => {
  it('reads the shim entry and the Codex table as host install writes them', () => {
    expect(shimOf({ args: ['/a/bag-shim.js', '--dir', '/h'] })).toEqual({ home: '/h' })
    expect(shimOf({ args: ['/a/bag-mcp.js', '--dir', '/h'] })).toBeNull()
    expect(shimOf(null)).toBeNull()
    expect(tableOf('[mcp_servers.bag]\ncommand = "n"\n[other]\n')).toBe('[mcp_servers.bag]\ncommand = "n"\n')
    expect(tableOf('bag = { command = "n" }\n')).toBe('')
    expect(tableOf('')).toBeNull()
  })
})

describe('installUser: what an earlier install left', () => {
  it("replaces an earlier version's service hook and an earlier wake link of bag's, and notes no writable root", () => {
    const w = world()
    const settings = join(w.HOME, '.claude', 'settings.json')
    mkdirSync(join(w.HOME, '.claude'))
    const old = `/old/node /b/bag.js wake-hook --session service --dir ${w.home} --max 3500`
    writeFileSync(settings, JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ command: old }] }] } }))
    installUser(w.env, p, m, w.home, 'claude-code', false, [])
    expect(json(settings).hooks.SessionStart).toEqual([
      {
        hooks: [
          {
            type: 'command',
            command: `/n/node /b/bag.js wake-hook --session service --dir ${w.home} --max 86000`,
            timeout: 86400,
            asyncRewake: true,
          },
        ],
      },
    ])
    const pre = join(w.HOME, '.omp', 'agent', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const target = join(folder(), 'omp-wake.ts')
    writeFileSync(target, '// an older wake')
    const earlier = join(pre, 'bag-wake.ts')
    symlinkSync(target, earlier)
    const out: string[] = []
    installUser(w.env, p, m, w.home, 'omp', false, out)
    expect(out).toContain(`wrote ${earlier}: an earlier wake link of bag's removed`)
    expect(() => lstatSync(earlier)).toThrow()
    expect(readlinkSync(join(pre, 'bag-wake.js'))).toBe('/b/bag-omp-wake.js')
    expect(userNotes({ HOME: folder() }, '/h', 'codex', false)).toHaveLength(2)
  })
})

describe('removeUser and installUser: the forms an install meets', () => {
  it('takes only bag service hooks out, leaves a non-list event, and finds nothing to remove for omp', () => {
    const w = world()
    installUser(w.env, p, m, w.home, 'claude-code', false, [])
    const settings = join(w.HOME, '.claude', 'settings.json')
    const doc = json(settings)
    doc.hooks.SessionStart.push({ hooks: [{ command: 'other' }] })
    doc.hooks.Note = 'x'
    writeFileSync(settings, JSON.stringify(doc))
    removeUser(w.env, 4242, w.home, 'claude-code', [])
    expect(json(settings).hooks).toEqual({ SessionStart: [{ hooks: [{ command: 'other' }] }], Note: 'x' })
    const out: string[] = []
    removeUser(w.env, 4242, w.home, 'omp', out)
    expect(out).toEqual(['nothing to change'])
  })

  it("refuses another home's shim, replaces this home's older Codex table, and leaves a one-line table on remove", () => {
    const w = world()
    const file = join(w.HOME, '.claude.json')
    writeFileSync(
      file,
      JSON.stringify({ mcpServers: { bag: { args: ['/a/bag-shim.js', '--dir', '/other'] } } }),
    )
    expect(() => installUser(w.env, p, m, w.home, 'claude-code', false, [])).toThrow(
      `exists: ${file} has mcpServers.bag for the home /other: run host migrate`,
    )
    mkdirSync(join(w.HOME, '.codex'))
    const config = join(w.HOME, '.codex', 'config.toml')
    const shim = JSON.stringify(['/b/bag-shim.js', '--dir', w.home])
    writeFileSync(config, `[mcp_servers.bag]\ncommand = "/old/node"\nargs = ${shim}\n`)
    installUser(w.env, p, m, w.home, 'codex', false, [])
    expect(readFileSync(config, 'utf8')).toBe(`[mcp_servers.bag]\ncommand = "/n/node"\nargs = ${shim}\n`)
    writeFileSync(config, 'bag = { command = "n" }\n')
    const out: string[] = []
    removeUser(w.env, 4242, w.home, 'codex', out)
    expect(out[0]).toBe(`left ${config}: its [mcp_servers.bag] is not the shim of ${w.home}`)
    expect(readFileSync(config, 'utf8')).toBe('bag = { command = "n" }\n')
  })
})
