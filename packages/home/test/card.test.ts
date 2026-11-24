import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  type Build,
  CARD_ID,
  cardAnswerers,
  type HostProcess,
  installUser,
  removeUser,
  shq,
  stableNode,
  stage,
} from '../src/index.ts'
import { folder } from './support.ts'

// The question card's plugin, Claude Code's directory marketplace of bag: staged from the package's
// dist/claude-code to <home>/package/claude-code, its two entries in Claude Code's user settings, the refusal of a
// second plugin named bag, the removal, an update, and S1's read-only list of what else could answer a card.

const p: HostProcess = { node: '/n/node', execPath: '/n/node', pid: 4242, uid: 501 }
/** An empty managed settings folder, so that no test reads the machine's own. */
const NOM = folder()
const json = (file: string) => JSON.parse(readFileSync(file, 'utf8'))
const put = (file: string, text: string) => {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, text)
}
const HOOKS = {
  modules: ['./card.js'],
  hooks: {
    Elicitation: [
      {
        matcher: 'bag',
        hooks: [
          { type: 'command', command: '@BAG_NODE@ @BAG_CLI@ card-hook --dir @BAG_HOME@', timeout: 600 },
        ],
      },
    ],
  },
}

/** A bundle's dist/ of `version` with the card's marketplace as packages/bag/build.ts makes it, the mod saying `body`. */
function bundle(version: string, body = 'v1', card = true): Build {
  const dist = folder()
  for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js'])
    writeFileSync(join(dist, f), `// ${f}`)
  if (card) {
    const c = join(dist, 'claude-code')
    put(join(c, '.claude-plugin', 'marketplace.json'), '{"name":"bag","owner":{"name":"bag"},"plugins":[]}\n')
    put(join(c, 'bag', '.claude-plugin', 'plugin.json'), `{"name":"bag","version":"${version}"}\n`)
    put(join(c, 'bag', 'hooks', 'hooks.json'), `${JSON.stringify(HOOKS, null, 2)}\n`)
    put(join(c, 'bag', 'hooks', 'card.js'), `// the mod ${body}\n`)
    if (body === 'v2') put(join(c, 'bag', 'hooks', 'logic.js'), '// new in v2\n')
  }
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

/** A home, a throwaway CLAUDE_CONFIG_DIR, and the settings file in it. */
function world() {
  const config = folder()
  return {
    home: folder(),
    config,
    env: { HOME: folder(), CLAUDE_CONFIG_DIR: config },
    settings: join(config, 'settings.json'),
  }
}

/** Every file under `dir`, relative, sorted. */
const files = (dir: string) =>
  (readdirSync(dir, { recursive: true }) as string[]).filter((f) => statSync(join(dir, f)).isFile()).sort()

describe('the question card: install', () => {
  it('stages the marketplace with its placeholders filled and writes exactly its two settings entries, once', () => {
    const w = world()
    const plain = world()
    const out: string[] = []
    const m = stage(w.home, bundle('0.4.6'), 4242)
    const card = join(w.home, 'package', 'claude-code')
    expect(m.card).toBe(card)
    installUser(w.env, p, m, w.home, 'claude-code', false, out, NOM)
    const { card: _card, ...without } = stage(plain.home, bundle('0.4.6', 'v1', false), 4242)
    expect(without).not.toHaveProperty('card')
    installUser(plain.env, p, without, plain.home, 'claude-code', false, [], NOM)
    const [s, t] = [json(w.settings), json(plain.settings)]
    expect(s.extraKnownMarketplaces).toEqual({ bag: { source: { source: 'directory', path: card } } })
    expect(s.enabledPlugins).toEqual({ [CARD_ID]: true })
    const strip = (o: Record<string, unknown>, home: string) =>
      JSON.parse(
        JSON.stringify({ ...o, extraKnownMarketplaces: 0, enabledPlugins: 0 }).replaceAll(home, '<home>'),
      )
    expect(strip(s, w.home)).toEqual(strip(t, plain.home))
    expect(files(card)).toEqual([
      '.claude-plugin/marketplace.json',
      'bag/.claude-plugin/plugin.json',
      'bag/hooks/card.js',
      'bag/hooks/hooks.json',
    ])
    const command = json(join(card, 'bag', 'hooks', 'hooks.json')).hooks.Elicitation[0].hooks[0].command
    expect(command).toBe(
      `${shq(stableNode(process.execPath))} ${shq(join(w.home, 'package', 'bag.js'))} card-hook --dir ${shq(w.home)}`,
    )
    expect(readdirSync(join(w.home, 'package')).filter((f) => f.startsWith('.'))).toEqual([])
    expect(out).toContain(`wrote ${card}: the question card's plugin bag, staged`)
    expect(out).toContain(
      `reload each Claude Code window once (a new session, or /reload-plugins): bag's questions then come in Claude Code's own question card, and each starts with "bag: "`,
    )
    expect(out.join('\n')).not.toContain('From the bag plugin')
    expect(out.join('\n')).toContain(
      `bag's staged folder ${card} runs inside Claude Code at every session start`,
    )
    const ino = statSync(card).ino
    const again: string[] = []
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4243), w.home, 'claude-code', false, again, NOM)
    expect(again[0]).toBe('nothing to change')
    expect(statSync(card).ino).toBe(ino)
  })

  it('keeps every other key of an existing settings file and refuses another plugin named bag, writing nothing', () => {
    const w = world()
    const m = stage(w.home, bundle('0.4.6'), 4242)
    const was = {
      model: 'opus',
      env: { A: '1' },
      enabledPlugins: { 'x@y': true, 'bag@old': false },
      extraKnownMarketplaces: { y: { source: { source: 'github', repo: 'o/y' } } },
    }
    put(w.settings, JSON.stringify(was))
    installUser(w.env, p, m, w.home, 'claude-code', false, [], NOM)
    const s = json(w.settings)
    expect(s.model).toBe('opus')
    expect(s.env).toEqual({ A: '1' })
    expect(s.enabledPlugins).toEqual({ 'x@y': true, 'bag@old': false, [CARD_ID]: true })
    expect(s.extraKnownMarketplaces.y).toEqual(was.extraKnownMarketplaces.y)
    const v = world()
    const text = JSON.stringify({ enabledPlugins: { 'bag@agent-comms': true } })
    put(v.settings, text)
    expect(() => installUser(v.env, p, m, v.home, 'claude-code', false, [], NOM)).toThrow(
      `exists: ${v.settings} enables bag@agent-comms, another plugin named bag`,
    )
    expect(readFileSync(v.settings, 'utf8')).toBe(text)
    expect(existsSync(join(v.config, '.claude.json'))).toBe(false)
    put(
      v.settings,
      JSON.stringify({ extraKnownMarketplaces: { bag: { source: { source: 'directory', path: '/x' } } } }),
    )
    expect(() => installUser(v.env, p, m, v.home, 'claude-code', false, [], NOM)).toThrow(
      'another marketplace named bag',
    )
  })
})

describe('the question card: removal and update', () => {
  it('removal takes out its two entries and the staged folder, leaving the file as an install without the card does', () => {
    const was = JSON.stringify({ model: 'opus', enabledPlugins: { 'x@y': true } }, null, 2)
    const run = (card: boolean) => {
      const w = world()
      put(w.settings, was)
      const m = stage(w.home, bundle('0.4.6', 'v1', card), 4242)
      installUser(w.env, p, m, w.home, 'claude-code', false, [], NOM)
      // Claude Code's own records of the plugin, as /plugin writes them.
      put(join(w.config, 'plugins', 'known_marketplaces.json'), '{"bag":{}}\n')
      put(join(w.config, 'plugins', 'data', 'bag-bag', 'kept'), 'x')
      const out: string[] = []
      removeUser(w.env, 4242, w.home, 'claude-code', out)
      return { w, out, text: readFileSync(w.settings, 'utf8').replaceAll(w.home, '<home>') }
    }
    const [carded, plain] = [run(true), run(false)]
    expect(carded.text).toBe(plain.text)
    expect(JSON.parse(carded.text).enabledPlugins).toEqual({ 'x@y': true })
    expect(JSON.parse(carded.text).extraKnownMarketplaces).toBeUndefined()
    const card = join(carded.w.home, 'package', 'claude-code')
    expect(existsSync(card)).toBe(false)
    expect(carded.out.join('\n')).toContain(`; the question card's plugin ${CARD_ID} removed`)
    expect(carded.out).toContain(`removed ${card}, the question card's plugin`)
    // What stays and why: Claude Code's own plugin records are not bag's to delete.
    const plugins = join(carded.w.config, 'plugins')
    expect(carded.out.at(-1)).toBe(
      `Claude Code keeps its own record of the bag marketplace and the plugin's data in ${plugins}; bag does not write or delete them: remove the marketplace with /plugin in Claude Code`,
    )
    expect(readFileSync(join(plugins, 'known_marketplaces.json'), 'utf8')).toBe('{"bag":{}}\n')
    expect(readFileSync(join(plugins, 'data', 'bag-bag', 'kept'), 'utf8')).toBe('x')
    expect(plain.out.join('\n')).not.toContain('question card')
    expect(plain.out.join('\n')).not.toContain('/plugin')
    expect(JSON.parse(carded.text).hooks).toBeUndefined()
  })

  it('an update replaces the folder whole through a copy beside it; a copy that fails leaves the old folder whole', () => {
    const w = world()
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, [], NOM)
    const card = join(w.home, 'package', 'claude-code')
    const bad = bundle('0.4.7', 'v2')
    // The version directory as an earlier stage left it, so that only the card's copy meets the unreadable file.
    const v = join(w.home, 'package', 'versions', '0.4.7')
    mkdirSync(v)
    for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js'])
      writeFileSync(join(v, f), `// ${f}`)
    const locked = join(dirname(bad.cli), 'claude-code', 'bag', 'hooks', 'logic.js')
    chmodSync(locked, 0o000)
    expect(() => stage(w.home, bad, 4243)).toThrow('EACCES')
    expect(files(card)).toEqual([
      '.claude-plugin/marketplace.json',
      'bag/.claude-plugin/plugin.json',
      'bag/hooks/card.js',
      'bag/hooks/hooks.json',
    ])
    expect(readFileSync(join(card, 'bag', 'hooks', 'card.js'), 'utf8')).toBe('// the mod v1\n')
    chmodSync(locked, 0o644)
    stage(w.home, bundle('0.4.8', 'v2'), 4244)
    expect(readFileSync(join(card, 'bag', 'hooks', 'card.js'), 'utf8')).toBe('// the mod v2\n')
    expect(json(join(card, 'bag', '.claude-plugin', 'plugin.json')).version).toBe('0.4.8')
    expect(files(card)).toContain('bag/hooks/logic.js')
    expect(readdirSync(join(w.home, 'package')).filter((f) => f.includes('claude-code.'))).toEqual([])
  })
})

describe('the question card: S1, what else could answer a card', () => {
  it('names settings hooks and plugins with a hooks module, by file, never their contents', () => {
    const w = world()
    const project = folder()
    const secret = 'SECRET-COMMAND-TEXT'
    const group = (matcher: string | undefined) => ({
      ...(matcher === undefined ? {} : { matcher }),
      hooks: [{ type: 'command', command: secret }],
    })
    put(
      w.settings,
      JSON.stringify({
        hooks: {
          Elicitation: [group(undefined)],
          PreToolUse: [group('Bash')],
          PermissionRequest: [group('*')],
        },
      }),
    )
    const local = join(project, '.claude', 'settings.local.json')
    put(
      local,
      JSON.stringify({ hooks: { PreToolUse: [group('AskUser.*')], Elicitation: [group('github')] } }),
    )
    const [mod, plain, own] = [folder(), folder(), folder()]
    put(
      join(mod, 'hooks', 'hooks.json'),
      JSON.stringify({ modules: ['./x.js'], hooks: { Stop: [group(undefined)] } }),
    )
    put(join(plain, 'hooks', 'hooks.json'), JSON.stringify({ hooks: { Stop: [group(undefined)] } }))
    put(join(own, 'hooks', 'hooks.json'), JSON.stringify({ modules: ['./card.js'] }))
    const at = (installPath: string) => [{ scope: 'user', installPath }]
    put(
      join(w.config, 'plugins', 'installed_plugins.json'),
      JSON.stringify({
        version: 2,
        plugins: { 'x@y': at(mod), 'z@y': at(plain), [CARD_ID]: at(own) },
      }),
    )
    const lines = cardAnswerers(w.env, project, NOM)
    expect(lines).toEqual([
      `a hook on PermissionRequest in ${w.settings}`,
      `a hook on Elicitation in ${w.settings}`,
      `a hook on PreToolUse in ${local}`,
      `the plugin x@y (${mod}): a hooks module`,
    ])
    expect(lines.join('\n')).not.toContain(secret)
    expect(cardAnswerers({}, undefined, NOM)).toEqual([])
    const out: string[] = []
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, out, NOM)
    expect(out.slice(out.indexOf('these could also answer a bag question card in your place:') + 1)).toEqual(
      lines.slice(0, 2).concat(lines.slice(3)),
    )
  })
})

describe("the question card: a person's own choice, removal that stays, placeholders, managed settings", () => {
  it("I1: leaves the person's own bag@bag false alone and says so; nothing staged", () => {
    const w = world()
    const text = JSON.stringify({ enabledPlugins: { [CARD_ID]: false } })
    put(w.settings, text)
    const out: string[] = []
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, out, NOM)
    const s = json(w.settings)
    expect(s.enabledPlugins).toEqual({ [CARD_ID]: false })
    expect(s.extraKnownMarketplaces).toBeUndefined()
    expect(existsSync(join(w.home, 'package', 'claude-code'))).toBe(false)
    expect(out).toContain(
      `bag's question card is switched off in your Claude Code settings (enabledPlugins ${CARD_ID} is false); bag left it off`,
    )
    expect(out.join('\n')).not.toContain('reload each Claude Code window once')
  })

  it('I2: after host remove, the next update stages no card folder', () => {
    const w = world()
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, [], NOM)
    const card = join(w.home, 'package', 'claude-code')
    expect(existsSync(card)).toBe(true)
    removeUser(w.env, 4242, w.home, 'claude-code', [])
    expect(existsSync(card)).toBe(false)
    expect(stage(w.home, bundle('0.4.7', 'v2'), 4243).card).toBe(card)
    expect(existsSync(card)).toBe(false)
  })

  it('I3: fills only the command values of hooks.json and refuses a placeholder anywhere else, the old folder whole', () => {
    const w = world()
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, [], NOM)
    const card = join(w.home, 'package', 'claude-code')
    const hooks = json(join(card, 'bag', 'hooks', 'hooks.json'))
    expect(JSON.stringify(hooks)).not.toContain('@BAG_')
    for (const [file, text] of [
      [join('bag', '.claude-plugin', 'plugin.json'), '{"name":"bag","description":"@BAG_HOME@"}\n'],
      [join('bag', 'hooks', 'hooks.json'), JSON.stringify({ ...HOOKS, note: '@BAG_CLI@' })],
    ] as const) {
      const b = bundle('0.4.8')
      put(join(dirname(b.cli), 'claude-code', file), text)
      expect(() => stage(w.home, b, 4244)).toThrow(
        `host-file-invalid: ${join(dirname(b.cli), 'claude-code')} holds a placeholder outside a hooks.json command (${file})`,
      )
      expect(readFileSync(join(card, 'bag', 'hooks', 'card.js'), 'utf8')).toBe('// the mod v1\n')
      expect(readdirSync(join(w.home, 'package')).filter((f) => f.includes('claude-code.'))).toEqual([])
    }
  })

  it('F5: refuses a symbolic link anywhere in the plugin source; the file it names is never written, the old folder whole', () => {
    const w = world()
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, [], NOM)
    const card = join(w.home, 'package', 'claude-code')
    const outside = join(folder(), 'outside.json')
    const text = `${JSON.stringify(HOOKS)}\n`
    writeFileSync(outside, text)
    const b = bundle('0.4.9')
    const hooks = join(dirname(b.cli), 'claude-code', 'bag', 'hooks', 'hooks.json')
    rmSync(hooks)
    symlinkSync(outside, hooks)
    expect(() => stage(w.home, b, 4245)).toThrow(
      `host-file-invalid: ${join(dirname(b.cli), 'claude-code')} holds a symbolic link (${join('bag', 'hooks', 'hooks.json')})`,
    )
    expect(readFileSync(outside, 'utf8')).toBe(text)
    expect(readFileSync(join(card, 'bag', 'hooks', 'card.js'), 'utf8')).toBe('// the mod v1\n')
    expect(readdirSync(join(w.home, 'package')).filter((f) => f.includes('claude-code.'))).toEqual([])
  })

  it('S1: names the managed settings files first, a drop-in that cannot be read as not readable, never contents', () => {
    const w = world()
    const managed = folder()
    const secret = 'MANAGED-COMMAND-TEXT'
    put(
      join(managed, 'managed-settings.json'),
      JSON.stringify({
        hooks: {
          PreToolUse: [{ matcher: 'AskUserQuestion', hooks: [{ type: 'command', command: secret }] }],
        },
      }),
    )
    const locked = join(managed, 'managed-settings.d', '10-team.json')
    put(locked, '{}')
    chmodSync(locked, 0o000)
    put(w.settings, JSON.stringify({ hooks: { Elicitation: [{ matcher: 'bag', hooks: [] }] } }))
    const lines = cardAnswerers(w.env, undefined, managed)
    expect(lines).toEqual([
      `a hook on PreToolUse in ${join(managed, 'managed-settings.json')}`,
      `${locked}: not readable`,
      `a hook on Elicitation in ${w.settings}`,
    ])
    expect(lines.join('\n')).not.toContain(secret)
    expect(cardAnswerers({}, undefined, managed)).toEqual(lines.slice(0, 2))
    const out: string[] = []
    installUser(w.env, p, stage(w.home, bundle('0.4.6'), 4242), w.home, 'claude-code', false, out, managed)
    expect(out.slice(-3)).toEqual(lines)
    chmodSync(locked, 0o644)
  })
})
