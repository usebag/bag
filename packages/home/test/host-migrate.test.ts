import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { type Build, type HostProcess, type MigrateInput, migrate, shq, undo } from '../src/index.ts'
import { type Answer, fakeIo, folder, homeWith } from './support.ts'

// host migrate and its undo: every per-folder entry of this home moved to the bag service's shim on one yes, each path
// backed up and journalled first, and put back by the undo on its own yes. The package is staged after the yes, so a
// no leaves nothing under <home>/package; a file that changed while the person was asked refuses busy.

const R1 = 'https://r1.example'
const proc: HostProcess = { node: '/n/node', execPath: '/n/node', pid: 4242, uid: process.getuid?.() }

/** A bundle's dist/ of version 0.4.0, as staging takes it. */
function bundle(): Build {
  const dist = folder()
  for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js'])
    writeFileSync(join(dist, f), `// ${f}`)
  return {
    packaged: true,
    version: '0.4.0',
    cli: join(dist, 'bag.js'),
    mcp: join(dist, 'bag-mcp.js'),
    omp: join(dist, 'bag-omp-wake.js'),
    shim: join(dist, 'bag-shim.js'),
  }
}

/**
 * A home with jane, a folder wired to her per-folder server, two folders whose entries are left (another home's, an
 * identities file's), a keep job, and the input of host migrate over the three folders.
 */
function world(answer: Answer = true) {
  const { home } = homeWith('jane')
  const HOME = folder()
  const project = folder()
  const mcp = join(project, '.mcp.json')
  const args = ['/old/bag-mcp.js', '--as', 'jane', '--relay', R1, '--dir', home, '--keep-alive-records']
  const text = JSON.stringify({ mcpServers: { bag: { command: '/n/node', args }, other: {} } })
  writeFileSync(mcp, text)
  const [elsewhere, listed] = [folder(), folder()]
  const other = ['/old/bag-mcp.js', '--as', 'jane', '--relay', R1, '--dir', '/no/such/home']
  writeFileSync(join(elsewhere, '.mcp.json'), JSON.stringify({ mcpServers: { bag: { args: other } } }))
  writeFileSync(
    join(listed, '.mcp.json'),
    JSON.stringify({ mcpServers: { bag: { args: ['/x/bag-mcp.js', '--identities', '/f'] } } }),
  )
  mkdirSync(join(HOME, 'Library', 'LaunchAgents'), { recursive: true })
  writeFileSync(join(HOME, 'Library', 'LaunchAgents', 'bag.keep.jane.plist'), '<plist/>')
  const io = fakeIo({ answer, env: { HOME } })
  const input: MigrateInput = {
    home,
    given: [project, elsewhere, listed],
    sandbox: false,
    build: bundle(),
    proc,
  }
  const stamp = new Date(io.now * 1000)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
  return { home, HOME, project, mcp, text, io, input, stamp, run: () => migrate(io, input) }
}

describe('migrate', () => {
  it('a no at the question writes nothing: no staged path under <home>/package, no journal, no host file', async () => {
    const w = world(false)
    await expect(w.run()).rejects.toThrow('declined: nothing was changed')
    expect(w.io.asked).toHaveLength(1)
    expect(w.io.asked[0]).toMatch(
      new RegExp(`^migrate 1 per-folder bag entries of ${w.home} to the bag service`),
    )
    expect(w.io.asked[0]).toContain(`edit ${realpathSync(w.mcp)}: mcpServers.bag (jane) out`)
    expect(w.io.asked[0]).toContain('left ')
    expect(existsSync(join(w.home, 'package'))).toBe(false)
    expect(existsSync(join(w.home, 'migrate'))).toBe(false)
    expect(existsSync(join(w.home, 'identities.json'))).toBe(false)
    expect(existsSync(join(w.HOME, '.claude.json'))).toBe(false)
    expect(readFileSync(w.mcp, 'utf8')).toBe(w.text)
    expect(w.io.said).toEqual([])
  })

  it('a dialog that fails writes nothing either', async () => {
    const w = world('throw')
    await expect(w.run()).rejects.toThrow('the dialog failed')
    expect(existsSync(join(w.home, 'package'))).toBe(false)
    expect(readFileSync(w.mcp, 'utf8')).toBe(w.text)
  })

  it('a file changed while asked refuses busy, naming it, and nothing is staged or written', async () => {
    const w = world(() => {
      writeFileSync(w.mcp, '{"mcpServers":{}}')
      return true
    })
    await expect(w.run()).rejects.toThrow(
      `busy: it changed while you were asked: ${realpathSync(w.mcp)}; nothing was changed, ask again`,
    )
    expect(existsSync(join(w.home, 'package'))).toBe(false)
    expect(existsSync(join(w.home, 'migrate'))).toBe(false)
    expect(existsSync(join(w.HOME, '.claude.json'))).toBe(false)
  })

  it('a yes stages the package, journals every path, writes the shim entry and says what to retire', async () => {
    const w = world()
    await w.run()
    const pkg = join(w.home, 'package')
    expect(readFileSync(join(pkg, 'current'), 'utf8')).toBe('0.4.0\n')
    expect(existsSync(join(pkg, 'versions', '0.4.0', 'bag-shim.js'))).toBe(true)
    const claude = JSON.parse(readFileSync(join(w.HOME, '.claude.json'), 'utf8'))
    expect(claude.mcpServers.bag.args).toEqual([join(pkg, 'bag-shim.js'), '--dir', w.home, '--input-hook'])
    expect(JSON.parse(readFileSync(w.mcp, 'utf8'))).toEqual({ mcpServers: { other: {} } })
    const journal = join(w.home, 'migrate', `${w.stamp}.json`)
    expect(JSON.parse(readFileSync(journal, 'utf8')).entries.length).toBeGreaterThan(3)
    expect(w.io.said).toContain(`wrote ${realpathSync(w.mcp)}: mcpServers.bag (jane) out`)
    expect(w.io.said).toContain(`journal ${journal}`)
    expect(w.io.said.some((l) => l.includes(`launchctl bootout gui/${proc.uid}/bag.keep.jane && mv `))).toBe(
      true,
    )
    expect(w.io.said.at(-1)).toMatch(/^close the windows of the migrated folders/)
    expect(JSON.parse(readFileSync(join(w.home, 'proposals.json'), 'utf8')).proposals[0]).toMatchObject({
      label: 'jane',
      host: 'claude-code',
      from: 'migrate',
    })
  })

  it("a yes stages the question card's folder that the two settings entries it writes name", async () => {
    const w = world()
    const card = join(dirname(w.input.build.cli), 'claude-code')
    const hooks = {
      hooks: { Elicitation: [{ hooks: [{ type: 'command', command: '@BAG_CLI@ card-hook' }] }] },
    }
    mkdirSync(join(card, 'bag', 'hooks'), { recursive: true })
    writeFileSync(join(card, 'bag', 'hooks', 'hooks.json'), JSON.stringify(hooks))
    await w.run()
    const staged = join(w.home, 'package', 'claude-code')
    const settings = JSON.parse(readFileSync(join(w.HOME, '.claude', 'settings.json'), 'utf8'))
    expect(settings.extraKnownMarketplaces.bag.source.path).toBe(staged)
    expect(settings.enabledPlugins['bag@bag']).toBe(true)
    const filled = JSON.parse(readFileSync(join(staged, 'bag', 'hooks', 'hooks.json'), 'utf8'))
    expect(filled.hooks.Elicitation[0].hooks[0].command).toBe(
      `${shq(join(w.home, 'package', 'bag.js'))} card-hook`,
    )
    expect(w.io.said).toContain(`wrote ${staged}: the question card's plugin bag, staged`)
  })

  it('finds nothing to migrate in a home no folder names, and asks nothing', async () => {
    const { home } = homeWith('jane')
    const io = fakeIo({ env: { HOME: folder() } })
    await migrate(io, { home, given: [], sandbox: false, build: bundle(), proc })
    expect(io.said).toEqual(['nothing to migrate: no per-folder bag entry of this home was found'])
    expect(io.asked).toEqual([])
  })

  it('refuses no HOME (usage), a home it does not own (unsafe-path) and no home (ENOENT)', async () => {
    const w = world()
    await expect(migrate(fakeIo(), w.input)).rejects.toThrow('usage: no HOME: host migrate edits')
    const uid = (proc.uid ?? 0) + 1
    await expect(migrate(w.io, { ...w.input, proc: { ...proc, uid } })).rejects.toThrow('unsafe-path: ')
    await expect(migrate(w.io, { ...w.input, home: join(folder(), 'gone') })).rejects.toThrow(
      'ENOENT: no home ',
    )
    expect(w.io.asked).toEqual([])
  })
})

describe('undo', () => {
  it('puts every path back on a yes, after a no and a change while asked left everything as it was', async () => {
    const w = world()
    await w.run()
    const claude = join(w.HOME, '.claude.json')
    const migrated = readFileSync(claude, 'utf8')
    const no = fakeIo({ answer: false, env: { HOME: w.HOME } })
    await expect(undo(no, w.home, w.stamp, 4242)).rejects.toThrow('declined: nothing was changed')
    expect(no.asked[0]).toMatch(new RegExp(`^undo the migration ${w.stamp}: put back\\n`))
    const busy = fakeIo({
      env: { HOME: w.HOME },
      answer: () => {
        writeFileSync(claude, migrated.replace('bag-shim', 'bag-shim2'))
        return true
      },
    })
    await expect(undo(busy, w.home, w.stamp, 4242)).rejects.toThrow(
      'busy: it changed while you were asked: ~/.claude.json; nothing was changed, ask again',
    )
    writeFileSync(claude, migrated)
    const yes = fakeIo({ env: { HOME: w.HOME } })
    await undo(yes, w.home, w.stamp, 4242)
    expect(readFileSync(w.mcp, 'utf8')).toBe(w.text)
    expect(existsSync(claude)).toBe(false)
    expect(existsSync(join(w.home, 'identities.json'))).toBe(false)
    expect(yes.said).toContain(`restored ${claude}`)
    expect(yes.said.at(-1)).toMatch(new RegExp(`^undone ${w.stamp}: the per-folder servers start again`))
    await expect(undo(yes, w.home, w.stamp, 4242)).rejects.toThrow('exists: ')
  })

  it('refuses a stamp of another form (usage), no journal (not-found) and a path changed since (stale-record)', async () => {
    const w = world()
    await expect(undo(w.io, w.home, 'yesterday', 1)).rejects.toThrow('usage: --undo takes a stamp')
    await expect(undo(w.io, w.home, w.stamp, 1)).rejects.toThrow('not-found: no migration journal ')
    await w.run()
    writeFileSync(join(w.HOME, '.claude.json'), '{}')
    await expect(undo(w.io, w.home, w.stamp, 1)).rejects.toThrow('stale-record: changed since the migration')
  })
})
