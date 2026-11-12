import { execFileSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { keepAliveChoice } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { serviceInstall, servicePlist, serviceUnit } from '../src/commands/host-service.ts'
import { stableNode } from '../src/packaged.ts'
import { stage } from '../src/stage.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The user-scope wiring of the bag service (host install <host> --user, no --as), host migrate and its undo, the
// login agent's text, and versioned staging. Temporary directories only: a fake HOME and fake projects.

const tmp = tempDir('host-service')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const RELAY2 = 'http://127.0.0.1:8'
const NODE = stableNode()
const SHIM = fileURLToPath(new URL('../../shim/src/main.ts', import.meta.url))
const OMP = fileURLToPath(new URL('../src/omp-wake.ts', import.meta.url))
const CLI = fileURLToPath(new URL('../src/main.ts', import.meta.url))
let n = 0

interface World {
  readonly io: TestIo
  readonly home: string
  readonly user: string
  readonly base: string
}

async function world(...names: string[]): Promise<World> {
  const base = join(tmp.dir, `w${n++}`)
  const [home, user] = [join(base, 'home'), join(base, 'user')]
  mkdirSync(user, { recursive: true })
  mkdirSync(home, { recursive: true })
  const io = testIo(new MemoryRelay(), { HOME: user })
  for (const name of names) expect((await cli(io, 'keygen', name, '--dir', home)).code).toBe(0)
  chmodSync(home, 0o700)
  return { io, home, user, base }
}

const json = (file: string): Record<string, unknown> => JSON.parse(readFileSync(file, 'utf8'))
const user = (w: World, host: string, ...more: string[]) =>
  cli(w.io, 'host', 'install', host, '--user', '--dir', w.home, ...more)
const shimEntry = (w: World, extra: string[] = []) => ({
  type: 'stdio',
  command: NODE,
  args: [SHIM, '--dir', w.home, ...extra],
})
const wake = (w: World, flags: string[]) =>
  [NODE, CLI, 'wake-hook', '--session', 'service', '--dir', w.home, ...flags].join(' ')

describe('host install <host> --user: the bag service for every identity of the home', () => {
  it('claude-code: the shim in ~/.claude.json, its hooks and the sandbox rule in ~/.claude/settings.json, merged', async () => {
    const w = await world('bob')
    mkdirSync(join(w.user, '.claude'), { recursive: true })
    const mine = {
      hooks: { Stop: [{ hooks: [{ type: 'command', command: 'my-own-hook' }] }] },
      permissions: { deny: ['Bash(rm:*)'] },
    }
    writeFileSync(join(w.user, '.claude', 'settings.json'), JSON.stringify(mine))
    writeFileSync(
      join(w.user, '.claude.json'),
      JSON.stringify({ numStartups: 3, mcpServers: { other: { command: 'x' } } }),
    )
    const ran = await user(w, 'claude-code')
    expect(ran.code).toBe(0)
    const top = json(join(w.user, '.claude.json'))
    expect(top.numStartups).toBe(3)
    expect(top.mcpServers).toEqual({ other: { command: 'x' }, bag: shimEntry(w, ['--input-hook']) })
    const s = json(join(w.user, '.claude', 'settings.json')) as Record<string, Record<string, unknown>>
    const run = join(w.home, 'run')
    expect(s.permissions?.deny).toEqual([
      'Bash(rm:*)',
      `Read(/${run}/**)`,
      `Edit(/${run}/**)`,
      `Read(/${join(w.home, 'keys')}/**)`,
      `Read(/${join(w.home, 'state')}/**)`,
      `Edit(/${join(w.home, 'package')}/**)`,
      `Edit(/${join(w.home, 'identities.json')})`,
    ])
    expect(s.sandbox).toEqual({ filesystem: { denyRead: [run], denyWrite: [run, join(w.home, 'package')] } })
    const hook = { type: 'command', command: wake(w, ['--max', '86000']), timeout: 86_400, asyncRewake: true }
    expect(s.hooks?.SessionStart).toEqual([{ hooks: [hook] }])
    expect(s.hooks?.Stop).toEqual([mine.hooks.Stop[0], { hooks: [hook] }])
    expect(s.hooks?.UserPromptSubmit).toEqual([
      { hooks: [{ type: 'command', command: [NODE, SHIM, 'hook', '--dir', w.home].join(' '), timeout: 10 }] },
    ])
    expect(ran.out.at(-1)).toMatch(/^sandbox.enabled is unchanged/)
    const again = await user(w, 'claude-code')
    expect(again.out[0]).toBe('nothing to change')
    const boxed = await user(w, 'claude-code', '--sandbox')
    expect(boxed.out[0]).toMatch(/sandbox.enabled true$/)
    expect((json(join(w.user, '.claude', 'settings.json')).sandbox as Record<string, unknown>).enabled).toBe(
      true,
    )
  })

  it('claude-code: a per-identity bag server at user scope, or the shim of another home, is refused before any write', async () => {
    const w = await world('bob')
    writeFileSync(
      join(w.user, '.claude.json'),
      JSON.stringify({ mcpServers: { bag: { command: NODE, args: ['x', '--as', 'bob'] } } }),
    )
    const ran = await user(w, 'claude-code')
    expect(ran.err[0]).toMatch(/^bag: exists: .*mcpServers.bag for one identity/)
    expect(existsSync(join(w.user, '.claude', 'settings.json'))).toBe(false)
  })

  it('codex: the shim table in ~/.codex/config.toml and its Stop hook; a plain identity table is left for host migrate', async () => {
    const w = await world('bob')
    const ran = await user(w, 'codex')
    expect(ran.code).toBe(0)
    const toml = readFileSync(join(w.user, '.codex', 'config.toml'), 'utf8')
    expect(toml).toBe(
      `[mcp_servers.bag]\ncommand = ${JSON.stringify(NODE)}\nargs = ${JSON.stringify([SHIM, '--dir', w.home])}\n`,
    )
    const hooks = json(join(w.user, '.codex', 'hooks.json')) as { hooks: { Stop: unknown[] } }
    expect(hooks.hooks.Stop).toEqual([
      {
        hooks: [
          {
            type: 'command',
            command: wake(w, ['--max', '30', '--no-idle-wake']),
            timeout: 60,
            statusMessage: 'bag: waiting for mail',
          },
        ],
      },
    ])
    expect(ran.out.some((l) => l.startsWith('Codex has no deny-read entry'))).toBe(true)
    expect(ran.out.some((l) => l.includes(`keep ${join(w.home, 'identities.json')}, `))).toBe(true)
    expect((await user(w, 'codex')).out[0]).toBe('nothing to change')
    const v = await world('bob')
    mkdirSync(join(v.user, '.codex'))
    writeFileSync(
      join(v.user, '.codex', 'config.toml'),
      '[mcp_servers.bag]\ncommand = "node"\nargs = ["m", "--as", "bob"]\n',
    )
    expect((await user(v, 'codex')).err[0]).toMatch(/^bag: exists: .*run host migrate/)
    writeFileSync(
      join(v.user, '.codex', 'config.toml'),
      `[sandbox_workspace_write]\nwritable_roots = ["${v.home}"]\n`,
    )
    expect(
      (await user(v, 'codex')).out.some((l) =>
        l.startsWith('warning: [sandbox_workspace_write] writable_roots'),
      ),
    ).toBe(true)
  })

  it("omp: the shim in <agentDir>/mcp.json, PI_CODING_AGENT_DIR honoured; --as and --sandbox are not this form's", async () => {
    const w = await world('bob')
    expect((await user(w, 'omp')).code).toBe(0)
    expect(json(join(w.user, '.omp', 'agent', 'mcp.json'))).toEqual({
      mcpServers: { bag: shimEntry(w, ['--input-hook']) },
    })
    // The wake extension at user level: a link to the omp-wake entry (from the package, the launcher bag-omp-wake.js).
    const link = join(w.user, '.omp', 'agent', 'hooks', 'pre', 'bag-wake.ts')
    expect(readlinkSync(link)).toBe(OMP)
    expect((await user(w, 'omp')).out[0]).toBe('nothing to change')
    expect(
      (await user(w, 'omp')).out.some((l) =>
        l.includes(`write ${join(w.home, 'identities.json')}, which the service serves from`),
      ),
    ).toBe(true)
    const v = await world('bob')
    mkdirSync(join(v.user, '.omp', 'agent', 'hooks', 'pre'), { recursive: true })
    writeFileSync(join(v.user, '.omp', 'agent', 'hooks', 'pre', 'bag-wake.js'), '// my own')
    expect((await user(v, 'omp')).err[0]).toMatch(/^bag: exists: .*bag-wake.js is not bag's wake link/)
    const agent = join(w.base, 'profile')
    const io = testIo(new MemoryRelay(), { HOME: w.user, PI_CODING_AGENT_DIR: agent })
    expect((await cli(io, 'host', 'install', 'omp', '--user', '--dir', w.home)).code).toBe(0)
    expect(existsSync(join(agent, 'mcp.json'))).toBe(true)
    expect((await user(w, 'omp', '--sandbox')).err[0]).toBe('bag: usage: --sandbox is for claude-code')
    expect((await user(w, 'claude-code', '--relay', RELAY)).err[0]).toMatch(
      /--relay is not taken by --user without --as/,
    )
  })
})

describe('host install claude-code --user writes where Claude Code reads: CLAUDE_CONFIG_DIR', () => {
  it('with CLAUDE_CONFIG_DIR, <dir>/.claude.json and <dir>/settings.json, nothing under ~/.claude; remove takes it out', async () => {
    const w = await world('bob')
    const dir = join(w.base, 'claude-work')
    const io = testIo(new MemoryRelay(), { HOME: w.user, CLAUDE_CONFIG_DIR: dir })
    const ran = await cli(io, 'host', 'install', 'claude-code', '--user', '--dir', w.home)
    expect(ran.out.slice(0, 2)).toEqual([
      `wrote ${join(dir, '.claude.json')}: mcpServers.bag, the bag service's shim`,
      `wrote ${join(dir, 'settings.json')}: the shim's SessionStart, Stop and UserPromptSubmit hooks; deny rules for ${join(w.home, 'run')}`,
    ])
    expect((json(join(dir, '.claude.json')).mcpServers as Record<string, unknown>).bag).toEqual(
      shimEntry(w, ['--input-hook']),
    )
    expect(
      Object.keys((json(join(dir, 'settings.json')).hooks as Record<string, unknown>) ?? {}).sort(),
    ).toEqual(['SessionStart', 'Stop', 'UserPromptSubmit'])
    expect(existsSync(join(w.user, '.claude.json'))).toBe(false)
    expect(existsSync(join(w.user, '.claude'))).toBe(false)
    const removed = await cli(io, 'host', 'remove', 'claude-code', '--user', '--dir', w.home)
    expect(removed.out).toEqual([
      `wrote ${join(dir, '.claude.json')}: mcpServers.bag (the shim) removed`,
      `wrote ${join(dir, 'settings.json')}: bag's service hooks removed`,
    ])
    // The one check line under a config dir, where settings.json's place is Claude Code's layout, not a live check.
    const check = `check once in Claude Code: /permissions should list bag's deny rules for ${join(w.home, 'keys')} and ${join(w.home, 'run')}; if it does not, say so at bag.dev`
    expect(ran.out).toContain(check)
    // A relative CLAUDE_CONFIG_DIR names no one folder: refused, nothing written.
    const rel = testIo(new MemoryRelay(), { HOME: w.user, CLAUDE_CONFIG_DIR: 'claude-x' })
    expect((await cli(rel, 'host', 'install', 'claude-code', '--user', '--dir', w.home)).err[0]).toBe(
      'bag: usage: CLAUDE_CONFIG_DIR is "claude-x", a relative path: set it to the absolute folder your Claude Code reads, then run this again',
    )
    // Without the variable: ~/.claude.json and ~/.claude/settings.json, as before, and no check line.
    const plain = await user(w, 'claude-code')
    expect(plain.out).not.toContain(check)
    expect(plain.out[0]).toBe(`wrote ${join(w.user, '.claude.json')}: mcpServers.bag, the bag service's shim`)
    expect(existsSync(join(w.user, '.claude', 'settings.json'))).toBe(true)
  })
})

describe('host remove <host> --user: the shim of this home out, every other server and hook kept', () => {
  it('takes out what --user wrote for each host, leaves the deny rules and a foreign entry, and says nothing to change after', async () => {
    const w = await world('bob')
    writeFileSync(join(w.user, '.claude.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }))
    for (const host of ['claude-code', 'codex', 'omp']) expect((await user(w, host)).code).toBe(0)
    const remove = (host: string) => cli(w.io, 'host', 'remove', host, '--user', '--dir', w.home)
    expect((await remove('claude-code')).out).toEqual([
      `wrote ${join(w.user, '.claude.json')}: mcpServers.bag (the shim) removed`,
      `wrote ${join(w.user, '.claude', 'settings.json')}: bag's service hooks removed`,
    ])
    expect(json(join(w.user, '.claude.json')).mcpServers).toEqual({ other: { command: 'x' } })
    const s = json(join(w.user, '.claude', 'settings.json')) as Record<string, Record<string, unknown>>
    expect(s.hooks).toEqual({})
    expect(s.permissions?.deny).toHaveLength(6)
    expect((await remove('codex')).code).toBe(0)
    expect(readFileSync(join(w.user, '.codex', 'config.toml'), 'utf8')).not.toContain('mcp_servers.bag')
    expect(JSON.stringify(json(join(w.user, '.codex', 'hooks.json')))).not.toContain('wake-hook')
    expect((await remove('omp')).code).toBe(0)
    expect(json(join(w.user, '.omp', 'agent', 'mcp.json')).mcpServers).toEqual({})
    expect(existsSync(join(w.user, '.omp', 'agent', 'hooks', 'pre', 'bag-wake.ts'))).toBe(false)
    expect((await remove('claude-code')).out).toEqual(['nothing to change'])
    writeFileSync(
      join(w.user, '.claude.json'),
      JSON.stringify({ mcpServers: { bag: { command: NODE, args: ['x', '--as', 'bob'] } } }),
    )
    expect((await remove('claude-code')).out[0]).toBe(
      `left ${join(w.user, '.claude.json')}: its mcpServers.bag is not the shim of ${w.home}`,
    )
  })
})

/** Every file under `dir` (links as their target), as path -> content, for a byte-equal check. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (d: string) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f)
      const st = lstatSync(p)
      if (st.isSymbolicLink()) out[p] = `link:${readlinkSync(p)}`
      else if (st.isDirectory()) walk(p)
      else out[p] = readFileSync(p, 'utf8')
    }
  }
  walk(dir)
  return out
}

/** Three folders and four identities wired per folder, plus a Codex identity and one folder of another home. */
async function wired(): Promise<World & { a: string; b: string; c: string; other: string }> {
  const w = await world('bob', 'carol', 'dave', 'erin')
  const [a, b, c, other] = ['a', 'b', 'c', 'other'].map((x) => join(w.base, x)) as [
    string,
    string,
    string,
    string,
  ]
  for (const d of [a, b, c, other]) mkdirSync(d)
  const per = (host: string, as: string, dir: string, home = w.home) =>
    cli(
      w.io,
      'host',
      'install',
      host,
      '--as',
      as,
      '--relay',
      RELAY,
      '--relay',
      RELAY2,
      '--dir',
      home,
      '--project',
      dir,
    )
  expect((await per('claude-code', 'bob', a)).code).toBe(0)
  expect((await per('omp', 'carol', b)).code).toBe(0)
  expect((await per('claude-code', 'dave', c)).code).toBe(0)
  const codex = [
    'host',
    'install',
    'codex',
    '--as',
    'erin',
    '--relay',
    RELAY,
    '--dir',
    w.home,
    '--user',
    '--mode',
    'mcp',
  ]
  expect((await cli(w.io, ...codex)).code).toBe(0)
  // A hook of the person's own beside bob's, which stays.
  const settings = join(a, '.claude', 'settings.json')
  const s = json(settings) as { hooks: Record<string, unknown[]> }
  s.hooks.Stop?.push({ hooks: [{ type: 'command', command: 'my-own-hook' }] })
  writeFileSync(settings, JSON.stringify(s, null, 2))
  // Another home's identity in a fourth folder: never migrated.
  const elsewhere = join(w.base, 'elsewhere')
  expect((await cli(w.io, 'keygen', 'zed', '--dir', elsewhere)).code).toBe(0)
  expect((await per('claude-code', 'zed', other, elsewhere)).code).toBe(0)
  mkdirSync(join(w.user, 'Library', 'LaunchAgents'), { recursive: true })
  writeFileSync(join(w.user, 'Library', 'LaunchAgents', 'bag.keep.bob.plist'), '<plist/>')
  w.io.tty = true
  return { ...w, a, b, c, other }
}

const migrate = (w: World, ...dirs: string[]) =>
  cli(w.io, 'host', 'migrate', '--dir', w.home, ...dirs.flatMap((d) => ['--project', d]))

describe('host migrate: per-folder wiring moved to the bag service, journalled, and undone', () => {
  it("moves only this home's entries after one y, keeps the rest, proposes each folder's identity, and undo restores every byte", async () => {
    const w = await wired()
    const before = { ...snapshot(w.base) }
    w.io.answers.push(true)
    const ran = await migrate(w, w.a, w.b, w.c, w.other)
    expect(ran.code).toBe(0)
    const question = w.io.asked.at(-1) as string
    expect(question).toMatch(/^migrate 4 per-folder bag entries of /)
    expect(question).toContain(
      `claude-code ${realpathSync(w.a)}: bob, proposed there, never bound without your word`,
    )
    expect(question).toContain('codex for this user: erin')
    expect(question).toMatch(/left .*zed of the home .*elsewhere/)
    // The folders: bag's entries, hooks and link out; the person's hook and the other home's entry stay.
    expect((json(join(w.a, '.mcp.json')).mcpServers as Record<string, unknown>).bag).toBeUndefined()
    const s = json(join(w.a, '.claude', 'settings.json')) as { hooks: Record<string, unknown> }
    expect(s.hooks).toEqual({ Stop: [{ hooks: [{ type: 'command', command: 'my-own-hook' }] }] })
    expect((json(join(w.b, '.omp', 'mcp.json')).mcpServers as Record<string, unknown>).bag).toBeUndefined()
    expect(existsSync(join(w.b, '.omp', 'hooks', 'pre', 'bag-wake.ts'))).toBe(false)
    expect(readFileSync(join(w.other, '.mcp.json'), 'utf8')).toBe(before[join(w.other, '.mcp.json')])
    // The user scope: the shim for each host kind that was wired.
    expect((json(join(w.user, '.claude.json')).mcpServers as Record<string, unknown>).bag).toEqual(
      shimEntry(w, ['--input-hook']),
    )
    expect(
      (json(join(w.user, '.omp', 'agent', 'mcp.json')).mcpServers as Record<string, unknown>).bag,
    ).toEqual(shimEntry(w, ['--input-hook']))
    expect(readFileSync(join(w.user, '.codex', 'config.toml'), 'utf8')).toContain(
      JSON.stringify([SHIM, '--dir', w.home]),
    )
    expect(JSON.stringify(json(join(w.user, '.codex', 'hooks.json')))).not.toContain('--as')
    // The home: four identities with their relays, four proposals, keep-alive on for each.
    const ids = json(join(w.home, 'identities.json')) as {
      identities: { label: string; relays: string[] }[]
    }
    expect(ids.identities.map((i) => i.label).sort()).toEqual(['bob', 'carol', 'dave', 'erin'])
    expect(ids.identities.find((i) => i.label === 'bob')?.relays).toEqual([RELAY, RELAY2])
    const props = json(join(w.home, 'proposals.json')) as {
      proposals: { folder: string; host: string; label: string }[]
    }
    expect(props.proposals.map((p) => `${p.host} ${p.label}`).sort()).toEqual([
      'claude-code bob',
      'claude-code dave',
      'codex erin',
      'omp carol',
    ])
    // Every entry carried --keep-alive-records ("while this server runs"): keep-alive stays the default, the person's
    // own word later; nothing is written to the service's table.
    for (const name of ['bob', 'carol', 'dave', 'erin']) expect(keepAliveChoice(w.home, name).keep).toBe(null)
    expect(existsSync(join(w.home, 'run', 'keep-alive.json'))).toBe(false)
    expect(question).toContain(
      "  keep-alive stays the default for bob, carol, dave, erin: to keep one's records alive always, type bag identity keep-alive on <name>",
    )
    expect(ran.out).toContain(
      'keep-alive is your choice per identity, the default for bob, carol, dave, erin; for one kept alive always: bag identity keep-alive on <name>',
    )
    const uid = process.getuid?.()
    const plist = join(w.user, 'Library', 'LaunchAgents', 'bag.keep.bob.plist')
    expect(ran.out).toContain(
      `retire the old keep job in a terminal (the service keeps records now): launchctl bootout gui/${uid}/bag.keep.bob && mv ${plist} ~/.Trash/`,
    )
    expect(existsSync(plist)).toBe(true)
    const journal = ran.out.find((l) => l.startsWith('journal '))?.slice(8) as string
    const stamp = /(\d{8}T\d{6}Z)\.json$/.exec(journal)?.[1] as string
    // A second run finds nothing more of this home.
    expect((await migrate(w, w.a, w.b, w.c)).out.at(-1)).toBe(
      'nothing to migrate: no per-folder bag entry of this home was found',
    )
    // Undo: every journalled path back, byte for byte; the journal and its backups stay.
    w.io.answers.push(true)
    const undone = await cli(w.io, 'host', 'migrate', '--undo', stamp, '--dir', w.home)
    expect(undone.code).toBe(0)
    const after = snapshot(w.base)
    // The journal and its backups stay.
    const kept = (p: string) => !p.includes(join(w.home, 'migrate'))
    expect(Object.fromEntries(Object.entries(after).filter(([p]) => kept(p)))).toEqual(before)
    expect(undone.out.some((l) => l.startsWith('keep-alive'))).toBe(false)
    w.io.answers.push(true)
    expect((await cli(w.io, 'host', 'migrate', '--undo', stamp, '--dir', w.home)).err[0]).toMatch(
      /^bag: exists: .* was undone at /,
    )
  })

  it('refuses a label collision before anything changes, keeps an entry the file holds, and an undo over a path changed since', async () => {
    const w = await wired()
    // Two folder entries of one label that differ: a collision, refused before anything is written.
    const d = join(w.base, 'd')
    mkdirSync(d)
    expect(
      (
        await cli(
          w.io,
          'host',
          'install',
          'claude-code',
          '--as',
          'bob',
          '--relay',
          RELAY2,
          '--dir',
          w.home,
          '--project',
          d,
        )
      ).code,
    ).toBe(0)
    const before = snapshot(w.base)
    w.io.answers.push(true)
    const ran = await migrate(w, w.a, w.b, w.c, d)
    expect(ran.err[0]).toBe(
      'bag: exists: identity bob is in the file with other settings: edit or remove it first',
    )
    expect(snapshot(w.base)).toEqual(before)
    // An entry the file holds already (keygen, init, restore or identity relays wrote it) is kept, with a WARNING.
    const entry = {
      label: 'bob',
      key: 'bob',
      home: w.home,
      relays: ['http://127.0.0.1:7'],
      keep_alive_records: true,
    }
    const file = join(w.home, 'identities.json')
    writeFileSync(file, JSON.stringify({ version: 1, identities: [entry] }), { mode: 0o600 })
    w.io.answers.push(true)
    const done = await migrate(w, w.a, w.b, w.c)
    expect(done.code).toBe(0)
    expect(w.io.asked.at(-1)).toContain(
      `    WARNING: ${file} holds bob with other settings (relays http://127.0.0.1:7), which are kept`,
    )
    const kept = json(file) as { identities: { label: string; relays: string[] }[] }
    expect(kept.identities.find((i) => i.label === 'bob')?.relays).toEqual(['http://127.0.0.1:7'])
    const stamp = /(\d{8}T\d{6}Z)\.json$/.exec(
      done.out.find((l) => l.startsWith('journal ')) ?? '',
    )?.[1] as string
    writeFileSync(join(w.a, '.mcp.json'), '{"mcpServers":{}}\n')
    w.io.answers.push(true)
    const undo = await cli(w.io, 'host', 'migrate', '--undo', stamp, '--dir', w.home)
    expect(undo.err[0]).toBe(
      `bag: stale-record: changed since the migration, so not put back: ${join(realpathSync(w.a), '.mcp.json')}; nothing was changed`,
    )
  })

  it("takes the relays from install/<name>.env over a folder entry's, and shows every entry's relays and roots with a warning where they differ", async () => {
    const w = await wired()
    mkdirSync(join(w.home, 'install'), { recursive: true })
    writeFileSync(
      join(w.home, 'install', 'bob.env'),
      `NAME="bob"\nRELAYS="${RELAY}"\nRENDEZVOUS="${RELAY}"\n`,
    )
    const mcp = join(w.a, '.mcp.json')
    const doc = json(mcp) as { mcpServers: { bag: { args: string[] } } }
    doc.mcpServers.bag.args.splice(-3, 0, '--trust-root', `ed25519:${'cd'.repeat(32)}`)
    writeFileSync(mcp, JSON.stringify(doc))
    w.io.answers.push(true)
    expect((await migrate(w, w.a, w.b, w.c)).code).toBe(0)
    const q = w.io.asked.at(-1) as string
    expect(q).toContain(
      `    from ${join(realpathSync(w.a), '.mcp.json')}: relays ${RELAY}, rendezvous ${RELAY}, trust roots ed25519:${'cd'.repeat(32)}`,
    )
    expect(q).toContain(
      `    WARNING: relays ${RELAY} ${RELAY2} differ from install/bob.env (${RELAY}), which is used`,
    )
    expect(q).toContain(`    WARNING: rendezvous none differs from install/bob.env (${RELAY}), which is used`)
    expect(q).toContain(`    WARNING: trusts ed25519:${'cd'.repeat(32)}: check that these roots are yours`)
    const ids = json(join(w.home, 'identities.json')) as { identities: { label: string; relays: string[] }[] }
    expect(ids.identities.find((i) => i.label === 'bob')?.relays).toEqual([RELAY])
  })

  it("is the person's act: no-tty without a terminal, declined on no, and nothing written either way", async () => {
    const w = await wired()
    const before = snapshot(w.base)
    w.io.tty = false
    expect((await migrate(w, w.a)).err[0]).toMatch(/^bag: no-tty: /)
    w.io.tty = true
    w.io.answers.push(false)
    expect((await migrate(w, w.a)).err[0]).toBe('bag: declined: nothing was changed')
    expect(snapshot(w.base)).toEqual(before)
    expect((await cli(w.io, 'host', 'migrate', '--undo', 'nope', '--dir', w.home)).err[0]).toMatch(
      /^bag: usage: --undo takes a stamp/,
    )
  })
})

describe('host install service: the login agent, printed for the person', () => {
  const env = {
    HOME: '/Users/x',
    USER: 'x',
    LANG: 'C',
    AC_HOME: '/Users/x/.bag',
    NODE_OPTIONS: '--inspect',
    HTTPS_PROXY: 'http://proxy:8080',
    http_proxy: 'http://u:p@proxy:8080',
    NODE_USE_ENV_PROXY: '1',
  }
  const main = '/Users/x/.bag/package/bag-mcp.js'
  it("is byte for byte S1's launchAgentPlist and systemdUnit for the same inputs (their own output on ecce5f0e)", () => {
    const s1 = readFileSync(fileURLToPath(new URL('./fixtures/svc-core-plist.txt', import.meta.url)), 'utf8')
    const ours = servicePlist({
      node: '/opt/homebrew/bin/node',
      main,
      home: '/Users/x/.bag',
      identities: '/Users/x/.bag/identities.json',
      env,
    })
    expect(ours).toBe(s1)
    expect(ours).not.toContain('NODE_OPTIONS')
    expect(ours).not.toContain('u:p@')
    const unit = readFileSync(fileURLToPath(new URL('./fixtures/svc-core-unit.txt', import.meta.url)), 'utf8')
    const o = {
      node: '/opt/homebrew/bin/node',
      main,
      home: '/Users/x/.bag',
      identities: '/Users/x/.bag/identities.json',
      env,
    }
    expect(serviceUnit(o)).toBe(unit)
  })

  it("names each proxy left out, ends with the person's one line, prints the unit on Linux, and one agent per user", () => {
    const none = () => null
    const mac = serviceInstall(
      env,
      '/Users/x/.bag',
      main,
      'node bag.js',
      'darwin',
      '/opt/homebrew/bin/node',
      none,
    )
    expect(mac).toContain('left out of the login agent: http_proxy (it carries a user name or password)')
    expect(mac.at(-1)).toMatch(
      /^mkdir -p \/Users\/x\/Library\/LaunchAgents && node bag.js host install service --dir \/Users\/x\/.bag \| sed -n '1,\/\^<\\\/plist>\$\/p' > \/Users\/x\/Library\/LaunchAgents\/dev.bag.service.plist && launchctl bootstrap gui\/\d+ \/Users\/x\/Library\/LaunchAgents\/dev.bag.service.plist$/,
    )
    const linux = serviceInstall(env, '/Users/x/.bag', main, 'node bag.js', 'linux', '/usr/bin/node', none)
    expect(linux[0]).toMatch(/^# ~\/\.config\/systemd\/user\/bag\.service: /)
    expect(linux[0]).toContain('UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD')
    expect(linux.at(-1)).toBe(
      "mkdir -p /Users/x/.config/systemd/user && node bag.js host install service --dir /Users/x/.bag | sed -n '1,/^WantedBy=/p' > /Users/x/.config/systemd/user/bag.service && systemctl --user daemon-reload && systemctl --user enable --now bag",
    )
    const other = serviceInstall(
      env,
      '/Users/x/.bag2',
      main,
      'node bag.js',
      'darwin',
      '/n',
      () => mac[0] as string,
    )
    expect(other).toEqual([
      'a login agent for another home is installed (/Users/x/Library/LaunchAgents/dev.bag.service.plist): bag 0.4.0 has one per user, so the service of /Users/x/.bag2 starts with its first window instead',
    ])
  })

  it('writes nothing: the command prints and exits', async () => {
    const w = await world()
    const ran = await cli(w.io, 'host', 'install', 'service', '--dir', w.home)
    expect(ran.code).toBe(0)
    expect(existsSync(join(w.user, 'Library'))).toBe(false)
  })
})

describe('versioned staging: <home>/package/versions/<version>/ and current', () => {
  it('stages once, points current at it, refuses another build of one version, and names the running service', () => {
    const base = join(tmp.dir, `stage${n++}`)
    const [dist, home] = [join(base, 'dist'), join(base, 'home')]
    mkdirSync(dist, { recursive: true })
    for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js'])
      writeFileSync(join(dist, f), `// ${f}`)
    const go = () =>
      stage(
        home,
        true,
        '0.4.0',
        join(dist, 'bag.js'),
        join(dist, 'bag-mcp.js'),
        join(dist, 'bag-omp-wake.js'),
      )
    const to = join(home, 'package', 'versions', '0.4.0')
    const first = go()
    const pkg = join(home, 'package')
    expect(first).toEqual({
      cli: join(pkg, 'bag.js'),
      mcp: join(pkg, 'bag-mcp.js'),
      omp: join(pkg, 'bag-omp-wake.js'),
      shim: join(pkg, 'bag-shim.js'),
      copied: to,
      notice: null,
      versioned: {
        cli: join(to, 'bag.js'),
        mcp: join(to, 'bag-mcp.js'),
        omp: join(to, 'bag-omp-wake.js'),
        shim: join(to, 'bag-shim.js'),
      },
    })
    expect(statSync(join(pkg, 'bag-shim.js')).mode & 0o777).toBe(0o755)
    expect(readFileSync(join(home, 'package', 'current'), 'utf8')).toBe('0.4.0\n')
    expect(readdirSync(join(home, 'package', 'versions'))).toEqual(['0.4.0'])
    expect(go().copied).toBe(null)
    mkdirSync(join(home, 'run'))
    writeFileSync(
      join(home, 'run', 'service.json'),
      JSON.stringify({ pid: 77, package_dir: join(home, 'package', 'versions', '0.9.0') }),
    )
    expect(go().notice).toBe(
      'the running bag service (pid 77) moves to bag 0.4.0 at its next drain and restart',
    )
    writeFileSync(join(dist, 'bag.js'), '// another build')
    expect(() => go()).toThrow(/holds another build of bag 0.4.0/)
    expect(readFileSync(join(to, 'bag.js'), 'utf8')).toBe('// bag.js')
  })
})

describe('the launchers: every host entry survives an upgrade and a prune', () => {
  it('runs the version current names, follows a new current, and keeps working when the old version is pruned', () => {
    const base = join(tmp.dir, `launch${n++}`)
    const home = join(base, 'home')
    const build = (v: string) => {
      const dist = join(base, `dist-${v}`)
      mkdirSync(dist, { recursive: true })
      for (const f of ['bag.js', 'bag-mcp.js', 'bag-omp-wake.js', 'bag-shim.js']) {
        writeFileSync(
          join(dist, f),
          `process.stdout.write(${JSON.stringify(`${v} ${f} `)} + process.argv.slice(2).join(' '))\nexport default '${v}'\n`,
        )
      }
      return stage(
        home,
        true,
        v,
        join(dist, 'bag.js'),
        join(dist, 'bag-mcp.js'),
        join(dist, 'bag-omp-wake.js'),
      )
    }
    const run = (file: string, ...args: string[]) =>
      execFileSync(process.execPath, [file, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } })
    const m = build('0.4.0')
    expect(run(m.shim, '--dir', home, '--input-hook')).toBe(`0.4.0 bag-shim.js --dir ${home} --input-hook`)
    expect(run(m.cli, 'wake-hook', '--session', 'service')).toBe('0.4.0 bag.js wake-hook --session service')
    const n2 = build('0.4.1')
    expect(n2.shim).toBe(m.shim)
    // W2's prune removes the old version: the same entries now run 0.4.1.
    renameSync(join(home, 'package', 'versions', '0.4.0'), join(base, 'pruned-0.4.0'))
    for (const f of [m.cli, m.mcp, m.shim]) expect(run(f, 'x')).toMatch(/^0\.4\.1 bag(-mcp|-shim)?\.js x$/)
    writeFileSync(join(home, 'package', 'current'), '../../etc\n')
    expect(() => run(m.shim)).toThrow(/no version named/)
  })
})

describe("identity relays: a service identity's relays in <home>/identities.json", () => {
  it('sets the list after one y, keeps every other member and entry, and says the record keep line', async () => {
    const w = await world('bob', 'carol')
    const file = join(w.home, 'identities.json')
    const entries = ['bob', 'carol'].map((label) => ({
      label,
      key: label,
      home: w.home,
      relays: [RELAY],
      keep_alive_records: true,
    }))
    writeFileSync(file, JSON.stringify({ version: 1, identities: entries }), { mode: 0o600 })
    const set = (...r: string[]) =>
      cli(w.io, 'identity', 'relays', 'bob', ...r.flatMap((x) => ['--relay', x]), '--dir', w.home)
    expect((await set(RELAY2)).err[0]).toMatch(/^bag: no-tty/)
    w.io.tty = true
    w.io.answers.push(true)
    const ran = await set(RELAY2, RELAY)
    expect(ran.out).toEqual([
      `relays bob ${RELAY2} ${RELAY}`,
      `publish its records at each: bag record keep --once --as bob --relay ${RELAY2} --relay ${RELAY}`,
    ])
    expect(w.io.asked.at(-1)).toBe(`set the relays of bob in ${file}: ${RELAY} -> ${RELAY2} ${RELAY}?`)
    const doc = json(file) as {
      identities: { label: string; relays: string[]; keep_alive_records: boolean }[]
    }
    expect(doc.identities.map((i) => [i.label, i.relays, i.keep_alive_records])).toEqual([
      ['bob', [RELAY2, RELAY], true],
      ['carol', [RELAY], true],
    ])
    expect((await set(RELAY2, RELAY)).out).toEqual([`relays bob ${RELAY2} ${RELAY} (unchanged)`])
    expect((await cli(w.io, 'identity', 'relays', 'zed', '--relay', RELAY, '--dir', w.home)).err[0]).toMatch(
      /^bag: ENOENT: no identity zed in /,
    )
  })

  it('adds a name the file lacks, and makes the file, on the y: a reused identity no folder wired', async () => {
    const w = await world('bob')
    const file = join(w.home, 'identities.json')
    expect(existsSync(file)).toBe(false)
    w.io.tty = true
    w.io.answers.push(true)
    const ran = await cli(w.io, 'identity', 'relays', 'bob', '--relay', RELAY, '--dir', w.home)
    expect(w.io.asked.at(-1)).toBe(`add bob to ${file} with the relays ${RELAY}?`)
    expect(ran.out).toEqual([
      `relays bob ${RELAY}`,
      `publish its records at each: bag record keep --once --as bob --relay ${RELAY}`,
    ])
    expect(json(file)).toEqual({
      version: 1,
      identities: [{ label: 'bob', key: 'bob', home: w.home, relays: [RELAY], keep_alive_records: true }],
    })
  })
})

describe("keygen, init and restore put the identity in the service's identities.json", () => {
  it("keygen adds it with install/<name>.env's relays, or the file's first entry's, and adds nothing with no relay known", async () => {
    const w = await world()
    const file = join(w.home, 'identities.json')
    const keygen = (name: string) => cli(w.io, 'keygen', name, '--custody', 'file', '--dir', w.home)
    const none = await keygen('ann')
    expect([none.code, none.err, existsSync(file)]).toEqual([0, [], false])
    mkdirSync(join(w.home, 'install'), { recursive: true, mode: 0o700 })
    writeFileSync(
      join(w.home, 'install', 'bob.env'),
      `NAME="bob"\nRELAYS="${RELAY} ${RELAY2}"\nRENDEZVOUS="${RELAY}"\n`,
    )
    const bob = await keygen('bob')
    expect(bob.out).toHaveLength(1)
    expect(bob.err).toEqual([`added bob to ${file} for the bag service (relays ${RELAY} ${RELAY2})`])
    const carol = await keygen('carol')
    expect(carol.err).toEqual([`added carol to ${file} for the bag service (relays ${RELAY} ${RELAY2})`])
    const doc = json(file) as { identities: Record<string, unknown>[] }
    expect(doc.identities).toEqual([
      {
        label: 'bob',
        key: 'bob',
        home: w.home,
        relays: [RELAY, RELAY2],
        rendezvous: RELAY,
        keep_alive_records: true,
      },
      { label: 'carol', key: 'carol', home: w.home, relays: [RELAY, RELAY2], keep_alive_records: true },
    ])
    // identity relays adds ann, whom keygen could not.
    w.io.tty = true
    w.io.answers.push(true)
    expect((await cli(w.io, 'identity', 'relays', 'ann', '--relay', RELAY, '--dir', w.home)).code).toBe(0)
    expect((json(file) as { identities: { label: string }[] }).identities.map((i) => i.label)).toEqual([
      'bob',
      'carol',
      'ann',
    ])
  })
})

describe("identity keep-alive: the person's word, through the edge's setKeepAlive", () => {
  it("sets on, off and default in the service's table, prints the word, and is the person's act", async () => {
    const w = await world('bob')
    const word = (x: string, name = 'bob') => cli(w.io, 'identity', 'keep-alive', x, name, '--dir', w.home)
    expect((await word('on')).err[0]).toMatch(/^bag: no-tty: /)
    w.io.tty = true
    expect((await word('on')).out).toEqual(['keep-alive bob on'])
    expect(keepAliveChoice(w.home, 'bob').keep).toBe(true)
    expect(existsSync(join(w.home, 'run', 'keep-alive.json'))).toBe(true)
    expect((await word('off')).out).toEqual(['keep-alive bob off'])
    expect(keepAliveChoice(w.home, 'bob').keep).toBe(false)
    expect((await word('default')).out).toEqual(['keep-alive bob default'])
    expect(keepAliveChoice(w.home, 'bob').keep).toBe(null)
    // The table is keyed by the label: a key name whose identities.json label differs writes the label's row.
    const file = join(w.home, 'identities.json')
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        identities: [{ label: 'work', key: 'bob', home: w.home, relays: [RELAY] }],
      }),
      { mode: 0o600 },
    )
    expect((await word('on')).out).toEqual(['keep-alive work on'])
    expect([keepAliveChoice(w.home, 'work').keep, keepAliveChoice(w.home, 'bob').keep]).toEqual([true, null])
    expect((await word('off', 'work')).out).toEqual(['keep-alive work off'])
    expect((await word('maybe')).err[0]).toBe('bag: usage: keep-alive takes on, off or default, not "maybe"')
    expect((await word('on', 'zed')).err[0]).toMatch(/^bag: ENOENT: no identity zed/)
  })
})

describe("names reserved for the bag service's own files", () => {
  it('keygen, init, restore, onboard and identity custody refuse a name ending in .service, .session or .signin', async () => {
    const w = await world()
    const line = (n: string, s: string) =>
      `bag: bad-name: "${n}" ends in ${s}, which is reserved for the bag service's own files: choose another name`
    const cases: [string[], string, string][] = [
      [['keygen', 'build.service'], 'build.service', '.service'],
      [['init', 'a.session', '--relay', RELAY], 'a.session', '.session'],
      [['restore', 'a.signin'], 'a.signin', '.signin'],
      [
        ['onboard', 'a.service', '--domain', 'a.example', '--relay', RELAY, '--accept', '*'],
        'a.service',
        '.service',
      ],
      [['identity', 'custody', 'a.session', '--to', 'file'], 'a.session', '.session'],
    ]
    for (const [argv, n, s] of cases) {
      const ran = await cli(w.io, ...argv, '--dir', w.home)
      expect([ran.code, ran.err[0]]).toEqual([1, line(n, s)])
    }
    expect(existsSync(join(w.home, 'keys', 'build.service.json'))).toBe(false)
    expect((await cli(w.io, 'keygen', 'service-bot', '--custody', 'file', '--dir', w.home)).code).toBe(0)
  })
})

describe('the keep job of a keychain identity', () => {
  it('refuses the old keep job for a keychain identity (a dialog at every run), and prints it for a key file', async () => {
    const w = await world('bob')
    const job = (as: string) =>
      cli(w.io, 'record', 'keep', '--as', as, '--relay', RELAY, '--plist', '--dir', w.home)
    expect((await job('bob')).out[0]).toMatch(/^<\?xml/)
    mkdirSync(join(w.home, 'keychain'), { recursive: true })
    writeFileSync(join(w.home, 'keychain', 'kim.json'), '{}')
    expect((await job('kim')).err[0]).toMatch(/^bag: custody-unsupported: kim is kept in the macOS keychain/)
  })
})
