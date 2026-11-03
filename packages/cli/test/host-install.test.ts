import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// host install (packages/mcp/README.md "Registering"): the MCP server's entry and the
// wake hooks for Claude Code in a project's files, the Codex table in ~/.codex/config.toml. Temp directories only.

const tmp = tempDir('host-install')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const ROOT = `ed25519:${'ab'.repeat(32)}`
const MCP_MAIN = fileURLToPath(new URL('../../mcp/src/main.ts', import.meta.url))
const CLI_MAIN = fileURLToPath(new URL('../src/main.ts', import.meta.url))
const CAVEAT = 'topic:build'
let n = 0

interface World {
  readonly io: TestIo
  /** The home with the identity bob. */
  readonly dir: string
  /** An empty project directory, and the HOME the io has. */
  readonly project: string
  readonly userHome: string
}

async function world(homeName = 'home'): Promise<World> {
  const base = join(tmp.dir, `w${n++}`)
  const [dir, project, userHome] = [join(base, homeName), join(base, 'project'), join(base, 'user')]
  mkdirSync(project, { recursive: true })
  mkdirSync(userHome, { recursive: true })
  const io = testIo(new MemoryRelay(), { HOME: userHome })
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  return { io, dir, project, userHome }
}

const install = (w: World, host: string, ...more: string[]) =>
  cli(w.io, 'host', 'install', host, '--as', 'bob', '--dir', w.dir, '--relay', RELAY, ...more)
const json = (file: string): unknown => JSON.parse(readFileSync(file, 'utf8'))
const text = (file: string): string => readFileSync(file, 'utf8')

const server = (dir: string, roots: string[] = []) => [
  MCP_MAIN,
  '--as',
  'bob',
  '--relay',
  RELAY,
  ...roots.flatMap((r) => ['--trust-root', r]),
  '--dir',
  dir,
  '--keep-alive-records',
]
/** The server args of `codex --mode mcp`: one server per Codex session, named from Codex's session id. */
const codexServer = (dir: string, roots: string[] = [], caveats: string[] = [CAVEAT]) => [
  MCP_MAIN,
  '--session',
  'auto:codex',
  '--principal',
  'bob',
  ...caveats.flatMap((c) => ['--grant-caveat', c]),
  '--relay',
  RELAY,
  ...roots.flatMap((r) => ['--trust-root', r]),
  '--dir',
  dir,
]
const hookOf = (command: string) => ({ type: 'command', command, timeout: 86_400, asyncRewake: true })
const wakeCommand = (dir: string): string =>
  `${process.execPath} ${CLI_MAIN} wake-hook --as bob --dir ${dir} --max 86000`
/** The hook an install wrote before the day-long wait: no --max (wake-hook's 3500 s), timeout 3600. */
const earlierHook = (command: string) => ({ type: 'command', command, timeout: 3600, asyncRewake: true })
const earlierCommand = (dir: string): string =>
  `${process.execPath} ${CLI_MAIN} wake-hook --as bob --dir ${dir}`

describe('host install claude-code: the MCP entry in .mcp.json and the wake hooks in .claude/settings.json', () => {
  it('writes both files, prints each path and entry, and a second run changes nothing and says so', async () => {
    const w = await world()
    const mcp = join(w.project, '.mcp.json')
    const settings = join(w.project, '.claude', 'settings.json')
    const first = await install(w, 'claude-code', '--trust-root', ROOT, '--project', w.project)
    const entry = { command: process.execPath, args: server(w.dir, [ROOT]) }
    // The address record lapses a day after its last publish without it (packages/mcp/README.md): both hosts carry it.
    expect(entry.args.at(-1)).toBe('--keep-alive-records')
    const group = [{ hooks: [hookOf(wakeCommand(w.dir))] }]
    expect(json(mcp)).toEqual({ mcpServers: { bag: entry } })
    expect(json(settings)).toEqual({ hooks: { SessionStart: group, Stop: group } })
    expect(first).toEqual({
      code: 0,
      out: [
        `wrote ${mcp}`,
        `  ${JSON.stringify({ bag: entry })}`,
        `wrote ${settings}`,
        `  ${JSON.stringify({ SessionStart: group, Stop: group })}`,
      ],
      err: [],
    })
    const [a, b] = [text(mcp), text(settings)]
    expect(await install(w, 'claude-code', '--trust-root', ROOT, '--project', w.project)).toEqual({
      code: 0,
      out: [`unchanged ${mcp}`, `unchanged ${settings}`, 'nothing to change'],
      err: [],
    })
    expect([text(mcp), text(settings)]).toEqual([a, b])
  })

  it('keeps every other key and hook, adds only the hook that is missing, and prints no key material', async () => {
    const w = await world()
    const mcp = join(w.project, '.mcp.json')
    const settings = join(w.project, '.claude', 'settings.json')
    const other = { command: 'node', args: ['other.js'] }
    writeFileSync(mcp, JSON.stringify({ note: 1, mcpServers: { other } }))
    mkdirSync(join(w.project, '.claude'))
    const mine = { hooks: [hookOf(wakeCommand(w.dir))] }
    const theirs = { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo hi' }] }
    writeFileSync(
      settings,
      JSON.stringify({
        permissions: { allow: ['Bash(ls)'] },
        hooks: { SessionStart: [theirs, mine], PreToolUse: [theirs] },
      }),
    )
    const got = await install(w, 'claude-code', '--project', w.project)
    expect(json(mcp)).toEqual({
      note: 1,
      mcpServers: { other, bag: { command: process.execPath, args: server(w.dir) } },
    })
    expect(json(settings)).toEqual({
      permissions: { allow: ['Bash(ls)'] },
      hooks: { SessionStart: [theirs, mine], PreToolUse: [theirs], Stop: [mine] },
    })
    expect(got.out[3]).toBe(`  ${JSON.stringify({ Stop: [mine] })}`)
    const keyFile = JSON.parse(text(join(w.dir, 'keys', 'bob.json'))) as Record<string, string>
    for (const secret of [keyFile.sign_seed, keyFile.seal_priv])
      expect(got.out.join('\n')).not.toContain(secret as string)
  })

  it('quotes a home with a space and a quote in the hook command, and keeps the path absolute', async () => {
    const w = await world("it's a home")
    await install(w, 'claude-code', '--project', w.project)
    const settings = json(join(w.project, '.claude', 'settings.json')) as {
      hooks: { Stop: [{ hooks: [{ command: string }] }] }
    }
    const quoted = `'${w.dir.replaceAll("'", "'\\''")}'`
    expect(settings.hooks.Stop[0].hooks[0].command).toBe(
      `${process.execPath} ${CLI_MAIN} wake-hook --as bob --dir ${quoted} --max 86000`,
    )
  })

  it("replaces an earlier install's hook (no --max, timeout 3600), prints it removed, and keeps the person's hooks", async () => {
    const w = await world()
    const settings = join(w.project, '.claude', 'settings.json')
    const before = earlierHook(earlierCommand(w.dir))
    const theirs = { hooks: [{ type: 'command', command: 'echo hi' }] }
    mkdirSync(join(w.project, '.claude'))
    const hooks = { SessionStart: [{ hooks: [before] }, theirs], Stop: [{ hooks: [before] }] }
    writeFileSync(settings, JSON.stringify({ hooks }))
    const got = await install(w, 'claude-code', '--project', w.project)
    const group = { hooks: [hookOf(wakeCommand(w.dir))] }
    expect(json(settings)).toEqual({ hooks: { SessionStart: [theirs, group], Stop: [group] } })
    expect(got.out.slice(2)).toEqual([
      `wrote ${settings}`,
      `  ${JSON.stringify({ removed: before.command, SessionStart: [group], Stop: [group] })}`,
    ])
    expect((await install(w, 'claude-code', '--project', w.project)).out.at(-1)).toBe('nothing to change')
  })

  it('refuses a bag entry with other settings, and files that are not the shape it merges into', async () => {
    const w = await world()
    const mcp = join(w.project, '.mcp.json')
    const settings = join(w.project, '.claude', 'settings.json')
    mkdirSync(join(w.project, '.claude'))
    const err = async () => (await install(w, 'claude-code', '--project', w.project)).err[0]
    writeFileSync(mcp, JSON.stringify({ mcpServers: { bag: { command: 'x', args: [] } } }))
    expect(await err()).toBe(
      'bag: exists: mcpServers.bag is there with other settings: edit or remove it first',
    )
    writeFileSync(mcp, '{ not json')
    expect(await err()).toBe(`bag: host-file-invalid: ${mcp} is not a JSON object`)
    writeFileSync(mcp, '[]')
    expect(await err()).toBe(`bag: host-file-invalid: ${mcp} is not a JSON object`)
    writeFileSync(mcp, JSON.stringify({ mcpServers: [] }))
    expect(await err()).toBe('bag: host-file-invalid: "mcpServers" is not a JSON object')
    writeFileSync(mcp, '{}')
    writeFileSync(settings, JSON.stringify({ hooks: { Stop: 'x' } }))
    expect(await err()).toBe('bag: host-file-invalid: hooks.Stop is not a list')
    expect(text(settings)).toBe(JSON.stringify({ hooks: { Stop: 'x' } }))
    // The refusal on settings.json came before any write: .mcp.json is as it was, not half installed.
    expect(text(mcp)).toBe('{}')
  })
})

describe('host install --rendezvous: the relay pairing codes meet at, passed to the server after --relay', () => {
  it('adds --rendezvous <url> to the claude-code and the codex mcp server args, and refuses one that is not a URL', async () => {
    const w = await world()
    const meet = ['--rendezvous', 'https://meet.example']
    expect((await install(w, 'claude-code', ...meet, '--project', w.project)).code).toBe(0)
    const want = server(w.dir)
    want.splice(want.indexOf(RELAY) + 1, 0, ...meet)
    const mcp = json(join(w.project, '.mcp.json')) as { mcpServers: { bag: { args: string[] } } }
    expect(mcp.mcpServers.bag.args).toEqual(want)
    const codex = await install(w, 'codex', '--user', '--mode', 'mcp', '--grant-caveat', CAVEAT, ...meet)
    expect(codex.code).toBe(0)
    const toml = text(join(w.userHome, '.codex', 'config.toml'))
    expect(toml).toContain(JSON.stringify(['--relay', RELAY, ...meet]).slice(1, -1))
    expect((await install(w, 'claude-code', '--rendezvous', 'meet', '--project', w.project)).err[0]).toBe(
      'bag: usage: "meet" is not a URL',
    )
  })
})

describe('host install codex --mode mcp: the table in ~/.codex/config.toml and the Stop hook in ~/.codex/hooks.json', () => {
  const table = (dir: string) =>
    `[mcp_servers.bag]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify(codexServer(dir, [ROOT]))}\n`
  const entry = (dir: string) => ({
    type: 'command',
    command: `${process.execPath} ${CLI_MAIN} wake-hook --as bob --session auto:codex --dir ${dir} --max 30 --no-idle-wake`,
    timeout: 60,
    statusMessage: 'bag: waiting for mail',
  })
  const NOTE =
    "mcp mode: one Codex session per server, named from Codex's session id at its first tool call; type y at the agent (ac login) for each session's grant. When a turn ends, a Stop hook waits up to 30 s for mail and continues the turn when one arrives; an idle session is not woken. Trust the hook in Codex with /hooks before it runs"
  const paths = (w: World): [string, string] => [
    join(w.userHome, '.codex', 'config.toml'),
    join(w.userHome, '.codex', 'hooks.json'),
  ]
  const mcpInstall = (w: World) =>
    install(w, 'codex', '--trust-root', ROOT, '--mode', 'mcp', '--grant-caveat', CAVEAT, '--user')

  it('writes the table 0600 and the Stop hook, prints both and a note on the wait and the trust step, and a second run changes nothing', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    const got = await mcpInstall(w)
    expect(text(file)).toBe(table(w.dir))
    expect(statSync(file).mode & 0o777).toBe(0o600)
    const stop = { Stop: [{ hooks: [entry(w.dir)] }] }
    expect(json(hooks)).toEqual({ hooks: stop })
    expect(got.out).toEqual([
      `wrote ${file}`,
      ...table(w.dir)
        .trimEnd()
        .split('\n')
        .map((l) => `  ${l}`),
      `wrote ${hooks}`,
      `  ${JSON.stringify(stop)}`,
      NOTE,
    ])
    const again = await mcpInstall(w)
    expect(again.out).toEqual([`unchanged ${file}`, `unchanged ${hooks}`, 'nothing to change', NOTE])
    expect(again.out.join('\n')).not.toContain('codex exec')
    expect(text(file)).toBe(table(w.dir))
    expect(json(hooks)).toEqual({ hooks: stop })
  })

  it('writes --session auto:codex with every --grant-caveat in order, and neither --as nor --keep-alive-records, and the Stop hook names auto:codex', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    await install(w, 'codex', '--mode', 'mcp', '--user', '--grant-caveat', 'a', '--grant-caveat', 'b=c')
    const args = JSON.parse(text(file).split('\n')[2]?.slice('args = '.length) as string) as string[]
    expect(args).toEqual(codexServer(w.dir, [], ['a', 'b=c']))
    expect(args).not.toContain('--as')
    expect(args).not.toContain('--keep-alive-records')
    expect(json(hooks)).toEqual({ hooks: { Stop: [{ hooks: [entry(w.dir)] }] } })
  })

  it('refuses --mode mcp without --grant-caveat, naming the grant, and writes neither file', async () => {
    const w = await world()
    const got = await install(w, 'codex', '--trust-root', ROOT, '--mode', 'mcp', '--user')
    expect([got.code, got.err[0]]).toEqual([
      1,
      'bag: usage: codex --mode mcp needs --grant-caveat <caveat>: the session asks the agent for a grant',
    ])
    expect(existsSync(join(w.userHome, '.codex'))).toBe(false)
  })

  it('merges the Stop entry into a hooks.json that has other keys and events, and a second run leaves it as it is', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    mkdirSync(join(w.userHome, '.codex'))
    const other = { type: 'command', command: 'echo other' }
    const before = {
      description: 'mine',
      hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [other] }], Stop: [{ hooks: [other] }] },
    }
    writeFileSync(hooks, JSON.stringify(before))
    await mcpInstall(w)
    const want = {
      ...before,
      hooks: { ...before.hooks, Stop: [{ hooks: [other] }, { hooks: [entry(w.dir)] }] },
    }
    expect(json(hooks)).toEqual(want)
    const again = await mcpInstall(w)
    expect(again.out.slice(0, 3)).toEqual([`unchanged ${file}`, `unchanged ${hooks}`, 'nothing to change'])
    expect(json(hooks)).toEqual(want)
  })

  it('writes the table when the Stop entry is already there, and says the hooks file is unchanged without saying nothing changed', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(hooks, JSON.stringify({ hooks: { Stop: [{ hooks: [entry(w.dir)] }] } }))
    const got = await mcpInstall(w)
    expect(got.out).toContain(`unchanged ${hooks}`)
    expect(got.out).toContain(`wrote ${file}`)
    expect(got.out).not.toContain('nothing to change')
    expect(text(file)).toBe(table(w.dir))
  })

  it('refuses a hooks.Stop that is not a list, or a hooks.json that is not an object, before it writes config.toml', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(hooks, JSON.stringify({ hooks: { Stop: 'x' } }))
    expect((await mcpInstall(w)).err[0]).toBe('bag: host-file-invalid: hooks.Stop is not a list')
    expect(existsSync(file)).toBe(false)
    expect(text(hooks)).toBe(JSON.stringify({ hooks: { Stop: 'x' } }))
    writeFileSync(hooks, '[]')
    expect((await mcpInstall(w)).err[0]).toBe(`bag: host-file-invalid: ${hooks} is not a JSON object`)
    expect(existsSync(file)).toBe(false)
  })

  it('refuses another bag table before it writes hooks.json', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(file, '[mcp_servers.bag]\ncommand = "other"\n')
    expect((await mcpInstall(w)).err[0]).toContain('with other settings')
    expect(existsSync(hooks)).toBe(false)
  })

  it('appends to a config that has other content (no final newline there), and refuses another bag table', async () => {
    const w = await world()
    const file = join(w.userHome, '.codex', 'config.toml')
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(file, 'model = "x"')
    await install(w, 'codex', '--trust-root', ROOT, '--mode', 'mcp', '--grant-caveat', CAVEAT, '--user')
    expect(text(file)).toBe(`model = "x"\n\n${table(w.dir)}`)
    writeFileSync(file, '[mcp_servers.bag]\ncommand = "other"\n')
    expect(
      (await install(w, 'codex', '--trust-root', ROOT, '--mode', 'mcp', '--grant-caveat', CAVEAT, '--user'))
        .err[0],
    ).toBe(`bag: exists: ${file} has [mcp_servers.bag] with other settings: edit or remove it first`)
    expect(text(file)).toBe('[mcp_servers.bag]\ncommand = "other"\n')
  })

  it('refuses a table written with spaces or a quoted name as one that is there, and the table is not written over it', async () => {
    const w = await world()
    const file = join(w.userHome, '.codex', 'config.toml')
    mkdirSync(join(w.userHome, '.codex'))
    for (const header of [
      '[ mcp_servers.bag ]',
      '[mcp_servers."bag"]',
      '# [mcp_servers.bag]',
      'mcp_servers.bag.command = "x"',
      '[mcp_servers]\nbag = { command = "x" }',
      '[mcp_servers.bag.env]',
      '[mcp_servers.bag]',
      '[ mcp_servers."bag" ]',
      '["mcp_servers"."bag"]',
      `'mcp_servers'.'bag'.command = "x"`,
      'mcp_servers = { bag = { command = "x" } }',
      'mcp_servers={bag={command="x"}}',
      'mcp_servers = { "bag" = { command = "x" } }',
      `mcp_servers = { 'bag' = { command = "x" } }`,
      'mcp_servers = { other = { command = "y" }, bag = { command = "x" } }',
      '"mcp_servers" = { bag = { command = "x" } }',
    ]) {
      writeFileSync(file, `${header}\ncommand = "other"\n`)
      expect(
        (await install(w, 'codex', '--mode', 'mcp', '--grant-caveat', CAVEAT, '--user')).err[0],
      ).toContain('with other settings')
    }
  })

  it('installs beside an inline server whose name only holds bag, as plugins/codex/install.sh does', async () => {
    const w = await world()
    const file = join(w.userHome, '.codex', 'config.toml')
    mkdirSync(join(w.userHome, '.codex'))
    for (const line of [
      'mcp_servers = { handbag = { command = "x" } }',
      'mcp_servers = { airbag = { command = "x" } }',
      'mcp_servers = { bagx = { command = "x" } }',
      'mcp_servers = { "handbag" = { command = "x" } }',
      'model = "bag"',
    ]) {
      writeFileSync(file, `${line}\n`)
      expect((await mcpInstall(w)).err, line).toEqual([])
      expect(text(file), line).toBe(`${line}\n\n${table(w.dir)}`)
    }
  })

  it('installs beside a table or value whose name only starts with bag', async () => {
    const w = await world()
    const file = join(w.userHome, '.codex', 'config.toml')
    mkdirSync(join(w.userHome, '.codex'))
    const old = '[mcp_servers.bagx]\ncommand = "other"\nmodel = "bagx"\n'
    writeFileSync(file, old)
    expect((await mcpInstall(w)).err).toEqual([])
    expect(text(file)).toBe(`${old}\n${table(w.dir)}`)
  })

  it('refuses the bag table plugins/codex/install.sh writes, by its name, and writes neither file', async () => {
    const w = await world()
    const [file, hooks] = paths(w)
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(file, '[mcp_servers.bag]\ncommand = "other"\n')
    expect((await mcpInstall(w)).err[0]).toBe(
      `bag: exists: ${file} has [mcp_servers.bag] with other settings: edit or remove it first`,
    )
    expect(text(file)).toBe('[mcp_servers.bag]\ncommand = "other"\n')
    expect(existsSync(hooks)).toBe(false)
  })

  it('needs HOME for --user', async () => {
    const w = await world()
    const io = testIo(new MemoryRelay(), {})
    const got = await cli(
      io,
      'host',
      'install',
      'codex',
      '--as',
      'bob',
      '--dir',
      w.dir,
      '--relay',
      RELAY,
      '--mode',
      'mcp',
      '--grant-caveat',
      CAVEAT,
      '--user',
    )
    expect(got.err[0]).toBe('bag: usage: no HOME: codex --user writes $HOME/.codex/config.toml')
  })
})

describe('host install codex --mode worker, the default: the worker line, and nothing written', () => {
  it('prints the inbox --watch --exec line with every relay and trust root, by default and with --mode worker, and writes no file', async () => {
    const w = await world()
    const line = `the worker path (no MCP table written: one receiver per identity): ${process.execPath} ${CLI_MAIN} inbox --watch --as bob --relay ${RELAY} --relay http://127.0.0.1:10 --dir ${w.dir} --trust-root ${ROOT} --exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'`
    const args = ['--relay', 'http://127.0.0.1:10', '--trust-root', ROOT, '--user']
    expect(await install(w, 'codex', ...args)).toEqual({ code: 0, out: [line], err: [] })
    expect(await install(w, 'codex', '--mode', 'worker', ...args)).toEqual({ code: 0, out: [line], err: [] })
    expect(existsSync(join(w.userHome, '.codex'))).toBe(false)
  })

  it('leaves an existing config.toml alone, and needs no HOME', async () => {
    const w = await world()
    const file = join(w.userHome, '.codex', 'config.toml')
    mkdirSync(join(w.userHome, '.codex'))
    writeFileSync(file, '[mcp_servers.bag]\ncommand = "other"\n')
    expect((await install(w, 'codex', '--user')).code).toBe(0)
    expect(text(file)).toBe('[mcp_servers.bag]\ncommand = "other"\n')
    const io = testIo(new MemoryRelay(), {})
    const got = await cli(
      io,
      'host',
      'install',
      'codex',
      '--as',
      'bob',
      '--dir',
      w.dir,
      '--relay',
      RELAY,
      '--user',
    )
    expect(got.code).toBe(0)
  })

  it('refuses --grant-caveat for the worker mode (by default and named) and for claude-code, and writes nothing', async () => {
    const w = await world()
    const only = 'bag: usage: --grant-caveat is for codex --mode mcp only'
    expect((await install(w, 'codex', '--user', '--grant-caveat', CAVEAT)).err[0]).toBe(only)
    expect((await install(w, 'codex', '--mode', 'worker', '--user', '--grant-caveat', CAVEAT)).err[0]).toBe(
      only,
    )
    expect((await install(w, 'claude-code', '--project', w.project, '--grant-caveat', CAVEAT)).err[0]).toBe(
      only,
    )
    expect(existsSync(join(w.project, '.mcp.json'))).toBe(false)
    expect(existsSync(join(w.userHome, '.codex'))).toBe(false)
  })

  it('refuses a mode that is not mcp or worker, and --mode for claude-code', async () => {
    const w = await world()
    expect((await install(w, 'codex', '--mode', 'both', '--user')).err[0]).toBe(
      'bag: usage: --mode is mcp or worker, not "both"',
    )
    expect((await install(w, 'claude-code', '--mode', 'mcp', '--project', w.project)).err[0]).toBe(
      'bag: usage: --mode is for codex only',
    )
    expect(existsSync(join(w.project, '.mcp.json'))).toBe(false)
  })
})

describe('host install: what it refuses', () => {
  it('names the two hosts for any other, and takes only install', async () => {
    const w = await world()
    expect((await install(w, 'cursor', '--user')).err[0]).toBe(
      'bag: usage: no host "cursor": the hosts are claude-code and codex',
    )
    expect((await cli(w.io, 'host', 'uninstall', 'codex', '--as', 'bob')).err[0]).toBe(
      'bag: usage: host takes install or remove, not "uninstall"',
    )
    expect((await cli(w.io, 'host', 'remove', 'codex', '--as', 'bob')).err[0]).toBe(
      'bag: usage: host remove takes claude-code --project <dir> --identities <file> --label <label>',
    )
  })

  it('refuses a scope the repo does not document: claude-code --user, codex --project', async () => {
    const w = await world()
    expect((await install(w, 'claude-code', '--user')).err[0]).toBe(
      'bag: usage: claude-code --user is not documented yet: use --project <dir> (.mcp.json, .claude/settings.json)',
    )
    expect((await install(w, 'codex', '--project', w.project)).err[0]).toBe(
      'bag: usage: codex --project is not documented yet: use --user (~/.codex/config.toml)',
    )
    expect(existsSync(join(w.userHome, '.codex'))).toBe(false)
  })

  it('refuses a --trust-root that is neither an address nor a domain, and writes nothing', async () => {
    const w = await world()
    const got = await install(w, 'claude-code', '--trust-root', 'not a root!', '--project', w.project)
    expect(got.err[0]).toBe('bag: usage: --trust-root "not a root!" is neither an address nor a domain')
    expect(existsSync(join(w.project, '.mcp.json'))).toBe(false)
    const ok = await install(w, 'claude-code', '--trust-root', 'acme.example', '--project', w.project)
    expect(ok.code).toBe(0)
  })

  it('wants exactly one of --project and --user, a --relay, a project directory that exists, and an identity', async () => {
    const w = await world()
    const err = async (...a: string[]) => (await cli(w.io, 'host', 'install', ...a)).err[0]
    expect(await err('codex', '--as', 'bob', '--dir', w.dir, '--relay', RELAY)).toBe(
      'bag: usage: give one of --project <dir> or --user',
    )
    expect(
      await err('codex', '--as', 'bob', '--dir', w.dir, '--relay', RELAY, '--user', '--project', w.project),
    ).toBe('bag: usage: give one of --project <dir> or --user')
    expect(await err('codex', '--as', 'bob', '--dir', w.dir, '--user')).toBe(
      'bag: usage: --relay <url> is required, at least once',
    )
    expect(await err('codex', '--as', 'bob', '--dir', w.dir, '--relay', 'ftp://x', '--user')).toContain(
      'is not an http or https URL',
    )
    const missing = join(w.project, 'nope')
    expect(
      await err('claude-code', '--as', 'bob', '--dir', w.dir, '--relay', RELAY, '--project', missing),
    ).toBe(`bag: ENOENT: no project directory ${missing}`)
    expect(await err('codex', '--as', 'nobody', '--dir', w.dir, '--relay', RELAY, '--user')).toMatch(
      /^bag: ENOENT: /,
    )
    expect(await err('codex', '--dir', w.dir)).toBe('bag: usage: --as is required')
    expect(await err('codex')).toBe('bag: usage: --as is required')
  })
})

describe('host install claude-code --identities: many identities in one server', () => {
  const RESTART = 'the change takes effect when Claude Code starts the server again'
  const MEET = 'http://127.0.0.1:8'

  /** A world with a second identity, carol, in a home of her own, and the identities file outside the project. */
  async function two(): Promise<World & { carol: string; file: string; mcp: string; settings: string }> {
    const w = await world()
    const carol = join(w.userHome, 'carol-home')
    expect((await cli(w.io, 'keygen', 'carol', '--dir', carol)).code).toBe(0)
    const [mcp, settings] = [join(w.project, '.mcp.json'), join(w.project, '.claude', 'settings.json')]
    return { ...w, carol, file: join(w.userHome, '.bag-identities', 'project.json'), mcp, settings }
  }
  type Two = Awaited<ReturnType<typeof two>>
  const multi = (w: Two, ...more: string[]) =>
    cli(
      w.io,
      'host',
      'install',
      'claude-code',
      '--project',
      w.project,
      '--identities',
      w.file,
      '--relay',
      RELAY,
      ...more,
    )
  const asBob = (w: Two, ...more: string[]) => multi(w, '--as', 'bob', '--dir', w.dir, ...more)
  const asCarol = (w: Two, ...more: string[]) =>
    multi(w, '--as', 'carol', '--dir', w.carol, '--label', 'lab', ...more)
  const removing = (w: Two, ...more: string[]) =>
    cli(w.io, 'host', 'remove', 'claude-code', '--project', w.project, '--identities', w.file, ...more)
  const bob = (w: Two, more: object = {}) => ({
    label: 'bob',
    key: 'bob',
    home: w.dir,
    relays: [RELAY],
    ...more,
    keep_alive_records: true,
  })
  const lab = (w: Two) => ({
    label: 'lab',
    key: 'carol',
    home: w.carol,
    relays: [RELAY],
    keep_alive_records: true,
  })
  const entryOf = (w: Two) => ({ command: process.execPath, args: [MCP_MAIN, '--identities', w.file] })
  const multiHook = (w: Two) =>
    hookOf(`${process.execPath} ${CLI_MAIN} wake-hook --identities ${w.file} --max 86000`)
  const three = (w: Two): string[] => [w.file, w.mcp, w.settings].map((f) => (existsSync(f) ? text(f) : ''))

  it('writes the file 0600 in a 0700 directory, the --identities server entry and hook; a re-run changes nothing', async () => {
    const w = await two()
    const got = await asBob(w, '--rendezvous', MEET, '--trust-root', ROOT)
    const me = {
      label: 'bob',
      key: 'bob',
      home: w.dir,
      relays: [RELAY],
      rendezvous: MEET,
      trust_roots: [ROOT],
      keep_alive_records: true,
    }
    expect(json(w.file)).toEqual({ version: 1, identities: [me] })
    expect(Object.keys((json(w.file) as { identities: object[] }).identities[0] ?? {})).toEqual(
      Object.keys(me),
    )
    expect(text(w.file)).toBe(`${JSON.stringify({ version: 1, identities: [me] }, null, 2)}\n`)
    expect([statSync(w.file).mode & 0o777, statSync(join(w.file, '..')).mode & 0o777]).toEqual([0o600, 0o700])
    const group = [{ hooks: [multiHook(w)] }]
    expect(json(w.mcp)).toEqual({ mcpServers: { bag: entryOf(w) } })
    expect(json(w.settings)).toEqual({ hooks: { SessionStart: group, Stop: group } })
    expect(got).toEqual({
      code: 0,
      out: [
        `wrote ${w.file}`,
        `  ${JSON.stringify([me])}`,
        `wrote ${w.mcp}`,
        `  ${JSON.stringify({ bag: entryOf(w) })}`,
        `wrote ${w.settings}`,
        `  ${JSON.stringify({ SessionStart: group, Stop: group })}`,
        RESTART,
      ],
      err: [],
    })
    expect((await asBob(w, '--rendezvous', MEET, '--trust-root', ROOT)).out).toEqual([
      `unchanged ${w.file}`,
      `unchanged ${w.mcp}`,
      `unchanged ${w.settings}`,
      'nothing to change',
    ])
  })

  it('adds a second identity under its --label to the file only; the server entry and the hook stay', async () => {
    const w = await two()
    expect((await asBob(w)).code).toBe(0)
    const [mcp, settings] = [text(w.mcp), text(w.settings)]
    expect((await asCarol(w)).out).toEqual([
      `wrote ${w.file}`,
      `  ${JSON.stringify([lab(w)])}`,
      `unchanged ${w.mcp}`,
      `unchanged ${w.settings}`,
      RESTART,
    ])
    expect(json(w.file)).toEqual({ version: 1, identities: [bob(w), lab(w)] })
    expect([text(w.mcp), text(w.settings)]).toEqual([mcp, settings])
  })

  it('refuses, leaving all three files as they were: a label with other settings, a shared home, a file open to others', async () => {
    const w = await two()
    expect((await asBob(w)).code).toBe(0)
    const before = three(w)
    const other = await asBob(w, '--relay', 'http://127.0.0.1:7')
    expect([other.code, other.err[0]]).toEqual([
      1,
      'bag: exists: identity bob is in the file with other settings: edit or remove it first',
    ])
    expect((await cli(w.io, 'keygen', 'dave', '--dir', w.dir)).code).toBe(0)
    const shared = await multi(w, '--as', 'dave', '--dir', w.dir)
    expect(shared.err[0]).toBe(
      `bag: home-shared: identities[1].home ${w.dir} is another identity's: one home per identity`,
    )
    chmodSync(w.file, 0o644)
    expect((await asCarol(w)).err[0]).toBe(
      `bag: identities-invalid: ${w.file} is open to the group or others: chmod 600 it`,
    )
    chmodSync(w.file, 0o600)
    expect(three(w)).toEqual(before)
  })

  it('refuses a file in the project, a relative path, codex, a label that is not one, and --label without --identities', async () => {
    const w = await two()
    const inside = join(w.project, 'ids', 'p.json')
    const err = async (...a: string[]) => (await cli(w.io, 'host', 'install', ...a)).err[0]
    const base = ['--as', 'bob', '--dir', w.dir, '--relay', RELAY]
    expect(await err('claude-code', ...base, '--project', w.project, '--identities', inside)).toBe(
      `bag: identities-in-project: ${inside} is in the project ${w.project}, which is often committed, and the file links every identity it lists: keep it outside`,
    )
    expect(await err('claude-code', ...base, '--project', w.project, '--identities', w.project)).toMatch(
      /^bag: identities-in-project: /,
    )
    expect(await err('claude-code', ...base, '--project', w.project, '--identities', 'p.json')).toBe(
      'bag: usage: --identities takes an absolute path, not "p.json"',
    )
    expect(await err('codex', ...base, '--user', '--identities', w.file)).toBe(
      'bag: usage: --identities with codex is not documented yet',
    )
    expect((await asBob(w, '--label', 'Bob')).err[0]).toBe(
      'bag: usage: --label is ^[a-z0-9][a-z0-9_-]{0,31}$, not "Bob"',
    )
    expect(await err('claude-code', ...base, '--project', w.project, '--label', 'lab')).toBe(
      'bag: usage: --label is for --identities only',
    )
    expect(await err('claude-code', '--project', w.project, '--identities', w.file, '--relay', RELAY)).toBe(
      'bag: usage: --as is required',
    )
    expect([existsSync(w.file), existsSync(w.mcp), existsSync(join(w.project, 'ids'))]).toEqual([
      false,
      false,
      false,
    ])
  })

  it('migrates the exact single-identity wiring: its identity first and the default, the entry and its hook groups replaced', async () => {
    const w = await two()
    expect((await install(w, 'claude-code', '--rendezvous', MEET, '--project', w.project)).code).toBe(0)
    const old = hookOf(wakeCommand(w.dir))
    const mine = { hooks: [{ type: 'command', command: 'echo mine' }] }
    // Stop's old group removed by hand: only SessionStart has one to replace; the person's own group stays in both.
    writeFileSync(
      w.settings,
      JSON.stringify({ hooks: { SessionStart: [{ hooks: [old] }, mine], Stop: [mine] } }),
    )
    const got = await asCarol(w)
    const group = { hooks: [multiHook(w)] }
    expect(json(w.file)).toEqual({
      version: 1,
      default: 'bob',
      identities: [bob(w, { rendezvous: MEET }), lab(w)],
    })
    expect(json(w.mcp)).toEqual({ mcpServers: { bag: entryOf(w) } })
    expect(json(w.settings)).toEqual({ hooks: { SessionStart: [mine, group], Stop: [mine, group] } })
    expect(got.out).toEqual([
      `wrote ${w.file}`,
      `  ${JSON.stringify([bob(w, { rendezvous: MEET }), lab(w)])}`,
      `wrote ${w.mcp}`,
      `  ${JSON.stringify({ bag: entryOf(w) })}`,
      `wrote ${w.settings}`,
      `  ${JSON.stringify({ removed: old.command, SessionStart: [group], Stop: [group] })}`,
      RESTART,
    ])
  })

  it("replaces an earlier install's --identities hook, and the migrated single hook in both its forms", async () => {
    const w = await two()
    expect((await install(w, 'claude-code', '--project', w.project)).code).toBe(0)
    const single = earlierHook(earlierCommand(w.dir))
    const many = earlierHook(`${process.execPath} ${CLI_MAIN} wake-hook --identities ${w.file}`)
    const now = hookOf(wakeCommand(w.dir))
    const hooks = { SessionStart: [{ hooks: [single] }], Stop: [{ hooks: [many] }, { hooks: [now] }] }
    writeFileSync(w.settings, JSON.stringify({ hooks }))
    const got = await asCarol(w)
    const group = { hooks: [multiHook(w)] }
    expect(json(w.settings)).toEqual({ hooks: { SessionStart: [group], Stop: [group] } })
    const removed = [single.command, many.command, now.command]
    expect(got.out.at(-2)).toBe(`  ${JSON.stringify({ removed, SessionStart: [group], Stop: [group] })}`)
  })

  it('migrates with trust roots into a file that already holds the old identity and a default, and with no settings file', async () => {
    const w = await two()
    expect((await install(w, 'claude-code', '--trust-root', ROOT, '--project', w.project)).code).toBe(0)
    renameSync(w.settings, `${w.settings}.gone`)
    mkdirSync(join(w.file, '..'), { recursive: true, mode: 0o700 })
    const held = { version: 1, default: 'bob', identities: [bob(w, { trust_roots: [ROOT] })] }
    writeFileSync(w.file, JSON.stringify(held), { mode: 0o600 })
    expect((await asCarol(w)).code).toBe(0)
    expect(json(w.file)).toEqual({ ...held, identities: [...held.identities, lab(w)] })
    const group = [{ hooks: [multiHook(w)] }]
    expect(json(w.settings)).toEqual({ hooks: { SessionStart: group, Stop: group } })
  })

  it('migrates a wiring whose one identity is the one added: the file holds it alone, as the default', async () => {
    const w = await two()
    expect((await install(w, 'claude-code', '--project', w.project)).code).toBe(0)
    expect((await asBob(w)).code).toBe(0)
    expect(json(w.file)).toEqual({ version: 1, default: 'bob', identities: [bob(w)] })
  })

  it('refuses exists for a bag entry of any other form, and changes nothing', async () => {
    const w = await two()
    const forms = [
      { command: process.execPath, args: [...server(w.dir), '--honor', ROOT] },
      { command: '/usr/bin/node', args: server(w.dir) },
      { command: process.execPath, args: [1] },
      { command: process.execPath, args: [MCP_MAIN] },
      { command: process.execPath },
    ]
    for (const entry of forms) {
      writeFileSync(w.mcp, JSON.stringify({ mcpServers: { bag: entry } }))
      expect((await asCarol(w)).err[0]).toBe(
        'bag: exists: mcpServers.bag is there with other settings: edit or remove it first',
      )
      expect([existsSync(w.file), existsSync(w.settings)]).toEqual([false, false])
    }
  })

  it('host remove takes an identity out of the file, and default with it; .mcp.json and settings.json stay', async () => {
    const w = await two()
    expect((await install(w, 'claude-code', '--project', w.project)).code).toBe(0)
    expect((await asCarol(w)).code).toBe(0)
    expect((await cli(w.io, 'keygen', 'dave', '--dir', join(w.userHome, 'dave-home'))).code).toBe(0)
    expect((await multi(w, '--as', 'dave', '--dir', join(w.userHome, 'dave-home'))).code).toBe(0)
    const [mcp, settings] = [text(w.mcp), text(w.settings)]
    expect(await removing(w, '--label', 'dave')).toEqual({
      code: 0,
      out: [`wrote ${w.file}`, '  removed dave', RESTART],
      err: [],
    })
    expect(json(w.file)).toEqual({ version: 1, default: 'bob', identities: [bob(w), lab(w)] })
    expect((await removing(w, '--label', 'bob')).out).toEqual([
      `wrote ${w.file}`,
      '  removed bob',
      'default bob dropped: lab is the default now',
      RESTART,
    ])
    expect(json(w.file)).toEqual({ version: 1, identities: [lab(w)] })
    expect(statSync(w.file).mode & 0o777).toBe(0o600)
    expect([text(w.mcp), text(w.settings)]).toEqual([mcp, settings])
    expect(existsSync(join(w.dir, 'keys', 'bob.json'))).toBe(true)
  })

  it('host remove refuses the last identity, an unknown label, other flags, a missing --label, and a file in the project', async () => {
    const w = await two()
    expect((await asBob(w)).code).toBe(0)
    const before = three(w)
    expect((await removing(w, '--label', 'bob')).err[0]).toBe(
      'bag: last-identity: bob is the last identity: keep one, or remove the server entry by hand',
    )
    expect((await removing(w, '--label', 'lab')).err[0]).toBe(
      'bag: unknown-identity: no identity lab in the file; its labels: bob',
    )
    expect((await removing(w, '--label', 'bob', '--as', 'bob')).err[0]).toBe(
      'bag: usage: host remove takes only --project, --identities and --label',
    )
    expect((await removing(w)).err[0]).toBe(
      'bag: usage: host remove takes claude-code --project <dir> --identities <file> --label <label>',
    )
    const inside = join(w.project, 'p.json')
    const got = await cli(
      w.io,
      'host',
      'remove',
      'claude-code',
      '--project',
      w.project,
      '--identities',
      inside,
      '--label',
      'bob',
    )
    expect(got.err[0]).toMatch(/^bag: identities-in-project: /)
    expect(three(w)).toEqual(before)
  })
})
