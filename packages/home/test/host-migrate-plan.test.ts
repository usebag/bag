import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  type Build,
  type HostProcess,
  type MigrateInput,
  migrate,
  readIdentities,
  saveIdentities,
  undo,
} from '../src/index.ts'
import { type Answer, fakeIo, folder, homeWith } from './support.ts'

// host migrate's plan over every place a per-folder entry can be: a folder given, one an install's settings name, one
// a server's lock names, an omp folder, the Codex table; the settings an install page wrote, the trust roots shown,
// entries the service's file holds already, proposals there already, and the entries it leaves.

const [R1, R2, R3] = ['https://r1.example', 'https://r2.example', 'https://r3.example']
const proc: HostProcess = { node: '/n/node', execPath: '/n/node', pid: 4242, uid: process.getuid?.() }
const build: Build = {
  packaged: false,
  version: 'source',
  cli: '/b/bag.js',
  mcp: '/b/bag-mcp.js',
  omp: '/b/bag-omp-wake.js',
  shim: '/b/bag-shim.js',
}
// JSON.parse's own type, so a test reads into the document without a cast at each step.
const json = (file: string) => JSON.parse(readFileSync(file, 'utf8'))
const put = (file: string, doc: unknown) => writeFileSync(file, JSON.stringify(doc))

/** A home with jane, kim and amy, and every kind of entry host migrate finds or leaves. */
function world(answer: Answer = true) {
  const { home } = homeWith('jane', 'kim', 'amy')
  const HOME = folder()
  // A: a folder given, jane's source entry with every setting a per-folder server takes, and her wake hooks.
  const A = folder()
  const janeArgs = [
    '/repo/packages/mcp/src/main.ts',
    '--as',
    'jane',
    '--relay',
    R1,
    '--rendezvous',
    R2,
    '--trust-root',
    'example.com',
    '--honor',
    'coding',
    '--accept-type',
    'note',
    '--allow-delegate',
    '--policy',
    '/p.json',
    '--members',
    '/m.json',
    '--dir',
    home,
  ]
  put(join(A, '.mcp.json'), { mcpServers: { bag: { args: janeArgs }, other: {} } })
  mkdirSync(join(A, '.claude'))
  const wake = `node /c wake-hook --as jane --dir ${home}`
  put(join(A, '.claude', 'settings.json'), {
    hooks: {
      SessionStart: [{ hooks: [{ command: `${wake} --max 86000` }, { command: 'other' }] }, { hooks: 'x' }],
      Stop: [{ hooks: [{ command: wake }] }],
      Note: 'x',
    },
  })
  // B: named by jane's install settings (WORK), which also name other relays and no rendezvous; kim's omp entry there.
  const B = folder()
  mkdirSync(join(home, 'install'))
  writeFileSync(join(home, 'install', 'jane.env'), `WORK="${B}"\nRELAYS="${R3}"\n`)
  mkdirSync(join(B, '.omp', 'hooks', 'pre'), { recursive: true })
  const kimArgs = ['/x/bag-mcp.js', '--as', 'kim', '--relay', R1, '--dir', home, '--keep-alive-records']
  put(join(B, '.omp', 'mcp.json'), { mcpServers: { bag: { args: kimArgs } } })
  const wakeEntry = join(folder(), 'bag-omp-wake.js')
  writeFileSync(wakeEntry, '// wake')
  symlinkSync(wakeEntry, join(B, '.omp', 'hooks', 'pre', 'bag-wake.js'))
  // C: named by a server's lock; its entry is of an identity the home lacks. Two more locks name no folder.
  const C = folder()
  for (const n of ['s1', 's2', 's3']) mkdirSync(join(home, 'state', n), { recursive: true })
  put(join(home, 'state', 's1', 'mcp.lock'), { cwd: C })
  put(join(home, 'state', 's2', 'mcp.lock'), { cwd: 5 })
  put(join(C, '.mcp.json'), {
    mcpServers: { bag: { args: ['/x/bag-mcp.js', '--as', 'zed', '--dir', home] } },
  })
  // Entries of other forms, each left: no args, another program, a session, no --dir, an argument that is no string.
  const others = [
    {},
    { args: ['/x/other.js', '--as', 'jane', '--dir', home] },
    { args: ['/x/bag-mcp.js', '--session', 'auto:codex', '--dir', home] },
    { args: ['/x/bag-mcp.js', '--as', 'jane'] },
    { args: [1] },
  ].map((bag) => {
    const dir = folder()
    put(join(dir, '.mcp.json'), { mcpServers: { bag } })
    return dir
  })
  // The Codex table of amy, and its Stop hook beside another.
  mkdirSync(join(HOME, '.codex'))
  const config = join(HOME, '.codex', 'config.toml')
  const table = `[mcp_servers.bag]\ncommand = "/n"\nargs = ["/x/bag-mcp.js", "--as", "amy", "--relay", "${R1}", "--dir", "${home}"]\n`
  writeFileSync(config, table)
  const codexHooks = join(HOME, '.codex', 'hooks.json')
  put(codexHooks, {
    hooks: {
      Stop: [
        { hooks: [{ command: `node /c wake-hook --as amy --dir ${home} --max 30 --no-idle-wake` }] },
        { hooks: [{ command: 'other' }] },
      ],
    },
  })
  // The service's file holds kim with other relays and amy with a rendezvous; a proposal for kim's omp folder exists.
  const idFile = join(home, 'identities.json')
  saveIdentities(idFile, {
    version: 1,
    identities: [
      { label: 'kim', home, relays: [R2] },
      { label: 'amy', home, relays: [R1], rendezvous: R2 },
    ],
  })
  const idText = readFileSync(idFile, 'utf8')
  const [realA, realB] = [realpathSync(A), realpathSync(B)]
  put(join(home, 'proposals.json'), {
    version: 1,
    proposals: [{ folder: realB, host: 'omp', label: 'kim', from: 'earlier' }],
  })
  const io = fakeIo({ answer, env: { HOME } })
  const input: MigrateInput = {
    home,
    given: [A, ...others, join(folder(), 'gone')],
    sandbox: false,
    build,
    proc,
  }
  return {
    ...{ home, HOME, A, B, C, realA, realB, config, table, codexHooks, idFile, idText, wakeEntry, io, input },
    run: () => migrate(io, input),
  }
}

describe('migrate: the plan', () => {
  it('names each entry found with its settings and warnings, every edit, and every entry it leaves', async () => {
    const w = world(false)
    await expect(w.run()).rejects.toThrow('declined: nothing was changed')
    const q = (w.io.asked[0] ?? '').split('\n')
    expect(q[0]).toMatch(new RegExp(`^migrate 3 per-folder bag entries of ${w.home} to the bag service`))
    expect(q).toContain(`  claude-code ${w.realA}: jane, proposed there, never bound without your word`)
    expect(q).toContain(`    from ${join(w.realA, '.mcp.json')}: relays ${R3}, trust roots example.com`)
    expect(q).toContain(`    WARNING: relays ${R1} differ from install/jane.env (${R3}), which is used`)
    expect(q).toContain(`    WARNING: rendezvous ${R2} differs from install/jane.env (none), which is used`)
    expect(q).toContain('    WARNING: trusts example.com: check that these roots are yours')
    expect(q).toContain(`  omp ${w.realB}: kim, proposed there, never bound without your word`)
    expect(q).toContain(
      `    WARNING: ${w.idFile} holds kim with other settings (relays ${R2}), which are kept`,
    )
    expect(q).toContain('  codex for this user: amy, proposed there, never bound without your word')
    expect(q).toContain(`    from ${w.config}: relays ${R1}, trust roots none`)
    expect(q).toContain(
      `    WARNING: ${w.idFile} holds amy with other settings (relays ${R1}), which are kept`,
    )
    expect(q).toContain(`  edit ${join(w.home, 'proposals.json')}: proposed jane (claude-code), amy (codex)`)
    expect(q).toContain(
      `  left ${join(realpathSync(w.C), '.mcp.json')}: zed is not an identity of ${w.home}: left as it is`,
    )
    expect(q.filter((l) => l.includes(': not a per-folder bag server of one identity'))).toHaveLength(5)
    expect(q.at(-1)).toBe('migrate?')
    expect(readFileSync(w.config, 'utf8')).toBe(w.table)
  })

  it('a yes moves each entry: the hooks of jane, the omp link, the Codex table and its hook; the undo puts all back', async () => {
    const w = world()
    await w.run()
    expect(json(join(w.A, '.mcp.json'))).toEqual({ mcpServers: { other: {} } })
    expect(json(join(w.A, '.claude', 'settings.json')).hooks).toEqual({
      SessionStart: [{ hooks: [{ command: 'other' }] }, { hooks: 'x' }],
      Note: 'x',
    })
    expect(json(join(w.B, '.omp', 'mcp.json'))).toEqual({ mcpServers: {} })
    expect(() => lstatSync(join(w.B, '.omp', 'hooks', 'pre', 'bag-wake.js'))).toThrow()
    expect(existsSync(w.wakeEntry)).toBe(true)
    const config = readFileSync(w.config, 'utf8')
    expect(config).toContain('/b/bag-shim.js')
    expect(config).not.toContain('"amy"')
    const stop = json(w.codexHooks).hooks.Stop
    expect(stop[0]).toEqual({ hooks: [{ command: 'other' }] })
    expect(stop).toHaveLength(2)
    expect(json(w.codexHooks).hooks.SessionEnd).toHaveLength(1)
    const ids = readIdentities(w.idFile, true).identities
    expect(ids.map((x) => x.label)).toEqual(['kim', 'amy', 'jane'])
    expect(ids[0]?.relays).toEqual([R2])
    expect(ids[2]).toMatchObject({
      relays: [R3],
      trust_roots: ['example.com'],
      honor: ['coding'],
      accept_types: ['note'],
      allow_delegate: true,
      policy: '/p.json',
      members: '/m.json',
    })
    expect(ids[2]?.rendezvous).toBeUndefined()
    const rows = json(join(w.home, 'proposals.json')).proposals
    expect(rows.map((r: { label: string }) => r.label)).toEqual(['kim', 'jane', 'amy'])
    expect(w.io.said).toContain(
      'the bag service is wired for every omp session of this user; a project .omp/mcp.json with a bag server shadows it: run host migrate',
    )
    expect(w.io.said.some((l) => l.startsWith('the bag service is wired for Codex'))).toBe(true)
    expect(w.io.said.some((l) => l.startsWith('retire the old keep job'))).toBe(false)
    const stamp = (w.io.said.find((l) => l.startsWith('journal ')) ?? '').replace(
      /^.*\/(\d{8}T\d{6}Z)\.json$/,
      '$1',
    )
    const back = fakeIo({ env: { HOME: w.HOME } })
    await undo(back, w.home, stamp, 4242)
    expect(readlinkSync(join(w.B, '.omp', 'hooks', 'pre', 'bag-wake.js'))).toBe(w.wakeEntry)
    expect(readFileSync(w.config, 'utf8')).toBe(w.table)
    expect(readFileSync(w.idFile, 'utf8')).toBe(w.idText)
    expect(existsSync(join(w.HOME, '.omp'))).toBe(true)
    expect(existsSync(join(w.HOME, '.omp', 'agent', 'mcp.json'))).toBe(false)
  })

  it('a file of the home changed while asked is named relative to the home: busy, nothing written', async () => {
    const w = world(() => {
      writeFileSync(join(w.home, 'proposals.json'), '{"version":1,"proposals":[]}')
      return true
    })
    await expect(w.run()).rejects.toThrow(
      'busy: it changed while you were asked: proposals.json; nothing was changed, ask again',
    )
    expect(readFileSync(w.config, 'utf8')).toBe(w.table)
    expect(existsSync(join(w.home, 'migrate'))).toBe(false)
  })

  it('two folders of one label with other settings are a collision (exists); with the same settings, two proposals', async () => {
    const { home } = homeWith('jane')
    const entry = (relay: string) => {
      const dir = folder()
      put(join(dir, '.mcp.json'), {
        mcpServers: { bag: { args: ['/x/bag-mcp.js', '--as', 'jane', '--relay', relay, '--dir', home] } },
      })
      return dir
    }
    const io = fakeIo({ env: { HOME: folder() } })
    const clash = { home, given: [entry(R1), entry(R2)], sandbox: false, build, proc }
    await expect(migrate(io, clash)).rejects.toThrow(
      'exists: identity jane is in the file with other settings: edit or remove it first',
    )
    expect(io.asked).toEqual([])
    await migrate(io, { ...clash, given: [entry(R1), entry(R1)] })
    expect(json(join(home, 'proposals.json')).proposals).toHaveLength(2)
    expect(readIdentities(join(home, 'identities.json'), true).identities).toHaveLength(1)
  })
})

describe('undo: the journal', () => {
  it('refuses a journal with no entries (not-found), and names a path outside the homes as it is when it changed', async () => {
    const w = world()
    mkdirSync(join(w.home, 'migrate'))
    writeFileSync(join(w.home, 'migrate', '20260101T000000Z.json'), '{"version":1}')
    await expect(undo(w.io, w.home, '20260101T000000Z', 1)).rejects.toThrow(
      'not-found: no migration journal ',
    )
    await w.run()
    const stamp = (w.io.said.find((l) => l.startsWith('journal ')) ?? '').replace(
      /^.*\/(\d{8}T\d{6}Z)\.json$/,
      '$1',
    )
    const mcp = join(w.realA, '.mcp.json')
    const after = readFileSync(mcp, 'utf8')
    // No HOME in this io: a path outside the home is named by itself.
    const io = fakeIo({
      answer: () => {
        writeFileSync(mcp, `${after}\n`)
        return true
      },
    })
    await expect(undo(io, w.home, stamp, 1)).rejects.toThrow(
      `busy: it changed while you were asked: ${mcp}; nothing was changed, ask again`,
    )
    expect(readFileSync(w.config, 'utf8')).not.toBe(w.table)
  })
})
