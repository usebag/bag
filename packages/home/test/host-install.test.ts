import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { keepAcceptCopy } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  copiedLines,
  type HostProcess,
  type Identity,
  installClaude,
  installCodex,
  installIdentities,
  installOmp,
  readIdentities,
  recordWarnings,
  removeClaude,
  removeIdentities,
  removeOmp,
  type Staged,
  wiredAs,
} from '../src/index.ts'
import { acceptFrom, FakeRelay, fakeIo, folder, homeWith, publishAt, signer } from './support.ts'

// host install and remove at project scope and Codex's user table: every file worked out before the first is written,
// an earlier install's entries replaced, another's refused; and the read-only check of an identity's records after.

const R1 = 'https://r1.example'
const R2 = 'https://r2.example'
const m: Staged = {
  cli: '/b/bag.js',
  mcp: '/b/bag-mcp.js',
  omp: '/b/bag-omp-wake.js',
  shim: '/b/bag-shim.js',
  copied: null,
  notice: null,
  versioned: null,
}
const p: HostProcess = { node: '/n/node', execPath: '/old/node', pid: 4242, uid: 501 }
const json = (file: string) => JSON.parse(readFileSync(file, 'utf8'))
const who = (label: string, home: string): Identity => ({
  label,
  key: label,
  home,
  relays: [R1],
  keep_alive_records: true,
})

describe("removeClaude: the reverse of installClaude, bag's entries only", () => {
  it("takes out the identity's server and its wake hooks, leaves every other server and hook; another identity's refuses", () => {
    const [dir, home] = [folder(), folder()]
    const [mcp, settings] = [join(dir, '.mcp.json'), join(dir, '.claude', 'settings.json')]
    installClaude(p, m, dir, who('jane', home), [])
    const doc = json(mcp)
    doc.mcpServers.other = { command: 'other' }
    writeFileSync(mcp, JSON.stringify(doc))
    const hooks = json(settings)
    hooks.hooks.Stop.push({ hooks: [{ type: 'command', command: 'echo mine' }] })
    writeFileSync(settings, JSON.stringify(hooks))
    expect(wiredAs(mcp)).toBe('jane')
    expect(() => removeClaude(dir, 'kim', home, [])).toThrow(/^not-found: .* another identity than kim/)
    expect(json(mcp).mcpServers.bag).toBeDefined()
    const out: string[] = []
    removeClaude(dir, 'jane', home, out)
    expect(out).toEqual([
      `wrote ${mcp} (bag's server removed)`,
      `wrote ${settings} (bag's wake-hook removed)`,
    ])
    expect(json(mcp).mcpServers).toEqual({ other: { command: 'other' } })
    expect(json(settings).hooks).toEqual({ Stop: [{ hooks: [{ type: 'command', command: 'echo mine' }] }] })
    const again: string[] = []
    removeClaude(dir, 'jane', home, again)
    expect(again).toEqual([`unchanged ${mcp}`, `unchanged ${settings}`])
    expect(wiredAs(mcp)).toBeNull()
  })
})

describe('installClaude', () => {
  it('writes the entry and both hooks, then changes nothing; an earlier install with the node running is replaced', () => {
    const [dir, home] = [folder(), folder()]
    const [mcp, settings] = [join(dir, '.mcp.json'), join(dir, '.claude', 'settings.json')]
    const args = ['/b/bag-mcp.js', '--as', 'jane', '--relay', R1, '--dir', home, '--keep-alive-records']
    const hook = `/n/node /b/bag.js wake-hook --as jane --dir ${home} --max 86000`
    mkdirSync(join(dir, '.claude'))
    writeFileSync(mcp, JSON.stringify({ mcpServers: { bag: { command: '/old/node', args }, other: {} } }))
    const before = `/old/node /b/bag.js wake-hook --as jane --dir ${home}`
    writeFileSync(settings, JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ command: before }] }] } }))
    const out: string[] = []
    installClaude(p, m, dir, who('jane', home), out)
    expect(out[0]).toBe(`wrote ${mcp}`)
    expect(out[2]).toBe(`wrote ${settings}`)
    expect(JSON.parse(out[3]?.slice(2) ?? '')).toMatchObject({ removed: before })
    expect(json(mcp).mcpServers).toEqual({ bag: { command: '/n/node', args }, other: {} })
    const s = json(settings).hooks
    for (const event of ['SessionStart', 'Stop']) {
      expect(s[event]).toEqual([
        { hooks: [{ type: 'command', command: hook, timeout: 86400, asyncRewake: true }] },
      ])
    }
    const again: string[] = []
    installClaude(p, m, dir, who('jane', home), again)
    expect(again).toEqual([`unchanged ${mcp}`, `unchanged ${settings}`, 'nothing to change'])
  })

  it('refuses another bag entry (exists) and a file that is not a JSON object, writing nothing', () => {
    const [dir, home] = [folder(), folder()]
    const mcp = join(dir, '.mcp.json')
    writeFileSync(mcp, JSON.stringify({ mcpServers: { bag: { command: 'x' } } }))
    expect(() => installClaude(p, m, dir, who('jane', home), [])).toThrow(
      'exists: mcpServers.bag is there with other settings',
    )
    expect(existsSync(join(dir, '.claude'))).toBe(false)
    writeFileSync(mcp, JSON.stringify({ mcpServers: [] }))
    expect(() => installClaude(p, m, dir, who('jane', home), [])).toThrow(
      'host-file-invalid: "mcpServers" is not a JSON object',
    )
    writeFileSync(mcp, '[]')
    expect(() => installClaude(p, m, dir, who('jane', home), [])).toThrow(`host-file-invalid: ${mcp} is not`)
    writeFileSync(mcp, '{}')
    mkdirSync(join(dir, '.claude'))
    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ hooks: { Stop: {} } }))
    expect(() => installClaude(p, m, dir, who('jane', home), [])).toThrow(
      'host-file-invalid: hooks.Stop is not a list',
    )
    expect(json(mcp)).toEqual({})
  })
})

describe('installIdentities and removeIdentities', () => {
  it('migrates a single-identity entry into the file as its default, adds the new one, and takes them out', () => {
    // One home per identity (identities.ts refuses home-shared): kim has a home of its own.
    const [dir, home, kimHome] = [folder(), folder(), folder()]
    const file = join(folder(), 'identities.json')
    installClaude(p, m, dir, who('jane', home), [])
    const out = installIdentities(p, m, file, dir, who('kim', kimHome))
    expect(out[0]).toBe(`wrote ${file}`)
    expect(out.at(-1)).toBe('the change takes effect when Claude Code starts the server again')
    const doc = readIdentities(file)
    expect(doc.default).toBe('jane')
    expect(doc.identities.map((x) => x.label)).toEqual(['jane', 'kim'])
    expect(json(join(dir, '.mcp.json')).mcpServers.bag).toEqual({
      command: '/n/node',
      args: ['/b/bag-mcp.js', '--identities', file],
    })
    const hooks = json(join(dir, '.claude', 'settings.json')).hooks
    expect(hooks.Stop).toHaveLength(1)
    expect(hooks.Stop[0].hooks[0].command).toBe(
      `/n/node /b/bag.js wake-hook --identities ${file} --max 86000`,
    )
    expect(installIdentities(p, m, file, dir, who('kim', kimHome))).toEqual([
      `unchanged ${file}`,
      `unchanged ${join(dir, '.mcp.json')}`,
      `unchanged ${join(dir, '.claude', 'settings.json')}`,
      'nothing to change',
    ])
    expect(removeIdentities(file, dir, 'jane')).toEqual([
      `wrote ${file}`,
      '  removed jane',
      'default jane dropped: kim is the default now',
      'the change takes effect when Claude Code starts the server again',
    ])
    expect(readIdentities(file).identities.map((x) => x.label)).toEqual(['kim'])
  })

  it('refuses a relative path (usage), a file in the project, a bad label and another entry', () => {
    const [dir, home] = [folder(), folder()]
    expect(() => installIdentities(p, m, 'ids.json', dir, who('kim', home))).toThrow(
      'usage: --identities takes an absolute path, not "ids.json"',
    )
    expect(() => removeIdentities(join(dir, 'ids.json'), dir, 'kim')).toThrow('identities-in-project: ')
    const file = join(folder(), 'ids.json')
    expect(() => installIdentities(p, m, file, dir, who('Kim!', home))).toThrow('usage: --label is ')
    writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { bag: { command: 'x' } } }))
    expect(() => installIdentities(p, m, file, dir, who('kim', home))).toThrow('exists: ')
    expect(existsSync(file)).toBe(false)
  })
})

describe('installCodex', () => {
  it('writes the plain table and its Stop hook once; an earlier table with the node running is replaced', () => {
    const [HOME, home] = [folder(), folder()]
    mkdirSync(join(HOME, '.codex'))
    const [config, hooks] = [join(HOME, '.codex', 'config.toml'), join(HOME, '.codex', 'hooks.json')]
    const args = ['/b/bag-mcp.js', '--as', 'jane', '--relay', R1, '--dir', home, '--keep-alive-records']
    writeFileSync(config, `[mcp_servers.bag]\ncommand = "/old/node"\nargs = ${JSON.stringify(args)}\n`)
    const out: string[] = []
    installCodex({ HOME }, p, m, who('jane', home), undefined, [], out)
    expect(readFileSync(config, 'utf8')).toBe(
      `[mcp_servers.bag]\ncommand = "/n/node"\nargs = ${JSON.stringify(args)}\n`,
    )
    expect(out.slice(0, 4)).toEqual([
      `wrote ${config}`,
      '  [mcp_servers.bag]',
      '  command = "/n/node"',
      `  args = ${JSON.stringify(args)}`,
    ])
    expect(json(hooks).hooks.Stop[0].hooks[0]).toEqual({
      type: 'command',
      command: `/n/node /b/bag.js wake-hook --as jane --dir ${home} --max 30 --no-idle-wake`,
      timeout: 60,
      statusMessage: 'bag: waiting for mail',
    })
    expect(out.at(-1)).toMatch(/^mcp mode: one plain identity jane for Codex/)
    const again: string[] = []
    installCodex({ HOME }, p, m, who('jane', home), undefined, [], again)
    expect(again.slice(0, 3)).toEqual([`unchanged ${config}`, `unchanged ${hooks}`, 'nothing to change'])
  })

  it('the session form names the principal and its caveats; the other form is exists; no HOME is usage', () => {
    const [HOME, home] = [folder(), folder()]
    const out: string[] = []
    installCodex({ HOME }, p, m, who('jane', home), 'auto:codex', ['c1'], out)
    const config = join(HOME, '.codex', 'config.toml')
    expect(readFileSync(config, 'utf8')).toContain(
      '"--session","auto:codex","--principal","jane","--grant-caveat","c1"',
    )
    expect(json(join(HOME, '.codex', 'hooks.json')).hooks.Stop[0].hooks[0].command).toContain(
      '--session auto:codex',
    )
    expect(out.at(-1)).toMatch(/^mcp mode: one Codex session per server/)
    expect(() => installCodex({ HOME }, p, m, who('jane', home), undefined, [], [])).toThrow(
      `exists: ${config} has [mcp_servers.bag] with other settings`,
    )
    expect(() => installCodex({}, p, m, who('jane', home), undefined, [], [])).toThrow(
      'usage: no HOME: codex --user writes $HOME/.codex/config.toml',
    )
  })
})

describe('installOmp and removeOmp', () => {
  it("writes the entry and the wake link, replaces an earlier link of bag's, warns of a second server, then takes both out", () => {
    const [dir, home, older, entries] = [folder(), folder(), folder(), folder()]
    // The links point at files that are there, as an installed home's and an older home's wake entries are.
    const mo: Staged = { ...m, omp: join(entries, 'bag-omp-wake.js') }
    writeFileSync(mo.omp, '// wake')
    writeFileSync(join(older, 'omp-wake.ts'), '// older wake')
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    symlinkSync(join(older, 'omp-wake.ts'), join(pre, 'bag-wake.ts'))
    mkdirSync(join(dir, '.claude'))
    writeFileSync(join(dir, '.claude', '.mcp.json'), JSON.stringify({ mcpServers: { bag: {} } }))
    const out: string[] = []
    installOmp(p, mo, dir, who('jane', home), out)
    const [file, link] = [join(dir, '.omp', 'mcp.json'), join(pre, 'bag-wake.js')]
    expect(out[0]).toBe(`wrote ${file}`)
    expect(out).toContain(`removed ${join(pre, 'bag-wake.ts')} (an earlier link of bag's)`)
    expect(() => lstatSync(join(pre, 'bag-wake.ts'))).toThrow()
    expect(existsSync(join(older, 'omp-wake.ts'))).toBe(true)
    expect(out).toContain(`wrote ${link} -> ${mo.omp}`)
    expect(out.some((l) => l.startsWith('warning: ') && l.includes('also names a bag server'))).toBe(true)
    expect(readlinkSync(link)).toBe(mo.omp)
    const bag = json(file).mcpServers.bag
    expect(bag.type).toBe('stdio')
    expect(bag.args.slice(-2)).toEqual(['--push', 'log'])
    const again: string[] = []
    installOmp(p, mo, dir, who('jane', home), again)
    expect(again.slice(0, 2)).toEqual([`unchanged ${file}`, `unchanged ${link}`])
    expect(again).toContain('nothing to change')
    expect(() => removeOmp(dir, 'kim', [])).toThrow(
      `not-found: ${file} has a bag server for another identity`,
    )
    const gone: string[] = []
    removeOmp(dir, 'jane', gone)
    expect(gone).toEqual([`wrote ${file} (mcpServers.bag removed)`, `removed ${link}`])
    expect(() => lstatSync(link)).toThrow()
    expect(existsSync(mo.omp)).toBe(true)
    const none: string[] = []
    removeOmp(dir, 'jane', none)
    expect(none).toEqual([`unchanged ${file}`])
  })

  it("removes a link of bag's whose target is gone, and a second install changes nothing", () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const stale = join(pre, 'bag-wake.ts')
    symlinkSync('/older/omp-wake.ts', stale)
    const out: string[] = []
    installOmp(p, m, dir, who('jane', home), out)
    expect(out).toContain(`removed ${stale} (an earlier link of bag's)`)
    expect(() => lstatSync(stale)).toThrow()
    const link = join(pre, 'bag-wake.js')
    const again: string[] = []
    installOmp(p, m, dir, who('jane', home), again)
    expect(again.slice(0, 2)).toEqual([`unchanged ${join(dir, '.omp', 'mcp.json')}`, `unchanged ${link}`])
    expect(again).not.toContain(`removed ${stale} (an earlier link of bag's)`)
    expect(again).toContain('nothing to change')
  })

  it('writes the wake link over a link a stopped run left at its temporary name, its target gone', () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const link = join(pre, 'bag-wake.js')
    const tmp = `${link}.${p.pid}.tmp`
    symlinkSync('/gone/bag-omp-wake.js', tmp)
    const out: string[] = []
    installOmp(p, m, dir, who('jane', home), out)
    expect(out).toContain(`wrote ${link} -> /b/bag-omp-wake.js`)
    expect(readlinkSync(link)).toBe('/b/bag-omp-wake.js')
    expect(() => lstatSync(tmp)).toThrow()
  })

  it('refuses a folder at the temporary name of the link (exists) before writing anything', () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const file = join(dir, '.omp', 'mcp.json')
    const before = JSON.stringify({ mcpServers: { other: {} } })
    writeFileSync(file, before)
    mkdirSync(`${join(pre, 'bag-wake.js')}.${p.pid}.tmp`)
    const tmp = `${join(pre, 'bag-wake.js')}.${p.pid}.tmp`
    expect(() => installOmp(p, m, dir, who('jane', home), [])).toThrow(
      `exists: ${tmp} is not a link of bag's: move it away first, then run this again`,
    )
    expect(readFileSync(file, 'utf8')).toBe(before)
    expect(() => lstatSync(join(pre, 'bag-wake.js'))).toThrow()
  })

  it('refuses a regular file at the temporary name of the link, leaving it and mcp.json as they were', () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const file = join(dir, '.omp', 'mcp.json')
    const before = JSON.stringify({ mcpServers: { other: {} } })
    writeFileSync(file, before)
    const tmp = `${join(pre, 'bag-wake.js')}.${p.pid}.tmp`
    writeFileSync(tmp, '// mine')
    expect(() => installOmp(p, m, dir, who('jane', home), [])).toThrow(
      `exists: ${tmp} is not a link of bag's: move it away first, then run this again`,
    )
    expect(readFileSync(tmp, 'utf8')).toBe('// mine')
    expect(readFileSync(file, 'utf8')).toBe(before)
    expect(() => lstatSync(join(pre, 'bag-wake.js'))).toThrow()
  })

  it('takes its temporary link out again when the write of mcp.json fails, leaving mcp.json as it was', () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    // .omp/mcp.json a link into a folder that is not there: read as absent, and its write fails (ENOENT), for any user.
    const file = join(dir, '.omp', 'mcp.json')
    symlinkSync(join(folder(), 'gone', 'mcp.json'), file)
    expect(() => installOmp(p, m, dir, who('jane', home), [])).toThrow()
    expect(readdirSync(pre)).toEqual([])
    expect(readlinkSync(file)).toContain(join('gone', 'mcp.json'))
  })

  it('install and remove take out a temporary link an earlier run left, and leave a file of that name', () => {
    const [dir, home, entries] = [folder(), folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    const entry = join(entries, 'bag-omp-wake.js')
    writeFileSync(entry, '// wake')
    const [first, kept] = [join(pre, 'bag-wake.js.99999.tmp'), join(pre, 'bag-wake.js.99998.tmp')]
    symlinkSync(entry, first)
    writeFileSync(kept, '// not a link')
    const out: string[] = []
    installOmp(p, m, dir, who('jane', home), out)
    expect(out).toContain(`removed ${first} (a temporary link a stopped install of bag left)`)
    expect(() => lstatSync(first)).toThrow()
    expect(readFileSync(kept, 'utf8')).toBe('// not a link')
    const again = join(pre, 'bag-wake.js.99997.tmp')
    symlinkSync(entry, again)
    const gone: string[] = []
    removeOmp(dir, 'jane', gone)
    expect(gone.at(-1)).toBe(`removed ${again} (a temporary link a stopped install of bag left)`)
    expect(() => lstatSync(again)).toThrow()
    expect(readFileSync(kept, 'utf8')).toBe('// not a link')
    expect(readdirSync(pre)).toEqual(['bag-wake.js.99998.tmp'])
  })

  it("removeOmp takes out a link of bag's whose target is gone, and says so once", () => {
    const [dir, home] = [folder(), folder()]
    installOmp(p, m, dir, who('jane', home), [])
    const link = join(dir, '.omp', 'hooks', 'pre', 'bag-wake.js')
    expect(readlinkSync(link)).toBe('/b/bag-omp-wake.js')
    const gone: string[] = []
    removeOmp(dir, 'jane', gone)
    expect(gone).toEqual([
      `wrote ${join(dir, '.omp', 'mcp.json')} (mcpServers.bag removed)`,
      `removed ${link}`,
    ])
    expect(() => lstatSync(link)).toThrow()
    const again: string[] = []
    removeOmp(dir, 'jane', again)
    expect(again).toEqual([`unchanged ${join(dir, '.omp', 'mcp.json')}`])
  })

  it("refuses a file at the link that is not bag's, and another bag entry, writing nothing", () => {
    const [dir, home] = [folder(), folder()]
    const pre = join(dir, '.omp', 'hooks', 'pre')
    mkdirSync(pre, { recursive: true })
    writeFileSync(join(pre, 'bag-wake.js'), '// mine')
    expect(() => installOmp(p, m, dir, who('jane', home), [])).toThrow("is not bag's wake link")
    expect(existsSync(join(dir, '.omp', 'mcp.json'))).toBe(false)
    writeFileSync(join(dir, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { bag: { command: 'x' } } }))
    expect(() => installOmp(p, m, dir, who('jane', home), [])).toThrow(
      'has mcpServers.bag with other settings',
    )
  })
})

describe('copiedLines', () => {
  it('names the version staged first, then the running service notice; nothing from source', () => {
    expect(copiedLines(m)).toEqual([])
    const lines = copiedLines({ ...m, copied: '/h/package/versions/0.4.0', notice: 'the notice' })
    expect(lines[0]).toMatch(/^wrote \/h\/package\/versions\/0\.4\.0 \(bag source /)
    expect(lines[1]).toBe('the notice')
  })
})

describe('recordWarnings', () => {
  it('republishes a record one relay or the home copy holds to the relay that lacks it, and warns of the rest', async () => {
    const { home, keys } = homeWith('jane')
    const signing = signer(keys, 'jane')
    const net = new FakeRelay()
    const io = fakeIo({ relay: net })
    const R3 = 'https://r3.example'
    net.down.add(R3)
    await publishAt(net, acceptFrom(signing, [signing.address], io.now - 10), R1)
    const lines = await recordWarnings(io, home, [R1, R2, R3], 'jane')
    expect(lines).toEqual([
      `warning: ${R3} did not answer (error): the records of jane there were not checked`,
      `republished the accept-from record of jane to ${R2} (it was at ${R1}; nothing re-signed)`,
      `warning: no address record at ${R1} for jane, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to jane`,
      `warning: no address record at ${R2} for jane, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to jane`,
    ])
    expect(net.rootsAt(R2, signing.address)).toEqual([signing.address])
  })

  it("publishes the home's copy when no relay holds one, and names a relay that refuses it", async () => {
    const { home, keys } = homeWith('jane')
    const signing = signer(keys, 'jane')
    const net = new FakeRelay()
    const io = fakeIo({ relay: net })
    keepAcceptCopy(home, 'jane', acceptFrom(signing, [signing.address], io.now - 10))
    net.refuse.set(R2, 'stale-record')
    const lines = await recordWarnings(io, home, [R1, R2], 'jane')
    expect(lines).toContain(
      `republished the accept-from record of jane to ${R1} (it was at the home copy (${join(home, 'records')}); nothing re-signed)`,
    )
    expect(lines).toContain(
      `warning: ${R2} refused the accept-from record of jane (stale-record): run bag record keep --once --as jane with every relay`,
    )
  })
})
