import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from 'node:fs'
import { platform } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readAuditLines, verifyAuditLog } from '@usebag/edge'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { CLI_AUDIT, renewing } from '../src/home.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// A background record keep: beside a live server that
// keeps its records alive it stands aside, a line and no error; what it audits goes to a file of its own, anchored, so
// that it can never fork the chain a live edge holds; it covers every identity of a file; and it prints a job for a
// person to install, touching neither launchd nor cron.

const tmp = tempDir('keep-background')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const CLI_MAIN = fileURLToPath(new URL('../src/main.ts', import.meta.url))
let n = 0

async function bob(): Promise<{
  io: TestIo
  relay: MemoryRelay
  dir: string
  address: string
  state: string
}> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  expect((await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)).code).toBe(0)
  return { io, relay, dir, address, state: join(dir, 'state', 'bob') }
}
const keep = (io: TestIo, dir: string, ...more: string[]) =>
  cli(io, 'record', 'keep', '--as', 'bob', '--relay', RELAY, '--once', ...more, '--dir', dir)
const lock = (state: string, body: object): void => {
  mkdirSync(state, { recursive: true })
  writeFileSync(join(state, 'mcp.lock'), JSON.stringify(body))
}

describe('record keep beside a server: it stands aside', () => {
  it('prints held session-open and exits 0 for a live server that keeps its records alive, and publishes nothing', async () => {
    const h = await bob()
    const before = h.relay.records.get(`${h.address} address`)
    h.io.time.now += 1
    lock(h.state, { pid: process.pid, keep_alive: true })
    expect(await keep(h.io, h.dir)).toEqual({ code: 0, out: [`held session-open ${h.address}`], err: [] })
    expect(h.relay.records.get(`${h.address} address`)).toBe(before)
  })

  it('goes on for a server that keeps nothing, a dead pid, a pid used again, and a lock that does not read', async () => {
    const h = await bob()
    for (const body of [
      { pid: process.pid, keep_alive: false },
      { pid: process.pid },
      { pid: 99_999_999, keep_alive: true },
    ]) {
      lock(h.state, body)
      expect(renewing(h.dir, 'bob')).toBe(false)
    }
    lock(h.state, { pid: process.pid, keep_alive: true })
    expect(renewing(h.dir, 'bob')).toBe(true)
    // A lock written before this process started names a pid used again: the server that wrote it is gone.
    const long = new Date(Date.now() - 86_400_000 * 365)
    utimesSync(join(h.state, 'mcp.lock'), long, long)
    expect(renewing(h.dir, 'bob')).toBe(false)
    writeFileSync(join(h.state, 'mcp.lock'), 'not json')
    expect(renewing(h.dir, 'bob')).toBe(false)
    h.io.time.now += 1
    expect((await keep(h.io, h.dir)).code).toBe(0)
  })

  it('takes a server it may not signal for live: EPERM is a process', async () => {
    const h = await bob()
    lock(h.state, { pid: 1, keep_alive: true })
    expect(renewing(h.dir, 'bob')).toBe(true)
  })
})

describe('what a keep audits goes to a file of its own (section 5)', () => {
  it('writes each rotation to cli-audit.jsonl, its own chain, and leaves audit.jsonl to the edge', async () => {
    const h = await bob()
    h.io.time.now += 13 * 3600
    expect((await keep(h.io, h.dir)).code).toBe(0)
    expect(existsSync(join(h.state, 'audit.jsonl'))).toBe(false)
    const lines = readAuditLines(join(h.state, CLI_AUDIT))
    expect(lines).toHaveLength(2)
    expect(verifyAuditLog(lines).ok).toBe(true)
    const verified = await cli(h.io, 'audit', 'verify', join(h.state, CLI_AUDIT))
    expect([verified.code, verified.out]).toEqual([0, ['ok 2 lines']])
  })

  it('audit verify reads the whole anchored set: an edge log, and the file beside it', async () => {
    const h = await bob()
    const body = ['--type', 'chat.v1', '--body', '{}', '--dir', h.dir]
    await cli(h.io, 'send', '--as', 'bob', '--to', h.address, '--relay', RELAY, ...body)
    const log = join(h.state, 'audit.jsonl')
    const whole = await cli(h.io, 'audit', 'verify', log)
    expect(whole.code).toBe(0)
    expect(whole.out.at(-1)).toMatch(new RegExp(`^${CLI_AUDIT}: ok \\d+ lines$`))
    const side = join(h.state, CLI_AUDIT)
    const text = readFileSync(side, 'utf8')
    writeFileSync(side, text.replace('"accept"', '"reject"'))
    const edited = await cli(h.io, 'audit', 'verify', log)
    expect(edited.code).toBe(1)
    expect(edited.out.at(-1)).toMatch(new RegExp(`^${CLI_AUDIT}: bad line 1: `))
    execFileSync('mv', [side, `${side}.gone`])
    const missing = await cli(h.io, 'audit', 'verify', log)
    expect(missing.code).toBe(1)
    expect(missing.out.at(-1)).toMatch(new RegExp(`^missing: ${CLI_AUDIT} is anchored at line \\d+ in `))
  })

  it('an edge will not start with an anchored file gone, or rewritten', async () => {
    const h = await bob()
    const side = join(h.state, CLI_AUDIT)
    const inbox = ['inbox', '--as', 'bob', '--relay', RELAY, '--once', '--dir', h.dir]
    expect((await cli(h.io, ...inbox)).code).toBe(0)
    execFileSync('mv', [side, `${side}.gone`])
    const gone = await cli(h.io, ...inbox)
    expect(gone.code).toBe(1)
    expect(gone.err[0]).toMatch(
      new RegExp(`^bag: truncated: the audit log ${CLI_AUDIT} is anchored at line \\d+ and is not there$`),
    )
    execFileSync('mv', [`${side}.gone`, side])
    writeFileSync(side, readFileSync(side, 'utf8').replace('"accept"', '"reject"'))
    const rewritten = await cli(h.io, ...inbox)
    expect(rewritten.code).toBe(1)
    expect(rewritten.err[0]).toMatch(/^bag: diverged: /)
  })
})

describe('record keep --identities: every identity of the file', () => {
  async function two() {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const base = join(tmp.dir, `many-${n++}`)
    const homes = [join(base, 'a'), join(base, 'b')] as const
    const made = []
    for (const dir of homes) {
      const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
      expect((await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)).code).toBe(0)
      made.push(address)
    }
    const file = join(base, 'ids.json')
    const entry = (label: string, home: string) => ({ label, key: 'bob', home, relays: [RELAY] })
    const doc = { version: 1, identities: [entry('one', homes[0]), entry('two', homes[1])] }
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    return { io, file, homes, made }
  }

  it('renews each, in one line', async () => {
    const m = await two()
    m.io.time.now += 1
    const got = await cli(m.io, 'record', 'keep', '--identities', m.file, '--once')
    expect(got.code).toBe(0)
    for (const a of m.made) expect(got.out.some((l) => l.startsWith(`republished address ${a}`))).toBe(true)
  })

  it('stops for no identity: a failure is a line, the rest are renewed, and the run ends with its code', async () => {
    const m = await two()
    m.io.time.now += 1
    execFileSync('mv', [join(m.homes[0], 'keys'), join(m.homes[0], 'gone')])
    const got = await cli(m.io, 'record', 'keep', '--identities', m.file, '--once')
    expect(got.code).toBe(1)
    expect(got.out[0]).toBe('failed one ENOENT')
    expect(got.out.some((l) => l.startsWith(`republished address ${m.made[1]}`))).toBe(true)
  })

  it('takes neither --as, --relay, --dir nor --every, an absolute path only, and --once or a job', async () => {
    const m = await two()
    const usage = '--identities takes no --as, --relay, --dir or --every: each identity is in the file'
    for (const more of [
      ['--as', 'bob'],
      ['--relay', RELAY],
      ['--dir', '/x'],
      ['--every', '60'],
    ]) {
      const got = await cli(m.io, 'record', 'keep', '--identities', m.file, '--once', ...more)
      expect(got.err[0]).toBe(`bag: usage: ${usage}`)
    }
    expect((await cli(m.io, 'record', 'keep', '--identities', 'ids.json', '--once')).err[0]).toBe(
      'bag: usage: --identities takes an absolute path, not "ids.json"',
    )
    expect((await cli(m.io, 'record', 'keep', '--identities', m.file)).err[0]).toBe(
      'bag: usage: --identities takes --once: a job, not a keeper that stays',
    )
  })
})

describe('the job a person installs: text on stdout, nothing written, nothing touched', () => {
  const job = ['record', 'keep', '--as', 'bob', '--relay', RELAY, '--dir', '/home/u/.bag']

  it('--plist prints a calendar job of --once, with absolute paths, that parses', async () => {
    const io = testIo(new MemoryRelay())
    const got = await cli(io, ...job, '--plist')
    expect(got.code).toBe(0)
    const text = got.out.join('\n')
    expect(text).toContain('<string>bag.keep.bob</string>')
    expect(text).toContain(`<string>${process.execPath}</string>`)
    expect(text).toContain(`<string>${CLI_MAIN}</string>`)
    expect(text).toContain('<string>--once</string>')
    expect(text).toContain('<key>StartCalendarInterval</key>')
    expect(text).not.toContain('StartInterval<')
    expect(text).toContain('<string>/home/u/.bag/keep.log</string>')
    for (const hour of [2, 8, 14, 20]) expect(text).toContain(`<key>Hour</key><integer>${hour}</integer>`)
    if (platform() === 'darwin') {
      const file = join(tmp.dir, `job-${n++}.plist`)
      writeFileSync(file, text)
      expect(execFileSync('plutil', ['-lint', file], { encoding: 'utf8' })).toContain('OK')
    }
  })

  it('--crontab prints the one line, cron skipping what the machine sleeps through', async () => {
    const io = testIo(new MemoryRelay())
    const got = await cli(io, ...job, '--crontab')
    expect(got.out).toHaveLength(1)
    expect(got.out[0]).toMatch(/^([0-9]|[1-5][0-9]) 2,8,14,20 \* \* \* /)
    expect(got.out[0]).toContain(
      `* * * ${process.execPath} ${CLI_MAIN} record keep --as bob --relay ${RELAY} --dir /home/u/.bag --once >> /home/u/.bag/keep.log 2>&1`,
    )
  })

  it('draws the minute of a job, so that the jobs of many people do not reach the relays together', async () => {
    const minutes = new Set<string>()
    for (let i = 0; i < 8; i++) {
      vi.resetModules()
      const { crontabLine } = await import('../src/commands/keep-schedule.ts')
      minutes.add(crontabLine(['x'], '/l').split(' ')[0] as string)
    }
    expect(minutes.size).toBeGreaterThan(1)
  })

  it('--identities names the file, and the log beside it', async () => {
    const io = testIo(new MemoryRelay())
    const got = await cli(io, 'record', 'keep', '--identities', '/home/u/ids/p.json', '--crontab')
    expect(got.out[0]).toContain('record keep --identities /home/u/ids/p.json --once >> /home/u/ids/keep.log')
  })
})

describe('record address by hand says what it leaves out', () => {
  it('names a revoked entry of the kept copy that the new record drops', async () => {
    const h = await bob()
    const gone = (await cli(h.io, 'keygen', 'gone', '--dir', h.dir)).out[0] as string
    const out = join(h.dir, 'r.json')
    const at = ['--relay', RELAY, '--dir', h.dir]
    h.io.time.now = T0 + 1
    await cli(h.io, 'record', 'address', 'bob', '--revoke', gone, ...at, '--out', out)
    await cli(h.io, 'publish', RELAY, out)
    expect((await keep(h.io, h.dir)).code).toBe(0)
    const dropped = await cli(h.io, 'record', 'address', 'bob', ...at, '--out', out)
    expect(dropped.err).toEqual([
      `bag: this record leaves out revoked entries of the record kept here: ${gone}`,
    ])
    expect((await cli(h.io, 'record', 'address', 'bob', '--revoke', gone, ...at, '--out', out)).err).toEqual(
      [],
    )
  })
})
