import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs'
import { join, relative } from 'node:path'
import { type AcceptFromRecord, decodeAddress, parseRecord, toHex } from '@usebag/core'
import { keepAcceptCopy } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { USAGE } from '../src/cli.ts'
import { addTrust, readTrust } from '../src/trust.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli } from './support/run.ts'

// identity remove: one identity out of a home that keeps others, after one y on a terminal, nothing deleted. The
// cases of the leave-per-identity design: a shared peer stays in trust.json
// for the identity that stays, the wiring of the one that leaves comes out of its own folder only, a held identity is
// refused, a one-identity home works, a run again is refused, and a Codex table is left to the person. In-process
// relays by URL (support/network.ts), the test io's terminal answers and clock, temp directories only.

const tmp = tempDir('identity-remove')
afterAll(() => tmp.cleanup())
const [R1, R2] = ['http://127.0.0.1:1', 'http://127.0.0.1:2']
let n = 0

/** A home with `first` and `second`, on a terminal with the answers given; p1 and p2, peers in homes of their own. */
async function world(answers: boolean[], env: Record<string, string> = {}) {
  const net = new Network()
  const base = join(tmp.dir, `w${n++}`)
  const io = testIo(net, env)
  io.tty = true
  io.answers.push(...answers)
  const dir = join(base, 'home')
  const key = async (name: string, home: string) =>
    (await cli(io, 'keygen', name, '--dir', home)).out[0] as string
  const first = await key('first', dir)
  const second = await key('second', dir)
  const p1 = await key('p1', join(base, 'p1'))
  const p2 = await key('p2', join(base, 'p2'))
  return { net, io, base, dir, first, second, p1, p2 }
}

type World = Awaited<ReturnType<typeof world>>

/** `name`'s accept-from of `roots`, one second on, published at both relays, with the home copy a pairing leaves. */
async function accept(w: World, name: string, roots: readonly string[]) {
  w.io.time.now += 1
  const file = join(w.base, `accept-${n++}.json`)
  const given = roots.flatMap((r) => ['--root', r])
  const sizes = ['--max-bytes', '4096', '--ttl', '3600', '--out', file, '--dir', w.dir]
  expect((await cli(w.io, 'record', 'accept-from', name, ...given, ...sizes)).code).toBe(0)
  for (const url of [R1, R2]) expect((await cli(w.io, 'publish', url, file, '--dir', w.dir)).code).toBe(0)
  keepAcceptCopy(w.dir, name, parseRecord(readFileSync(file)) as AcceptFromRecord)
}

/** The shared world of case 1: both paired with p1, second with p2 too; first named second (it paired with it). */
async function paired(w: World) {
  for (const r of [w.p1, w.p2]) addTrust(w.dir, r, T0)
  await accept(w, 'first', [w.p1, w.second])
  await accept(w, 'second', [w.p1, w.p2])
  for (const [k, a] of [
    ['p1', w.p1],
    ['p2', w.p2],
    ['sec', w.second],
  ] as const)
    expect((await cli(w.io, 'name', 'add', k, a, '--dir', w.dir)).code).toBe(0)
  expect(
    (await cli(w.io, 'keys', 'rotate', 'second', '--relay', R1, '--relay', R2, '--dir', w.dir)).code,
  ).toBe(0)
  mkdirSync(join(w.dir, 'install'), { recursive: true })
  writeFileSync(join(w.dir, 'install', 'second.env'), 'NAME="second"\n')
  writeFileSync(join(w.dir, 'install', 'first.env'), 'NAME="first"\n')
  mkdirSync(join(w.dir, 'package'), { recursive: true })
  writeFileSync(join(w.dir, 'package', 'bag.js'), '// bag\n')
}

const remove = (w: World, name: string, ...more: string[]) =>
  cli(w.io, 'identity', 'remove', name, '--relay', R1, '--relay', R2, '--dir', w.dir, ...more)

/** Every file under `dir`, relative, with its bytes (a link as its target text). */
function files(dir: string): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name)
      if (e.isDirectory()) walk(p)
      else out.set(relative(dir, p), e.isSymbolicLink() ? `link` : readFileSync(p, 'latin1'))
    }
  }
  if (existsSync(dir)) walk(dir)
  return out
}

/** The files of `files` that are not second's nor the shared trust.json and names.json. */
const notSecond = (all: Map<string, string>) =>
  [...all].filter(
    ([f]) =>
      !f.includes('second') && !['trust.json', 'names.json'].includes(f) && !f.startsWith('key-records'),
  )

const acceptAt = (w: World, url: string, who: string) =>
  parseRecord(w.net.at(url).records.get(`${who} accept-from`) as Uint8Array) as AcceptFromRecord

describe('identity remove <name>: one identity out of a shared home', () => {
  it('(1) second leaves: first and the shared peer stay, the rest moves into --to', async () => {
    const w = await world([true])
    await paired(w)
    const before = notSecond(files(w.dir))
    const hex = toHex(decodeAddress(w.second))
    const to = join(w.base, 'left')
    const ran = await remove(w, 'second', '--to', to)
    expect(ran.err).toEqual([])
    expect(ran.code).toBe(0)
    expect(w.io.asked).toHaveLength(1)
    const q = w.io.asked[0] as string
    expect(q).toContain(`remove second (${w.second}) from ${w.dir}:`)
    expect(q).toContain(`its accept-from re-signed to name only ${w.second}, at ${R1} ${R2}`)
    expect(q).toContain(`trust.json: ${w.p2} leave`)
    expect(q).toContain(`trust.json keeps ${w.p1} for first`)
    expect(q).toContain('names.json forgets sec')
    expect(ran.out).toEqual([
      `published accept-from ${w.second} ${R1}`,
      `published accept-from ${w.second} ${R2}`,
      `kept trust ${w.p1}: the accept-from of first still names it`,
      `untrusted ${w.p2}`,
      `forgot sec ${w.second}`,
      `first accepts ${w.second}: to end that, run on a terminal: bag unpair ${w.second} --as first --relay ${R1} --relay ${R2}`,
      ...[
        join('state', 'second'),
        join('records', 'second.address.json'),
        join('records', 'second.accept.json'),
      ]
        .concat([join('key-records', hex)])
        .concat(['install/second.env', 'keys/second.json'])
        .map((f) => `moved ${join(w.dir, f)} -> ${join(to, 'home', f)}`),
      `removed second ${w.second}: ${to}`,
      `${to} holds the private key of second: this is not a revocation, and moving the files back undoes it; to end second for good, delete that folder yourself`,
    ])
    expect((await cli(w.io, 'keys', 'list', '--dir', w.dir)).out.map((l) => l.split(' ')[0])).toEqual([
      'first',
    ])
    expect(notSecond(files(w.dir))).toEqual(before)
    expect(Object.keys(readTrust(w.dir))).toEqual([w.p1])
    for (const url of [R1, R2]) expect(acceptAt(w, url, w.second).roots).toEqual([w.second])
    expect(readFileSync(join(w.dir, 'names.json'), 'utf8')).not.toContain(w.second)
    const moved = [...files(to).keys()]
    for (const f of ['home/keys/second.json', 'home/records/second.accept.json', 'home/install/second.env'])
      expect(moved).toContain(f)
    expect(moved.some((f) => f.startsWith(`home/key-records/${hex}/`))).toBe(true)
    expect(moved.some((f) => f.startsWith('home/state/second/'))).toBe(true)
    expect(lstatSync(to).mode & 0o777).toBe(0o700)
    expect(USAGE).toContain(
      '  identity remove <name> --relay <url>... [--to <dir>] [--project <dir>] [--dir <home>]\n',
    )
  })

  it('(2) --project takes out only that identity wiring: omp and Claude Code, other servers and hooks stay', async () => {
    const w = await world([true])
    const [a, b, c] = ['a', 'b', 'c'].map((d) => join(w.base, d)) as [string, string, string]
    mkdirSync(join(b, '.omp'), { recursive: true })
    writeFileSync(join(b, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }))
    mkdirSync(a)
    const omp = (name: string, dir: string) =>
      cli(w.io, 'host', 'install', 'omp', '--as', name, '--dir', w.dir, '--relay', R1, '--project', dir)
    expect((await omp('first', a)).code).toBe(0)
    expect((await omp('second', b)).code).toBe(0)
    const aBefore = files(a)
    expect(existsSync(join(b, '.omp', 'hooks', 'pre', 'bag-wake.ts'))).toBe(true)
    let ran = await remove(w, 'second', '--project', b, '--to', join(w.base, 'left-b'))
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(w.io.asked[0]).toContain(`${b}/.omp/mcp.json: its bag server and bag's wake link come out`)
    expect(JSON.parse(readFileSync(join(b, '.omp', 'mcp.json'), 'utf8'))).toEqual({
      mcpServers: { other: { command: 'x' } },
    })
    expect(existsSync(join(b, '.omp', 'hooks', 'pre', 'bag-wake.ts'))).toBe(false)
    expect(files(a)).toEqual(aBefore)

    // Claude Code, project mode: first's server and hook in c are another identity's, so a run for a third leaves them.
    mkdirSync(join(c, '.claude'), { recursive: true })
    const other = { type: 'command', command: 'echo hi' }
    writeFileSync(join(c, '.mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'y' } } }))
    writeFileSync(
      join(c, '.claude', 'settings.json'),
      JSON.stringify({ hooks: { Stop: [{ hooks: [other] }] } }),
    )
    expect((await cli(w.io, 'keygen', 'third', '--dir', w.dir)).code).toBe(0)
    const cc = (name: string) =>
      cli(w.io, 'host', 'install', 'claude-code', '--as', name, '--dir', w.dir, '--relay', R1, '--project', c)
    expect((await cc('third')).code).toBe(0)
    const cBefore = files(c)
    w.io.answers.push(true)
    ran = await remove(w, 'first', '--project', c, '--to', join(w.base, 'left-c'))
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(w.io.asked[1]).toContain(`${c}/.mcp.json: its bag server is not first's: left as it is`)
    expect(files(c)).toEqual(cBefore)
    w.io.answers.push(true)
    ran = await remove(w, 'third', '--project', c, '--to', join(w.base, 'left-t'))
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out).toContain(`wrote ${c}/.mcp.json (mcpServers.bag removed)`)
    expect(ran.out).toContain(`wrote ${c}/.claude/settings.json (the wake hooks of third removed)`)
    expect(JSON.parse(readFileSync(join(c, '.mcp.json'), 'utf8'))).toEqual({
      mcpServers: { other: { command: 'y' } },
    })
    expect(JSON.parse(readFileSync(join(c, '.claude', 'settings.json'), 'utf8'))).toEqual({
      hooks: { Stop: [{ hooks: [other] }] },
    })
  })

  it('(3) refused held while a live MCP server holds it: nothing moved, nothing published', async () => {
    const w = await world([true])
    await paired(w)
    writeFileSync(join(w.dir, 'state', 'second', 'mcp.lock'), JSON.stringify({ pid: process.pid }))
    const [all, log] = [files(w.dir), w.net.log.length]
    const ran = await remove(w, 'second')
    expect([ran.code, ran.out, w.io.asked]).toEqual([1, [], []])
    expect(ran.err[0]).toMatch(/^bag: held: the identity second is held by a running bag MCP server \(pid /)
    expect(files(w.dir)).toEqual(all)
    expect(w.net.log).toHaveLength(log)
  })

  it('(4) a one-identity home: the home keeps only package/ and the shared files', async () => {
    const w = await world([true, true])
    await paired(w)
    expect((await remove(w, 'second', '--to', join(w.base, 'l1'))).code).toBe(0)
    expect((await remove(w, 'first', '--to', join(w.base, 'l2'))).code).toBe(0)
    expect(readdirSync(w.dir).sort()).toEqual([
      'install',
      'key-records',
      'keys',
      'names.json',
      'package',
      'records',
      'state',
      'trust.json',
    ])
    expect([...files(w.dir).keys()].sort()).toEqual(['names.json', 'package/bag.js', 'trust.json'])
    expect(readTrust(w.dir)).toEqual({})
    for (const url of [R1, R2]) expect(acceptAt(w, url, w.first).roots).toEqual([w.first])
  })

  it('(5) run twice: the second run is refused ENOENT, nothing moved', async () => {
    const w = await world([true, true])
    await paired(w)
    expect((await remove(w, 'second', '--to', join(w.base, 'l1'))).code).toBe(0)
    const all = files(w.dir)
    const ran = await remove(w, 'second', '--to', join(w.base, 'l2'))
    expect([ran.code, ran.out, ran.err]).toEqual([
      1,
      [],
      [`bag: ENOENT: no identity second in ${w.dir}: no key file, keychain or agent pointer`],
    ])
    expect(files(w.dir)).toEqual(all)
    expect(existsSync(join(w.base, 'l2'))).toBe(false)
  })

  it('(6) Codex: the table naming it is printed for the person, the file untouched', async () => {
    const user = join(tmp.dir, `user-${n++}`)
    const w = await world([true], { HOME: user })
    mkdirSync(join(user, '.codex'), { recursive: true })
    const toml = `[mcp_servers.bag]\ncommand = "node"\nargs = ["mcp.js","--session","auto:codex","--principal","second"]\n`
    writeFileSync(join(user, '.codex', 'config.toml'), toml)
    const ran = await remove(w, 'second', '--to', join(w.base, 'l'))
    const note =
      `${user}/.codex/config.toml runs bag for second ([mcp_servers.bag], --principal second): bag never edits it; ` +
      `take that table out, and the Stop hook of second in ${user}/.codex/hooks.json`
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out).toContain(note)
    expect(w.io.asked[0]).toContain(note)
    expect(readFileSync(join(user, '.codex', 'config.toml'), 'utf8')).toBe(toml)
  })

  it('n changes nothing; a --to that is not empty and a keep plist are refused before the question', async () => {
    const user = join(tmp.dir, `user-${n++}`)
    const w = await world([false], { HOME: user })
    await paired(w)
    const [all, log, trust] = [files(w.dir), w.net.log.length, readFileSync(join(w.dir, 'trust.json'))]
    const no = await remove(w, 'second')
    expect([no.code, no.out, no.err]).toEqual([1, [], ['bag: declined: nothing was changed']])
    expect([files(w.dir), w.net.log.length, readFileSync(join(w.dir, 'trust.json'))]).toEqual([
      all,
      log,
      trust,
    ])
    const full = join(w.base, 'full')
    mkdirSync(full)
    writeFileSync(join(full, 'x'), 'x')
    const busy = await remove(w, 'second', '--to', full)
    expect(busy.err).toEqual([`bag: exists: ${full} is not empty: name another --to`])
    const agents = join(user, 'Library', 'LaunchAgents')
    mkdirSync(agents, { recursive: true })
    writeFileSync(join(agents, 'bag.keep.second.plist'), '<plist/>')
    const kept = await remove(w, 'second')
    expect(kept.code).toBe(1)
    expect(kept.err[0]).toContain(`launchctl bootout gui/${process.getuid?.()}/bag.keep.second`)
    expect(w.io.asked).toHaveLength(1)
    expect(files(w.dir)).toEqual(all)
  })

  it('a relay that does not take the re-sign stops the run before anything local changes', async () => {
    const w = await world([true, true])
    await paired(w)
    const { RelayError } = await import('@usebag/edge')
    w.net.at(R2).failRecordPublish.set(R2, new RelayError(null, 0, null, 'down'))
    const all = notSecond(files(w.dir))
    const trust = readFileSync(join(w.dir, 'trust.json'))
    const ran = await remove(w, 'second', '--to', join(w.base, 'l1'))
    expect(ran.code).toBe(1)
    expect(ran.out).toEqual([
      `published accept-from ${w.second} ${R1}`,
      `failed accept-from ${w.second} ${R2} unreachable`,
    ])
    expect([notSecond(files(w.dir)), readFileSync(join(w.dir, 'trust.json'))]).toEqual([all, trust])
    expect(existsSync(join(w.dir, 'keys', 'second.json'))).toBe(true)
    // Up again: the run again reads the roots from the home copy, so p2 still leaves trust.json.
    w.net.at(R2).failRecordPublish.clear()
    const again = await remove(w, 'second', '--to', join(w.base, 'l2'))
    expect(again.code, again.err.join(' ')).toBe(0)
    expect(again.out).toContain(`untrusted ${w.p2}`)
    expect(Object.keys(readTrust(w.dir))).toEqual([w.p1])
  })

  it('a twin address and an agent identity are refused before the question, nothing changed', async () => {
    const w = await world([true, true])
    await paired(w)
    copyFileSync(join(w.dir, 'keys', 'second.json'), join(w.dir, 'keys', 'twin.json'))
    const twin = await remove(w, 'second', '--to', join(w.base, 'left-twin'))
    expect([twin.code, twin.err[0]?.startsWith('bag: exists: ')]).toEqual([1, true])
    renameSync(join(w.dir, 'keys', 'twin.json'), join(w.base, 'twin-gone.json'))
    const made = await cli(
      w.io,
      'keygen',
      'agt',
      '--custody',
      'agent',
      '--principal',
      'first',
      '--dir',
      w.dir,
    )
    expect(made.code, made.err.join(' ')).toBe(0)
    const agent = await remove(w, 'agt', '--to', join(w.base, 'left-agt'))
    expect([agent.code, agent.err[0]?.startsWith('bag: not-authorized: ')]).toEqual([1, true])
    expect(w.io.asked).toEqual([])
    expect(existsSync(join(w.dir, 'keys', 'second.json'))).toBe(true)
  })

  it("an orphaned copy (its identity's key file gone) keeps no root in trust.json", async () => {
    const w = await world([true])
    await paired(w)
    await cli(w.io, 'keygen', 'ghost', '--dir', w.dir)
    await accept(w, 'ghost', [w.p2])
    renameSync(join(w.dir, 'keys', 'ghost.json'), join(w.base, 'ghost-gone.json'))
    const ran = await remove(w, 'second', '--to', join(w.base, 'left-ghost'))
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out).toContain(`untrusted ${w.p2}`)
    expect(Object.keys(readTrust(w.dir))).toEqual([w.p1])
  })

  it('a run again after a failed move continues into the partial folder, with no --to', async () => {
    const w = await world([true])
    await paired(w)
    // a run that moved state/ and then stopped: its folder holds files, not yet the key
    const partial = join(w.base, 'bag-left-second-20261112T000000Z')
    mkdirSync(join(partial, 'home', 'state'), { recursive: true, mode: 0o700 })
    renameSync(join(w.dir, 'state', 'second'), join(partial, 'home', 'state', 'second'))
    const ran = await remove(w, 'second')
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out).toContain(`removed second ${w.second}: ${partial}`)
    expect(existsSync(join(partial, 'home', 'keys', 'second.json'))).toBe(true)
    expect(existsSync(join(partial, 'home', 'state', 'second'))).toBe(true)
    expect(readdirSync(w.base).filter((e) => e.startsWith('bag-left-second-'))).toEqual([
      'bag-left-second-20261112T000000Z',
    ])
  })
})
