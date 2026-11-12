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
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { stableNode } from '../src/packaged.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

/** The node host install writes: Homebrew's link when it is the node running (packaged.ts). */
const NODE = stableNode()

// host install omp (cut/docs/host-omp.md): the bag server in <project>/.omp/mcp.json and the wake link
// <project>/.omp/hooks/pre/bag-wake.<ext> to the omp wake entry. Temp directories only.

const tmp = tempDir('host-install-omp')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const MCP_MAIN = fileURLToPath(new URL('../../mcp/src/main.ts', import.meta.url))
const OMP_WAKE = fileURLToPath(new URL('../src/omp-wake.ts', import.meta.url))
let n = 0

interface World {
  readonly io: TestIo
  readonly relay: MemoryRelay
  readonly dir: string
  readonly project: string
}

async function world(): Promise<World> {
  const base = join(tmp.dir, `w${n++}`)
  const [dir, project] = [join(base, 'home'), join(base, 'project')]
  mkdirSync(project, { recursive: true })
  const relay = new MemoryRelay()
  const io = testIo(relay, { HOME: join(base, 'user') })
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  return { io, relay, dir, project }
}

const install = (w: World, ...more: string[]) =>
  cli(
    w.io,
    'host',
    'install',
    'omp',
    '--as',
    'bob',
    '--dir',
    w.dir,
    '--relay',
    RELAY,
    '--project',
    w.project,
    ...more,
  )
const remove = (w: World, name = 'bob') =>
  cli(w.io, 'host', 'remove', 'omp', '--as', name, '--project', w.project)
const json = (file: string): unknown => JSON.parse(readFileSync(file, 'utf8'))
const entry = (dir: string) => ({
  type: 'stdio',
  command: NODE,
  args: [MCP_MAIN, '--as', 'bob', '--relay', RELAY, '--dir', dir, '--keep-alive-records', '--push', 'log'],
})
const link = (w: World) => join(w.project, '.omp', 'hooks', 'pre', 'bag-wake.ts')

describe('host install omp', () => {
  it('writes .omp/mcp.json and links the wake to the entry, and a second run changes nothing', async () => {
    const w = await world()
    const first = await install(w)
    expect(first.code).toBe(0)
    expect(json(join(w.project, '.omp', 'mcp.json'))).toEqual({ mcpServers: { bag: entry(w.dir) } })
    expect(lstatSync(link(w)).isSymbolicLink()).toBe(true)
    expect(readlinkSync(link(w))).toBe(OMP_WAKE)
    expect(first.out).toContain(`wrote ${link(w)} -> ${OMP_WAKE}`)
    const again = await install(w)
    expect(again.code).toBe(0)
    expect(again.out).toContain('nothing to change')
    expect(again.out).toContain(`unchanged ${link(w)}`)
  })

  it('keeps the other servers and keys of .omp/mcp.json', async () => {
    const w = await world()
    mkdirSync(join(w.project, '.omp'))
    writeFileSync(
      join(w.project, '.omp', 'mcp.json'),
      JSON.stringify({ $schema: 'x', mcpServers: { other: { command: 'o' } } }),
    )
    expect((await install(w)).code).toBe(0)
    expect(json(join(w.project, '.omp', 'mcp.json'))).toEqual({
      $schema: 'x',
      mcpServers: { other: { command: 'o' }, bag: entry(w.dir) },
    })
  })

  it('refuses a bag server with other settings, and a hand-written wake at the link, writing nothing', async () => {
    const w = await world()
    mkdirSync(join(w.project, '.omp'))
    const mcp = join(w.project, '.omp', 'mcp.json')
    writeFileSync(mcp, JSON.stringify({ mcpServers: { bag: { command: 'other' } } }))
    const got = await install(w)
    expect(got.code).toBe(1)
    expect(got.err[0]).toContain('with other settings')
    expect(existsSync(link(w))).toBe(false)

    const v = await world()
    mkdirSync(join(v.project, '.omp', 'hooks', 'pre'), { recursive: true })
    writeFileSync(join(v.project, '.omp', 'hooks', 'pre', 'bag-wake.ts'), '// hand-written\n')
    const hand = await install(v)
    expect(hand.code).toBe(1)
    expect(hand.err[0]).toContain("is not bag's wake link")
    expect(existsSync(join(v.project, '.omp', 'mcp.json'))).toBe(false)
  })

  it('replaces a link of bag to another place, and warns of a bag server in .claude/', async () => {
    const w = await world()
    mkdirSync(join(w.project, '.omp', 'hooks', 'pre'), { recursive: true })
    symlinkSync('/old/home/package/bag-omp-wake.js', join(w.project, '.omp', 'hooks', 'pre', 'bag-wake.js'))
    mkdirSync(join(w.project, '.claude'))
    writeFileSync(join(w.project, '.claude', 'mcp.json'), JSON.stringify({ mcpServers: { bag: {} } }))
    const got = await install(w)
    expect(got.code).toBe(0)
    expect(existsSync(join(w.project, '.omp', 'hooks', 'pre', 'bag-wake.js'))).toBe(false)
    expect(readlinkSync(link(w))).toBe(OMP_WAKE)
    expect(got.out.some((l) => l.startsWith('warning:') && l.includes('.claude'))).toBe(true)
  })

  it('takes no --user, --mode, --identities or --label, and needs --project and --relay', async () => {
    const w = await world()
    for (const extra of [['--user'], ['--mode', 'mcp'], ['--label', 'b']]) {
      expect((await install(w, ...extra)).err[0]).toContain('is not taken by omp')
    }
    const bare = await cli(w.io, 'host', 'install', 'omp', '--as', 'bob', '--dir', w.dir, '--relay', RELAY)
    expect(bare.err[0]).toContain('--project')
    const norelay = await cli(
      w.io,
      'host',
      'install',
      'omp',
      '--as',
      'bob',
      '--dir',
      w.dir,
      '--project',
      w.project,
    )
    expect(norelay.err[0]).toContain('--relay')
  })

  it('warns, read-only, of a relay that holds neither record of a fresh identity, and installs all the same', async () => {
    const w = await world()
    const got = await install(w)
    expect(got.code).toBe(0)
    expect(got.out).toContain(
      `warning: no address and accept-from record at ${RELAY} for bob, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to bob`,
    )
    expect(existsSync(link(w))).toBe(true)
  })

  it('says nothing of records the relay holds, and names a relay that does not answer as unchecked', async () => {
    const w = await world()
    const file = (k: string) => join(w.dir, `${k}.json`)
    expect(
      (
        await cli(
          w.io,
          'record',
          'address',
          'bob',
          '--relay',
          RELAY,
          '--sealing-key',
          '--out',
          file('a'),
          '--dir',
          w.dir,
        )
      ).code,
    ).toBe(0)
    expect((await cli(w.io, 'publish', RELAY, file('a'), '--dir', w.dir)).code).toBe(0)
    const accept = ['record', 'accept-from', 'bob', '--root', '*', '--max-bytes', '65536', '--ttl', '86400']
    expect((await cli(w.io, ...accept, '--out', file('f'), '--dir', w.dir)).code).toBe(0)
    expect((await cli(w.io, 'publish', RELAY, file('f'), '--dir', w.dir)).code).toBe(0)
    const held = await install(w)
    expect(held.out.filter((l) => l.startsWith('warning:'))).toEqual([])
    w.relay.failRecordFetch.set(RELAY, Object.assign(new Error('down'), { code: 'unreachable' }))
    const away = await install(w)
    expect(away.code).toBe(0)
    expect(away.out).toContain(
      `warning: ${RELAY} did not answer (unreachable): the records of bob there were not checked`,
    )
  })

  describe('records held at one relay or in the home copy are republished to a relay that lacks them', () => {
    const R1 = 'http://127.0.0.1:7'
    const R2 = 'http://127.0.0.1:8'
    /** bob's address and accept-from records, signed into files, published at `at` (none: not published). */
    async function signed(w: World, at: readonly string[]): Promise<{ a: string; f: string }> {
      const file = (k: string) => join(w.dir, `${k}.json`)
      const rel = [R1, R2].flatMap((r) => ['--relay', r])
      expect(
        (
          await cli(
            w.io,
            'record',
            'address',
            'bob',
            ...rel,
            '--sealing-key',
            '--out',
            file('a'),
            '--dir',
            w.dir,
          )
        ).code,
      ).toBe(0)
      const accept = ['record', 'accept-from', 'bob', '--root', '*', '--max-bytes', '65536', '--ttl', '86400']
      expect((await cli(w.io, ...accept, '--out', file('f'), '--dir', w.dir)).code).toBe(0)
      for (const url of at) {
        expect((await cli(w.io, 'publish', url, file('a'), '--dir', w.dir)).code).toBe(0)
        expect((await cli(w.io, 'publish', url, file('f'), '--dir', w.dir)).code).toBe(0)
      }
      return { a: file('a'), f: file('f') }
    }
    const installAt = (w: World) =>
      cli(
        w.io,
        'host',
        'install',
        'omp',
        '--as',
        'bob',
        '--dir',
        w.dir,
        '--relay',
        R1,
        '--relay',
        R2,
        '--project',
        w.project,
      )
    const fresh = async () => {
      const w = await world()
      for (const r of [R1, R2]) w.relay.recordsAt.set(r, new Map())
      return w
    }

    it('a relay that lacks them gets the records another named relay holds, published as they are', async () => {
      const w = await fresh()
      await signed(w, [R1])
      const at1 = new Map(w.relay.recordsAt.get(R1))
      const got = await installAt(w)
      expect(got.code).toBe(0)
      expect(got.out.filter((l) => l.startsWith('republished') || l.startsWith('warning'))).toEqual([
        `republished the address record of bob to ${R2} (it was at ${R1}; nothing re-signed)`,
        `republished the accept-from record of bob to ${R2} (it was at ${R1}; nothing re-signed)`,
      ])
      expect([...(w.relay.recordsAt.get(R2)?.values() ?? [])].map((b) => Buffer.from(b).toString())).toEqual(
        [...at1.values()].map((b) => Buffer.from(b).toString()),
      )
      expect(
        (await installAt(w)).out.filter((l) => l.startsWith('republished') || l.startsWith('warning')),
      ).toEqual([])
    })

    it('with no relay holding them, the home copies are published, and with none anywhere it warns of onboard', async () => {
      const w = await fresh()
      const { a, f } = await signed(w, [])
      mkdirSync(join(w.dir, 'records'), { recursive: true })
      writeFileSync(join(w.dir, 'records', 'bob.address.json'), readFileSync(a))
      writeFileSync(join(w.dir, 'records', 'bob.accept.json'), readFileSync(f))
      const got = await installAt(w)
      const lines = got.out.filter((l) => l.startsWith('republished') || l.startsWith('warning'))
      expect(lines.length).toBe(4)
      expect(lines.every((l) => l.startsWith('republished') && l.includes('the home copy'))).toBe(true)
      const v = await fresh()
      const none = await installAt(v)
      expect(none.out.filter((l) => l.startsWith('warning'))).toEqual([
        `warning: no address and accept-from record at ${R1} for bob, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to bob`,
        `warning: no address and accept-from record at ${R2} for bob, and no relay or home copy holds one: run bag onboard first (docs/partner-install.md section 4); until then the relay refuses mail to bob`,
      ])
    })

    it('a relay that refuses the republish is a warning naming record keep', async () => {
      const w = await fresh()
      await signed(w, [R1])
      w.relay.failRecordPublish.set(R2, Object.assign(new Error('no'), { code: 'rate-limited' }))
      const got = await installAt(w)
      expect(got.code).toBe(0)
      expect(got.out.filter((l) => l.startsWith('warning'))).toEqual([
        `warning: ${R2} refused the address record of bob (rate-limited): run bag record keep --once --as bob with every relay`,
        `warning: ${R2} refused the accept-from record of bob (rate-limited): run bag record keep --once --as bob with every relay`,
      ])
    })
  })

  it('host remove omp takes out the identity entry and the link, and refuses another identity', async () => {
    const w = await world()
    mkdirSync(join(w.project, '.omp'))
    writeFileSync(
      join(w.project, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { other: { command: 'o' } } }),
    )
    expect((await install(w)).code).toBe(0)
    const other = await remove(w, 'carol')
    expect(other.code).toBe(1)
    const got = await remove(w)
    expect(got.code).toBe(0)
    expect(json(join(w.project, '.omp', 'mcp.json'))).toEqual({ mcpServers: { other: { command: 'o' } } })
    expect(existsSync(link(w))).toBe(false)
    expect((await remove(w)).out[0]).toBe(`unchanged ${join(w.project, '.omp', 'mcp.json')}`)
  })
})
