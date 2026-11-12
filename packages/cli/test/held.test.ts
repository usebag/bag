import { mkdirSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { describeHolder, holder, refuseWhileHeld, servers } from '../src/held.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('held')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0

/** A home with the identity bob and, when `lock` is given, its mcp.lock. */
async function home(lock?: unknown): Promise<{ dir: string; io: ReturnType<typeof testIo> }> {
  const io = testIo(new MemoryRelay())
  const dir = join(tmp.dir, `home-${n++}`)
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  if (lock !== undefined) {
    mkdirSync(join(dir, 'state', 'bob'), { recursive: true })
    writeFileSync(
      join(dir, 'state', 'bob', 'mcp.lock'),
      typeof lock === 'string' ? lock : JSON.stringify(lock),
    )
  }
  return { dir, io }
}

const live = { pid: process.pid, started_at: '2026-11-11T12:00:00.000Z', cwd: '/work/a', host: 'omp' }

describe('the CLI beside an MCP server that holds the identity', () => {
  it('reads the holder from a live lock, and from one an older server wrote (the pid alone)', async () => {
    const a = await home(live)
    expect(holder(a.dir, 'bob')).toEqual({
      pid: process.pid,
      startedAt: '2026-11-11T12:00:00.000Z',
      cwd: '/work/a',
      host: 'omp',
    })
    expect(describeHolder(holder(a.dir, 'bob') as NonNullable<ReturnType<typeof holder>>)).toBe(
      `pid ${process.pid}, started 2026-11-11T12:00:00.000Z, omp, in /work/a`,
    )
    const b = await home({ pid: process.pid })
    expect(holder(b.dir, 'bob')).toEqual({ pid: process.pid, startedAt: null, cwd: null, host: null })
  })

  it('is no holder: no lock, a dead pid, an unreadable lock, a pid that is not a number', async () => {
    expect(holder((await home()).dir, 'bob')).toBeNull()
    expect(holder((await home({ pid: 2 ** 22 + 12345 })).dir, 'bob')).toBeNull()
    expect(holder((await home('not json')).dir, 'bob')).toBeNull()
    expect(holder((await home({ pid: '7' })).dir, 'bob')).toBeNull()
    expect(holder((await home({ pid: 1 })).dir, 'bob')).toBeNull()
  })

  it('inbox refuses with held, naming the holder and the way on, and status prints held_by', async () => {
    const { dir, io } = await home(live)
    const r = await cli(io, 'inbox', '--as', 'bob', '--dir', dir, '--relay', RELAY, '--once')
    expect(r.code).not.toBe(0)
    expect(r.err.join('\n')).toMatch(
      /held: the identity bob is held by a running bag MCP server \(pid \d+, started 2026-11-11T12:00:00.000Z, omp, in \/work\/a\); that session reads this mailbox with its inbox tool, so inbox needs that session closed first/,
    )
    const s = await cli(io, 'status', '--as', 'bob', '--dir', dir)
    expect(s.out).toContain(`held_by pid ${process.pid}, started 2026-11-11T12:00:00.000Z, omp, in /work/a`)
    expect(() => refuseWhileHeld(dir, 'bob', 'inbox release')).toThrow(
      /inbox release needs that session closed/,
    )
  })

  it('inbox and status are as before when nothing holds the identity', async () => {
    const { dir, io } = await home({ pid: 2 ** 22 + 12345 })
    const s = await cli(io, 'status', '--as', 'bob', '--dir', dir)
    expect(s.out.join('\n')).not.toContain('held_by')
    const r = await cli(io, 'inbox', '--as', 'bob', '--dir', dir, '--relay', RELAY, '--once')
    expect(r.err.join('\n')).not.toContain('held:')
  })
})

describe('the servers of a home (host install refuses to replace <home>/package under them)', () => {
  it('names each live holder but the one left out; a dead pid, no lock and no state folder name none', async () => {
    const { dir } = await home(live)
    const lock = (name: string, body: unknown) => {
      mkdirSync(join(dir, 'state', name), { recursive: true })
      writeFileSync(join(dir, 'state', name, 'mcp.lock'), JSON.stringify(body))
    }
    lock('qrfolk', { pid: process.pid })
    lock('gone', { pid: 2 ** 22 + 12345 })
    mkdirSync(join(dir, 'state', 'nolock'), { recursive: true })
    expect(servers(dir, 'bob')).toEqual([`qrfolk (pid ${process.pid})`])
    expect(servers(dir, 'qrfolk').sort()).toEqual([`bob (pid ${process.pid})`])
    expect(servers(join(tmp.dir, 'no-home'), 'bob')).toEqual([])
  })
})

describe('the servers of a home: a pid used again', () => {
  it('a live pid that started after the lock was written (mtime plus START_TOLERANCE) is no server', async () => {
    const { dir } = await home({ pid: process.pid })
    const lock = join(dir, 'state', 'bob', 'mcp.lock')
    expect(servers(dir, 'nobody')).toEqual([`bob (pid ${process.pid})`])
    const past = new Date('2000-01-01T00:00:00Z')
    utimesSync(lock, past, past)
    expect(servers(dir, 'nobody')).toEqual([])
  })
})
