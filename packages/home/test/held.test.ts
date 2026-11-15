import { mkdirSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { describeHolder, holder, lockHolder, refuseWhileHeld, servers } from '../src/index.ts'
import { folder } from './support.ts'

// Who holds an identity: the live MCP server its mcp.lock names.

const lock = (home: string, name: string, body: unknown): string => {
  mkdirSync(join(home, 'state', name), { recursive: true })
  const file = join(home, 'state', name, 'mcp.lock')
  writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body))
  return file
}

describe('holder and lockHolder', () => {
  it('is null with no lock, an unreadable lock, a pid that is not one, or a pid that is gone', () => {
    const home = folder()
    expect(holder(home, 'jane')).toBeNull()
    const file = lock(home, 'jane', '{')
    expect(lockHolder(file)).toBeNull()
    lock(home, 'jane', { pid: 1 })
    expect(lockHolder(file)).toBeNull()
    lock(home, 'jane', { pid: 'x' })
    expect(lockHolder(file)).toBeNull()
    lock(home, 'jane', { pid: 4242 })
    expect(lockHolder(file, { alive: () => false })).toBeNull()
  })

  it('names a live pid with what the lock gives, unless it started after the lock was written', () => {
    const home = folder()
    const file = lock(home, 'jane', { pid: 4242, started_at: 'then', cwd: '/w', host: 'claude-code' })
    const procs = { alive: () => true, startOf: () => null }
    expect(lockHolder(file, procs)).toEqual({ pid: 4242, startedAt: 'then', cwd: '/w', host: 'claude-code' })
    utimesSync(file, 1000, 1000)
    expect(lockHolder(file, { alive: () => true, startOf: () => 2_000_000_000 })).toBeNull()
    lock(home, 'kim', { pid: 4242 })
    expect(holder(home, 'kim', procs)).toEqual({ pid: 4242, startedAt: null, cwd: null, host: null })
  })

  it('reads a live process of its own, and refuses a receiving act beside it (held)', () => {
    const home = folder()
    lock(home, 'jane', { pid: process.pid })
    expect(holder(home, 'jane')?.pid).toBe(process.pid)
    expect(() => refuseWhileHeld(home, 'jane', 'inbox')).toThrow(
      `held: the identity jane is held by a running bag MCP server (pid ${process.pid})`,
    )
    expect(() => refuseWhileHeld(home, 'kim', 'inbox')).not.toThrow()
    // The service's own quiet of that label passes it; its word on another label does not.
    expect(() => refuseWhileHeld(home, 'jane', 'identity remove', (n) => n === 'jane')).not.toThrow()
    expect(() => refuseWhileHeld(home, 'jane', 'identity remove', (n) => n === 'kim')).toThrow('held:')
    expect(servers(home, 'kim')).toEqual([`jane (pid ${process.pid})`])
    expect(servers(home, 'jane')).toEqual([])
    expect(servers(folder(), 'jane')).toEqual([])
  })
})

describe('describeHolder', () => {
  it('says the pid, then start, host and folder when the lock gave them', () => {
    expect(describeHolder({ pid: 7, startedAt: null, cwd: null, host: null })).toBe('pid 7')
    expect(describeHolder({ pid: 7, startedAt: 't', cwd: '/w', host: 'codex' })).toBe(
      'pid 7, started t, codex, in /w',
    )
  })
})
