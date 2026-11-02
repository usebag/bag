import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { readSessionFile, resolveSessionName } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { P, type TestServer } from './support/fixtures.ts'
import { type AgentHome, agentHome, eventually, sessionServerOf, TREE } from './support/sessions.ts'

// --session auto: the name comes from the main claude process; the server leaves the hook its session
// file and, while a grant is asked, the request code; with no claude above it, it refuses visibly and makes nothing.

let h: AgentHome
let s: TestServer | null

beforeEach(async () => {
  h = await agentHome()
  h.agent.login(P.jane.keys)
  s = null
})

afterEach(async () => {
  await s?.close()
  await h.agent.close()
  h.tmp.cleanup()
})

const anchor = { pid: 200, start: 1_793_000_000 }
const sessionsDir = (): string => join(h.tmp.dir, 'state', 'sessions')

describe('--session auto', () => {
  it('names the session from the main claude, makes its key, and leaves the hook its session file', async () => {
    const { name } = resolveSessionName(P.jane.address, TREE)
    s = await sessionServerOf(h, 'auto', 1, TREE)
    expect(existsSync(join(h.tmp.dir, 'keys', `${name}.json`))).toBe(true)
    expect(readSessionFile(h.tmp.dir, anchor)).toEqual({ v: 1, name, principal: P.jane.address, ...anchor })
    h.type('y')
    await s.running.ready
    expect((await s.call('status')).value).toMatchObject({ session: name })
  })

  it('removes its session file at close, and leaves one that names another session', async () => {
    const { name } = resolveSessionName(P.jane.address, TREE)
    s = await sessionServerOf(h, 'auto', 1, TREE)
    await s.close()
    s = null
    expect(readSessionFile(h.tmp.dir, anchor)).toBeNull()
    s = await sessionServerOf(h, 'auto', 1, TREE)
    const file = join(sessionsDir(), '200-1793000000.json')
    writeFileSync(
      file,
      JSON.stringify({ v: 1, name: `s-${'0'.repeat(16)}`, principal: P.jane.address, ...anchor }),
    )
    expect(name).not.toBe(`s-${'0'.repeat(16)}`)
    await s.close()
    s = null
    expect(readSessionFile(h.tmp.dir, anchor)?.name).toBe(`s-${'0'.repeat(16)}`)
  })

  it('refuses no-session with no claude above the server: nothing is made, no other name is used', async () => {
    await expect(sessionServerOf(h, 'auto', 1, { ...TREE, pid: 900 })).rejects.toMatchObject({
      code: 'no-session',
      message: expect.stringContaining('start it from one'),
    })
    expect(readdirSync(join(h.tmp.dir, 'keys')).filter((f) => f.startsWith('s-'))).toEqual([])
    expect(existsSync(join(h.tmp.dir, 'state'))).toBe(false)
    expect(existsSync(sessionsDir())).toBe(false)
  })
})

describe('the request code file', () => {
  it('holds the code the agent shows while the grant waits, and goes with the y', async () => {
    s = await sessionServerOf(h, 's-one', 1, undefined)
    const file = join(h.tmp.dir, 'state', 's-one', 'grant-request.json')
    await eventually('the code', async () => h.codes().length === 1 && existsSync(file))
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ v: 1, code: h.codes()[0] })
    h.type('y')
    await s.running.ready
    expect(existsSync(file)).toBe(false)
  })
})
