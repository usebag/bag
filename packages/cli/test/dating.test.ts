import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DEFAULT_SKEW, DEFAULT_TTL } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import {
  type AgentHome,
  agentHome,
  CAVEAT,
  heldAddress,
  loggedInAt,
  publishRecord,
  RELAY,
  sessionAddress,
} from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli, type Ran } from './support/run.ts'

// The agent's revoked entries dated across windows: each
// `ac login` is its own process, so the hop exps the agent saw are kept in <home>/agent-revoked-exp.json (0600), read
// at login and written at the window's end. Kill criterion K0-4: the third window's logout drops a first-window entry
// past exp + TTL + skew, and drops nothing still inside that bound.

const tmp = tempDir('dating')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
const dir = (): string => join(tmp.dir, `h${n++}`)
const HOLD = DEFAULT_TTL + DEFAULT_SKEW
const W2 = T0 + 1000
/** Past the first window's grant (exp T0 + 60) by TTL + skew, inside the second's (exp W2 + 60). */
const W3 = T0 + 60 + HOLD + 1

/** One window at `at`: a login, a first grant of `life` s to `session` after a y, and ac logout. */
async function window(
  relay: MemoryRelay,
  h: AgentHome,
  at: number,
  session: string,
  life = 60,
): Promise<[Ran, Ran]> {
  const login = await loggedInAt(relay, h, at)
  login.io.lines.push('y')
  const io = testIo(relay)
  io.time.now = at
  const args = ['--as', 'jane', '--session', session, '--caveat', CAVEAT, `--exp=+${life}`, '--dir', h.dir]
  expect((await cli(io, 'grant', ...args)).code).toBe(0)
  const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
  return [out, await login.ran]
}

/** A home with jane's address record at the relay, and its dated file. */
function home(relay: MemoryRelay): { h: AgentHome; file: string } {
  const h = agentHome(dir())
  publishRecord(relay, h)
  return { h, file: join(h.dir, `agent-revoked-exp.${h.address}.json`) }
}

describe('revoked entries dated across windows (K0-4)', () => {
  it('drops a first-window entry past exp + TTL + skew at the third logout, and keeps the entry of the second', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    const [S1, S2, S3] = [sessionAddress(), sessionAddress(), sessionAddress()]
    await window(relay, h, T0, S1)
    expect(heldAddress(relay, h.address).revoked).toEqual([S1])
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ [S1]: T0 + 60 })
    await window(relay, h, W2, S2)
    expect([...heldAddress(relay, h.address).revoked].sort()).toEqual([S1, S2].sort())
    const [out, login] = await window(relay, h, W3, S3)
    expect([out.code, login.code]).toEqual([0, 0])
    expect([...heldAddress(relay, h.address).revoked].sort()).toEqual([S2, S3].sort())
  })

  it('keeps every entry undated when the file is corrupt, so none is dropped early', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    const [S1, S3] = [sessionAddress(), sessionAddress()]
    await window(relay, h, T0, S1)
    writeFileSync(file, '{"not": "a number"}')
    await window(relay, h, W3, S3)
    expect([...heldAddress(relay, h.address).revoked].sort()).toEqual([S1, S3].sort())
  })

  it('dates a subject by its latest grant across windows', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    const [S, S3] = [sessionAddress(), sessionAddress()]
    await window(relay, h, T0, S)
    await window(relay, h, W2, S, 3600)
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ [S]: W2 + 3600 })
    await window(relay, h, W3, S3)
    expect([...heldAddress(relay, h.address).revoked].sort()).toEqual([S, S3].sort())
  })

  it('keeps a subject undated when the window that re-granted it could not write the file (B2)', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    const [S, S3] = [sessionAddress(), sessionAddress()]
    await window(relay, h, T0, S)
    mkdirSync(`${file}.tmp`)
    await window(relay, h, W2, S, 3600)
    expect(existsSync(file)).toBe(false)
    await window(relay, h, W3, S3)
    expect([...heldAddress(relay, h.address).revoked].sort()).toEqual([S, S3].sort())
  })

  it('makes a manual revoke undated, so a later window keeps it', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    const S = sessionAddress()
    await window(relay, h, T0, S)
    const args = ['address', 'jane-keys', '--relay', RELAY, '--revoke', S, '--dir', h.dir]
    const made = await cli(testIo(relay), 'record', ...args)
    expect(made.code).toBe(0)
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({})
  })

  it('publishes the record when the file cannot be written, and says so', async () => {
    const relay = new MemoryRelay()
    const { h, file } = home(relay)
    mkdirSync(`${file}.tmp`)
    const S1 = sessionAddress()
    const [out, login] = await window(relay, h, T0, S1)
    expect([out.code, login.code]).toEqual([0, 0])
    expect(heldAddress(relay, h.address).revoked).toEqual([S1])
    expect(login.err.at(-1)).toMatch(new RegExp(`^bag: ${file} not written \\(`))
  })
})
