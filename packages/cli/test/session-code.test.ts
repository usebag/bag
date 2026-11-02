import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  resolveSessionName,
  SessionFileError,
  SessionNameError,
  type SessionNameOptions,
  writeSessionFile,
} from '@usebag/edge/agent'
import { afterAll, describe, expect, it } from 'vitest'
import { sessionCode } from '../src/commands/wake-hook.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// session-code: the one JSON line a synchronous SessionStart hook prints while a grant request waits. The process
// tree is a fake one (the anchor options), the poll and the wait are short, and the session file is written with the
// real writeSessionFile, as the MCP server does.

const tmp = tempDir('session-code')
afterAll(() => tmp.cleanup())
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
let n = 0

/** A fake process tree: this hook (pid 10) under a `claude` (pid 100) that started at 1000. */
const tree: SessionNameOptions = {
  pid: 10,
  info: (pid) =>
    pid === 10
      ? { ppid: 100, command: 'node main.ts session-code' }
      : pid === 100
        ? { ppid: 1, command: '/usr/local/bin/claude' }
        : null,
  startOf: () => 1000,
}

/** A home with the identity bob and the session file the server writes for the fake tree. */
async function world() {
  const io = testIo(new MemoryRelay())
  const dir = join(tmp.dir, `home-${n++}`)
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  const address = (await cli(io, 'address', 'bob', '--dir', dir)).out[0] as string
  const { name, anchor } = resolveSessionName(address, tree)
  io.stdout.length = 0
  io.stderr.length = 0
  const state = join(dir, 'state', name)
  mkdirSync(state, { recursive: true })
  return {
    io,
    dir,
    name,
    address,
    anchor,
    serve: () => writeSessionFile(dir, { v: 1, name, principal: address, ...anchor }),
    request: (text: string) => writeFileSync(join(state, 'grant-request.json'), text),
    grant: () => writeFileSync(join(state, 'grant.json'), '{}'),
  }
}
const run = (w: Awaited<ReturnType<typeof world>>, waitMs = 300) =>
  sessionCode(['--as', 'bob', '--session', 'auto', '--dir', w.dir], w.io, 5, tree, waitMs)
const line = (name: string, code: string): string => {
  const text = `bag: session ${name} waits for y at the agent, request code ${code}. Type y there only if the codes match.`
  return JSON.stringify({
    systemMessage: text,
    hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: text },
  })
}

describe('session-code: the request code at session start', () => {
  it('prints the code as one JSON line, systemMessage and additionalContext the same sentence, exit 0', async () => {
    const w = await world()
    w.serve()
    w.request(JSON.stringify({ v: 1, code: 'a"b\nc', at: 1_800_000_000 }))
    expect(await run(w)).toBe(0)
    expect(w.io.stdout).toEqual([line(w.name, 'a"b\nc')])
    expect(w.io.stdout[0]).toContain('a\\"b\\nc') // the quote and the newline are escaped in the one line
    expect(w.io.stderr).toEqual([])
  })

  it('prints nothing, exit 0, when a grant is already given', async () => {
    const w = await world()
    w.serve()
    w.request(JSON.stringify({ v: 1, code: 'k7Q2', at: 1_800_000_000 }))
    w.grant()
    expect(await run(w)).toBe(0)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
  })

  it('prints nothing, exit 0, when no request appears within the wait, and takes about the wait', async () => {
    const w = await world()
    w.serve()
    const t0 = Date.now()
    expect(await run(w, 150)).toBe(0)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(140)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
  })

  it('ends 0, silent, when a grant.json appears while it polls', async () => {
    const w = await world()
    w.serve()
    const t0 = Date.now()
    const waiting = run(w, 5000)
    await sleep(40)
    w.grant()
    expect(await waiting).toBe(0)
    expect(Date.now() - t0).toBeLessThan(2000)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
  })

  it('has one deadline for the session file and the request: a file served late leaves the rest of the wait', async () => {
    const w = await world()
    const t0 = Date.now()
    const waiting = run(w, 150)
    await sleep(100)
    w.serve()
    expect(await waiting).toBe(0)
    expect(Date.now() - t0).toBeLessThan(400)
    expect([w.io.stdout, w.io.stderr]).toEqual([[], []])
  })

  it('treats a request file that does not parse (or is not version 1) as absent and goes on polling', async () => {
    const w = await world()
    w.serve()
    w.request('{"v":1,"co')
    const waiting = run(w, 2000)
    await sleep(40)
    expect(w.io.stdout).toEqual([])
    w.request(JSON.stringify({ v: 2, code: 'no' }))
    await sleep(40)
    expect(w.io.stdout).toEqual([])
    w.request(JSON.stringify({ v: 1, code: 'zz9', at: 1 }))
    expect(await waiting).toBe(0)
    expect(w.io.stdout).toEqual([line(w.name, 'zz9')])
  })

  it('prints a request, and waits for the session file first, when they appear mid-wait', async () => {
    const w = await world()
    const waiting = run(w, 2000)
    await sleep(40)
    w.serve()
    await sleep(40)
    expect(w.io.stdout).toEqual([])
    w.request(JSON.stringify({ v: 1, code: 'ab12', at: 1_800_000_001 }))
    expect(await waiting).toBe(0)
    expect(w.io.stdout).toEqual([line(w.name, 'ab12')])
  })

  it('ends 0, silent, on the stop signal during the wait', async () => {
    const w = await world()
    w.serve()
    const waiting = run(w, 60_000)
    await sleep(40)
    w.io.stop.abort()
    expect(await waiting).toBe(0)
    expect(w.io.stdout).toEqual([])
  })

  it('refuses a malformed session file (SessionFileError), no claude ancestor, no file in the wait, a file of another principal', async () => {
    const w = await world()
    mkdirSync(join(w.dir, 'state', 'sessions'), { recursive: true })
    writeFileSync(join(w.dir, 'state', 'sessions', `${w.anchor.pid}-${w.anchor.start}.json`), '{"v":1,')
    await expect(run(w)).rejects.toThrow(SessionFileError)
    const none: SessionNameOptions = { pid: 10, info: () => null, startOf: () => 1 }
    const argv = ['--as', 'bob', '--session', 'auto', '--dir', w.dir]
    await expect(sessionCode(argv, w.io, 5, none)).rejects.toThrow(SessionNameError)
    const empty = await world()
    await expect(run(empty, 60)).rejects.toThrow(/no-session-file: no file for pid 100/)
    const other = await world()
    writeSessionFile(other.dir, { v: 1, name: other.name, principal: w.address, ...other.anchor })
    await expect(run(other)).rejects.toThrow(/session-principal/)
    const x = await cli(w.io, 'session-code', '--as', 'bob', '--session', 'x', '--dir', w.dir)
    expect(x.code).toBe(1)
  })
})
