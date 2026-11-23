import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import {
  type CallToolResult,
  ElicitRequestSchema,
  type ElicitResult,
} from '@modelcontextprotocol/sdk/types.js'
import { servicePlist, serviceUnit, stableNode } from '@usebag/home'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseConfig } from '../src/config.ts'
import { startServer } from '../src/server.ts'
import { ACT_QUESTIONS } from '../src/tools.ts'
import {
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  RELAY,
  saveKeys,
  seededRng,
  tempDir,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The service tool (T13, T14): after the person's Yes it writes the login agent from home's fixed template, every
// path from the home and the process, and answers the one line the person runs to load it. It never starts a process:
// every spawn of node:child_process throws in this file, so a tool that ran launchctl or systemctl fails here.

vi.mock('node:child_process', async (actual) => {
  const real = (await actual()) as Record<string, unknown>
  const refuse = (): never => {
    throw new Error('the service tool spawned a process')
  }
  return {
    ...real,
    spawn: refuse,
    spawnSync: refuse,
    exec: refuse,
    execFile: refuse,
    execFileSync: refuse,
    execSync: refuse,
  }
})

const tmp = tempDir('service-tool')
const stops: (() => Promise<void>)[] = []
afterEach(async () => {
  for (const s of stops.splice(0)) await s()
})
let n = 0

/** A server of alice with a client that shows dialogs, each answered by `answer`; HOME a fresh folder. */
async function serverWith(answer: () => ElicitResult) {
  const root = join(tmp.dir, `m${n++}`)
  const [home, user] = [join(root, 'h'), join(root, 'user')]
  mkdirSync(home, { recursive: true, mode: 0o700 })
  mkdirSync(user, { recursive: true })
  saveKeys(home, P.alice)
  const config = parseConfig(['--as', P.alice.name, '--dir', home, '--relay', RELAY], {})
  if (config === 'help') throw new Error('help')
  const running = await startServer(config, {
    clock: new FakeClock(),
    rng: seededRng('service-tool'),
    relay: new MemoryRelay(),
    records: fakeRecords(new Map()),
    timers: new ManualTimers(),
    pid: 4242,
    alive: () => false,
    log: new MemoryLog(),
    resubscribeDelayMs: () => 0,
    // A person's pace (0.4.4): each dialog reads as a second, never as answered at once (FAST_ANSWER_MS).
    mono: (
      (t) => () =>
        (t += 1000)
    )(0),
    env: { HOME: user },
  })
  const [a, b] = InMemoryTransport.createLinkedPair()
  await running.mcp.connect(b)
  const client = new Client(
    { name: 'service-tool', version: '0' },
    { capabilities: { elicitation: { form: {} } } },
  )
  const asked: string[] = []
  client.setRequestHandler(ElicitRequestSchema, async (request) => {
    asked.push(request.params.message)
    await new Promise((r) => setTimeout(r, 300))
    return answer()
  })
  await client.connect(a)
  stops.push(async () => {
    await client.close()
    await running.stop()
  })
  const call = async (): Promise<Record<string, unknown>> => {
    const r = (await client.callTool({ name: 'service', arguments: {} })) as CallToolResult
    return JSON.parse((r.content[0] as { text: string }).text) as Record<string, unknown>
  }
  const agentFile =
    process.platform === 'darwin'
      ? join(user, 'Library', 'LaunchAgents', 'dev.bag.service.plist')
      : join(user, '.config', 'systemd', 'user', 'bag.service')
  return { home, user, call, asked, agentFile }
}

describe('the service tool', () => {
  it("T13: after the Yes the agent file is home's fixed template, paths from the home only; the answer is the person's line; no spawn", async () => {
    const s = await serverWith(() => ({ action: 'accept', content: { confirm: true } }))
    const r = await s.call()
    expect(s.asked).toEqual([ACT_QUESTIONS.service.message])
    // Byte for byte home's fixed template, with the home's launcher as its main and the server's own environment.
    const fixed = (process.platform === 'darwin' ? servicePlist : serviceUnit)({
      node: stableNode(process.execPath),
      main: join(s.home, 'package', 'bag-mcp.js'),
      home: s.home,
      identities: join(s.home, 'identities.json'),
      env: { HOME: s.user },
    })
    expect(readFileSync(s.agentFile, 'utf8')).toBe(fixed)
    const lines = r.lines as string[]
    expect(lines[0]).toBe(`wrote ${s.agentFile}`)
    expect(lines.at(-1)).toMatch(
      process.platform === 'darwin'
        ? /^to load it, run in a terminal: launchctl bootstrap gui\/\d+ /
        : /^to load it, run in a terminal: systemctl --user daemon-reload && systemctl --user enable --now bag$/,
    )
    // A second Yes finds the same text: unchanged, the same line.
    const again = await s.call()
    expect((again.lines as string[])[0]).toBe(`unchanged ${s.agentFile}`)
    expect(existsSync(join(s.home, 'run'))).toBe(true)
  })

  it('T14: the question says the agent starts bag at every login; a No or no answer writes no file', async () => {
    expect(ACT_QUESTIONS.service.message).toContain('starts the bag service')
    expect(ACT_QUESTIONS.service.message).toContain('at every login')
    const no = await serverWith(() => ({ action: 'accept', content: { confirm: false } }))
    expect(await no.call()).toMatchObject({ error: 'declined' })
    expect(existsSync(no.agentFile)).toBe(false)
    const none = await serverWith(() => ({ action: 'cancel' }))
    expect(await none.call()).toMatchObject({ error: 'cancelled' })
    expect(existsSync(none.agentFile)).toBe(false)
    expect(readdirSync(none.user)).toEqual([])
  })
})
