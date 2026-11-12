import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { crontabLine, launchdJob } from '../src/commands/keep-schedule.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The other writers of a node path, after stableNode (packaged.ts): record keep's launchd job and crontab line
// (keep-schedule.ts) and onboard's printed commands and cron line. The node is mocked to a link (never run), so the
// test needs no Homebrew. These writers print text and write no file, so there is no earlier entry to replace.

const LINK = '/opt/homebrew/bin/node'
vi.mock('../src/packaged.ts', async (orig) => ({
  ...(await orig<typeof import('../src/packaged.ts')>()),
  stableNode: () => LINK,
}))

const tmp = tempDir('stable-node-writers')
afterAll(() => tmp.cleanup())
const RELAY = 'http://203.0.113.9'

describe('the launchd job and crontab line name the node they are given, stableNode by default', () => {
  it('an injected node is written first, then the CLI', () => {
    expect(crontabLine(['x'], '/l', '/cli.js', null, '/n/node')).toMatch(
      / \/n\/node \/cli\.js x >> \/l 2>&1$/,
    )
    expect(launchdJob('bag.t', ['x'], '/l', '/cli.js', null, '/n/node')).toContain(
      '    <string>/n/node</string>\n    <string>/cli.js</string>\n    <string>x</string>',
    )
  })

  it('record keep --crontab and --plist write the link', async () => {
    const keep = ['record', 'keep', '--as', 'bob', '--relay', RELAY, '--dir', '/home/u/.bag']
    const io = testIo(new MemoryRelay())
    expect((await cli(io, ...keep, '--crontab')).out[0]).toContain(` ${LINK} `)
    expect((await cli(io, ...keep, '--plist')).out.join('\n')).toContain(`<string>${LINK}</string>`)
    expect((await cli(io, ...keep, '--crontab')).out[0]).not.toContain(process.execPath)
  })

  it("onboard's next commands and cron line start with the link", async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, 'home')
    const inviter = (await cli(io, 'keygen', 'inviter', '--dir', join(tmp.dir, 'inviter'))).out[0] as string
    const args = ['jane', '--domain', 'acme.test', '--relay', RELAY, '--accept', inviter, '--dir', dir]
    const out = (await cli(io, 'onboard', ...args)).out
    // Every printed command of the CLI: the next steps and the cron line.
    const lines = out.filter((l) => l.includes(' src/main.ts ') || l.includes('/src/main.ts '))
    expect(lines.some((l) => l.startsWith('cron '))).toBe(true)
    for (const l of lines)
      expect([l.includes(` ${LINK} `), l.includes(process.execPath)]).toEqual([true, false])
  })
})
