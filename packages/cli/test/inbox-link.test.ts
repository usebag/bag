import { RelayError, type SubscriptionLink } from '@usebag/edge'
import { afterAll, expect, it } from 'vitest'
import { linkLines } from '../src/commands/inbox.ts'
import type { CliRelay } from '../src/io.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// A live `ac inbox` on a relay that refuses it: the WebSocket retries for good and no frame ever comes, so these lines
// are all a person gets. A retry that fails again says nothing new.

const tmp = tempDir('inbox-link')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const lost: SubscriptionLink = {
  admitted: false,
  error: new RelayError(null, 0, null, `${RELAY}: refused`),
}
const lostLine = `bag: no response: ${RELAY}: refused; trying again`

/** A relay that reports each of `script` to the subscription it makes. */
class ReportingRelay extends MemoryRelay {
  readonly #script: SubscriptionLink[][]

  constructor(script: SubscriptionLink[][]) {
    super()
    this.#script = script
  }

  override subscribe(...[url, mailbox, signer, hops, cursor, onLink]: Parameters<CliRelay['subscribe']>) {
    for (const link of this.#script.shift() ?? []) onLink?.(link)
    return super.subscribe(url, mailbox, signer, hops, cursor)
  }
}

/** The lines `ac inbox <mode>` wrote about its connection. */
async function reported(mode: string, script: SubscriptionLink[][]): Promise<string[]> {
  const relay = new ReportingRelay(script)
  const io = testIo(relay)
  const dir = `${tmp.dir}/${mode}`
  await cli(io, 'keygen', 'bob', '--dir', dir)
  const running = cli(io, 'inbox', mode, '--as', 'bob', '--relay', RELAY, '--dir', dir)
  if (mode === '--watch') {
    while (relay.subs.size === 0) await new Promise((done) => setTimeout(done, 5))
    io.stop.abort()
  }
  await running
  return io.stderr.filter((line) => /trying again|subscribed again/.test(line))
}

it('says once that the connection went, and once that it came back', () => {
  const lines: string[] = []
  const report = linkLines({ err: (line) => lines.push(line) })
  report({ admitted: true })
  expect(lines).toEqual([])
  report(lost)
  report(lost)
  expect(lines).toEqual([lostLine])
  report({ admitted: true })
  report({ admitted: true })
  report(lost)
  expect(lines.slice(1)).toEqual(['bag: subscribed again', lostLine])
})

it('a live inbox prints them', async () => {
  const lines = await reported('--watch', [[lost, { admitted: true }]])
  expect(lines).toEqual([lostLine, 'bag: subscribed again'])
})

it('a one-shot inbox prints none: a connection lost fails the command with the reason', async () => {
  expect(await reported('--once', [[lost]])).toEqual([])
})
