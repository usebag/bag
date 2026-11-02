import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, onTestFinished } from 'vitest'
import { startRelay, until, withSpawnedRelays } from './harness.ts'

// The harness's own spawn contract, not a scenario: the relay it starts runs with --exit-on-stdin-eof on a stdin
// pipe this process holds, so that a relay never outlives a test run killed or crashed before its stop() ran (ten
// relays were left on one Mac that way, 2026-10-27). Ending the pipe here stands in for this process ending, which
// closes it the same way. Spawned even under AC_RELAY_URL, as the adversarial rows spawn theirs.
describe('e2e harness: the relay it spawns', () => {
  it('runs with --exit-on-stdin-eof and stops cleanly within 5 s of its stdin pipe closing', async () => {
    const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-e2e-harness-'))
    const relay = await withSpawnedRelays(() => startRelay(dir))
    onTestFinished(async () => {
      await relay.stop()
      if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
    })
    const { child } = relay
    if (child === null || child.stdin === null) throw new Error('no stdin pipe on the relay')
    expect(child.spawnargs).toContain('--exit-on-stdin-eof')
    const health = await fetch(`${relay.url}/v0/health`)
    await health.arrayBuffer()
    expect(health.status).toBe(200)

    const closed = Date.now()
    child.stdin.end()
    await until('the relay to exit', () => child.exitCode !== null || child.signalCode !== null, 5_000)
    console.log(`MEASURE harness stdin-eof: exit ${Date.now() - closed} ms after stdin closed`)
    expect([child.exitCode, child.signalCode]).toEqual([0, null])
    const events = relay
      .stderr()
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => (JSON.parse(l) as { fields: { event?: string } }).fields.event)
    expect(events[0]).toBe('listening')
    expect(events.filter((e) => e === 'stdin-eof')).toHaveLength(1)
    expect(events.at(-1)).toBe('stopped')
    expect(await relay.stop()).toEqual({ code: 0, signal: null })
  })
})
