import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { serializeHandleRecord, signHandleRecord, utf8 } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  DEFAULT_RELAY_CMD,
  now,
  type Party,
  party,
  rawPublish,
  relayEvents,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 33 (spec/SPEC.md §7.1, §8.2, §8.8): the release relay serves nothing new for
// handles. (a) A handle record published is 400 bad-record, as any kind the relay does not keep, and a fetch of the
// kind handle is 404; (b) the test-only --dns-resolve is refused (exit 2) unless the relay listens on loopback, and on
// loopback it logs a dns-resolve warning naming its names, and the listening line names the fixed TXT source.

describe('e2e scenario 33: the relay serves nothing new for handles, and --dns-resolve is loopback-only', () => {
  it('(33) a handle record is 400 bad-record at publish and 404 at fetch; --dns-resolve exits 2 on 0.0.0.0, and on loopback warns with its names', async () => {
    const name = '_bag.acme.e2e.test'
    const w = await withSpawnedRelays(() =>
      world('s33', { relayArgs: ['--bind', '127.0.0.1', '--dns-resolve', `${name}="v=ac1"`] }),
    )
    const [org, jane] = ['org', 'jane'].map((n) => party(n)) as [Party, Party]
    const handle = signHandleRecord(org.signing, {
      kind: 'handle',
      org: org.address,
      handle: 'jane@acme.e2e.test',
      address: jane.address,
      iat: now(),
      ttl: 3600,
    })
    expect(await rawPublish(w.url, serializeHandleRecord(handle))).toEqual({
      status: 400,
      body: { error: 'bad-record' },
      retryAfter: null,
    })
    const fetched = await fetch(`${w.url}/v0/fetch/record/${org.address}/handle`)
    expect([fetched.status, await fetched.json()]).toEqual([404, { error: 'not-found' }])
    const events = relayEvents(w.relay)
    expect(events.find((e) => e.event === 'listening')?.txt).toBe('fixed')
    expect(events.filter((e) => e.event === 'dns-resolve').map((e) => e.names)).toEqual([name])

    const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
    const refused = spawnSync(
      cmd,
      [
        '--port',
        '0',
        '--bind',
        '0.0.0.0',
        '--db',
        join(w.dir, 'never.sqlite'),
        '--dns-resolve',
        `${name}="v=ac1"`,
      ],
      { timeout: 10_000 },
    )
    expect(refused.status).toBe(2)
    expect(String(refused.stderr)).toContain('loopback --bind')
    expect(String(refused.stdout)).toBe('')
    const badValue = spawnSync(
      cmd,
      ['--port', '0', '--db', join(w.dir, 'never.sqlite'), '--dns-resolve', 'no-equals'],
      {
        timeout: 10_000,
      },
    )
    expect(badValue.status).toBe(2)
    expect(utf8(String(badValue.stdout)).length).toBe(0)
  })
})
