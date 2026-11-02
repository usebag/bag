import { join } from 'node:path'
import { parseRecord, verifyRecord } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// record accept-from with domain roots: the CLI takes `domain:<host>` beside
// addresses, checks each root through the core and writes the roots back as given.

const tmp = tempDir('record-domain')
afterAll(() => tmp.cleanup())

describe('record accept-from --root domain:<host>', () => {
  it('signs domain roots beside addresses, in their order, and names a bad root', async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, 'home')
    const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
    const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const args = ['--max-bytes', '65536', '--ttl', '86400', '--dir', dir]
    const roots = ['--root', 'domain:acme.usuals.now', '--root', alice, '--root', 'domain:globex.usuals.now']
    const r = await cli(io, 'record', 'accept-from', 'bob', ...roots, ...args)
    expect(r.code).toBe(0)
    expect(verifyRecord(parseRecord(r.out[0] as string), T0)).toMatchObject({
      kind: 'accept-from',
      owner: bob,
      roots: ['domain:acme.usuals.now', alice, 'domain:globex.usuals.now'],
    })
    for (const bad of ['domain:ACME.usuals.now', 'domain:127.0.0.1', 'domain:localhost', 'acme.usuals.now']) {
      const refused = await cli(io, 'record', 'accept-from', 'bob', '--root', bad, ...args)
      expect([refused.code, refused.err[0]], bad).toEqual([
        1,
        `bag: bad-record: ${JSON.stringify(bad)} is not an address, "*" or domain:<host>`,
      ])
    }
    const twice = await cli(
      io,
      'record',
      'accept-from',
      'bob',
      '--root',
      'domain:a.b',
      '--root',
      'domain:a.b',
      ...args,
    )
    expect(twice.err[0]).toBe(
      'bag: bad-record: roots lists distinct addresses and domain:<host> entries, or is ["*"]',
    )
  })
})
