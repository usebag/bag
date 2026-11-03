import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { Audit, type AuditEntry, FsAuditSink, generateEdgeKeys, HomeCustody, RelayError } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('status')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0

/** status's first line, always: bob's doorbell, an absolute path whether or not the file exists. */
const bell = (dir: string): string => `doorbell ${join(dir, 'state', 'bob', 'doorbell')}`

/** A home with the identity bob (a key file), its io and its relay. */
async function home(): Promise<{ dir: string; io: ReturnType<typeof testIo>; relay: MemoryRelay }> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  expect((await cli(io, 'keygen', 'bob', '--dir', dir)).code).toBe(0)
  return { dir, io, relay }
}

/** bob's audit log, written by the edge's Audit as the receiver writes it, one line per entry given. */
function log(dir: string, entries: readonly AuditEntry[]): string {
  const state = join(dir, 'state', 'bob')
  mkdirSync(state, { recursive: true })
  const file = join(state, 'audit.jsonl')
  const audit = new Audit(new FsAuditSink(file), { now: () => T0 })
  for (const e of entries) audit.record(e)
  return file
}

// A retry line in the older shape, before 8b14775 added the mailbox (receiver.ts 328 and 338 now write one; status
// ignores it), and an end with the edge's detail, or another one.
const retry = {
  event: 'subscribe',
  decision: 'retry',
  reason: 'not-authorized',
  detail: { relay: RELAY, attempt: 1, wait_ms: 250 },
} as const
const end = (relay: string, reason: 'revoked' | 'not-authorized', detail?: AuditEntry['detail']) =>
  ({
    ...retry,
    decision: 'reject',
    reason,
    detail: detail ?? { relay, refusals: 3, end: 'subscription-ended' },
  }) as const

describe('status: the doorbell line first, then one line for a subscription the relay refused three times in a row, else nothing more', () => {
  it('prints the line after inbox ends on three refusals, keeps it after an inbox that subscribes, and refuses the log cut short of its anchor', async () => {
    const { dir, io, relay } = await home()
    relay.failSubscribe = new RelayError('not-authorized', 401, null, 'refused')
    const inbox = ['inbox', '--as', 'bob', '--relay', RELAY, '--once', '--dir', dir]
    const refused = await cli(io, ...inbox)
    expect([refused.code, refused.err[0]]).toEqual([1, 'bag: not-authorized: refused'])
    const status = () => cli(io, 'status', '--as', 'bob', '--dir', dir)
    const printed = {
      code: 0,
      out: [
        bell(dir),
        `mailbox refused: not-authorized at ${RELAY} after 3 refusals; edge errors 3, last not-authorized at 2027-01-15T08:00:00Z`,
      ],
      err: [],
    }
    expect(await status()).toEqual(printed)
    // The limit: the edge audits no subscription that succeeds, so the line stays until a later retry line follows.
    relay.failSubscribe = null
    expect((await cli(io, ...inbox)).code).toBe(0)
    expect(await status()).toEqual(printed)
    // The log without its last line, the reject: the anchor in edge.sqlite beside it says it was cut.
    const file = join(dir, 'state', 'bob', 'audit.jsonl')
    const lines = readFileSync(file, 'utf8').trim().split('\n')
    writeFileSync(file, `${lines.slice(0, -1).join('\n')}\n`)
    const cut = await status()
    expect([cut.code, cut.out]).toEqual([1, [bell(dir)]])
    expect(cut.err[0]).toBe(
      `bag: bad-audit: ${file} line ${lines.length}: truncated: the log has ${lines.length - 1} lines; its anchor is at line ${lines.length}`,
    )
  })

  it('prints nothing with no log, with no subscribe line, with a retry last, and with a reject that is no end', async () => {
    const { dir, io } = await home()
    const status = () => cli(io, 'status', '--as', 'bob', '--dir', dir)
    expect(await status()).toEqual({ code: 0, out: [bell(dir)], err: [] })
    log(dir, [{ event: 'verify', decision: 'accept' }])
    expect(await status()).toEqual({ code: 0, out: [bell(dir)], err: [] })
    log(dir, [retry])
    expect(await status()).toEqual({ code: 0, out: [bell(dir)], err: [] })
    // Reject lines that are not the edge's end of a subscription: no detail, a detail without end, refusals or relay.
    const { detail: _, ...bare } = end(RELAY, 'revoked')
    for (const d of [
      undefined,
      { relay: RELAY, refusals: 3 },
      { relay: RELAY, end: 'subscription-ended' },
      { refusals: 3, end: 'subscription-ended' },
    ]) {
      log(dir, [d === undefined ? bare : end(RELAY, 'revoked', d)])
      expect(await status()).toEqual({ code: 0, out: [bell(dir)], err: [] })
    }
    // An end, then a later retry (at any mailbox: status ignores the mailbox the lines now carry): the end is hidden.
    log(dir, [end(RELAY, 'not-authorized'), retry])
    expect(await status()).toEqual({ code: 0, out: [bell(dir)], err: [] })
  })

  it('counts every subscribe retry and reject line as an edge error, reads the last end, and opens no key file', async () => {
    const { dir, io } = await home()
    // A key file with a loose mode, which loading the key refuses: status reads no key, so it still answers.
    chmodSync(join(dir, 'keys', 'bob.json'), 0o644)
    log(dir, [
      retry,
      retry,
      end(RELAY, 'not-authorized'),
      { ...retry, reason: 'revoked' },
      end('http://r2', 'revoked'),
    ])
    expect((await cli(io, 'status', '--as', 'bob', '--dir', dir)).out).toEqual([
      bell(dir),
      'mailbox refused: revoked at http://r2 after 3 refusals; edge errors 5, last revoked at 2027-01-15T08:00:00Z',
    ])
  })

  it('refuses a log whose chain does not verify (bad-audit), a missing --as, and an identity the home lacks', async () => {
    const { dir, io } = await home()
    const file = log(dir, [retry, retry])
    const lines = readFileSync(file, 'utf8').split('\n')
    writeFileSync(file, [lines[0], (lines[1] as string).replace('"retry"', '"reject"'), ''].join('\n'))
    expect(await cli(io, 'status', '--as', 'bob', '--dir', dir)).toEqual({
      code: 1,
      out: [bell(dir)],
      err: [`bag: bad-audit: ${file} line 2: the hash does not recompute`],
    })
    writeFileSync(file, 'not json\n')
    expect((await cli(io, 'status', '--as', 'bob', '--dir', dir)).err).toEqual([
      `bag: bad-audit: ${file} line 1: not an audit line`,
    ])
    expect((await cli(io, 'status', '--dir', dir)).err[0]).toBe('bag: usage: --as is required')
    const nobody = await cli(io, 'status', '--as', 'nobody', '--dir', dir)
    expect([nobody.out, nobody.err[0]]).toEqual([[], expect.stringMatching(/^bag: ENOENT: /)])
    const outside = await cli(io, 'status', '--as', '../keys', '--dir', dir)
    expect([outside.out, outside.err[0]]).toEqual([[], expect.stringContaining('a key name is 1 to 64')])
  })

  it('prints the proxy behind a proxy, without its user or password, and whether Node sends through it', async () => {
    const { dir } = await home()
    const proxied = (env: Record<string, string>) => testIo(new MemoryRelay(), env)
    const off = await cli(
      proxied({ HTTPS_PROXY: 'http://jane:s3cret@proxy.corp:3128', no_proxy: 'localhost' }),
      'status',
      '--as',
      'bob',
      '--dir',
      dir,
    )
    expect(off.out).toEqual([
      bell(dir),
      'network proxy https=http://proxy.corp:3128 http=none no_proxy=localhost active=no: set NODE_USE_ENV_PROXY=1',
    ])
    expect(JSON.stringify(off)).not.toMatch(/jane|s3cret/)
    const on = await cli(
      proxied({ http_proxy: 'http://proxy.corp:8080', NODE_USE_ENV_PROXY: '1' }),
      'status',
      '--as',
      'bob',
      '--dir',
      dir,
    )
    expect(on.out[1]).toBe('network proxy https=none http=http://proxy.corp:8080 no_proxy=none active=yes')
  })

  it('prints the doorbell as an absolute path for a relative --dir, before the file exists', async () => {
    const { dir, io } = await home()
    const got = await cli(io, 'status', '--as', 'bob', '--dir', relative(process.cwd(), dir))
    expect(got).toEqual({ code: 0, out: [bell(dir)], err: [] })
    expect(existsSync(join(dir, 'state', 'bob', 'doorbell'))).toBe(false)
  })

  it('finds an identity the agent holds by its pointer, and names the pointer in the refusal for one the home lacks', async () => {
    const { dir, io } = await home()
    new HomeCustody(dir).agent.create('zed', generateEdgeKeys(io.rng))
    expect(await cli(io, 'status', '--as', 'zed', '--dir', dir)).toEqual({
      code: 0,
      out: [`doorbell ${join(dir, 'state', 'zed', 'doorbell')}`],
      err: [],
    })
    expect((await cli(io, 'status', '--as', 'nobody', '--dir', dir)).err).toEqual([
      `bag: ENOENT: no identity nobody in ${dir}: no key file, keychain or agent pointer`,
    ])
  })
})
