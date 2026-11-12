import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  type AsyncSecurityRunner,
  createAsyncSecurityRunner,
  type SecurityResult,
  type SecurityRunner,
} from '../src/adapters/keychain.ts'
import { HomeCustody, openIdentityKeys } from '../src/custody/home.ts'
import { P, tempDir } from './support/fixtures.ts'
import { FakeSecurity } from './support/security.ts'

// The asynchronous keychain read a bag service opens keys with: one identity's dialog (a slow read) holds only its
// own open, never a second open, a timer or the process; the runner keeps the sync runner's timeout, output cap and
// errors; the error mapping is unchanged; the output is zeroed. The runner is exercised on ordinary programs (cat,
// sleep, false, yes) and the keychain path on the fake security only: nothing here reaches a keychain or a dialog.

const tmp = tempDir('custody-async')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `h${n++}`)
const result = (status: number | null, o: Partial<SecurityResult> = {}): SecurityResult => ({
  status,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
  ...o,
})
const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p
  } catch (e) {
    return String((e as { code?: unknown }).code ?? (e as Error).message)
  }
  return 'none'
}

/** A home with keychain identities bob and carol; a sync runner that refuses every read (so only runAsync reads). */
function home2(): { home: string; fake: FakeSecurity; noSyncRead: SecurityRunner } {
  const fake = new FakeSecurity()
  const home = fresh()
  const c = new HomeCustody(home, { run: fake.run })
  c.create('bob', P.bob.keys, { custody: 'keychain' })
  c.create('carol', P.carol.keys, { custody: 'keychain' })
  const noSyncRead: SecurityRunner = (args, input) => {
    if (args[0] === 'find-generic-password') throw new Error('a blocking read: the async path was not taken')
    return fake.run(args, input)
  }
  return { home, fake, noSyncRead }
}

describe('openIdentityKeys: a slow read (a dialog up) blocks only its own identity', () => {
  it('carol opens, and a timer fires, while bob waits at his dialog; then bob opens', async () => {
    const { home, fake, noSyncRead } = home2()
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => {
      release = r
    })
    const runAsync: AsyncSecurityRunner = async (args, input) => {
      if (args.includes('bag:bob')) await gate // bob's dialog, not answered yet
      return fake.run(args, input)
    }
    const o = { run: noSyncRead, runAsync }
    let bobDone = false
    const bob = openIdentityKeys(home, 'bob', o).then((k) => {
      bobDone = true
      return k
    })
    let ticked = false
    setTimeout(() => {
      ticked = true
    }, 0)
    const carol = await openIdentityKeys(home, 'carol', o)
    expect(carol.address).toBe(P.carol.address)
    await new Promise((r) => setTimeout(r, 5))
    expect([ticked, bobDone]).toEqual([true, false])
    release()
    const b = await bob
    expect([b.custody, b.address, bobDone]).toEqual(['keychain', P.bob.address, true])
    expect(Buffer.from(b.keys?.sealing.exportSeed() ?? [])).toEqual(Buffer.from(P.bob.sealing.exportSeed()))
  })

  it("the error mapping is the sync read's: no item ENOENT, Deny EACCES, no answer ETIMEDOUT, no program ENOENT", async () => {
    const { home, noSyncRead } = home2()
    for (const [r, code] of [
      [result(44), 'ENOENT'],
      [result(128), 'EACCES'],
      [result(36), 'EACCES'],
      [result(null, { error: 'ETIMEDOUT' }), 'ETIMEDOUT'],
      [result(null, { error: 'ENOENT' }), 'ENOENT'],
    ] as const) {
      const o = { run: noSyncRead, runAsync: async () => r }
      expect(await codeOf(openIdentityKeys(home, 'bob', o))).toBe(code)
    }
  })

  it('zeroes the read output, on success and on a refusal; a key file opens through the same path', async () => {
    const { home, fake, noSyncRead } = home2()
    const given: Uint8Array[] = []
    const runAsync: AsyncSecurityRunner = async (args, input) => {
      const r = fake.run(args, input)
      given.push(r.stdout)
      return r
    }
    await openIdentityKeys(home, 'bob', { run: noSyncRead, runAsync })
    const bad = new TextEncoder().encode('not a key\n')
    expect(
      await codeOf(
        openIdentityKeys(home, 'carol', {
          run: noSyncRead,
          runAsync: async () => result(0, { stdout: bad }),
        }),
      ),
    ).toMatch(/not a suite/)
    for (const b of [...given, bad]) expect(b.every((x) => x === 0)).toBe(true)
    new HomeCustody(home).create('alice', P.jane.keys, { custody: 'file' })
    const a = await openIdentityKeys(home, 'alice', { run: noSyncRead, runAsync })
    expect([a.custody, a.address]).toEqual(['home-key', P.jane.address])
  })
})

describe("createAsyncSecurityRunner: the sync runner's contract without blocking (ordinary programs only)", () => {
  it('passes stdin and returns stdout and the status', async () => {
    const cat = createAsyncSecurityRunner({ path: '/bin/cat', timeoutMs: 5000 })
    const r = await cat([], new TextEncoder().encode('line on stdin\n'))
    expect([r.status, new TextDecoder().decode(r.stdout), r.error]).toEqual([0, 'line on stdin\n', undefined])
    const no = await createAsyncSecurityRunner({ path: '/usr/bin/false' })([])
    expect([no.status, no.error]).toEqual([1, undefined])
  })

  it('kills a child past the timeout (ETIMEDOUT), and timers run while it waits', async () => {
    let ticks = 0
    const t = setInterval(() => ticks++, 10)
    const started = Date.now()
    const r = await createAsyncSecurityRunner({ path: '/bin/sleep', timeoutMs: 200 })(['5'])
    clearInterval(t)
    expect([r.status, r.error]).toEqual([null, 'ETIMEDOUT'])
    expect(Date.now() - started).toBeLessThan(3000)
    expect(ticks).toBeGreaterThan(3)
  })

  it('ENOENT without the program, ENOBUFS past the output cap', async () => {
    const gone = await createAsyncSecurityRunner({ path: join(fresh(), 'no-such-program') })([])
    expect([gone.status, gone.error]).toEqual([null, 'ENOENT'])
    const yes = await createAsyncSecurityRunner({ path: '/usr/bin/yes', timeoutMs: 10_000 })([])
    expect(yes.error).toBe('ENOBUFS')
  })
})
