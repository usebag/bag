import { randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildEnvelope,
  newThread,
  openSealed,
  parseEnvelope,
  preimageDigest,
  toHex,
  utf8,
  verifyOuter,
  verifySig,
} from '@usebag/core'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { KeychainCustody, runSecurity } from '../src/adapters/keychain.ts'
import { keyText } from '../src/custody/files.ts'
import { generateEdgeKeys } from '../src/edge.ts'
import type { EdgeKeys } from '../src/ports.ts'
import { seededRng, T0 } from './support/fixtures.ts'
import { forms, occurrences } from './support/security.ts'

// The Keychain custody on the real /usr/bin/security: a temporary keychain made here, under AC_TEST_TMP, with a
// random password that only ever travels on `security -i`'s stdin, unlocked, and deleted after the tests even when one fails.
// Every spawn goes through a pass-through spy of node:child_process that records its arguments, environment and
// stdin, and refuses any spawn that does not name this keychain file, so no test touches the default keychain or the
// search list. The keys are test data from a seeded rng. On a system without /usr/bin/security the one test says so.

const spy = vi.hoisted(() => ({
  keychain: '',
  calls: [] as { file: string; args: string[]; env: Record<string, string>; input: string | null }[],
}))

vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>()
  const spawnSync = (
    file: string,
    args: string[],
    options: { input?: Uint8Array; env?: Record<string, string> },
  ) => {
    const input = options.input === undefined ? null : Buffer.from(options.input).toString('utf8')
    if (
      spy.keychain === '' ||
      !(args.includes(spy.keychain) || (input ?? '').includes(`"${spy.keychain}"`))
    ) {
      throw new Error('keychain-live: refused a spawn that does not name the temporary keychain')
    }
    spy.calls.push({ file, args: [...args], env: { ...options.env }, input })
    return real.spawnSync(file, args, options)
  }
  return { ...real, spawnSync }
})

const darwin = process.platform === 'darwin' && existsSync('/usr/bin/security')
const root = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-edge-keychain-live-'))
spy.keychain = join(root, 'test.keychain-db')
const password = randomBytes(32).toString('hex')
const command = (line: string): number | null => runSecurity(['-i'], utf8(`${line}\n`)).status
const party = (label: string): EdgeKeys => generateEdgeKeys(seededRng(`keychain-live:${label}`))
const alice = party('alice')
const bob = party('bob')
const carol = party('carol')
const needles = [alice, bob, carol].flatMap((k) => [
  ...forms(k.signing.exportSeed()),
  ...forms(k.sealing.exportSeed()),
  keyText(k),
  toHex(utf8(keyText(k))),
])

function deleteKeychain(): void {
  if (existsSync(spy.keychain)) expect(runSecurity(['delete-keychain', spy.keychain]).status).toBe(0)
  expect(existsSync(spy.keychain)).toBe(false)
}

afterAll(() => {
  try {
    if (darwin) deleteKeychain()
  } finally {
    if (process.env.AC_KEEP_TMP !== '1') rmSync(root, { recursive: true, force: true })
  }
})

// One of the two describes exists on a system, never both, so neither is ever a skipped test.
const live = darwin ? describe : (_name: string, _body: () => void): void => {}
const absent = darwin ? (_name: string, _body: () => void): void => {} : describe

absent('the Keychain custody without /usr/bin/security (not macOS)', () => {
  it('refuses ENOENT, naming the program it needs', () => {
    const custody = new KeychainCustody({ dir: join(root, 'keychain'), keychain: spy.keychain })
    expect(() => custody.create('alice', alice)).toThrow('there is no /usr/bin/security (macOS only)')
  })
})

live('the Keychain custody on /usr/bin/security and a temporary keychain', () => {
  beforeAll(() => {
    expect(command(`create-keychain -p ${password} "${spy.keychain}"`)).toBe(0)
    expect(command(`unlock-keychain -p ${password} "${spy.keychain}"`)).toBe(0)
    expect(runSecurity(['set-keychain-settings', spy.keychain]).status).toBe(0)
  })

  it('L2 (a, b, c): items listed with their addresses; a signature the core verifies; a sealed message that opens', () => {
    const dir = join(root, 'home', 'keychain')
    const custody = new KeychainCustody({ dir, keychain: spy.keychain, access: 'security' })
    custody.create('alice', alice)
    custody.create('bob', bob)
    expect(custody.list().map((e) => [e.name, e.address, e.custody])).toEqual([
      ['alice', alice.signing.address, 'keychain'],
      ['bob', bob.signing.address, 'keychain'],
    ])
    // A new custody on the same pointers reads the items from the keychain, nothing from the create.
    const reader = new KeychainCustody({ dir })
    const reads = spy.calls.length
    const signer = reader.signer(alice.signing.address)
    const digest = preimageDigest(['ac/test/1', 'keychain-live'])
    expect(verifySig(alice.signing.publicKey, digest, signer.sign(digest))).toBe(true)
    const rng = seededRng('keychain-live:envelope')
    const built = buildEnvelope({
      from: signer,
      to: [{ address: bob.signing.address, sealingKey: bob.sealing.publicKey }],
      type: 'chat.v1',
      thread: newThread((n) => rng.bytes(n)),
      body: { text: 'through the keychain' },
      ts: T0,
      rng: (n) => rng.bytes(n),
    })
    const env = parseEnvelope(built.bytes)
    expect(() => verifyOuter(env, T0)).not.toThrow()
    const content = openSealed(env, { address: bob.signing.address, key: reader.opener(bob.signing.address) })
    expect([content.type, content.body]).toEqual(['chat.v1', { text: 'through the keychain' }])
    expect(spy.calls.slice(reads).map((c) => c.args[0])).toEqual([
      'find-generic-password',
      'find-generic-password',
    ])
    console.log(
      `MEASURE L2: 2 items made and read back from a temporary keychain through /usr/bin/security; a signature verified; an envelope verified and opened; ${spy.calls.length} spawns so far`,
    )
  })

  it('L2: an item made with the prompt access trusts no application, one with security trusts /usr/bin/security (never read: a read would raise the dialog)', () => {
    new KeychainCustody({ dir: join(root, 'home2', 'keychain'), keychain: spy.keychain }).create(
      'carol',
      carol,
    )
    const dump = runSecurity(['dump-keychain', '-a', spy.keychain])
    expect(dump.status).toBe(0)
    const text = new TextDecoder().decode(dump.stdout)
    expect(occurrences(text, needles)).toBe(0)
    const decrypt = (svce: string): string => {
      const item = text.split(/^keychain: /m).find((s) => s.includes(`"svce"<blob>="${svce}"`)) as string
      return (item.split(/entry \d+:/).find((e) => e.includes('decrypt')) as string).trim()
    }
    expect(decrypt('bag:carol')).toMatch(/applications \(0\):$/)
    expect(decrypt('bag:alice')).toMatch(/applications \(1\):\s+0: \/usr\/bin\/security \(OK\)/)
  })

  it('L3: no seed in any argument, environment or file; each key text on one security -i stdin; the detector sees a plant', () => {
    const files = readdirSync(root, { recursive: true, withFileTypes: true }).filter((f) => f.isFile())
    let inFiles = 0
    for (const f of files) {
      const bytes = readFileSync(join(f.parentPath, f.name))
      inFiles += occurrences(bytes.toString('latin1'), needles)
      for (const k of [alice, bob, carol]) {
        for (const s of [k.signing.exportSeed(), k.sealing.exportSeed()]) if (bytes.indexOf(s) >= 0) inFiles++
      }
    }
    expect(files.some((f) => f.name === 'test.keychain-db')).toBe(true)
    const inArgs = spy.calls.reduce((n, c) => n + occurrences(c.args.join('\n'), needles), 0)
    const inEnv = spy.calls.reduce((n, c) => n + occurrences(Object.values(c.env).join('\n'), needles), 0)
    const envNames = new Set(spy.calls.flatMap((c) => Object.keys(c.env)))
    const onStdin = [alice, bob, carol].map(
      (k) => spy.calls.filter((c) => (c.input ?? '').includes(toHex(utf8(keyText(k))))).length,
    )
    console.log(
      `MEASURE L3: ${spy.calls.length} spawns of ${[...new Set(spy.calls.map((c) => c.file))].join(', ')}; seeds in arguments ${inArgs}, in environments ${inEnv}, in ${files.length} files ${inFiles}; key texts on security -i's stdin ${onStdin.join(', ')}; environment names ${[...envNames].sort().join(' ')}`,
    )
    expect([inArgs, inEnv, inFiles]).toEqual([0, 0, 0])
    expect(onStdin).toEqual([1, 1, 1])
    expect([...new Set(spy.calls.map((c) => c.file))]).toEqual(['/usr/bin/security'])
    expect([...envNames].every((k) => ['PATH', 'LC_ALL', 'HOME', 'USER', 'LOGNAME'].includes(k))).toBe(true)
    // The negative control: the same detector counts a seed planted in an argument and in an environment value.
    expect(occurrences(['-w', toHex(alice.signing.exportSeed())].join('\n'), needles)).toBeGreaterThan(0)
    expect(occurrences(Buffer.from(bob.sealing.exportSeed()).toString('base64'), needles)).toBeGreaterThan(0)
  })
})
