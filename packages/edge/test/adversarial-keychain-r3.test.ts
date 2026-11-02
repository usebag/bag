import { randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { preimageDigest, toHex, utf8, verifySig } from '@usebag/core'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { createSecurityRunner, KeychainCustody, runSecurity } from '../src/adapters/keychain.ts'
import { keyText } from '../src/custody/files.ts'
import { generateEdgeKeys } from '../src/edge.ts'
import type { EdgeKeys } from '../src/ports.ts'
import { seededRng } from './support/fixtures.ts'
import { forms, occurrences } from './support/security.ts'

// C1: the macOS Keychain custody on the REAL /usr/bin/security against a TEMPORARY keychain created
// and deleted inside this test, never the login keychain and never anyone's items. Every spawn
// goes through a pass-through spy that refuses any spawn not naming this temporary keychain, so no call reaches the
// default keychain or the search list. Keys are generated here from a seeded rng; the over-size blob is throwaway
// test data with a marker, never a real secret. C1 measures two things the live keychain tests do not:
//  - a keychain-FILE path that CONTAINS A SPACE is quoted on the `security -i` line (keychain.ts:159) and still round
//    trips, while a path with a quote character (" \ \n \r) is refused before any spawn (keychain.ts:143-145);
//  - a stored item whose read output exceeds maxBuffer 1<<20 (keychain.ts:56) truncates and the read fails as a
//    benign error (failure() maps status/spawn-error only, keychain.ts:90-108), with no key material or marker in any
//    argv, env, log or error message.
// V1 control: a normal create + read round trip on the temporary keychain. Nothing of the live keychain tests is re-run.

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
    // Police /usr/bin/security only: every security spawn must name the temporary keychain, so none reaches the login
    // keychain or the search list. A non-security helper (the /bin/cat maxBuffer probe) touches no keychain and is let
    // through.
    const names = args.includes(spy.keychain) || (input ?? '').includes(`"${spy.keychain}"`)
    if (file === '/usr/bin/security' && (spy.keychain === '' || !names)) {
      throw new Error('refused a security spawn that does not name the temporary keychain')
    }
    spy.calls.push({ file, args: [...args], env: { ...options.env }, input })
    return real.spawnSync(file, args, options)
  }
  return { ...real, spawnSync }
})

const darwin = process.platform === 'darwin' && existsSync('/usr/bin/security')
const root = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-edge-keychain-r3-'))
// The headline of C1: the temporary keychain's file path CONTAINS A SPACE.
spy.keychain = join(root, 'spy custody.keychain-db')
const password = randomBytes(32).toString('hex')
const command = (line: string): number | null => runSecurity(['-i'], utf8(`${line}\n`)).status
const party = (label: string): EdgeKeys => generateEdgeKeys(seededRng(`study24-c1:${label}`))
const alice = party('alice')
const big = party('big')
const needles = [alice, big].flatMap((k) => [
  ...forms(k.signing.exportSeed()),
  ...forms(k.sealing.exportSeed()),
  keyText(k),
  toHex(utf8(keyText(k))),
])
const MARKER = 'STUDY24-C1-NOT-A-REAL-SECRET'

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

// Exactly one of the two describes is defined on a system, so neither is ever a skipped test.
const live = darwin ? describe : (_name: string, _body: () => void): void => {}
const absent = darwin ? (_name: string, _body: () => void): void => {} : describe

absent(
  'C1 without /usr/bin/security (not macOS): the custody needs the program, so C1 is a reported deviation',
  () => {
    it('reports that /usr/bin/security is required for C1', () => {
      expect(darwin).toBe(false)
      console.log('DEVIATION C1: /usr/bin/security is not available; C1 was not measured on this host')
    })
  },
)

live('C1 on /usr/bin/security and a temporary keychain whose path contains a space', () => {
  beforeAll(() => {
    expect(command(`create-keychain -p ${password} "${spy.keychain}"`)).toBe(0)
    expect(command(`unlock-keychain -p ${password} "${spy.keychain}"`)).toBe(0)
    expect(runSecurity(['set-keychain-settings', spy.keychain]).status).toBe(0)
  })

  it('C1 V1 + space path: a create and read round trip through the space-bearing keychain path; a verifiable signature; no seed in any argv, env or pointer file', () => {
    const dir = join(root, 'home', 'keychain')
    const custody = new KeychainCustody({ dir, keychain: spy.keychain, access: 'security' })
    const entry = custody.create('alice', alice)
    expect([entry.name, entry.address, entry.custody]).toEqual(['alice', alice.signing.address, 'keychain'])
    // The pointer records the space-bearing path verbatim; the line that stored the item quoted it.
    const pointer = JSON.parse(readFileSync(join(dir, 'alice.json'), 'utf8')) as Record<string, unknown>
    expect(pointer.keychain).toBe(spy.keychain)
    const createCall = spy.calls.at(-1) as { args: string[]; input: string }
    expect(createCall.args).toEqual(['-i'])
    expect(createCall.input.endsWith(`"${spy.keychain}"\n`)).toBe(true)

    // A new custody on the same pointer reads the item back from the keychain and signs with it.
    const reader = new KeychainCustody({ dir })
    const signer = reader.signer(alice.signing.address)
    const digest = preimageDigest(['ac/test/1', 'study24-c1'])
    expect(verifySig(alice.signing.publicKey, digest, signer.sign(digest))).toBe(true)
    expect(signer.address).toBe(alice.signing.address)
    expect(reader.opener(alice.signing.address).publicKey).toEqual(alice.sealing.publicKey)

    // No seed reached any argument, environment value or pointer file (the seed detector, counts only).
    const inArgs = spy.calls.reduce((n, c) => n + occurrences(c.args.join('\n'), needles), 0)
    const inEnv = spy.calls.reduce((n, c) => n + occurrences(Object.values(c.env).join('\n'), needles), 0)
    const pointerText = readFileSync(join(dir, 'alice.json'), 'utf8')
    console.log(
      `MEASURE C1 space-path: round trip through "${spy.keychain}"; seeds in argv ${inArgs}, in env ${inEnv}, in pointer ${occurrences(pointerText, needles)}; ${spy.calls.length} spawns`,
    )
    expect([inArgs, inEnv, occurrences(pointerText, needles)]).toEqual([0, 0, 0])
  })

  it('C1 quote-char paths: a keychain path with a quote, backslash, newline or carriage return is refused before any spawn', () => {
    const before = spy.calls.length
    for (const bad of ['/tmp/a"b.keychain-db', '/tmp/a\\b.keychain-db', '/tmp/a\nb', '/tmp/a\rb']) {
      let message = 'no error'
      try {
        new KeychainCustody({ dir: join(root, 'quote'), keychain: bad }).create('q', alice)
      } catch (e) {
        message = (e as Error).message
      }
      expect(message).toMatch(/^keychain: security -i cannot quote the path /)
    }
    expect(spy.calls.length, 'no spawn for any unquotable path').toBe(before)
  })

  it('C1 over-size (A, real keychain, DEVIATION): /usr/bin/security cannot store an item large enough to exceed the read cap, so a real item never reaches maxBuffer 1<<20', () => {
    // The read cap is keychain.ts:56 (maxBuffer 1<<20 = 1048576). To reach it, find-generic-password -w must print
    // more than 1 MiB, i.e. a stored password over 1 MiB. `security -i` truncates even a few-KiB command line (an add
    // line splits and is refused), and a -X hex over ~1 MiB on argv would hit ARG_MAX, so such an item cannot be
    // stored at all. This is the honest deviation from the pre-registered C1: the read cap sits safely ABOVE the
    // largest item the tool can store, and a real keychain item never truncates. The attempt is refused.
    const blob = MARKER.repeat(Math.ceil((1 << 20) / MARKER.length) + 1) // > 1 MiB of throwaway marker data
    expect(blob.length).toBeGreaterThan(1 << 20)
    const status = command(
      `add-generic-password -s bag:oversize -a a -X ${toHex(utf8(blob))} "${spy.keychain}"`,
    )
    console.log(
      `MEASURE C1 over-size (A): storing a ${blob.length}-byte item through security -i is refused (status ${status}); a real item cannot exceed the ${1 << 20}-byte read cap`,
    )
    expect(status, 'an over-cap item cannot be stored through security -i').not.toBe(0)
    // Nothing of that service is readable (the add did not take).
    expect(
      runSecurity(['find-generic-password', '-s', 'bag:oversize', '-a', 'a', '-w', spy.keychain]).status,
    ).not.toBe(0)
  })

  it('C1 over-size (B): the read runner (createSecurityRunner maxBuffer 1<<20, keychain.ts:56) surfaces output over 1 MiB as a benign ENOBUFS result, no crash', () => {
    // Exercise the exact runner the custody reads through (createSecurityRunner), over /bin/cat producing more than
    // the cap, so the maxBuffer path at keychain.ts:56 fires. A non-security helper is used because no keychain item
    // can be made this large (sub-test A); the data is non-secret 'x' bytes. The runner must return a benign result
    // (error ENOBUFS) rather than throw or crash. The exit status after a buffer-exceeded kill is nondeterministic on
    // a fast pipe (null or 0); either way the custody handles it benignly (a null status is the ENOBUFS message of
    // sub-test C; a 0 status falls to a secret-free key-parse failure), so only the stable ENOBUFS flag is asserted.
    const over = Buffer.alloc((1 << 20) + 4096, 0x78) // 'x' bytes, > 1 MiB
    const r = createSecurityRunner({ path: '/bin/cat' })([], over)
    console.log(
      `MEASURE C1 over-size (B): /bin/cat emitted >${1 << 20} bytes -> status ${r.status}, error ${r.error}, stdout ${r.stdout.length} bytes`,
    )
    expect(r.error, 'maxBuffer exceeded is surfaced as a benign spawn error').toBe('ENOBUFS')
    expect(occurrences(new TextDecoder().decode(r.stdout), needles)).toBe(0)
  })

  it('C1 over-size (C): the custody maps an over-size (ENOBUFS) read to a benign error, with no key material in the message', () => {
    // End to end through the custody's read path (keychain.ts:90-108 failure mapping and the stdout zeroing at
    // :200-202): a real pointer + item is made, then the item is read through a runner that returns the measured
    // over-size shape (ENOBUFS, marker-bearing stdout, no status). The thrown error must be benign and name the item
    // by status alone, never the stdout, so the "secret" the read carried cannot reach any message.
    const dir = join(root, 'home-cap', 'keychain')
    const capKeys = party('cap')
    new KeychainCustody({ dir, keychain: spy.keychain, access: 'security' }).create('cap', capKeys)
    const address = capKeys.signing.address
    const oversize = (): { status: null; stdout: Uint8Array; stderr: Uint8Array; error: string } => ({
      status: null,
      stdout: utf8(`${MARKER}${toHex(capKeys.signing.exportSeed())}`.repeat(50_000)),
      stderr: new Uint8Array(),
      error: 'ENOBUFS',
    })
    const reader = new KeychainCustody({ dir, run: oversize })
    let message = 'no error'
    try {
      reader.signer(address)
    } catch (e) {
      message = (e as Error).message
    }
    console.log(`MEASURE C1 over-size (C): custody read of an ENOBUFS result -> ${JSON.stringify(message)}`)
    expect(message).not.toBe('no error')
    expect(message).toBe('keychain: reading the item of cap: security exited ENOBUFS')
    expect(message).not.toContain(MARKER)
    expect(occurrences(message, needles)).toBe(0)
  })

  it('C1 no secret left in any file under the temporary tree (the seed detector, counts only)', () => {
    const files = readdirSync(root, { recursive: true, withFileTypes: true }).filter((f) => f.isFile())
    let inFiles = 0
    for (const f of files) {
      const bytes = readFileSync(join(f.parentPath, f.name))
      inFiles += occurrences(bytes.toString('latin1'), needles)
    }
    // The keychain-db itself holds the encrypted items, so the detector never sees a plaintext seed there.
    expect(files.some((f) => f.name === 'spy custody.keychain-db')).toBe(true)
    console.log(`MEASURE C1 files: ${files.length} files under the temp tree, seeds in files ${inFiles}`)
    expect(inFiles).toBe(0)
    // Negative control: the same detector counts a seed planted in a string (so a 0 above is not a dead detector).
    expect(occurrences(toHex(alice.signing.exportSeed()), needles)).toBeGreaterThan(0)
  })
})
