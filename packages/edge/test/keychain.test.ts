import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { preimageDigest, toHex, verifySig } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import {
  createSecurityRunner,
  KeychainCustody,
  SECURITY_PATH,
  type SecurityResult,
  securityEnv,
} from '../src/adapters/keychain.ts'
import { P, tempDir } from './support/fixtures.ts'
import { FakeSecurity, forms, occurrences, words } from './support/security.ts'

// The Keychain custody on a fake /usr/bin/security (every branch; the real one is in
// keychain-live.test.ts): the pointer, the `security -i` line, the read, the cache, and every refusal by its code.

const tmp = tempDir('keychain')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `home-${n++}`, 'keychain')
const KC = '/tmp/bag-test/test.keychain-db'
const secrets = [...P.jane.secrets, ...P.bob.secrets].flatMap((h) => forms(Buffer.from(h, 'hex')))
const result = (status: number | null, extra: Partial<SecurityResult> = {}): SecurityResult => ({
  status,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
  ...extra,
})
const keyText = (keys = P.jane.keys): string =>
  JSON.stringify({
    suite: 1,
    sign_seed: toHex(keys.signing.exportSeed()),
    seal_priv: toHex(keys.sealing.exportSeed()),
  })
const message = (f: () => unknown): string => {
  try {
    f()
  } catch (e) {
    return `${(e as { code?: string }).code ?? 'no code'} ${(e as Error).message}`
  }
  return 'no error'
}

describe('KeychainCustody: one item per identity through security -i, a pointer per identity', () => {
  it('creates an item with the security access in a named keychain: the line, the pointer, the entry', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    const custody = new KeychainCustody({ dir, keychain: KC, access: 'security', run: fake.run })
    expect(custody.kind).toBe('keychain')
    const before = Math.floor(Date.now() / 1000)
    const entry = custody.create('jane', P.jane.keys)
    expect(entry).toEqual({
      name: 'jane',
      address: P.jane.address,
      custody: 'keychain',
      created: entry.created,
    })
    expect(entry.created).toBeGreaterThanOrEqual(before - 1)
    expect(entry.created).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1)
    expect(fake.calls).toHaveLength(1)
    const call = fake.calls[0] as { args: string[]; input: string }
    expect(call.args).toEqual(['-i'])
    expect(words(call.input)).toEqual([
      'add-generic-password',
      '-s',
      'bag:jane',
      '-a',
      P.jane.address,
      '-X',
      Buffer.from(keyText()).toString('hex'),
      KC,
    ])
    expect(call.input.endsWith(`"${KC}"\n`)).toBe(true)
    const item = fake.items.get(FakeSecurity.key(KC, 'bag:jane', P.jane.address))
    expect(new TextDecoder().decode(item?.data)).toBe(keyText())
    expect(item?.noApplication).toBe(false)
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(join(dir, 'jane.json')).mode & 0o777).toBe(0o600)
    const pointer = readFileSync(join(dir, 'jane.json'), 'utf8')
    expect(JSON.parse(pointer)).toEqual({
      suite: 1,
      custody: 'keychain',
      address: P.jane.address,
      keychain: KC,
      access: 'security',
    })
    expect(occurrences(pointer, secrets)).toBe(0)
    expect(custody.list()).toEqual([entry])
    expect(custody.entry('jane')).toEqual(entry)
  })

  it('by default trusts no application (-T "") and names no keychain, so the default keychain takes the item', () => {
    const fake = new FakeSecurity()
    const custody = new KeychainCustody({ dir: fresh(), run: fake.run })
    custody.create('bob', P.bob.keys)
    const line = words(fake.calls[0]?.input as string)
    expect(line.slice(0, 7)).toEqual(['add-generic-password', '-s', 'bag:bob', '-a', P.bob.address, '-T', ''])
    expect(line).toHaveLength(9)
    const item = fake.items.get(FakeSecurity.key(null, 'bag:bob', P.bob.address))
    expect(item?.noApplication).toBe(true)
  })

  it('reads an identity once for its signer and its opener, which are its keys, and zeroes the output', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    new KeychainCustody({ dir, keychain: KC, access: 'security', run: fake.run }).create('jane', P.jane.keys)
    // A new custody on the same pointers: nothing cached from the create.
    const custody = new KeychainCustody({ dir, run: fake.run })
    const signer = custody.signer(P.jane.address)
    const opener = custody.opener(P.jane.address)
    expect(fake.calls.map((c) => c.args)).toEqual([
      ['-i'],
      ['find-generic-password', '-s', 'bag:jane', '-a', P.jane.address, '-w', KC],
    ])
    const digest = preimageDigest(['ac/test/1', 'custody'])
    expect(verifySig(P.jane.signing.publicKey, digest, signer.sign(digest))).toBe(true)
    expect(signer.address).toBe(P.jane.address)
    expect(opener.publicKey).toEqual(P.jane.sealing.publicKey)
    expect(fake.given).toHaveLength(1)
    expect([...(fake.given[0] as Uint8Array)].every((b) => b === 0)).toBe(true)
  })

  it('reads an item from the default keychain, and an output without its final newline', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    new KeychainCustody({ dir, access: 'security', run: fake.run }).create('jane', P.jane.keys)
    const custody = new KeychainCustody({ dir, run: fake.run })
    expect(custody.signer(P.jane.address).address).toBe(P.jane.address)
    expect(fake.calls[1]?.args).toEqual([
      'find-generic-password',
      '-s',
      'bag:jane',
      '-a',
      P.jane.address,
      '-w',
    ])
    fake.next.push(result(0, { stdout: new TextEncoder().encode(keyText()) }))
    expect(new KeychainCustody({ dir, run: fake.run }).opener(P.jane.address).publicKey).toEqual(
      P.jane.sealing.publicKey,
    )
  })

  it('lists pointers by name and ignores other files; nothing without a directory', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    const custody = new KeychainCustody({ dir, keychain: KC, run: fake.run })
    expect(custody.list()).toEqual([])
    custody.create('zed', P.carol.keys)
    custody.create('amy', P.jane.keys)
    writeFileSync(join(dir, 'notes.txt'), 'not a pointer')
    writeFileSync(join(dir, 'Upper.json'), '{}')
    expect(custody.list().map((e) => [e.name, e.address])).toEqual([
      ['amy', P.jane.address],
      ['zed', P.carol.address],
    ])
    expect(fake.calls).toHaveLength(2)
  })

  it('refuses a name, a keychain path security -i cannot quote, and a name that has a pointer', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    expect(message(() => new KeychainCustody({ dir, run: fake.run }).create('../x', P.jane.keys))).toBe(
      'no code keychain: a key name is 1 to 64 of [a-z0-9._-], not "../x"',
    )
    for (const path of ['/tmp/a"b.keychain-db', '/tmp/a\\b', '/tmp/a\nb']) {
      expect(
        message(() => new KeychainCustody({ dir, keychain: path, run: fake.run }).create('j', P.jane.keys)),
      ).toMatch(/^no code keychain: security -i cannot quote the path /)
    }
    expect(fake.calls).toHaveLength(0)
    const custody = new KeychainCustody({ dir, keychain: KC, run: fake.run })
    custody.create('jane', P.jane.keys)
    expect(message(() => custody.create('jane', P.bob.keys))).toMatch(
      /^EEXIST EEXIST: file already exists, open /,
    )
    expect(fake.calls).toHaveLength(1)
  })

  it('takes the pointer back when security refuses the item, or the runner throws', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    const custody = new KeychainCustody({ dir, keychain: KC, run: fake.run })
    fake.next.push(result(45, { stderr: new TextEncoder().encode('The specified item already exists') }))
    expect(message(() => custody.create('jane', P.jane.keys))).toBe(
      'EEXIST keychain: adding the item of jane: the keychain holds that item already (security exited 45)',
    )
    expect(custody.list()).toEqual([])
    fake.next.push(Object.assign(new Error('spawn failed'), { code: 'EAGAIN' }))
    expect(message(() => custody.create('jane', P.jane.keys))).toBe('EAGAIN spawn failed')
    expect(custody.list()).toEqual([])
    custody.create('jane', P.jane.keys)
    expect(custody.list().map((e) => e.name)).toEqual(['jane'])
  })

  it('names each failure by its status, never by what security printed', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    new KeychainCustody({ dir, keychain: KC, access: 'security', run: fake.run }).create('jane', P.jane.keys)
    const planted = new TextEncoder().encode(`${P.jane.secrets.join(' ')} ${P.bob.secrets.join(' ')}`)
    const read = (r: SecurityResult): string => {
      fake.next.push(r)
      return message(() => new KeychainCustody({ dir, run: fake.run }).signer(P.jane.address))
    }
    const cases: [SecurityResult, string][] = [
      [
        result(44),
        'ENOENT keychain: reading the item of jane: no such item or keychain (security exited 44)',
      ],
      [
        result(50),
        'ENOENT keychain: reading the item of jane: no such item or keychain (security exited 50)',
      ],
      [
        result(45),
        'EEXIST keychain: reading the item of jane: the keychain holds that item already (security exited 45)',
      ],
      ...[36, 51, 128].map((s): [SecurityResult, string] => [
        result(s),
        `EACCES keychain: reading the item of jane: refused, locked or denied at the dialog (security exited ${s})`,
      ]),
      [
        result(null, { error: 'ENOENT' }),
        `ENOENT keychain: reading the item of jane: there is no ${SECURITY_PATH} (macOS only)`,
      ],
      [
        result(null, { error: 'ETIMEDOUT' }),
        'ETIMEDOUT keychain: reading the item of jane: security did not answer in 300 s',
      ],
      [result(1), 'no code keychain: reading the item of jane: security exited 1'],
      [
        result(null, { error: 'ENOBUFS' }),
        'no code keychain: reading the item of jane: security exited ENOBUFS',
      ],
      [result(null), 'no code keychain: reading the item of jane: security exited without a status'],
    ]
    for (const [r, want] of cases) {
      const got = read({ ...r, stdout: planted, stderr: planted })
      expect(got).toBe(want)
      expect(occurrences(got, secrets)).toBe(0)
    }
  })

  it('refuses an item that is not a suite 1 key, and one that holds another key than the pointer', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    new KeychainCustody({ dir, keychain: KC, run: fake.run }).create('jane', P.jane.keys)
    const read = (stdout: string): string => {
      fake.next.push(result(0, { stdout: new TextEncoder().encode(stdout) }))
      return message(() => new KeychainCustody({ dir, run: fake.run }).signer(P.jane.address))
    }
    for (const text of [
      'not json\n',
      'null\n',
      '{"suite":2}\n',
      `${keyText().replace('"suite":1', '"suite":2')}\n`,
    ]) {
      expect(read(text)).toBe('no code keychain: the item of jane is not a suite 1 key')
    }
    const other = read(`${keyText(P.bob.keys)}\n`)
    expect(other).toBe(`bad-key bad-key: keychain: the item of jane holds another key than ${P.jane.address}`)
    expect(occurrences(other, secrets)).toBe(0)
  })

  it('refuses an address it has no pointer for, and a pointer or directory that is not private or not one', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    const custody = new KeychainCustody({ dir, keychain: KC, run: fake.run })
    custody.create('jane', P.jane.keys)
    expect(message(() => custody.signer(P.bob.address))).toBe(
      `ENOENT keychain: no pointer in ${dir} is ${P.bob.address}'s`,
    )
    expect(message(() => custody.entry('ghost'))).toMatch(/^ENOENT ENOENT: no such file or directory, lstat /)
    const file = join(dir, 'jane.json')
    chmodSync(file, 0o644)
    expect(message(() => custody.entry('jane'))).toBe(
      `no code keychain: ${file} has mode 0644; it must be 0600`,
    )
    chmodSync(file, 0o600)
    chmodSync(dir, 0o755)
    expect(message(() => custody.list())).toBe(`no code keychain: ${dir} has mode 0755; it must be 0700`)
    chmodSync(dir, 0o700)
    const plain = join(tmp.dir, `plain-${n++}`)
    writeFileSync(plain, 'x')
    expect(message(() => new KeychainCustody({ dir: plain }).list())).toBe(
      `no code keychain: ${plain} is not a directory`,
    )
    mkdirSync(join(dir, 'dir.json'))
    expect(message(() => custody.list())).toBe(
      `no code keychain: ${join(dir, 'dir.json')} is not a regular file`,
    )
  })

  it('refuses a pointer that is not JSON or not a keychain pointer, member by member', () => {
    const fake = new FakeSecurity()
    const dir = fresh()
    const custody = new KeychainCustody({ dir, keychain: KC, run: fake.run })
    custody.create('jane', P.jane.keys)
    const file = join(dir, 'jane.json')
    const good = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const put = (text: string): string => {
      chmodSync(file, 0o600)
      writeFileSync(file, text)
      return message(() => custody.entry('jane'))
    }
    expect(put('{')).toBe(`no code keychain: ${file} is not JSON`)
    expect(put('7')).toBe(`no code keychain: ${file} is not a keychain pointer`)
    for (const bad of [
      { suite: 2 },
      { custody: 'file' },
      { address: 'jane' },
      { keychain: 7 },
      { access: 'anyone' },
    ]) {
      expect(put(JSON.stringify({ ...good, ...bad }))).toBe(
        `no code keychain: ${file} is not a keychain pointer`,
      )
    }
    expect(put(JSON.stringify({ ...good, keychain: null, access: 'prompt' }))).toBe('no error')
  })
})

describe('the security runner: no shell, a minimal environment, a timeout', () => {
  it('passes only PATH, LC_ALL, HOME, USER and LOGNAME, the last three when set', () => {
    expect(securityEnv({ HOME: '/h', USER: 'u', LOGNAME: 'l', SECRET: 'x', AC_HOME: '/a' })).toEqual({
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      LC_ALL: 'C',
      HOME: '/h',
      USER: 'u',
      LOGNAME: 'l',
    })
    expect(securityEnv({ HOME: '/h' })).toEqual({
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      LC_ALL: 'C',
      HOME: '/h',
    })
  })

  it('writes the input to stdin and reads stdout, reports a program that is not there, and one past its timeout', () => {
    const cat = createSecurityRunner({ path: '/bin/cat' })([], new TextEncoder().encode('line\n'))
    expect(cat.status).toBe(0)
    expect(new TextDecoder().decode(cat.stdout)).toBe('line\n')
    expect(cat.error).toBeUndefined()
    const none = createSecurityRunner({ path: join(tmp.dir, 'no-such-program') })(['x'])
    expect([none.status, none.error, none.stdout.length, none.stderr.length]).toEqual([null, 'ENOENT', 0, 0])
    const slow = createSecurityRunner({ path: '/bin/sleep', timeoutMs: 50 })(['5'])
    expect([slow.status, slow.error]).toEqual([null, 'ETIMEDOUT'])
  })
})
