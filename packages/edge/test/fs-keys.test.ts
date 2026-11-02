import { chmodSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { FsKeyStore } from '../src/adapters/fs-keys.ts'
import { P, tempDir } from './support/fixtures.ts'

const tmp = tempDir('keys')
afterAll(() => tmp.cleanup())

describe('FsKeyStore: key files of mode 0600 in a directory of mode 0700 (spec/SPEC.md §9.9)', () => {
  it('creates the directory 0700 and the file 0600, and loads the same keys back', () => {
    const dir = join(tmp.dir, 'a', 'keys')
    const store = new FsKeyStore(dir)
    store.save('jane', P.jane.keys)
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(join(dir, 'jane.json')).mode & 0o777).toBe(0o600)
    const keys = store.load('jane')
    expect(keys.signing.address).toBe(P.jane.address)
    expect(keys.sealing.publicKey).toEqual(P.jane.sealing.publicKey)
    expect(Object.keys(JSON.parse(readFileSync(join(dir, 'jane.json'), 'utf8')))).toEqual([
      'suite',
      'sign_seed',
      'seal_priv',
    ])
  })

  it('refuses a key file that others can read, as 0644, and loads one that is 0400', () => {
    const dir = join(tmp.dir, 'b')
    const store = new FsKeyStore(dir)
    store.save('bob', P.bob.keys)
    const file = join(dir, 'bob.json')
    chmodSync(file, 0o644)
    expect(statSync(file).mode & 0o777).toBe(0o644)
    expect(() => store.load('bob')).toThrow(`fs-keys: ${file} has mode 0644; it must be 0600`)
    chmodSync(file, 0o400)
    expect(store.load('bob').signing.address).toBe(P.bob.address)
  })

  it('refuses a directory that others can enter, for load and save', () => {
    const dir = join(tmp.dir, 'c')
    mkdirSync(dir, { mode: 0o755 })
    chmodSync(dir, 0o755)
    const store = new FsKeyStore(dir)
    expect(() => store.save('x', P.bob.keys)).toThrow('has mode 0755; it must be 0700')
    expect(() => store.load('x')).toThrow('has mode 0755; it must be 0700')
  })

  it('never overwrites a key file', () => {
    const store = new FsKeyStore(join(tmp.dir, 'd'))
    store.save('carol', P.carol.keys)
    expect(() => store.save('carol', P.bob.keys)).toThrow(/EEXIST/)
    expect(store.load('carol').signing.address).toBe(P.carol.address)
  })

  it('refuses a name that could leave the directory, a symlink, a directory as a file, and a missing file', () => {
    const dir = join(tmp.dir, 'e')
    const store = new FsKeyStore(dir)
    for (const name of ['../x', 'a/b', '', '.hidden', 'UPPER', 'x'.repeat(65)]) {
      expect(() => store.load(name), name).toThrow('fs-keys: a key name')
    }
    store.save('real', P.bob.keys)
    symlinkSync(join(dir, 'real.json'), join(dir, 'link.json'))
    expect(() => store.load('link')).toThrow('is not a regular file')
    mkdirSync(join(dir, 'sub.json'), { mode: 0o700 })
    expect(() => store.load('sub')).toThrow('is not a regular file')
    expect(() => store.load('absent')).toThrow(/ENOENT/)
    writeFileSync(join(tmp.dir, 'plain'), '')
    expect(() => new FsKeyStore(join(tmp.dir, 'plain')).load('x')).toThrow('is not a directory')
  })

  it('refuses a file that is not a suite 1 key file, without printing its contents', () => {
    const dir = join(tmp.dir, 'f')
    const store = new FsKeyStore(dir)
    store.save('ok', P.bob.keys)
    const bad: Record<string, string> = {
      notjson: 'secret-material{',
      array: '[]',
      null: 'null',
      suite: JSON.stringify({ suite: 2, sign_seed: '00'.repeat(32), seal_priv: '00'.repeat(32) }),
      short: JSON.stringify({ suite: 1, sign_seed: '00'.repeat(31), seal_priv: '00'.repeat(32) }),
      upper: JSON.stringify({ suite: 1, sign_seed: '00'.repeat(32), seal_priv: 'AA'.repeat(32) }),
    }
    for (const [name, content] of Object.entries(bad)) {
      writeFileSync(join(dir, `${name}.json`), content, { mode: 0o600 })
      let message = ''
      try {
        store.load(name)
      } catch (e) {
        message = (e as Error).message
      }
      expect(message, name).toMatch(/^fs-keys: .* is not (JSON|a suite 1 key file)$/)
      expect(message).not.toContain('secret-material')
    }
  })
})
