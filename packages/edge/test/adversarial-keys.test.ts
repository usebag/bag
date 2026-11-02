import { execFileSync } from 'node:child_process'
import { chmodSync, lstatSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { FsKeyStore } from '../src/adapters/fs-keys.ts'
import { type Identity, identity, occurrences, scratch } from './support/adversarial.ts'

// FsKeyStore (the edge half): key files at 0644, 0640 and 0620; the key directory at 0750 and 0707; a symlink
// to a 0600 file; a FIFO; a file that is not JSON; one of the right shape with a 31-byte seed. Each is refused with a
// message that names the path and the mode (or the shape) and quotes none of the file's contents. Every case first
// shows its positive control: the same key file at 0600 in a 0700 directory loads. The CLI half (`address <name>`)
// and the modes after a CLI run are in packages/cli/test/adversarial-secrets.test.ts.

interface Home {
  readonly dir: string
  readonly file: string
  readonly store: FsKeyStore
  readonly id: Identity
}

/** A 0700 key directory holding one 0600 key file `k.json`, which loads (the positive control). */
function home(label: string): Home {
  const id = identity(`keys:${label}`)
  const dir = join(scratch(`keys-${label}`), 'keys')
  const store = new FsKeyStore(dir)
  store.save('k', id.keys)
  const file = join(dir, 'k.json')
  expect(lstatSync(dir).mode & 0o777).toBe(0o700)
  expect(lstatSync(file).mode & 0o777).toBe(0o600)
  expect(store.load('k').signing.address).toBe(id.address)
  return { dir, file, store, id }
}

/** The message `load` throws, or '' when it does not throw. */
function refusal(store: FsKeyStore, name: string): string {
  try {
    store.load(name)
    return ''
  } catch (e) {
    return e instanceof Error ? e.message : String(e)
  }
}

/** None of the identity's secret forms is in the message (a count, so a failure prints no secret). */
function quotesNothing(message: string, id: Identity): void {
  expect(occurrences(message, [...id.secrets, id.keyFile])).toBe(0)
}

describe('FsKeyStore refuses a key file or directory that is not private, or not a key file', () => {
  for (const mode of [0o644, 0o640, 0o620]) {
    const octal = mode.toString(8).padStart(4, '0')
    it(`a key file at ${octal}: refused, naming the path and the mode`, () => {
      const h = home(`file-${octal}`)
      chmodSync(h.file, mode)
      expect(lstatSync(h.file).mode & 0o777).toBe(mode)
      const message = refusal(h.store, 'k')
      expect(message).toBe(`fs-keys: ${h.file} has mode ${octal}; it must be 0600`)
      quotesNothing(message, h.id)
    })
  }

  for (const mode of [0o750, 0o707]) {
    const octal = mode.toString(8).padStart(4, '0')
    it(`the key directory at ${octal}: refused, naming the path and the mode`, () => {
      const h = home(`dir-${octal}`)
      chmodSync(h.dir, mode)
      expect(lstatSync(h.dir).mode & 0o777).toBe(mode)
      const message = refusal(h.store, 'k')
      expect(message).toBe(`fs-keys: ${h.dir} has mode ${octal}; it must be 0700`)
      quotesNothing(message, h.id)
    })
  }

  it('a symlink to a 0600 key file: refused as not a regular file, naming the path', () => {
    const h = home('symlink')
    const link = join(h.dir, 'link.json')
    symlinkSync(h.file, link)
    expect(lstatSync(link).isSymbolicLink()).toBe(true)
    const message = refusal(h.store, 'link')
    expect(message).toBe(`fs-keys: ${link} is not a regular file`)
    quotesNothing(message, h.id)
  })

  it('a FIFO in place of a key file: refused as not a regular file, before any open (no hang)', () => {
    const h = home('fifo')
    const fifo = join(h.dir, 'pipe.json')
    execFileSync('mkfifo', ['-m', '0600', fifo])
    expect(lstatSync(fifo).isFIFO()).toBe(true)
    const message = refusal(h.store, 'pipe')
    expect(message).toBe(`fs-keys: ${fifo} is not a regular file`)
  })

  it('a key file that is not JSON (a truncated key file): refused as not JSON, quoting none of it', () => {
    const h = home('notjson')
    const file = join(h.dir, 'cut.json')
    writeFileSync(file, h.id.keyFile.slice(0, -2), { mode: 0o600 })
    // The truncated text still holds both seeds, so a message that quoted the file would show them.
    expect(occurrences(h.id.keyFile.slice(0, -2), h.id.secrets)).toBe(2)
    const message = refusal(h.store, 'cut')
    expect(message).toBe(`fs-keys: ${file} is not JSON`)
    quotesNothing(message, h.id)
  })

  it('a key file of the right shape with a 31-byte seed: refused as not a suite 1 key file, quoting none of it', () => {
    const h = home('short')
    const [sign, seal] = h.id.secrets as [string, string]
    const file = join(h.dir, 'short.json')
    writeFileSync(file, JSON.stringify({ suite: 1, sign_seed: sign.slice(0, 62), seal_priv: seal }), {
      mode: 0o600,
    })
    const message = refusal(h.store, 'short')
    expect(message).toBe(`fs-keys: ${file} is not a suite 1 key file`)
    quotesNothing(message, h.id)
    expect(occurrences(message, [sign.slice(0, 62)])).toBe(0)
  })

  it('a key directory that is a symlink to a 0700 directory: refused as not a directory', () => {
    const h = home('dirlink')
    const link = join(h.dir, '..', 'keys-link')
    symlinkSync(h.dir, link)
    const message = refusal(new FsKeyStore(link), 'k')
    expect(message).toBe(`fs-keys: ${link} is not a directory`)
  })
})
