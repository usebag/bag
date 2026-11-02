import { closeSync, fchmodSync, fsyncSync, lstatSync, openSync, readdirSync, writeSync } from 'node:fs'
import { fromHex, isHex, SUITE, sealingKeyFromSeed, signingKeyFromSeed, toHex } from '@usebag/core'
import type { EdgeKeys } from '../ports.ts'

// The file rules both custodies keep (spec/SPEC.md Appendix B 43), and the key text both store. A key file
// (fs-keys) and a keychain pointer (keychain) are 0600 files in a 0700 directory, named `<name>.json`, written once
// with an exclusive create. Each message names its custody by `prefix`, so the file custody's are the original ones.

/** An error with an errno name as its code, as Node's file errors have (ENOENT, EEXIST, EACCES). */
export function errno(code: string, message: string): Error & { readonly code: string } {
  return Object.assign(new Error(message), { code })
}

/** Throws unless `name` is 1 to 64 of [a-z0-9._-] starting with a letter or digit, so it stays in its directory. */
export function checkName(prefix: string, name: string): void {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(name))
    throw new Error(`${prefix}: a key name is 1 to 64 of [a-z0-9._-], not ${JSON.stringify(name)}`)
}

/** Throws unless `path` is a directory (or a regular file) that no one but its owner may read, write or enter. */
export function strict(prefix: string, path: string, directory: boolean): void {
  const st = lstatSync(path)
  if (directory ? !st.isDirectory() : !st.isFile()) {
    throw new Error(`${prefix}: ${path} is not a ${directory ? 'directory' : 'regular file'}`)
  }
  if ((st.mode & 0o077) !== 0) {
    const mode = (st.mode & 0o777).toString(8).padStart(4, '0')
    throw new Error(`${prefix}: ${path} has mode ${mode}; it must be ${directory ? '0700' : '0600'}`)
  }
}

/** The names of the `<name>.json` files of a strict directory, sorted; none when the directory does not exist. */
export function names(prefix: string, dir: string): string[] {
  try {
    strict(prefix, dir, true)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []
    throw e
  }
  return readdirSync(dir)
    .flatMap((f) => /^([a-z0-9][a-z0-9._-]{0,63})\.json$/.exec(f)?.slice(1, 2) ?? [])
    .sort()
}

/** True when something is at `path` (a symlink is not followed); false for ENOENT; any other failure throws. */
export function present(path: string): boolean {
  try {
    lstatSync(path)
    return true
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw e
  }
}

/** Writes a new file of mode 0600 and syncs it; EEXIST when the file exists, which is never overwritten. */
export function writeNew(file: string, text: string): void {
  const fd = openSync(file, 'wx', 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeSync(fd, text)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** A file's mtime in whole Unix seconds: when a file written once was written. */
export function writtenAt(path: string): number {
  return Math.floor(lstatSync(path).mtimeMs / 1000)
}

/** The text a key file holds, and a keychain item: `{suite, sign_seed, seal_priv}` with the seeds in hex. */
export function keyText(keys: EdgeKeys): string {
  return JSON.stringify({
    suite: SUITE,
    sign_seed: toHex(keys.signing.exportSeed()),
    seal_priv: toHex(keys.sealing.exportSeed()),
  })
}

/** The keys of the key text `read` returns; `json` when it throws or is not JSON, `shape` when not a suite 1 key. */
export function keysOf(read: () => string): EdgeKeys | 'json' | 'shape' {
  let v: unknown
  try {
    v = JSON.parse(read())
  } catch {
    return 'json'
  }
  const o = (typeof v === 'object' && v !== null ? v : {}) as Record<string, unknown>
  if (o.suite !== SUITE || !isHex(o.sign_seed, 32) || !isHex(o.seal_priv, 32)) return 'shape'
  return {
    signing: signingKeyFromSeed(fromHex(o.sign_seed)),
    sealing: sealingKeyFromSeed(fromHex(o.seal_priv)),
  }
}
