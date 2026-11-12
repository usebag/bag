import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { AcError, isAddress, SUITE, toHex, utf8 } from '@usebag/core'
import { checkName, errno, keysOf, keyText, names, strict, writeNew, writtenAt } from '../custody/files.ts'
import type { EdgeKeys, KeyCustody, KeyEntry } from '../ports.ts'

// The macOS Keychain custody: encrypted storage, with a dialog
// at every read unless the item trusts /usr/bin/security. One generic password item per identity holds both its keys
// as the key file's text; its service is `bag:<name>` and its account the address, so no attribute holds a
// seed. The edge has no native module, so this runs /usr/bin/security, and no secret travels in an argument or the
// environment: an item is written by one command line on the stdin of `security -i`, and read by
// `find-generic-password -w`, whose stdout is parsed in this process and zeroed. A pointer,
// `<dir>/<name>.json` (0600 in 0700, no seed), records an identity's address, keychain file and access, so listing and
// naming identities read no keychain. No message, entry or error here holds key material or security's output.

const PREFIX = 'keychain'
export const SECURITY_PATH = '/usr/bin/security'
/** How long one call may wait, for a person at the dialog: 300 s. */
export const SECURITY_TIMEOUT_MS = 300_000

/** Who reads an item without a dialog: no application (`prompt`, its `-T ""`), or `security`, its creator. */
export type KeychainAccess = 'prompt' | 'security'

/** One run of /usr/bin/security: its status (null when it did not exit), its output, and the spawn's own error. */
export interface SecurityResult {
  readonly status: number | null
  readonly stdout: Uint8Array
  readonly stderr: Uint8Array
  /** ENOENT without the program, ETIMEDOUT past the timeout. */
  readonly error?: string
}

/** Runs /usr/bin/security with `args`, and `input` on its stdin when given. */
export type SecurityRunner = (args: readonly string[], input?: Uint8Array) => SecurityResult

/** The environment of every call: these variables only, so nothing else of the caller's travels. */
export function securityEnv(source: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const env: Record<string, string> = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C' }
  for (const k of ['HOME', 'USER', 'LOGNAME']) {
    const v = source[k]
    if (v !== undefined) env[k] = v
  }
  return env
}

/** A runner that spawns `path` (/usr/bin/security) with no shell, securityEnv of this process and a timeout. */
export function createSecurityRunner(
  o: { readonly path?: string; readonly timeoutMs?: number } = {},
): SecurityRunner {
  return (args, input) => {
    const r = spawnSync(o.path ?? SECURITY_PATH, [...args], {
      ...(input === undefined ? {} : { input }),
      env: securityEnv(process.env),
      timeout: o.timeoutMs ?? SECURITY_TIMEOUT_MS,
      maxBuffer: 1 << 20,
    })
    const code = (r.error as NodeJS.ErrnoException | undefined)?.code
    const out = {
      status: r.status,
      stdout: r.stdout ?? new Uint8Array(),
      stderr: r.stderr ?? new Uint8Array(),
    }
    return code === undefined ? out : { ...out, error: code }
  }
}

/** The default runner: /usr/bin/security, 300 s. */
export const runSecurity: SecurityRunner = createSecurityRunner()

/** Runs /usr/bin/security as `SecurityRunner` does, without blocking the event loop while it waits (on a dialog). */
export type AsyncSecurityRunner = (args: readonly string[], input?: Uint8Array) => Promise<SecurityResult>

/**
 * The asynchronous runner: the same program, arguments, securityEnv, timeout (ETIMEDOUT, the child killed) and output
 * cap (ENOBUFS) as createSecurityRunner, by spawn. Each chunk of output is zeroed once copied into the result, so the
 * only copy left is the one the caller zeroes after parsing it. A long wait (a dialog) holds only this promise.
 */
export function createAsyncSecurityRunner(
  o: { readonly path?: string; readonly timeoutMs?: number } = {},
): AsyncSecurityRunner {
  return (args, input) =>
    new Promise((resolve) => {
      const out: Buffer[] = []
      const err: Buffer[] = []
      let size = 0
      let error: string | undefined
      let done = false
      const child = spawn(o.path ?? SECURITY_PATH, [...args], {
        env: securityEnv(process.env),
        stdio: ['pipe', 'pipe', 'pipe'],
      })
      const stop = (code: string): void => {
        error ??= code
        child.kill('SIGKILL')
      }
      const timer = setTimeout(() => stop('ETIMEDOUT'), o.timeoutMs ?? SECURITY_TIMEOUT_MS)
      const take = (into: Buffer[]) => (b: Buffer) => {
        size += b.length
        if (size > 1 << 20) stop('ENOBUFS')
        else into.push(b)
      }
      child.stdout.on('data', take(out))
      child.stderr.on('data', take(err))
      child.stdin.on('error', () => {}) // a child that exits before reading its stdin
      const finish = (status: number | null): void => {
        if (done) return
        done = true
        clearTimeout(timer)
        const stdout = new Uint8Array(Buffer.concat(out))
        const stderr = new Uint8Array(Buffer.concat(err))
        for (const b of [...out, ...err]) b.fill(0)
        resolve(error === undefined ? { status, stdout, stderr } : { status, stdout, stderr, error })
      }
      child.on('error', (e: NodeJS.ErrnoException) => {
        error ??= e.code ?? 'EIO'
        finish(null)
      })
      child.on('close', (code) => finish(code))
      if (input === undefined) child.stdin.end()
      else child.stdin.end(Buffer.from(input.buffer, input.byteOffset, input.byteLength))
    })
}

/** The default asynchronous runner: /usr/bin/security, 300 s. */
export const runSecurityAsync: AsyncSecurityRunner = createAsyncSecurityRunner()

export interface KeychainCustodyOptions {
  /** The directory of the pointers, `<dir>/<name>.json` (the CLI's `<home>/keychain`). */
  readonly dir: string
  /** The keychain file new items go to; by default the user's default keychain, and its search list for reads. */
  readonly keychain?: string
  /** Who may read a new item without a dialog; `prompt` by default. */
  readonly access?: KeychainAccess
  /** How /usr/bin/security runs; runSecurity by default. */
  readonly run?: SecurityRunner
  /**
   * How readKeys runs it without blocking: runSecurityAsync when neither runner is given. When only `run` is given
   * (a test's fake), readKeys calls `run` as it is, which blocks while it runs: a service passes no `run`, or both.
   */
  readonly runAsync?: AsyncSecurityRunner
}

interface Pointer {
  readonly address: string
  readonly keychain: string | null
}

const service = (name: string): string => `bag:${name}`

/** A failed call's error, from its status alone (44 for no item and for no keychain file, 45 taken). */
export function failure(what: string, r: SecurityResult): Error {
  const s = r.status
  if (r.error === 'ENOENT')
    return errno('ENOENT', `keychain: ${what}: there is no ${SECURITY_PATH} (macOS only)`)
  if (r.error === 'ETIMEDOUT')
    return errno('ETIMEDOUT', `keychain: ${what}: security did not answer in 300 s`)
  if (s === 44 || s === 50)
    return errno('ENOENT', `keychain: ${what}: no such item or keychain (security exited ${s})`)
  if (s === 45)
    return errno('EEXIST', `keychain: ${what}: the keychain holds that item already (security exited 45)`)
  // errSecInteractionNotAllowed (locked, no one to ask), errSecAuthFailed, errSecUserCanceled (Deny at the dialog).
  if (s === 36 || s === 51 || s === 128) {
    return errno(
      'EACCES',
      `keychain: ${what}: refused, locked or denied at the dialog (security exited ${s})`,
    )
  }
  return new Error(`keychain: ${what}: security exited ${s ?? r.error ?? 'without a status'}`)
}

/**
 * The user's default keychain file, from `security default-keychain` (reads no item, raises no dialog), when it
 * answers 0 with one quoted path that exists; else null: no /usr/bin/security (not macOS), no default keychain (a
 * fresh account, a daemon's user), or a path that is not there. keygen's default custody on macOS turns on it.
 */
export function defaultKeychain(run: SecurityRunner): string | null {
  let r: SecurityResult
  try {
    r = run(['default-keychain'])
  } catch {
    return null
  }
  if (r.status !== 0 || r.error !== undefined) return null
  const m = /^\s*"([^"\n]+)"\s*$/.exec(new TextDecoder().decode(r.stdout))
  return m?.[1] !== undefined && existsSync(m[1]) ? m[1] : null
}

/** The macOS Keychain custody: one item per identity, one pointer per identity in `dir`. */
export class KeychainCustody implements KeyCustody {
  readonly kind = 'keychain'
  readonly #o: KeychainCustodyOptions
  /** The keys read from the keychain, by address: one read, so one dialog, per identity and custody. */
  readonly #read = new Map<string, EdgeKeys>()

  constructor(options: KeychainCustodyOptions) {
    this.#o = options
  }

  /** Every pointer of the directory, by name; none when the directory does not exist. Reads no keychain. */
  list(): KeyEntry[] {
    return names(PREFIX, this.#o.dir).map((name) => this.entry(name))
  }

  /** The identity `name`, from its pointer: ENOENT without one. Reads no keychain. */
  entry(name: string): KeyEntry {
    return {
      name,
      address: this.#pointer(name).address,
      custody: 'keychain',
      created: writtenAt(this.#file(name)),
    }
  }

  /**
   * Writes the pointer (EEXIST for a name taken), then the item, by one line on `security -i`'s stdin, in the
   * custody's keychain with its access; a failure takes the pointer back. The line, the keys in hex, is zeroed after.
   */
  create(name: string, keys: EdgeKeys): KeyEntry {
    const file = this.#file(name)
    const keychain = this.#o.keychain ?? null
    if (keychain !== null && /["\\\n\r]/.test(keychain)) {
      throw new Error(`keychain: security -i cannot quote the path ${JSON.stringify(keychain)}`)
    }
    const access = this.#o.access ?? 'prompt'
    mkdirSync(this.#o.dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, this.#o.dir, true)
    const address = keys.signing.address
    writeNew(file, JSON.stringify({ suite: SUITE, custody: 'keychain', address, keychain, access }))
    const words = [
      'add-generic-password',
      '-s',
      service(name),
      '-a',
      address,
      ...(access === 'prompt' ? ['-T', '""'] : []),
    ]
    words.push('-X', toHex(utf8(keyText(keys))), ...(keychain === null ? [] : [`"${keychain}"`]))
    const line = utf8(`${words.join(' ')}\n`)
    try {
      const r = this.#run(['-i'], line)
      if (r.status !== 0) throw failure(`adding the item of ${name}`, r)
    } catch (e) {
      unlinkSync(file)
      throw e
    } finally {
      line.fill(0)
    }
    return this.entry(name)
  }

  signer(address: string): EdgeKeys['signing'] {
    return this.#keys(address).signing
  }

  opener(address: string): EdgeKeys['sealing'] {
    return this.#keys(address).sealing
  }

  /** The keys of `address`, read before or read now from its identity's item (one dialog under `prompt`). */
  #keys(address: string): EdgeKeys {
    const known = this.#read.get(address)
    if (known !== undefined) return known
    const { name, args } = this.#find(address)
    return this.#parse(name, address, this.#run(args))
  }

  /**
   * The keys of `address`, as signer and opener give them, read without blocking the event loop: a dialog (or a locked
   * keychain) holds only this promise, never the process. Read before: from memory. The error codes are #keys's.
   */
  async readKeys(address: string): Promise<EdgeKeys> {
    const known = this.#read.get(address)
    if (known !== undefined) return known
    const { name, args } = this.#find(address)
    const run = this.#o.runAsync ?? (this.#o.run === undefined ? runSecurityAsync : undefined)
    const r = run === undefined ? (this.#o.run as SecurityRunner)(args) : await run(args)
    return this.#parse(name, address, r)
  }

  /** The pointer of `address` and the find-generic-password arguments of its item. */
  #find(address: string): { name: string; args: string[] } {
    const e = this.list().find((x) => x.address === address)
    if (e === undefined) throw errno('ENOENT', `keychain: no pointer in ${this.#o.dir} is ${address}'s`)
    const p = this.#pointer(e.name)
    const args = ['find-generic-password', '-s', service(e.name), '-a', address, '-w']
    return { name: e.name, args: p.keychain === null ? args : [...args, p.keychain] }
  }

  /** The keys in one read's output, checked against `address`, kept; the output is zeroed in every case. */
  #parse(name: string, address: string, r: SecurityResult): EdgeKeys {
    try {
      if (r.status !== 0) throw failure(`reading the item of ${name}`, r)
      const keys = keysOf(() => new TextDecoder().decode(r.stdout).replace(/\n$/, ''))
      if (typeof keys === 'string')
        throw new Error(`keychain: the item of ${name} is not a suite ${SUITE} key`)
      if (keys.signing.address !== address) {
        throw new AcError('bad-key', `keychain: the item of ${name} holds another key than ${address}`)
      }
      this.#read.set(address, keys)
      return keys
    } finally {
      r.stdout.fill(0)
    }
  }

  #run(args: readonly string[], input?: Uint8Array): SecurityResult {
    return (this.#o.run ?? runSecurity)(args, input)
  }

  /** The pointer of `name`: 0600 in a 0700 directory, of the right shape; ENOENT without one. */
  #pointer(name: string): Pointer {
    const file = this.#file(name)
    strict(PREFIX, this.#o.dir, true)
    strict(PREFIX, file, false)
    let o: Record<string, unknown>
    try {
      o = Object(JSON.parse(readFileSync(file, 'utf8')))
    } catch {
      throw new Error(`keychain: ${file} is not JSON`)
    }
    const { address, keychain, access } = o
    const shaped =
      o.suite === SUITE && o.custody === 'keychain' && (access === 'prompt' || access === 'security')
    if (!shaped || !isAddress(address) || !(keychain === null || typeof keychain === 'string')) {
      throw new Error(`keychain: ${file} is not a keychain pointer`)
    }
    return { address, keychain }
  }

  #file(name: string): string {
    checkName(PREFIX, name)
    return join(this.#o.dir, `${name}.json`)
  }
}
