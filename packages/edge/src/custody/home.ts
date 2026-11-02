import { randomUUID } from 'node:crypto'
import { lstatSync, readFileSync, renameSync, unlinkSync, utimesSync } from 'node:fs'
import { join } from 'node:path'
import { sealingKeyFromSeed, toHex, utf8 } from '@usebag/core'
import { FsKeyStore } from '../adapters/fs-keys.ts'
import {
  failure,
  type KeychainAccess,
  KeychainCustody,
  runSecurity,
  type SecurityRunner,
} from '../adapters/keychain.ts'
import type { AgentClient } from '../agent/client.ts'
import type { EdgeKeys, KeyCustody, KeyEntry } from '../ports.ts'
import { AgentCustody } from './agent.ts'
import { checkName, errno, keyText, present, writeNew } from './files.ts'

// The custodies of a home: key files in <home>/keys (FsKeyStore), the pointers of keychain
// identities in <home>/keychain (KeychainCustody) and of agent identities in <home>/agent (AgentCustody). An identity
// is in one of them, chosen when it is made, and every later use finds it there. The CLI composes its home this way; the MCP server, which composes the edge as the CLI
// does, can too.

/** Where HomeCustody.create puts a new identity: a key file, or an item in a keychain with its access. */
export type CustodyTarget =
  | { readonly custody: 'file' }
  | { readonly custody: 'keychain'; readonly keychain?: string; readonly access?: KeychainAccess }

export interface HomeCustodyOptions {
  /** How the keychain custody runs /usr/bin/security; its default runner by default. */
  readonly run?: SecurityRunner
  readonly client?: () => AgentClient
}

/** A home's three custodies, and which of them holds each name. */
export class HomeCustody {
  readonly files: FsKeyStore
  readonly keychain: KeychainCustody
  readonly agent: AgentCustody
  readonly #home: string
  readonly #run: { readonly run?: SecurityRunner }
  readonly #runner: SecurityRunner

  constructor(home: string, options: HomeCustodyOptions = {}) {
    this.#home = home
    this.#run = options.run === undefined ? {} : { run: options.run }
    this.#runner = options.run ?? runSecurity
    this.files = new FsKeyStore(join(home, 'keys'))
    this.keychain = new KeychainCustody({ dir: join(home, 'keychain'), ...this.#run })
    this.agent = new AgentCustody(join(home, 'agent'), options.client)
  }

  /**
   * The custody that holds `name` (checked first by the key files' rule): the keychain's when its pointer exists, else
   * the key files', whose refusals are those of a key file (ENOENT for a missing one); EEXIST when both hold it.
   */
  holder(name: string): KeyCustody {
    checkName('fs-keys', name)
    if (!present(this.#path('keychain', name))) return this.files
    if (present(this.#path('keys', name)))
      throw errno('EEXIST', `${name} has both a key file and a keychain pointer`)
    return this.keychain
  }

  entry(name: string): KeyEntry {
    if (!present(this.#path('agent', name))) return this.holder(name).entry(name)
    const other = [this.#path('keys', name), this.#path('keychain', name)].find(present)
    if (other !== undefined) throw errno('EEXIST', `${name} is held by the agent and by ${other}`)
    return this.agent.entry(name)
  }

  /** The keys of `name`: its custody's signer and opener of its address, from one read. */
  keys(name: string): EdgeKeys {
    const custody = this.holder(name)
    const { address } = custody.entry(name)
    return { signing: custody.signer(address), sealing: custody.opener(address) }
  }

  /** Every identity of the three custodies, by name, then custody. */
  list(): KeyEntry[] {
    const key = (e: KeyEntry): string => `${e.name} ${e.custody}`
    const all = [...this.files.list(), ...this.keychain.list(), ...this.agent.list()]
    return all.sort((a, b) => (key(a) < key(b) ? -1 : 1))
  }

  /** Makes `name` in the custody `target` names; EEXIST when any custody holds the name. */
  create(name: string, keys: EdgeKeys, target: CustodyTarget): KeyEntry {
    checkName('fs-keys', name)
    const other = [
      this.#path(target.custody === 'file' ? 'keychain' : 'keys', name),
      this.#path('agent', name),
    ].find(present)
    if (other !== undefined) throw errno('EEXIST', `${name} is held already, by ${other}`)
    if (target.custody === 'file') return this.files.create(name, keys)
    const { keychain, access } = target
    return new KeychainCustody({
      dir: join(this.#home, 'keychain'),
      ...(keychain === undefined ? {} : { keychain }),
      ...(access === undefined ? {} : { access }),
      ...this.#run,
    }).create(name, keys)
  }

  /**
   * Replaces the long-term sealing key of `name` by `seed` (32 random bytes; ac keys prune), keeping its signing
   * key and the key text's form. A key file is rewritten through a new 0600 file and a rename; a keychain item is
   * updated by one `security -i` line (`add-generic-password -U`) through the custody's runner, its pointer untouched;
   * the line names the pointer's access as create does (`-T ""` for prompt), so an item it has to add is not readable
   * by `security` without a dialog.
   * The line is zeroed after; a failed call has the keychain custody's codes. `-U` matches within the pointer's
   * keychain only: read the item back through a new HomeCustody (this one's reads are cached) to see which key it holds.
   */
  replaceSealing(name: string, seed: Uint8Array): void {
    const custody = this.holder(name)
    const { address } = custody.entry(name)
    const text = keyText({ signing: custody.signer(address), sealing: sealingKeyFromSeed(seed) })
    if (custody === this.files) {
      const file = this.#path('keys', name)
      const next = `${file}.${randomUUID()}.tmp`
      const was = lstatSync(file) // the key file's mtime is when the identity was made (keys list): kept
      writeNew(next, text)
      try {
        renameSync(next, file)
      } catch (e) {
        unlinkSync(next) // it holds sign_seed
        throw e
      }
      utimesSync(file, was.atimeMs / 1000, was.mtimeMs / 1000)
      return
    }
    const { keychain, access } = JSON.parse(readFileSync(this.#path('keychain', name), 'utf8')) as {
      keychain: string | null
      access: 'prompt' | 'security'
    }
    if (/["\\\n\r]/.test(keychain ?? '')) throw new Error('keychain: security -i cannot quote the path')
    const item = `-s bag:${name} -a ${address}${access === 'prompt' ? ' -T ""' : ''} -X ${toHex(utf8(text))}`
    const line = utf8(`add-generic-password -U ${item}${keychain === null ? '' : ` "${keychain}"`}\n`)
    try {
      const r = this.#runner(['-i'], line)
      if (r.status !== 0) throw failure(`replacing the item of ${name}`, r)
    } finally {
      line.fill(0)
    }
  }

  #path(dir: 'keys' | 'keychain' | 'agent', name: string): string {
    return join(this.#home, dir, `${name}.json`)
  }
}
