import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fromHex, isAddress, isHex, SUITE, toHex } from '@usebag/core'
import { type AgentClient, AgentOpener, AgentSigner } from '../agent/client.ts'
import type { EdgeKeys, KeyCustody, KeyEntry, KeyPair } from '../ports.ts'
import { checkName, errno, names, strict, writeNew, writtenAt } from './files.ts'

// The agent custody: a public-data pointer per identity; its signer and opener ask the agent over `client()`.

const PREFIX = 'agent'
type Pointer = Pick<KeyEntry, 'address' | 'recovery'> & { readonly sealing_key: string }
const noSession = (): AgentClient => {
  throw errno('ENOENT', 'agent: no session is connected to an agent')
}

export class AgentCustody implements KeyCustody<KeyPair<AgentSigner, AgentOpener>> {
  readonly kind = 'agent'
  readonly #dir: string
  readonly #client: () => AgentClient

  constructor(dir: string, client: () => AgentClient = noSession) {
    this.#dir = dir
    this.#client = client
  }

  list(): KeyEntry[] {
    return names(PREFIX, this.#dir).map((name) => this.entry(name))
  }

  entry(name: string): KeyEntry {
    const { address, recovery } = this.#pointer(name)
    return { name, address, custody: 'agent', created: writtenAt(this.#file(name)), recovery }
  }

  /** Writes the pointer from the public halves of `keys`; the seeds go nowhere here (EEXIST for a name taken). */
  create(name: string, keys: EdgeKeys, recovery?: string): KeyEntry {
    const file = this.#file(name)
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, this.#dir, true)
    const pointer = { suite: SUITE, custody: 'agent', address: keys.signing.address, recovery }
    writeNew(file, JSON.stringify({ ...pointer, sealing_key: toHex(keys.sealing.publicKey) }))
    return this.entry(name)
  }

  signer(address: string): AgentSigner {
    this.#named(address)
    return new AgentSigner(address, this.#client)
  }

  opener(address: string): AgentOpener {
    return new AgentOpener(address, fromHex(this.#named(address).sealing_key, 32), this.#client)
  }

  #named(address: string): Pointer {
    const found = names(PREFIX, this.#dir)
      .map((name) => this.#pointer(name))
      .find((p) => p.address === address)
    if (found === undefined) throw errno('ENOENT', `agent: no pointer in ${this.#dir} is ${address}'s`)
    return found
  }

  #pointer(name: string): Pointer {
    const file = this.#file(name)
    strict(PREFIX, this.#dir, true)
    strict(PREFIX, file, false)
    const { suite, custody, address, sealing_key, recovery } = Object(JSON.parse(readFileSync(file, 'utf8')))
    if (suite !== SUITE || custody !== 'agent' || !isAddress(address) || !isHex(sealing_key, 32)) {
      throw new Error(`agent: ${file} is not an agent pointer`)
    }
    return { address, sealing_key, recovery: ['personal', 'none'].includes(recovery) ? recovery : undefined }
  }

  #file(name: string): string {
    checkName(PREFIX, name)
    return join(this.#dir, `${name}.json`)
  }
}
