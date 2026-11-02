import { mkdirSync, readdirSync, readFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import {
  AcError,
  checkGroupKeyBody,
  decodeAddress,
  encodeAddress,
  fromHex,
  type GroupKeyBody,
  isHex,
  parseJson,
  SealingKey,
  toHex,
} from '@usebag/core'
import { errno, present, strict, writeNew } from './files.ts'

// The group store: one directory per group, <dir>/<the group's 64 hex>/, of mode 0700,
// holding g<n>.json, generation n's body as its holder received it (the wrap, never the private key), and the
// admin's state.json (public data), each of mode 0600. A generation is written once, with an exclusive create; a
// renewal (the same key, a later hop) and a new state replace their file through a new file and a rename. No message
// here holds key material: a body holds none.
//
// A member also keeps, under its KEYS tree (the second root, <home>/keys/groups/<name>/<group hex>/g<n>.key, mode
// 0600 in a 0700 dir, beside the identity's own sealing seed), the opened generation key at rest: its 32 hex seed,
// written once. It lives inside keys/ (never outside it) so the registered secret scans, which read every file of a
// home outside keys/, never see a generation's private key. The key is decoupled from the member's short-lived epoch
// sealing key (forward secrecy), so the member opens a generation it accepted after that epoch key is deleted;
// never logged, never published. The SEALED body (no private key) stays under the groups root. A store built with no
// keys root keeps no such key (putKey is a no-op, heldKey is null): then an opener opens each body against the live
// holder, as before. The admin does not need one: it opens its own copy with its durable identity sealing key
// (groups/admin.ts).

const PREFIX = 'groups'

/** A member as the admin keeps it: its address, its hop's exp, and the relays its records are looked up at first. */
export interface GroupMember {
  readonly address: string
  readonly exp: number
  readonly relays: readonly string[]
}

/** A removed member, listed in the group record's revoked list until `until` (spec/SPEC.md §7.2's rule). */
export interface RevokedMember {
  readonly address: string
  readonly until: number
}

/** What the admin keeps of a group: the generation, the record's last iat, relays, ttl and rotation key, the members. */
export interface GroupState {
  readonly group: string
  readonly generation: number
  readonly iat: number
  readonly relays: readonly string[]
  readonly ttl: number
  readonly rotationKey: string
  readonly members: readonly GroupMember[]
  readonly revoked: readonly RevokedMember[]
}

/** How a body was kept: a new generation, a renewal of a held one, or nothing new. */
export type Kept = 'new' | 'renewed' | 'held'

let temp = 0

/** Writes `text` to `file` through a new 0600 file and a rename, so a reader sees the old text or the new. */
function replace(file: string, text: string): void {
  const next = `${file}.${process.pid}.${temp++}.tmp`
  writeNew(next, text)
  renameSync(next, file)
}

export class GroupKeyStore {
  readonly #dir: string
  readonly #keysDir: string | undefined

  /**
   * `dir` is the groups root (<home>/groups/<name>): the sealed bodies and the admin's state. `keysDir` is the member's
   * keys root for this group store (<home>/keys/groups/<name>), where the opened generation keys are kept at rest,
   * beside the identity's own sealing seed under <home>/keys. Pass `keysDir` for a member that accepts group keys (so
   * it keeps access past its epoch key's deletion); omit it where no opened key is kept (the bodies are opened against
   * a live holder each time, as before): a store with no keys root keeps none (putKey is a no-op, heldKey is null).
   */
  constructor(dir: string, keysDir?: string) {
    this.#dir = dir
    this.#keysDir = keysDir
  }

  /** The generations held of a group, newest first; none when its directory does not exist. */
  generations(group: string): number[] {
    const dir = this.#group(group)
    if (!present(dir)) return []
    strict(PREFIX, dir, true)
    return readdirSync(dir)
      .flatMap((f) => /^g([1-9][0-9]*)\.json$/.exec(f)?.slice(1, 2) ?? [])
      .map(Number)
      .sort((a, b) => b - a)
  }

  /**
   * Every body held, by group, newest first: what `ac login` replays into P's agent, each through takeGroupKey({body}).
   * The stored bodies only, never a key; one with no hop (the group's own copy, the admin's) is left out,
   * the agent takes none. None when the store does not exist; strict()'s refusals for a symlink or a loose mode.
   */
  groups(): GroupKeyBody[] {
    if (!present(this.#dir)) return []
    strict(PREFIX, this.#dir, true)
    return readdirSync(this.#dir)
      .filter((d) => /^[0-9a-f]{64}$/.test(d))
      .sort()
      .map((d) => encodeAddress(fromHex(d, 32)))
      .flatMap((g) => this.generations(g).map((n) => this.body(g, n)))
      .filter((b) => b.hop !== null)
  }

  /** Generation `n`'s body, checked for its form and its place (bad-content); ENOENT when it is not held. */
  body(group: string, n: number): GroupKeyBody {
    const file = join(this.#group(group), `g${n}.json`)
    if (!present(file)) throw errno('ENOENT', `${PREFIX}: no generation ${n} of ${group} is held`)
    strict(PREFIX, file, false)
    const body = checkGroupKeyBody(parseJson(readFileSync(file), 'bad-content'))
    if (body.group !== group || body.generation !== n) {
      throw new AcError('bad-content', `${file} holds another generation`)
    }
    return body
  }

  /**
   * Keeps a body its holder verified (openGroupKey): a new generation is written once; a held one with the same key
   * and a hop that lasts longer replaces its file (a renewal); bad-key for another key at a held generation.
   */
  put(body: GroupKeyBody): Kept {
    const dir = this.#group(body.group)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, this.#dir, true)
    strict(PREFIX, dir, true)
    const file = join(dir, `g${body.generation}.json`)
    const text = JSON.stringify(checkGroupKeyBody(body))
    if (!present(file)) {
      writeNew(file, text)
      return 'new'
    }
    const held = this.body(body.group, body.generation)
    if (held.sealing_key !== body.sealing_key) {
      throw new AcError('bad-key', `generation ${body.generation} of ${body.group} is held with another key`)
    }
    if ((body.hop?.exp ?? 0) <= (held.hop?.exp ?? 0)) return 'held'
    replace(file, text)
    return 'renewed'
  }

  /**
   * Keeps the opened generation key of generation `n` at rest, for a member (groups/member.ts acceptGroupKey): its
   * 32-byte seed as hex in <keys root>/<group hex>/g<n>.key, mode 0600, written once (a second accept of the held
   * generation keeps the key it holds). The group's keys dir is made 0700 and checked strict first, as `put` does.
   * This is the member's durable local custody of the key, decoupled from its short-lived epoch sealing key; it is
   * never logged. A no-op when the store was built with no keys root (then an opener opens the body against the holder).
   */
  putKey(group: string, n: number, key: SealingKey): void {
    if (this.#keysDir === undefined) return
    const dir = this.#keysGroup(group)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, dir, true)
    const file = join(dir, `g${n}.key`)
    if (present(file)) return
    writeNew(file, toHex(key.exportSeed()))
  }

  /**
   * The opened generation key kept at rest for generation `n`, or null when none is kept (the store has no keys root,
   * or no key file for `n`): an opener then falls back to the body. strict()'s refusals for a loose mode or a symlink;
   * bad-content for a file that is not a 32-byte seed.
   */
  heldKey(group: string, n: number): SealingKey | null {
    if (this.#keysDir === undefined) return null
    const file = join(this.#keysGroup(group), `g${n}.key`)
    if (!present(file)) return null
    strict(PREFIX, file, false)
    const hex = readFileSync(file, 'utf8').trim()
    if (!isHex(hex, 32)) throw new AcError('bad-content', `${file} is not a generation key`)
    return new SealingKey(fromHex(hex, 32))
  }

  /** The admin's state of a group, or null when it keeps none. */
  state(group: string): GroupState | null {
    const file = join(this.#group(group), 'state.json')
    if (!present(file)) return null
    strict(PREFIX, file, false)
    const state = parseJson(readFileSync(file)) as GroupState
    if (state.group !== group) throw new AcError('bad-json', `${file} holds another group's state`)
    return state
  }

  /** Writes the admin's state of a group, replacing the last. */
  saveState(state: GroupState): void {
    const dir = this.#group(state.group)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    strict(PREFIX, dir, true)
    replace(join(dir, 'state.json'), JSON.stringify(state))
  }

  #group(group: string): string {
    return join(this.#dir, toHex(decodeAddress(group)))
  }

  #keysGroup(group: string): string {
    return join(this.#keysDir as string, toHex(decodeAddress(group)))
  }
}
