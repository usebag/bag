import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { MAX_RELAYS } from '@usebag/core'
import { generateEdgeKeys, HomeCustody, KeyEpochStore, systemRng } from '@usebag/edge'

// The one table both identities.json readers are tested with (home's checkIdentities and the MCP server's reader), so
// they agree on an entry's relays: 0 to MAX_RELAYS distinct URLs, and relays [] refused for a key that was published.
// The MCP server's reader test imports it too, as @usebag/home/test-support, so the two readers are held to one table.
// Each reader words its own refusal; the table says only whether the entry is taken, and the published key's refusal is shared.

/** One case: an entry's relays, whether its key has a published epoch, and whether a reader takes it. */
export interface RelaysCase {
  readonly why: string
  readonly relays: unknown
  /** Make the key's key-records/ hold epoch 1 marked published (as a promotion or onboard leaves it). */
  readonly published: boolean
  readonly taken: boolean
  /** The detail a refusal names, when both readers word it the same (the published key's refusal). */
  readonly detail?: (label: string) => string
}

const R = (i: number): string => `https://r${i}.example`

/** The published key's refusal, word for word, in both readers. */
export const PUBLISHED_REFUSAL = (label: string): string =>
  `${label} was published: remove it, not its relays`

export const RELAYS_CASES: readonly RelaysCase[] = [
  { why: 'one relay', relays: [R(0)], published: false, taken: true },
  {
    why: `${MAX_RELAYS} relays`,
    relays: Array.from({ length: MAX_RELAYS }, (_, i) => R(i)),
    published: false,
    taken: true,
  },
  { why: 'no relays: this machine only', relays: [], published: false, taken: true },
  { why: 'relays on a published key', relays: [R(0)], published: true, taken: true },
  {
    why: 'no relays on a published key',
    relays: [],
    published: true,
    taken: false,
    detail: PUBLISHED_REFUSAL,
  },
  {
    why: `${MAX_RELAYS + 1} relays`,
    relays: Array.from({ length: MAX_RELAYS + 1 }, (_, i) => R(i)),
    published: false,
    taken: false,
  },
  { why: 'a repeated relay', relays: [R(0), R(0)], published: false, taken: false },
  { why: 'not a list', relays: R(0), published: false, taken: false },
]

/**
 * A new home (0700) at <dir>/home, `dir` an empty folder from the caller's own temp helper, holding a key file of
 * `key`, and, when `published`, epoch 1 of its address in key-records/ marked published. Returns the home and the
 * address; the entry to test is {label, key, home, relays}.
 */
export function relaysHome(dir: string, key: string, published: boolean): { home: string; address: string } {
  const home = join(dir, 'home')
  mkdirSync(home, { mode: 0o700 })
  const keys = generateEdgeKeys(systemRng)
  new HomeCustody(home).create(key, keys, { custody: 'file' })
  const address = keys.signing.address
  const store = new KeyEpochStore(join(home, 'key-records'))
  store.put(address, 1, keys.sealing, 1_800_000_000, 1_800_086_400)
  if (published) store.markPublished(address, 1)
  return { home, address }
}
