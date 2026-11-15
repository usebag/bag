import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  parseRecord,
  serializeRecord,
  signRecord,
  verifyRecord,
  WILDCARD_ROOT,
} from '@usebag/core'
import { keepAcceptCopy, liftMaxBytes, RelayError, type SecurityRunner } from '@usebag/edge'
import { namedStates } from './check.ts'
import { homeCustody, loadKeys } from './keys.ts'
import { dropLocalPairs, needPairsTable, pairedLocally, peersPath } from './local.ts'
import { askWithRecheck, HomeError, type HomeIo } from './ports.ts'
import { newestAccept } from './records.ts'
import { readTrust, removeTrust } from './trust.ts'

// unpair: the person's act that ends a pairing (or a typed accept), the inverse of a pairing's yes. A root enters
// <home>/trust.json only by a person's explicit act, and leaves it only by this one, after one yes; never by an
// incoming message, a resolved record or a default. The accept-from is re-signed as the edge's admit re-signs it
// (packages/edge/src/pairing.ts): the newest record at the relays, its max_bytes and ttl kept, at max(now, its iat +
// 1), and published at every relay named. trust.json is one file for the whole home: a root that another identity's
// accept-from copy (<home>/records/<name>.accept.json) still names stays in it, for that identity.

/** What unpair takes: the identity, the root it ends, and the relays its accept-from is read and published at. */
export interface UnpairInput {
  readonly home: string
  readonly as: string
  readonly root: string
  readonly relays: readonly string[]
}

const declined = (): HomeError => new HomeError('declined', 'nothing was changed')

/** The files that say which custody holds `name`, for a check that it is still there after the question. */
export const custodyFiles = (home: string, name: string): string[] =>
  ['keys', 'keychain', 'agent'].map((d) => join(home, d, `${name}.json`))

/**
 * Ends the pairing of `as` with `root` (an address, or domain:<host>). An own identity paired locally leaves the
 * service's table (no relay is called); else trust.json and the accept-from at each relay are read, and nothing is
 * written until the yes, after which every relay is read again (a change while asking is stale-record). A newest
 * record of `*` is accept-all (it admits every root, and none can leave it); a root neither holds is not-trusted.
 * Says `untrusted <root>` or `not trusted <root>`; then `not accepted <root>`, or per relay `published accept-from
 * <agent> <relay>`, `unchanged ... stale-record` or `failed ... <code>`, throwing the first such code after them.
 */
export async function unpairRoot(io: HomeIo, { home, as, root, relays }: UnpairInput): Promise<void> {
  const keys = loadKeys(io.security, home, as)
  const agent = keys.signing.address
  if (root === agent) throw new HomeError('usage', `${root} is ${as} itself`)
  // An own identity paired locally (spec/SPEC.md 9.2): the pair leaves the service's table; no relay is called, since
  // a local pair is never in trust.json or an accept-from. An own identity with the table refused: nothing changes.
  if (ownAddresses(io.security, home).includes(root)) needPairsTable(home)
  if (pairedLocally(home, agent, root)) {
    const check = () => ({
      ...namedStates(home, io.env.HOME, [peersPath(home), ...custodyFiles(home, as)]),
      'local pair': pairedLocally(home, agent, root),
    })
    const question = `unpair ${as} and ${root} on this machine (run/local-peers.json)?`
    if (!(await askWithRecheck(io, question, check))) throw declined()
    const ours = (x: string, y: string): boolean => (x === agent && y === root) || (x === root && y === agent)
    dropLocalPairs(home, (q) => ours(q.a_addr, q.b_addr))
    io.say(`unpaired locally ${root}`)
    return
  }
  const trusted = Object.hasOwn(readTrust(home), root)
  const keptFor = trusted ? heldBy(home, as, agent, root) : []
  const client = io.relay({})
  const silent: RelayError[] = []
  // Each relay on its own: one whose record still holds the root (a past run could not reach it) is found, and one that
  // does not answer, undefined here, lags: it stops nothing (spec/SPEC.md Appendix B 110).
  const read = (url: string): Promise<AcceptFromRecord | null | undefined> =>
    newestAccept(client, [url], agent).catch((e: unknown) => {
      if (!(e instanceof RelayError)) throw e
      silent.push(e)
      return undefined
    })
  const held = await Promise.all(relays.map(read))
  if (!trusted && silent.length === relays.length) throw silent[0]
  const lag = relays.filter((_, i) => held[i] === undefined)
  const records = held.filter((r): r is AcceptFromRecord => r !== null && r !== undefined)
  const newest = records.sort((a, b) => b.iat - a.iat)[0]
  if (newest?.roots.includes(WILDCARD_ROOT)) {
    throw new HomeError(
      'accept-all',
      `the accept-from of ${agent} is *, which admits every root, so none can leave it: publish the ` +
        'roots to keep first (onboard --accept, or record accept-from and publish), then run unpair again',
    )
  }
  const accepted = records.some((r) => r.roots.includes(root))
  if (!trusted && !accepted) {
    throw new HomeError(
      'not-trusted',
      `${root} is in neither ${home}/trust.json nor the accept-from of ${agent} at ${relays.join(' ')}; ` +
        'nothing was changed',
    )
  }
  const places = [
    ...(trusted && keptFor.length === 0 ? [`${home}/trust.json`] : []),
    ...(accepted ? [`the accept-from at ${relays.join(' ')}`] : []),
  ]
  const kept = keptFor.length > 0 ? ` (it stays in ${home}/trust.json for ${keptFor.join(', ')})` : ''
  const question =
    places.length > 0
      ? `unpair ${root} from ${as} (${agent}): remove it from ${places.join(' and ')}?${kept}`
      : `unpair ${root} from ${as} (${agent}): nothing to remove${kept}; go on?`
  const check = () => ({
    ...namedStates(home, io.env.HOME, [join(home, 'trust.json'), ...custodyFiles(home, as)]),
    'accept-from copies': trusted ? heldBy(home, as, agent, root) : [],
  })
  if (!(await askWithRecheck(io, question, check))) throw declined()
  // A record published while the question waited (a pairing, an onboard refresh) would be overwritten by one
  // signed from the first read: each relay is read again, and any change refuses before anything is written.
  const after = await Promise.all(relays.map(read))
  if (after.some((r, i) => r !== undefined && held[i] !== undefined && r?.iat !== held[i]?.iat)) {
    throw new HomeError(
      'stale-record',
      `the accept-from of ${agent} changed while asking; nothing was changed: run unpair again`,
    )
  }
  if (keptFor.length > 0)
    io.say(`kept trust ${root}: the accept-from of ${keptFor.join(', ')} still names it`)
  else io.say(`${removeTrust(home, root) ? 'untrusted' : 'not trusted'} ${root}`)
  if (!accepted) {
    io.say(`not accepted ${root}`)
    if (lag.length === 0) return
    for (const url of lag) io.say(`failed accept-from ${agent} ${url} unreachable`)
    throw new HomeError('unreachable', `${lag.join(' ')} may still hold ${root}: run unpair again`)
  }
  const base = newest as AcceptFromRecord
  const left = base.roots.filter((r) => r !== root)
  if (left.length === 0) io.say(`last root: the accept-from of ${agent} now names only ${agent}, its owner`)
  const iat = Math.max(io.clock.now(), base.iat + 1)
  const record = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: agent,
    roots: left.length === 0 ? [agent] : left,
    max_bytes: liftMaxBytes(base.max_bytes),
    ttl: base.ttl,
    iat,
  })
  let failure: HomeError | null = null
  let taken = false
  for (const url of relays) {
    try {
      await client.publish(url, serializeRecord(record))
      taken = true
      io.say(`published accept-from ${agent} ${url}`)
    } catch (e) {
      const code = failed(e)
      io.say(`${code === 'stale-record' ? 'unchanged' : 'failed'} accept-from ${agent} ${url} ${code}`)
      const why = `${url} did not take the accept-from of iat ${iat}, which leaves out ${root}`
      failure ??= new HomeError(code, `${why}: run unpair again (it reads each relay's record)`)
    }
  }
  // The home copy follows the published record, so another identity's unpair reads this identity's roots as they are.
  if (taken) {
    try {
      keepAcceptCopy(home, as, record)
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e)
      io.warn(
        `the home copy ${home}/records/${as}.accept.json is stale (${why}): it may still name ${root}; run unpair again`,
      )
    }
  }
  if (failure !== null) throw failure
}

/**
 * The other identities of `home` whose accept-from copy still names `root`, sorted: a copy that the core verifies at its
 * own iat, of an owner other than `agent`, whose identity is still in the home. An unreadable or unverifiable copy
 * names no one.
 */
export function heldBy(home: string, as: string, agent: string, root: string): string[] {
  let files: string[]
  try {
    files = readdirSync(join(home, 'records'))
  } catch {
    return []
  }
  const names: string[] = []
  for (const file of files.sort()) {
    const name = /^(.+)\.accept\.json$/.exec(file)?.[1]
    // A copy counts only while its identity is here (a key file, keychain or agent pointer, as checkIdentity looks):
    // an orphaned copy names no one. Presence only: nothing under keys/ is read.
    if (name === undefined || name === as) continue
    if (!['keys', 'keychain', 'agent'].some((d) => existsSync(join(home, d, `${name}.json`)))) continue
    try {
      const parsed = parseRecord(readFileSync(join(home, 'records', file)))
      const r = verifyRecord(parsed, parsed.iat)
      if (r.kind === 'accept-from' && r.owner !== agent && r.roots.includes(root)) names.push(name)
    } catch {
      // an unreadable or unverifiable copy names no one
    }
  }
  return names
}

/** A failed publish's code, as the command line names a relay's: its own code, unreachable, or http-<status>. */
export function failed(e: unknown): string {
  if (!(e instanceof RelayError)) return 'error'
  return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
}

/** The addresses of this home's identities, by their custody entries (no key read); none when they do not list. */
export function ownAddresses(security: SecurityRunner | undefined, home: string): string[] {
  try {
    return homeCustody(security, home)
      .list()
      .map((e) => e.address)
  } catch {
    return []
  }
}
