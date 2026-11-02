import { type AcceptFromRecord, MAX_RELAYS, serializeRecord, signRecord, WILDCARD_ROOT } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { CliError, list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'
import { confirmed, needTty } from '../policy.ts'
import { isTrustRoot, readTrust, removeTrust } from '../trust.ts'
import { newestAccept } from './record.ts'

// unpair: the person's act that ends a pairing (or a typed --accept), the inverse of peer's y. The trust
// invariant holds both ways: a root enters <home>/trust.json only by a person's
// explicit act, and leaves it only by this one, on a terminal after one y; never by an incoming message, a
// resolved record or a default. The accept-from is re-signed as the edge's admit re-signs it
// (packages/edge/src/pairing.ts): the newest record at the relays, its max_bytes and ttl kept, at
// max(now, its iat + 1), and published at every relay named.

const S = { type: 'string' } as const

/**
 * unpair <address|domain:<host>> --as <name> --relay <url>... [--dir <home>]: a terminal first (no-tty
 * before any network); then trust.json and the accept-from at each relay are read, and nothing is written
 * until the y, after which every relay is read again (a change while asking is stale-record). A newest
 * record of `*` is accept-all (it admits every root, and none can leave it); a root neither holds is
 * not-trusted. Prints `untrusted <root>` or `not trusted <root>`; then `not accepted
 * <root>`, or per relay `published accept-from <agent> <relay>`, `unchanged ... stale-record` or
 * `failed ... <code>`, exiting 1 with the first such code. A record left with no root names only its owner:
 * the core refuses empty roots, and admit's rollback publishes the same `[owner]`.
 */
export async function unpair(args: readonly string[], io: Io): Promise<number> {
  const options = { as: S, relay: { ...S, multiple: true }, dir: S }
  const p = parse(args, { positionals: ['root'], options, required: ['as', 'relay'] })
  const root = p.positionals[0] as string
  if (!isTrustRoot(root)) {
    throw new UsageError(`${JSON.stringify(root)} is not a root: an address, or domain:<host> with no port`)
  }
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  if (relays.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  needTty(io, 'unpair')
  const home = homeDir(io, str(p, 'dir'))
  const as = req(p, 'as')
  const keys = loadKeys(io, home, as)
  const agent = keys.signing.address
  if (root === agent) throw new UsageError(`${root} is ${as} itself`)
  const trusted = Object.hasOwn(readTrust(home), root)
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
    throw new CliError(
      'accept-all',
      `the accept-from of ${agent} is *, which admits every root, so none can leave it: publish the ` +
        'roots to keep first (onboard --accept, or record accept-from and publish), then run unpair again',
    )
  }
  const accepted = records.some((r) => r.roots.includes(root))
  if (!trusted && !accepted) {
    throw new CliError(
      'not-trusted',
      `${root} is in neither ${home}/trust.json nor the accept-from of ${agent} at ${relays.join(' ')}; ` +
        'nothing was changed',
    )
  }
  const places = [
    ...(trusted ? [`${home}/trust.json`] : []),
    ...(accepted ? [`the accept-from at ${relays.join(' ')}`] : []),
  ]
  const question = `unpair ${root} from ${as} (${agent}): remove it from ${places.join(' and ')}?`
  await confirmed(io, question, 'nothing was changed')
  // A record published while the question waited (a pairing, an onboard refresh) would be overwritten by one
  // signed from the first read: each relay is read again, and any change refuses before anything is written.
  const after = await Promise.all(relays.map(read))
  if (after.some((r, i) => r !== undefined && held[i] !== undefined && r?.iat !== held[i]?.iat)) {
    throw new CliError(
      'stale-record',
      `the accept-from of ${agent} changed while asking; nothing was changed: run unpair again`,
    )
  }
  io.out(`${removeTrust(home, root) ? 'untrusted' : 'not trusted'} ${root}`)
  if (!accepted) {
    io.out(`not accepted ${root}`)
    if (lag.length === 0) return 0
    for (const url of lag) io.out(`failed accept-from ${agent} ${url} unreachable`)
    throw new CliError('unreachable', `${lag.join(' ')} may still hold ${root}: run unpair again`)
  }
  const base = newest as AcceptFromRecord
  const left = base.roots.filter((r) => r !== root)
  if (left.length === 0) io.out(`last root: the accept-from of ${agent} now names only ${agent}, its owner`)
  const iat = Math.max(io.clock.now(), base.iat + 1)
  const record = signRecord(keys.signing, {
    kind: 'accept-from',
    owner: agent,
    roots: left.length === 0 ? [agent] : left,
    max_bytes: base.max_bytes,
    ttl: base.ttl,
    iat,
  })
  let failure: CliError | null = null
  for (const url of relays) {
    try {
      await client.publish(url, serializeRecord(record))
      io.out(`published accept-from ${agent} ${url}`)
    } catch (e) {
      const code = failed(e)
      io.out(`${code === 'stale-record' ? 'unchanged' : 'failed'} accept-from ${agent} ${url} ${code}`)
      const why = `${url} did not take the accept-from of iat ${iat}, which leaves out ${root}`
      failure ??= new CliError(code, `${why}: run unpair again (it reads each relay's record)`)
    }
  }
  if (failure !== null) throw failure
  return 0
}

/** A failed publish's code, as cli.ts's codeOf names a relay's (importing it would make a cycle). */
export function failed(e: unknown): string {
  if (!(e instanceof RelayError)) return 'error'
  return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
}
