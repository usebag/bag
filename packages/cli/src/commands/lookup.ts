import { isAddress, isHandle } from '@usebag/core'
import { type LookupReport, RelayGuard, Resolver } from '@usebag/edge'
import { flag, list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { homeDir, openEdge } from '../home.ts'
import type { Io } from '../io.ts'

// lookup: where an address's records live. It prints what the identity's cache holds, then what each relay
// answered, asked as a send resolves (the --at hints, then the --relay relays). It writes nothing: no cache, pin or audit.
// A domain's lookup and a handle's (spec/SPEC.md §12.2, §12.4) print each step: the TXT record, the org record at the
// origin, the handle record, then the address's records at the org record's relays, the hints and the --relay relays.

const DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/

/** The lines of a lookup: the cache first, then one per source asked. */
export function lookupLines(report: LookupReport): string[] {
  const c = report.cached
  const cache =
    c === null ? 'none' : `kind=${c.kind} iat=${c.iat} valid_until=${c.valid_until} source=${c.source ?? '-'}`
  return [
    `cache ${report.subject} ${cache}`,
    ...report.results.map((r) => {
      const fields = [`kind=${r.kind}`]
      for (const name of ['iat', 'valid_until', 'key'] as const)
        if (r[name] !== undefined) fields.push(`${name}=${r[name]}`)
      if (r.detail !== undefined) fields.push(r.detail)
      return `${r.relay} ${r.outcome} ${fields.join(' ')}`
    }),
  ]
}

/**
 * lookup <address|domain:<host>|handle> --as <name> --relay <url>... [--at <url>...] [--allow-private-relays] [--dir <home>]:
 * opens the identity's edge as send does, for its record cache; a private relay that is not a --relay is refused.
 */
export async function lookup(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['address'],
    options: {
      as: { type: 'string' },
      relay: { type: 'string', multiple: true },
      at: { type: 'string', multiple: true },
      'allow-private-relays': { type: 'boolean' },
      dir: { type: 'string' },
    },
    required: ['as', 'relay'],
  })
  const subject = p.positionals[0] as string
  const domain = subject.startsWith('domain:') ? subject.slice('domain:'.length) : null
  if (domain === null ? !isAddress(subject) && !isHandle(subject) : !DOMAIN.test(domain)) {
    throw new UsageError(`${JSON.stringify(subject)} is neither an address, domain:<host> nor a handle`)
  }
  const relays = list(p, 'relay').map(relayUrl)
  const allowPrivateRelays = flag(p, 'allow-private-relays')
  const client = io.relay({})
  const home = homeDir(io, str(p, 'dir'))
  const where = { home, name: req(p, 'as'), relay: relays[0] as string, client, allowPrivateRelays }
  const opened = openEdge(io, { ...where, policy: { roots: [], types: [] } })
  try {
    const guard = new RelayGuard({ own: relays, allowPrivate: allowPrivateRelays })
    const { store, edge } = opened
    const source = io.records(client)
    const resolver = new Resolver({ store, source, clock: io.clock, audit: edge.audit, relays, guard })
    for (const line of lookupLines(await resolver.lookup(subject, list(p, 'at').map(relayUrl)))) io.out(line)
    return 0
  } finally {
    opened.close()
  }
}
