import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { DEFAULT_TTL, GROUP_RECORD_TTL, MAX_ENVELOPE_BYTES, MEMBERSHIP_SECONDS } from '@usebag/core'
import { GroupAdmin, GroupKeyStore } from '@usebag/edge'
import { flag, int, list, type OptionSpec, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { homeDir, loadKeys, openEdge } from '../home.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'
import { expiry } from './delegate.ts'
import { reportSent } from './send.ts'

/**
 * An identity's group store: the sealed bodies and an admin's state under <home>/groups/<name>, and a member's opened
 * generation keys kept at rest under <home>/keys/groups/<name>, so a member opens a
 * generation it holds after the epoch key that delivered it is deleted.
 */
export const groupStore = (home: string, name: string) =>
  new GroupKeyStore(join(home, 'groups', name), join(home, 'keys', 'groups', name))

const SENDS_ONLY = { roots: [], types: [] }
const [S, M] = [{ type: 'string' }, { type: 'string', multiple: true }] as const
const VERBS: Record<string, [string[], Record<string, OptionSpec>]> = {
  create: [[], { relay: M, 'rotation-key': S, root: M, ttl: S, 'max-bytes': S, retention: S }],
  add: [['member'], { exp: S, 'relay-hint': M }],
  remove: [['member'], {}],
  rotate: [[], {}],
  keep: [[], { every: S, once: { type: 'boolean' } }],
}

// group <verb> <name>: GroupAdmin's steps, CLI only; no key printed; records at members' relays too.
export async function group(args: readonly string[], io: Io): Promise<number> {
  const [verb = '', ...rest] = args
  const spec = VERBS[verb]
  if (spec === undefined) throw new UsageError('group create|add|remove|rotate|keep <name> ...')
  const options = { ...spec[1], 'allow-private-relays': { type: 'boolean' }, dir: S } as const
  const required = verb === 'create' ? ['relay', 'rotation-key'] : []
  const p = parse(rest, { positionals: ['name', ...spec[0]], options, required })
  const [[name, who], home] = [p.positionals as [string, string], homeDir(io, str(p, 'dir'))]
  const [keys, store] = [loadKeys(io, home, name), groupStore(home, name)]
  const relays = store.state(keys.signing.address)?.relays ?? list(p, 'relay').map(relayUrl)
  const at = { home, name, keys, relay: relays[0] as string, client: io.relay({}), policy: SENDS_ONLY }
  const opened = openEdge(io, { ...at, allowPrivateRelays: flag(p, 'allow-private-relays') })
  const admin = new GroupAdmin({ edge: opened.edge, keys, store, clock: io.clock, rng: io.rng })
  const theirs = () =>
    [...new Set(admin.state().members.flatMap((m) => m.relays))].filter((u) => !relays.includes(u))
  try {
    if (verb === 'create') {
      const [ttl, maxBytes] = [int(p, 'ttl') ?? GROUP_RECORD_TTL, int(p, 'max-bytes') ?? MAX_ENVELOPE_BYTES]
      const o = { relays, rotationKey: req(p, 'rotation-key'), roots: list(p, 'root'), ttl, maxBytes }
      const made = await admin.create({ ...o, retention: int(p, 'retention') ?? DEFAULT_TTL })
      io.out(`group ${admin.group} generation 1`)
      for (const kind of ['address', 'accept-from'])
        for (const u of relays) io.out(`published ${kind} ${admin.group} iat ${made.record.iat} ${u}`)
      return 0
    }
    const member = verb === 'add' || verb === 'remove' ? NameBook.load(home).resolve(who) : ''
    if (verb === 'add') {
      const exp = expiry(str(p, 'exp') ?? `+${MEMBERSHIP_SECONDS}`, io.clock.now())
      const o = { exp, relays: list(p, 'relay-hint').map(relayUrl) }
      const sent = await admin.add(member, o.relays.length > 0 ? o : { exp })
      io.out(`added ${member} exp ${exp}`)
      return reportSent(io, opened.edge, sent)
    }
    if (verb !== 'keep') {
      const r = await (verb === 'rotate' ? admin.rotate() : admin.remove(member))
      await opened.edge.publishRecord(r.record, theirs())
      io.out(`generation ${r.generation} sent ${r.sent.length} record iat ${r.record.iat}`)
      return 0
    }
    const { ttl } = admin.state()
    const every = int(p, 'every') ?? Math.max(1, Math.floor(ttl / 2))
    if (every >= ttl) throw new UsageError(`--every ${every} is not below the record's ttl, ${ttl} s`)
    for (;;) {
      const [record, more] = [await admin.keep(), theirs()]
      await opened.edge.publishRecord(record, more)
      for (const u of [...relays, ...more]) io.out(`published address ${admin.group} iat ${record.iat} ${u}`)
      if (flag(p, 'once')) return 0
      io.out(`next ${record.iat + every}`)
      const ms = (record.iat + every - io.clock.now()) * 1000
      if (await sleep(ms, false, { signal: io.stopSignal() }).catch(() => true)) return 0
    }
  } finally {
    opened.close()
  }
}
