import { join } from 'node:path'
import { invitePeer } from '@usebag/edge'
import {
  endLinks,
  newPairs,
  type PairingPorts,
  pairingCommands,
  readSession,
  runPairing,
  tick,
} from '@usebag/enterprise-client'
import { flag, parse, str, UsageError } from '../args.ts'
import { currentKey } from '../epochs.ts'
import { homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'
import { addTrust, removeTrust } from '../trust.ts'
import { pairingPorts } from './peer.ts'
import { deps } from './refresher.ts'

// pairings: the console's pairings for this machine's enterprise agent (decision 38b, packages/enterprise-client
// pairings.ts), for an agent with no MCP host to poll them. The OSS ceremony runs here as `peer invite` runs it, with
// the console's person in the inviter's seat: the code is posted to the instance (and printed), the digits come back
// typed on the console. A paired peer is named in the book and trusted in trust.json, as `peer invite` writes it; a
// link the console revokes or whose term ends leaves trust.json, and the accept-from drops it at the tick after.

const WATCH_MS = 15_000

/** pairings [--watch] [--org <domain>] [--dir <home>]: one pass over the console's pairings, or one every 15 s. */
export async function pairings(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: [],
    options: { watch: { type: 'boolean' }, org: { type: 'string' }, dir: { type: 'string' } },
  })
  const home = homeDir(io, str(p, 'dir'))
  const fetch = io.fetch ?? globalThis.fetch
  const signal = io.stopSignal()
  do {
    const s = readSession(home, str(p, 'org'))
    if (s === null) throw new UsageError(`no enterprise session in ${home}: run bag connect`)
    const profile = join(home, 'orgs', s.domain) // the profile's own home (enterprise-client session.ts)
    const commands = s.state === 'live' ? await pairingCommands(s, fetch) : null
    if (commands !== null) {
      const ports = machinePorts(io, home, s.name, s.org.relays[0] as string)
      for (const id of await endLinks(s, fetch, profile, commands, ports)) io.out(`unpaired ${id}`)
      for (const c of newPairs(profile, commands)) {
        io.out(`pairing ${c.id}`)
        await runPairing(s, fetch, profile, c, ports)
      }
      await tick({ ...deps(io, home), org: s.domain })
    }
    if (!flag(p, 'watch') || signal.aborted) return 0
    await (io.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms))))(WATCH_MS)
  } while (!signal.aborted)
  return 0
}

/** The ceremony on this machine for the identity `as` at its organisation's relay, and the writes `peer invite` makes. */
function machinePorts(io: Io, home: string, as: string, relay: string): PairingPorts {
  const keys = loadKeys(io, home, as)
  const sleep = io.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)))
  return {
    invite: async (o) => {
      const at = o.relay ?? relay
      const q = await invitePeer(pairingPorts(io, home, as, keys, [at]), {
        relay: at,
        keys,
        key: await currentKey(io, home, as, keys, at),
        ttl: o.ttl,
        ...(o.only === undefined ? {} : { only: o.only }),
        opened: (text, exp) => {
          io.out(`pairing code ${text}`)
          o.opened(text, exp)
        },
        refused: (from, code) => io.out(`refused ${from} ${code}`),
        ask: o.ask,
        leaked: (from) => io.out(`second request ${from}: the invite string leaked`),
        write: () => {},
      })
      return q.from
    },
    write: (peer, name) => {
      const book = NameBook.load(home)
      book.check(name, peer)
      book.add(name, peer, io.clock.now())
      book.save()
      addTrust(home, peer, io.clock.now())
      io.out(`paired ${name} ${peer}`)
    },
    remove: async (peer) => void removeTrust(home, peer),
    now: () => io.clock.now(),
    sleep,
  }
}
