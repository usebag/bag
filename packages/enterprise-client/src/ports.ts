import {
  BUILD_INFO,
  type Clock,
  httpGet,
  RelayGuard,
  type Rng,
  systemClock,
  systemDns,
  systemRng,
  testZoneDns,
} from '@usebag/edge'
import type { DiscoveryNet } from './discovery.ts'
import type { EnterpriseDeps } from './flow.ts'
import type { Fetch } from './instance.ts'
import type { Publisher } from './records.ts'

// What the flow runs on, apart from the home and the lines it says: the process's (systemPorts) or a test's. bag's
// commands and its MCP server each build an EnterpriseDeps from one of these (enterpriseDeps), so the flow never reads
// the process itself.

/** This client's version: the published build's, else `source`. It is sent to the instance as bag_version. */
export const VERSION: string = BUILD_INFO?.version ?? 'source'

/** The flow's ports: the environment, the clock and rng, the network, a wait, and where the agent's records go. */
export interface EnterprisePorts {
  readonly env: Readonly<Record<string, string | undefined>>
  readonly clock: Clock
  readonly rng: Rng
  readonly fetch: Fetch | undefined
  /** The discovery network: TXT records, the guarded GET of the org's record, the private-address guard. */
  readonly net: DiscoveryNet
  readonly sleep: (ms: number) => Promise<void>
  /** Where the agent's records are published; unset, bag's own HTTP relay client (a test passes a fake). */
  readonly relays?: Publisher
}

/** The flow's deps over `ports` and the bag home: lines go to `say`, the console code comes from `readCode`. */
export function enterpriseDeps(
  ports: EnterprisePorts,
  home: string,
  say: (line: string) => void,
  readCode: () => Promise<string | null>,
): EnterpriseDeps {
  return {
    home,
    env: ports.env,
    clock: ports.clock,
    rng: ports.rng,
    fetch: ports.fetch,
    net: ports.net,
    sleep: ports.sleep,
    say,
    readCode,
    ...(ports.relays === undefined ? {} : { relays: ports.relays }),
  }
}

/**
 * The process's ports under `env`: the system clock, CSPRNG and DNS, globalThis.fetch, the edge's guarded well-known
 * GET (httpGet, the one bag's CLI reads well-known records with) and a private-address guard with no own relays.
 */
/** The system's DNS, with the test zone switch's zone file answering its names while the switch is on. */
const zoned = testZoneDns(systemDns)

export function systemPorts(env: Readonly<Record<string, string | undefined>>): EnterprisePorts {
  return {
    env,
    clock: systemClock,
    rng: systemRng,
    fetch: globalThis.fetch,
    net: { txt: (name) => zoned.txt(name), get: httpGet, guard: new RelayGuard({ own: [] }) },
    sleep: (ms) => new Promise((done) => setTimeout(done, ms)),
  }
}
