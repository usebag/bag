import { addToServiceHome as add } from '@usebag/home'
import { viaHome } from './home-io.ts'

// The bag service's identities file in a home moved to packages/home, which the MCP server shares; the command line's
// modules read it here. A relay that install/<name>.env names and that is no URL is a usage error, as before.
export { installEnv, RESERVED, refuseReserved } from '@usebag/home'

/** Adds `name` to <home>/identities.json when it is not there (packages/home's addToServiceHome). */
export function addToServiceHome(
  home: string,
  name: string,
  relays: readonly string[] = [],
  rendezvous?: string,
): string | null {
  return viaHome(() => add(home, name, relays, rendezvous))
}
