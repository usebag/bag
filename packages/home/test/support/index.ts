// What other packages' tests import from this package as @usebag/home/test-support (package.json exports): the relays
// table both identities.json readers are tested with, so the MCP server's reader is held to the same table as home's.
export {
  PUBLISHED_REFUSAL,
  RELAYS_CASES,
  type RelaysCase,
  relaysHome,
} from '../fixtures/identities-relays.ts'
