// The identities file moved to packages/home, which the MCP server shares; the command line's modules read it here.
export {
  addIdentity,
  checkIdentities,
  type Identities,
  type Identity,
  keyOf,
  LABEL,
  MAX_IDENTITIES,
  readIdentities,
  removeIdentity,
  saveIdentities,
} from '@usebag/home'
