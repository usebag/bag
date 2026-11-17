// The identities file moved to packages/home, which the MCP server shares; the command line's modules read it here.
export {
  addIdentity,
  checkIdentities,
  type Identities,
  type Identity,
  keyOf,
  LABEL,
  localLabel,
  localOnly,
  MAX_IDENTITIES,
  readIdentities,
  refuseLocalOnly,
  removeIdentity,
  saveIdentities,
} from '@usebag/home'
