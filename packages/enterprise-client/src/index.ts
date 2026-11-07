import { packageName as coreName } from '@usebag/core'
import { packageName as edgeName } from '@usebag/edge'

// The public API of @usebag/enterprise-client: the agent side of a bag enterprise session (connect with a console's
// one-time code, sign-in by the device flow, the refresh tick, the agent's records at the organisation's relays, the
// MCP tools). bag's commands (@usebag/cli) and its MCP server (@usebag/mcp) are built on it.

export {
  type AgentSignInOptions,
  pinnedInstance,
  signInSecrets,
  signInThroughAgent,
} from './agent-sign-in.ts'
export { type ConnectOptions, connect, guardOrigin, sayRelayFailures } from './connect.ts'
export {
  CONNECT_CODE,
  type ConnectCode,
  connectCodeOf,
  isLoopbackOrigin,
  parseConnectCode,
} from './connect-code.ts'
export { withSession } from './defaults.ts'
export { type Directory, type DirectoryOptions, directory, resolveLabel } from './directory.ts'
export {
  bareOrigin,
  type DiscoveryNet,
  discoverInstance,
  ENTERPRISE_RECORD_PATH,
  RESERVED_LABELS,
} from './discovery.ts'
export {
  CLOCKS,
  chainText,
  defaultName,
  type EnterpriseDeps,
  enterpriseStatus,
  fingerprint,
  refreshDue,
  report,
  type SignInOptions,
  signIn,
  signOut,
  type Tick,
  tick,
} from './flow.ts'
export { AGENT_PATHS, call, EnterpriseError, type Fetch } from './instance.ts'
export {
  AGENT_TAGS,
  bindNonce,
  bindPreimage,
  layerNonce,
  type ReportedRelay,
  refreshPreimage,
  reportedHash,
  statePreimage,
} from './layer-auth.ts'
export { createMcpServer, MCP_TOOLS, serveMcp } from './mcp.ts'
export { type EnterprisePorts, enterpriseDeps, systemPorts, VERSION } from './ports.ts'
export {
  ACCEPT_MAX_BYTES,
  ACCEPT_TTL,
  ADDRESS_TTL,
  agentRecords,
  outcomeLine,
  type Publisher,
  type PublishOutcome,
  publishAgentRecords,
  readRecordsCopy,
  recordsDue,
  recordsPath,
} from './records.ts'
export {
  chainPath,
  enterpriseDir,
  lockPath,
  type Org,
  ownerOnly,
  type Pending,
  readPending,
  readSession,
  type Session,
  secureHome,
  writeJson,
} from './session.ts'
export {
  MAX_SOURCED_ROOTS,
  readTrustFile,
  type SourcedRoot,
  syncSourcedTrust,
  type TrustRoots,
  writeTrustFile,
} from './trust-file.ts'

/** The npm name of this package. */
export function packageName(): string {
  return '@usebag/enterprise-client'
}

/** The workspace packages this one depends on, each read from that package's own export (the scaffold check). */
export function dependsOn(): readonly string[] {
  return [coreName(), edgeName()]
}
