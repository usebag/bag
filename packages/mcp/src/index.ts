import { packageName as coreName } from '@usebag/core'
import { packageName as edgeName } from '@usebag/edge'

// The public API of @usebag/mcp: the server, its configuration, the desk, the keepers, the name book's reader and
// the tools. The
// process entry is src/main.ts. Nothing in this repository imports this package but the e2e suite.

export {
  CHAIN_LEAD_S,
  CHAIN_RETRY_MAX_S,
  CHAIN_RETRY_S,
  ChainKeeper,
  type ChainKeeperOptions,
  type ChainSource,
  type ChainStatus,
  COMMAND_MAX_BYTES,
  COMMAND_TIMEOUT_MS,
  type Env,
  earliestExp,
  loadChain,
  parseChainText,
  type RunCommand,
  readChain,
  runShell,
  shellRunner,
} from './chain.ts'
export {
  type Config,
  ConfigError,
  DEFAULT_MAX_TOOL_SECONDS,
  DEFAULT_PROGRESS_SECONDS,
  MAX_TOOL_SECONDS,
  maxToolSeconds,
  PROFILES,
  PUSH_KINDS,
  parseConfig,
  parseServerConfig,
  progressSeconds,
  relayUrl,
  type ServerConfig,
  trustedRoot,
  USAGE,
} from './config.ts'
export {
  type Counts,
  Desk,
  HANDED_OFF,
  HANDOFF,
  type HandedOff,
  type InboxPage,
  type InboxQuery,
  type Message,
  parseResume,
  type Resume,
  realTimers,
  resumeToken,
  SESSION,
  type Timers,
  TRUST_NOTE,
  type Trust,
} from './desk.ts'
export { MAX_IDENTITIES, readIdentities } from './identities.ts'
export {
  KEEP_ALIVE_RETRY_MAX_S,
  KEEP_ALIVE_RETRY_S,
  type KeepAliveStatus,
  RecordKeeper,
  type RecordKeeperOptions,
} from './keepalive.ts'
export { jsonLogger, type Logger, type LogLevel, type LogValue } from './log.ts'
export { NAMES_FILE, type Named, type NameRef, Names } from './names.ts'
export {
  acquireLock,
  type Identity,
  type Observer,
  type OpenDeps,
  type Opened,
  observed,
  openIdentity,
  pidAlive,
} from './open.ts'
export { type ProgressExtra, type ProgressOptions, startProgress } from './progress.ts'
export { CHANNEL_NOTE, notice, registerPush } from './push.ts'
export { inboxUri, RESOURCE_NOTE, RESOURCE_SHOWN, registerInboxResource, unreadView } from './resource.ts'
export {
  type ManyDeps,
  type ProcessIo,
  processIo,
  type Running,
  type ServerDeps,
  serve,
  startIdentities,
  startServer,
} from './server.ts'
export { GRANT_RETRY_MS, type SessionStart, startSession } from './session.ts'
export {
  HINTS,
  type Refused,
  type SubscriptionState,
  Subscriptions,
  type SubscriptionView,
} from './subscriptions.ts'
export {
  codeOf,
  DELEGATE_MAX_SECONDS,
  detailOf,
  HANDOFF_TYPE,
  INSTRUCTIONS,
  QUESTION_TYPE,
  registerTools,
  TOOL_NAMES,
  type ToolContext,
  ToolError,
  UNREACHABLE,
} from './tools.ts'

/** The npm name of this package. */
export function packageName(): string {
  return '@usebag/mcp'
}

/** The workspace packages this one depends on, each read from that package's own export. */
export function dependsOn(): readonly string[] {
  return [coreName(), edgeName()]
}
