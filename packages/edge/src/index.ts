// The public API of @usebag/edge (spec/SPEC.md §9): the ports, the services, the Edge that composes them, and
// the production adapters. Every export is listed by name.

export { FsAuditSink, readAuditLines } from './adapters/fs-audit.ts'
export { FsKeyStore } from './adapters/fs-keys.ts'
export {
  acquireLock,
  type LockFs,
  type LockHolder,
  type LockOptions,
  nodeLockFs,
  pidAlive,
  processStart,
  START_TOLERANCE,
} from './adapters/fs-lock.ts'
export {
  createHttpRelay,
  createRelayClient,
  type HttpRelayOptions,
  MAX_RESPONSE_BYTES,
} from './adapters/http-relay.ts'
export {
  createSecurityRunner,
  type KeychainAccess,
  KeychainCustody,
  type KeychainCustodyOptions,
  runSecurity,
  SECURITY_PATH,
  SECURITY_TIMEOUT_MS,
  type SecurityResult,
  type SecurityRunner,
  securityEnv,
} from './adapters/keychain.ts'
export { type Leave, RELAY_TURNS, RelayTurns } from './adapters/relay-turns.ts'
export {
  readAuditAnchor,
  readAuditAnchors,
  SqliteStore,
  type SqliteStoreOptions,
  storeLockPath,
} from './adapters/sqlite-store.ts'
export { systemClock, systemRng } from './adapters/system-clock.ts'
export {
  createRecordSource,
  httpGet,
  type OriginAnswer,
  type OriginGet,
  WELL_KNOWN_PATH,
  type WellKnownOptions,
  wellKnownUrl,
} from './adapters/well-known.ts'
export {
  createWsSubscriber,
  type SocketFactory,
  type SocketLike,
  subscribeUrl,
  type WsSubscriberOptions,
  webSocketFactory,
} from './adapters/ws-relay.ts'
export {
  type AnchorCheck,
  type AnchorState,
  type AnchorStore,
  AUDIT_DECISIONS,
  AUDIT_EVENTS,
  Audit,
  type AuditDecision,
  type AuditEntry,
  type AuditEvent,
  type AuditLine,
  type AuditValue,
  type AuditVerdict,
  checkAuditAnchor,
  parseAuditLine,
  verifyAuditLog,
} from './audit.ts'
export { BUILD_INFO, type BuildInfo } from './build-info.ts'
export { checkName } from './custody/files.ts'
export { type CustodyTarget, HomeCustody, type HomeCustodyOptions } from './custody/home.ts'
export {
  addressCopy,
  continueFrom,
  type Epoch,
  KeyEpochStore,
  keepAddressCopy,
  lastAddress,
} from './custody/key-records.ts'
export {
  newSeeds,
  type RecoveryState,
  readRecoveryState,
  readSheet,
  type Seeds,
  SHEET_LINES,
  seedKeys,
  sheetChecksum,
  sheetLines,
  writeRecoveryState,
  zeroSeeds,
} from './custody/recovery.ts'
export {
  Edge,
  type EdgeOptions,
  generateEdgeKeys,
  hopsFrom,
  type PeerRelays,
  type RenewedChain,
  type ReplyInput,
} from './edge.ts'
export * from './groups/index.ts'
export { isInboxTransition, isWaiting, TRANSIENT_CODES } from './inbox.ts'
export {
  EpochOpener,
  epochOpener,
  KeyRecordAdmin,
  type KeyRecordOptions,
  publishedKeyRecord,
  type Rotation as KeyRotation,
} from './key-records.ts'
export {
  type AddressClass,
  classifyAddress,
  GuardRefused,
  hostOf,
  ipv4Bytes,
  ipv6Bytes,
  type Lookup,
  type Refusal,
  RelayGuard,
  type RelayGuardOptions,
  type ResolveTxt,
  relayKey,
  systemDns,
  systemLookup,
  txtDns,
} from './net.ts'
export {
  heldSomewhere,
  INCOMPLETE_REVOCATION,
  type Lagging,
  type Offered,
  type OfferOptions,
  offerBehind,
  offerRecord,
} from './offer.ts'
export {
  backoff,
  jitterOf,
  MAX_BACKOFF,
  MAX_JITTER,
  retryWait,
  type TryFailure,
  UNREACHABLE,
} from './outbox.ts'
export { Policy, type PolicyOptions, type TrustedRoot, typeMatches } from './policy.ts'
export type {
  AuditAnchor,
  AuditSink,
  CacheKind,
  Clock,
  CustodyKind,
  Dns,
  DueTarget,
  EdgeErrorCode,
  EdgeKeys,
  EdgeStore,
  FetchedBytes,
  FetchProof,
  Frame,
  InboundMessage,
  InboxPatch,
  InboxRow,
  InboxState,
  KeyCustody,
  KeyEntry,
  KeyPair,
  KeyStore,
  Opener,
  OutboxEntry,
  OutboxReason,
  OutboxState,
  OutboxTarget,
  PairOpen,
  PairReach,
  Pin,
  PublishResult,
  Receipt,
  RecordAnswer,
  RecordSource,
  RelayClient,
  Rng,
  SessionHandler,
  Signer,
  SpawnContext,
  SpawnHook,
  Subscription,
  SubscriptionLink,
} from './ports.ts'
export { EdgeError, RelayError } from './ports.ts'
export { programName } from './program.ts'
export { RECEIPT_ACK, RECEIPT_HINT, RECEIPT_TYPE } from './receipts.ts'
export {
  MAX_REFUSALS,
  REFUSALS,
  Receiver,
  type ReceiverOptions,
  resubscribeDelay,
} from './receiver.ts'
export {
  type CachedRecord,
  domainRootRefusal,
  type HandleBinding,
  type LookupKind,
  type LookupReport,
  type LookupResult,
  type ResolvedRecipient,
  ResolveFailed,
  Resolver,
  type ResolverOptions,
  SPECIAL_USE_TLDS,
  type Tried,
  type VerifiedHandle,
} from './resolver.ts'
export { type RouteOutcome, Router } from './router.ts'
export {
  coreRng,
  Sender,
  type SenderOptions,
  type SendInput,
  type SendResult,
  type WaitingSend,
} from './sender.ts'

/** The npm name of this package (the scaffold export; the CLI reads it to check the workspace link). */
export function packageName(): string {
  return '@usebag/edge'
}

// The org policy at the edge: appended last, a registration of its own.
export {
  DEFAULT_BREAKERS,
  Gate,
  type GateOptions,
  type GateResult,
  type Held,
  PolicyRefusal,
  policyStatus,
  SendHeld,
} from './moderation/gate.ts'
export { allowAll, keyword, type Moderator } from './moderation/modules.ts'
// The word code and its rendezvous.
export {
  CODE_WORDS,
  type Code,
  claimRendezvous,
  codeSecret,
  formatCode,
  newWords,
  openRendezvous,
  parseCode,
  WORDS,
} from './pair-code.ts'
// The `peer` grant's protocol, for the CLI's peer commands and the MCP server's pair tools.
export {
  acceptPeer,
  digitsMatch,
  INVITE_PREFIX,
  type Invite,
  inviteOf,
  invitePeer,
  inviteText,
  MAX_CODE_MISSES,
  MAX_DIGIT_TRIES,
  MAX_INVITE_TTL,
  type PairingPorts,
  type PeerRequest,
  pairingCode,
  readInvite,
  refuseOtherInviter,
} from './pairing.ts'
// A corporate proxy: HTTPS_PROXY, HTTP_PROXY and NO_PROXY for fetch and the WebSocket through Node's own agent (one
// re-run with NODE_USE_ENV_PROXY=1), and the well-known GET's own CONNECT tunnel; shown without credentials.
export {
  bypassed,
  proxyFor,
  proxyShown,
  proxyStatus,
  REEXEC_GUARD,
  type ReexecProcess,
  useEnvProxy,
} from './proxy.ts'
// The telemetry switch, one per machine, its spool of counts and the report it builds: opt-in, read by the CLI, the
// MCP server and the A2A bridge; the sender sends each finished day's report once while it is on.
export {
  addTelemetryCounts,
  countDuration,
  countRelayCall,
  countRelayError,
  countTelemetry,
  flushTelemetry,
  machineTelemetryNotice,
  noticeText,
  PREVIEW_ID,
  readTelemetrySpool,
  relayName,
  setTelemetry,
  startTelemetry,
  stopTelemetry,
  TELEMETRY_COUNTS_FILE,
  TELEMETRY_FILE,
  TELEMETRY_NOTICE,
  TELEMETRY_PAIRS_FILE,
  TELEMETRY_SENT_FILE,
  type TelemetryReason,
  type TelemetryState,
  telemetryCode,
  telemetryDir,
  telemetryId,
  telemetryNotice,
  telemetryOn,
  telemetryReport,
  telemetrySince,
  telemetrySpoolBytes,
  telemetryState,
} from './telemetry.ts'
export { notePairs, type SentStore, trackPairs } from './telemetry-pairs.ts'
export {
  buildTelemetryReport,
  checkoutCommit,
  machineFacts,
  type TelemetryFacts,
  type TelemetryReport,
} from './telemetry-report.ts'
export {
  eraseTelemetry,
  type SendOptions,
  sendDueTelemetry,
  startTelemetrySender,
  telemetryDue,
  telemetryEndpoint,
  telemetrySent,
} from './telemetry-send.ts'
export {
  activateTestZone,
  isInTestZone,
  setTestZone,
  TEST_ZONE,
  TEST_ZONE_FILE_ENV,
  TEST_ZONE_ORIGINS_ENV,
  type TestZone,
  testZone,
  testZoneDns,
  testZoneFetch,
  testZoneFromEnv,
  testZoneLine,
  testZoneOrigin,
} from './test-zone.ts'
