// The telemetry report's closed schema, the client's copy (spec/SPEC.md Appendix B 111): the values of
// deploy/telemetry/src/schema.ts and src/builds.ts at TELEMETRY_SCHEMA_COMMIT, and MAX_BYTES of its src/index.ts. The
// public cut carries packages/ and never deploy/telemetry/ (cut/MANIFEST), so the edge holds a copy, and
// test/telemetry-report.test.ts imports the Worker's files wherever the checkout holds them and fails on any
// difference. This is the clients' one copy: the edge maps every value outside these sets to `other` before it
// stores or builds anything.

/**
 * The commit whose deploy/telemetry/src/schema.ts, builds.ts and index.ts these values copy (the package versions
 * 0.1.0, 0.1.1, 0.1.2, 0.2.0 and 0.2.1 as builds, and `version` as a command).
 */
export const TELEMETRY_SCHEMA_COMMIT = '20ad785ea8af8cd921341f639248b22e70b6e316'

/**
 * The builds a report's `build` may name (builds.ts): the published versions of the npm package @usebag/bag, and the
 * commit of any public cut whose checkout reports from source, of which none is listed yet.
 */
export const BUILDS: readonly string[] = ['0.1.0', '0.1.1', '0.1.2', '0.2.0', '0.2.1']

/** The largest count a report may carry: 2^19. Every count is 0 or a power of two up to it. */
export const MAX_COUNT = 2 ** 19

/** How many days before today a report's date may be: the client's spool keeps seven days, plus a day of skew. */
export const MAX_AGE_DAYS = 8

/** The largest report, in bytes (index.ts). */
export const MAX_BYTES = 4096

const words = (text: string): readonly string[] => text.trim().split(/\s+/)

/** The closed sets, by name. */
export const SETS = {
  build: [...BUILDS, 'other'],
  os: words('linux darwin win32 other'),
  arch: words('x64 arm64 other'),
  // The supported Node majors.
  node: words('22 24 26 other'),
  host: words('claude-code codex other'),
  // The two public relay names; any other relay is `other`, never its URL.
  relay: words('relay1 relay2 other'),
  // packages/cli/src/cli.ts, COMMANDS, help and version (the dispatcher answers both itself), and the verbs that split
  // jobs from acts (OBS-F6).
  command: words(`
    keygen init restore address keys login logout grant name peer unpair record publish delegate onboard group send
    resend inbox held audit status wake-hook session-code host lookup health telemetry help version
    record-keep peer-invite peer-accept host-install-claude-code host-install-codex keys-rotate other
  `),
  exit: words('0 1 2 3 other'),
  // packages/mcp/src/tools.ts, TOOL_NAMES; `other` takes the cells a family's cap merges (MAX_CELLS).
  tool: words('send inbox wait delegate ask handoff status lookup receipts pair_invite pair_accept other'),
  // packages/a2a/src/protocol.ts: METHODS' names, and `ok` or ERRORS' names as a request's outcome.
  method: words(`
    SendMessage SendStreamingMessage GetTask ListTasks CancelTask SubscribeToTask CreateTaskPushNotificationConfig
    GetTaskPushNotificationConfig ListTaskPushNotificationConfigs DeleteTaskPushNotificationConfig GetExtendedAgentCard
    other
  `),
  outcome: words(`
    ok parseError invalidRequest methodNotFound invalidParams internalError taskNotFound taskNotCancelable
    pushNotificationNotSupported unsupportedOperation contentTypeNotSupported invalidAgentResponse
    extendedAgentCardNotConfigured extensionSupportRequired versionNotSupported serverBusy other
  `),
  // packages/edge/src/audit.ts, AUDIT_EVENTS and AUDIT_DECISIONS.
  event: words(`
    verify policy dedup unseal route publish resolve pin rotate rate-limit subscribe moderate release onboard restore
    pair other
  `),
  decision: words('accept reject retry route queue other'),
  // `ok`, the closed set of spec/SPEC.md Appendix A (packages/core/src/errors.ts) and the policy code, then the codes
  // of the edge, the CLI, the MCP server and the bridge that are not in it.
  code: words(`
    ok
    bad-canonical bad-hex bad-address bad-key bad-json bad-shape bad-version bad-suite envelope-too-large
    too-many-recipients bad-id bad-sig stale-ts future-ts too-many-hops bad-hop too-many-caveats caveat-too-long
    chain-broken chain-not-to-sender exp-not-monotone hop-expired bad-hop-sig unknown-caveat caveat-failed
    not-recipient open-failed bad-content bad-thread too-many-prev bad-record too-many-relays too-many-revoked
    bad-record-sig future-iat record-expired bad-rotation
    body-too-large not-hosted root-not-accepted too-large-for-mailbox rate-limited bad-auth not-authorized not-found
    stale-record internal store-full no-nameplate
    untrusted-root type-not-accepted revoked pin-mismatch duplicate resolve-failed publish-failed unreachable bad-code
    leaked digits-mismatch
    policy-refused
    agent-locked not-in-grant busy chain-mismatch
    bad-invite invite-expired bad-request bad-mac not-for declined no-answer no-elicitation
    bad-audit bad-name bad-sheet custody-unsupported exists group-admin home-shared host-file-invalid
    identities-invalid name-exists name-unknown names-invalid no-forward-secrecy no-identity no-relays no-session-file
    no-tty not-individual rotation session-principal single-copy trust-invalid unhealthy unsafe-path window-open
    as-required body-names-other-identity cancelled thread-of-other-identity to-own-identity unknown-identity usage
    error other
  `),
  // The buckets of a duration, in the order a histogram lists them.
  duration: words('under-100ms under-1s under-10s under-60s 60s-or-more'),
  // The machine's peers at the day's end by age, and of each, those sent to in the 7 days before (W6). No `other`: the
  // family's cap is the set, so the client never merges a cell.
  pairs: words('under-7d under-7d-sending 7d-or-more 7d-or-more-sending'),
}

export type SetName = keyof typeof SETS

/** One member's type: a fixed number, a date, the install id, one of a set, counts, or histograms. */
export type Member =
  | { readonly kind: 'const'; readonly value: number }
  | { readonly kind: 'date' }
  | { readonly kind: 'id' }
  | { readonly kind: 'one'; readonly set: SetName }
  // Nested maps, one level per set, keyed from that set; each leaf a count.
  | { readonly kind: 'counts'; readonly keys: readonly SetName[] }
  // A map keyed from one set, each value a list of counts, one for each duration bucket in order.
  | { readonly kind: 'hist'; readonly key: SetName }

/** The members of a report, in the order a stored report keeps them, and nothing else. */
export const MEMBERS: Readonly<Record<string, Member>> = {
  schema: { kind: 'const', value: 1 },
  // The UTC date, never a time.
  date: { kind: 'date' },
  // The install id, 32 lowercase hex. It names the stored object through NAME_KEY and is never stored.
  id: { kind: 'id' },
  // The package's version, or from source the checkout's commit, when builds.ts lists it, else `other`.
  build: { kind: 'one', set: 'build' },
  os: { kind: 'one', set: 'os' },
  arch: { kind: 'one', set: 'arch' },
  node: { kind: 'one', set: 'node' },
  // The machine's host kind.
  host: { kind: 'one', set: 'host' },
  // The day's calls to each relay used.
  relays: { kind: 'counts', keys: ['relay'] },
  cli: { kind: 'counts', keys: ['command', 'exit', 'code'] },
  mcp: { kind: 'counts', keys: ['tool', 'code'] },
  // The MCP sessions the day's servers ran, by the host kind each served, never a host's name.
  sessions: { kind: 'counts', keys: ['host'] },
  // The A2A bridge: its starts by code, and its requests by method and outcome.
  bridge_starts: { kind: 'counts', keys: ['code'] },
  bridge_requests: { kind: 'counts', keys: ['method', 'outcome'] },
  // The audit lines (event, decision, reason), the reason `ok` or a code.
  audit: { kind: 'counts', keys: ['event', 'decision', 'code'] },
  pairing: { kind: 'counts', keys: ['code'] },
  // The peers of the machine's homes, summed over homes (opt-in at consent version 2; the red team's ruling, W6).
  pairs: { kind: 'counts', keys: ['pairs'] },
  relay_errors: { kind: 'counts', keys: ['relay', 'code'] },
  // How long each CLI command and each MCP tool call took.
  cli_durations: { kind: 'hist', key: 'command' },
  mcp_durations: { kind: 'hist', key: 'tool' },
}

/**
 * The most cells (counted leaves) each count family may carry. With every family at its cap, each duration family at
 * MAX_KEYS and a cut commit for the build, a report fits MAX_BYTES with at least 256 bytes to spare
 * (deploy/telemetry/test/worker.test.ts measures it). The client's rule (telemetry-report.ts): a family over its cap
 * keeps its largest cells, one fewer than the cap, and sums the rest into the family's `other` cell, `other` at every
 * level, bucketed as any count is. The Worker refuses a family over its cap. relays and sessions are capped at their
 * sets' sizes.
 */
export const MAX_CELLS: Readonly<Record<string, number>> = {
  relays: 3,
  cli: 12,
  mcp: 8,
  sessions: 3,
  bridge_starts: 4,
  bridge_requests: 4,
  audit: 12,
  pairing: 3,
  pairs: 4,
  relay_errors: 3,
}

/**
 * The most keys each duration family may carry, the least telling family per byte. The client keeps the commands or
 * tools with the largest counts, one fewer than the cap, and sums the rest into the `other` key bucket by bucket,
 * bucketed. The Worker refuses a family over its cap.
 */
export const MAX_KEYS: Readonly<Record<string, number>> = {
  cli_durations: 8,
  mcp_durations: 8,
}
