// The host kind the shim reports in service/hello, found as the install page finds it (deploy/install/install.md,
// step 0): OMPCODE=1 is omp, else CLAUDECODE=1 is Claude Code (omp passes on a parent's CLAUDECODE=1, so omp is read
// first). Codex sets neither, so it is known only when the host says so in initialize (its clientInfo.name). Else
// other.

export type HostKind = 'omp' | 'claude-code' | 'codex' | 'other'

/** The host kind from the environment and, when known, the MCP client's name from initialize. */
export function hostKind(env: Readonly<Record<string, string | undefined>>, clientName = ''): HostKind {
  if (env.OMPCODE === '1') return 'omp'
  if (env.CLAUDECODE === '1') return 'claude-code'
  if (/codex/i.test(clientName)) return 'codex'
  if (/claude[ -]?code/i.test(clientName)) return 'claude-code'
  if (/\bomp\b|oh-my-pi/i.test(clientName)) return 'omp'
  return 'other'
}

/**
 * The longest a host waits for one tool call before it gives up on it, in milliseconds, or null for a host that
 * waits for good. Codex's default tool timeout is 60 s (its mcp_servers tool_timeout_sec); a call still running at
 * RESUME_AFTER_MS of it answers with a resume token instead (shim.ts).
 */
export function toolTimeoutMs(kind: HostKind): number | null {
  return kind === 'codex' ? 60_000 : null
}

/** How long before the host's tool timeout a still-running call is answered with a resume token, in milliseconds. */
export const RESUME_MARGIN_MS = 10_000
