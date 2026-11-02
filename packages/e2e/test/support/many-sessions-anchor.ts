import { spawn } from 'node:child_process'
import { basename } from 'node:path'

// The stand-in for a Claude Code session's main `claude` process (scenario 47). The MCP server's session name is
// anchored on the topmost `claude` ancestor of its process, found by `ps` (packages/edge/src/agent/session-name.ts);
// no flag or environment variable of the server names the anchor, so the scenario gives each server a real parent whose
// command line starts with `claude`, which the real walk then finds. Nothing in the server is faked.
//
//   node many-sessions-anchor.ts <main.ts> <server flags...>
//
// Run as `node`, this process re-runs itself with argv[0] set to `claude` (the anchor); run as `claude`, it prints its
// pid on stderr (AC_ANCHOR_PID=<pid>) and runs the MCP server as its child, stdio inherited, so the test's pipes reach
// the server itself. A signal goes down the chain; the exit status comes back up.

const [script, ...rest] = process.argv.slice(1)
const anchor = basename(process.argv0) === 'claude'

const child = anchor
  ? spawn(process.execPath, rest, { stdio: 'inherit' })
  : spawn(process.execPath, [script as string, ...rest], { stdio: 'inherit', argv0: 'claude' })

if (anchor) process.stderr.write(`AC_ANCHOR_PID=${process.pid}\n`)

for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => child.kill(signal))
child.once('error', (e) => {
  process.stderr.write(`many-sessions-anchor: ${e.message}\n`)
  process.exit(1)
})
child.once('exit', (code, signal) => process.exit(code ?? (signal === null ? 0 : 1)))
