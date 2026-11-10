// The MCP server as a process: node packages/mcp/src/main.ts --as <key name> --relay <url> [options]. An MCP host
// (Claude Code, Codex, opencode, ...) starts it and speaks MCP over its stdin and stdout (packages/mcp/README.md).
// Behind a proxy it first runs itself again in the same process with NODE_USE_ENV_PROXY=1 (the edge's proxy.ts): the
// same pid, arguments and stdio, so the host's pipes and the lock files hold. serve logs the proxy it runs under.
// BAG_TEST_ZONE_FILE turns the test zone switch on (the edge's test-zone.ts): one line on stderr, never stdout.
import { activateTestZone, useEnvProxy } from '@usebag/edge'
import { processIo, serve } from './server.ts'

useEnvProxy()
let zoned = true
try {
  activateTestZone(process.env, (line) => process.stderr.write(`${line}\n`))
} catch (e) {
  process.stderr.write(`bag-mcp: ${(e as Error).message}\n`)
  process.exitCode = 2
  zoned = false
}
if (zoned) process.exitCode = await serve(processIo())
