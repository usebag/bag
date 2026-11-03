// The MCP server as a process: node packages/mcp/src/main.ts --as <key name> --relay <url> [options]. An MCP host
// (Claude Code, Codex, opencode, ...) starts it and speaks MCP over its stdin and stdout (packages/mcp/README.md).
// Behind a proxy it first runs itself again in the same process with NODE_USE_ENV_PROXY=1 (the edge's proxy.ts): the
// same pid, arguments and stdio, so the host's pipes and the lock files hold. serve logs the proxy it runs under.
import { useEnvProxy } from '@usebag/edge'
import { processIo, serve } from './server.ts'

useEnvProxy()
process.exitCode = await serve(processIo())
