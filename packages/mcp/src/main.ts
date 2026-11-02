// The MCP server as a process: node packages/mcp/src/main.ts --as <key name> --relay <url> [options]. An MCP host
// (Claude Code, Codex, opencode, ...) starts it and speaks MCP over its stdin and stdout (packages/mcp/README.md).
import { processIo, serve } from './server.ts'

process.exitCode = await serve(processIo())
