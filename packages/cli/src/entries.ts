// The process entries that commands write into other programs' files (host install's .mcp.json and hooks, record
// keep's launchd job and cron line, onboard's cron line): absolute paths, run with this Node. From source they are this
// checkout's main.ts files; the published package (packages/bag/src/build.ts) replaces this module with its bins
// (dist/bag.js, dist/bag-mcp.js), which sit beside every chunk of the bundle, and PACKAGED true.
import { fileURLToPath } from 'node:url'

/** The CLI's entry. */
export const CLI_MAIN = fileURLToPath(new URL('./main.ts', import.meta.url))

/** The MCP server's entry. */
export const MCP_MAIN = fileURLToPath(new URL('../../mcp/src/main.ts', import.meta.url))

/** Whether this runs from the package's bundle, not from source. */
export const PACKAGED: boolean = false
