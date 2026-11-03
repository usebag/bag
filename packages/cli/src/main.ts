// The bag CLI as a process: node packages/cli/src/main.ts <command> [options], or the bin `bag` of the published
// package (packages/bag), built from this file. Behind a proxy it first runs itself again with NODE_USE_ENV_PROXY=1 (the edge's
// proxy.ts), so that Node's fetch and WebSocket use the proxy.
import { useEnvProxy } from '@usebag/edge'
import { run } from './cli.ts'
import { processIo } from './io.ts'
import { dropSqliteWarning } from './warnings.ts'

const hint = useEnvProxy()
if (hint !== null) process.stderr.write(`${hint}\n`)
dropSqliteWarning(process)
process.exitCode = await run(process.argv.slice(2), processIo())
