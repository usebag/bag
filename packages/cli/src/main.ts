// The bag CLI as a process: node packages/cli/src/main.ts <command> [options], or the bin `bag` of the published
// package (packages/bag), built from this file. Behind a proxy it first runs itself again with NODE_USE_ENV_PROXY=1 (the edge's
// proxy.ts), so that Node's fetch and WebSocket use the proxy. BAG_TEST_ZONE_FILE turns the test zone switch on for the
// process, with one line on stderr (the edge's test-zone.ts); a malformed switch is a usage line and exit 2.
import { activateTestZone, useEnvProxy } from '@usebag/edge'
import { run } from './cli.ts'
import { processIo } from './io.ts'
import { dropSqliteWarning } from './warnings.ts'

const hint = useEnvProxy()
if (hint !== null) process.stderr.write(`${hint}\n`)
dropSqliteWarning(process)
let zoned = true
try {
  activateTestZone(process.env, (line) => process.stderr.write(`${line}\n`))
} catch (e) {
  process.stderr.write(`bag: ${(e as Error).message}\n`)
  process.exitCode = 2
  zoned = false
}
if (zoned) process.exitCode = await run(process.argv.slice(2), processIo())
