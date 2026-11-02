// The bag CLI as a process: node packages/cli/src/main.ts <command> [options]. There is no bin entry, since
// one would change the npm lock.
import { run } from './cli.ts'
import { processIo } from './io.ts'
import { dropSqliteWarning } from './warnings.ts'

dropSqliteWarning(process)
process.exitCode = await run(process.argv.slice(2), processIo())
