import { packageName as coreName } from '@usebag/core'
import { packageName as edgeName } from '@usebag/edge'

// The public API of @usebag/cli: the command runner, its io port and the name book (also ./names). The process entry is src/main.ts.

export { CliError, UsageError } from './args.ts'
export { codeOf, run, USAGE } from './cli.ts'
export { NO_RECOVERY } from './commands/keygen.ts'
export { type CliRelay, type Io, type ProcessLike, processIo } from './io.ts'
export { type Display, NAME, NAMES_FILE, NameBook, type NameEntry, type Previous, short } from './names.ts'

/** The npm name of this package. */
export function packageName(): string {
  return '@usebag/cli'
}

/** The workspace packages this one depends on, each read from that package's own export (the scaffold check). */
export function dependsOn(): readonly string[] {
  return [coreName(), edgeName()]
}
