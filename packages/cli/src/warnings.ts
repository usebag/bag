// The one warning the CLI's process drops: Node 24 prints "ExperimentalWarning: SQLite is an
// experimental feature and might change at any time" on stderr when the edge loads node:sqlite, on every command. The
// filter takes Node's own printers off the process's 'warning' event and passes them every warning but that one, so
// any other warning, experimental or not, still prints as Node prints it. Only src/main.ts installs it: the library
// never does, so a host that embeds the edge keeps its warnings.

/** A listener of the process's 'warning' event. */
type WarningListener = (warning: Error) => void

/** The part of a process the filter touches. */
export interface WarningSource {
  listeners(event: 'warning'): WarningListener[]
  removeListener(event: 'warning', listener: WarningListener): unknown
  on(event: 'warning', listener: WarningListener): unknown
}

/** True for Node's ExperimentalWarning about SQLite (Node 24.4.1's text), and for no other warning. */
export function isSqliteWarning(warning: Error): boolean {
  return (
    warning.name === 'ExperimentalWarning' && /^SQLite is an experimental feature\b/.test(warning.message)
  )
}

/** Drops the SQLite ExperimentalWarning on `source`; every other warning reaches the listeners it had before. */
export function dropSqliteWarning(source: WarningSource): void {
  const printers = source.listeners('warning')
  for (const p of printers) source.removeListener('warning', p)
  source.on('warning', (warning) => {
    if (!isSqliteWarning(warning)) for (const p of printers) p(warning)
  })
}
