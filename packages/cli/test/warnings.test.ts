import { execFile } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { dropSqliteWarning, isSqliteWarning, type WarningSource } from '../src/warnings.ts'

// The CLI's warning filter (src/warnings.ts): Node 24.4.1's SQLite ExperimentalWarning is dropped, and every other
// warning still reaches the printers the process had, an ExperimentalWarning about anything else included.

const SQLITE = 'SQLite is an experimental feature and might change at any time'

function warning(name: string, message: string): Error {
  const w = new Error(message)
  w.name = name
  return w
}

describe('dropSqliteWarning', () => {
  it("drops only the SQLite ExperimentalWarning and passes every other to the process's own printers", () => {
    const source = new EventEmitter() as EventEmitter & WarningSource
    const printed: string[][] = [[], []]
    for (const out of printed) source.on('warning', (w: Error) => out.push(`${w.name}: ${w.message}`))
    dropSqliteWarning(source)
    expect(source.listenerCount('warning')).toBe(1)
    for (const w of [
      warning('ExperimentalWarning', SQLITE),
      warning('ExperimentalWarning', 'VM Modules is an experimental feature'),
      warning('DeprecationWarning', SQLITE),
      warning('Warning', 'something else'),
    ])
      source.emit('warning', w)
    const others = [
      'ExperimentalWarning: VM Modules is an experimental feature',
      `DeprecationWarning: ${SQLITE}`,
      'Warning: something else',
    ]
    expect(printed).toEqual([others, others])
    expect([
      isSqliteWarning(warning('ExperimentalWarning', SQLITE)),
      isSqliteWarning(new Error(SQLITE)),
    ]).toEqual([true, false])
  })

  it('as a process: node:sqlite loads with no warning on stderr, and another process.emitWarning still prints', async () => {
    const filter = fileURLToPath(new URL('../src/warnings.ts', import.meta.url))
    const script = [
      `import { dropSqliteWarning } from ${JSON.stringify(filter)}`,
      'dropSqliteWarning(process)',
      "await import('node:sqlite')",
      "process.emitWarning('another feature', 'ExperimentalWarning')",
    ].join('\n')
    const env: NodeJS.ProcessEnv = { ...process.env }
    delete env.NODE_OPTIONS
    const stderr = await new Promise<string>((done, fail) => {
      execFile(
        process.execPath,
        ['--input-type=module', '-e', script],
        { env, timeout: 30_000 },
        (e, _out, err) => (e === null ? done(err) : fail(e)),
      )
    })
    expect(stderr).not.toContain('SQLite')
    expect(stderr).toMatch(/^\(node:\d+\) ExperimentalWarning: another feature$/m)
  })
})
