import { describe, expect, it } from 'vitest'
import * as cli from '../src/index.ts'

describe('@usebag/cli: the public API', () => {
  it('names its package', () => {
    expect(cli.packageName()).toBe('@usebag/cli')
  })

  it('resolves its workspace dependencies through the package names', () => {
    expect(cli.dependsOn()).toEqual(['@usebag/core', '@usebag/edge'])
  })

  it('exports the runner, its io, its errors and the name book by name', () => {
    expect(Object.keys(cli).sort()).toEqual([
      'CliError',
      'NAME',
      'NAMES_FILE',
      'NO_RECOVERY',
      'NameBook',
      'USAGE',
      'UsageError',
      'codeOf',
      'dependsOn',
      'packageName',
      'processIo',
      'run',
      'short',
    ])
  })
})

describe('@usebag/cli/names: the name book alone', () => {
  it('is the package export ./names, the same module as the root exports', async () => {
    const names = await import('@usebag/cli/names')
    expect(names.NameBook).toBe(cli.NameBook)
    expect(Object.keys(names).sort()).toEqual(['NAME', 'NAMES_FILE', 'NameBook', 'instant', 'short'])
  })
})
