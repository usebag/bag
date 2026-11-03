import { describe, expect, it } from 'vitest'
import { programName } from '../src/program.ts'

// program.ts: how the three usage texts name their program (the package's own bins are pinned in packages/bag/test).
describe('programName', () => {
  it('from source: node and the entry; from the package: the bin', () => {
    expect(programName('bag', 'packages/cli/src/main.ts')).toBe('node packages/cli/src/main.ts')
    expect(programName('bag-mcp', 'packages/mcp/src/main.ts', true)).toBe('bag-mcp')
  })
})
