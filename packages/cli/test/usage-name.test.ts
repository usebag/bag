import { describe, expect, it } from 'vitest'
import { USAGE } from '../src/cli.ts'

// The usage text from source names the entry this checkout runs; the package's text (usage: bag) is pinned in
// packages/bag/test/build.test.ts.
describe('the usage text from source', () => {
  it('names node packages/cli/src/main.ts', () => {
    expect(USAGE).toContain('\nusage: node packages/cli/src/main.ts <command> [options]\n')
  })
})
