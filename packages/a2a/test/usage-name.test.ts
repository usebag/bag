import { describe, expect, it } from 'vitest'
import { USAGE } from '../src/run.ts'

// From source the usage names this checkout's entry; the package's (usage: bag-a2a) is pinned in packages/bag/test.
describe('the usage text from source', () => {
  it('names node packages/a2a/src/main.ts', () => {
    expect(USAGE).toContain('\nusage: node packages/a2a/src/main.ts --as <key name> --relay <url>...')
  })
})
