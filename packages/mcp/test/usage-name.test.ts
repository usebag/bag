import { describe, expect, it } from 'vitest'
import { USAGE } from '../src/config.ts'

// From source the usage names this checkout's entry; the package's (usage: bag-mcp) is pinned in packages/bag/test.
describe('the usage text from source', () => {
  it('names node packages/mcp/src/main.ts on both lines', () => {
    expect(USAGE).toContain(
      '\nusage: node packages/mcp/src/main.ts --as <key name> --relay <url>... [options]\n',
    )
    expect(USAGE).toContain('\n       node packages/mcp/src/main.ts --identities <file> [options]\n')
  })
})
