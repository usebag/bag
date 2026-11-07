import { spawnSync } from 'node:child_process'
import { describe, expect, it } from 'vitest'

// The toolchain smoke. The harness and the 14 scenarios sit beside it (test/scenarios/).
describe('e2e toolchain smoke', () => {
  it('runs on Node 24 or later', () => {
    const major = Number(process.versions.node.split('.')[0])
    expect(major).toBeGreaterThanOrEqual(24)
  })

  it('loads node:sqlite and runs a query', async () => {
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(':memory:')
    try {
      expect(db.prepare('select 1 + 1 as two').get()).toEqual({ two: 2 })
    } finally {
      db.close()
    }
  })

  it('runs TypeScript source in a child node, with no build step, across workspace packages', () => {
    const entry = new URL('../../cli/src/index.ts', import.meta.url).href
    const code = `import { dependsOn } from ${JSON.stringify(entry)}; console.log(JSON.stringify(dependsOn()))`
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' })
    expect(child.status, child.stderr).toBe(0)
    expect(JSON.parse(child.stdout)).toEqual(['@usebag/core', '@usebag/edge', '@usebag/enterprise-client'])
  })
})
