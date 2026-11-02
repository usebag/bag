import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { AGENT } from './support.ts'

// card.ts as the process's entry (deploy/make-a2a-extension.sh runs `node packages/a2a/src/card.ts ...`): in a file of its
// own, so that card.ts is first imported here, with process.argv naming it. support.ts does not import card.ts.

describe('card.ts as a program', () => {
  it('runs makeCardMain on its argv when it is the entry, and sets the exit code', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bag-a2a-entry-'))
    const argv = process.argv
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    try {
      const record = join(dir, 'address.json')
      const fields = { kind: 'address', key: AGENT, sealing_key: '0'.repeat(64), relays: ['r'] }
      writeFileSync(record, JSON.stringify(fields))
      const out = join(dir, 'card.json')
      const entry = resolve(import.meta.dirname, '../src/card.ts')
      process.argv = [argv[0] as string, entry, '--record', record, '--out', out, '--domain', 'a.example']
      await import('../src/card.ts')
      expect(process.exitCode).toBe(0)
      expect(JSON.parse(readFileSync(out, 'utf8')).params.address).toBe(AGENT)
      expect(log).toHaveBeenCalledTimes(1)
    } finally {
      process.argv = argv
      process.exitCode = undefined
      log.mockRestore()
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
