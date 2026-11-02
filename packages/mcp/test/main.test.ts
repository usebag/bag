import { describe, expect, it, vi } from 'vitest'

describe('main: the process entry', () => {
  it('serves on the process io and sets the exit code: a bad flag exits 2, with nothing on stdout', async () => {
    const argv = process.argv
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    process.argv = [argv[0] as string, 'main.ts', '--relay', 'http://relay.test']
    try {
      await import('../src/main.ts')
      expect(process.exitCode).toBe(2)
      expect(out).not.toHaveBeenCalled()
      // Node 24.4.1 may warn first that node:sqlite is experimental; the log line follows.
      const lines = err.mock.calls.map((c) => String(c[0])).filter((l) => l.startsWith('{'))
      expect(lines).toEqual([
        expect.stringMatching(
          /"event":"start","code":"usage","detail":"--as <key name> or --session auto\|auto:codex\|<name> is required"/,
        ),
      ])
    } finally {
      process.argv = argv
      out.mockRestore()
      err.mockRestore()
      process.exitCode = undefined
    }
  })
})
