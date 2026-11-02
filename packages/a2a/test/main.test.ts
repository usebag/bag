import { describe, expect, it, vi } from 'vitest'

describe('main: the process entry', () => {
  it('runs the bridge on the process argv and sets the exit code: a bad flag exits 2', async () => {
    const argv = process.argv
    const before = { int: process.listeners('SIGINT'), term: process.listeners('SIGTERM') }
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    process.argv = [argv[0] as string, 'main.ts', '--nope']
    try {
      await import('../src/main.ts')
      expect(process.exitCode).toBe(2)
      expect(String(err.mock.calls[0]?.[0])).toMatch(/^a2a-bridge: /)
    } finally {
      process.argv = argv
      process.exitCode = undefined
      err.mockRestore()
      // The entry's signal listeners are this test's to remove; any the runner had stay.
      for (const l of process.listeners('SIGINT')) {
        if (!before.int.includes(l)) process.removeListener('SIGINT', l)
      }
      for (const l of process.listeners('SIGTERM')) {
        if (!before.term.includes(l)) process.removeListener('SIGTERM', l)
      }
    }
  })
})
