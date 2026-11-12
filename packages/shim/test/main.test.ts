import { describe, expect, it, vi } from 'vitest'

describe('main: the process entry', () => {
  it('runs on the process io and sets the exit code: a bad flag exits 2, nothing on stdout', async () => {
    const argv = process.argv
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    process.argv = [argv[0] as string, 'main.ts', '--bogus']
    try {
      await import('../src/main.ts')
      expect(process.exitCode).toBe(2)
      expect(out).not.toHaveBeenCalled()
      expect(err.mock.calls.map((c) => String(c[0])).join('')).toContain('usage: bag-shim')
    } finally {
      process.argv = argv
      out.mockRestore()
      err.mockRestore()
      process.exitCode = undefined
    }
  })
})
