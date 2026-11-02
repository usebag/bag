import { describe, expect, it, vi } from 'vitest'
import { USAGE } from '../src/cli.ts'

describe('main: the process entry', () => {
  it('runs the command line of process.argv on the process io and sets the exit code', async () => {
    const argv = process.argv
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    process.argv = [argv[0] as string, 'main.ts', 'help']
    // The process io reads the real environment: DO_NOT_TRACK keeps this run out of the machine's telemetry store.
    vi.stubEnv('DO_NOT_TRACK', '1')
    try {
      await import('../src/main.ts')
      expect(process.exitCode).toBe(0)
      expect(write).toHaveBeenCalledWith(`${USAGE}\n`)
    } finally {
      process.argv = argv
      write.mockRestore()
      vi.unstubAllEnvs()
      process.exitCode = undefined
    }
  })
})
