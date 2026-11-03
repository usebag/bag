import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // The build and the processes it spawns take seconds, not the default 5.
    testTimeout: 60_000,
    hookTimeout: 120_000,
    // The JSON report lets a run count skipped and todo tests, which it reports as not run.
    reporters: ['default', 'json'],
    outputFile: { json: 'coverage/test-results.json' },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'json-summary'],
      // Floors, not targets. Raise them when coverage grows; never lower them to make a build pass.
      thresholds: { statements: 90, branches: 90, functions: 90, lines: 90 },
    },
  },
})
