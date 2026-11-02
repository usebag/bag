import { defineConfig } from 'vitest/config'

// No coverage gate here: the scenarios drive the packages through a real relay process, and coverage is gated per
// package. A scenario that cannot run fails; it is never skipped (a skipped test fails the run).
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // Builds target/release/ac-relay when it is missing and neither AC_RELAY_URL nor AC_RELAY_CMD is set.
    globalSetup: ['test/global-setup.ts'],
    // Real processes and sockets: generous timeouts, so a loaded machine slows the run instead of failing it.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Every scenario spawns the CLI, a bridge or a server with this process's environment, some with the real HOME:
    // DO_NOT_TRACK in every test process keeps the telemetry notice, its marker and the counts out of the real
    // machine store, whatever a scenario passes (the harness, the terminal and scenario 41 also set it themselves).
    env: { DO_NOT_TRACK: '1' },
    // The JSON report lets a run count skipped and todo tests (coverage/ is gitignored).
    reporters: ['default', 'json'],
    outputFile: { json: 'coverage/test-results.json' },
  },
})
