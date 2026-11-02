import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_RELAY_CMD, REPO } from './harness.ts'

// Runs once before the scenarios: with neither AC_RELAY_URL nor AC_RELAY_CMD set, builds the release relay when
// target/release/ac-relay is missing. CI builds it first and passes AC_RELAY_CMD.
export default function setup(): void {
  if (process.env.AC_RELAY_URL || process.env.AC_RELAY_CMD || existsSync(DEFAULT_RELAY_CMD)) return
  const rustup = join(homedir(), '.cargo', 'bin', 'cargo')
  const cargo = existsSync(rustup) ? rustup : 'cargo'
  console.log(`e2e: ${DEFAULT_RELAY_CMD} is missing; building it: cargo build --release --locked -p ac-relay`)
  const built = spawnSync(cargo, ['build', '--release', '--locked', '-p', 'ac-relay'], {
    cwd: REPO,
    stdio: 'inherit',
  })
  if (built.status !== 0)
    throw new Error('e2e: cargo build --release -p ac-relay failed; the scenarios need the relay')
}
