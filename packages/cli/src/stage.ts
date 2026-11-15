import { fileURLToPath } from 'node:url'
import { BUILD_INFO } from '@usebag/edge'
import { type Build, type Staged, stage as stageOf } from '@usebag/home'
import { CLI_MAIN, MCP_MAIN, OMP_WAKE, PACKAGED } from './entries.ts'

// The staging of the package moved to packages/home (stage.ts there), which the MCP server shares; the command line
// names its own entries (entries.ts, which the package build replaces with the bundle's) and the shim's from source.

export { launcherText, type Staged } from '@usebag/home'

/** The shim's entry from source (packages/shim). */
const SHIM_SOURCE = fileURLToPath(new URL('../../shim/src/main.ts', import.meta.url))

/** The package this command line runs from, as staging takes it. */
export const buildOf = (
  packaged = PACKAGED,
  version = BUILD_INFO?.version ?? 'source',
  cli = CLI_MAIN,
  mcp = MCP_MAIN,
  omp = OMP_WAKE,
): Build => ({ packaged, version, cli, mcp, omp, shim: SHIM_SOURCE })

/**
 * Stages the package for `home` (packages/home's stage) and returns the entries in its version directory; from source,
 * the checkout's. A version directory already there with other bytes (two builds of one version) refuses `exists`.
 */
export function stage(
  home: string,
  packaged = PACKAGED,
  version = BUILD_INFO?.version ?? 'source',
  cli = CLI_MAIN,
  mcp = MCP_MAIN,
  omp = OMP_WAKE,
): Staged {
  return stageOf(home, buildOf(packaged, version, cli, mcp, omp), process.pid)
}
