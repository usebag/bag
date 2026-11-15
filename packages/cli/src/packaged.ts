import { BUILD_INFO } from '@usebag/edge'
import { type Mains, stableNode as stableNodeOf } from '@usebag/home'
import { CLI_MAIN, MCP_MAIN, OMP_WAKE, PACKAGED } from './entries.ts'
import { stage } from './stage.ts'

// The package's staging and its versions moved to packages/home (packaged.ts there), which the MCP server shares. The
// command line keeps the entries it was built with (entries.ts) as the defaults, and the node it runs on.

export {
  byVersion,
  currentFile,
  currentVersion,
  type Mains,
  pruneVersions,
  versionLine,
  versionsDir,
} from '@usebag/home'

/**
 * The entries to write for the home `home` (record keep's job, onboard's cron line, the refresher's job): stage.ts's,
 * the version-independent launchers under <home>/package/ that run the version <home>/package/current names, after the
 * package is staged at <home>/package/versions/<version>/ once. From source (`packaged` false), the checkout's entries.
 * Nothing but the launchers, `current` and `versions/` is written under <home>/package/, and no staged file is ever
 * replaced, so nothing changes under a running server (the package-in-use refusal is gone with the copy).
 */
export function stableMains(
  home: string,
  cli = CLI_MAIN,
  mcp = MCP_MAIN,
  packaged = PACKAGED,
  omp = OMP_WAKE,
  version: string = BUILD_INFO?.version ?? 'source',
): Mains {
  const {
    shim: _shim,
    notice: _notice,
    versioned: _versioned,
    ...mains
  } = stage(home, packaged, version, cli, mcp, omp)
  return mains
}

/** The node for another program's files (packages/home's stableNode), by default for the node running this. */
export function stableNode(
  exec = process.execPath,
  links?: readonly string[],
  real?: (path: string) => string,
): string {
  return stableNodeOf(exec, links, real)
}
