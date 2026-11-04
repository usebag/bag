// The published package's build (packages/bag): its npm version and the commit it was built from. From source this is
// null. The package build (packages/bag/src/build.ts) replaces this module with the two values, so the package carries
// its source commit: `bag --version` prints it, the MCP server reports the version, and the telemetry report's `build`
// is the version (when BUILDS in telemetry-schema.ts lists it, else `other`).

/** A package build: the version in packages/bag/package.json and the 40-hex commit (plus -dirty for an unclean tree). */
export interface BuildInfo {
  readonly version: string
  readonly commit: string
}

/** This build, or null when running from source. */
export const BUILD_INFO: BuildInfo | null = null
