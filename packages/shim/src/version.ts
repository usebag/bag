// The shim's own version, sent in its hello and its MCP serverInfo: the package build (packages/bag/src/build.ts)
// replaces this module with the package's version as the bundle loads; from source it is `source`, as the CLI's version
// line says from source.
export const SHIM_VERSION: string = 'source'
