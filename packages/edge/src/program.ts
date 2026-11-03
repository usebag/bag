import { BUILD_INFO } from './build-info.ts'

/**
 * How a usage line names one of the three programs: its bin (`bag`, `bag-mcp`, `bag-a2a`) when it runs from the
 * published package (build-info.ts holds a build), else `node <source>`, the entry this checkout runs.
 */
export function programName(bin: string, source: string, packaged = BUILD_INFO !== null): string {
  return packaged ? bin : `node ${source}`
}
