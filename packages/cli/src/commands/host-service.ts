import { serviceInstall as serviceText } from '@usebag/home'
import { stableNode } from '../packaged.ts'

// host install service: the login agent's text moved to packages/home (host-service.ts there), which the MCP server
// shares. The command line names the platform, the node and the user it runs as.

export { proxyOmitted, SERVICE_LABEL as LABEL, servicePlist, serviceUnit } from '@usebag/home'

/**
 * The output for `platform`: the plist (macOS) or the systemd user unit (Linux), stdout first, one line per proxy
 * variable left out, and the person's one line, which keeps the text only (packages/home's serviceInstall, which makes the
 * home's run/ first).
 */
export function serviceInstall(
  env: Readonly<Record<string, string | undefined>>,
  home: string,
  main: string,
  self: string,
  platform: string = process.platform,
  node = stableNode(),
  read?: (file: string) => string | null,
  prepare?: (dir: string) => void,
): string[] {
  return serviceText(env, home, main, self, platform, node, process.getuid?.(), read, prepare)
}
