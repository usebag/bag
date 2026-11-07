import { serveMcp } from '@usebag/enterprise-client'
import { parse, str } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { enterprisePorts } from './refresher.ts'

/**
 * mcp [--dir <home>]: the tools connect, sign_in and status as a stdio MCP server (@usebag/enterprise-client's mcp.ts)
 * until the host closes it or stdin ends (the SDK's stdio transport does not close at its end). stdout is the
 * transport: nothing else is written there, and the tools' lines go only into their results.
 */
export async function mcp(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, { positionals: [], options: { dir: { type: 'string' } } })
  const served = serveMcp(enterprisePorts(io), homeDir(io, str(p, 'dir')), io.mcpTransport)
  await Promise.race([served, ...(io.stdinEnded === undefined ? [] : [io.stdinEnded()])])
  return 0
}
