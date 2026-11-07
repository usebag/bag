import {
  connect,
  type EnterpriseDeps,
  type EnterprisePorts,
  enterpriseDeps,
  enterpriseStatus,
  signInSecrets,
  signInThroughAgent,
  VERSION,
} from '@usebag/enterprise-client'

// The enterprise tools' work (tools.ts registers them): connect, sign_in and enterprise_status, the standalone `bag mcp`
// server's three (the enterprise client's mcp.ts, where the last is named status), run at this server's home on the
// library's own flow: the code's parse, the pin, the guard and the redeem are the library's, never redone here. An
// outcome holds the exit the command would end with and the lines it prints, scrubbed as the standalone server scrubs
// its results: the code and its secret part for connect, the device code and the token (before and after) for sign_in.

/** The enterprise tools, as tools.ts lists them. */
export const ENTERPRISE_TOOLS = ['connect', 'sign_in', 'enterprise_status'] as const

export type EnterpriseTool = (typeof ENTERPRISE_TOOLS)[number]

/** An enterprise tool's outcome: the command's exit, its lines (scrubbed), and its failure's code (null: no failure). */
export interface EnterpriseOutcome {
  readonly exit: number
  readonly lines: readonly string[]
  readonly code: string | null
}

/** The commands' deps over these ports, with every line collected instead of printed (stdout is the MCP transport). */
function collecting(ports: EnterprisePorts, home: string, lines: string[]): EnterpriseDeps {
  return enterpriseDeps(
    ports,
    home,
    (line) => lines.push(line),
    async () => null,
  )
}

/** `lines` with every piece of `secret` (the code, and its secret part) and every `more` taken out. */
function scrub(lines: readonly string[], secret: string | null, more: readonly string[]): string[] {
  let text = lines.join('\n')
  const pieces = secret === null ? [] : [secret, secret.slice(secret.lastIndexOf('.') + 1)]
  for (const p of [...pieces, ...more].filter((x) => x.length >= 8)) text = text.split(p).join('[the code]')
  return lines.length === 0 ? [] : text.split('\n')
}

/** The error's code, as the command prints it: its own, else `error`. */
function codeOf(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code
  return typeof code === 'string' && code !== '' ? code : 'error'
}

/** The error's public line, as the command prints it: "<code>: <detail>". */
function failure(e: unknown): string {
  const c = codeOf(e)
  const message = e instanceof Error ? e.message : String(e)
  return message.startsWith(`${c}: `) ? message : `${c}: ${message}`
}

/** The exit the command would end with on `e`: the enterprise error's own, else 1. */
function exitOf(e: unknown): number {
  const exit = (e as { exit?: unknown } | null)?.exit
  return typeof exit === 'number' && Number.isInteger(exit) && exit > 0 ? exit : 1
}

/** Runs one command into collected lines: a failing exit is the code `error`, a throw its own code and line. */
async function run(
  work: (lines: string[]) => Promise<number>,
  failed: (exit: number) => boolean,
  secret: string | null,
  more: () => readonly string[] = () => [],
): Promise<EnterpriseOutcome> {
  const lines: string[] = []
  try {
    const exit = await work(lines)
    return { exit, lines: scrub(lines, secret, more()), code: failed(exit) ? 'error' : null }
  } catch (e) {
    return { exit: exitOf(e), lines: scrub([...lines, failure(e)], secret, more()), code: codeOf(e) }
  }
}

/** A command's failure, as the standalone server marks it: any exit but 0 and 4 (waiting). */
const notDone = (exit: number): boolean => exit !== 0 && exit !== 4

/** Runs the enterprise tool `tool` with `args` over `ports` at the bag home `home`. */
export async function runEnterprise(
  ports: EnterprisePorts,
  home: string,
  tool: EnterpriseTool,
  args: Readonly<Record<string, unknown>>,
): Promise<EnterpriseOutcome> {
  const deps = (lines: string[]): EnterpriseDeps => collecting(ports, home, lines)
  if (tool === 'connect') {
    const code = typeof args.code === 'string' ? args.code : ''
    if (code.trim() === '')
      return { exit: 2, lines: ['usage: no code: paste the code from the console'], code: 'usage' }
    return run((lines) => connect(deps(lines), { text: code, version: VERSION }), notDone, code.trim())
  }
  if (tool === 'sign_in') {
    const [domain, instance] = [args.domain, args.instance].map((v) => (typeof v === 'string' ? v : ''))
    // The device code and the token are this home's; scrubbed from the result as well as never said.
    const before = signInSecrets(home)
    return run(
      (lines) =>
        signInThroughAgent(deps(lines), {
          domain: domain as string,
          instance: instance as string,
          version: VERSION,
        }),
      notDone,
      null,
      () => [...before, ...signInSecrets(home)],
    )
  }
  // Several organisations: org names one; else the most recently connected, named on the first line.
  const org = typeof args.org === 'string' && args.org !== '' ? { org: args.org } : {}
  const status = (lines: string[]): EnterpriseDeps => ({
    ...deps(lines),
    note: (line) => lines.push(line.replace(/^bag: /, '')),
    ...org,
  })
  return run(
    (lines) => enterpriseStatus(status(lines)),
    (exit) => exit === 1,
    null,
  )
}
