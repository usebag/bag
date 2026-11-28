import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { signInSecrets, signInThroughAgent } from './agent-sign-in.ts'
import { connect } from './connect.ts'
import { type EnterpriseDeps, enterpriseStatus } from './flow.ts'
import { type EnterprisePorts, enterpriseDeps, type HomeReads, VERSION } from './ports.ts'

// The enterprise client as a stdio MCP server, so a person in an MCP host pastes the console's connect code into the
// chat and the agent connects itself (nothing else typed). Three tools, nothing else: `connect` (the code, the
// command's own parse, pin, guard and redeem path: connect.ts), `sign_in` (no code: the domain and the console origin,
// the device flow a person approves, agent-sign-in.ts) and `status` (the command's status). No sign_out: its revoke is
// for good, and this server has no dialog to ask the person first (the bag service's window asks, or bag sign-out). A result holds only the
// public lines the commands print; the code given is never echoed (every result is scrubbed of it as well). The SDK is
// the one bag's MCP server uses, at its pin; its low-level Server takes plain JSON Schema, so no schema library is
// added.
//
// The honest limit: the code reaches this server as a tool argument, so it sits in the MCP host's transcript. Its
// defences are its life (15 minutes by default) and its single use: once redeemed, the string opens nothing.
//
// With the home's reads given (the CLI passes packages/home's) it also offers `identities`, and `status` leads with bag's version, the home's identities and its relays' health, so
// an agent in a window with no identity learns what the machine holds without the CLI or a page. It changes nothing.

export const MCP_TOOLS = [
  {
    name: 'connect',
    description:
      "Connects this machine's agent to its organisation with the one-time connect code a person copied from the bag enterprise console. Give the code exactly as pasted.",
    inputSchema: {
      type: 'object' as const,
      properties: { code: { type: 'string', description: 'The connect code from the console, as pasted.' } },
      required: ['code'],
      additionalProperties: false,
    },
  },
  {
    name: 'sign_in',
    description:
      "Signs this machine's agent in to its organisation without a code: a person approves it in the bag enterprise console. The first call returns the link to open and the agent key's fingerprint; call it again to see whether the person approved.",
    inputSchema: {
      type: 'object' as const,
      properties: {
        domain: { type: 'string', description: "The organisation's domain, such as example.com." },
        instance: {
          type: 'string',
          description: 'The bag enterprise console address, such as https://console.example.com.',
        },
      },
      required: ['domain', 'instance'],
      additionalProperties: false,
    },
  },
  {
    name: 'status',
    description:
      "Shows this machine's bag enterprise session: the organisation, the agent, its state and its clocks, and the relay round trip. Signed in to several organisations, it shows the most recently connected and names the others, unless org names one.",
    inputSchema: {
      type: 'object' as const,
      properties: { org: { type: 'string', description: "One organisation's domain, such as example.com." } },
      additionalProperties: false,
    },
  },
]

/**
 * What `identities` shows a window that acts as no identity: 'count', how many, with their names left to the person's
 * bind dialog (the default), or 'labels', their names and nothing else. Changing the default is this one line.
 */
export const UNBOUND_LISTING: 'count' | 'labels' = 'count'

/** The identities tool, offered when the home's reads are given. */
export const IDENTITIES_TOOL = {
  name: 'identities',
  description:
    "Lists the bag identities this machine holds. This window acts as none of them, so it shows how many there are and not their names (unless this build lists names): your person picks one in a window that runs the bag service, by answering its bind dialog or, where the host passes typed words to bag, by typing use and its name. It reads only this machine's identities file: no relay, no network, nothing changed.",
  inputSchema: { type: 'object' as const, properties: {}, additionalProperties: false },
}

/** The status tool's description when the home's reads are given: the home's facts first, then the enterprise session. */
const HOME_STATUS =
  "Shows this machine's bag: the version, how many identities it holds, and how many of the relays they name answer a health probe (those relays' URLs only when names are listed); then its bag enterprise session, if it has one (the organisation, the agent, its state and clocks, and the relay round trip), the most recently connected unless org names one. It changes nothing."

/** The tools over these ports: the three enterprise tools, and identities when the home's reads are given. */
export function toolsOf(ports: EnterprisePorts): typeof MCP_TOOLS {
  if (ports.home === undefined) return MCP_TOOLS
  return [
    ...MCP_TOOLS.map((t) => (t.name === 'status' ? { ...t, description: HOME_STATUS } : t)),
    IDENTITIES_TOOL,
  ] as typeof MCP_TOOLS
}

type Result = { content: { type: 'text'; text: string }[]; isError?: boolean }

/** The identities tool's answer, as JSON text: a count by default, the labels when the switch says so. */
export function identitiesAnswer(
  labels: readonly string[],
  listing: 'count' | 'labels' = UNBOUND_LISTING,
): Record<string, unknown> {
  if (labels.length === 0)
    return {
      bound: false,
      identities: listing === 'count' ? 0 : [],
      note: 'no identity on this machine yet.',
    }
  if (listing === 'labels')
    return {
      bound: false,
      identities: labels.map((label) => ({ label })),
      note: 'these are the identities on this machine; your person binds a window that runs the bag service to one, through its bind dialog or, where the host passes typed words to bag, by typing use and a name. Addresses show once a window is bound.',
    }
  const n = labels.length
  return {
    bound: false,
    identities: n,
    note: `${n === 1 ? 'one identity is' : `${n} identities are`} on this machine; your person picks one by name when a window that runs the bag service binds it (through its bind dialog or, where the host passes typed words to bag, by typing use and its name). The names are not shown here.`,
  }
}

/**
 * status's leading lines from the home's reads: the version, the identities' count, and the relays' health. Under
 * 'count' the relays are a count and how many answered, never their URLs, since a person's own relay would tell an
 * unbound model what the names would; under 'labels' each relay's URL and answer.
 */
export async function homeLines(
  reads: HomeReads,
  home: string,
  listing: 'count' | 'labels' = UNBOUND_LISTING,
): Promise<string[]> {
  const ids = reads.identities(home)
  const relays = [...new Set(ids.flatMap((i) => i.relays))]
  const health = await reads.relaysHealth(relays)
  const ok = health.filter((h) => h.ok).length
  const shown =
    health.length === 0
      ? ['relays none listed']
      : listing === 'count'
        ? [`relays ${health.length}, ok ${ok}`]
        : health.map((h) => `relay ${h.relay} ${h.ok ? 'ok' : 'unreachable'}`)
  return [`bag ${VERSION}`, `identities ${ids.length}`, ...shown]
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

/** A result of `lines`, with every piece of `secret` (the code, and its secret part) and every `more` taken out. */
function result(
  lines: string[],
  isError: boolean,
  secret: string | null,
  more: readonly string[] = [],
): Result {
  let text = lines.join('\n')
  const pieces = secret === null ? [] : [secret, secret.slice(secret.lastIndexOf('.') + 1)]
  for (const p of [...pieces, ...more].filter((x) => x.length >= 8)) text = text.split(p).join('[the code]')
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) }
}

/** The error's public line, as the command prints it: "<code>: <detail>". */
function failure(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code
  const message = e instanceof Error ? e.message : String(e)
  const c = typeof code === 'string' && code !== '' ? code : 'error'
  return message.startsWith(`${c}: `) ? message : `${c}: ${message}`
}

/** The keys an argument refusal echoes, at most, and each one's length at most: keys only, never a value. */
const SHOWN_KEYS = 8
const KEY_CHARS = 64

/**
 * The refusal of a call whose arguments hold a key the tool's schema does not define: the keys (printable ones, each
 * cut to 64 characters, at most 8, and how many more) and the tool's own argument names, from its schema; never a value.
 */
export function unknownArguments(tool: string, keys: readonly string[], unknown: readonly string[]): string {
  const printable = unknown.filter((k) => /^[\x20-\x7e]+$/.test(k))
  const shown = printable.slice(0, SHOWN_KEYS).map((k) => JSON.stringify(k.slice(0, KEY_CHARS)))
  const rest = unknown.length - shown.length
  const named =
    shown.length === 0
      ? `(${rest} not printable)`
      : `${shown.join(', ')}${rest > 0 ? ` and ${rest} more` : ''}`
  const takes = keys.length === 0 ? `${tool} takes no argument` : `${tool} takes ${keys.join(', ')}`
  return `unknown argument${unknown.length === 1 ? '' : 's'} ${named}: ${takes}`
}

async function callTool(
  ports: EnterprisePorts,
  home: string,
  name: string,
  args: Record<string, unknown>,
): Promise<Result> {
  const lines: string[] = []
  // A key the tool's schema does not define is refused before anything runs: named, never its value.
  const tool = toolsOf(ports).find((t) => t.name === name)
  const keys = Object.keys(tool?.inputSchema.properties ?? {})
  const unknown = tool === undefined ? [] : Object.keys(args).filter((k) => !keys.includes(k))
  if (unknown.length > 0) return result([`usage: ${unknownArguments(name, keys, unknown)}`], true, null)
  if (name === 'connect') {
    const code = typeof args.code === 'string' ? args.code : ''
    if (code.trim() === '') return result(['usage: no code: paste the code from the console'], true, null)
    try {
      const exit = await connect(collecting(ports, home, lines), { text: code, version: VERSION })
      return result(lines, exit !== 0 && exit !== 4, code.trim())
    } catch (e) {
      return result([...lines, failure(e)], true, code.trim())
    }
  }
  if (name === 'sign_in') {
    const [domain, instance] = [args.domain, args.instance].map((v) => (typeof v === 'string' ? v : ''))
    // The device code and the token are this home's; scrubbed from the result as well as never said.
    const before = signInSecrets(home)
    const secrets = () => [...before, ...signInSecrets(home)]
    try {
      const exit = await signInThroughAgent(collecting(ports, home, lines), {
        domain: domain as string,
        instance: instance as string,
        version: VERSION,
      })
      return result(lines, exit !== 0 && exit !== 4, null, secrets())
    } catch (e) {
      return result([...lines, failure(e)], true, null, secrets())
    }
  }
  if (name === 'status') {
    try {
      // With the home's reads, its facts lead, and no enterprise session is no error: most homes have none.
      if (ports.home !== undefined) lines.push(...(await homeLines(ports.home, home)))
      const org = typeof args.org === 'string' && args.org !== '' ? { org: args.org } : {}
      const note = (line: string) => lines.push(line.replace(/^bag: /, ''))
      const exit = await enterpriseStatus({ ...collecting(ports, home, lines), note, ...org })
      // Exit 1 is a live session whose relay probe failed: an error with or without the home's reads.
      return result(lines, exit === 1, null)
    } catch (e) {
      // enterpriseStatus throws signed-out when there is no session: with the home's reads that is a fact, not an error.
      const signedOut = (e as { code?: unknown } | null)?.code === 'signed-out'
      return result([...lines, failure(e)], !(signedOut && ports.home !== undefined), null)
    }
  }
  if (name === 'identities' && ports.home !== undefined) {
    try {
      const labels = ports.home.identities(home).map((i) => i.label)
      return result([JSON.stringify(identitiesAnswer(labels))], false, null)
    } catch (e) {
      return result([failure(e)], true, null)
    }
  }
  return result([`usage: no tool ${JSON.stringify(name)}`], true, null)
}

/** The MCP server over `ports` and the bag home: the three tools, and identities with the home's reads. */
export function createMcpServer(ports: EnterprisePorts, home: string): Server {
  const server = new Server({ name: 'bag', version: VERSION }, { capabilities: { tools: {} } })
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolsOf(ports) }))
  server.setRequestHandler(CallToolRequestSchema, async (req) =>
    callTool(ports, home, req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>),
  )
  return server
}

/** Serves the tools over `transport` (stdio by default) until it closes. */
export async function serveMcp(
  ports: EnterprisePorts,
  home: string,
  transport: Transport = new StdioServerTransport(),
): Promise<void> {
  const server = createMcpServer(ports, home)
  const closed = new Promise<void>((done) => {
    server.onclose = () => done()
  })
  await server.connect(transport)
  await closed
}
