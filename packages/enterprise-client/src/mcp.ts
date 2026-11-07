import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { signInSecrets, signInThroughAgent } from './agent-sign-in.ts'
import { connect } from './connect.ts'
import { type EnterpriseDeps, enterpriseStatus } from './flow.ts'
import { type EnterprisePorts, enterpriseDeps, VERSION } from './ports.ts'

// The enterprise client as a stdio MCP server, so a person in an MCP host pastes the console's connect code into the
// chat and the agent connects itself (nothing else typed). Three tools, nothing else: `connect` (the code, the
// command's own parse, pin, guard and redeem path: connect.ts), `sign_in` (no code: the domain and the console origin,
// the device flow a person approves, agent-sign-in.ts) and `status` (the command's status). A result holds only the
// public lines the commands print; the code given is never echoed (every result is scrubbed of it as well). The SDK is
// the one bag's MCP server uses, at its pin; its low-level Server takes plain JSON Schema, so no schema library is
// added.
//
// The honest limit: the code reaches this server as a tool argument, so it sits in the MCP host's transcript. Its
// defences are its life (15 minutes by default) and its single use: once redeemed, the string opens nothing.

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
      "Shows this machine's bag enterprise session: the organisation, the agent, its state and its clocks.",
    inputSchema: { type: 'object' as const, properties: {}, additionalProperties: false },
  },
]

type Result = { content: { type: 'text'; text: string }[]; isError?: boolean }

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

async function callTool(
  ports: EnterprisePorts,
  home: string,
  name: string,
  args: Record<string, unknown>,
): Promise<Result> {
  const lines: string[] = []
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
      const exit = await enterpriseStatus(collecting(ports, home, lines))
      return result(lines, exit === 1, null)
    } catch (e) {
      return result([...lines, failure(e)], true, null)
    }
  }
  return result([`usage: no tool ${JSON.stringify(name)}`], true, null)
}

/** The MCP server over `ports` and the bag home: the three tools. */
export function createMcpServer(ports: EnterprisePorts, home: string): Server {
  const server = new Server({ name: 'bag', version: VERSION }, { capabilities: { tools: {} } })
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MCP_TOOLS }))
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
