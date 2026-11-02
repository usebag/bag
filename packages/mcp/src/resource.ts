import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
  ErrorCode,
  McpError,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import type { Desk } from './desk.ts'
import type { Logger } from './log.ts'
import { notice } from './push.ts'
import { codeOf } from './tools.ts'

// The inbox as an MCP resource, behind --push resource: bag://inbox/<name> lists the desk's
// unread messages by id, sender and type, never a body, and marks none read. A client subscribed to it gets one
// notifications/resources/updated per delivered message (Desk.delivered, as push.ts), none before its initialize.

/** The most unread messages one read lists; `unread` counts them all. */
export const RESOURCE_SHOWN = 50

/** What every read carries: the resource lists, never carries a body and marks nothing read. */
export const RESOURCE_NOTE =
  'each message by cursor, id, sender, type and arrival, never its body: read it with inbox or wait (which mark it read); reading this resource marks nothing read'

/** The inbox resource's URI for the key name the server runs as (--as). */
export const inboxUri = (name: string): string => `bag://inbox/${encodeURIComponent(name)}`

/** A URI as the SDK's resources/read compares it (`new URL(uri)`, normalised), or null when it does not parse. */
function hrefOf(text: string): string | null {
  try {
    return new URL(text).href
  } catch {
    return null
  }
}

/** A read's JSON: the unread list in the order the desk took it; each one's cursor, id, from, type, arrival; no body. */
export function unreadView(desk: Pick<Desk, 'unread'>): Record<string, unknown> {
  const unread = desk.unread()
  const messages = unread.slice(0, RESOURCE_SHOWN).map((m) => {
    const { id, from, type } = notice(m).meta
    return { cursor: m.cursor, id, from, type, received_at: m.received_at }
  })
  return { unread: unread.length, messages, more: unread.length > RESOURCE_SHOWN, note: RESOURCE_NOTE }
}

/** Each server's inbox resources by URI (one per identity of an --identities server), and whether each is subscribed. */
const SUBSCRIBED = new WeakMap<McpServer, Map<string, boolean>>()

/** Registers the inbox resource on one client's server, before it connects; the subscription is that client's. */
export function registerInboxResource(
  mcp: McpServer,
  name: string,
  desk: Pick<Desk, 'delivered' | 'unread'>,
  log: Logger,
): void {
  const server = mcp.server
  const uri = new URL(inboxUri(name)).href
  const description = `The messages delivered to ${name} that inbox or wait has not returned: id, from and type, never the body; reading it marks none read.`
  mcp.registerResource(
    'inbox',
    uri,
    { title: `Unread mail for ${name}`, description, mimeType: 'application/json' },
    () => ({ contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(unreadView(desk)) }] }),
  )
  const subscribed = SUBSCRIBED.get(mcp) ?? new Map<string, boolean>()
  if (!SUBSCRIBED.has(mcp)) {
    SUBSCRIBED.set(mcp, subscribed)
    // Over the SDK's own declaration: one resource per identity for the server's life, so its list never changes.
    server.registerCapabilities({ resources: { subscribe: true, listChanged: false } })
    const subscribe = (asked: string, on: boolean) => {
      const href = hrefOf(asked) ?? ''
      if (!subscribed.has(href)) throw new McpError(ErrorCode.InvalidParams, `Resource ${asked} not found`)
      subscribed.set(href, on)
      return {}
    }
    server.setRequestHandler(SubscribeRequestSchema, (r) => subscribe(r.params.uri, true))
    server.setRequestHandler(UnsubscribeRequestSchema, (r) => subscribe(r.params.uri, false))
  }
  subscribed.set(uri, false)
  const warn = (e: unknown): void => log.log('warn', 'push', { kind: 'resource', code: codeOf(e) })
  desk.delivered.add(() => {
    // Only to a subscribed client, and never before its initialize (as push.ts).
    if (subscribed.get(uri) !== true || server.getClientCapabilities() === undefined) return
    server.sendResourceUpdated({ uri }).catch(warn)
  })
}
