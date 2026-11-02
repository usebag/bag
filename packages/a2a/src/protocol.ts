// The A2A protocol objects this binding speaks: A2A 1.0.0 (https://a2a-protocol.org/v1.0.0/specification/; the
// normative proto is specification/a2a.proto at tag v1.0.0, commit 173695755607e884aa9acf8ce4feed90e32727a1 of
// github.com/a2aproject/A2A). On the JSON-RPC binding every object is the ProtoJSON form of its proto message:
// camelCase member names, enums as their names (TASK_STATE_COMPLETED, ROLE_USER), timestamps as RFC 3339 strings,
// and no `kind` discriminator (removed in 1.0, Appendix A.2.1).

/** The protocol version this binding implements, as the A2A-Version header and AgentInterface.protocolVersion say. */
export const A2A_VERSION = '1.0'
/** The binding's name in an AgentInterface (a2a.proto: JSONRPC, GRPC and HTTP+JSON are the core ones). */
export const JSONRPC_BINDING = 'JSONRPC'
/** The specification this package cites. */
export const A2A_SPEC_URL = 'https://a2a-protocol.org/v1.0.0/specification/'

/** The JSON-RPC method names of A2A 1.0 (section 9.4): PascalCase, as gRPC names them. */
export const METHODS = {
  sendMessage: 'SendMessage',
  sendStreamingMessage: 'SendStreamingMessage',
  getTask: 'GetTask',
  listTasks: 'ListTasks',
  cancelTask: 'CancelTask',
  subscribeToTask: 'SubscribeToTask',
  createPushConfig: 'CreateTaskPushNotificationConfig',
  getPushConfig: 'GetTaskPushNotificationConfig',
  listPushConfigs: 'ListTaskPushNotificationConfigs',
  deletePushConfig: 'DeleteTaskPushNotificationConfig',
  getExtendedAgentCard: 'GetExtendedAgentCard',
} as const

/** The JSON-RPC error codes: JSON-RPC 2.0's own, then A2A's (sections 5.4 and 9.5). */
export const ERRORS = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
  taskNotFound: -32001,
  taskNotCancelable: -32002,
  pushNotificationNotSupported: -32003,
  unsupportedOperation: -32004,
  contentTypeNotSupported: -32005,
  invalidAgentResponse: -32006,
  extendedAgentCardNotConfigured: -32007,
  extensionSupportRequired: -32008,
  versionNotSupported: -32009,
  /**
   * JSON-RPC 2.0's range for implementation-defined server errors (-32000 to -32099): A2A 1.0 names no error for an
   * agent at its limit of tasks or of turns running, so this one says so, and the client may try again later.
   */
  serverBusy: -32000,
} as const

export type Role = 'ROLE_USER' | 'ROLE_AGENT'

/** The enum numbers of the roles (a2a.proto); a ProtoJSON reader accepts an enum by name or by number. */
export const ROLE_NUMBER: Readonly<Record<Role, number>> = { ROLE_USER: 1, ROLE_AGENT: 2 }
const ROLE_NAME: Readonly<Record<number, Role>> = { 1: 'ROLE_USER', 2: 'ROLE_AGENT' }

/** TaskState (a2a.proto); TASK_STATE_UNSPECIFIED is never written. */
export type TaskState =
  | 'TASK_STATE_SUBMITTED'
  | 'TASK_STATE_WORKING'
  | 'TASK_STATE_COMPLETED'
  | 'TASK_STATE_FAILED'
  | 'TASK_STATE_CANCELED'
  | 'TASK_STATE_INPUT_REQUIRED'
  | 'TASK_STATE_REJECTED'
  | 'TASK_STATE_AUTH_REQUIRED'

export const TASK_STATES: readonly TaskState[] = [
  'TASK_STATE_SUBMITTED',
  'TASK_STATE_WORKING',
  'TASK_STATE_COMPLETED',
  'TASK_STATE_FAILED',
  'TASK_STATE_CANCELED',
  'TASK_STATE_INPUT_REQUIRED',
  'TASK_STATE_REJECTED',
  'TASK_STATE_AUTH_REQUIRED',
]

/** The terminal states: a task in one takes no further message and cannot be canceled. */
export const TERMINAL: readonly TaskState[] = [
  'TASK_STATE_COMPLETED',
  'TASK_STATE_FAILED',
  'TASK_STATE_CANCELED',
  'TASK_STATE_REJECTED',
]
/** The interrupted states: the task waits for the client's next message on it. */
export const INTERRUPTED: readonly TaskState[] = ['TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_AUTH_REQUIRED']

/** A Part: exactly one of text, raw (base64), url or data, with optional metadata, filename and mediaType. */
export interface Part {
  readonly text?: string
  readonly raw?: string
  readonly url?: string
  readonly data?: unknown
  readonly metadata?: Readonly<Record<string, unknown>>
  readonly filename?: string
  readonly mediaType?: string
}

export interface Message {
  readonly messageId: string
  readonly contextId?: string
  readonly taskId?: string
  readonly role: Role
  readonly parts: readonly Part[]
  readonly metadata?: Readonly<Record<string, unknown>>
  readonly extensions?: readonly string[]
  readonly referenceTaskIds?: readonly string[]
}

export interface TaskStatus {
  readonly state: TaskState
  readonly message?: Message
  readonly timestamp?: string
}

export interface Artifact {
  readonly artifactId: string
  readonly name?: string
  readonly description?: string
  readonly parts: readonly Part[]
  readonly metadata?: Readonly<Record<string, unknown>>
  readonly extensions?: readonly string[]
}

export interface Task {
  readonly id: string
  readonly contextId?: string
  readonly status: TaskStatus
  readonly artifacts?: readonly Artifact[]
  readonly history?: readonly Message[]
  readonly metadata?: Readonly<Record<string, unknown>>
}

/** AgentInterface: where and how the agent is reached. The first of a card's interfaces is the preferred one. */
export interface AgentInterface {
  readonly url: string
  readonly protocolBinding: string
  readonly protocolVersion: string
  readonly tenant?: string
}

export interface AgentExtension {
  readonly uri: string
  readonly description?: string
  readonly required?: boolean
  readonly params?: Readonly<Record<string, unknown>>
}

export interface AgentCapabilities {
  readonly streaming?: boolean
  readonly pushNotifications?: boolean
  readonly extensions?: readonly AgentExtension[]
  readonly extendedAgentCard?: boolean
}

export interface AgentSkill {
  readonly id: string
  readonly name: string
  readonly description: string
  readonly tags: readonly string[]
  readonly examples?: readonly string[]
  readonly inputModes?: readonly string[]
  readonly outputModes?: readonly string[]
}

export interface AgentProvider {
  readonly url: string
  readonly organization: string
}

/** The AgentCard (section 4.4.1), as a bridge serves it at /a2a/<address>/.well-known/agent-card.json. */
export interface AgentCard {
  readonly name: string
  readonly description: string
  readonly supportedInterfaces: readonly AgentInterface[]
  readonly provider?: AgentProvider
  readonly version: string
  readonly documentationUrl?: string
  readonly capabilities: AgentCapabilities
  readonly defaultInputModes: readonly string[]
  readonly defaultOutputModes: readonly string[]
  readonly skills: readonly AgentSkill[]
  readonly iconUrl?: string
}

/** The well-known path of the agent card (section 8.2; the URI registered in section 14.3). */
export const AGENT_CARD_PATH = '/.well-known/agent-card.json'

export const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

const isString = (v: unknown): v is string => typeof v === 'string'
const isNonEmpty = (v: unknown): v is string => typeof v === 'string' && v !== ''
const isStringList = (v: unknown): v is string[] => Array.isArray(v) && v.every(isString)

/** Why a value is not a Part, or null when it is one. */
export function partProblem(v: unknown): string | null {
  if (!isRecord(v)) return 'a part is an object'
  const content = ['text', 'raw', 'url', 'data'].filter((k) => v[k] !== undefined)
  if (content.length !== 1) return 'a part holds exactly one of text, raw, url and data'
  for (const k of ['text', 'raw', 'url', 'filename', 'mediaType'])
    if (v[k] !== undefined && !isString(v[k])) return `part.${k} is a string`
  if (v.metadata !== undefined && !isRecord(v.metadata)) return 'part.metadata is an object'
  return null
}

/** Why a value is not a Message the given role may send (by name or enum number), or null when it is one. */
export function messageProblem(v: unknown, role: Role): string | null {
  if (!isRecord(v)) return 'message is an object'
  if (!isNonEmpty(v.messageId)) return 'message.messageId is a non-empty string'
  if (v.role !== role && v.role !== ROLE_NUMBER[role]) return `message.role is ${role}`
  if (!Array.isArray(v.parts) || v.parts.length === 0) return 'message.parts is a non-empty list'
  for (const p of v.parts) {
    const why = partProblem(p)
    if (why !== null) return why
  }
  for (const k of ['contextId', 'taskId'])
    if (v[k] !== undefined && !isNonEmpty(v[k])) return `message.${k} is a non-empty string`
  for (const k of ['extensions', 'referenceTaskIds'])
    if (v[k] !== undefined && !isStringList(v[k])) return `message.${k} is a list of strings`
  if (v.metadata !== undefined && !isRecord(v.metadata)) return 'message.metadata is an object'
  return null
}

const MESSAGE_KEYS = [
  'messageId',
  'contextId',
  'taskId',
  'role',
  'parts',
  'metadata',
  'extensions',
  'referenceTaskIds',
]

/**
 * A checked message, copied member by member: only the members of a2a.proto's Message are kept, and a role given by
 * its enum number is written by name.
 */
export function copyMessage(v: Record<string, unknown>): Message {
  const out: Record<string, unknown> = {}
  for (const k of MESSAGE_KEYS) if (v[k] !== undefined) out[k] = structuredClone(v[k])
  if (typeof out.role === 'number') out.role = ROLE_NAME[out.role]
  return out as unknown as Message
}

/** The text of a message's text parts, joined by a line feed. */
export function textOf(message: Message): string {
  return message.parts
    .filter((p) => p.text !== undefined)
    .map((p) => p.text)
    .join('\n')
}
