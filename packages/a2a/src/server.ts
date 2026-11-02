import { randomUUID } from 'node:crypto'
import type { InboundMessage, SessionHandler } from '@usebag/edge'
import { A2A_TYPE, jsonBytes, MAX_RPC_BYTES, readRequestBody, responseBody } from './binding.ts'
import { failure, type JsonRpcRequest, type JsonRpcResponse, success } from './jsonrpc.ts'
import {
  type Artifact,
  copyMessage,
  ERRORS,
  INTERRUPTED,
  isRecord,
  METHODS,
  type Message,
  messageProblem,
  type Part,
  partProblem,
  type Task,
  type TaskState,
  type TaskStatus,
  TERMINAL,
} from './protocol.ts'

// The agent's side of the binding: an A2A 1.0 server whose requests arrive as opened envelopes. It keeps the tasks
// in memory, each owned by the principal that opened it (an A2A client behind another principal's bridge cannot read
// or cancel it: TaskNotFoundError), runs the agent's handler once per message, and answers SendMessage, GetTask and
// CancelTask. Streaming, ListTasks, push notifications and the extended card are answered with the error the
// specification names for an agent that does not support them.
//
// Bounds: at most `maxTasks` tasks and `maxTasksPerOwner` per principal, the oldest finished task forgotten first and
// a live one (submitted, working or interrupted) never; at most `maxTurns` handler turns at once; a blocking
// SendMessage waits at most `blockMs` (20 s, under the bridge's 30 s) and then answers the working task, which the
// client reads again with GetTask. Over a bound the request is refused with serverBusy (-32000).

/** The states a handler may end a turn in. */
export type OutcomeState =
  | 'TASK_STATE_COMPLETED'
  | 'TASK_STATE_FAILED'
  | 'TASK_STATE_REJECTED'
  | 'TASK_STATE_INPUT_REQUIRED'
  | 'TASK_STATE_AUTH_REQUIRED'

const OUTCOME_STATES: readonly string[] = [
  'TASK_STATE_COMPLETED',
  'TASK_STATE_FAILED',
  'TASK_STATE_REJECTED',
  'TASK_STATE_INPUT_REQUIRED',
  'TASK_STATE_AUTH_REQUIRED',
]

/** One turn of a task, as the handler sees it. */
export interface A2aTurn {
  /** The principal the message came from (the edge's InboundMessage.principal); the task's owner. */
  readonly sender: string
  /** The client's message, with the task's id and context id filled in. */
  readonly message: Message
  /** The task before this turn's answer: its history ends with `message`. */
  readonly task: Task
}

/**
 * What a turn ends in: a state (default TASK_STATE_COMPLETED), the agent's reply parts and any artifacts. It is read
 * as JSON: a value JSON cannot carry (a function, a BigInt) makes the outcome invalid and the task failed.
 */
export interface A2aOutcome {
  readonly state?: OutcomeState
  readonly parts?: readonly Part[]
  readonly artifacts?: readonly (Omit<Artifact, 'artifactId'> & { readonly artifactId?: string })[]
}

export type A2aHandler = (turn: A2aTurn) => A2aOutcome | Promise<A2aOutcome>

export interface A2aServerOptions {
  readonly handler: A2aHandler
  /** The clock of the status timestamps (default the system's). */
  readonly now?: () => Date
  /** The ids of tasks, contexts, messages and artifacts (default random UUIDs). */
  readonly newId?: () => string
  /** The most tasks kept (default 1,000). */
  readonly maxTasks?: number
  /** The most tasks one principal may hold (default 100). */
  readonly maxTasksPerOwner?: number
  /** The most handler turns running at once (default 16). */
  readonly maxTurns?: number
  /** How long a blocking SendMessage waits for its turn, in milliseconds (default 20,000). */
  readonly blockMs?: number
}

interface TaskRecord {
  readonly owner: string
  readonly id: string
  readonly contextId: string
  status: TaskStatus
  readonly history: Message[]
  readonly artifacts: Artifact[]
}

class Refusal extends Error {
  readonly code: number
  constructor(code: number, message: string) {
    super(message)
    this.code = code
  }
}

const isState = (s: TaskState, list: readonly TaskState[]): boolean => list.includes(s)

/** A request id as long as any a client is expected to send: room kept for it when a reply's size is checked. */
const ROOM_FOR_ID = 'i'.repeat(256)

/** A count member, absent allowed: a non-negative integer, or its decimal string (ProtoJSON's int32 may be quoted). */
function count(v: unknown, name: string): number | undefined {
  if (v === undefined) return undefined
  const n = typeof v === 'string' && /^\d{1,9}$/.test(v) ? Number(v) : v
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) {
    throw new Refusal(ERRORS.invalidParams, `${name} is a non-negative integer`)
  }
  return n
}

/** An object without one member. */
const without = (o: Record<string, unknown>, key: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([k]) => k !== key))

/** The A2A server: one per agent, shared by every principal that calls it. */
export class A2aServer {
  readonly #o: A2aServerOptions
  readonly #tasks = new Map<string, TaskRecord>()
  readonly #running = new Set<Promise<void>>()

  constructor(options: A2aServerOptions) {
    this.#o = options
  }

  /** Answers one JSON-RPC request of the principal `sender`. Never throws: every failure is an error response. */
  async handle(sender: string, request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const params = isRecord(request.params) ? request.params : {}
    try {
      return success(request.id, await this.#call(sender, request.method, params))
    } catch (e) {
      if (e instanceof Refusal) return failure(request.id, e.code, e.message)
      return failure(request.id, ERRORS.internalError, 'internal error')
    }
  }

  /** Resolves once every turn started has ended. */
  async settled(): Promise<void> {
    while (this.#running.size > 0) await Promise.all([...this.#running])
  }

  async #call(sender: string, method: string, params: Record<string, unknown>): Promise<unknown> {
    switch (method) {
      case METHODS.sendMessage:
        return { task: await this.#send(sender, params) }
      case METHODS.getTask: {
        const historyLength = count(params.historyLength, 'historyLength')
        return this.#view(this.#own(sender, params.id), historyLength)
      }
      case METHODS.cancelTask:
        return this.#cancel(sender, params.id)
      case METHODS.sendStreamingMessage:
      case METHODS.subscribeToTask:
        throw new Refusal(ERRORS.unsupportedOperation, 'streaming is not supported by this agent')
      case METHODS.listTasks:
        throw new Refusal(ERRORS.unsupportedOperation, 'ListTasks is not supported by this agent')
      case METHODS.createPushConfig:
      case METHODS.getPushConfig:
      case METHODS.listPushConfigs:
      case METHODS.deletePushConfig:
        throw new Refusal(ERRORS.pushNotificationNotSupported, 'push notifications are not supported')
      case METHODS.getExtendedAgentCard:
        throw new Refusal(ERRORS.extendedAgentCardNotConfigured, 'no extended agent card is configured')
      default:
        throw new Refusal(ERRORS.methodNotFound, `no method ${method}`)
    }
  }

  async #send(sender: string, params: Record<string, unknown>): Promise<Task> {
    const why = messageProblem(params.message, 'ROLE_USER')
    if (why !== null) throw new Refusal(ERRORS.invalidParams, why)
    const config = params.configuration ?? {}
    if (!isRecord(config)) throw new Refusal(ERRORS.invalidParams, 'configuration is an object')
    if (config.returnImmediately !== undefined && typeof config.returnImmediately !== 'boolean') {
      throw new Refusal(ERRORS.invalidParams, 'configuration.returnImmediately is a boolean')
    }
    // 1.0's member is taskPushNotificationConfig; 0.3 named it pushNotificationConfig. Neither is supported.
    if (config.taskPushNotificationConfig !== undefined || config.pushNotificationConfig !== undefined) {
      throw new Refusal(ERRORS.pushNotificationNotSupported, 'push notifications are not supported')
    }
    const historyLength = count(config.historyLength, 'configuration.historyLength')
    if (this.#running.size >= (this.#o.maxTurns ?? 16)) {
      throw new Refusal(ERRORS.serverBusy, 'the agent is running as many turns as it may; try again later')
    }
    const given = copyMessage(params.message as Record<string, unknown>)
    const record = given.taskId === undefined ? this.#open(sender, given) : this.#resume(sender, given)
    const message: Message = { ...given, taskId: record.id, contextId: record.contextId }
    record.history.push(message)
    record.status = { state: 'TASK_STATE_WORKING', timestamp: this.#now() }
    // The turn never rejects: the handler's fault and a fault after it are both caught inside, so no .catch is chained.
    const turn = this.#turn(sender, record, message)
    this.#running.add(turn)
    turn.finally(() => this.#running.delete(turn))
    if (config.returnImmediately !== true) await this.#wait(turn)
    return this.#view(record, historyLength)
  }

  /** The turn, or the blocking window's end, whichever comes first. */
  async #wait(turn: Promise<void>): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const window = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, this.#o.blockMs ?? 20_000)
    })
    await Promise.race([turn, window])
    clearTimeout(timer)
  }

  #open(sender: string, message: Message): TaskRecord {
    const all = [...this.#tasks.values()]
    const mine = all.filter((t) => t.owner === sender)
    if (mine.length >= (this.#o.maxTasksPerOwner ?? 100) && !this.#forget(mine)) {
      throw new Refusal(ERRORS.serverBusy, 'this sender holds as many live tasks as it may; finish one first')
    }
    if (this.#tasks.size >= (this.#o.maxTasks ?? 1000) && !this.#forget(all)) {
      throw new Refusal(ERRORS.serverBusy, 'the agent holds as many live tasks as it may; try again later')
    }
    const record: TaskRecord = {
      owner: sender,
      id: this.#id(),
      contextId: message.contextId ?? this.#id(),
      status: { state: 'TASK_STATE_SUBMITTED', timestamp: this.#now() },
      history: [],
      artifacts: [],
    }
    this.#tasks.set(record.id, record)
    return record
  }

  /** Forgets the oldest finished task of the list; false when every one is live. */
  #forget(list: readonly TaskRecord[]): boolean {
    const old = list.find((t) => isState(t.status.state, TERMINAL))
    if (old !== undefined) this.#tasks.delete(old.id)
    return old !== undefined
  }

  #resume(sender: string, message: Message): TaskRecord {
    const record = this.#own(sender, message.taskId)
    if (message.contextId !== undefined && message.contextId !== record.contextId) {
      throw new Refusal(ERRORS.invalidParams, `task ${record.id} is in context ${record.contextId}`)
    }
    if (!isState(record.status.state, INTERRUPTED)) {
      throw new Refusal(
        ERRORS.unsupportedOperation,
        `task ${record.id} is ${record.status.state} and takes no further message`,
      )
    }
    return record
  }

  async #turn(sender: string, record: TaskRecord, message: Message): Promise<void> {
    let outcome: unknown
    try {
      outcome = await this.#o.handler({ sender, message, task: this.#view(record, undefined) })
    } catch {
      outcome = { state: 'TASK_STATE_FAILED', parts: [{ text: 'the agent failed on this message' }] }
    }
    try {
      this.#finish(record, outcome)
    } catch {
      // A fault after the handler answered (an id or a clock that throws): the task fails, with nothing more said.
      // #finish returns before anything can throw on a canceled task, so this never overwrites a cancel.
      record.status = { state: 'TASK_STATE_FAILED' }
    }
  }

  /** Applies a turn's outcome, read as JSON and checked; one whose answer no response could carry fails the task. */
  #finish(record: TaskRecord, outcome: unknown): void {
    // A task canceled while its turn ran stays canceled: the late answer is dropped.
    if (record.status.state === 'TASK_STATE_CANCELED') return
    const checked = checkOutcome(asJson(outcome))
    const state = (checked?.state ?? 'TASK_STATE_FAILED') as TaskState
    const parts = checked === null ? [{ text: 'the agent answered no valid outcome' }] : checked.parts
    const reply = parts === undefined || parts.length === 0 ? undefined : this.#agentMessage(record, parts)
    const timestamp = this.#now()
    const status: TaskStatus = { state, ...(reply === undefined ? {} : { message: reply }), timestamp }
    const lean = { task: { id: record.id, contextId: record.contextId, status } }
    if (jsonBytes(responseBody(success(ROOM_FOR_ID, lean))) > MAX_RPC_BYTES) {
      const why = [{ text: `the answer is over ${MAX_RPC_BYTES} bytes, dropped` }]
      const dropped = this.#agentMessage(record, why)
      record.history.push(dropped)
      record.status = { state: 'TASK_STATE_FAILED', message: dropped, timestamp }
      return
    }
    if (reply !== undefined) record.history.push(reply)
    for (const a of checked?.artifacts ?? []) {
      record.artifacts.push({ ...a, artifactId: a.artifactId ?? this.#id() })
    }
    record.status = status
  }

  #agentMessage(record: TaskRecord, parts: readonly Part[]): Message {
    const messageId = this.#id()
    return { messageId, contextId: record.contextId, taskId: record.id, role: 'ROLE_AGENT', parts }
  }

  #cancel(sender: string, id: unknown): Task {
    const record = this.#own(sender, id)
    if (isState(record.status.state, TERMINAL)) {
      throw new Refusal(ERRORS.taskNotCancelable, `task ${record.id} is ${record.status.state}`)
    }
    record.status = { state: 'TASK_STATE_CANCELED', timestamp: this.#now() }
    return this.#view(record, undefined)
  }

  /** The sender's task by id; TaskNotFoundError for an unknown id and for another principal's task alike. */
  #own(sender: string, id: unknown): TaskRecord {
    if (typeof id !== 'string' || id === '') {
      throw new Refusal(ERRORS.invalidParams, 'id is a non-empty string')
    }
    const record = this.#tasks.get(id)
    if (record === undefined || record.owner !== sender) {
      throw new Refusal(ERRORS.taskNotFound, `no task ${id}`)
    }
    return record
  }

  /** The task as A2A shows it: history cut to its last `historyLength` messages (0: none), a deep copy. */
  #view(record: TaskRecord, historyLength: number | undefined): Task {
    let shown = record.history
    if (historyLength === 0) shown = []
    else if (historyLength !== undefined) shown = record.history.slice(-historyLength)
    return structuredClone({
      id: record.id,
      contextId: record.contextId,
      status: record.status,
      ...(record.artifacts.length === 0 ? {} : { artifacts: record.artifacts }),
      ...(shown.length === 0 ? {} : { history: shown }),
    })
  }

  #id(): string {
    return (this.#o.newId ?? randomUUID)()
  }

  #now(): string {
    return (this.#o.now?.() ?? new Date()).toISOString()
  }
}

/** The value as JSON reads it back, or undefined when JSON cannot carry it (a BigInt; a function at the top). */
function asJson(v: unknown): unknown {
  try {
    return JSON.parse(JSON.stringify(v))
  } catch {
    return undefined
  }
}

/** A handler's outcome checked, or null when it is not one: a known state, valid parts and valid artifacts. */
function checkOutcome(v: unknown): A2aOutcome | null {
  if (!isRecord(v)) return null
  if (v.state !== undefined && !OUTCOME_STATES.includes(v.state as string)) return null
  if (v.parts !== undefined && (!Array.isArray(v.parts) || v.parts.some((p) => partProblem(p) !== null))) {
    return null
  }
  if (v.artifacts !== undefined) {
    if (!Array.isArray(v.artifacts)) return null
    for (const a of v.artifacts) {
      if (!isRecord(a) || !Array.isArray(a.parts) || a.parts.length === 0) return null
      if (a.parts.some((p) => partProblem(p) !== null)) return null
      if (a.artifactId !== undefined && (typeof a.artifactId !== 'string' || a.artifactId === '')) return null
    }
  }
  return { ...(v as A2aOutcome), state: (v.state ?? 'TASK_STATE_COMPLETED') as OutcomeState }
}

/**
 * The response cut to fit a sealed reply: whole when it fits; else a task without its history (A2A 1.0 section 3.2.4
 * leaves the default history to the implementation), then without its artifacts too; else Internal error. A task
 * whose status alone cannot fit was failed at the end of its turn, so every task stays readable.
 */
export function fitResponse(response: JsonRpcResponse, max = MAX_RPC_BYTES): JsonRpcResponse {
  const size = (r: JsonRpcResponse): number => jsonBytes(responseBody(r))
  if (size(response) <= max) return response
  if ('result' in response && isRecord(response.result)) {
    const wrapped = isRecord(response.result.task)
    const task = (wrapped ? response.result.task : response.result) as Record<string, unknown>
    const lean = without(task, 'history')
    for (const t of [lean, without(lean, 'artifacts')]) {
      const next: JsonRpcResponse = { jsonrpc: '2.0', id: response.id, result: wrapped ? { task: t } : t }
      if (size(next) <= max) return next
    }
  }
  return failure(response.id, ERRORS.internalError, `the response is over ${max} bytes`)
}

/** The part of an edge the agent's side uses: a reply in the message's thread, to its principal. */
export interface AgentEdge {
  reply(message: InboundMessage, input: { readonly type: string; readonly body: unknown }): Promise<unknown>
}

export interface A2aSessionOptions {
  /** The session id of the handler (default "a2a"). */
  readonly session?: string
  /** Called with a message of another type, which this handler does not answer. */
  readonly other?: (message: InboundMessage) => void | Promise<void>
  /** Called with the error of an answer that could not be made or sent. */
  readonly onError?: (error: unknown) => void
}

/** The agent's session handler, and a wait for the answers it is still making. */
export interface A2aSession extends SessionHandler {
  settled(): Promise<void>
}

/**
 * A session handler that answers each A2A envelope with the server's response, sealed back in the same thread:
 * `edge.setDefault(a2aSessionHandler(edge, server))` makes an agent answer A2A clients that call it through a bridge.
 * Delivery returns at once and the answer is made in the background, so a long turn never holds the edge's frame loop;
 * the server's blocking window (20 s) keeps the answer inside the bridge's wait (30 s).
 */
export function a2aSessionHandler(
  edge: AgentEdge,
  server: A2aServer,
  options: A2aSessionOptions = {},
): A2aSession {
  const running = new Set<Promise<void>>()
  const answer = async (m: InboundMessage): Promise<void> => {
    const read = readRequestBody(m.body)
    const response = fitResponse(read.ok ? await server.handle(m.principal, read.request) : read.response)
    await edge.reply(m, { type: A2A_TYPE, body: responseBody(response) })
  }
  // The answer runs in the background: a fault anywhere in it (the size, the seal, the send) goes to onError.
  const track = (m: InboundMessage): void => {
    const p = answer(m).catch((e: unknown) => options.onError?.(e))
    running.add(p)
    p.finally(() => running.delete(p))
  }
  return {
    session: options.session ?? 'a2a',
    deliver: (m) => (m.type === A2A_TYPE ? track(m) : options.other?.(m)),
    settled: async () => {
      while (running.size > 0) await Promise.all([...running])
    },
  }
}
