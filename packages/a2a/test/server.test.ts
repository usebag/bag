import { describe, expect, it } from 'vitest'
import { A2A_TYPE, jsonBytes, MAX_RPC_BYTES, requestBody, responseBody } from '../src/binding.ts'
import { failure, type JsonRpcRequest, type JsonRpcResponse, success } from '../src/jsonrpc.ts'
import { type Task, textOf } from '../src/protocol.ts'
import {
  type A2aHandler,
  A2aServer,
  type A2aTurn,
  type AgentEdge,
  a2aSessionHandler,
  fitResponse,
} from '../src/server.ts'
import { CLIENT, deferred, inbound, OTHER, say, server, T0 } from './support.ts'

let rpcId = 0
const call = (method: string, params?: Record<string, unknown>): JsonRpcRequest =>
  params === undefined
    ? { jsonrpc: '2.0', id: ++rpcId, method }
    : { jsonrpc: '2.0', id: ++rpcId, method, params }

const echo: A2aHandler = (turn) => ({ parts: [{ text: `echo: ${turn.message.parts[0]?.text}` }] })

/** The task of a SendMessage answer, or the result of another. */
const taskOf = (r: JsonRpcResponse): Task => {
  if (!('result' in r)) throw new Error(`an error: ${JSON.stringify(r.error)}`)
  const result = r.result as { task?: Task }
  return result.task ?? (r.result as Task)
}
const codeOf = (r: JsonRpcResponse): number | null => ('error' in r ? r.error.code : null)

/** A handler that waits for `gate` before it echoes. */
const gated = (gate: { readonly promise: Promise<void> }): A2aHandler => {
  return async (turn) => {
    await gate.promise
    return echo(turn)
  }
}

describe('A2aServer: SendMessage, GetTask and CancelTask over tasks each principal owns', () => {
  it('SendMessage blocks until the turn ends: a completed task with the user message and the reply in history', async () => {
    const turns: A2aTurn[] = []
    const s = server({
      handler: (turn) => {
        turns.push(turn)
        return echo(turn)
      },
    })
    const r = await s.handle(CLIENT, call('SendMessage', { message: say('hi') }))
    expect(r).toMatchObject({ jsonrpc: '2.0', id: rpcId })
    const task = taskOf(r)
    const agentMessage = {
      messageId: 'id-3',
      contextId: 'id-2',
      taskId: 'id-1',
      role: 'ROLE_AGENT',
      parts: [{ text: 'echo: hi' }],
    }
    expect(task).toEqual({
      id: 'id-1',
      contextId: 'id-2',
      status: { state: 'TASK_STATE_COMPLETED', message: agentMessage, timestamp: T0 },
      history: [{ ...say('hi'), taskId: 'id-1', contextId: 'id-2' }, agentMessage],
    })
    expect(turns).toHaveLength(1)
    expect(turns[0]?.sender).toBe(CLIENT)
    expect(turns[0]?.task.status.state).toBe('TASK_STATE_WORKING')
    expect(turns[0]?.task.history?.at(-1)).toEqual(turns[0]?.message)
    // GetTask reads the same task; historyLength cuts the history to its last messages, 0 to none; a quoted count is
    // read as ProtoJSON reads an int32.
    expect(taskOf(await s.handle(CLIENT, call('GetTask', { id: 'id-1' })))).toEqual(task)
    const cut = async (historyLength: unknown) =>
      taskOf(await s.handle(CLIENT, call('GetTask', { id: 'id-1', historyLength }))).history
    expect(await cut(1)).toEqual([agentMessage])
    expect(await cut('1')).toEqual([agentMessage])
    expect(await cut(0)).toBeUndefined()
  })

  it("keeps the client's contextId, adds artifacts with ids, and a turn without parts leaves no agent message", async () => {
    const artifacts = [{ parts: [{ data: { n: 1 } }] }, { artifactId: 'given', parts: [{ text: 'x' }] }]
    const s = server({ handler: () => ({ artifacts }) })
    const r = await s.handle(CLIENT, call('SendMessage', { message: say('a', { contextId: 'ctx' }) }))
    const task = taskOf(r)
    expect(task.contextId).toBe('ctx')
    expect(task.status).toEqual({ state: 'TASK_STATE_COMPLETED', timestamp: T0 })
    expect(task.artifacts).toEqual([
      { artifactId: 'id-2', parts: [{ data: { n: 1 } }] },
      { artifactId: 'given', parts: [{ text: 'x' }] },
    ])
    expect(task.history).toHaveLength(1)
    const empty = server({ handler: () => ({ parts: [] }) })
    const quiet = taskOf(await empty.handle(CLIENT, call('SendMessage', { message: say('b') })))
    expect(quiet.status).toEqual({ state: 'TASK_STATE_COMPLETED', timestamp: T0 })
  })

  it('takes a role given by its enum number, and runs on the system clock and random ids by default', async () => {
    const s = new A2aServer({ handler: echo })
    const task = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('n', { role: 1 }) })))
    expect(task.id).toMatch(/^[0-9a-f-]{36}$/)
    expect(Date.parse(task.status.timestamp as string)).toBeGreaterThan(0)
    expect(task.history?.[0]?.role).toBe('ROLE_USER')
  })

  it('returnImmediately answers the working task at once; GetTask reads it completed once the turn ends', async () => {
    const gate = deferred()
    const s = server({ handler: gated(gate) })
    const configuration = { returnImmediately: true, historyLength: 1 }
    const first = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('slow'), configuration })))
    expect(first.status.state).toBe('TASK_STATE_WORKING')
    expect(first.history).toHaveLength(1)
    gate.resolve()
    await s.settled()
    const done = taskOf(await s.handle(CLIENT, call('GetTask', { id: first.id })))
    expect(done.status.state).toBe('TASK_STATE_COMPLETED')
    expect(done.status.message?.parts).toEqual([{ text: 'echo: slow' }])
  })

  it('a blocking SendMessage waits at most blockMs, then answers the working task for the client to poll', async () => {
    const gate = deferred()
    const s = server({ handler: gated(gate), blockMs: 20 })
    const started = Date.now()
    const working = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('long') })))
    expect(working.status.state).toBe('TASK_STATE_WORKING')
    expect(Date.now() - started).toBeLessThan(5_000)
    gate.resolve()
    await s.settled()
    expect(taskOf(await s.handle(CLIENT, call('GetTask', { id: working.id }))).status.state).toBe(
      'TASK_STATE_COMPLETED',
    )
  })

  it('an interrupted task takes the next message on its id; a finished one, another context or id does not', async () => {
    const s = server({
      handler: (turn) =>
        turn.task.history?.length === 1
          ? { state: 'TASK_STATE_INPUT_REQUIRED', parts: [{ text: 'which one?' }] }
          : { parts: [{ text: `took ${turn.message.parts[0]?.text}` }] },
    })
    const asked = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('book') })))
    expect(asked.status.state).toBe('TASK_STATE_INPUT_REQUIRED')
    const follow = (text: string, extra: Record<string, unknown>) =>
      s.handle(CLIENT, call('SendMessage', { message: say(text, extra) }))
    expect(codeOf(await follow('x', { taskId: asked.id, contextId: 'elsewhere' }))).toBe(-32602)
    const done = taskOf(await follow('the red one', { taskId: asked.id, contextId: asked.contextId }))
    expect(done.id).toBe(asked.id)
    expect(done.status.state).toBe('TASK_STATE_COMPLETED')
    expect(done.history?.map((m) => m.role)).toEqual(['ROLE_USER', 'ROLE_AGENT', 'ROLE_USER', 'ROLE_AGENT'])
    expect(codeOf(await follow('again', { taskId: asked.id }))).toBe(-32004)
    expect(codeOf(await follow('who', { taskId: 'nope' }))).toBe(-32001)
    // Another principal does not see the task at all.
    expect(codeOf(await s.handle(OTHER, call('GetTask', { id: asked.id })))).toBe(-32001)
    expect(codeOf(await s.handle(OTHER, call('CancelTask', { id: asked.id })))).toBe(-32001)
  })

  it('CancelTask cancels a working task, whose late answer is dropped; a finished task is TaskNotCancelableError', async () => {
    const gate = deferred()
    const s = server({ handler: gated(gate) })
    const configuration = { returnImmediately: true }
    const task = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('x'), configuration })))
    const canceled = taskOf(await s.handle(CLIENT, call('CancelTask', { id: task.id })))
    expect(canceled.status).toEqual({ state: 'TASK_STATE_CANCELED', timestamp: T0 })
    gate.resolve()
    await s.settled()
    const after = taskOf(await s.handle(CLIENT, call('GetTask', { id: task.id })))
    expect(after.status.state).toBe('TASK_STATE_CANCELED')
    expect(codeOf(await s.handle(CLIENT, call('CancelTask', { id: task.id })))).toBe(-32002)
  })

  it('a handler that throws or answers no valid outcome, JSON or not, fails the task with a reply that says so', async () => {
    const outcomes: unknown[] = [
      'x',
      undefined,
      { state: 'TASK_STATE_WORKING' },
      { parts: 'x' },
      { parts: [{}] },
      { parts: [{ data: () => 1 }] },
      { parts: [{ data: 1n }] },
      { artifacts: 'x' },
      { artifacts: ['x'] },
      { artifacts: [{ parts: [] }] },
      { artifacts: [{ parts: [{ text: 1 }] }] },
      { artifacts: [{ artifactId: '', parts: [{ text: 'a' }] }] },
      { artifacts: [{ artifactId: 1, parts: [{ text: 'a' }] }] },
    ]
    for (const outcome of outcomes) {
      const s = server({ handler: () => outcome as never })
      const task = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('x') })))
      expect(task.status.state).toBe('TASK_STATE_FAILED')
      expect(task.status.message?.parts).toEqual([{ text: 'the agent answered no valid outcome' }])
    }
    const thrown = server({
      handler: () => {
        throw new Error('secret detail')
      },
    })
    const task = taskOf(await thrown.handle(CLIENT, call('SendMessage', { message: say('x') })))
    expect(task.status.state).toBe('TASK_STATE_FAILED')
    expect(JSON.stringify(task)).not.toContain('secret detail')
    const explicit = server({ handler: () => ({ state: 'TASK_STATE_REJECTED' }) })
    const rejected = taskOf(await explicit.handle(CLIENT, call('SendMessage', { message: say('x') })))
    expect(rejected.status.state).toBe('TASK_STATE_REJECTED')
  })

  it('a fault after the handler answered fails the task; an answer no response could carry fails it at the turn end', async () => {
    let n = 0
    const broken = new A2aServer({
      handler: echo,
      newId: () => {
        n++
        if (n === 3) throw new Error('no id for the reply')
        return `id-${n}`
      },
    })
    const failed = taskOf(await broken.handle(CLIENT, call('SendMessage', { message: say('x') })))
    expect(failed.status).toEqual({ state: 'TASK_STATE_FAILED' })
    const big = server({ handler: () => ({ parts: [{ text: 'x'.repeat(MAX_RPC_BYTES) }] }) })
    const dropped = taskOf(await big.handle(CLIENT, call('SendMessage', { message: say('x') })))
    expect(dropped.status.state).toBe('TASK_STATE_FAILED')
    const said = [{ text: `the answer is over ${MAX_RPC_BYTES} bytes, dropped` }]
    expect(dropped.status.message?.parts).toEqual(said)
    expect(jsonBytes(dropped)).toBeLessThan(1000)
  })

  it('refuses bad params with Invalid params, and names the error of each method it does not support', async () => {
    const s = server({ handler: echo })
    const codes = async (method: string, params?: Record<string, unknown>) =>
      codeOf(await s.handle(CLIENT, call(method, params)))
    expect(await codes('SendMessage')).toBe(-32602)
    expect(await codes('SendMessage', { message: { ...say('x'), role: 'ROLE_AGENT' } })).toBe(-32602)
    expect(await codes('SendMessage', { message: say('x'), configuration: 1 })).toBe(-32602)
    const configured = (configuration: unknown) => codes('SendMessage', { message: say('x'), configuration })
    expect(await configured({ returnImmediately: 1 })).toBe(-32602)
    expect(await configured({ historyLength: -1 })).toBe(-32602)
    expect(await configured({ historyLength: 'x' })).toBe(-32602)
    expect(await configured({ taskPushNotificationConfig: { url: 'https://x.example' } })).toBe(-32003)
    expect(await configured({ pushNotificationConfig: { url: 'https://x.example' } })).toBe(-32003)
    expect(await codes('GetTask')).toBe(-32602)
    expect(await codes('GetTask', { id: 'x', historyLength: 1.5 })).toBe(-32602)
    expect(await codes('GetTask', { id: 'unknown' })).toBe(-32001)
    expect(await codes('SendStreamingMessage', { message: say('x') })).toBe(-32004)
    expect(await codes('SubscribeToTask', { id: 'x' })).toBe(-32004)
    expect(await codes('ListTasks')).toBe(-32004)
    for (const m of [
      'CreateTaskPushNotificationConfig',
      'GetTaskPushNotificationConfig',
      'ListTaskPushNotificationConfigs',
      'DeleteTaskPushNotificationConfig',
    ]) {
      expect(await codes(m)).toBe(-32003)
    }
    expect(await codes('GetExtendedAgentCard')).toBe(-32007)
    expect(await codes('message/send', { message: say('x') })).toBe(-32601)
  })

  it('forgets the oldest finished task past maxTasks, never a live one, and answers Internal error when it fails itself', async () => {
    const s = server({ handler: echo, maxTasks: 1 })
    const first = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('1') })))
    await s.handle(CLIENT, call('SendMessage', { message: say('2') }))
    expect(codeOf(await s.handle(CLIENT, call('GetTask', { id: first.id })))).toBe(-32001)
    const ask: A2aHandler = () => ({ state: 'TASK_STATE_INPUT_REQUIRED', parts: [{ text: '?' }] })
    const live = server({ handler: ask, maxTasks: 1 })
    const waiting = taskOf(await live.handle(CLIENT, call('SendMessage', { message: say('1') })))
    expect(codeOf(await live.handle(OTHER, call('SendMessage', { message: say('2') })))).toBe(-32000)
    expect(taskOf(await live.handle(CLIENT, call('GetTask', { id: waiting.id }))).id).toBe(waiting.id)
    const broken = server({
      handler: echo,
      newId: () => {
        throw new Error('no ids')
      },
    })
    const r = await broken.handle(CLIENT, call('SendMessage', { message: say('x') }))
    expect(r).toEqual({ jsonrpc: '2.0', id: rpcId, error: { code: -32603, message: 'internal error' } })
  })

  it('caps the tasks of one principal (its finished ones forgotten first) and the turns running at once', async () => {
    const ask: A2aHandler = (turn) =>
      textOf(turn.message) === 'done' ? {} : { state: 'TASK_STATE_INPUT_REQUIRED', parts: [{ text: '?' }] }
    const s = server({ handler: ask, maxTasksPerOwner: 1 })
    const done = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('done') })))
    const open = taskOf(await s.handle(CLIENT, call('SendMessage', { message: say('open') })))
    expect(codeOf(await s.handle(CLIENT, call('GetTask', { id: done.id })))).toBe(-32001)
    expect(open.status.state).toBe('TASK_STATE_INPUT_REQUIRED')
    expect(codeOf(await s.handle(CLIENT, call('SendMessage', { message: say('more') })))).toBe(-32000)
    expect(taskOf(await s.handle(OTHER, call('SendMessage', { message: say('done') }))).status.state).toBe(
      'TASK_STATE_COMPLETED',
    )
    const gate = deferred()
    const busy = server({ handler: gated(gate), maxTurns: 1 })
    const configuration = { returnImmediately: true }
    await busy.handle(CLIENT, call('SendMessage', { message: say('1'), configuration }))
    expect(codeOf(await busy.handle(OTHER, call('SendMessage', { message: say('2') })))).toBe(-32000)
    gate.resolve()
    await busy.settled()
    const after = await busy.handle(OTHER, call('SendMessage', { message: say('3') }))
    expect(taskOf(after).status.state).toBe('TASK_STATE_COMPLETED')
  })
})

describe('fitResponse: a response cut to fit a sealed reply', () => {
  const task = (history: string, artifact: string) => ({
    id: 't',
    contextId: 'c',
    status: { state: 'TASK_STATE_COMPLETED' },
    artifacts: [{ artifactId: 'a', parts: [{ text: artifact }] }],
    history: [{ messageId: 'm', role: 'ROLE_USER', parts: [{ text: history }] }],
  })
  const big = 'x'.repeat(MAX_RPC_BYTES)

  it('keeps a response that fits, drops the history, then the artifacts, and else answers Internal error', () => {
    const small = success(1, { task: task('h', 'a') })
    expect(fitResponse(small)).toBe(small)
    const artifacts = [{ artifactId: 'a', parts: [{ text: 'a' }] }]
    const lean = { id: 't', contextId: 'c', status: { state: 'TASK_STATE_COMPLETED' }, artifacts }
    expect(fitResponse(success(1, { task: task(big, 'a') }))).toEqual(success(1, { task: lean }))
    // GetTask and CancelTask answer the Task itself, not {task}.
    expect(fitResponse(success(2, task(big, big)))).toEqual(
      success(2, { id: 't', contextId: 'c', status: { state: 'TASK_STATE_COMPLETED' } }),
    )
    const over = failure(3, -32603, `the response is over ${MAX_RPC_BYTES} bytes`)
    expect(fitResponse(success(3, big))).toEqual(over)
    expect(fitResponse(success(3, { task: { ...task('h', 'a'), status: { message: big } } }))).toEqual(over)
    expect(fitResponse(failure(3, -32603, big))).toEqual(over)
    const tiny = failure(4, -32603, 'the response is over 10 bytes')
    expect(fitResponse(success(4, task('h', 'a')), 10)).toEqual(tiny)
  })
})

describe('a2aSessionHandler: the agent answers each A2A envelope in its thread, in the background', () => {
  const edge = (replies: { type: string; body: unknown }[]): AgentEdge => ({
    reply: async (_m, input) => {
      replies.push(input)
    },
  })

  it('answers an A2A request with the response, and a malformed body with Invalid Request', async () => {
    const replies: { type: string; body: unknown }[] = []
    const h = a2aSessionHandler(edge(replies), server({ handler: echo }))
    expect(h.session).toBe('a2a')
    const request = call('SendMessage', { message: say('hi') })
    expect(h.deliver(inbound({ type: A2A_TYPE, body: requestBody(request) }))).toBeUndefined()
    h.deliver(inbound({ type: A2A_TYPE, body: { nope: 1 } }))
    await h.settled()
    expect(replies.map((r) => r.type)).toEqual([A2A_TYPE, A2A_TYPE])
    const bodies = replies.map((r) => r.body)
    expect(bodies).toContainEqual({ a2a: '1.0', response: failure(null, -32600, expect.any(String)) })
    const answered = bodies.find((b) => (b as { response: { id: unknown } }).response.id === request.id)
    const completed = { status: { state: 'TASK_STATE_COMPLETED' } }
    expect(answered).toMatchObject({ a2a: '1.0', response: { result: { task: completed } } })
  })

  it('returns from delivery at once: a slow turn holds no other request', async () => {
    const replies: { type: string; body: unknown }[] = []
    const gate = deferred()
    const h = a2aSessionHandler(edge(replies), server({ handler: gated(gate) }))
    const slow = call('SendMessage', { message: say('slow') })
    const quick = call('GetTask', { id: 'none' })
    h.deliver(inbound({ type: A2A_TYPE, body: requestBody(slow) }))
    h.deliver(inbound({ type: A2A_TYPE, body: requestBody(quick) }))
    while (replies.length === 0) await new Promise((r) => setTimeout(r, 5))
    const ids = (): unknown[] => replies.map((r) => (r.body as { response: { id: number } }).response.id)
    expect(ids()).toEqual([quick.id])
    gate.resolve()
    await h.settled()
    expect(ids()).toEqual([quick.id, slow.id])
  })

  it('hands other types to `other`, fits a large task into the reply, and reports a failed reply', async () => {
    const replies: { type: string; body: unknown }[] = []
    const others: string[] = []
    const errors: unknown[] = []
    const half = 'x'.repeat(MAX_RPC_BYTES / 2)
    const big = server({ handler: () => ({ parts: [{ text: half }] }) })
    const other = (m: { readonly type: string }): void => {
      others.push(m.type)
    }
    const h = a2aSessionHandler(edge(replies), big, { session: 's', other })
    expect(h.session).toBe('s')
    h.deliver(inbound({ type: 'chat.v1', body: {} }))
    expect(others).toEqual(['chat.v1'])
    const request = call('SendMessage', { message: say('x') })
    h.deliver(inbound({ type: A2A_TYPE, body: requestBody(request) }))
    await h.settled()
    const [first] = replies.map((r) => r.body)
    const response = (first as { response: { result: { task: Task } } }).response
    expect(response.result.task.status.state).toBe('TASK_STATE_COMPLETED')
    expect(response.result.task.history).toBeUndefined()
    expect(jsonBytes(responseBody(response as JsonRpcResponse))).toBeLessThanOrEqual(MAX_RPC_BYTES)
    const failing: AgentEdge = {
      reply: async () => {
        throw new Error('relay down')
      },
    }
    const quiet = a2aSessionHandler(failing, server({ handler: echo }), { onError: (e) => errors.push(e) })
    quiet.deliver(inbound({ type: A2A_TYPE, body: requestBody(call('GetTask', { id: 'x' })) }))
    await quiet.settled()
    expect(errors).toEqual([new Error('relay down')])
    // Without `other` or `onError`, another type and a failed reply are dropped quietly.
    const bare = a2aSessionHandler(failing, server({ handler: echo }))
    expect(bare.deliver(inbound({ type: 'chat.v1', body: {} }))).toBeUndefined()
    bare.deliver(inbound({ type: A2A_TYPE, body: requestBody(call('GetTask', { id: 'x' })) }))
    await expect(bare.settled()).resolves.toBeUndefined()
  })
})
