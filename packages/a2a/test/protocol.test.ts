import { describe, expect, it } from 'vitest'
import { checkRequest, failure, isResponseTo, parseRequest, success } from '../src/jsonrpc.ts'
import {
  A2A_VERSION,
  copyMessage,
  ERRORS,
  INTERRUPTED,
  messageProblem,
  partProblem,
  ROLE_NUMBER,
  TASK_STATES,
  TERMINAL,
  textOf,
} from '../src/protocol.ts'

const user = { messageId: 'm1', role: 'ROLE_USER', parts: [{ text: 'hello' }] }

describe('the A2A 1.0 objects', () => {
  it('names version 1.0, eight task states without UNSPECIFIED, four terminal and two interrupted', () => {
    expect(A2A_VERSION).toBe('1.0')
    expect(TASK_STATES).toHaveLength(8)
    expect(TASK_STATES).not.toContain('TASK_STATE_UNSPECIFIED')
    expect(TERMINAL).toEqual([
      'TASK_STATE_COMPLETED',
      'TASK_STATE_FAILED',
      'TASK_STATE_CANCELED',
      'TASK_STATE_REJECTED',
    ])
    expect(INTERRUPTED).toEqual(['TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_AUTH_REQUIRED'])
    const codes = [ERRORS.taskNotFound, ERRORS.versionNotSupported, ERRORS.parseError]
    expect(codes).toEqual([-32001, -32009, -32700])
  })

  it('a part holds exactly one of text, raw, url and data, and its optional members have their types', () => {
    for (const ok of [
      { text: 'x' },
      { raw: 'aGk=', mediaType: 'text/plain', filename: 'a.txt' },
      { url: 'https://x.example/a' },
      { data: { a: 1 }, metadata: { k: 'v' } },
      { data: null },
    ]) {
      expect(partProblem(ok)).toBeNull()
    }
    expect(partProblem('x')).toBe('a part is an object')
    expect(partProblem({})).toBe('a part holds exactly one of text, raw, url and data')
    expect(partProblem({ text: 'a', url: 'b' })).toBe('a part holds exactly one of text, raw, url and data')
    expect(partProblem({ text: 1 })).toBe('part.text is a string')
    expect(partProblem({ text: 'a', mediaType: 2 })).toBe('part.mediaType is a string')
    expect(partProblem({ text: 'a', metadata: [] })).toBe('part.metadata is an object')
  })

  it('a message has an id, the expected role, non-empty valid parts and typed optional members', () => {
    expect(messageProblem(user, 'ROLE_USER')).toBeNull()
    const full = { ...user, contextId: 'c', taskId: 't', extensions: ['e'], referenceTaskIds: [] }
    expect(messageProblem(full, 'ROLE_USER')).toBeNull()
    expect(messageProblem(null, 'ROLE_USER')).toBe('message is an object')
    const problem = (extra: Record<string, unknown>): string | null =>
      messageProblem({ ...user, ...extra }, 'ROLE_USER')
    expect(problem({ messageId: '' })).toBe('message.messageId is a non-empty string')
    expect(messageProblem(user, 'ROLE_AGENT')).toBe('message.role is ROLE_AGENT')
    expect(problem({ parts: [] })).toBe('message.parts is a non-empty list')
    expect(problem({ parts: [{}] })).toBe('a part holds exactly one of text, raw, url and data')
    expect(problem({ taskId: '' })).toBe('message.taskId is a non-empty string')
    expect(problem({ extensions: [1] })).toBe('message.extensions is a list of strings')
    expect(problem({ metadata: 'm' })).toBe('message.metadata is an object')
  })

  it('reads a role by its enum number as ProtoJSON does, and copyMessage writes it by name', () => {
    expect(ROLE_NUMBER).toEqual({ ROLE_USER: 1, ROLE_AGENT: 2 })
    expect(messageProblem({ ...user, role: 1 }, 'ROLE_USER')).toBeNull()
    expect(messageProblem({ ...user, role: 2 }, 'ROLE_USER')).toBe('message.role is ROLE_USER')
    expect(messageProblem({ ...user, role: 2 }, 'ROLE_AGENT')).toBeNull()
    expect(copyMessage({ ...user, role: 1 }).role).toBe('ROLE_USER')
    expect(copyMessage({ ...user, role: 2 }).role).toBe('ROLE_AGENT')
  })

  it('copyMessage keeps the members of a2a.proto Message only, deep-copied; textOf joins the text parts', () => {
    const given = { ...user, kind: 'message', extra: 1, parts: [{ text: 'a' }, { data: 1 }, { text: 'b' }] }
    const copy = copyMessage(given)
    expect(copy).toEqual({ messageId: 'm1', role: 'ROLE_USER', parts: given.parts })
    expect(copy.parts).not.toBe(given.parts)
    expect(textOf(copy)).toBe('a\nb')
  })
})

describe('JSON-RPC 2.0', () => {
  it('parses a request, and answers Parse error, Invalid Request and Invalid params with the id when it has one', () => {
    expect(parseRequest('{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}')).toEqual({
      ok: true,
      request: { jsonrpc: '2.0', id: 1, method: 'GetTask', params: { id: 't' } },
    })
    expect(checkRequest({ jsonrpc: '2.0', id: 'a', method: 'M' })).toEqual({
      ok: true,
      request: { jsonrpc: '2.0', id: 'a', method: 'M' },
    })
    const code = (r: ReturnType<typeof parseRequest>): [number, unknown] =>
      r.ok ? [0, null] : [(r.response as { error: { code: number } }).error.code, r.response.id]
    expect(code(parseRequest('{'))).toEqual([-32700, null])
    expect(code(parseRequest('[]'))).toEqual([-32600, null])
    expect(code(checkRequest({ jsonrpc: '1.0', id: 1, method: 'M' }))).toEqual([-32600, 1])
    expect(code(checkRequest({ jsonrpc: '2.0', method: 'M' }))).toEqual([-32600, null])
    expect(code(checkRequest({ jsonrpc: '2.0', id: Number.NaN, method: 'M' }))).toEqual([-32600, null])
    expect(code(checkRequest({ jsonrpc: '2.0', id: 2, method: '' }))).toEqual([-32600, 2])
    expect(code(checkRequest({ jsonrpc: '2.0', id: 3, method: 'M', params: [1] }))).toEqual([-32602, 3])
  })

  it('isResponseTo holds for a result or a well-formed error to the same id, never both and never neither', () => {
    expect(isResponseTo(success(1, { a: 1 }), 1)).toBe(true)
    expect(isResponseTo(failure(1, -32001, 'no'), 1)).toBe(true)
    expect(isResponseTo(success(1, null), 2)).toBe(false)
    expect(isResponseTo({ jsonrpc: '2.0', id: 1 }, 1)).toBe(false)
    expect(isResponseTo({ jsonrpc: '2.0', id: 1, result: 1, error: { code: 1, message: '' } }, 1)).toBe(false)
    expect(isResponseTo({ jsonrpc: '2.0', id: 1, error: { code: 1.5, message: '' } }, 1)).toBe(false)
    expect(isResponseTo({ jsonrpc: '2.0', id: 1, error: 'x' }, 1)).toBe(false)
    expect(isResponseTo({ jsonrpc: '1.0', id: 1, result: 1 }, 1)).toBe(false)
    expect(isResponseTo('x', 1)).toBe(false)
  })
})
