import { describe, expect, it } from 'vitest'
import * as mcp from '../src/index.ts'

describe('@usebag/mcp: its public API', () => {
  it('names itself and the two workspace packages it builds on, and exports the server by name', () => {
    expect(mcp.packageName()).toBe('@usebag/mcp')
    expect(mcp.dependsOn()).toEqual(['@usebag/core', '@usebag/edge'])
    for (const name of [
      'serve',
      'startServer',
      'processIo',
      'parseConfig',
      'openIdentity',
      'Desk',
      'registerTools',
    ]) {
      expect(typeof (mcp as Record<string, unknown>)[name]).toBe('function')
    }
    expect([mcp.SESSION, mcp.TOOL_NAMES.length, mcp.QUESTION_TYPE, mcp.HANDOFF_TYPE]).toEqual([
      'mcp',
      11,
      'question.v1',
      'handoff.v1',
    ])
  })
})
