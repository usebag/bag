import { beforeEach, describe, expect, it, vi } from 'vitest'
import { runExec } from '../src/commands/watch.ts'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'

// runExec's stdin error handler for an error not EPIPE, ECONNRESET or ENOTCONN: the line is the
// error's own message, once. A real child cannot be made to fail its stdin with another code (the pipe is
// runExec's own), so this file replaces node:child_process's spawn with a fake child, and only this file:
// watch.test.ts keeps the real one for every other test. The fake's stdin raises the planned errors in end(),
// and the child closes with exit code 0 afterwards, or the close comes first and the errors after it.

const plan = vi.hoisted(() => ({ errors: [] as Error[], closeFirst: false }))

vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>()
  const { EventEmitter } = await import('node:events')
  const spawn = (): unknown => {
    const child = Object.assign(new EventEmitter(), { kill: () => true, stdin: new EventEmitter() })
    const raise = (): void => {
      for (const e of plan.errors) child.stdin.emit('error', e)
    }
    Object.assign(child.stdin, {
      end: () => {
        if (!plan.closeFirst) raise()
        setImmediate(() => {
          child.emit('close', 0, null)
          if (plan.closeFirst) raise()
        })
      },
    })
    return child
  }
  return { ...real, spawn }
})

const withCode = (message: string, code: string): Error => Object.assign(new Error(message), { code })
const LINE = 'bag: exec-failed: '

describe('runExec: a stdin error with another code is the error message, once, and the run resolves', () => {
  beforeEach(() => {
    plan.errors = []
    plan.closeFirst = false
  })

  it('logs the message of an EIO error, though the command exits 0', async () => {
    plan.errors = [withCode('write EIO', 'EIO')]
    const io = testIo(new MemoryRelay())
    await runExec('true', 'line', io, '/bin/sh')
    expect(io.stderr).toEqual([`${LINE}write EIO`])
  })

  it('logs the message of an error with no code', async () => {
    plan.errors = [new Error('stdin broke')]
    const io = testIo(new MemoryRelay())
    await runExec('true', 'line', io, '/bin/sh')
    expect(io.stderr).toEqual([`${LINE}stdin broke`])
  })

  it('logs only the first of two errors', async () => {
    plan.errors = [withCode('write EIO', 'EIO'), new Error('stdin broke')]
    const io = testIo(new MemoryRelay())
    await runExec('true', 'line', io, '/bin/sh')
    expect(io.stderr).toEqual([`${LINE}write EIO`])
  })

  it('logs one line when the close (exit 0) comes first, and the close fails nothing', async () => {
    plan.closeFirst = true
    plan.errors = [withCode('write EIO', 'EIO'), new Error('stdin broke')]
    const io = testIo(new MemoryRelay())
    await runExec('true', 'line', io, '/bin/sh')
    expect(io.stderr).toEqual([`${LINE}write EIO`])
  })
})
