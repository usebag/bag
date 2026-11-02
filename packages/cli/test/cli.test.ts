import { AcError } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { CliError } from '../src/args.ts'
import { codeOf, detailOf, USAGE } from '../src/cli.ts'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

describe('the command line: help, unknown commands, and errors as "bag: <code>: <detail>" with exit 1', () => {
  it('prints the usage for help, --help and -h, with exit 0', async () => {
    const io = testIo(new MemoryRelay())
    for (const h of ['help', '--help', '-h']) {
      expect(await cli(io, h)).toEqual({ code: 0, out: [USAGE], err: [] })
    }
    for (const command of [
      'keygen',
      'login',
      'logout',
      'grant',
      'record address',
      'record keep',
      'delegate',
      'name add',
      'send',
      'inbox',
      'audit verify',
      'health',
    ]) {
      expect(USAGE).toContain(`  ${command} `)
    }
  })

  it('prints the usage for --help or -h after a command, and runs nothing', async () => {
    const io = testIo(new MemoryRelay())
    for (const asked of ['--help', '-h']) {
      expect(await cli(io, 'send', '--to', 'x', asked)).toEqual({ code: 0, out: [USAGE], err: [] })
    }
  })

  it('refuses no command and an unknown one with a usage error', async () => {
    const io = testIo(new MemoryRelay())
    expect(await cli(io)).toEqual({
      code: 1,
      out: [],
      err: ['bag: usage: no command', `run "node ${process.argv[1]} help" for the commands`],
    })
    expect((await cli(io, 'constructor')).err[0]).toBe('bag: usage: no command "constructor"')
  })

  it('names the code of every kind of error', () => {
    expect(codeOf(new AcError('bad-record', 'x'))).toBe('bad-record')
    expect(codeOf(new CliError('unhealthy', 'x'))).toBe('unhealthy')
    expect(codeOf(new RelayError('rate-limited', 429, 7, 'x'))).toBe('rate-limited')
    expect(codeOf(new RelayError(null, 0, null, 'x'))).toBe('unreachable')
    expect(codeOf(new RelayError(null, 500, null, 'x'))).toBe('http-500')
    expect(codeOf(Object.assign(new Error('x'), { code: 'EEXIST' }))).toBe('EEXIST')
    expect(codeOf(new Error('x'))).toBe('error')
    expect(codeOf('a string')).toBe('error')
    expect(codeOf(null)).toBe('error')
  })

  it('drops the leading code from a detail that repeats it', () => {
    expect(detailOf(new AcError('bad-record', 'roots is a list'), 'bad-record')).toBe('roots is a list')
    expect(detailOf(new Error('EEXIST: file already exists'), 'EEXIST')).toBe('file already exists')
    expect(detailOf(new Error('plain'), 'error')).toBe('plain')
    expect(detailOf('thrown text', 'error')).toBe('thrown text')
  })
})
