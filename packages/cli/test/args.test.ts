import { describe, expect, it } from 'vitest'
import { CliError, flag, int, list, parse, relayUrl, str, UsageError } from '../src/args.ts'

const SPEC = {
  positionals: ['name'],
  options: {
    one: { type: 'string' },
    many: { type: 'string', multiple: true },
    on: { type: 'boolean' },
    n: { type: 'string' },
  },
  required: ['one'],
} as const

describe('args: strict parsing of positionals, options and their values', () => {
  it('reads positionals, strings, repeated strings, flags and positive integers', () => {
    const p = parse(['x', '--one', 'a', '--many', 'b', '--many=c', '--on', '--n', '42'], SPEC)
    expect(p.positionals).toEqual(['x'])
    expect([str(p, 'one'), list(p, 'many'), flag(p, 'on'), int(p, 'n')]).toEqual(['a', ['b', 'c'], true, 42])
    const q = parse(['y', '--one', 'a'], SPEC)
    expect([str(q, 'none'), list(q, 'many'), flag(q, 'on'), int(q, 'n')]).toEqual([
      undefined,
      [],
      false,
      undefined,
    ])
  })

  it('refuses an unknown option, a missing value, a missing required option and the wrong positionals', () => {
    for (const [args, message] of [
      [['x', '--one', 'a', '--two'], "Unknown option '--two'"],
      [['x', '--one'], "Option '--one <value>' argument missing"],
      [['x'], '--one is required'],
      [['--one', 'a'], 'expected <name>'],
      [['x', 'y', '--one', 'a'], 'expected <name>'],
    ] as const) {
      const e = (() => {
        try {
          parse(args, SPEC)
        } catch (x) {
          return x
        }
        return null
      })()
      expect(e, args.join(' ')).toBeInstanceOf(UsageError)
      expect((e as UsageError).message, args.join(' ')).toContain(message)
    }
    expect(() => parse(['stray'], { positionals: [], options: {} })).toThrow(
      'usage: no positional argument, not stray',
    )
  })

  it('reads only decimal positive integers', () => {
    for (const bad of ['0', '-1', '1.5', '1e3', '01', ' 7', 'x', String(2 ** 53)]) {
      expect(() => int(parse(['x', '--one', 'a', `--n=${bad}`], SPEC), 'n'), bad).toThrow(
        `usage: --n is a positive integer, not ${JSON.stringify(bad)}`,
      )
    }
  })

  it('takes http and https relay URLs, without a trailing slash, and refuses anything else', () => {
    expect(relayUrl('http://127.0.0.1:8080/')).toBe('http://127.0.0.1:8080')
    expect(relayUrl('https://relay.example')).toBe('https://relay.example')
    expect(() => relayUrl('relay.example')).toThrow('is not a URL')
    expect(() => relayUrl('ftp://relay.example')).toThrow('is not an http or https URL')
  })

  it('gives its own errors a code, usage for a UsageError', () => {
    expect(new CliError('unhealthy', 'x')).toMatchObject({ code: 'unhealthy', message: 'unhealthy: x' })
    expect(new UsageError('y')).toMatchObject({ code: 'usage', name: 'UsageError', message: 'usage: y' })
  })
})
