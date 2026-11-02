import { AcError } from '@usebag/core'
import { EdgeError, RelayError } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { ConfigError } from '../src/config.ts'
import { jsonLogger } from '../src/log.ts'
import { codeOf, detailOf, ToolError } from '../src/tools.ts'
import { FakeClock } from './support/fixtures.ts'

describe('codeOf and detailOf: every failure as a code and a detail', () => {
  it("names the closed set's codes, the server's own, a relay failure's, an errno, and internal for the rest", () => {
    const cases: [unknown, string, string][] = [
      [new AcError('bad-sig', 'it does not verify'), 'bad-sig', 'it does not verify'],
      [new ToolError('usage', 'exp is wrong'), 'usage', 'exp is wrong'],
      [new ConfigError('busy', 'held'), 'busy', 'held'],
      [new EdgeError('busy', 'another writer'), 'busy', 'another writer'],
      [new EdgeError('truncated', 'the log is short'), 'truncated', 'the log is short'],
      [new RelayError('rate-limited', 429, 3, 'slow down'), 'rate-limited', 'slow down'],
      [new RelayError(null, 0, null, 'refused'), 'unreachable', 'no response: refused'],
      [new RelayError(null, 500, null, 'internal'), 'http-500', 'status 500: internal'],
      [Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' }), 'ENOENT', 'no such file'],
      [Object.assign(new Error('not open'), { code: 'ERR_INVALID_STATE' }), 'internal', 'not open'],
      ['a thrown string', 'internal', 'a thrown string'],
      [null, 'internal', 'null'],
    ]
    for (const [error, code, detail] of cases) {
      expect([codeOf(error), detailOf(error, codeOf(error))]).toEqual([code, detail])
    }
  })
})

describe('jsonLogger', () => {
  it('writes one JSON line per event, its time from the clock, with or without fields', () => {
    const lines: string[] = []
    const log = jsonLogger((l) => lines.push(l), new FakeClock())
    log.log('info', 'start', { address: 'ed25519:00', relays: ['http://r'] })
    log.log('warn', 'bare')
    expect(lines).toEqual([
      '{"ts":"2027-01-15T08:00:00.000Z","level":"info","event":"start","address":"ed25519:00","relays":["http://r"]}\n',
      '{"ts":"2027-01-15T08:00:00.000Z","level":"warn","event":"bare"}\n',
    ])
  })
})
