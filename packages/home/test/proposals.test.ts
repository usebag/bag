import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { proposalRows, proposalsText, writeProposals } from '../src/index.ts'
import { folder } from './support.ts'

// <home>/proposals.json's one writer: host migrate builds its text with proposalsText, and the service's host_wire
// changes its rows with writeProposals, written beside and renamed in.

const row = { folder: '/w/a', host: 'omp', label: 'jane', from: 'host_wire', stamp: '20261115T030000Z' }

describe('writeProposals', () => {
  it('writes the rows 0600 through a file beside it, renamed in, and changes the rows already there', () => {
    const home = folder()
    expect(writeProposals(home, (rows) => [...rows, row], 77)).toEqual([row])
    const file = join(home, 'proposals.json')
    expect(readFileSync(file, 'utf8')).toBe(proposalsText([row]))
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ version: 1, proposals: [row] })
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(readdirSync(home)).toEqual(['proposals.json'])
    expect(writeProposals(home, (rows) => rows.filter((r) => r.folder !== '/w/a'), 77)).toEqual([])
    expect(proposalRows(JSON.parse(readFileSync(file, 'utf8')))).toEqual([])
  })

  it('refuses a file that does not read as JSON, never writing over it', () => {
    const home = folder()
    writeFileSync(join(home, 'proposals.json'), 'not json', { mode: 0o600 })
    expect(() => writeProposals(home, () => [row])).toThrow(
      /does not read as proposals: it is not written over/,
    )
    expect(readFileSync(join(home, 'proposals.json'), 'utf8')).toBe('not json')
  })

  it('reads no rows from no file, or a file whose proposals is not a list', () => {
    expect(proposalRows(null)).toEqual([])
    expect(proposalRows({ version: 1, proposals: 'x' })).toEqual([])
  })
})
