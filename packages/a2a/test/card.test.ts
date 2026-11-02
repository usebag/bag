import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  agentCard,
  BRIDGE_CARD_PATH,
  EXTENSION_URI,
  formatJson,
  makeCardMain,
  publicExtension,
  recordProblem,
} from '../src/card.ts'
import { AGENT } from './support.ts'

const REPO = resolve(import.meta.dirname, '../../..')
const record = {
  kind: 'address',
  key: AGENT,
  sealing_key: '0'.repeat(64),
  relays: ['https://relay-acme.usuals.now'],
}

interface Run {
  readonly code: number
  readonly out: string[]
  readonly err: string[]
}

/** Runs the program; its exit code and the lines it printed. */
function run(argv: readonly string[]): Run {
  const out: string[] = []
  const err: string[] = []
  const code = makeCardMain(argv, { out: (l) => out.push(l), err: (l) => err.push(l) })
  return { code, out, err }
}

describe('the public document and the full AgentCard of an address record', () => {
  it('the public document is the bag extension alone, not an AgentCard, and names no loopback URL', () => {
    const doc = publicExtension(record, 'acme.usuals.now')
    expect(doc).toEqual({
      uri: EXTENSION_URI,
      description: expect.stringMatching(/^The bag A2A extension of acme\.usuals\.now, not an /),
      required: true,
      params: {
        address: AGENT,
        addressRecord: 'https://acme.usuals.now/.well-known/bag/address.json',
        envelopeType: 'a2a.jsonrpc.v1',
      },
    })
    expect(doc.description).toContain(`/a2a/<address>${BRIDGE_CARD_PATH}`)
    expect(JSON.stringify(doc)).not.toMatch(/127\.0\.0\.1|localhost|\[::1\]/)
    expect(doc).not.toHaveProperty('supportedInterfaces')
  })

  it('the full card names one JSONRPC 1.0 interface at the bridge, no streaming, the extension and a skill', () => {
    const card = agentCard(record, { endpoint: 'http://127.0.0.1:7741/' })
    expect(card).toEqual({
      name: AGENT,
      description: expect.stringContaining('the relays carry ciphertext only'),
      supportedInterfaces: [
        { url: `http://127.0.0.1:7741/a2a/${AGENT}`, protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
      ],
      version: '0.0.0',
      capabilities: {
        streaming: false,
        pushNotifications: false,
        extendedAgentCard: false,
        extensions: [
          {
            uri: EXTENSION_URI,
            description: expect.any(String),
            required: false,
            params: { address: AGENT, relays: record.relays, envelopeType: 'a2a.jsonrpc.v1' },
          },
        ],
      },
      defaultInputModes: ['text/plain', 'application/json'],
      defaultOutputModes: ['text/plain', 'application/json'],
      skills: [expect.objectContaining({ id: 'message', tags: ['bag', 'message'] })],
    })
    const skills = [{ id: 'a', name: 'A', description: 'a', tags: [] }]
    const options = { endpoint: 'http://h:1', name: 'X', description: 'd', version: '2', skills }
    const named = agentCard(record, options)
    expect([named.name, named.description, named.version, named.skills]).toEqual(['X', 'd', '2', skills])
  })

  it('refuses a record that is not an address record with a key, a sealing key and relays', () => {
    expect(recordProblem(record)).toBeNull()
    expect(recordProblem('x')).toMatch(/kind "address"/)
    expect(recordProblem({ ...record, kind: 'handle' })).toMatch(/kind "address"/)
    expect(recordProblem({ ...record, key: 1 })).toMatch(/ed25519/)
    expect(recordProblem({ ...record, key: 'ed25519:xyz' })).toMatch(/ed25519/)
    expect(recordProblem({ ...record, sealing_key: null })).toMatch(/sealing key/)
    expect(recordProblem({ ...record, relays: [] })).toMatch(/relays/)
    expect(recordProblem({ ...record, relays: [1] })).toMatch(/relays/)
    expect(recordProblem({ ...record, relays: 'x' })).toMatch(/relays/)
  })

  it('formats JSON as Biome does: objects broken, arrays on one line when they fit and hold no object', () => {
    expect(formatJson({})).toBe('{}\n')
    expect(formatJson({ a: [], b: {}, c: [1, 'x', null], d: [{ e: true }], f: undefined })).toBe(
      '{\n  "a": [],\n  "b": {},\n  "c": [1, "x", null],\n  "d": [\n    {\n      "e": true\n    }\n  ]\n}\n',
    )
    const long = ['a'.repeat(50), 'b'.repeat(50)]
    expect(formatJson({ long })).toBe(`{\n  "long": [\n    "${long[0]}",\n    "${long[1]}"\n  ]\n}\n`)
    // The lead `  "fits": ` (10), the array (98) and the comma make 109, which fits; with 97 c's, 112 does not.
    const fits = ['c'.repeat(94)]
    expect(formatJson({ fits, z: 1 }).split('\n')[1]).toBe(`  "fits": ["${fits[0]}"],`)
    expect(formatJson({ fits: ['c'.repeat(97)], z: 1 }).split('\n')[1]).toBe('  "fits": [')
    expect(formatJson([[1, 2], []])).toBe('[[1, 2], []]\n')
  })
})

describe('makeCardMain, the program deploy/make-a2a-extension.sh runs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bag-a2a-card-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  const recordFile = join(dir, 'address.json')
  writeFileSync(recordFile, JSON.stringify(record))

  it('writes the public document and prints one line; the committed samples regenerate byte for byte', () => {
    const out = join(dir, 'card.json')
    const r = run(['--record', recordFile, '--out', out, '--domain', 'acme.usuals.now'])
    expect([r.code, r.err]).toEqual([0, []])
    expect(r.out).toEqual([`extension ${EXTENSION_URI} address ${AGENT} envelope a2a.jsonrpc.v1 out ${out}`])
    expect(JSON.parse(readFileSync(out, 'utf8'))).toEqual(publicExtension(record, 'acme.usuals.now'))
    for (const org of ['acme', 'globex']) {
      const wellKnown = join(REPO, 'deploy', 'well-known', 'public', org, '.well-known')
      const again = join(dir, `${org}.json`)
      const args = ['--record', join(wellKnown, 'bag', 'address.json'), '--out', again]
      expect(run([...args, '--domain', `${org}.usuals.now`]).code).toBe(0)
      const committed = readFileSync(join(wellKnown, 'bag', 'a2a.json'), 'utf8')
      expect(readFileSync(again, 'utf8')).toBe(committed)
    }
  })

  it('refuses, exit 2 and nothing written: bad usage, an unreadable record, a bad record', () => {
    const out = join(dir, 'never.json')
    const usage = /^usage: card\.ts /
    expect(run([]).err[0]).toMatch(usage)
    expect(run(['--record', recordFile, '--out', out, '--nope', 'x']).err[0]).toMatch(usage)
    expect(run(['--record', recordFile, '--out']).err[0]).toMatch(usage)
    expect(run(['--record', recordFile, '--record', recordFile]).err[0]).toMatch(usage)
    expect(run(['--record', recordFile]).err[0]).toMatch(usage)
    const missing = run(['--record', join(dir, 'absent.json'), '--out', out, '--domain', 'a.example'])
    const unreadable = expect.stringMatching(/^make-a2a-extension: could not read the record/)
    expect([missing.code, missing.err[0]]).toEqual([2, unreadable])
    const bad = join(dir, 'bad.json')
    writeFileSync(bad, JSON.stringify({ ...record, kind: 'accept-from' }))
    const refused = run(['--record', bad, '--out', out, '--domain', 'a.example'])
    expect([refused.code, refused.err[0]]).toEqual([2, expect.stringMatching(/kind "address"/)])
    expect(() => readFileSync(out)).toThrow()
  })
})
