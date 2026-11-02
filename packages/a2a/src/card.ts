import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { A2A_TYPE } from './binding.ts'
import {
  A2A_VERSION,
  type AgentCard,
  type AgentExtension,
  type AgentSkill,
  isRecord,
  JSONRPC_BINDING,
} from './protocol.ts'

// Two documents of a bag address, both from its address record (spec/SPEC.md §7.2).
//
// The public one, served at the org's /.well-known/bag/a2a.json beside the record: an AgentExtension object
// (A2A 1.0.0, section 4.4.4) standing alone,
// `urn:bag:a2a:v1` with the address, the record's URL and the envelope type, and no interface. No public
// /.well-known/agent-card.json is served: section 14.3 says the resource there MUST be an AgentCard, an AgentCard
// requires supportedInterfaces (section 4.4.1; a2a.proto marks supported_interfaces REQUIRED) with an accurate URL
// (section 8.3.1), and the only URL that reaches the agent is the caller's own bridge on loopback. The description
// says what the file is and where the card is.
//
// The full AgentCard, which the caller's bridge serves at its loopback path /a2a/<address>/.well-known/agent-card.json
// from the record it fetched and verified: one JSONRPC 1.0 interface at http://<bridge>/a2a/<address>.
//
// This file runs as a program too, with no workspace package (deploy/make-a2a-extension.sh writes the public one):
//   node packages/a2a/src/card.ts --record <address.json> --out <file> --domain <domain>

/** The extension that names the binding. */
export const EXTENSION_URI = 'urn:bag:a2a:v1'
/** Where a bridge serves an address's full card, under the address's endpoint. */
export const BRIDGE_CARD_PATH = '/.well-known/agent-card.json'
const MODES = ['text/plain', 'application/json']
const ADDRESS = /^ed25519:[0-9a-f]{64}$/

/** The fields of an address record a card reads. */
export interface CardRecord {
  readonly key: string
  readonly relays: readonly string[]
}

/** Why a value is not an address record a card can be made from, or null. */
export function recordProblem(v: unknown): string | null {
  if (!isRecord(v) || v.kind !== 'address') return 'the record is an address record (kind "address")'
  if (typeof v.key !== 'string' || !ADDRESS.test(v.key)) return 'the record key is ed25519:<64 hex>'
  if (typeof v.sealing_key !== 'string') return 'the record names a sealing key, so that requests seal to it'
  if (!Array.isArray(v.relays) || v.relays.length === 0 || !v.relays.every((r) => typeof r === 'string')) {
    return 'the record names its relays'
  }
  return null
}

/** The public document: the bag extension of the address, not an AgentCard. */
export function publicExtension(record: CardRecord, domain: string): AgentExtension {
  return {
    uri: EXTENSION_URI,
    description:
      `The bag A2A extension of ${domain}, not an AgentCard: ${domain} is reached through ` +
      "the caller's local A2A bridge, which seals each request to this address and serves the full " +
      `AgentCard at /a2a/<address>${BRIDGE_CARD_PATH} on its own port. Pre-release sample.`,
    required: true,
    params: {
      address: record.key,
      addressRecord: `https://${domain}/.well-known/bag/address.json`,
      envelopeType: A2A_TYPE,
    },
  }
}

export interface CardOptions {
  /** The bridge's base URL, http://127.0.0.1:<port>. */
  readonly endpoint: string
  readonly name?: string
  readonly description?: string
  /** The agent's own version (default 0.0.0, the repository's package version). */
  readonly version?: string
  readonly skills?: readonly AgentSkill[]
}

/** The full AgentCard of an address at a bridge: one JSONRPC 1.0 interface at <endpoint>/a2a/<address>. */
export function agentCard(record: CardRecord, o: CardOptions): AgentCard {
  return {
    name: o.name ?? record.key,
    description:
      o.description ??
      'A bag agent, reached through this local A2A bridge: each request is sealed to its address, ' +
        'and the relays carry ciphertext only.',
    supportedInterfaces: [
      {
        url: `${o.endpoint.replace(/\/+$/, '')}/a2a/${record.key}`,
        protocolBinding: JSONRPC_BINDING,
        protocolVersion: A2A_VERSION,
      },
    ],
    version: o.version ?? '0.0.0',
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extendedAgentCard: false,
      extensions: [
        {
          uri: EXTENSION_URI,
          description: 'A2A JSON-RPC sealed in bag envelopes by this bridge.',
          required: false,
          params: { address: record.key, relays: record.relays, envelopeType: A2A_TYPE },
        },
      ],
    },
    defaultInputModes: MODES,
    defaultOutputModes: MODES,
    skills: o.skills ?? [
      {
        id: 'message',
        name: 'Message',
        description: 'Send this agent a message and get a task back, sealed end to end over bag.',
        tags: ['bag', 'message'],
      },
    ],
  }
}

const WIDTH = 110

/**
 * JSON as Biome formats it (biome.json: 2 spaces, width 110): every object broken one member per line, an array on
 * one line when it fits and holds no object, else one element per line. The file can then be committed as written.
 */
export function formatJson(value: unknown): string {
  return `${format(value, 0, 0, 0)}\n`
}

/** `value` starting at column `column`, inside a block indented `indent`, followed by `trail` characters. */
function format(value: unknown, indent: number, column: number, trail: number): string {
  const pad = ' '.repeat(indent + 2)
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]'
    if (!value.some(isRecord)) {
      const inline = `[${value.map((v) => format(v, indent, 0, 0)).join(', ')}]`
      if (column + inline.length + trail <= WIDTH) return inline
    }
    const items = value.map((v, i) => pad + format(v, indent + 2, pad.length, i < value.length - 1 ? 1 : 0))
    return `[\n${items.join(',\n')}\n${' '.repeat(indent)}]`
  }
  if (isRecord(value)) {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined)
    if (entries.length === 0) return '{}'
    const lines = entries.map(([k, v], i) => {
      const lead = `${pad}${JSON.stringify(k)}: `
      return lead + format(v, indent + 2, lead.length, i < entries.length - 1 ? 1 : 0)
    })
    return `{\n${lines.join(',\n')}\n${' '.repeat(indent)}}`
  }
  return JSON.stringify(value)
}

export interface CardIo {
  readonly out: (line: string) => void
  readonly err: (line: string) => void
}

const USAGE = 'usage: card.ts --record <address.json> --out <file> --domain <domain>'
const FLAGS = ['--record', '--out', '--domain']

/** The program: writes the public document and prints one line; 0 on success, 2 on a refusal (nothing written). */
export function makeCardMain(argv: readonly string[], io: CardIo): number {
  const a = new Map<string, string>()
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i] as string
    const value = argv[i + 1]
    if (!FLAGS.includes(flag) || value === undefined || a.has(flag)) {
      io.err(USAGE)
      return 2
    }
    a.set(flag, value)
  }
  const record = a.get('--record')
  const out = a.get('--out')
  const domain = a.get('--domain')
  if (record === undefined || out === undefined || domain === undefined) {
    io.err(USAGE)
    return 2
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(record, 'utf8'))
  } catch (e) {
    io.err(`make-a2a-extension: could not read the record: ${(e as Error).message}`)
    return 2
  }
  const why = recordProblem(parsed)
  if (why !== null) {
    io.err(`make-a2a-extension: ${why}`)
    return 2
  }
  const { key } = parsed as CardRecord
  writeFileSync(out, formatJson(publicExtension(parsed as CardRecord, domain)))
  io.out(`extension ${EXTENSION_URI} address ${key} envelope ${A2A_TYPE} out ${out}`)
  return 0
}

// The process's entry (node packages/a2a/src/card.ts ...); imported, it does nothing (test/card-entry.test.ts runs both).
if (resolve(String(process.argv[1])) === fileURLToPath(import.meta.url)) {
  process.exitCode = makeCardMain(process.argv.slice(2), { out: console.log, err: console.error })
}
