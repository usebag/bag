import { lstatSync, readFileSync } from 'node:fs'
import {
  type MembersRecord,
  newThread,
  type PolicyRecord,
  parseEnvelope,
  parseMembersRecord,
  parsePolicyRecord,
  verifyMembersRecord,
  verifyPolicyRecord,
} from '@usebag/core'
import {
  allowAll,
  type Clock,
  coreRng,
  type Edge,
  type EdgeStore,
  type Held,
  keyword,
  type PolicyOptions,
  type Rng,
  SendHeld,
  type SendInput,
  type SendResult,
  type WaitingSend,
} from '@usebag/edge'
import { type Config, ConfigError } from './config.ts'

// The org's two policy records at the MCP server: --policy <file>, the
// served record, and --members <file>, the members record, the org's own (0600 like a key file, never served, never
// shown to the model). Both are read once, at start, and verified at the server's clock; a changed file takes effect
// at the next start. With a members record, every send of the tools (send and its replies, ask, handoff) goes through
// the edge's outbound gate, which the Edge composes. What the model sees of the policy is counts and metadata, never a body, and nothing here
// releases or drops: release and drop are a person's acts, through the CLI on a terminal.

/** A policy file the server refuses at start: unreadable, a members file not 0600, or a record that does not verify. */
export class PolicyFileError extends ConfigError {}

/** The records the edge takes: the served one, the members one, either, or neither. */
export type OrgRecords = { readonly org?: PolicyRecord; readonly members?: MembersRecord }

/** Reads a file through `check`; a refusal names the flag, the file and the code (the core's, or the errno). */
function read<R>(flag: string, file: string, check: (bytes: Uint8Array) => R): R {
  try {
    return check(readFileSync(file))
  } catch (e) {
    const { code, message } = e as { code: string; message: string }
    throw new PolicyFileError(code, `${flag} ${file}: ${message}`)
  }
}

/** Loads --policy and --members, each verified at `now`, both (when given) signed by one org root. */
export function loadRecords(config: Pick<Config, 'policy' | 'members'>, now: number): OrgRecords {
  const out: { org?: PolicyRecord; members?: MembersRecord } = {}
  const { policy, members } = config
  if (policy !== null)
    out.org = read('--policy', policy, (b) => verifyPolicyRecord(parsePolicyRecord(b), now))
  if (members !== null) {
    // As a key file: a regular file (a symlink is not followed) that no one but its owner may read or write.
    const st = read('--members', members, () => lstatSync(members))
    if (!st.isFile() || (st.mode & 0o077) !== 0) {
      const what = st.isFile()
        ? `mode ${(st.mode & 0o777).toString(8).padStart(4, '0')}`
        : 'not a regular file'
      throw new PolicyFileError(
        'bad-mode',
        `--members ${members} is ${what}; it must be a 0600 file, as a key file is`,
      )
    }
    out.members = read('--members', members, (b) => verifyMembersRecord(parseMembersRecord(b), now))
  }
  if (out.org !== undefined && out.members !== undefined && out.org.key !== out.members.key) {
    throw new PolicyFileError(
      'bad-record',
      `--policy is signed by ${out.org.key}, --members by ${out.members.key}`,
    )
  }
  return out
}

/** The edge's policy with the org's records and the two moderation modules the edge ships (allow-all, keyword). */
export function withRecords(policy: PolicyOptions, records: OrgRecords): PolicyOptions {
  if (records.org === undefined && records.members === undefined) return policy
  return { ...policy, ...records, moderators: [allowAll, keyword] }
}

export type HeldSend = ReturnType<EdgeStore['heldSendList']>[number]

/** What the tools tell the model of a send the gate holds. */
export const HELD_NOTE =
  'This send was held by the organisation policy before it was sealed: nothing was sent. A person releases or drops it through the bag CLI on a terminal; no tool of this server can, and sending it again will not.'

/** A held send as the tools answer it: `held <id> <rule>`, its metadata and the note; never its body. */
export function heldOf(h: HeldSend): Record<string, unknown> {
  const input = JSON.parse(h.input) as SendInput
  return {
    held: `held ${h.id} ${h.rule}`,
    id: h.id,
    rule: h.rule,
    to: input.to,
    type: input.type,
    note: HELD_NOTE,
  }
}

/** What a send through the tools comes to: sent, waiting for its recipient to resolve, or held by the gate. */
export type Outcome = SendResult | WaitingSend | Held

export interface Outbound {
  readonly edge: Edge
  readonly store: EdgeStore
  readonly clock: Clock
  readonly rng: Rng
  readonly records: OrgRecords
  /** Under agent custody, the agent's register (agent.ts): each thread is registered before a send on it. */
  readonly register?: (thread: string) => Promise<void>
}

/**
 * Sends through the edge: Edge.sendOrWait (or Edge.send when `wait` is false), which with a members record go through
 * the edge's outbound gate: a denied recipient is refused (PolicyRefusal, nothing sealed) and a send
 * a breaker trips is held. A send the gate passes may still wait for its recipient, as without a gate.
 */
export async function sendThrough(o: Outbound, input: SendInput, wait: boolean): Promise<Outcome> {
  let message = input
  if (o.register !== undefined) {
    const thread = input.thread ?? newThread(coreRng(o.rng))
    await o.register(thread.id)
    message = { ...input, thread }
  }
  const sent: Promise<Outcome> = wait ? o.edge.sendOrWait(message) : o.edge.send(message)
  return sent.catch((e: unknown) => {
    if (e instanceof SendHeld) return e.held
    throw e
  })
}

/**
 * The policy's view for inbox, with a members record only: the quarantined rows (`seq`, `id`, `from`, `root`, the
 * `rule`) and the sends held pending a person (`id`, `to`, `rule`); metadata only, never a body.
 */
export function policyView(o: Outbound): Record<string, unknown> {
  if (o.records.members === undefined) return {}
  const quarantined = o.edge.receiver.quarantined().map(({ row, hold }) => {
    const env = parseEnvelope(row.bytes)
    return { seq: row.seq, id: env.id, from: env.from, root: env.auth[0]?.iss ?? env.from, rule: hold.rule }
  })
  const held = o.store
    .heldSendList('pending-approval')
    .map((h) => ({ id: h.id, to: (JSON.parse(h.input) as SendInput).to, rule: h.rule }))
  return { quarantined, held }
}
