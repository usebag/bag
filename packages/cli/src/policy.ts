import { lstatSync, readFileSync } from 'node:fs'
import {
  type MembersRecord,
  type PolicyRecord,
  parseEnvelope,
  parseMembersRecord,
  parsePolicyRecord,
  verifyMembersRecord,
  verifyPolicyRecord,
} from '@usebag/core'
import { allowAll, type Gate, keyword, type PolicyOptions, type Receiver } from '@usebag/edge'
import { CliError } from './args.ts'
import type { Io } from './io.ts'
import type { NameBook } from './names.ts'

// The org's two policy records: --policy <file>, the served record, and --members
// <file>, the members record, the org's own: 0600 like a key file, never served or printed. Each is read once, when
// the command starts, and verified at the io's clock: a changed file takes effect at the next start. The lines of the
// quarantine and of the held sends name metadata only, never a body.

/** A policy file the CLI refuses: unreadable, a members file not 0600, or a record that does not verify. Exits 2. */
export class PolicyFileError extends CliError {}

/** The records an edge takes: the served one, the members one, either, or neither. */
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
export function loadRecords(
  policy: string | undefined,
  members: string | undefined,
  now: number,
): OrgRecords {
  const out: { org?: PolicyRecord; members?: MembersRecord } = {}
  if (policy !== undefined)
    out.org = read('--policy', policy, (b) => verifyPolicyRecord(parsePolicyRecord(b), now))
  if (members !== undefined) {
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

export type Quarantined = ReturnType<Receiver['quarantined']>[number]
export type HeldSend = ReturnType<Gate['held']>[number]

/** A quarantined row's line: `<seq> <id> <from> <root> <rule>`, the addresses through the name book; no body. */
export function quarantinedLine({ row, hold }: Quarantined, book: NameBook): string {
  const env = parseEnvelope(row.bytes)
  return `${row.seq} ${env.id} ${book.label(env.from)} ${book.label(env.auth[0]?.iss ?? env.from)} ${hold.rule}`
}

/**
 * A held send's line: `<id> <rule> <type> <to,...>`; no body. The type shows as a short token or `(not shown)`, as
 * inbox's shownType shows it: a held send's type is local and not yet sealed, and this line prints before the person
 * confirms the release (held.ts), so it guards the same control-character class the decode rule refuses (SPEC §5.2).
 * The guard is inlined, not imported from commands/inbox.ts, because inbox.ts imports this module — a cycle otherwise.
 */
export function heldLine(held: HeldSend): string {
  const input = JSON.parse(held.input) as { to: string[]; type: string }
  const type = /^[\w.+*-]{1,64}$/.test(input.type) ? input.type : '(not shown)'
  return `${held.id} ${held.rule} ${type} ${input.to.join(',')}`
}

/** Refuses no-tty an act a person confirms on a terminal when stdin is not one. */
export function needTty(io: Io, what: string): void {
  if (!io.isTty)
    throw new CliError('no-tty', `${what} is a person's act, confirmed on a terminal; stdin is not one`)
}

/** Asks the person at the terminal; a refusal `declined` unless they answer yes. */
export async function confirmed(io: Io, prompt: string, unchanged: string): Promise<void> {
  if (!(await io.confirm(prompt))) throw new CliError('declined', unchanged)
}
