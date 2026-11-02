import { createPrivateKey, type KeyObject, sign } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  AcError,
  type AcRecord,
  type AddressRecord,
  codingEvaluator,
  groupEvaluator,
  type Hop,
  hpkeOpen,
  parseRecord,
  type RecordKind,
  recordSigner,
  sealingKeyFromSeed,
  serializeRecord,
  signingKeyFromSeed,
  verifyRecord,
} from '@usebag/core'
import {
  continueFrom,
  type EdgeKeys,
  epochOpener,
  FsAuditSink,
  INCOMPLETE_REVOCATION,
  keepAddressCopy,
  type RelayClient,
} from '@usebag/edge'
import {
  Agent,
  AgentAudit,
  AgentClient,
  AgentServer,
  type LogoutOutcome,
  type PrincipalKeys,
  WINDOW_MAX,
} from '@usebag/edge/agent'
import { CliError, int, list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { readChain } from '../chain.ts'
import { epochDue, healed, rotateEpoch, staleLine } from '../epochs.ts'
import { changeover, epochStore, homeCustody, homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { instant, NameBook } from '../names.ts'
import { groupStore } from './group.ts'

// ac login, and what ac grant and ac logout share with it: the agent of a home
// listens on <home>/agent.sock; an agent identity is a pointer, <home>/agent/<name>.json, of public data only.

const S = { type: 'string' } as const
/** The DER prefix of an Ed25519 private key in PKCS#8 (RFC 8410), before its 32-byte seed. */
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex')

/** The address of the agent identity `name`; usage for an identity in another custody. */
export function agentAddress(io: Io, home: string, name: string): string {
  const e = homeCustody(io, home).entry(name)
  if (e.custody !== 'agent') throw new UsageError(`${name} is a ${e.custody} identity, not an agent identity`)
  return e.address
}

/**
 * Runs `f` on a plain client of the home's agent, for the agent identity `name`, and closes it; agent-locked when no
 * agent answers (no socket, or a stale one: the client's socket closes with no reply).
 */
export async function withAgent<T>(
  io: Io,
  home: string,
  name: string,
  f: (client: AgentClient, address: string) => Promise<T>,
): Promise<T> {
  const address = agentAddress(io, home, name)
  const path = join(home, 'agent.sock')
  const client = new AgentClient(path)
  try {
    return await f(client, address)
  } catch (e) {
    const gone = ['ENOENT', 'ECONNREFUSED'].includes(String((e as { code?: unknown }).code))
    if (!gone && (e as Error).message !== 'agent: the socket closed') throw e
    throw new CliError('agent-locked', `no agent listens at ${path}: run ac login`)
  } finally {
    client.close()
  }
}

/**
 * Publishes a logout's re-signed address record at the relays it names, one line each. When a relay did not take it,
 * or it names none, the record is kept in <home>/logout-record-<iat>.json (0600, a new file each time, never one
 * overwritten) with the line that publishes it again, and
 * the subjects it revokes are printed; 1 then (no-relays thrown for none).
 */
export async function publishAddress(
  io: Io,
  client: RelayClient,
  home: string,
  name: string,
  r: AddressRecord,
): Promise<number> {
  keepAddressCopy(home, name, r) // first: a revocation must outlive a relay that did not take it, and a lapse
  const failed: string[] = []
  for (const url of r.relays) {
    try {
      await client.publish(url, serializeRecord(r))
      io.out(`published address ${r.key} iat ${r.iat} ${url}`)
    } catch (e) {
      const code = String((e as { code?: unknown }).code ?? 'error')
      io.out(`failed address ${r.key} iat ${r.iat} ${url} ${code}`)
      if (r.revoked.length > 0)
        io.out(`incomplete revocation ${r.key} ${url} ${code}: ${INCOMPLETE_REVOCATION}`)
      failed.push(url)
    }
  }
  if (r.relays.length > 0 && failed.length === 0) return 0
  const file = join(home, `logout-record-${r.iat}.json`)
  writeFileSync(file, serializeRecord(r), { mode: 0o600, flag: 'wx' })
  io.err(`bag: the logout record is kept in ${file}; it revokes ${r.revoked.join(' ')}`)
  for (const url of failed) io.err(`bag: publish it again: ac publish ${url} ${file}`)
  if (failed.length === 0) throw new CliError('no-relays', `the address record of ${r.key} names no relay`)
  return 1
}

/**
 * The principal's keys, from the key file or keychain identity of its address (the agent pointer holds no seed), over
 * two seed buffers of login's own, and `zero`, which overwrites both and drops the signing key object; with the
 * identity's name and `edgeKeys`, the same keys as the edge's classes for an epoch rotation at login, made from
 * the buffers and valid only until `zero`.
 */
export function principalKeys(
  io: Io,
  home: string,
  address: string,
): { keys: PrincipalKeys; zero: () => void; name: string; edgeKeys: () => EdgeKeys } {
  const c = homeCustody(io, home)
  const holder = [c.files, c.keychain].find((k) => k.list().some((e) => e.address === address))
  if (holder === undefined) throw new CliError('ENOENT', `no key file or keychain identity holds ${address}`)
  const [seed, sealing] = [holder.signer(address).exportSeed(), holder.opener(address).exportSeed()]
  const der = Buffer.concat([PKCS8, seed])
  let key: KeyObject | null = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  der.fill(0)
  const signing = { address, sign: (m: Uint8Array) => new Uint8Array(sign(null, m, key as KeyObject)) }
  // Forward secrecy: P's mail is opened with P's held epoch keys when it has any, and with the long-term key
  // last while none or epoch 1 is held (the changeover), the store read at each open: the window's own rotation at
  // login comes after these keys are made.
  const epochs = epochStore(home)
  const longTerm = hpkeOpen.bind(null, sealing)
  const opener = {
    open: (enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array => {
      if (epochs.epochs(address).length === 0) return longTerm(enc, info, aad, ct)
      try {
        return epochOpener(epochs, address).open(enc, info, aad, ct)
      } catch (e) {
        if (!changeover(epochs, address)) throw e
        return longTerm(enc, info, aad, ct)
      }
    },
  }
  const keys = { signing, sealing: opener }
  return {
    keys,
    name: (holder.list().find((e) => e.address === address) as { name: string }).name,
    edgeKeys: () => ({ signing: signingKeyFromSeed(seed), sealing: sealingKeyFromSeed(sealing) }),
    zero: () => {
      seed.fill(0)
      sealing.fill(0)
      key = null
    },
  }
}

/**
 * Fills `held` with the newest address and accept-from records of `address`, signed by it, at every relay named and
 * then at every relay the newest address record names, until none is left unasked, so one relay rolled back cannot
 * hide a newer record. A failed fetch, or a record that does not verify or is another key's, refuses; a relay that
 * holds no address record is reported.
 */
async function heldRecords(
  io: Io,
  client: RelayClient,
  relays: readonly string[],
  address: string,
  held: Map<RecordKind, AcRecord>,
  home: string,
  name: string,
): Promise<void> {
  const asked = new Set<string>()
  for (let url: string | undefined = relays[0]; url !== undefined; ) {
    asked.add(url)
    for (const kind of ['address', 'accept-from'] as const) {
      const bytes = await client.fetchRecord(url, address, kind)
      if (bytes === null && kind === 'address') io.err(`login: ${url} holds no address record of ${address}`)
      if (bytes === null) continue
      const parsed = parseRecord(bytes)
      const r = verifyRecord(parsed, parsed.iat)
      if (r.kind !== kind || recordSigner(r) !== address) {
        throw new AcError('bad-record', `${url} answered another record for the ${kind} record of ${address}`)
      }
      if ((held.get(kind)?.iat ?? -1) < r.iat) held.set(kind, r)
    }
    const newest = held.get('address')
    url = [...relays, ...(newest?.kind === 'address' ? newest.relays : [])].find((u) => !asked.has(u))
  }
  // Swept by a lapse, or a relay's replay: the copy in the home goes on, with its rotation key and revoked list.
  const found = held.get('address')
  const copy = continueFrom(found?.kind === 'address' ? found : null, home, name, address)
  if (copy !== null && copy !== found) {
    held.set('address', copy)
    healed(io, home, copy)
  }
  const a = held.get('address')
  if (a?.kind !== 'address') throw new AcError('not-found', `no address record of ${address} at the relays`)
  if (a.rotated_from !== null) throw new CliError('rotation', 'logout re-signs no rotation record')
}

/** The file of the hop exps a principal's agent saw in this home, by subject: what dates its own `revoked` entries. */
export const datedFile = (home: string, principal: string): string =>
  join(home, `agent-revoked-exp.${principal}.json`)

/**
 * Takes the dated subjects from `file` and removes it, so a window that never writes it back leaves no file and the
 * next window keeps every entry undated. Missing, malformed, a value not an integer, or not removed: none.
 */
function takeDated(file: string): Map<string, number> {
  try {
    const text = readFileSync(file, 'utf8')
    unlinkSync(file)
    const all = Object.entries(JSON.parse(text) as object)
    return all.every((e) => Number.isSafeInteger(e[1])) ? new Map(all as [string, number][]) : new Map()
  } catch {
    return new Map()
  }
}

/** Writes them for the next window: a fresh 0600 temp file (`wx`) renamed over the file; a failure is only reported. */
function writeDated(io: Io, file: string, dated: Map<string, number>): void {
  try {
    rmSync(`${file}.tmp`, { force: true })
    writeFileSync(`${file}.tmp`, JSON.stringify(Object.fromEntries(dated)), { mode: 0o600, flag: 'wx' })
    renameSync(`${file}.tmp`, file)
  } catch (e) {
    io.err(`bag: ${file} not written (${(e as Error).message}); the next window dates nothing`)
  }
}

/** A manual revoke (`record address --revoke`) makes its subjects undated, so they are kept until a person drops them. */
export function undate(io: Io, home: string, address: string, subjects: readonly string[]): void {
  const file = datedFile(home, address)
  if (subjects.length === 0 || !existsSync(file)) return
  const dated = takeDated(file)
  for (const s of subjects) dated.delete(s)
  writeDated(io, file, dated)
}

/** A device's end: each session subject still live and until when, and the one step that cuts them, on P's side. */
export function unrevoked(io: Io, held: string, subjects: LogoutOutcome['unrevoked'] = []): boolean {
  for (const u of subjects) io.out(`unrevoked ${u.sub} until ${instant(u.until)}`)
  const step = `on the principal's machine, after its ac logout: ac record address <name> --relay <url> --revoke ${held}`
  if (subjects.length > 0) io.err(`bag: to end them now, ${step}`)
  return subjects.length > 0
}

/** The hop P -> D of `login --device`: one hop to the held key, from a principal the name book holds (ac peer). */
function deviceHop(home: string, file: string, held: string): Hop {
  const [hop, ...more] = readChain(file)
  if (hop?.sub !== held || more.length > 0 || NameBook.load(home).display(hop.iss)?.former !== false) {
    throw new CliError('not-authorized', `${file}: no one hop to ${held} from a principal in the name book`)
  }
  return hop
}

/**
 * login --as <name> --relay <url>... [--window <seconds>] [--dir <home>]: opens a window, at most 8 hours (the
 * default), in which the agent holds the principal's keys and answers sessions on <home>/agent.sock. It runs in the
 * foreground on a terminal (no-tty otherwise): each first grant (ac grant) is printed on stderr with a short code and
 * signed only when the next line typed is exactly `y`. The window ends at ac logout, SIGINT, SIGHUP or SIGTERM, or its
 * end; the address record re-signed with the grants' subjects revoked is published at the relays it names, by ac
 * logout or, at a signal, here (at the window's end the agent revokes nothing: its grants have expired). The groups the
 * principal's identities hold are replayed into the window. login --as <name> --device <file> on a device: <name>
 * holds D, the window answers for the hop's issuer P, ends by the hop's exp, signs only, and reads no record of P's.
 */
export async function login(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: [],
    options: { as: S, relay: { type: 'string', multiple: true }, window: S, dir: S, device: S },
    required: ['as'],
  })
  if (!p.values.relay && !p.values.device) throw new UsageError('--relay is required')
  const window = int(p, 'window') ?? WINDOW_MAX
  if (window > WINDOW_MAX) throw new UsageError(`--window is at most ${WINDOW_MAX} seconds (8 hours)`)
  if (!io.isTty) throw new CliError('no-tty', 'login asks for each first grant on its own terminal')
  const home = homeDir(io, str(p, 'dir'))
  const address = agentAddress(io, home, req(p, 'as'))
  const file = str(p, 'device')
  const device = file === undefined ? null : deviceHop(home, file, address)
  const mine = device === null ? homeCustody(io, home).list() : []
  const bodies = mine.flatMap((e) => (e.address === address ? groupStore(home, e.name).groups() : []))
  // A membership past its exp is not replayed: it would only take one of the window's GROUPS_MAX places.
  const live = bodies.filter((b) => b.hop !== null && b.hop.exp >= io.clock.now())
  const client = io.relay({})
  const records = new Map<RecordKind, AcRecord>()
  const { clock, rng } = io
  const audit = new AgentAudit(new FsAuditSink(join(home, 'agent-audit.jsonl')), clock)
  const evaluators = [codingEvaluator, groupEvaluator]
  const agent = new Agent({ principal: device?.iss ?? address, clock, rng, audit, evaluators, device })
  let settled = Promise.resolve(0)
  const ended = ({ record, error, unrevoked: left }: LogoutOutcome): void => {
    unrevoked(io, address, left)
    if (error !== null) io.err(`bag: bad-record: ${error.message}`)
    const status = Promise.resolve(error === null ? 0 : 1)
    const publish = record === null ? status : publishAddress(io, client, home, req(p, 'as'), record)
    settled = publish.finally(() => server.close())
  }
  const terminal = { print: (line: string) => io.err(line), ask: async () => (await io.readLine()) ?? '' }
  let zero = (): void => {}
  const dated = datedFile(home, address)
  const expiry = new Map<string, number>()
  const server = new AgentServer({ agent, clock, home, terminal, records, ended, expiry, zero: () => zero() })
  // The socket answers before the records are read, so a publish of this principal's address record from this home is
  // refused window-open (checkNoWindow) from here on; every failure after it zeroes the keys and closes the socket.
  await server.listen()
  const closed = once(server.listener, 'close')
  try {
    const relays = [...new Set(list(p, 'relay').map(relayUrl))]
    if (device === null) await heldRecords(io, client, relays, address, records, home, req(p, 'as'))
    const held = principalKeys(io, home, address)
    zero = held.zero
    for (const [s, exp] of takeDated(dated)) expiry.set(s, exp)
    const end = server.login(held.keys, window)
    const of = device === null ? '' : ` for ${device.iss}`
    io.out(`login ${address}${of} until ${instant(end)} on ${server.path}`)
    // A new epoch at login once the newest is 12 hours old (or none is held). A failure is
    // a line, never a refusal: the window opens mail with the epochs held, and ac keys rotate publishes the next one.
    // Past its life the record needs its re-signing too, which a rotation does: a swept record comes back here.
    const a = records.get('address')
    const now = io.clock.now()
    if (a?.kind === 'address' && (epochDue(home, address, now) || now > a.iat + a.ttl)) {
      try {
        const r = await rotateEpoch(io, {
          home,
          name: held.name,
          keys: held.edgeKeys(),
          relays: a.relays,
          held: a,
        })
        records.set('address', r.address)
      } catch (e) {
        io.err(
          `login: no new epoch: ${(e as Error).message}; senders get resolve-failed once the newest key record lapses (ac keys rotate ${held.name} --relay <url> publishes one)`,
        )
      }
    }
    // A rotation made the second copy stale; a line at every login until a new copy is confirmed, not a refusal.
    staleLine(io, home, address, 'login')
    for (const body of live) {
      const r = agent.takeGroupKey({ body })
      if (!r.ok) io.err(`login: group ${body.group} generation ${body.generation} not held: ${r.code}`)
    }
  } catch (e) {
    zero()
    await server.close()
    throw e
  }
  await closed
  writeDated(io, dated, expiry)
  io.release()
  const status = await settled
  io.out(`logout ${address}`)
  return status
}
