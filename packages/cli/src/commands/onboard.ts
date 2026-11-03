import { randomUUID } from 'node:crypto'
import { chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import {
  type AcceptFromRecord,
  type AddressRecord,
  checkAcceptRoot,
  domainOfRoot,
  handlePath,
  isAcError,
  isAddress,
  isHandle,
  MAX_ADDRESS_TTL,
  MAX_RELAYS,
  MAX_ROOTS,
  parseHandleRecord,
  parseRecord,
  type RecordKind,
  recordSigner,
  serializeHandleRecord,
  serializeRecord,
  signHandleRecord,
  signRecord,
  verifyHandleRecord,
  verifyRecord,
  WELL_KNOWN_RECORD_PATH,
  WILDCARD_ROOT,
} from '@usebag/core'
import { classifyAddress, continueFrom, domainRootRefusal, hostOf, RelayError } from '@usebag/edge'
import { CliError, flag, int, list, parse, relayUrl, req, str, UsageError } from '../args.ts'
import { currentKey, epochDue, laggingLines, rotateEpoch } from '../epochs.ts'
import { checkNoWindow, homeCustody, homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'
import { stableMains } from '../packaged.ts'
import { addTrust, readTrust } from '../trust.ts'
import { delegate } from './delegate.ts'
import { keygen } from './keygen.ts'
import { lookup } from './lookup.ts'
import { newest, newestAccept, record } from './record.ts'
import { publish } from './relay.ts'
import { failed } from './unpair.ts'

// onboard (the domain kit's second half): one command that puts an agent on its org's own domain, with no
// hand step but the owner's two (host the tree it writes; add the TXT record it prints). It calls the commands
// in-process (keygen, record, publish, delegate, lookup) and the trust file's helper; it never shells out. Every step
// is idempotent, so running it again with the same arguments is the daily refresh: the records live a day at most.
// A refresh keeps the accept-from roots held at the relays (a pairing's) beside the typed ones (acceptRoots).
// Under forward secrecy the agent's address record names no sealing key; its key record goes first.

/** A delegation chain's life without --chain-exp, 7 days, and its most, §6.1's 30 days. */
const CHAIN_EXP = 604_800
const MAX_CHAIN_EXP = 2_592_000
/** The accept-from record's largest envelope and retention by default, the values of cut/docs/partner-install.md. */
const MAX_BYTES = 65_536
const RETENTION = 604_800
/** The exit when everything is written and published but the handle does not resolve yet. */
const PENDING = 3
/**
 * How early a run may come and still publish a new epoch: the cron line and EPOCH_DUE are both
 * 12 hours, and a run that comes back seconds short of the newest epoch's 12 hours would skip it,
 * leaving the next one to the run after, when the key record is seconds from its exp or past it.
 */
const EARLY = 3600
/**
 * The command line of this CLI for the home `home`, for the commands onboard prints: absolute paths (cron's PATH has no
 * node in it), the package's stable copy when run from the package (packaged.ts).
 */
const acOf = (home: string): string => `${sh(process.execPath)} ${sh(stableMains(home).cli)}`

/**
 * onboard <name> --domain <host> --relay <url>... --accept <root>... (cli.ts's USAGE names every option): each
 * argument is checked before anything is written; then the keys, the tree a static host serves (<out>), the agent's
 * records at its relays, the trust file, the chain, the owner's two steps, a cron line and the self-check. --check
 * runs the self-check only. Exits 0 when the handle resolves end to end, PENDING when it does not yet.
 */
export async function onboard(args: readonly string[], io: Io): Promise<number> {
  const p = parse(args, {
    positionals: ['name'],
    options: {
      domain: { type: 'string' },
      relay: { type: 'string', multiple: true },
      accept: { type: 'string', multiple: true },
      handle: { type: 'string' },
      'org-key': { type: 'string' },
      out: { type: 'string' },
      origin: { type: 'string' },
      ttl: { type: 'string' },
      'chain-exp': { type: 'string' },
      'max-bytes': { type: 'string' },
      retention: { type: 'string' },
      check: { type: 'boolean' },
      'allow-private-relays': { type: 'boolean' },
      dir: { type: 'string' },
    },
    required: ['domain', 'relay', 'accept'],
  })
  const name = p.positionals[0] as string
  const domain = req(p, 'domain')
  const refusal = domainRootRefusal(domain)
  if (refusal !== null) throw new UsageError(`--domain: ${refusal}`)
  const handle = `${str(p, 'handle') ?? name}@${domain}`
  if (!isHandle(handle)) {
    throw new UsageError(
      `${JSON.stringify(handle)} is not a handle: a local part is 1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit`,
    )
  }
  const origin = str(p, 'origin') ?? 'apex'
  if (origin !== 'apex' && origin !== 'bag') {
    throw new UsageError(`--origin is apex or bag, not ${JSON.stringify(origin)}`)
  }
  const ttl = int(p, 'ttl') ?? MAX_ADDRESS_TTL
  if (ttl > MAX_ADDRESS_TTL) throw new UsageError(`--ttl is at most ${MAX_ADDRESS_TTL} seconds, not ${ttl}`)
  const chainExp = int(p, 'chain-exp') ?? CHAIN_EXP
  if (chainExp > MAX_CHAIN_EXP) {
    throw new UsageError(`--chain-exp is at most ${MAX_CHAIN_EXP} seconds, not ${chainExp}`)
  }
  const maxBytes = int(p, 'max-bytes')
  const retention = int(p, 'retention')
  const relays = [...new Set(list(p, 'relay').map(relayUrl))]
  if (relays.length > MAX_RELAYS) throw new UsageError(`--relay names more than ${MAX_RELAYS} relays`)
  const roots = [...new Set(list(p, 'accept').map(checkAcceptRoot))]
  if (roots.length > MAX_ROOTS) throw new UsageError(`--accept names more than ${MAX_ROOTS} roots`)
  if (roots.includes(WILDCARD_ROOT) && roots.length > 1) throw new UsageError('--accept * stands alone')
  const home = resolve(homeDir(io, str(p, 'dir')))
  const out = resolve(str(p, 'out') ?? join(home, 'serve', domain))
  const up = relative(out, home)
  if (up !== '..' && !up.startsWith(`..${sep}`) && !isAbsolute(up)) {
    throw new UsageError(`--out ${out} holds the home ${home}: its keys would be served`)
  }
  const orgKey = str(p, 'org-key') ?? `org-${domain}`
  if (orgKey.length > 64) {
    throw new UsageError(`the org key's name ${orgKey} is over 64 characters: give --org-key`)
  }
  if (orgKey === name) {
    throw new UsageError('--org-key names the agent itself: the org key is another identity')
  }
  // The custody checks each name (1 to 64 of [a-z0-9._-]) before anything is written.
  const custody = homeCustody(io, home)
  for (const n of [orgKey, name]) custody.holder(n)
  const relayArgs = relays.flatMap((r) => ['--relay', r])
  const guard = flag(p, 'allow-private-relays') ? ['--allow-private-relays'] : []
  const look = [...relayArgs, '--as', orgKey, '--dir', home, ...guard]
  if (flag(p, 'check')) return selfCheck(io, domain, handle, custody.entry(name).address, look)

  // The trust file's roots (typed --accept roots, pairing y's), read before any write: trust-invalid.
  const trusted = Object.keys(readTrust(home))
  const quiet: Io = { ...io, out: () => {} }
  const orgAddress = ensureKey(io, quiet, home, orgKey)
  const agent = ensureKey(io, quiet, home, name)
  await checkNoWindow(io, home, agent)
  const own = await ownRecords(io, relays, agent)
  const held = own.accept
  const accepted = acceptRoots(held, trusted, roots, agent)
  // A null here is an identity that never published from this home; one that lost its copy is no-held-record.
  const continued = continueFrom(own.address, home, name, agent)
  // Past the refusals that come before any write, so a warned relay is one a record names; --check writes
  // no record, and --allow-private-relays means the person knows.
  if (!flag(p, 'allow-private-relays')) for (const url of relays) warnPrivate(io, url)
  const orgFile = join(out, WELL_KNOWN_RECORD_PATH)
  const handleFile = join(out, handlePath(handle))
  // out (when made here) and the directories below it are 0755 whatever the umask, so a host can read the tree.
  if (mkdirSync(out, { recursive: true }) !== undefined) chmodSync(out, 0o755)
  for (const d of [join(out, '.well-known'), dirname(orgFile), dirname(handleFile)]) {
    if (!present(d, true)) {
      mkdirSync(d)
      chmodSync(d, 0o755)
    }
  }
  const served = present(orgFile, false) ? servedRecord(orgFile, orgKey, orgAddress) : null
  const bound = present(handleFile, false) ? boundTo(handleFile) : null
  const ttlArgs = ['--ttl', `${ttl}`, '--dir', home]
  const tmp = (f: string): string => join(dirname(f), `.${basename(f)}.${randomUUID()}.tmp`)
  const [orgTmp, handleTmp] = [tmp(orgFile), tmp(handleFile)]
  try {
    const org = ['address', orgKey, ...relayArgs, '--sealing-key', ...carry(served), ...ttlArgs]
    await record([...org, '--out', orgTmp], quiet)
    const now = io.clock.now()
    const signed = verifyRecord(parseRecord(readFileSync(orgTmp)), now) as AddressRecord
    const unsigned = { kind: 'handle', org: orgAddress, handle, address: agent, iat: now, ttl } as const
    const bytes = serializeHandleRecord(signHandleRecord(loadKeys(io, home, orgKey).signing, unsigned))
    verifyHandleRecord(parseHandleRecord(bytes), { org: signed.key, handle, revoked: signed.revoked }, now)
    writeFileSync(handleTmp, `${new TextDecoder().decode(bytes)}\n`, { flag: 'wx' })
    place(io, orgTmp, orgFile)
    place(io, handleTmp, handleFile)
    if (bound !== null && bound !== agent) io.out(`replaced ${bound}`)
  } finally {
    for (const t of [orgTmp, handleTmp]) rmSync(t, { force: true })
  }

  const records = join(home, 'records')
  mkdirSync(records, { recursive: true, mode: 0o700 })
  const file = (kind: string): string => join(records, `${name}.${kind}.json`)
  // Signed here, not by record address, whose --revoke would undate a logout's revocations (login.ts, undate): the
  // rotation key and revoked list of the agent's newest record at its relays are kept as they are; with none
  // there (lapsed and swept), those of the record last written here (lastAddress).
  // No sealing key: senders seal to the key record, published below before it. Its iat is past the
  // held one's, as record keep dates a re-sign, so a run again within the same second is still newer.
  const keys = loadKeys(io, home, name)
  const mine = signRecord(keys.signing, {
    kind: 'address',
    key: agent,
    sealing_key: null,
    relays,
    rotation_key: continued?.rotation_key ?? null,
    revoked: continued?.revoked ?? [],
    ttl,
    iat: Math.max(io.clock.now(), (continued?.iat ?? 0) + 1),
    rotated_from: null,
  })
  writeFileSync(file('address'), `${new TextDecoder().decode(serializeRecord(mine))}\n`)
  // The held record's max_bytes and retention are kept when no flag names them, as peer's admit keeps them.
  const size = maxBytes ?? held?.max_bytes ?? MAX_BYTES
  const keep = retention ?? held?.ttl ?? RETENTION
  const rootArgs = accepted.flatMap((r) => ['--root', r])
  const acceptArgs = ['--max-bytes', `${size}`, '--ttl', `${keep}`, '--dir', home]
  await record(['accept-from', name, ...rootArgs, ...acceptArgs, '--out', file('accept-from')], quiet)
  for (const root of accepted.filter((r) => !roots.includes(r))) io.out(`kept ${root}`)
  // cron runs in $HOME, where a relative --out or --dir names other paths: both go in again as absolute paths.
  const named = (a = ''): boolean => /^--(out|dir)$/.test(a)
  const given = args.filter((a, i) => !named(a) && !named(args[i - 1]) && !/^--(out|dir)=/.test(a))
  const AC = acOf(home)
  const again = `${AC} onboard ${[...given, '--out', out, '--dir', home].map(sh).join(' ')}`
  const missed = new Map<RecordKind, unknown[]>()
  const put = async (kind: RecordKind, url: string, send: () => Promise<unknown>): Promise<void> => {
    try {
      await send()
      io.out(`published ${kind} ${agent} ${url}`)
    } catch (e) {
      if (!(e instanceof RelayError)) throw e
      // A relay keeps the record it holds when this one is not newer: the key record as published,
      // or an accept-from signed in the same second.
      if (e.code === 'stale-record') return void io.out(`unchanged ${kind} ${agent} ${url}`)
      // One relay that does not take it stops nothing: `record keep` offers it again (spec/SPEC.md Appendix B 110).
      const revokes = kind === 'address' && mine.revoked.length > 0
      laggingLines(io, agent, [{ relay: url, kind, code: failed(e), revokes }])
      missed.set(kind, [...(missed.get(kind) ?? []), e])
    }
  }
  // The key record first: a new epoch when one is due within EARLY, or the newest again, re-dated,
  // when its publish failed (KeyRecordAdmin through rotateEpoch, which prints `published key`; `mine`,
  // already null-sealing, is kept as it is), else the newest epoch's record as published.
  if (epochDue(home, agent, io.clock.now() + EARLY)) {
    await rotateEpoch(io, { home, name, keys, relays, held: mine, step: () => again })
  } else {
    const key = serializeRecord(await currentKey(io, home, name, keys, relays[0] as string))
    for (const url of relays) await put('key', url, () => io.relay({}).publish(url, key))
  }
  for (const url of relays) {
    for (const kind of ['address', 'accept-from'] as const) {
      await put(kind, url, () => publish([url, file(kind), '--dir', home], quiet))
    }
  }
  for (const errors of missed.values()) if (errors.length === relays.length) throw errors[0]
  const now = io.clock.now()
  for (const root of roots.filter(isAddress)) {
    addTrust(home, root, now)
    io.out(`trust ${root}`)
  }
  for (const root of roots.filter((r) => domainOfRoot(r) !== null)) trustDomain(io, home, root, now)
  const chain = join(home, `${name}.chain.json`)
  delegate(['--from', orgKey, '--to', agent, '--exp', `+${chainExp}`, '--out', chain, '--dir', home], quiet)
  io.out(`chain ${chain} root ${orgAddress} exp ${now + chainExp}`)

  const host = origin === 'apex' ? domain : `bag.${domain}`
  const hostField = origin === 'apex' ? '' : '; host=bag'
  const txt = `_bag.${domain}.  IN  TXT  "v=ac1; key=${orgAddress}${hostField}"`
  io.out(
    `step 1: serve ${out} as the root of https://${host}/ (HTTPS on port 443; each file a 200 with no redirect, as application/json), so that these answer:`,
  )
  for (const path of [WELL_KNOWN_RECORD_PATH, handlePath(handle)]) io.out(`url https://${host}${path}`)
  io.out(`step 2: add this TXT record to the DNS of ${domain}:`)
  io.out(`dns ${txt}`)
  const relay = sh(relays[0] as string)
  const half = Math.max(1, Math.floor(ttl / 2))
  const every =
    half >= 3600 ? `0 */${Math.floor(half / 3600)} * * *` : `*/${Math.max(1, Math.floor(half / 60))} * * * *`
  io.out(
    `next an inviter accepts ${handle} by root domain:${domain} (send with --auth ${chain}) or by ${agent} (send without it)`,
  )
  io.out(
    `next ${AC} send --as ${name} --auth ${sh(chain)} --to <handle|address> --relay ${relay} --type <type> --body <json> --dir ${sh(home)}`,
  )
  const inbox = [AC, 'inbox', '--as', name, '--relay', relay, '--dir', sh(home)]
  io.out(`next ${inbox.join(' ')}`)
  io.out(`next run this command again every ${half} s at most (records live ${ttl} s); nothing installs it:`)
  io.out(`cron ${every} ${again}`)
  return selfCheck(io, domain, handle, agent, look)
}

/**
 * Stores a typed `--accept domain:<host>` in the trust file (addTrust, as peer --trust-domain does), so that
 * inbox and the MCP server trust the domain with no --trust-root; prints `trust domain:<host>`. Idempotent:
 * an entry the file has stays. No y: the typed --accept counts as the
 * person's act that names the root; no root is written from a message, a resolved record or a default.
 */
function trustDomain(io: Io, home: string, root: string, now: number): void {
  addTrust(home, root, now)
  io.out(`trust ${root}`)
}

/**
 * Warns on stderr (never refuses) when the relay `url`, about to go into a published record, has a private
 * host the edge's guard would refuse: an IP literal the guard's classifyAddress puts outside `public`, or a
 * `localhost` name (the guard's RFC 6761 rule). No DNS: a name that resolves to a private address is not
 * warned.
 */
function warnPrivate(io: Io, url: string): void {
  const host = hostOf(url)
  const named = host === 'localhost' || host.endsWith('.localhost') ? 'loopback' : null
  const kind = classifyAddress(host) ?? named
  if (kind === null || kind === 'public') return
  const refuse = "peers' edges refuse to deliver there unless they pass --allow-private-relays"
  io.err(`bag: warning: relay ${url} is a private address (${kind}); ${refuse}`)
}

/** The identity's address, made by keygen when the home lacks it; prints `key <name> <address> new|existing`. */
function ensureKey(io: Io, quiet: Io, home: string, name: string): string {
  const custody = homeCustody(io, home)
  const held = custody.list().find((e) => e.name === name)
  if (held === undefined) keygen([name, '--dir', home], quiet)
  const address = held?.address ?? custody.entry(name).address
  io.out(`key ${name} ${address} ${held === undefined ? 'new' : 'existing'}`)
  return address
}

/** The agent's newest records at its relays: either may be null. */
interface Own {
  readonly address: AddressRecord | null
  readonly accept: AcceptFromRecord | null
}

/**
 * The agent's newest address record at its relays and its newest accept-from record, each checked by the core
 * as record keep's `newest` checks them (rotation for an address record that names rotated_from).
 */
async function ownRecords(io: Io, relays: readonly string[], agent: string): Promise<Own> {
  const client = io.relay({})
  try {
    return await newest(client, relays, agent, null)
  } catch (e) {
    if (!isAcError(e, 'not-found')) throw e
    // No address record: a first run, or one lapsed and swept (a relay sweeps address records, never an
    // accept-from: crates/ac-relay/src/store.rs, expiry_of); the accept-from is read all the same.
    return { address: null, accept: await newestAccept(client, relays, agent) }
  }
}

/**
 * The roots of the accept-from record onboard publishes (decided 2026-10-28), in
 * this order, deduplicated: those of the agent's newest one at its relays (`held`, which a pairing extends,
 * as peer's admit appends a root: packages/edge/src/pairing.ts), then the trust file's in its file order
 * (typed --accept roots and pairing y's, so a peer paired under a held `*` comes back), then the typed
 * --accept roots. A held `*` is not kept: it stands alone (the core's rule), and a pairing adds nothing to
 * it. A typed `*` is published alone (it admits every trusted root, which a later narrowing brings back
 * from the trust file), but beside held roots it is accept-held, so none is dropped unseen; over MAX_ROOTS
 * in all is too-many-roots.
 */
function acceptRoots(
  held: AcceptFromRecord | null,
  trusted: readonly string[],
  typed: readonly string[],
  agent: string,
): string[] {
  const kept = (held?.roots ?? []).filter((r) => r !== WILDCARD_ROOT)
  if (typed.includes(WILDCARD_ROOT)) {
    if (kept.length === 0) return [WILDCARD_ROOT]
    throw new CliError(
      'accept-held',
      `--accept * stands alone, and the accept-from of ${agent} at its relays holds ${kept.join(' ')}: ` +
        "to accept every sender, publish one of --root '*' by hand (record accept-from, then publish), " +
        'then run onboard again',
    )
  }
  const roots = [...new Set([...kept, ...trusted, ...typed])]
  if (roots.length > MAX_ROOTS) {
    throw new CliError(
      'too-many-roots',
      `the accept-from of ${agent} would hold ${roots.length} roots (${kept.length} held at its relays, ` +
        `${trusted.length} in the trust file, then the typed --accept ones); the cap is ${MAX_ROOTS}`,
    )
  }
  return roots
}

/** Whether `path` exists as a directory (`dir`) or a regular file; unsafe-path for a link or anything else there. */
function present(path: string, dir: boolean): boolean {
  const st = lstatSync(path, { throwIfNoEntry: false })
  if (st === undefined) return false
  if (dir ? st.isDirectory() : st.isFile()) return true
  throw new CliError('unsafe-path', `${path} is a link or not a ${dir ? 'directory' : 'regular file'}`)
}

/**
 * The org's address record served now at `file`, checked by the core as record keep checks one (form and signature,
 * at its own iat); org-key-mismatch when it is not one of the org key's, rotation when it names rotated_from.
 */
function servedRecord(file: string, orgKey: string, address: string): AddressRecord {
  const parsed = parseRecord(readFileSync(file))
  const r = verifyRecord(parsed, parsed.iat)
  if (r.kind !== 'address' || r.key !== address) {
    throw new CliError(
      'org-key-mismatch',
      `${file} is a record of ${recordSigner(r)}, not of ${orgKey} (${address}): move it, or give the --org-key that signed it`,
    )
  }
  if (r.rotated_from === null) return r
  throw new CliError(
    'rotation',
    `${file} names rotated_from ${r.rotated_from}, whose countersignature covers its iat: once peers have moved their pins, replace it with a record without it (record address ${orgKey} --relay <url>... --sealing-key --out ${file}), then run onboard again`,
  )
}

/** The address the handle record at `file` binds, or null when the core cannot parse it. */
function boundTo(file: string): string | null {
  try {
    return parseHandleRecord(readFileSync(file)).address
  } catch {
    return null
  }
}

/** The arguments that keep a record's rotation key and revoked list when it is signed again (as record keep does). */
function carry(r: AddressRecord | null): string[] {
  if (r === null) return []
  const rotation = r.rotation_key === null ? [] : ['--rotation-key', r.rotation_key]
  return [...rotation, ...r.revoked.flatMap((a) => ['--revoke', a])]
}

/** Puts the file `tmp` at `file` by one rename in its directory, mode 0644: a reader sees the old file or the new. */
function place(io: Io, tmp: string, file: string): void {
  chmodSync(tmp, 0o644)
  renameSync(tmp, file)
  io.out(`wrote ${file}`)
}

/** A word for a POSIX shell: as it is when it needs no quotes, else in single quotes. */
function sh(word: string): string {
  return /^[\w@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`
}

/**
 * The self-check: lookup of domain:<domain>, then of the handle, as a peer's edge resolves them (the edge's Resolver,
 * through the io's record source), each line printed after `check `. 0 when the handle record is found naming `agent`
 * and after it the agent's address record and key record at a relay (so the TXT record, when there is
 * one, and the org record agreed, and a peer has a key to seal to: the address record names none);
 * else PENDING, naming the missing key record when only it is missing.
 */
async function selfCheck(
  io: Io,
  domain: string,
  handle: string,
  agent: string,
  look: readonly string[],
): Promise<number> {
  const lines: string[] = []
  const seen: Io = {
    ...io,
    out: (line) => {
      lines.push(line)
      io.out(`check ${line}`)
    },
  }
  await lookup([`domain:${domain}`, ...look], seen)
  const from = lines.length
  await lookup([handle, ...look], seen)
  // lookup's printed lines are read back: a line of another form matches nothing, so a change there fails safe.
  const named = (l: string): boolean => / found kind=handle /.test(l) && l.endsWith(` address ${agent}`)
  const at = lines.findIndex((l, i) => i >= from && named(l))
  const found = (kind: string): boolean => lines.slice(at + 1).some((l) => l.includes(` found kind=${kind} `))
  if (at !== -1 && found('address') && found('key')) {
    io.out(`self-check ok ${handle}`)
    return 0
  }
  if (at !== -1 && found('address')) {
    io.out(`self-check pending ${handle}: no key record at the relays; run onboard again, without --check`)
    return PENDING
  }
  io.out(`self-check pending ${handle}: not resolving yet; do steps 1 and 2, then run again with --check`)
  return PENDING
}
