import { performance } from 'node:perf_hooks'
import { isAcError } from '@usebag/core'
import { countDuration, countTelemetry, RelayError, startTelemetry, stopTelemetry } from '@usebag/edge'
import { CliError, UsageError } from './args.ts'
import { address } from './commands/address.ts'
import { audit } from './commands/audit.ts'
import { delegate } from './commands/delegate.ts'
import { grant } from './commands/grant.ts'
import { group } from './commands/group.ts'
import { held } from './commands/held.ts'
import { hostInstall } from './commands/host-install.ts'
import { inbox } from './commands/inbox.ts'
import { init, restore } from './commands/init.ts'
import { keygen } from './commands/keygen.ts'
import { keys } from './commands/keys.ts'
import { login } from './commands/login.ts'
import { logout } from './commands/logout.ts'
import { lookup } from './commands/lookup.ts'
import { name } from './commands/name.ts'
import { onboard } from './commands/onboard.ts'
import { peer } from './commands/peer.ts'
import { record } from './commands/record.ts'
import { health, publish } from './commands/relay.ts'
import { resend } from './commands/resend.ts'
import { send } from './commands/send.ts'
import { status } from './commands/status.ts'
import { notice, telemetry, verbOf } from './commands/telemetry.ts'
import { unpair } from './commands/unpair.ts'
import { sessionCode, wakeHook } from './commands/wake-hook.ts'
import { watch } from './commands/watch.ts'
import type { Io } from './io.ts'
import { PolicyFileError } from './policy.ts'

// The command line: one command per run, its exit status 0, or 1 with "bag: <code>: <detail>" on stderr (2 for
// an org policy file that cannot be read or does not verify; 3 for onboard's records written but not resolving yet).
// No command prints key material: keygen, address and keys list print addresses, which are public by design.

export const USAGE = `bag: the bag v0 command line (pre-release)

usage: node packages/cli/src/main.ts <command> [options]

  keygen <name> [--custody file|keychain] [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]
      a signing key and a separate sealing key; prints the address only. --custody keychain keeps both in one item
      of a macOS keychain (the default keychain, or --keychain), which no application reads without a dialog
      (--keychain-access prompt, the default) or which /usr/bin/security reads while the keychain is unlocked
      (security, for a host no one watches); the default custody is a key file
  keygen <name> --custody agent --principal <identity> [--recovery personal|none] [--dir <home>]
      the agent identity <name>: a pointer of the public address and sealing key of the key file or keychain
      identity <identity>, no new key, and with --recovery its recovery setting; ac login <name> then holds it
  init <name> --relay <url> [--custody file|keychain] [--accept-loss | --reprint] [--dir <home>]
      a person's identity with its recovery sheet, printed once on a terminal: the three seeds, the relay and an
      8-character checksum typed back; only then are the keys stored and the address record published (else
      single-copy, nothing written). --accept-loss: no sheet, the exact phrase instead. --reprint: the held sheet
      again, its checksum typed back clears a stale copy
  restore <name> [--relay <url>] [--custody file|keychain] [--dir <home>]
      the identity back from its sheet, typed on a terminal with the echo off: refused on a bad checksum before any
      network call, on a record that revokes it, and stale on a record of other keys; asks before publishing when
      no relay holds a record
  address <name> [--dir <home>]
      prints the address of an identity
  keys list [--dir <home>]
      one line per identity, "<name> <address> <custody> <created>" (file, keychain or agent; an ISO 8601 UTC
      instant to the second, - when unknown), then "recovery=<setting>" for an agent pointer that has one, and
      "copy=<copy>" and "stale_since=<instant>" from a recovery state; never a key
  keys rotate <name> --relay <url>... [--accept-loss] [--dir <home>]
      publishes the identity's next epoch now (forward secrecy): a key record over a fresh sealing key, living a
      day, and the address record re-signed with no sealing key when it still names one, offered to every relay it
      lists: done once one holds each, "failed <kind> <address> <relay> <code>" for each that lags, which record keep
      carries; exit 3 when a record that carries a revoked list lags ("incomplete revocation ..."); login and record keep
      rotate on their own once the newest epoch is 12 hours old (record keep 11: run it at least every 11 hours).
      With no record at any relay the copy in the home goes on, rotation key and revoked list with it; an identity
      that published here and lost that copy is refused no-held-record unless --accept-loss says they are gone
  keys prune <name> [--dir <home>]
      replaces the identity's long-term sealing key by a fresh random seed that no record names, once epoch 1 is
      deleted; refused for an agent identity, an org, a group admin, an identity with no epoch, one that holds
      epoch 1 and one an ac login window holds
  login --as <name> --relay <url>... [--window <seconds>] [--dir <home>]
      opens a window, at most 8 hours (the default), in which the agent holds the principal <name>'s keys and
      answers sessions on <home>/agent.sock; runs on a terminal until logout, SIGINT, SIGHUP, SIGTERM or the
      window's end. Its address record is read at the relays named; logout re-signs it and publishes it. The
      groups the principal's identities hold are taken into the window (its sessions open at a group's mailbox)
  login --as <name> --device <file> [--window <seconds>] [--dir <home>]
      on a device: <name> holds the device key D; <file> is the hop P -> D of grant --device, from a principal in
      the name book. The window answers for P, ends by the hop's exp, signs only, opens nothing, reads no record
  grant --as <name> --session <address> --caveat <caveat>... --exp <unix seconds|+seconds> [--chain <file>] [--dir <home>]
      gives a session its first grant: the agent prints it on its terminal and signs only after one y there;
      --chain (on a device, the hop P -> D) is printed before it
  grant --as <name> --device <name|address> [--caveat <caveat>...] --exp <unix seconds|+seconds> [--dir <home>]
      the device hop P -> D, at most 30 days, for a key paired with ac peer, signed after one y at the agent;
      printed as a chain of one hop to carry to the device by hand
  logout --as <name> [--dir <home>]
      ends the window, drops every grant, and revokes the sessions' keys on the wire; on a device it signs nothing
      and prints "unrevoked <address> until <time>" per session, and the record address --revoke step for P
  peer invite --as <name> --relay <url> [--rendezvous <url>] --name <petname> [--for <address>] [--ttl <seconds>] [--allow-private-relays] [--dir <home>]
  peer accept --as <name> --relay <url> [--rendezvous <url>] --name <petname> [--for <address>] <code or invite> [--allow-private-relays] [--dir <home>]
      pairs two identities on two terminals: invite prints a one-use pairing code (or string), live 600 s at
      most; accept shows six check digits, which its person reads to the inviter before answering y; invite never shows them and takes them typed (3 tries). Each side then names the other,
      trusts it in <home>/trust.json (0600; inbox and the MCP server read it) and adds it to its accept-from record
  unpair <address|domain:<host>> --as <name> --relay <url>... [--dir <home>]
      the one way a root leaves: on a terminal, after one y, removes it from <home>/trust.json and from
      the newest accept-from of <name> (re-signed, max_bytes and ttl kept, published at each relay);
      refused accept-all under a held *, not-trusted when neither holds it. A root that onboard's cron
      line types in --accept comes back on its next run unless dropped there
  record address <name> --relay <url>... [--sealing-key] [--ttl <seconds>] [--rotated-from <name>] [--rotation-key <address>] [--revoke <address>...] [--out <file>] [--dir <home>]
      a signed address record (sealing key included with --sealing-key; ttl at most 86400, the default); with
      --rotated-from, a rotation from that identity's key, which countersigns it; --rotation-key names a separate
      key that may countersign this key's next rotation; --revoke names a key whose hops the record revokes (up
      to 1024): keep each entry until its hop's exp + TTL + skew (604800 + 300 s after the hop's exp with the
      relay defaults), the last second an envelope under that hop passes the stale-ts check; refused window-open
      while a login window of the home holds the identity (logout would overwrite the record)
  record accept-from <name> --root <address|domain:<host>|*>... --max-bytes <n> --ttl <seconds> [--out <file>] [--dir <home>]
      a signed accept-from record: the roots the mailbox accepts (a domain root accepts the domain's current key,
      which the relay resolves and pins), its largest envelope and its retention
  record keep --as <name> --relay <url>... [--every <seconds>] [--once] [--plist | --crontab] [--dir <home>]
  record keep --identities <file> (--once | --plist | --crontab)
      keeps the identity's records alive: at half the address record's ttl (or every <seconds>) signs its newest
      address record, and its accept-from record when it has one, again unchanged but for a newer iat, and offers
      both to every relay until each holds them, one line per republish, with the newest key record beside them;
      "incomplete revocation ..." when a record that carries a revoked list lags; runs until SIGINT or SIGTERM;
      --once republishes now.
      Beside a live MCP server that keeps its records alive it stands aside: held session-open <address>, exit 0.
      --identities runs --once for every identity of the file. --plist and --crontab print a job that runs --once four
      times a day, for a person to install; they write nothing
      While a login window of the home holds the identity it skips a cycle with "held window-open <address>" and
      tries again after 60 s (--once: refused window-open)
  publish <relay-url> <record-file> [--dir <home>]
      publishes a signed record; an address record of an identity a login window of the home holds is refused
      (window-open), as record address and record keep refuse it: logout would overwrite it
  delegate --from <name> --to <address> [--caveat <caveat>...] --exp <unix seconds|+seconds> [--chain <in.json>] --out <chain.json> [--dir <home>]
      one hop from the identity <name> to <address>, under the caveats it adds, appended to --chain when given;
      writes the chain and prints the subject, then "root <address> hops <n> exp <seconds> caveats <JSON list>"
  onboard <name> --domain <host> --relay <url>... --accept <address|domain:<host>|*>... [--handle <local>] [--org-key <name>] [--out <dir>] [--origin apex|bag] [--ttl <seconds>] [--chain-exp <seconds>] [--max-bytes <n>] [--retention <seconds>] [--check] [--allow-private-relays] [--dir <home>]
      puts the agent <name> on its org's own domain, and is run again (cron) as the daily refresh: the org key
      (--org-key, default org-<host>) and <name>'s key, each made when missing ("key <name> <address> new|existing");
      the tree to serve, <out> (default <home>/serve/<host>): the org's address record (its sealing key, the relays,
      --ttl default 86400, the rotation key and revoked list of the record already there kept) and the handle record
      of <local>@<host> (default <name>), verified, each put in place by a rename, 0644 ("wrote <file>"); <name>'s
      address and accept-from records (--max-bytes 65536, --retention 604800 by default) in <home>/records,
      published at each relay ("published", or "unchanged" for a relay holding one of the same second); each
      --accept address trusted; the chain from the org key to <name>, <home>/<name>.chain.json (--chain-exp default
      604800). Then the owner's two steps: serve <out> as https://<host>/ (https://bag.<host>/ with --origin
      bag), and add the TXT record of the "dns" line; the next commands and a cron line; and the self-check,
      lookup of domain:<host> and the handle as a peer's edge resolves them ("check <line>"). --check runs only the
      self-check. Exits 0 when the handle resolves end to end, 3 when written and published but not resolving yet
  name add <name> <address> [--replace] [--dir <home>] | name list [--dir <home>] | name forget <name> [--dir <home>]
      the home's local name book, <home>/names.json (0600): a name ([a-z0-9][a-z0-9._-], at most 32) pinned to one
      address, changed only with --replace, which keeps the old one as former; list prints "<name> <address>" and a
      "  former <address> replaced <unix>" line per former address. Names are resolved here, never sent on the wire
  send --as <name> --to <name|address|handle>... --relay <url> --type <type> --body <json> [--auth <chain.json>] [--thread <id> [--prev <id>...]] [--policy <file>] [--members <file>] [--allow-private-relays] [--dir <home>]
      one envelope to every recipient, signed by <name>: as its own root, or with --auth as a session under the
      chain delegate wrote (whose last hop is to <name>); --to takes a name from the name book, an address, or a
      handle such as jane@acme.example, which the edge resolves through the domain's TXT record, its org record
      and the handle record the org signs (resolve-failed naming the step, or revoked; name-unknown for a name the
      book lacks); prints its id and each target's state. A recipient relay
      on a private or loopback address other than --relay is refused unless --allow-private-relays is given;
      with --members, a recipient the org denies is policy-refused and a send a breaker trips is "held <id> <rule>"
  resend --as <name> --relay <url> [--id <id>] [--members <file>] [--policy <file>] [--auth <chain.json>] [--allow-private-relays] [--dir <home>]
      one flush of the identity's outbox, as a running edge makes: the exact bytes of every due target, through the
      outbox's retry and failover, the same id. --id first seals that envelope's failed targets again. Prints each
      envelope as send does, and "waiting <to,...> tries=<n> next_at=<n>" per send that has not resolved, or "nothing
      is waiting"; exits 1 with the reason of the first that has not landed, once all are printed
  inbox [release <seq> | drop <seq>] --as <name> --relay <url>... [--once] [--quarantined] [--group <group>] [--trust-root <domain|address>...] [--honor coding] [--accept-type <type>...] [--policy <file>] [--members <file>] [--allow-private-relays] [--doorbell-path] [--dir <home>]
      receives and prints "accept <id> <from> <root> <type> <body>", "reject <id> <code>" or "quarantined <id>
      <code>" per message; a caveat fails closed (unknown-caveat) unless --honor names its profile. A <from> or
      <root> the name book knows prints as "<name> (ed25519:<8 hex>…)", a name's former address as "<name>? (…)
      WARNING: former address of <name>, replaced <time>"; any other address in full. A <from> whose principal
      has a handle this home resolved (send --to) and holds, unexpired, signed by the chain's root under
      the domain's pinned key prints "[<name> ]<handle> (ed25519:<8 hex>…)". --policy and --members are
      the org's records (verified at start, exit 2 with the code if not; the members file 0600, never served);
      --quarantined prints "<seq> <id> <from> <root> <rule>" per held row; release and drop are a person's, on a
      terminal (no-tty otherwise): the row, a question, then "<seq> <state> <reason>". Each accepted message
      moves the mtime of the doorbell, <home>/state/<name>/doorbell (empty, 0600); --doorbell-path prints
      "doorbell <absolute path>" first
  held list | held release <id> | held drop <id>   --as <name> --relay <url> [--members <file>] [--policy <file>] [--auth <chain.json>] [--allow-private-relays] [--dir <home>]
      the held sends, "<id> <rule> <type> <to,...>"; release (--members: the deny list again) and drop as above
  inbox --watch [--exec <cmd> [--exec-timeout <s>]] --as <name> --relay <url>... [inbox's options but --once, --quarantined, release, drop]
      the live inbox, each accept line printed at once; reject and quarantined lines go to stderr. --exec runs <cmd>
      with sh -c per accepted message, "message <id> from <address>, type <type>" on its stdin (the MCP push notice's three fields; never the body), one
      run at a time, each for at most --exec-timeout seconds (default 120; 0: no limit): then SIGTERM, SIGKILL 5 s
      later, one stderr line each; a command that needs longer must background itself; the queue is unbounded. A
      failed run is one stderr line, and the watch goes on. --exec-timeout without --exec is accepted and ignored.
      It is the identity's one receiver: of it and an MCP server of the same identity, whichever starts second is
      refused busy; so it watches no doorbell: the doorbell serves a process that is not the receiver. SIGINT or
      SIGTERM: pending runs finish, then exit 0
  lookup <address|domain:<host>|handle> --as <name> --relay <url>... [--at <url>...] [--allow-private-relays] [--dir <home>]
      where an address's records live: the cache, then each relay a send asks (--at first), one line each, for the
      address and key records; for a domain, its TXT record and its org record at the origin; for a handle, those,
      its handle record, then its address's records: "<source> <found|none|refused|error> kind=<k> [...]"
  group create <name> --relay <url>... --rotation-key <address> [--root <address>...] [--ttl <s>] [--max-bytes <n>] [--retention <s>] | group add <name> <member> [--exp <unix seconds|+seconds>] [--relay-hint <url>...] | group remove <name> <member> | group rotate <name> | group keep <name> [--every <s>] [--once]   [--allow-private-relays] [--dir <home>]
      the identity <name> becomes a group (CLI only); members read it with inbox --group, post with send --to
  audit verify <file>
      recomputes an audit log's hash chain; prints "ok <n> lines" or the first bad line
  status --as <name> [--dir <home>]
      first, always, "doorbell <absolute path>"; then, from the identity's audit log, when its last subscription
      ended for good (three refusals in a row): "mailbox refused: <code> at <relay> after <n> refusals; edge
      errors <e>, last <code> at <time>"; else nothing more. It names a relay, not a mailbox, though the log's lines
      carry one: the identity's own and its groups' subscriptions share the log. A subscription that succeeds is not
      audited, so the line stays until a later subscribe retry line, whatever its mailbox, follows it
  wake-hook --as <name> [--session auto|auto:codex] [--max <seconds>] [--exit-code <n>] [--no-idle-wake] [--print] [--dir <home>]
      for a host hook: polls <home>/state/<name>/doorbell once a second and compares its mtime with the one in
      <home>/state/<name>/wake-seen (0600), the last it reported; the first run takes the current mtime as the baseline.
      On a change it stores it, writes one stderr line telling the model to read the inbox and exits <n> (default 2, the
      code that wakes a Claude Code asyncRewake hook); at --max seconds (default 3500) it exits 0, silent (after
      one wake per mail-free stretch, unless --no-idle-wake: then no wake-idle is made or removed and the deadline is
      always silent). --print writes
      "doorbell <mtime>" on stdout per change instead and runs until SIGINT or SIGTERM. Opens no edge and no store;
      --session auto takes the name from the MCP server's session file (exit 1 if none); --session auto:codex, for a
      Codex Stop hook, names it from the session_id of the Stop JSON on stdin (exit 0 at once before the first tool call)
  wake-hook --identities <file> [--max <seconds>] [--exit-code <n>] [--no-idle-wake] [--print]
      the same for every identity of an identities file, each by its own doorbell; a ring names the identity's label
  session-code --as <principal> --session auto [--dir <home>]: for a synchronous SessionStart hook, prints the grant request's code as JSON
  host install <claude-code|codex> --as <name> --relay <url>... [--trust-root <address>]... [--grant-caveat <caveat>]... (--project <dir> | --user) [--mode worker|mcp] [--dir <home>]
      claude-code --project <dir>: the MCP server in <dir>/.mcp.json and a SessionStart and a Stop wake-hook in
      <dir>/.claude/settings.json; codex --user [--mode worker|mcp]: worker (the default; Codex has no idle wake) prints
      the inbox --watch --exec 'codex exec ...' line and writes nothing, mcp writes ~/.codex/config.toml and a Stop
      hook in ~/.codex/hooks.json (a turn that ends waits up to 30 s for mail; trust it with /hooks in Codex); mcp needs
      --grant-caveat and starts the server as --session auto:codex, one Codex session per server.
      Merges into what is there, a second run changes nothing and says so; any other place is
      "not documented yet". claude-code --identities <file> [--label <label>] adds the identity to an identities
      file (absolute, outside the project, 0600) and wires the server and the hook to the file
  host remove claude-code --project <dir> --identities <file> --label <label>
      takes the identity out of the file; no key, home or state is touched
  health <relay-url>
      prints "ok" when the relay answers its health probe
  telemetry on | off | status | preview [--date <YYYY-MM-DD>]
      off until a person turns it on, one choice and one install id per machine, whatever the home, and this version
      sends nothing: on and off write ~/.bag/telemetry.json (0600), on with a random install id, off removing it and
      the spool of counts (~/.bag/telemetry-counts.jsonl); each prints "telemetry <on|off> reason=<reason>
      choice=<on|off|none> id=<id|none> spool=<bytes>", the id an erasure request names. preview prints the exact
      report for a UTC date (today, or --date, up to 7 days back) and, on stderr, its size. AC_TELEMETRY=off, DO_NOT_TRACK and CI turn it
      off whatever the file says. While it is on, each command line, how long it took and the audit lines, relay
      calls and pairings it made are counted. While no choice is made, a command a person runs at a terminal, or host
      install, prints a notice once per machine that names this preview

The home is --dir, else $AC_HOME, else ~/.bag: keys in <home>/keys (0600 files in a 0700 directory), or in a
keychain item that <home>/keychain/<name>.json names, or in the agent (<home>/agent/<name>.json holds the public
halves; the keys live in the agent for a login window, and a command that signs as that identity refuses it); an
identity's edge state in <home>/state/<name>/ (edge.sqlite, audit.jsonl); the name book in <home>/names.json. An
identity signs as its own root, or as a session under a chain (send --auth). Errors exit 1 with
"bag: <code>: <detail>" on stderr.`

type Command = (args: readonly string[], io: Io) => number | Promise<number>

const COMMANDS: ReadonlyMap<string, Command> = new Map<string, Command>([
  ['keygen', keygen],
  ['init', init],
  ['restore', restore],
  ['address', address],
  ['keys', keys],
  ['login', login],
  ['logout', logout],
  ['grant', grant],
  ['name', name],
  ['peer', peer],
  ['unpair', unpair],
  ['record', record],
  ['publish', publish],
  ['delegate', delegate],
  ['onboard', onboard],
  ['group', group],
  ['send', send],
  ['resend', resend],
  ['inbox', (args, io) => (args.some((a) => /^--(watch$|exec($|=))/.test(a)) ? watch : inbox)(args, io)],
  ['held', held],
  ['audit', audit],
  ['status', status],
  ['wake-hook', wakeHook],
  ['session-code', sessionCode],
  ['host', hostInstall],
  ['lookup', lookup],
  ['health', health],
  ['telemetry', telemetry],
])

/** The code an error is reported with: its own from the closed set, the CLI's, a system errno, or `error`. */
export function codeOf(e: unknown): string {
  if (isAcError(e) || e instanceof CliError) return e.code
  if (e instanceof RelayError) return e.code ?? (e.status === 0 ? 'unreachable' : `http-${e.status}`)
  const errno = (e as { code?: unknown } | null)?.code
  return typeof errno === 'string' ? errno : 'error'
}

/** The detail of an error: its message without the leading "<code>: " that the core's and the edge's carry. */
export function detailOf(e: unknown, code: string): string {
  const message = e instanceof Error ? e.message : String(e)
  return message.startsWith(`${code}: `) ? message.slice(code.length + 2) : message
}

/**
 * Runs one command line and returns its exit status. While the machine's telemetry is on (the edge's telemetry.ts), it
 * counts the line by its verb, exit and code, and how long it took, beside what the command's edge counts.
 */
export async function run(argv: readonly string[], io: Io): Promise<number> {
  const counting = startTelemetry(io.env, io.clock)
  const start = performance.now()
  let exit = 1
  let code = 'ok'
  try {
    exit = await dispatch(argv, io)
    return exit
  } catch (e) {
    code = codeOf(e)
    io.err(`bag: ${code}: ${detailOf(e, code)}`)
    if (e instanceof UsageError) io.err(`run "node ${process.argv[1]} help" for the commands`)
    exit = e instanceof PolicyFileError ? 2 : 1
    return exit
  } finally {
    if (counting) {
      countTelemetry('cli', [verbOf(argv), String(exit), code])
      countDuration('cli_durations', verbOf(argv), performance.now() - start)
      stopTelemetry()
    }
  }
}

async function dispatch(argv: readonly string[], io: Io): Promise<number> {
  const [name, ...rest] = argv
  if (name === 'help' || argv.includes('--help') || argv.includes('-h')) {
    io.out(USAGE)
    return 0
  }
  const command = COMMANDS.get(name ?? '')
  if (command === undefined) {
    throw new UsageError(name === undefined ? 'no command' : `no command ${JSON.stringify(name)}`)
  }
  const exit = await command(rest, io)
  if ((io.isTty && name !== 'telemetry') || name === 'host') notice(io)
  return exit
}
