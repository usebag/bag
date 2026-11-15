import { lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { shq } from './host-common.ts'
import { HomeError } from './ports.ts'

// host install service: the login agent that starts the bag service at login and restarts it after a crash, as text
// for the person, with the one line that loads it. Nothing here writes the file or touches launchd or systemd: the
// person's line does. It makes one folder, the home's run/ (0700), which both agents name as the service's working
// directory and stderr file before the service ever ran: a fresh home has none, and systemd refuses to start the
// unit without it (status 222/STDERR). The text is byte for byte the bag service's launchAgentPlist (packages/mcp/src/service.ts), which the CLI
// may not import (scripts/check-imports.sh); packages/cli/test/fixtures/launch-agent-plist.txt is its own output and
// pins it. bag-mcp.js --print-login-agent (packages/mcp/src/service.ts) prints the login agent too; this printer
// stays. The Linux unit is the bag service's systemdUnit, pinned the same way.

type Env = Readonly<Record<string, string | undefined>>

/**
 * The login agent's names (docs/bag-service.md, "What runs"): the launchd label, and the systemd user unit, one
 * per user for one home.
 */
export const SERVICE_LABEL = 'dev.bag.service'
const UNIT = 'bag.service'
const UNIT_FILE = '~/.config/systemd/user/bag.service'

/** The bag service's SCRUB_ENV (packages/mcp/src/service.ts), in its order; PATH first, fixed. */
const SCRUB_ENV = [
  'HOME',
  'USER',
  'LOGNAME',
  'LANG',
  'TMPDIR',
  'AC_HOME',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
  'NODE_USE_ENV_PROXY',
]
const PROXIES = ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']

/** The proxy variables whose value carries a user name or password: never written (as the service's proxyOmitted). */
export function proxyOmitted(env: Env): string[] {
  return PROXIES.filter((k) => {
    const v = env[k]
    if (v === undefined) return false
    try {
      const u = new URL(v)
      return u.username !== '' || u.password !== ''
    } catch {
      return /@/.test(v)
    }
  })
}

const xml = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

/**
 * The plist: <node> --disable-sigusr1 <main> --service --dir <home> --identities <identities>, in <home>/run, the
 * scrubbed environment, KeepAlive on a crash, core dumps 0, stderr to <home>/run/service.log.
 */
export function servicePlist(o: {
  readonly node: string
  readonly main: string
  readonly home: string
  readonly identities: string
  readonly env: Env
}): string {
  // XML 1.0 has no form for most C0 control characters, escaped or not: a path holding one would write a plist launchd
  // cannot parse, and the agent would never load, without a word. Tab, LF and CR are XML's own and stay.
  for (const p of [o.node, o.main, o.home, o.identities])
    if ([...p].some((c) => c < ' ' && c !== '\t' && c !== '\n' && c !== '\r'))
      throw new HomeError(
        'unsafe-path',
        `${JSON.stringify(p)} holds a control character, which a plist cannot hold`,
      )
  const args = [
    o.node,
    '--disable-sigusr1',
    o.main,
    '--service',
    '--dir',
    o.home,
    '--identities',
    o.identities,
  ]
  const env: Record<string, string> = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }
  for (const k of SCRUB_ENV) if (o.env[k] !== undefined) env[k] = o.env[k] as string
  for (const k of proxyOmitted(o.env)) delete env[k]
  const run = join(o.home, 'run')
  const str = (s: string): string => `<string>${xml(s)}</string>`
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    `  <key>Label</key>${str(SERVICE_LABEL)}`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    ...args.map((a) => `    ${str(a)}`),
    '  </array>',
    `  <key>WorkingDirectory</key>${str(run)}`,
    '  <key>EnvironmentVariables</key>',
    '  <dict>',
    ...Object.entries(env).map(([k, v]) => `    <key>${xml(k)}</key>${str(v)}`),
    '  </dict>',
    '  <key>RunAtLoad</key><true/>',
    '  <key>KeepAlive</key>',
    '  <dict>',
    '    <key>SuccessfulExit</key><false/>',
    '  </dict>',
    '  <key>ProcessType</key><string>Background</string>',
    '  <key>Umask</key><integer>63</integer>',
    '  <key>SoftResourceLimits</key>',
    '  <dict>',
    '    <key>Core</key><integer>0</integer>',
    '  </dict>',
    '  <key>HardResourceLimits</key>',
    '  <dict>',
    '    <key>Core</key><integer>0</integer>',
    '  </dict>',
    `  <key>StandardErrorPath</key>${str(join(run, 'service.log'))}`,
    '</dict>',
    '</plist>',
    '',
  ].join('\n')
}

/**
 * The run directory both login agents name, made 0700 (under umask 077) when absent, then refused unless it is a
 * directory, not a link, owned by this user, with no group or other bit: the bag service's own check of the folder
 * (ensureRunDir in packages/mcp/src/socket.ts), which this package may not import. Unlike the service's, it makes no
 * parent: a home that does not exist, or is a file, is refused (ENOENT), never made by a command that prints text.
 */
export function ensureRunDir(dir: string, uid: number = process.getuid?.() ?? -1): void {
  const old = process.umask(0o077)
  try {
    mkdirSync(dir, { mode: 0o700 })
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR') throw new HomeError('ENOENT', `no home ${dirname(dir)}`)
    if (code !== 'EEXIST') throw e
  } finally {
    process.umask(old)
  }
  const st = lstatSync(dir)
  if (st.isSymbolicLink() || !st.isDirectory())
    throw new HomeError('unsafe-path', `${dir} is a link or not a directory`)
  if (uid >= 0 && st.uid !== uid)
    throw new HomeError('unsafe-path', `${dir} belongs to another user (uid ${st.uid})`)
  if ((st.mode & 0o077) !== 0) {
    const octal = (st.mode & 0o777).toString(8).padStart(4, '0')
    throw new HomeError('unsafe-path', `${dir} has mode ${octal}; it must be 0700`)
  }
}

/** A systemd ExecStart or Environment word, quoted as the service quotes it: backslash, quote, `%` and `$` escaped. */
const unitWord = (s: string): string =>
  `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`

/**
 * The systemd user unit, byte for byte the bag service's systemdUnit (packages/mcp/src/service.ts), pinned by
 * packages/cli/test/fixtures/systemd-unit.txt: the same argv and environment as the plist, the run directory, core
 * dumps 0, umask 077, a restart on a crash, the inherited NODE_OPTIONS, NODE_PATH and LD_PRELOAD unset, stderr to
 * run/service.log.
 */
export function serviceUnit(o: {
  readonly node: string
  readonly main: string
  readonly home: string
  readonly identities: string
  readonly env: Env
}): string {
  const args = [
    o.node,
    '--disable-sigusr1',
    o.main,
    '--service',
    '--dir',
    o.home,
    '--identities',
    o.identities,
  ]
  const env: Record<string, string> = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }
  for (const k of SCRUB_ENV) if (o.env[k] !== undefined) env[k] = o.env[k] as string
  for (const k of proxyOmitted(o.env)) delete env[k]
  // A unit file is read line by line: a path holding a line break would end its setting and start another, so it is
  // refused before any text is made.
  for (const p of [o.node, o.main, o.home, o.identities])
    if (/[\r\n]/.test(p))
      throw new HomeError(
        'unsafe-path',
        `${JSON.stringify(p)} holds a line break, which a systemd unit cannot hold`,
      )
  const run = join(o.home, 'run')
  return [
    `# ${UNIT_FILE}: the bag service's systemd user unit, one per user, for one home`,
    '[Unit]',
    `Description=${SERVICE_LABEL}`,
    '',
    '[Service]',
    'Type=simple',
    `ExecStart=${args.map(unitWord).join(' ')}`,
    // A bare path: systemd allows quotes only where a setting says so (systemd.syntax(7), Quoting), and this one does not.
    `WorkingDirectory=${run.replace(/%/g, '%%')}`,
    ...Object.entries(env).map(([k, v]) => `Environment=${unitWord(`${k}=${v}`)}`),
    'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD',
    'UMask=0077',
    'LimitCORE=0',
    'Restart=on-failure',
    'StandardOutput=null',
    // `%` is a specifier in systemd values, so it is doubled here as in WorkingDirectory.
    `StandardError=append:${join(run, 'service.log').replace(/%/g, '%%')}`,
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n')
}

/**
 * The output for `platform`: the plist (macOS) or the systemd user unit (Linux), stdout first, one line per proxy
 * variable left out, and the person's one line, which keeps the text only. One login agent per user for one home: when
 * the agent's file is there for another home, one line says so instead (a second home starts with its first window).
 * `self` is how the person's line runs the command line, `uid` the user's id in macOS's load line. The home's run/ is
 * made first (`prepare`), on both platforms: the agent's stderr file and working directory are in it.
 */
export function serviceInstall(
  env: Env,
  home: string,
  main: string,
  self: string,
  platform: string,
  node: string,
  uid: number | undefined,
  read: (file: string) => string | null = readOrNull,
  prepare: (dir: string) => void = ensureRunDir,
): string[] {
  const mac = platform === 'darwin'
  const dir = mac
    ? join(env.HOME ?? '~', 'Library', 'LaunchAgents')
    : join(env.HOME ?? '~', '.config', 'systemd', 'user')
  const file = join(dir, mac ? `${SERVICE_LABEL}.plist` : UNIT)
  const identities = join(home, 'identities.json')
  const have = read(file)
  if (have !== null && !have.includes(join(home, 'run'))) {
    return [
      `a login agent for another home is installed (${file}): bag 0.4.0 has one per user, so the service of ${home} starts with its first window instead`,
    ]
  }
  prepare(join(home, 'run'))
  const text = (mac ? servicePlist : serviceUnit)({ node, main, home, identities, env }).replace(/\n$/, '')
  const load = mac
    ? `launchctl bootstrap gui/${uid ?? '<uid>'} ${shq(file)}`
    : 'systemctl --user daemon-reload && systemctl --user enable --now bag'
  const keep = mac ? "sed -n '1,/^<\\/plist>$/p'" : "sed -n '1,/^WantedBy=/p'"
  // The text is saved outside the agents' folder, on its file system, so nothing loads it there; it is moved in only
  // when it ends as a login agent does, since a pipe's status is the last command's and a refusal would be saved too.
  // Never a redirect into the file itself: the shell empties it before the command reads it, and an empty file reads
  // as another home's login agent.
  const next = mac
    ? join(env.HOME ?? '~', 'Library', `${SERVICE_LABEL}.plist.new`)
    : join(env.HOME ?? '~', '.config', `${UNIT}.new`)
  const ends = mac ? "'^</plist>$'" : "'^WantedBy='"
  const stop = `echo 'STOP: bag printed no login agent, so nothing was moved or loaded; what it printed is in' ${shq(next)} >&2; false`
  return [
    text,
    '',
    ...proxyOmitted(env).map((k) => `left out of the login agent: ${k} (it carries a user name or password)`),
    `the login agent above starts the bag service for ${home} at login and after a crash. To install it, save it and load it in a terminal:`,
    `mkdir -p ${shq(dir)} && ${self} host install service --dir ${shq(home)} | ${keep} > ${shq(next)} && if grep -q ${ends} ${shq(next)}; then mv ${shq(next)} ${shq(file)} && ${load}; else ${stop}; fi`,
  ]
}

/**
 * The login agent written for `home` after the person's Yes (an MCP tool's act, where no terminal saves the text): the
 * fixed template (servicePlist or serviceUnit) with every path from the home and the process, never from an argument,
 * put in place beside and renamed over, its folder made; then the person's one line that loads it, which nothing here
 * runs (no launchctl, no systemctl). The agent's file of another home refuses exists; the same text is unchanged.
 */
export function serviceWrite(
  env: Env,
  home: string,
  main: string,
  platform: string,
  node: string,
  uid: number | undefined,
  prepare: (dir: string) => void = ensureRunDir,
): string[] {
  const mac = platform === 'darwin'
  if (!mac && platform !== 'linux') throw new HomeError('usage', `no login agent for ${platform}`)
  if (env.HOME === undefined) throw new HomeError('usage', 'no HOME: the login agent goes under HOME')
  const dir = mac ? join(env.HOME, 'Library', 'LaunchAgents') : join(env.HOME, '.config', 'systemd', 'user')
  const file = join(dir, mac ? `${SERVICE_LABEL}.plist` : UNIT)
  const have = readOrNull(file)
  if (have !== null && !have.includes(join(home, 'run')))
    throw new HomeError(
      'exists',
      `a login agent for another home is installed (${file}): nothing was written`,
    )
  prepare(join(home, 'run'))
  const text = (mac ? servicePlist : serviceUnit)({
    node,
    main,
    home,
    identities: join(home, 'identities.json'),
    env,
  })
  const load = mac
    ? `launchctl bootstrap gui/${uid ?? '<uid>'} ${shq(file)}`
    : 'systemctl --user daemon-reload && systemctl --user enable --now bag'
  const omitted = proxyOmitted(env).map(
    (k) => `left out of the login agent: ${k} (it carries a user name or password)`,
  )
  if (have === text) return [`unchanged ${file}`, ...omitted, `to load it, run in a terminal: ${load}`]
  mkdirSync(dir, { recursive: true })
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, text, { mode: 0o644 })
  renameSync(tmp, file)
  return [`wrote ${file}`, ...omitted, `to load it, run in a terminal: ${load}`]
}

function readOrNull(file: string): string | null {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return null
  }
}
