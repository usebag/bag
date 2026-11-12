import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { shq } from '../args.ts'
import { stableNode } from '../packaged.ts'

// host install service: the login agent that starts the bag service at login and restarts it after a crash, as text
// for the person, with the one line that loads it. Nothing here writes the file or touches launchd: the person's line
// does. The text is byte for byte S1's launchAgentPlist (packages/mcp/src/service.ts, as on ecce5f0e), which
// the CLI may not import (scripts/check-imports.sh); test/fixtures/svc-core-plist.txt is S1's own output and pins it.
// W2's --print-login-agent flag on bag-mcp.js replaces this printer when it lands. The Linux unit is S1's systemdUnit, pinned the same way.

type Env = Readonly<Record<string, string | undefined>>

/** The login agent's names (svc-core): the launchd label, and the systemd user unit, one per user for one home. */
export const LABEL = 'dev.bag.service'
const UNIT = 'bag.service'
const UNIT_FILE = '~/.config/systemd/user/bag.service'

/** S1's SCRUB_ENV, in its order; PATH first, fixed. */
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

/** The proxy variables whose value carries a user name or password: never written into the text (S1's proxyOmitted). */
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
    `  <key>Label</key>${str(LABEL)}`,
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

/** A systemd ExecStart or Environment word: quoted, with backslash, quote, `%` (a specifier) and `$` escaped (S1's). */
const unitWord = (s: string): string =>
  `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`

/**
 * The systemd user unit, byte for byte S1's systemdUnit (packages/mcp/src/service.ts), pinned by
 * test/fixtures/svc-core-unit.txt: the same argv and environment as the plist, the run directory, core dumps 0, umask
 * 077, a restart on a crash, the inherited NODE_OPTIONS, NODE_PATH and LD_PRELOAD unset, stderr to run/service.log.
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
  const run = join(o.home, 'run')
  return [
    `# ${UNIT_FILE}: the bag service's systemd user unit, one per user, for one home`,
    '[Unit]',
    `Description=${LABEL}`,
    '',
    '[Service]',
    'Type=simple',
    `ExecStart=${args.map(unitWord).join(' ')}`,
    `WorkingDirectory=${unitWord(run)}`,
    ...Object.entries(env).map(([k, v]) => `Environment=${unitWord(`${k}=${v}`)}`),
    'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD',
    'UMask=0077',
    'LimitCORE=0',
    'Restart=on-failure',
    'StandardOutput=null',
    `StandardError=append:${join(run, 'service.log')}`,
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
 */
export function serviceInstall(
  env: Env,
  home: string,
  main: string,
  self: string,
  platform: string = process.platform,
  node = stableNode(),
  read: (file: string) => string | null = readOrNull,
): string[] {
  const mac = platform === 'darwin'
  const dir = mac
    ? join(env.HOME ?? '~', 'Library', 'LaunchAgents')
    : join(env.HOME ?? '~', '.config', 'systemd', 'user')
  const file = join(dir, mac ? `${LABEL}.plist` : UNIT)
  const identities = join(home, 'identities.json')
  const have = read(file)
  if (have !== null && !have.includes(join(home, 'run'))) {
    return [
      `a login agent for another home is installed (${file}): bag 0.4.0 has one per user, so the service of ${home} starts with its first window instead`,
    ]
  }
  const text = (mac ? servicePlist : serviceUnit)({ node, main, home, identities, env }).replace(/\n$/, '')
  const load = mac
    ? `launchctl bootstrap gui/${process.getuid?.() ?? '<uid>'} ${shq(file)}`
    : 'systemctl --user daemon-reload && systemctl --user enable --now bag'
  const keep = mac ? "sed -n '1,/^<\\/plist>$/p'" : "sed -n '1,/^WantedBy=/p'"
  return [
    text,
    '',
    ...proxyOmitted(env).map((k) => `left out of the login agent: ${k} (it carries a user name or password)`),
    `the login agent above starts the bag service for ${home} at login and after a crash. To install it, save it and load it in a terminal:`,
    `mkdir -p ${shq(dir)} && ${self} host install service --dir ${shq(home)} | ${keep} > ${shq(file)} && ${load}`,
  ]
}

function readOrNull(file: string): string | null {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return null
  }
}
