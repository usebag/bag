import { execFileSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  ensureRunDir,
  HomeError,
  proxyOmitted,
  SERVICE_LABEL,
  serviceInstall,
  servicePlist,
  serviceUnit,
  serviceWrite,
} from '../src/index.ts'
import { folder } from './support.ts'

// host install service: the login agent's text and the person's one line that loads it; only the home's run/ is made.

const env = {
  HOME: '/Users/x',
  USER: 'x',
  HTTPS_PROXY: 'http://proxy:3128',
  http_proxy: 'http://u:p@proxy:3128',
  HTTP_PROXY: 'user@host',
}
const none = () => null
const made: string[] = []
const prep = (dir: string) => {
  made.push(dir)
}

describe('serviceInstall', () => {
  it("macOS: the plist, the proxies left out, and the person's line with the user's id", () => {
    const lines = serviceInstall(
      env,
      '/Users/x/.bag',
      '/p/bag-mcp.js',
      'node bag.js',
      'darwin',
      '/n',
      501,
      none,
      prep,
    )
    expect(lines[0]).toContain(`<key>Label</key><string>${SERVICE_LABEL}</string>`)
    expect(lines[0]).toContain('<string>/n</string>')
    expect(lines[0]).not.toContain('u:p@proxy')
    expect(lines[0]).toContain('http://proxy:3128')
    expect(lines).toContain('left out of the login agent: http_proxy (it carries a user name or password)')
    expect(lines).toContain('left out of the login agent: HTTP_PROXY (it carries a user name or password)')
    expect(lines.at(-1)).toBe(
      "mkdir -p /Users/x/Library/LaunchAgents && node bag.js host install service --dir /Users/x/.bag | sed -n '1,/^<\\/plist>$/p' > /Users/x/Library/dev.bag.service.plist.new && if grep -q '^</plist>$' /Users/x/Library/dev.bag.service.plist.new; then mv /Users/x/Library/dev.bag.service.plist.new /Users/x/Library/LaunchAgents/dev.bag.service.plist && launchctl bootstrap gui/501 /Users/x/Library/LaunchAgents/dev.bag.service.plist; else echo 'STOP: bag printed no login agent, so nothing was moved or loaded; what it printed is in' /Users/x/Library/dev.bag.service.plist.new >&2; false; fi",
    )
    const nobody = serviceInstall(
      env,
      '/Users/x/.bag',
      '/p/bag-mcp.js',
      'node bag.js',
      'darwin',
      '/n',
      undefined,
      undefined,
      prep,
    )
    expect(nobody.at(-1)).toContain('launchctl bootstrap gui/<uid> ')
  })

  it('Linux: the systemd unit; a login agent of another home is one line instead', () => {
    const lines = serviceInstall(env, '/h', '/p/bag-mcp.js', 'node bag.js', 'linux', '/n', 1000, none, prep)
    expect(lines[0]).toMatch(/^# ~\/\.config\/systemd\/user\/bag\.service: /)
    expect(lines.at(-1)).toBe(
      "mkdir -p /Users/x/.config/systemd/user && node bag.js host install service --dir /h | sed -n '1,/^WantedBy=/p' > /Users/x/.config/bag.service.new && if grep -q '^WantedBy=' /Users/x/.config/bag.service.new; then mv /Users/x/.config/bag.service.new /Users/x/.config/systemd/user/bag.service && systemctl --user daemon-reload && systemctl --user enable --now bag; else echo 'STOP: bag printed no login agent, so nothing was moved or loaded; what it printed is in' /Users/x/.config/bag.service.new >&2; false; fi",
    )
    const other = serviceInstall(
      env,
      '/h2',
      '/m',
      'node bag.js',
      'linux',
      '/n',
      1000,
      () => lines[0] as string,
      prep,
    )
    expect(other).toEqual([
      'a login agent for another home is installed (/Users/x/.config/systemd/user/bag.service): bag 0.4.0 has one per user, so the service of /h2 starts with its first window instead',
    ])
    const same = serviceInstall(
      env,
      '/h',
      '/p/bag-mcp.js',
      'node bag.js',
      'linux',
      '/n',
      1000,
      () => lines[0] as string,
      prep,
    )
    expect(same).toEqual(lines)
  })

  it('the plist and the unit carry one argv and the scrubbed environment', () => {
    const o = {
      node: '/n',
      main: '/m',
      home: '/h',
      identities: '/h/identities.json',
      env: { HOME: '/u', X: 'y' },
    }
    expect(servicePlist(o)).toContain('<key>HOME</key><string>/u</string>')
    expect(servicePlist(o)).not.toContain('<key>X</key>')
    expect(serviceUnit(o)).toContain(
      'ExecStart="/n" "--disable-sigusr1" "/m" "--service" "--dir" "/h" "--identities"',
    )
    expect(serviceUnit(o)).toContain('\nWorkingDirectory=/h/run\n')
    expect(serviceUnit(o)).not.toContain('WorkingDirectory="')
    expect(serviceUnit({ ...o, home: '/h%$"' })).toContain('\nWorkingDirectory=/h%%$"/run\n')
    expect(serviceUnit({ ...o, home: '/h%x' })).toContain('\nStandardError=append:/h%%x/run/service.log\n')
    for (const bad of [{ home: '/h\nx' }, { home: '/h\rx' }, { node: '/n\n' }, { identities: '/h/i\n.json' }])
      expect(() => serviceUnit({ ...o, ...bad })).toThrow(
        'holds a line break, which a systemd unit cannot hold',
      )
    for (const bad of [{ home: '/h\u0001x' }, { main: '/m\u001f' }, { identities: '/h/i\u0008.json' }])
      expect(() => servicePlist({ ...o, ...bad })).toThrow(
        'holds a control character, which a plist cannot hold',
      )
    expect(servicePlist({ ...o, home: '/h\tx' })).toContain('<string>/h\tx</string>') // tab is XML's own
    expect(proxyOmitted({})).toEqual([])
  })
})

describe("the home's run/, made before the agent's text (both agents name it before the service ran)", () => {
  it('is prepared on macOS and on Linux, and not when another home holds the login agent', () => {
    made.length = 0
    serviceInstall(env, '/h', '/m', 'node bag.js', 'darwin', '/n', 501, none, prep)
    serviceInstall(env, '/h', '/m', 'node bag.js', 'linux', '/n', 1000, none, prep)
    serviceInstall(env, '/h2', '/m', 'node bag.js', 'linux', '/n', 1000, () => '# another home', prep)
    expect(made).toEqual(['/h/run', '/h/run'])
  })

  it('makes run/ 0700 on a fresh home by default, on both platforms, and keeps an existing 0700 one', () => {
    for (const platform of ['darwin', 'linux']) {
      const home = join(folder(), '.bag')
      mkdirSync(home, { mode: 0o700 })
      serviceInstall(env, home, '/m', 'node bag.js', platform, '/n', 501, none)
      const st = lstatSync(join(home, 'run'))
      expect(st.isDirectory()).toBe(true)
      expect(st.mode & 0o777).toBe(0o700)
      expect(() => ensureRunDir(join(home, 'run'))).not.toThrow()
    }
  })

  it('makes no home: a home that does not exist is refused, nothing made', () => {
    const base = folder()
    let thrown: unknown
    try {
      ensureRunDir(join(base, 'absent', 'run'))
    } catch (e) {
      thrown = e
    }
    expect((thrown as HomeError).code).toBe('ENOENT')
    expect(() => lstatSync(join(base, 'absent'))).toThrow()
    writeFileSync(join(base, 'file'), '')
    let file: unknown
    try {
      ensureRunDir(join(base, 'file', 'run'))
    } catch (e) {
      file = e
    }
    expect((file as HomeError).code).toBe('ENOENT')
  })

  it('refuses a run/ that is a link, not a folder, or open to group or other', () => {
    const base = folder()
    mkdirSync(join(base, 'real'), { mode: 0o700 })
    symlinkSync(join(base, 'real'), join(base, 'link'))
    mkdirSync(join(base, 'open'))
    chmodSync(join(base, 'open'), 0o755)
    writeFileSync(join(base, 'plain'), '')
    for (const [dir, says] of [
      [join(base, 'link'), 'is a link or not a directory'],
      [join(base, 'plain'), 'is a link or not a directory'],
      [join(base, 'open'), 'has mode 0755; it must be 0700'],
    ] as const) {
      let thrown: unknown
      try {
        ensureRunDir(dir)
      } catch (e) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(HomeError)
      expect((thrown as HomeError).code).toBe('unsafe-path')
      expect((thrown as Error).message).toContain(says)
    }
  })

  it('refuses a run/ another user owns, by the uid it is given; with no uid (-1) the owner is not tested', () => {
    const run = join(folder(), 'run')
    mkdirSync(run, { mode: 0o700 })
    const owner = lstatSync(run).uid
    let thrown: unknown
    try {
      ensureRunDir(run, owner + 1)
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(HomeError)
    expect((thrown as HomeError).code).toBe('unsafe-path')
    expect((thrown as Error).message).toBe(`unsafe-path: ${run} belongs to another user (uid ${owner})`)
    expect(() => ensureRunDir(run, owner)).not.toThrow()
    expect(() => ensureRunDir(run, -1)).not.toThrow()
  })
})

describe("the person's line, run", () => {
  /** A fake HOME, the home, and a folder with a launchctl that only marks that it ran, first on PATH. */
  function world() {
    const [HOME, home, bin] = [folder(), folder(), folder()]
    const ran = join(bin, 'loaded')
    writeFileSync(join(bin, 'launchctl'), `#!/bin/sh\ntouch '${ran}'\n`, { mode: 0o755 })
    const file = join(HOME, 'Library', 'LaunchAgents', 'dev.bag.service.plist')
    const next = join(HOME, 'Library', 'dev.bag.service.plist.new')
    const run = (stub: string) => {
      const line = serviceInstall({ HOME }, home, '/m', `sh '${stub}'`, 'darwin', '/n', 501, none, prep).at(
        -1,
      )
      execFileSync('/bin/sh', ['-c', line as string], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
        stdio: 'pipe',
      })
    }
    return { HOME, home, bin, ran, file, next, run }
  }

  it('saves and loads the login agent on a first install and on a second, never the refusal for another home', () => {
    const w = world()
    const plist = `<?xml version="1.0"?>\n<plist version="1.0">\n<string>${join(w.home, 'run')}</string>\n</plist>\n`
    writeFileSync(join(w.bin, 'agent.plist'), plist)
    // The command line's stand-in: it reads the login agent's file as serviceInstall does (there, and naming another
    // home's run folder, is the refusal) and prints that, else the login agent.
    const stub = join(w.bin, 'bag.sh')
    writeFileSync(
      stub,
      [
        `if [ -e '${w.file}' ] && ! grep -q '${join(w.home, 'run')}' '${w.file}'; then`,
        `  echo 'a login agent for another home is installed (${w.file})'`,
        'else',
        `  cat '${join(w.bin, 'agent.plist')}'`,
        'fi',
        '',
      ].join('\n'),
    )
    for (const run of [1, 2]) {
      w.run(stub)
      expect(readFileSync(w.file, 'utf8'), `run ${run}`).toBe(plist)
    }
    expect(existsSync(w.ran)).toBe(true)
    expect(existsSync(w.next)).toBe(false)
  })

  it('a refusal is left beside, the agent file as it was, nothing loaded, and the line fails with STOP', () => {
    const w = world()
    mkdirSync(join(w.HOME, 'Library', 'LaunchAgents'), { recursive: true })
    writeFileSync(w.file, '<plist>an earlier agent</plist>\n')
    const stub = join(w.bin, 'bag.sh')
    writeFileSync(stub, "echo 'bag: usage: a refusal'\nexit 1\n")
    let stderr = ''
    try {
      w.run(stub)
    } catch (e) {
      stderr = String((e as { stderr?: unknown }).stderr)
    }
    expect(stderr).toContain(
      `STOP: bag printed no login agent, so nothing was moved or loaded; what it printed is in ${w.next}`,
    )
    expect(readFileSync(w.file, 'utf8')).toBe('<plist>an earlier agent</plist>\n')
    expect(readFileSync(w.next, 'utf8')).toBe('bag: usage: a refusal\n')
    expect(existsSync(w.ran)).toBe(false)
  })
})

describe('serviceWrite: the login agent written after a Yes, from the fixed template, never loaded here', () => {
  for (const platform of ['darwin', 'linux'] as const)
    it(`${platform}: writes the template with paths from the home only, then the person's line; the same text is unchanged; another home's refuses`, () => {
      const [home, user] = [folder(), folder()]
      const e = { HOME: user, USER: 'x' }
      const o = {
        node: '/n/node',
        main: join(home, 'package', 'bag-mcp.js'),
        home,
        identities: join(home, 'identities.json'),
        env: e,
      }
      const file =
        platform === 'darwin'
          ? join(user, 'Library', 'LaunchAgents', `${SERVICE_LABEL}.plist`)
          : join(user, '.config', 'systemd', 'user', 'bag.service')
      const load =
        platform === 'darwin'
          ? `launchctl bootstrap gui/501 ${file}`
          : 'systemctl --user daemon-reload && systemctl --user enable --now bag'
      expect(serviceWrite(e, home, o.main, platform, '/n/node', 501, prep)).toEqual([
        `wrote ${file}`,
        `to load it, run in a terminal: ${load}`,
      ])
      expect(readFileSync(file, 'utf8')).toBe((platform === 'darwin' ? servicePlist : serviceUnit)(o))
      expect(serviceWrite(e, home, o.main, platform, '/n/node', 501, prep)[0]).toBe(`unchanged ${file}`)
      expect(() => serviceWrite(e, folder(), o.main, platform, '/n/node', 501, prep)).toThrow(
        /^exists: a login agent for another home is installed/,
      )
      expect(readFileSync(file, 'utf8')).toContain(join(home, 'run'))
    })

  it('refuses a platform with no login agent, and no HOME, writing nothing', () => {
    expect(() => serviceWrite({ HOME: folder() }, folder(), '/m', 'win32', '/n', 1, prep)).toThrow(
      /^usage: no login agent/,
    )
    expect(() => serviceWrite({}, folder(), '/m', 'linux', '/n', 1, prep)).toThrow(/^usage: no HOME/)
  })
})
