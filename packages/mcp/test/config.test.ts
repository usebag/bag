import { chmodSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  type Config,
  ConfigError,
  maxToolSeconds,
  parseConfig,
  parseServerConfig,
  progressSeconds,
  relayUrl,
  type ServerConfig,
  trustedRoot,
  USAGE,
} from '../src/config.ts'
import { P, tempDir } from './support/fixtures.ts'

const base = ['--as', 'alice', '--relay', 'http://r.test/'] as const

function refused(
  argv: readonly string[],
  env: Record<string, string> = { HOME: '/h' },
): { code: string; message: string } {
  try {
    parseConfig(argv, env)
  } catch (e) {
    expect(e).toBeInstanceOf(ConfigError)
    return { code: (e as ConfigError).code, message: (e as ConfigError).message }
  }
  throw new Error('parseConfig accepted it')
}

describe('parseConfig: flags and the environment, never stdin', () => {
  it('reads the minimal flags with every default: home from HOME, trust no root, honor nothing, accept every type, queue', () => {
    expect(parseConfig(base, { HOME: '/home/u/' })).toEqual({
      label: 'alice',
      as: 'alice',
      home: '/home/u/.bag',
      relays: ['http://r.test'],
      rendezvous: 'http://r.test',
      trustRootTexts: [],
      trustRoots: [],
      honor: [],
      acceptTypes: ['*'],
      defaultHandler: 'queue',
      auth: null,
      chainCmd: null,
      mailbox: null,
      session: null,
      allowDelegate: false,
      allowSessionDelegation: false,
      keepAliveRecords: false,
      receiptsTo: [],
      maxToolSeconds: 25,
      progressSeconds: 15,
      allowPrivateRelays: false,
      policy: null,
      members: null,
      push: [],
    } satisfies Config)
  })

  it('reads every flag: repeated relays (deduplicated), roots by address and by domain, coding, types, a session', () => {
    const config = parseConfig(
      [
        ...base,
        '--relay',
        'https://s.test',
        '--relay',
        'http://r.test',
        '--rendezvous',
        'https://meet.test/',
        '--trust-root',
        P.bob.address,
        '--trust-root',
        'acme.test',
        '--honor',
        'coding',
        '--honor',
        'coding',
        '--accept-type',
        'chat.v1',
        '--accept-type',
        'coding.*',
        '--accept-type',
        'chat.v1',
        '--default-handler',
        'queue',
        '--auth',
        '/c/chain.json',
        '--mailbox',
        P.jane.address,
        '--allow-delegate',
        '--allow-session-delegation',
        '--allow-private-relays',
        '--max-tool-seconds',
        '55',
        '--progress-seconds',
        '10',
        '--policy',
        '/o/policy.json',
        '--members',
        '/o/members.json',
        '--push',
        'channel',
        '--push',
        'log',
        '--push',
        'channel',
        '--push',
        'resource',
        '--dir',
        '/d',
      ],
      { AC_HOME: '/ignored' },
    )
    expect(config).toEqual({
      label: 'alice',
      as: 'alice',
      home: '/d',
      relays: ['http://r.test', 'https://s.test'],
      rendezvous: 'https://meet.test',
      trustRootTexts: [P.bob.address, 'acme.test'],
      trustRoots: [{ address: P.bob.address }, { domain: 'acme.test' }],
      honor: ['coding'],
      acceptTypes: ['chat.v1', 'coding.*'],
      defaultHandler: 'queue',
      auth: '/c/chain.json',
      chainCmd: null,
      mailbox: P.jane.address,
      session: null,
      allowDelegate: true,
      allowSessionDelegation: true,
      keepAliveRecords: false,
      receiptsTo: [],
      maxToolSeconds: 55,
      progressSeconds: 10,
      allowPrivateRelays: true,
      policy: '/o/policy.json',
      members: '/o/members.json',
      push: ['channel', 'log', 'resource'],
    } satisfies Config)
  })

  it('takes the home from AC_HOME before HOME, and refuses when neither is set', () => {
    expect((parseConfig(base, { AC_HOME: '/ac', HOME: '/h' }) as Config).home).toBe('/ac')
    expect(refused(base, {})).toEqual({
      code: 'usage',
      message: 'usage: no home directory: pass --dir, or set AC_HOME or HOME',
    })
  })

  it('answers help for --help and -h, and the usage names every flag', () => {
    expect(parseConfig(['--help'], {})).toBe('help')
    expect(parseConfig(['-h'], {})).toBe('help')
    for (const flag of ['--as', '--relay', '--trust-root', '--honor', '--accept-type', '--default-handler']) {
      expect(USAGE).toContain(flag)
    }
    for (const flag of ['--auth', '--chain-cmd', '--mailbox', '--dir', '--help', '--policy', '--members'])
      expect(USAGE).toContain(flag)
    for (const flag of [
      '--allow-delegate',
      '--allow-session-delegation',
      '--keep-alive-records',
      '--max-tool-seconds',
      '--progress-seconds',
      '--allow-private-relays',
      '--push',
    ]) {
      expect(USAGE).toContain(flag)
    }
  })

  it('refuses a missing --as and a missing --relay, with usage', () => {
    expect(refused(['--relay', 'http://r.test'])).toEqual({
      code: 'usage',
      message: 'usage: --as <key name> or --session auto|auto:codex|<name> is required',
    })
    expect(refused(['--as', 'alice'])).toEqual({
      code: 'usage',
      message: 'usage: --relay <url> is required, at least once',
    })
  })

  it('refuses an unknown flag, a positional argument and a flag without its value', () => {
    expect(refused([...base, '--spawn']).code).toBe('usage')
    expect(refused([...base, 'extra']).code).toBe('usage')
    expect(refused(['--relay', 'http://r.test', '--as']).code).toBe('usage')
  })

  it('refuses an unknown profile, an unknown --push kind, an empty type and any default handler but queue', () => {
    expect(refused([...base, '--honor', 'payments']).message).toBe(
      'usage: --honor "payments" is not a profile; the profiles are coding',
    )
    expect(refused([...base, '--push', 'email']).message).toBe(
      'usage: --push "email" is not resource, log or channel',
    )
    expect(refused([...base, '--accept-type', '']).message).toBe(
      'usage: --accept-type is a type, <prefix>.* or *, not empty',
    )
    expect(refused([...base, '--default-handler', 'spawn']).message).toBe(
      'usage: --default-handler "spawn": queue is the only mode in v0 (nothing is spawned)',
    )
  })

  it('refuses a session without its mailbox, a mailbox without a chain, and a mailbox that is not an address', () => {
    expect(refused([...base, '--auth', 'c.json']).message).toBe(
      "usage: a session (--auth or --chain-cmd) receives at its principal's mailbox: pass --mailbox <principal address>",
    )
    expect(refused([...base, '--chain-cmd', 'helper']).message).toBe(
      "usage: a session (--auth or --chain-cmd) receives at its principal's mailbox: pass --mailbox <principal address>",
    )
    expect(refused([...base, '--mailbox', P.jane.address]).message).toBe(
      'usage: --mailbox is for a session: pass --auth <chain.json> or --chain-cmd <command> too',
    )
    expect(refused([...base, '--auth', 'c.json', '--mailbox', 'jane'])).toEqual({
      code: 'bad-address',
      message: 'bad-address: --mailbox "jane" is not an address',
    })
  })
})

describe('relayUrl and trustedRoot', () => {
  it('takes http and https URLs without their trailing slashes, and refuses anything else', () => {
    expect(relayUrl('https://relay.test//')).toBe('https://relay.test')
    expect(() => relayUrl('not a url')).toThrow('usage: --relay "not a url" is not a URL')
    expect(() => relayUrl('ftp://relay.test')).toThrow(
      'usage: --relay "ftp://relay.test" is not an http or https URL',
    )
    // --rendezvous is read the same way, and named in its refusal.
    expect(() => relayUrl('ftp://meet.test', '--rendezvous')).toThrow(
      'usage: --rendezvous "ftp://meet.test" is not an http or https URL',
    )
  })

  it('reads an address as a key root and a host name as a domain root, and refuses the rest', () => {
    expect(trustedRoot(P.bob.address)).toEqual({ address: P.bob.address })
    expect(trustedRoot('acme.test:8443')).toEqual({ domain: 'acme.test:8443' })
    expect(() => trustedRoot('https://acme.test/x')).toThrow(
      'usage: --trust-root "https://acme.test/x" is neither an address nor a domain',
    )
  })
})

describe('the follow-up flags: --chain-cmd, --max-tool-seconds, --keep-alive-records', () => {
  it('reads a session under --chain-cmd, and refuses it beside --auth, empty, or with --keep-alive-records', () => {
    const config = parseConfig([...base, '--chain-cmd', 'print-chain --for s', '--mailbox', P.jane.address], {
      HOME: '/h',
    }) as Config
    expect([config.auth, config.chainCmd, config.mailbox]).toEqual([
      null,
      'print-chain --for s',
      P.jane.address,
    ])
    expect(
      refused([...base, '--auth', 'c.json', '--chain-cmd', 'x', '--mailbox', P.jane.address]).message,
    ).toBe('usage: --auth and --chain-cmd are two sources of one chain: pass one of them')
    expect(refused([...base, '--chain-cmd', '  ', '--mailbox', P.jane.address]).message).toBe(
      'usage: --chain-cmd is a command, not empty',
    )
    for (const session of [
      ['--auth', 'c.json'],
      ['--chain-cmd', 'x'],
    ]) {
      expect(
        refused([...base, ...session, '--mailbox', P.jane.address, '--keep-alive-records']).message,
      ).toBe(
        "usage: --keep-alive-records re-signs this identity's own records: a session cannot sign its principal's",
      )
    }
  })

  it('turns the keep-alive on for a principal, and session delegation on, both off by default', () => {
    const on = parseConfig([...base, '--keep-alive-records', '--allow-session-delegation'], { HOME: '/h' })
    expect(on).toMatchObject({ keepAliveRecords: true, allowSessionDelegation: true })
  })

  it('lists the delegate tool only under --allow-delegate, off by default, and says so', () => {
    expect(parseConfig(base, { HOME: '/h' })).toMatchObject({ allowDelegate: false })
    expect(parseConfig([...base, '--allow-delegate'], { HOME: '/h' })).toMatchObject({ allowDelegate: true })
    // --allow-session-delegation alone is taken, and does nothing without the tool: the usage says so.
    expect(parseConfig([...base, '--allow-session-delegation'], { HOME: '/h' })).toMatchObject({
      allowDelegate: false,
      allowSessionDelegation: true,
    })
    expect(USAGE).toContain('at least one caveat,\n')
    expect(USAGE).toContain('an expiry within 8 hours; off by default, and then the tool is not listed')
    expect(USAGE).toContain('without --allow-delegate it does nothing')
  })

  it('takes --max-tool-seconds from 1 to 300 whole seconds, 25 without it, and refuses anything else', () => {
    expect([maxToolSeconds(undefined), maxToolSeconds('1'), maxToolSeconds('300')]).toEqual([25, 1, 300])
    for (const bad of ['0', '301', '999', '1000', '2.5', '-1', '', ' 5', '05', 'x']) {
      expect(refused([...base, `--max-tool-seconds=${bad}`]).message).toBe(
        `usage: --max-tool-seconds ${JSON.stringify(bad)} is not a whole number of seconds from 1 to 300`,
      )
    }
  })

  it('takes --progress-seconds from 0 (none) to 300 whole seconds, 15 without it, and refuses anything else', () => {
    expect([progressSeconds(undefined), progressSeconds('0'), progressSeconds('300')]).toEqual([15, 0, 300])
    for (const bad of ['301', '1000', '2.5', '-1', '', ' 5', '05', '00', 'x']) {
      expect(refused([...base, `--progress-seconds=${bad}`]).message).toBe(
        `usage: --progress-seconds ${JSON.stringify(bad)} is not a whole number of seconds from 0 to 300`,
      )
    }
  })
})

describe('parseServerConfig: one identity from the flags, or several from --identities', () => {
  /** A 0600 identities file of two identities, lab the default; its path. */
  function identitiesFile(): string {
    const tmp = tempDir('config-identities')
    onTestFinished(() => tmp.cleanup())
    const path = join(tmp.dir, 'ids.json')
    const entry = (label: string) => ({ label, home: `/home/u/.ac-${label}`, relays: ['https://r.test'] })
    writeFileSync(
      path,
      JSON.stringify({ version: 1, default: 'lab', identities: [entry('personal'), entry('lab')] }),
    )
    chmodSync(path, 0o600)
    return path
  }

  function refusedServer(argv: readonly string[]): { code: string; message: string } {
    try {
      parseServerConfig(argv, { HOME: '/h' })
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError)
      return { code: (e as ConfigError).code, message: (e as ConfigError).message }
    }
    throw new Error('parseServerConfig accepted it')
  }

  it("wraps parseConfig's one Config without --identities: labelled with its key name, not multi", () => {
    const argv = [...base, '--push', 'log', '--max-tool-seconds', '40']
    const one = parseConfig(argv, { HOME: '/h' }) as Config
    expect(one.label).toBe('alice')
    expect(parseServerConfig(argv, { HOME: '/h' })).toEqual({
      identities: [one],
      defaultLabel: 'alice',
      multi: false,
      maxToolSeconds: 40,
      progressSeconds: 15,
      push: ['log'],
      allowPrivateRelays: false,
      defaultHandler: 'queue',
    } satisfies ServerConfig)
    expect(refusedServer(['--relay', 'http://r.test']).message).toBe(
      'usage: --as <key name> or --session auto|auto:codex|<name> is required',
    )
  })

  it('answers help for --help, with or without --identities', () => {
    expect(parseServerConfig(['--help'], {})).toBe('help')
    expect(parseServerConfig(['--identities', '/home/u/none.json', '-h'], {})).toBe('help')
  })

  it('reads the file with every server-wide flag beside it, and gives each identity those values', () => {
    const config = parseServerConfig(
      [
        '--identities',
        identitiesFile(),
        '--max-tool-seconds',
        '55',
        '--progress-seconds',
        '0',
        '--push',
        'channel',
        '--push',
        'resource',
        '--allow-private-relays',
        '--default-handler',
        'queue',
      ],
      {},
    ) as ServerConfig
    const wide = {
      maxToolSeconds: 55,
      progressSeconds: 0,
      push: ['channel', 'resource'],
      allowPrivateRelays: true,
      defaultHandler: 'queue',
    }
    expect(config).toMatchObject({ defaultLabel: 'lab', multi: true, ...wide })
    expect(config.identities.map((c) => c.label)).toEqual(['personal', 'lab'])
    for (const c of config.identities) {
      expect(c).toMatchObject({ ...wide, auth: null, chainCmd: null, mailbox: null, session: null })
    }
    // Without the server-wide flags, their defaults.
    expect(parseServerConfig(['--identities', identitiesFile()], {})).toMatchObject({
      maxToolSeconds: 25,
      progressSeconds: 15,
      push: [],
      allowPrivateRelays: false,
    })
  })

  it('refuses every per-identity, session and chain flag beside --identities, before it reads the file', () => {
    for (const flag of [
      ['--as', 'alice'],
      ['--relay', 'http://r.test'],
      ['--rendezvous', 'http://r.test'],
      ['--trust-root', 'acme.test'],
      ['--dir', '/d'],
      ['--honor', 'coding'],
      ['--accept-type', '*'],
      ['--keep-alive-records'],
      ['--allow-delegate'],
      ['--policy', '/o/policy.json'],
      ['--members', '/o/members.json'],
      ['--session', 'auto'],
      ['--principal', 'jane'],
      ['--grant-caveat', 'type=chat.*'],
      ['--grant-exp', '+60'],
      ['--auth', '/c/chain.json'],
      ['--chain-cmd', 'print-chain'],
      ['--mailbox', P.jane.address],
      ['--allow-session-delegation'],
    ]) {
      // The file does not exist: the flag is refused first.
      expect(refusedServer(['--identities', '/home/u/none.json', ...flag])).toEqual({
        code: 'usage',
        message: `usage: ${flag[0]} does not go with --identities: it goes in the file, or not at all`,
      })
    }
  })

  it('refuses a bad server-wide value beside --identities, a relative file, and --identities in parseConfig', () => {
    expect(refusedServer(['--identities', '/home/u/none.json', '--push', 'email']).message).toBe(
      'usage: --push "email" is not resource, log or channel',
    )
    expect(refusedServer(['--identities', '/home/u/none.json', '--default-handler', 'spawn']).message).toBe(
      'usage: --default-handler "spawn": queue is the only mode in v0 (nothing is spawned)',
    )
    expect(refusedServer(['--identities', 'ids.json']).message).toBe(
      'usage: --identities: "ids.json" is not an absolute path',
    )
    const none = join(identitiesFile(), '..', 'none.json')
    expect(refusedServer(['--identities', none]).message).toBe(
      `usage: --identities: ${none} cannot be read (ENOENT)`,
    )
    expect(refused(['--identities', '/home/u/ids.json']).message).toBe(
      'usage: --identities is read by parseServerConfig, not parseConfig',
    )
  })

  it('names --identities in the usage, beside --as', () => {
    expect(USAGE).toContain('       node packages/mcp/src/main.ts --identities <file> [options]\n')
    expect(USAGE).toContain('  --identities <file>           several unlinked identities in one server')
  })
})
