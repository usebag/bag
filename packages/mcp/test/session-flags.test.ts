import { describe, expect, it } from 'vitest'
import { ConfigError, parseConfig } from '../src/config.ts'

// --session's flags: --session auto|auto:codex|<name> with --principal and at least one
// --grant-caveat, in place of --as, --auth and --mailbox; --grant-exp optional; and their refusals.

const base = ['--relay', 'http://r.test', '--dir', '/d']
const session = ['--session', 'auto', '--principal', 'jane', '--grant-caveat', 'type=chat.*']

function refusal(argv: readonly string[]): string {
  try {
    parseConfig([...base, ...argv], {})
  } catch (e) {
    expect(e).toBeInstanceOf(ConfigError)
    return (e as ConfigError).message
  }
  throw new Error('parseConfig accepted it')
}

describe('--session', () => {
  it('reads auto, the principal, the caveats (deduplicated) and no exp; --as is the mode until the name resolves', () => {
    const config = parseConfig(
      [...base, ...session, '--grant-caveat', 'repo=x', '--grant-caveat', 'type=chat.*'],
      {},
    )
    expect(config).toMatchObject({
      as: 'auto',
      auth: null,
      mailbox: null,
      keepAliveRecords: false,
      session: { name: 'auto', principal: 'jane', caveats: ['type=chat.*', 'repo=x'], exp: null },
    })
  })

  it('reads a fixed name and --grant-exp as unix seconds or +seconds', () => {
    expect(
      parseConfig([...base, ...session.slice(2), '--session', 's-x', '--grant-exp', '+3600'], {}),
    ).toMatchObject({
      as: 's-x',
      session: { name: 's-x', exp: '+3600' },
    })
    expect(parseConfig([...base, ...session, '--grant-exp', '1800003600'], {})).toMatchObject({
      session: { exp: '1800003600' },
    })
  })

  it('reads auto:codex with --principal and a --grant-caveat, as auto; --as is the mode until a call binds it', () => {
    const codex = ['--session', 'auto:codex', ...session.slice(2)]
    expect(parseConfig([...base, ...codex, '--push', 'log'], {})).toMatchObject({
      as: 'auto:codex',
      push: ['log'],
      session: { name: 'auto:codex', principal: 'jane', caveats: ['type=chat.*'], exp: null },
    })
    expect(refusal(['--session', 'auto:codex', '--grant-caveat', 'type=chat.*'])).toMatch(/needs --principal/)
    expect(refusal(['--session', 'auto:codex', '--principal', 'jane'])).toMatch(/needs --grant-caveat/)
    expect(refusal([...codex, '--as', 'alice'])).toMatch('usage: --as does not go with --session')
    for (const name of ['auto:claude', 'Auto:codex', 'auto:codex:x', 'codex:auto'])
      expect(refusal([`--session=${name}`, ...session.slice(2)])).toMatch(
        /--session is auto, auto:codex or a name/,
      )
  })

  it('refuses --push resource with auto:codex: the resource is named at start, the session at its first call', () => {
    const codex = ['--session', 'auto:codex', ...session.slice(2)]
    expect(refusal([...codex, '--push', 'log', '--push', 'resource'])).toBe(
      'usage: --push resource does not go with --session auto:codex (named only at the first tool call)',
    )
    expect(parseConfig([...base, ...session, '--push', 'resource'], {})).toMatchObject({ push: ['resource'] })
  })

  it('is null without --session, and --as is required then', () => {
    expect(parseConfig([...base, '--as', 'alice'], {})).toMatchObject({ as: 'alice', session: null })
    expect(refusal([])).toMatch(/--as <key name> or --session/)
  })

  it('refuses the flags it replaces, and those a session cannot use', () => {
    for (const extra of [
      ['--as', 'alice'],
      ['--auth', '/c.json'],
      ['--chain-cmd', 'true'],
      ['--mailbox', 'ed25519:00'],
      ['--keep-alive-records'],
      ['--allow-delegate'],
    ]) {
      expect(refusal([...session, ...extra])).toMatch(`usage: ${extra[0]} does not go with --session`)
    }
  })

  it('needs --principal and a --grant-caveat, and refuses them, and --grant-exp, without --session', () => {
    expect(refusal(['--session', 'auto', '--grant-caveat', 'type=chat.*'])).toMatch(/needs --principal/)
    expect(refusal(['--session', 'auto', '--principal', 'jane'])).toMatch(/needs --grant-caveat/)
    for (const extra of [
      ['--principal', 'jane'],
      ['--grant-caveat', 'type=chat.*'],
      ['--grant-exp', '+60'],
    ]) {
      expect(refusal(['--as', 'alice', ...extra])).toMatch(/go with --session/)
    }
  })

  it('refuses a --grant-exp that is not unix seconds or +seconds', () => {
    for (const exp of ['soon', '-60', '+0', '0', '1.5', '+']) {
      expect(refusal([...session, `--grant-exp=${exp}`])).toMatch(/--grant-exp is unix seconds or \+seconds/)
    }
  })

  it('refuses a session name that could leave the home or is not a plain name', () => {
    for (const name of ['../x', 'a/b', '', '-x', 'a b', '.hidden', 'x'.repeat(65)]) {
      expect(refusal([`--session=${name}`, '--principal', 'jane', '--grant-caveat', 'type=chat.*'])).toMatch(
        /--session is auto, auto:codex or a name/,
      )
    }
  })
})
