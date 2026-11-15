import { existsSync } from 'node:fs'
import { connect } from 'node:net'
import { join } from 'node:path'
import { AcError } from '@usebag/core'
import { type EdgeKeys, HomeCustody, type SecurityRunner } from '@usebag/edge'
import { HomeError } from './ports.ts'

// An identity's keys in its home: a key file in <home>/keys, a macOS keychain item that <home>/keychain/<name>.json
// points to, or the agent (<home>/agent/<name>.json, public data), each through the edge's HomeCustody. The keychain
// is reached through the caller's runner of /usr/bin/security, so a caller with none never reaches a real keychain.

/** The runner when the caller has no /usr/bin/security: every keychain call refuses ENOENT. */
const noSecurity: SecurityRunner = () => {
  throw Object.assign(new Error('keychain: this io runs no /usr/bin/security'), { code: 'ENOENT' })
}

/** The custodies of a home, which run /usr/bin/security through `security`. */
export function homeCustody(security: SecurityRunner | undefined, home: string): HomeCustody {
  return new HomeCustody(home, { run: security ?? noSecurity })
}

/** Refuses a name the custody refuses, and an identity the home lacks (ENOENT: no key file, keychain or agent). */
export function checkIdentity(security: SecurityRunner | undefined, home: string, name: string): void {
  homeCustody(security, home).holder(name)
  if (!['keys', 'keychain', 'agent'].some((d) => existsSync(join(home, d, `${name}.json`))))
    throw new HomeError('ENOENT', `no identity ${name} in ${home}: no key file, keychain or agent pointer`)
}

/**
 * The keys of an identity, from its custody (name and modes checked); the agent's are not-authorized. The class is
 * the edge's custodyOf, the one a bag service checks per call (custodyClass), so both refuse the same identities.
 */
export function loadKeys(security: SecurityRunner | undefined, home: string, name: string): EdgeKeys {
  const custody = homeCustody(security, home)
  if (custody.custodyOf(name) === 'agent') {
    throw new AcError('not-authorized', `${name} is held by the agent, which signs a session's hops only`)
  }
  return custody.keys(name)
}

/** The agent identity whose login window of this home is open on `address` (its socket accepts), else null. */
export async function windowOf(
  security: SecurityRunner | undefined,
  home: string,
  address: string,
): Promise<string | null> {
  const sock = join(home, 'agent.sock')
  if (!existsSync(sock)) return null
  const held = homeCustody(security, home)
    .agent.list()
    .find((e) => e.address === address)
  if (held === undefined) return null
  const live = await new Promise<boolean>((done) => {
    const s = connect(sock, () => {
      s.destroy()
      done(true)
    })
    s.on('error', () => done(false))
  })
  return live ? held.name : null
}

/**
 * Refuses (window-open) a record of `address` while a login window of this home holds it: the agent re-signs the
 * address record it read at login when the window ends, so a record published meanwhile would be overwritten.
 */
export async function checkNoWindow(
  security: SecurityRunner | undefined,
  home: string,
  address: string,
): Promise<void> {
  const name = await windowOf(security, home, address)
  if (name !== null) throw new HomeError('window-open', `a login window holds ${name}: run ac logout first`)
}
