import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { type CustodyTarget, generateEdgeKeys } from '@usebag/edge'
import { CliError, type Parsed, parse, str, UsageError } from '../args.ts'
import { homeCustody, homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'

/** keygen's one stderr line: its identity has no second copy. */
export const NO_RECOVERY = 'keygen: no recovery copy; for sessions and tests (people: ac init)'

/** The custody a new identity goes to: --custody file (the default) or keychain, with its keychain and access. */
export function target(p: Parsed): CustodyTarget {
  const custody = str(p, 'custody') ?? 'file'
  const keychain = str(p, 'keychain')
  const access = str(p, 'keychain-access')
  if (custody === 'file') {
    if (keychain !== undefined || access !== undefined) {
      throw new UsageError('--keychain and --keychain-access go with --custody keychain')
    }
    return { custody }
  }
  if (custody !== 'keychain') {
    throw new UsageError(`--custody is file, keychain or agent, not ${JSON.stringify(custody)}`)
  }
  if (access !== undefined && access !== 'prompt' && access !== 'security') {
    throw new UsageError(`--keychain-access is prompt or security, not ${JSON.stringify(access)}`)
  }
  return {
    custody,
    ...(keychain === undefined ? {} : { keychain }),
    ...(access === undefined ? {} : { access }),
  }
}

/** The agent pointer `name`: the address and sealing key of the file or keychain identity --principal, no new seed. */
function agentPointer(p: Parsed, io: Io, home: string, name: string): number {
  const principal = str(p, 'principal')
  if (principal === undefined) throw new UsageError('--custody agent needs --principal <identity>')
  if (str(p, 'keychain') !== undefined || str(p, 'keychain-access') !== undefined) {
    throw new UsageError('--keychain and --keychain-access go with --custody keychain')
  }
  const recovery = str(p, 'recovery')
  if (recovery !== undefined && !['personal', 'none'].includes(recovery)) {
    throw new UsageError(`--recovery is personal or none, not ${JSON.stringify(recovery)}`)
  }
  const custody = homeCustody(io, home)
  custody.holder(name)
  const held = ['keys', 'keychain'].map((d) => join(home, d, `${name}.json`)).find(existsSync)
  if (held !== undefined) throw new CliError('EEXIST', `${name} is held already, by ${held}`)
  const keys = loadKeys(io, home, principal)
  custody.agent.create(name, keys, recovery)
  io.out(keys.signing.address)
  return 0
}

/**
 * keygen <name> --custody agent --principal <identity> [--recovery personal|none] [--dir <home>]: the pointer
 * <home>/agent/<name>.json (public data) for the address and sealing key of the key file or keychain identity
 * <identity>, which ac login then lets the agent hold for a window; makes no key (a keychain principal raises its one
 * dialog) and prints the address. --recovery writes the recovery setting into the pointer, a format field only.
 *
 * keygen <name> [--custody file|keychain] [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]: a new
 * signing key and a separate sealing key from the CSPRNG, kept by the custody chosen: a key file of the
 * edge's key store (0600 in 0700, never over an existing file), the default; or one macOS keychain item, in the
 * default keychain or --keychain, that no application may read without a dialog (--keychain-access prompt, the
 * default) or that /usr/bin/security reads while the keychain is unlocked (security). A name either custody holds is
 * refused. Prints the address only, never key material.
 */
export function keygen(args: readonly string[], io: Io): number {
  const p = parse(args, {
    positionals: ['name'],
    options: {
      custody: { type: 'string' },
      keychain: { type: 'string' },
      'keychain-access': { type: 'string' },
      principal: { type: 'string' },
      recovery: { type: 'string' },
      dir: { type: 'string' },
    },
  })
  const [home, name] = [homeDir(io, str(p, 'dir')), p.positionals[0] as string]
  if (str(p, 'custody') === 'agent') return agentPointer(p, io, home, name)
  if (str(p, 'principal') !== undefined || str(p, 'recovery') !== undefined) {
    throw new UsageError('--principal and --recovery go with --custody agent')
  }
  const into = target(p)
  const keys = generateEdgeKeys(io.rng)
  homeCustody(io, home).create(name, keys, into)
  if (io.isTty) io.err(NO_RECOVERY) // said to a person at a terminal; a script, or onboard's own keygen, is not one
  io.out(keys.signing.address)
  return 0
}
