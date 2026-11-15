import { type CustodyTarget, defaultKeychain } from '@usebag/edge'
import { createAgentPointer, createIdentity, refuseReserved, refuseSecond } from '@usebag/home'
import { CliError, flag, type Parsed, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import { homeIo, viaHome } from '../home-io.ts'
import type { Io } from '../io.ts'

export { HOLDS_IDENTITIES, heldIdentities } from '@usebag/home'

/** keygen's one stderr line: its identity has no second copy. */
export const NO_RECOVERY = 'keygen: no recovery copy; for sessions and tests (people: ac init)'

/**
 * keygen's custody when --custody is not given: the keychain on macOS (io.platform darwin) for a person at a terminal
 * (io.isTty: never a script, onboard's own keygen, SSH without a terminal, CI or rehearse) when `security
 * default-keychain` names a keychain file that exists, else a key file (Linux, a Mac account with no default
 * keychain, the unit tests' io). The item's access is then the prompt default: no application reads it without a dialog.
 */
export function defaultCustody(io: Pick<Io, 'platform' | 'security' | 'isTty'>): 'file' | 'keychain' {
  if (!io.isTty || io.platform !== 'darwin' || io.security === undefined) return 'file'
  return defaultKeychain(io.security) === null ? 'file' : 'keychain'
}

/** The custody a new identity goes to: --custody file or keychain (else `fallback`), with its keychain and access. */
export function target(p: Parsed, fallback: 'file' | 'keychain' = 'file'): CustodyTarget {
  const custody = str(p, 'custody') ?? fallback
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
  viaHome(() => createAgentPointer(homeIo(io), home, name, principal, recovery))
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
 * default) or that /usr/bin/security reads while the keychain is unlocked (security). With no --custody the custody
 * is defaultCustody's: the keychain on macOS with a default keychain (one stderr line says so), else a key file; a
 * defaulted keychain that refuses (locked, no one at the dialog) says --custody file. A name either custody holds is
 * refused. Prints the address only, never key material.
 *
 * On a home that holds identities already (heldIdentities), a name it does not hold is refused (exists,
 * HOLDS_IDENTITIES) unless --new is passed: one home serves every identity of a machine, so a second identity is the
 * person's choice, said in the command. A fresh home is unchanged, a held name keeps its own refusal with or without
 * --new, and --custody agent, a pointer to an identity the home holds and no new key, is not asked for --new (and
 * takes it with no effect, so a script may pass --new to every keygen it runs).
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
      new: { type: 'boolean' },
    },
  })
  const [home, name] = [homeDir(io, str(p, 'dir')), p.positionals[0] as string]
  refuseReserved(name)
  if (str(p, 'custody') === 'agent') return agentPointer(p, io, home, name) // --new changes nothing here
  refuseSecond(home, name, flag(p, 'new') === true)
  if (str(p, 'principal') !== undefined || str(p, 'recovery') !== undefined) {
    throw new UsageError('--principal and --recovery go with --custody agent')
  }
  const defaulted = str(p, 'custody') === undefined
  const into = target(p, defaulted ? defaultCustody(io) : 'file')
  // A defaulted keychain that refuses (locked, no one at the dialog) says how to run again with a key file.
  const refused = (e: unknown): unknown => {
    const code = (e as { code?: unknown }).code
    if (!defaulted || into.custody !== 'keychain' || (code !== 'EACCES' && code !== 'ETIMEDOUT')) return e
    const hint = 'on a host no one watches, run keygen again with --custody file'
    return new CliError(code, `${(e as Error).message}; ${hint}`)
  }
  // said to a person at a terminal; a script, or onboard's own keygen, is not one
  const note = io.isTty ? { note: NO_RECOVERY } : {}
  viaHome(() =>
    createIdentity(homeIo(io), home, name, {
      into,
      defaulted,
      allowNew: flag(p, 'new') === true,
      refused,
      ...note,
    }),
  )
  return 0
}
