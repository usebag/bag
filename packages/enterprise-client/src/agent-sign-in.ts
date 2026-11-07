import { isDomainHost } from '@usebag/core'
import { guardOrigin, sayRelayFailures } from './connect.ts'
import { bareOrigin } from './discovery.ts'
import { type EnterpriseDeps, signIn } from './flow.ts'
import { EnterpriseError } from './instance.ts'
import type { PublishOutcome } from './records.ts'
import { readPending, readSession } from './session.ts'

// Sign-in through an agent with no code: the domain and the instance's console origin are given, and the
// existing device flow runs (route a): the first call asks the instance for a code and returns the approval
// link and the agent key's fingerprint; each later call polls once and reports the state, waiting, connected or
// refused. The instance is pinned as connect pins a code's (no discovery, no record), and keeps the same rules: https,
// or http only on a loopback host; a non-loopback origin through the private-address guard first; every call refuses
// a redirect. The lines are public: the link and its user code (made to be shown to a person), the fingerprint, the
// state. Never the device code, the token or a key. The MCP tool `sign_in` and `sign-in --instance` share it.

export interface AgentSignInOptions {
  readonly domain: string
  readonly instance: string
  readonly version: string
}

/** The instance origin given, held to connect's rules; usage (exit 2) for anything else. */
export function pinnedInstance(text: string): string {
  const origin = bareOrigin(text.trim(), true)
  if (origin === null)
    throw new EnterpriseError('usage', 'the instance is the console origin: https, or http on this machine')
  return origin
}

/** Signs in through the device flow without waiting; the lines go to `d.say`; the exit is AGENT_EXIT's. */
export async function signInThroughAgent(d: EnterpriseDeps, o: AgentSignInOptions): Promise<number> {
  const domain = o.domain.trim().toLowerCase()
  if (!isDomainHost(domain))
    throw new EnterpriseError('usage', "the domain is the organisation's, such as example.com")
  const instance = pinnedInstance(o.instance)
  await guardOrigin(d, instance)
  d.say(`Signing in to ${domain} at ${instance}`)
  const lines: string[] = []
  const published: PublishOutcome[] = []
  const quiet: EnterpriseDeps = { ...d, say: (l) => lines.push(l), onRecords: (r) => published.push(...r) }
  const opening = (l: string) =>
    l.startsWith('open ') || l.startsWith('fingerprint ') || l.startsWith('approve only')
  let exit: number
  try {
    exit = await signIn(quiet, { domain, instance, code: false, wait: false, version: o.version })
  } catch (e) {
    for (const l of lines.filter(opening)) d.say(l)
    if (e instanceof EnterpriseError && e.code === 'authorization_pending') {
      d.say('Waiting for a person to approve it; ask again to see the state')
      return 4
    }
    throw e
  }
  for (const l of lines.filter(opening)) d.say(l)
  const s = readSession(d.home)
  if (s === null) throw new EnterpriseError('bad-answer', 'the instance answered, but no session was written')
  if (exit === 0) d.say(`Connected as ${s.name}`)
  else if (s.state === 'live' && s.hop === null)
    d.say("Approved; waiting for the organisation's signer: ask again in a minute")
  else d.say(`Not connected: the session is ${s.state}${s.reason === null ? '' : ` (${s.reason})`}`)
  sayRelayFailures(d, published)
  return exit
}

/** The secrets of this home's sign-in, for a scrub: the waiting device code and the session's token. */
export function signInSecrets(home: string): string[] {
  const out: string[] = []
  try {
    const p = readPending(home)
    if (p !== null && p.device_code !== '') out.push(p.device_code)
  } catch {
    // no readable pending file
  }
  try {
    const s = readSession(home)
    if (s !== null) out.push(s.access_token)
  } catch {
    // no readable session
  }
  return out
}
