import { isAcError } from '@usebag/core'
import { isLoopbackOrigin, parseConnectCode } from './connect-code.ts'
import { defaultName, type EnterpriseDeps, fingerprint, signIn } from './flow.ts'
import { EnterpriseError } from './instance.ts'
import type { PublishOutcome } from './records.ts'
import { readSession } from './session.ts'

// bag connect: the console's one-time code, pasted, and nothing else to type. The code names the instance and the
// organisation (connect-code.ts), so no BAG_ENTERPRISE_INSTANCES, no domain and no discovery: the code's origin is
// pinned, and where the organisation's own record (.well-known/bag/enterprise.json) names another instance, the code's
// wins, since a person of that organisation minted it in that instance's console. The origin still passes
// discovery's rules: https, or http only on a loopback host (a local instance); a non-loopback origin through the
// private-address guard before any call; every call refuses a redirect (instance.ts). Then the whole code is redeemed
// with the binding over its nonce (route b, sign-in's --code), in one call. One line per state; no key, token or code
// is printed. Exits are AGENT_EXIT's: 0 connected, 1 refused, 2 usage, 3 ended, 4 waiting on the signer.

export interface ConnectOptions {
  /** The pasted text: BAG_ORG_CODE, or a line of stdin; never argv. */
  readonly text: string
  readonly name?: string
  readonly label?: string
  readonly version: string
}

/** Refuses an origin the private-address guard refuses (a loopback origin is a local instance and passes). */
export async function guardOrigin(d: EnterpriseDeps, origin: string): Promise<void> {
  if (isLoopbackOrigin(origin)) return
  try {
    await d.net.guard.connectTo(origin)
  } catch (e) {
    const code = isAcError(e) ? e.code : 'discovery_failed'
    throw new EnterpriseError(code, `${origin} is refused: ${(e as Error).message}`)
  }
}

export async function connect(d: EnterpriseDeps, o: ConnectOptions): Promise<number> {
  const c = parseConnectCode(o.text)
  await guardOrigin(d, c.origin)
  d.say(`Connecting to ${c.domain} at ${c.origin}`)
  const name = o.name ?? defaultName(c.domain)
  const published: PublishOutcome[] = []
  const quiet: EnterpriseDeps = {
    ...d,
    say: () => {},
    readCode: async () => c.code,
    onRecords: (o) => published.push(...o),
  }
  const exit = await signIn(quiet, {
    domain: c.domain,
    instance: c.origin,
    name,
    ...(o.label === undefined ? {} : { label: o.label }),
    code: true,
    wait: false,
    version: o.version,
  })
  const s = readSession(d.home)
  if (s === null) throw new EnterpriseError('bad-answer', 'the instance answered, but no session was written')
  d.say(`Approved: agent ${fingerprint(s.agent_address)}`)
  const label = o.label ?? s.name
  if (exit === 0) d.say(`Connected as ${label}`)
  else if (s.state === 'live' && s.hop === null)
    d.say("Waiting for the organisation's signer: run bag status in a minute")
  else d.say(`Not connected: the session is ${s.state}${s.reason === null ? '' : ` (${s.reason})`}`)
  // A relay that did not take both records, once, with its first code: the agent cannot be reached there until a tick
  // publishes them (every tick retries). Nothing when every relay took both. The exit stays the sign-in's.
  sayRelayFailures(d, published)
  return exit
}

/** One line per relay that did not take both records, with its first code; nothing when every relay took both. */
export function sayRelayFailures(d: EnterpriseDeps, published: readonly PublishOutcome[]): void {
  const failed = new Map<string, string>()
  for (const o of published) if (!o.ok && !failed.has(o.relay)) failed.set(o.relay, o.code ?? 'error')
  for (const [relay, code] of failed) d.say(`relay ${relay}: records not published (${code})`)
}
