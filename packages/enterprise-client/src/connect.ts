import { isAcError } from '@usebag/core'
import { isLoopbackOrigin, parseConnectCode } from './connect-code.ts'
import {
  connectedLine,
  defaultName,
  type EnterpriseDeps,
  fingerprint,
  roundTrip,
  StepFailed,
  signIn,
  tick,
} from './flow.ts'
import { EnterpriseError } from './instance.ts'
import { outcomeLine, type PublishOutcome, readRecordsCopy, recordsDue } from './records.ts'
import { profileHome, profiles, readSession, type Session, setCurrent } from './session.ts'

// bag connect: the console's one-time code, pasted, and nothing else to type. The code names the instance and the
// organisation (connect-code.ts), so no BAG_ENTERPRISE_INSTANCES, no domain and no discovery: the code's origin is
// pinned, and where the organisation's own record (.well-known/bag/enterprise.json) names another instance, the code's
// wins, since a person of that organisation minted it in that instance's console. The origin still passes
// discovery's rules: https, or http only on a loopback host (a local instance); a non-loopback origin through the
// private-address guard before any call; every call refuses a redirect (instance.ts). Then the whole code is redeemed
// with the binding over its nonce (route b, sign-in's --code), in one call. Once connected, the same command proves
// the path a message takes: (a) the agent's records at the organisation's relays, (b) one envelope to itself through
// the first relay, read back (flow.ts roundTrip). One line in all, `Connected as <label>; relay round trip <n> ms`, or
// one line naming the step and the relay that failed (exit 1, the session kept). No key, token or code is printed;
// the fingerprint and each relay's outcome only with `verbose`. Exits are AGENT_EXIT's: 0 connected, 1 refused or a
// step failed, 2 usage, 3 ended, 4 waiting on the signer.

export interface ConnectOptions {
  /** The pasted text: BAG_ORG_CODE, or a line of stdin; never argv. */
  readonly text: string
  readonly name?: string
  readonly label?: string
  readonly version: string
  /** Also the progress lines: the instance, the agent's fingerprint, each relay's records. */
  readonly verbose?: boolean
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
  const more = o.verbose === true ? d.say : () => {}
  more(`Connecting to ${c.domain} at ${c.origin}`)
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
  }).catch((e: unknown) => {
    // The code is unused: the same code again, without --label (the code's own label) or with another, connects.
    if (!(e instanceof EnterpriseError) || e.code !== 'label_taken') throw e
    throw new EnterpriseError(
      'label_taken',
      `the label ${o.label} is held by a live agent of ${c.domain}: connect again without --label, or with another`,
    )
  })
  const s = readSession(d.home, c.domain)
  if (s === null) throw new EnterpriseError('bad-answer', 'the instance answered, but no session was written')
  more(`Approved: agent ${fingerprint(s.agent_address)}`)
  // The label the instance gave this agent (the code's, or the --label it took).
  const label = s.label ?? o.label ?? s.name
  if (exit !== 0 && s.state === 'live' && s.hop === null)
    d.say("Waiting for the organisation's signer: run bag status in a minute")
  else if (exit !== 0)
    d.say(`Not connected: the session is ${s.state}${s.reason === null ? '' : ` (${s.reason})`}`)
  if (exit !== 0) return exit
  try {
    try {
      await recordsAt({ ...quiet, org: c.domain }, published)
    } finally {
      for (const p of published) more(outcomeLine(p))
    }
    const ms = await roundTrip(d, readSession(d.home, c.domain) ?? s)
    // Another organisation's profile stays as it was; this one becomes the most recently connected.
    const others = profiles(d.home).filter((o) => o !== c.domain)
    setCurrent(d.home, c.domain)
    if (others.length === 0) d.say(connectedLine(label, ms))
    else
      d.say(
        `${connectedLine(`${label} (${c.domain})`, ms)}; also signed in to ${others.join(', ')}: bag status --org ${others[0]}`,
      )
    return 0
  } catch (e) {
    if (!(e instanceof StepFailed)) throw e
    d.say(`Connected as ${label}, but ${e.message}: bag status tries again`)
    return 1
  }
}

/**
 * Step (a): the agent's records at every relay of the organisation. The sign-in's tick publishes them; when it did not
 * (a session already there, the refresher's lock held), one more tick does, unless a fresh copy says they are there.
 * The first relay that did not take both fails the step with its code.
 */
async function recordsAt(d: EnterpriseDeps & { org: string }, published: PublishOutcome[]): Promise<void> {
  if (published.length === 0) published.push(...((await tick(d)).records ?? []))
  const s = readSession(d.home, d.org) as Session
  const bad = published.find((p) => !p.ok)
  const relay = bad?.relay ?? s.org.relays[0] ?? 'none'
  const why = 'its records were not published'
  if (bad !== undefined) throw new StepFailed(why, relay, bad.code ?? 'error')
  if (recordsDue(s, readRecordsCopy(profileHome(d.home, d.org)), d.clock.now()))
    throw new StepFailed(why, relay, 'not-published')
}

/** One line per relay that did not take both records, with its first code; nothing when every relay took both. */
export function sayRelayFailures(d: EnterpriseDeps, published: readonly PublishOutcome[]): void {
  const failed = new Map<string, string>()
  for (const o of published) if (!o.ok && !failed.has(o.relay)) failed.set(o.relay, o.code ?? 'error')
  for (const [relay, code] of failed) d.say(`relay ${relay}: records not published (${code})`)
}
