import { join } from 'node:path'
import type { Clock } from '@usebag/edge'
import {
  endLinks,
  enterpriseDeps,
  type Fetch,
  newPairs,
  type PairingPorts,
  pairingCommands,
  readSession,
  runPairing,
  systemPorts,
  tick,
} from '@usebag/enterprise-client'
import type { Logger } from './log.ts'
import { Names } from './names.ts'
import { codeOf, pairingsFor, type ToolContext } from './tools.ts'
import { addTrust, removeTrust } from './trust.ts'

// The console's pairings inside the MCP host (decision 38c): while the home holds a live enterprise session, every
// CONSOLE_POLL_MS the server reads the console's pairing commands (packages/enterprise-client pairings.ts) and runs
// them as the CLI's `bag pairings --watch` does: the links the console revoked or whose term ended leave the trust
// file, then each new `pair` runs the OSS ceremony (Pairings.consoleInvite), one at a time, never beside a pair tool's;
// a pass that ended a link or ran a pairing then runs the enterprise tick, so the accept-from follows at once.
// A pass that fails is one log line on stderr; nothing here prints, for stdout is the MCP transport.

export const CONSOLE_POLL_MS = 15_000

/** A wait whose timer holds no process open. */
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms).unref())

export interface Pairer {
  readonly invite: PairingPorts['invite']
  busy(): boolean
}

export interface ConsoleDeps {
  readonly home: string
  readonly fetch: Fetch
  readonly clock: Clock
  readonly log: Logger
  /**
   * The ceremony of the identity `name` of this home, and whether a pairing runs; null when this server does not hold
   * it open. Only the one server that holds the identity (its mcp.lock) polls, so two never run one command.
   */
  readonly pairer: (name: string) => Pairer | null
  /** The wait between runPairing's digit polls (default `wait`). */
  readonly sleep?: (ms: number) => Promise<void>
  /** The enterprise tick, which signs the accept-from again over the peers kept now (records.ts); none: no tick. */
  readonly republish?: () => Promise<unknown>
}

/** One pass: the commands of the home's live session, the revoked and ended links removed, then each new pair run. */
export async function consolePass(d: ConsoleDeps): Promise<void> {
  const s = readSession(d.home)
  if (s === null || s.state !== 'live') return
  const pairer = d.pairer(s.name)
  if (pairer === null) return
  const commands = await pairingCommands(s, d.fetch)
  if (commands === null) return
  const profile = join(d.home, 'orgs', s.domain) // the profile's own home (enterprise-client session.ts)
  const now = (): number => d.clock.now()
  const ports: Omit<PairingPorts, 'invite'> = {
    write: (peer, name) => {
      // The book as it is now, as pair_invite's write reads it; save checks the name first.
      Names.read(d.home).save(name, peer, now())
      addTrust(d.home, peer, now())
    },
    remove: async (peer) => void removeTrust(d.home, peer),
    now,
    sleep: d.sleep ?? wait,
  }
  const ended = await endLinks(s, d.fetch, profile, commands, ports)
  for (const id of ended) d.log.log('info', 'console-unpaired', { id })
  let ran = 0
  for (const c of newPairs(profile, commands)) {
    if (pairer.busy()) break // a pair tool's pairing runs: a later pass
    d.log.log('info', 'console-pairing', { id: c.id })
    await runPairing(s, d.fetch, profile, c, { ...ports, invite: pairer.invite })
    ran++
  }
  if (ended.length + ran > 0) await d.republish?.()
}

/** Runs a pass every `every` ms (unref'd), none beside a running one, a failure logged; returns the stop. */
export function pollConsole(d: ConsoleDeps, every = CONSOLE_POLL_MS): () => void {
  let running = false
  let stopped = false
  const sleep = d.sleep ?? wait
  // After the stop a ceremony waiting for the spoken numerals ends at its next wait: no pass outlives the server.
  const deps: ConsoleDeps = {
    ...d,
    sleep: (ms) => (stopped ? Promise.reject(new Error('stopped')) : sleep(ms)),
  }
  const timer = setInterval(() => {
    if (running || stopped) return
    running = true
    consolePass(deps)
      .catch((e: unknown) => {
        // An enterprise error's own code (session-invalid), else the server's.
        const own = (e as { code?: unknown } | null)?.code
        d.log.log('warn', 'console-pairings', { code: typeof own === 'string' ? own : codeOf(e) })
      })
      .finally(() => {
        running = false
      })
  }, every)
  timer.unref()
  return () => {
    stopped = true
    clearInterval(timer)
  }
}

/** The poller of the server whose tools were registered on `root`, over its identities `contexts`. */
export function watchConsole(root: ToolContext, contexts: readonly ToolContext[]): () => void {
  const { home } = root.config
  return pollConsole({
    home,
    fetch: root.enterprise?.fetch ?? globalThis.fetch,
    clock: root.clock,
    log: root.log,
    republish: () => {
      const ports = { ...systemPorts(root.env), clock: root.clock, rng: root.rng, ...root.enterprise }
      return tick(
        enterpriseDeps(
          ports,
          home,
          () => {},
          async () => null,
        ),
      )
    },
    pairer: (name) => {
      const c = contexts.find((x) => x.config.home === home && x.config.as === name)
      const p = c === undefined || !isOpen(c) ? null : pairingsFor(root, c)
      return p === null ? null : { invite: p.consoleInvite, busy: () => p.busy() }
    },
  })
}

/** Whether an identity is open: its context's `opened` throws while it waits for a grant or has failed. */
function isOpen(c: ToolContext): boolean {
  try {
    return c.opened !== undefined
  } catch {
    return false
  }
}
