import { join } from 'node:path'
import { AcError, type Hop, isAcError, type SigningKey, toHex } from '@usebag/core'
import type { Clock, Rng } from '@usebag/edge'
import { AgentClient, AgentError, clampLife } from '@usebag/edge/agent'

// A session under `agent` custody: its mailbox is an agent identity of the home,
// whose agent opens what arrives (the edge's awaited opener), registers each thread the session sends on, and renews
// its grant. The session's own key signs its envelopes and proofs. One connection serves the session and
// presents the edge's current chain with every request, so a renewed chain is its authority at once; a connection
// whose socket failed is made again at the next call (the window's grants and threads outlive it).

/** The least time between two renewals, in seconds, or half the grant's life when shorter: no 10 s churn, no lapse. */
export const RENEW_MIN_S = 300
/** The least time between two probes of the grant, in seconds. */
export const PROBE_MIN_S = 5

export interface SessionAgent {
  /** The connection to the agent, the current chain to present with its next request. */
  readonly client: () => AgentClient
  /** Registers a thread at the agent once, before the first send on it, so a reply on it is released. */
  readonly register: (thread: string) => Promise<void>
  /** Whether a thread was registered here (or is being): the front desk lets its roots pass (edge/agent front-desk.ts). */
  readonly registered: (thread: string) => boolean
  /** The threads registered here, for the next agent session to register again after a new grant. */
  readonly threads: () => string[]
  /** Asks the agent whether this session's grant is still in its window (a register of a fixed thread). */
  readonly probe: () => void
  /** A renewal: the grant again, its caveats, its first life from now (halved while the window is shorter). */
  readonly renew: () => Promise<readonly Hop[]>
  readonly close: () => void
}

/**
 * A connection that is dead after any failed call: its socket may be gone, and a refusal before the agent accepts a
 * request's seq (agent-locked, bad-sig, bad-shape) spends none, so the client's next seq would be refused bad-shape.
 */
class AgentConnection extends AgentClient {
  dead = false
  readonly #lost: () => void
  readonly #refused: () => void

  constructor(
    path: string,
    session: ConstructorParameters<typeof AgentClient>[1],
    lost: () => void,
    refused: () => void,
  ) {
    super(path, session)
    this.#lost = lost
    this.#refused = refused
  }

  override open(...a: Parameters<AgentClient['open']>) {
    return this.#watch(super.open(...a), true)
  }

  override sign(...a: Parameters<AgentClient['sign']>) {
    return this.#watch(super.sign(...a), false)
  }

  override register(...a: Parameters<AgentClient['register']>) {
    return this.#watch(super.register(...a), false)
  }

  /**
   * agent-locked on any call, or not-in-grant on a sign or a register, says this session's grant is no longer in the
   * agent's window (a logout, the window's end, a new login: the grant-set is per window). A not-in-grant on an open
   * can also be a reply on a thread another session registered (the read rule), so it only asks for a probe, as does a
   * sign or register that failed on the socket itself (not an AcError, not an AgentError).
   */
  #watch<T>(p: Promise<T>, open: boolean): Promise<T> {
    return p.catch((e: unknown) => {
      this.dead = true
      if (e instanceof AgentError) {
        if (e.code === 'agent-locked' || (e.code === 'not-in-grant' && !open)) this.#lost()
        else if (e.code === 'not-in-grant') this.#refused()
      } else if (!open && !isAcError(e)) {
        this.#refused() // a sign or register that failed on the socket (the agent restarted?): probe now
      }
      throw e
    })
  }
}

export interface SessionAgentOptions {
  /** Called when the agent says this session's grant is gone (a new grant is needed). */
  readonly lost?: () => void
  /** Threads to register again at the agent, as a new grant lost the window's registrations. */
  readonly replay?: readonly string[]
  /** Called with a thread that could not be registered again, and why. */
  readonly replayFailed?: (thread: string, error: unknown) => void
}

/** The agent of `home` for the session `key`, whose chain is `first` at start and `current()` after. */
export function sessionAgent(
  home: string,
  key: SigningKey,
  first: Hop,
  current: () => readonly Hop[],
  clock: Clock,
  rng: Rng,
  options: SessionAgentOptions = {},
): SessionAgent {
  // A hop has no iat: the life left at start is at most the life the person granted, and never more is asked for.
  const life = Math.max(1, first.exp - clock.now())
  const pace = Math.min(RENEW_MIN_S, Math.floor(life / 2))
  let renewed = Number.NEGATIVE_INFINITY
  const registered = new Map<string, Promise<void>>()
  const path = join(home, 'agent.sock')
  let conn: AgentConnection | null = null
  const client = (): AgentClient => {
    if (conn?.dead) conn.close()
    if (conn === null || conn.dead) {
      conn = new AgentConnection(path, { key, chain: current() }, () => options.lost?.(), probe)
    }
    conn.use(current())
    return conn
  }
  // A thread id no session sends on: registering it asks the agent whether the grant is live. It is drawn here, for the
  // agent releases a registered thread ahead of every caveat, so a fixed id would let any admitted sender past this
  // session's caveats by naming it (spec/SPEC.md §13.8 (a): naming a thread id is the capability).
  const probeThread = toHex(rng.bytes(32))
  let probed = Number.NEGATIVE_INFINITY
  function probe(): void {
    const now = clock.now()
    if (now - probed < PROBE_MIN_S) return
    probed = now
    client()
      .register(probeThread)
      .catch((e: unknown) => {
        // An agent refusal is reported by the connection's own watch. A failure of the socket itself, on a connection
        // made just now, says no agent listens: its window is gone, and so is this session's grant.
        if (!(e instanceof AgentError) && !isAcError(e)) options.lost?.()
      })
  }
  const agent: SessionAgent = {
    client,
    register: (thread) => {
      let p = registered.get(thread)
      if (p === undefined) {
        p = Promise.resolve(thread).then((t) => client().register(t))
        registered.set(thread, p)
        p.catch(() => registered.delete(thread))
      }
      return p
    },
    registered: (thread) => registered.has(thread),
    threads: () => [...registered.keys()],
    probe,
    renew: async () => {
      const now = clock.now()
      if (now - renewed < pace) {
        throw new AcError('rate-limited', `a session renews at most every ${pace} s`)
      }
      // The window's end is not known to a session: ask for now + life and, while it is past the end, for half.
      const hop = await clampLife(life, (l) => client().sign(key.address, first.caveats, now + l))
      renewed = now
      return [hop]
    },
    close: () => conn?.close(),
  }
  for (const thread of options.replay ?? []) {
    agent.register(thread).catch((e: unknown) => options.replayFailed?.(thread, e))
  }
  return agent
}
